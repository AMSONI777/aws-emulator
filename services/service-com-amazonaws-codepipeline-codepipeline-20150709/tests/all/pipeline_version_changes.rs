// SPDX-License-Identifier: CC0-1.0

//! What a write to a pipeline's structure does to its `version`, end to end over the wire
//! the service speaks (`awsJson1_1`).
//!
//! The rule under test: `UpdatePipeline` DIFFS the submitted `PipelineDeclaration` against
//! the stored one and advances `version` only when the two describe different pipelines, and
//! then by exactly one — `PipelineDeclaration$version` is "the version number of the
//! pipeline. A new pipeline always has a version number of 1. This number is incremented
//! when a pipeline is updated", so what the number counts is changes to the pipeline rather
//! than calls against it. A write that submits the structure the pipeline already has is
//! accepted and moves nothing.
//!
//! Each suite is a TABLE whose rows differ along what the rule generalises over: for the
//! no-op half, the FORM the unchanged structure is re-submitted in (the one a read answered,
//! the one the create sent, one whose service-resolved members are left out, one carrying a
//! `version` the pipeline never had); for the changed half, WHICH member of the structure
//! the single edit touches.

use serde_json::{json, Value};

// The harness, the base declaration and the stage builders are shared with the
// create/read suite rather than copied (`tests/all/pipeline_lifecycle.rs`).
use crate::pipeline_lifecycle::{
    build_stage, reported_stages, source_stage, Emulator, ROLE_ARN,
};

/// The fixture every row writes against: a source stage, a build stage, and an invoke stage
/// whose action carries `UserParameters` — a configuration value that is itself a document,
/// so the diff is exercised over a map entry whose text a client round-trips.
fn fixture(name: &str) -> Value {
    json!({
        "name": name,
        "roleArn": ROLE_ARN,
        "artifactStore": {"type": "S3", "location": "my-bucket"},
        "stages": [
            source_stage("Source"),
            build_stage("Build", 1),
            invoke_stage("Launch", "{\"mode\":\"full\",\"retries\":2}"),
        ],
    })
}

/// A stage whose action invokes a function with `user_parameters` (`Invoke`/`AWS`/`Lambda`
/// publishes `FunctionName` and `UserParameters`).
fn invoke_stage(name: &str, user_parameters: &str) -> Value {
    json!({
        "name": name,
        "actions": [{
            "name": "Launch",
            "actionTypeId": {
                "category": "Invoke",
                "owner": "AWS",
                "provider": "Lambda",
                "version": "1",
            },
            "configuration": {
                "FunctionName": "etl-launcher",
                "UserParameters": user_parameters,
            },
        }],
    })
}

/// Create the fixture pipeline and answer the structure `GetPipeline` reports for it.
async fn created(emulator: &Emulator, name: &str) -> Value {
    emulator
        .ok("CreatePipeline", &json!({"pipeline": fixture(name)}))
        .await;
    let read = emulator.ok("GetPipeline", &json!({"name": name})).await;
    read["pipeline"].clone()
}

/// A structure with `member` removed from its top level.
fn without(declaration: &Value, member: &str) -> Value {
    let mut stripped = declaration.clone();
    stripped
        .as_object_mut()
        .expect("a declaration is an object")
        .remove(member);
    stripped
}

/// One row of the no-op table: how an unchanged structure is re-submitted, given the
/// structure a read answered and the one the create sent.
type Resubmission = fn(&Value, &Value) -> Value;

/// One row of the changed table: the single edit it applies to the stored structure.
type Edit = fn(&mut Value);

/// Every re-submission of the structure a pipeline ALREADY has is accepted and moves
/// nothing: not the version it answers, not the version a later read reports, not the
/// structure stored, not the instant the pipeline was last updated at — and no second
/// version is stored for a read to address.
#[tokio::test]
async fn a_write_that_submits_the_stored_structure_advances_nothing() {
    // (case, how the unchanged structure is re-submitted, given the structure the read
    // answered and the one the create sent)
    let rows: Vec<(&str, Resubmission)> = vec![
        // Byte-identical to what the read answered: the normal shape of an idempotent
        // re-apply (read the definition, send it back).
        ("the declaration GetPipeline answered", |read, _sent| {
            read.clone()
        }),
        // The structure the CREATE sent, which leaves out the members the service fills in
        // for an action (its run order, its empty artifact lists).
        ("the declaration the create sent", |_read, sent| sent.clone()),
        // The read-back structure with each member the SERVICE resolves left out, so the
        // service resolves them again — to the same values, which is no change.
        ("the read-back declaration without its version", |read, _sent| {
            without(read, "version")
        }),
        (
            "the read-back declaration without its pipelineType",
            |read, _sent| without(read, "pipelineType"),
        ),
        (
            "the read-back declaration without its executionMode",
            |read, _sent| without(read, "executionMode"),
        ),
        // The version is the SERVICE's own number, so one the request made up says nothing
        // about whether the structure differs.
        ("a declaration carrying a version the pipeline never had", |read, _sent| {
            let mut sent = read.clone();
            sent["version"] = json!(99);
            sent
        }),
    ];

    for (case, resubmit) in rows {
        let emulator = Emulator::new();
        let stored = created(&emulator, "demo").await;
        let before = emulator.ok("GetPipeline", &json!({"name": "demo"})).await;

        let sent = resubmit(&stored, &fixture("demo"));
        let answered = emulator
            .ok("UpdatePipeline", &json!({"pipeline": sent}))
            .await;
        assert_eq!(
            answered["pipeline"], stored,
            "case {case:?}: a write of the stored structure must answer with that structure \
             unchanged, got {answered}"
        );
        assert_eq!(
            answered["pipeline"]["version"],
            json!(1),
            "case {case:?}: nothing changed, so the version must stay 1, got {answered}"
        );

        let after = emulator.ok("GetPipeline", &json!({"name": "demo"})).await;
        assert_eq!(
            after["pipeline"], before["pipeline"],
            "case {case:?}: a later read must report the same structure, got {after}"
        );
        assert_eq!(
            after["metadata"]["updated"], before["metadata"]["updated"],
            "case {case:?}: nothing changed, so the last-updated instant must not move, got \
             {after}"
        );
        let (status, code) = emulator
            .expect_error("GetPipeline", &json!({"name": "demo", "version": 2}))
            .await;
        assert_eq!(
            (status, code.as_str()),
            (400, "PipelineVersionNotFoundException"),
            "case {case:?}: a write that changed nothing stores no second version"
        );

        // The summary every other reader of the stored pipeline answers with follows the
        // same number.
        let listed = emulator.ok("ListPipelines", &json!({})).await;
        assert_eq!(
            listed["pipelines"][0]["version"],
            json!(1),
            "case {case:?}: the summary must report the version the pipeline is at, got \
             {listed}"
        );
    }
}

/// A write that really DOES change the structure advances the version by exactly one, and
/// only the member the row edited differs from what was stored.
///
/// The rows differ along which member of the structure the one edit touches: an action's
/// configuration value, the configuration DOCUMENT an invoke action carries, the stage list,
/// the artifact store, the role, the V2 parameter lists, and an action's run order.
#[tokio::test]
async fn a_write_that_changes_the_structure_advances_the_version_by_one() {
    // (case, the one edit applied to the structure the read answered)
    let rows: Vec<(&str, Edit)> = vec![
        ("a build action's configuration value", |sent| {
            sent["stages"][1]["actions"][0]["configuration"]["ProjectName"] =
                json!("project-renamed");
        }),
        ("the invoke action's UserParameters document", |sent| {
            sent["stages"][2]["actions"][0]["configuration"]["UserParameters"] =
                json!("{\"mode\":\"incremental\",\"retries\":2}");
        }),
        ("a stage added", |sent| {
            let added = build_stage("Test", 1);
            sent["stages"]
                .as_array_mut()
                .expect("stages is a list")
                .push(added);
        }),
        ("a stage removed", |sent| {
            sent["stages"]
                .as_array_mut()
                .expect("stages is a list")
                .pop();
        }),
        ("the artifact store's location", |sent| {
            sent["artifactStore"]["location"] = json!("another-bucket");
        }),
        ("the role the pipeline runs as", |sent| {
            sent["roleArn"] = json!("arn:aws:iam::123456789012:role/service-role/other");
        }),
        ("a pipeline variable added", |sent| {
            sent["variables"] = json!([{"name": "Env", "defaultValue": "test"}]);
        }),
        ("an action's run order", |sent| {
            sent["stages"][1]["actions"][0]["runOrder"] = json!(2);
        }),
        ("an output artifact added to an action", |sent| {
            sent["stages"][1]["actions"][0]["outputArtifacts"] = json!([{"name": "BuildOut"}]);
        }),
    ];

    for (case, edit) in rows {
        let emulator = Emulator::new();
        let stored = created(&emulator, "demo").await;

        let mut sent = stored.clone();
        edit(&mut sent);
        assert_ne!(
            sent, stored,
            "case {case:?}: the row must really edit the structure"
        );

        let answered = emulator
            .ok("UpdatePipeline", &json!({"pipeline": sent}))
            .await;
        assert_eq!(
            answered["pipeline"]["version"],
            json!(2),
            "case {case:?}: a changed structure must be stored at the next version, got \
             {answered}"
        );
        let updated = answered["pipeline"].clone();

        // Only the edited member differs: comparing the two structures with the version
        // equalised is what makes "only that field changed" strict.
        let mut edited_at_version_one = updated.clone();
        edited_at_version_one["version"] = json!(1);
        let mut expected = stored.clone();
        edit(&mut expected);
        // A stage the row ADDED is sent in the form a client writes it, so the structure it
        // is expected to be stored in is that one read through the projection every report
        // of a declaration takes (`reported_stages`).
        expected["stages"] = reported_stages(&expected);
        assert_eq!(
            edited_at_version_one, expected,
            "case {case:?}: the stored structure must be the stored one with the row's edit \
             applied and nothing else, got {updated}"
        );

        let after = emulator.ok("GetPipeline", &json!({"name": "demo"})).await;
        assert_eq!(
            after["pipeline"], updated,
            "case {case:?}: a later read must report the changed structure, got {after}"
        );

        // And the change having landed, re-submitting it again changes nothing: the version
        // stays where the real edit left it.
        let again = emulator
            .ok("UpdatePipeline", &json!({"pipeline": updated}))
            .await;
        assert_eq!(
            again["pipeline"]["version"],
            json!(2),
            "case {case:?}: re-submitting the structure now stored must not advance the \
             version, got {again}"
        );
        let (status, code) = emulator
            .expect_error("GetPipeline", &json!({"name": "demo", "version": 3}))
            .await;
        assert_eq!(
            (status, code.as_str()),
            (400, "PipelineVersionNotFoundException"),
            "case {case:?}: only the real change stored a new version"
        );
    }
}

/// The two halves of the rule in one sequence: a no-op write, then a real edit, then the
/// no-op write of the edited structure — the version is 1, 2, 2, and every version stored
/// keeps the structure it was stored with.
#[tokio::test]
async fn the_version_counts_changes_rather_than_calls() {
    let emulator = Emulator::new();
    let at_one = created(&emulator, "demo").await;

    for repeat in 1..=3u32 {
        let answered = emulator
            .ok("UpdatePipeline", &json!({"pipeline": at_one}))
            .await;
        assert_eq!(
            answered["pipeline"]["version"],
            json!(1),
            "repeat {repeat}: no write changed anything, so the version must still be 1, got \
             {answered}"
        );
    }

    let mut edited = at_one.clone();
    edited["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"] = json!("release.zip");
    let answered = emulator
        .ok("UpdatePipeline", &json!({"pipeline": edited}))
        .await;
    let at_two = answered["pipeline"].clone();
    assert_eq!(
        at_two["version"],
        json!(2),
        "the one real edit must advance the version to 2, got {at_two}"
    );

    for repeat in 1..=3u32 {
        let answered = emulator
            .ok("UpdatePipeline", &json!({"pipeline": at_two}))
            .await;
        assert_eq!(
            answered["pipeline"]["version"],
            json!(2),
            "repeat {repeat}: the edited structure is the stored one, so the version must \
             stay 2, got {answered}"
        );
    }

    // Both versions are still readable, each with the structure it was stored with.
    for (version, structure) in [(1, &at_one), (2, &at_two)] {
        let read = emulator
            .ok("GetPipeline", &json!({"name": "demo", "version": version}))
            .await;
        assert_eq!(
            read["pipeline"], *structure,
            "version {version} must still read the structure stored at it, got {read}"
        );
    }
}
