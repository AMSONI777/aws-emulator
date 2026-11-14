// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for what `CreateApplication` persists BESIDE the application's own
//! launch details, which `tests/all/applications.rs` already pins.
//!
//! Every case drives the awsJson1_1 front door through the shared
//! [`Emulator`](crate::stack_fleet_lifecycle::Emulator) harness, so what is exercised is
//! the dispatch → deserialize → handle → serialize walk.
//!
//! The rules under test, each asserted over a TABLE of inputs rather than over one
//! recorded request:
//!
//! * the `Tags` a CREATE carries are persisted ON the application record, so they are the
//!   one map every later tag call works on: `ListTagsForResource` reports exactly the tags
//!   the create was given, and `UntagResource`/`TagResource` then remove from and add to
//!   that same map. `tests/all/resource_tags.rs` pins the tag operations themselves, on
//!   resources it creates UNTAGGED; what this suite pins is the create's own write, so
//!   the tag class it spans is read from that suite rather than restated here;
//! * a create that carries no `Tags` leaves the application with an empty collection
//!   rather than with nothing to report, and a later write still lands on it;
//! * the application store is bounded like every other store a request can grow, so a
//!   create that would take it past that ceiling is refused with `LimitExceededException`
//!   (HTTP 400) and persists nothing, a name the account already holds is still refused as
//!   a duplicate at the ceiling, and deleting an application makes room again.

use serde_json::{json, Value};

use crate::applications::{application_arn, create_app_block};
use crate::refusal_messages::refusal;
use crate::resource_tags::{listed_tags, numbered_tags, object, MAX_TAGS};
use crate::stack_fleet_lifecycle::{assert_error, Emulator};
use crate::user_stack_associations::limit_sentence;

/// The app block every application below is created against.
const APP_BLOCK: &str = "creation-block";

/// The emulator's per-store memory ceiling, read from the crate so this suite tracks the
/// constant rather than a copy of its value.
const CEILING: usize =
    service_com_amazonaws_appstream_photonadminproxyservice::state::MAX_RECORDS_PER_STORE;

/// The records the application store holds, as the ceiling's refusal sentence names them.
const APPLICATIONS_STORE: &str = "applications";
/// The word AWS's duplicate-name refusal uses for an application.
const APPLICATION_KIND: &str =
    service_com_amazonaws_appstream_photonadminproxyservice::state::APPLICATION_KIND;

/// A `CreateApplication` request for `name` against `app_block_arn`, carrying `tags` when
/// the row has any. Only the required members beside them, so what each row below varies
/// is the tag map and nothing else.
fn create_request(name: &str, app_block_arn: &str, tags: Option<&Value>) -> Value {
    let mut request = json!({
        "Name": name,
        "AppBlockArn": app_block_arn,
        "IconS3Location": { "S3Bucket": "app-icons", "S3Key": "icons/app.png" },
        "LaunchPath": "C:\\Program Files\\App\\app.exe",
        "Platforms": ["WINDOWS_SERVER_2019"],
        "InstanceFamilies": ["GENERAL_PURPOSE"],
    });
    if let Some(tags) = tags {
        request["Tags"] = tags.clone();
    }
    request
}

/// The tag maps a create may carry: the shared class the tag suite already states
/// ([`crate::resource_tags::tag_rows`]), plus the largest map a create may carry —
/// `Tags` is `length 1..50`
/// (`smithy_query(query="operation", operation="CreateApplication")`), so one entry is
/// the smallest and fifty the largest.
fn tag_rows() -> Vec<(&'static str, Value)> {
    let mut rows = crate::resource_tags::tag_rows();
    rows.push((
        "the largest map a create may carry",
        numbered_tags("tag", MAX_TAGS),
    ));
    rows
}

// ---------------------------------------------------------------------------
// The tags a create carries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_tags_a_create_carries_are_the_map_every_later_tag_call_works_on() {
    for (label, tags) in tag_rows() {
        let case = format!("created with {label}");
        let emulator = Emulator::new();
        let app_block_arn = create_app_block(&emulator, &case, APP_BLOCK).await;
        let arn = application_arn("tagged");

        emulator
            .ok(
                &case,
                "CreateApplication",
                create_request("tagged", &app_block_arn, Some(&tags)),
            )
            .await;

        // The create persisted the tags on the application record, so the read reports
        // exactly what the create was given — no more and no fewer.
        let listed = listed_tags(&emulator, &case, &arn).await;
        assert_eq!(
            listed,
            object(&tags),
            "case {case:?}: the create must persist exactly the tags it carried, got \
             {listed:?}"
        );

        // Reading again reports the same tags: the read changed nothing.
        let again = listed_tags(&emulator, &case, &arn).await;
        assert_eq!(
            again, listed,
            "case {case:?}: a read must not change what a later caller sees, got {again:?}"
        );

        // It is ONE map: `UntagResource` removes a key the CREATE wrote, which is only
        // possible if the create wrote into the map the tag operations work on.
        let removed = listed
            .keys()
            .next()
            .expect("every row above carries at least one tag")
            .clone();
        emulator
            .ok(
                &case,
                "UntagResource",
                json!({ "ResourceArn": arn, "TagKeys": [removed.clone()] }),
            )
            .await;
        let mut expected = listed.clone();
        expected.remove(&removed);
        let after_untag = listed_tags(&emulator, &case, &arn).await;
        assert_eq!(
            after_untag, expected,
            "case {case:?}: untagging must remove only {removed:?} from the map the create \
             wrote, got {after_untag:?}"
        );

        // And `TagResource` adds to that same map rather than replacing it.
        emulator
            .ok(
                &case,
                "TagResource",
                json!({ "ResourceArn": arn, "Tags": { "Added": "later" } }),
            )
            .await;
        expected.insert("Added".to_string(), json!("later"));
        let after_tag = listed_tags(&emulator, &case, &arn).await;
        assert_eq!(
            after_tag, expected,
            "case {case:?}: tagging must add to the map the create wrote, got {after_tag:?}"
        );
    }
}

#[tokio::test]
async fn an_application_created_without_tags_reports_an_empty_collection() {
    let case = "created with no Tags member";
    let emulator = Emulator::new();
    let app_block_arn = create_app_block(&emulator, case, APP_BLOCK).await;
    let arn = application_arn("untagged");

    emulator
        .ok(
            case,
            "CreateApplication",
            create_request("untagged", &app_block_arn, None),
        )
        .await;

    let listed = listed_tags(&emulator, case, &arn).await;
    assert!(
        listed.is_empty(),
        "case {case:?}: an application created without tags must report none, got {listed:?}"
    );

    // The untagged application is still a resource tags belong to, so a later write lands
    // on it: the empty collection is "no tags yet", not "no map".
    emulator
        .ok(
            case,
            "TagResource",
            json!({ "ResourceArn": arn, "Tags": { "Environment": "Test" } }),
        )
        .await;
    let listed = listed_tags(&emulator, case, &arn).await;
    assert_eq!(
        listed,
        object(&json!({ "Environment": "Test" })),
        "case {case:?}: a write on an untagged application must land on it, got {listed:?}"
    );
}

// ---------------------------------------------------------------------------
// The application store's ceiling
// ---------------------------------------------------------------------------

/// AWS's `ResourceAlreadyExistsException` sentence for an application name already taken.
fn already_exists_sentence(name: &str) -> String {
    crate::refusal_messages::already_exists_sentence(APPLICATION_KIND, name)
}

/// The name of the `index`-th application the ceiling case fills the store with.
fn filler_name(index: usize) -> String {
    format!("a{index:05}")
}

#[tokio::test]
async fn the_application_store_refuses_a_create_past_its_ceiling() {
    let emulator = Emulator::new();
    let app_block_arn = create_app_block(&emulator, "setup", APP_BLOCK).await;
    for index in 0..CEILING {
        emulator
            .ok(
                "setup",
                "CreateApplication",
                create_request(&filler_name(index), &app_block_arn, None),
            )
            .await;
    }

    // Rows: names that would each be the record past the ceiling. Every one is refused,
    // whatever the name looks like — the store is full, not the name taken.
    for (case, name) in [
        ("a plain name", "one-too-many".to_string()),
        ("a punctuated name", "9over_the.limit-1".to_string()),
        // The longest name the `Name` pattern admits:
        // ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$, so 101 characters.
        ("the longest name a create admits", format!("z{}", "9".repeat(100))),
    ] {
        let message = refusal(
            &emulator,
            case,
            "CreateApplication",
            create_request(&name, &app_block_arn, None),
            400,
            "LimitExceededException",
        )
        .await;
        assert_eq!(
            message,
            limit_sentence(APPLICATIONS_STORE),
            "case {case:?}: expected the sentence naming the account's limit, got {message:?}"
        );

        // The refused create persisted nothing: that name addresses no application.
        assert_error(
            &emulator,
            case,
            "DescribeApplications",
            json!({ "Arns": [application_arn(&name)] }),
            400,
            "ResourceNotFoundException",
        )
        .await;
    }

    // A name the account already holds is still a duplicate at the ceiling: the
    // duplicate check runs first and inserts nothing, so a full store does not turn an
    // already-exists into a limit failure.
    let taken = filler_name(0);
    let message = refusal(
        &emulator,
        "a name already held, at the ceiling",
        "CreateApplication",
        create_request(&taken, &app_block_arn, None),
        400,
        "ResourceAlreadyExistsException",
    )
    .await;
    assert_eq!(
        message,
        already_exists_sentence(&taken),
        "case \"a name already held, at the ceiling\": expected AWS's duplicate-name \
         sentence, got {message:?}"
    );

    // Deleting an application makes room again, so the ceiling is a bound on what the
    // store holds, not a latch that closes the create for good.
    emulator
        .ok("room again", "DeleteApplication", json!({ "Name": taken }))
        .await;
    emulator
        .ok(
            "room again",
            "CreateApplication",
            create_request("one-too-many", &app_block_arn, None),
        )
        .await;
    let (reported, _) = crate::applications::describe(
        &emulator,
        "room again",
        json!({ "Arns": [application_arn("one-too-many")] }),
    )
    .await;
    assert_eq!(
        reported.len(),
        1,
        "case \"room again\": the create that found room must have persisted its \
         application, got {reported:?}"
    );
}
