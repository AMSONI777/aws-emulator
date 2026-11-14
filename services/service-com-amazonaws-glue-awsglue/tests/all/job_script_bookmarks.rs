// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for what a Glue job run's script READS out of Amazon S3: which objects
//! under the paths it was given, and which of them a run with the JOB BOOKMARK enabled has
//! not processed yet.
//!
//! Every call goes over the wire through the shared [`crate::wire`] harness; the scripts and
//! the source objects are staged through Amazon S3's own `PutObject`, and what each run read
//! is read back out of the object the script itself wrote. So what is asserted is HTTP
//! behaviour over state the data plane really holds.
//!
//! Two rules are under test.
//!
//! * A read of Amazon S3 paths descends the sub-prefixes under them only when its connection
//!   options ask it to (`"recurse"`), and takes only the objects at the paths' own level
//!   otherwise.
//! * A run whose `--job-bookmark-option` enables the bookmark reads, for each transformation
//!   context, only the source objects modified after the point the last COMMITTED run of that
//!   job recorded — `job.commit()` is what advances it — while a run the option pauses or
//!   disables reads every object under its paths; `ResetJobBookmark` drops the point, so the
//!   next run reads them all again, and the entry it answers reports an empty position and a
//!   run counter past the last run's rather than a rewound one.
//!
//! The recorded case — a job over a prefix read with `{"recurse": True}`, run once, then run
//! again after one further object was added, then reset and run again — is one row of each
//! table below.
//!
//! Every run is read back until it has come to rest ([`crate::job_runs::run_at_rest`]), with
//! the span the clock owes it made due through the store rather than slept out, so no
//! assertion here depends on how fast the host runs.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::job_script_execution::{
    create_bucket, emulator_with_s3, object_body, run_to_rest, stage_script, BUCKET, ROLE_ARN,
    SCRIPTS,
};
use crate::wire::ok;

/// The transformation context the suite's reads are named under, which is what the bookmark's
/// resume point is keyed by.
const CONTEXT: &str = "source";

/// A script that reads the objects under one path and writes the ids it read, sorted, as the
/// object its `--output` argument names — so what one run really read is readable from the
/// object store.
///
/// `--recurse` says how the read asks to descend sub-prefixes: a client names that option
/// either as a boolean or as its text, so the sentinels pick which form reaches the reader,
/// and `absent` leaves the option off altogether.
const READS_A_PATH: &str = r#"
import json
import sys

import boto3
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext

args = getResolvedOptions(
    sys.argv, ["JOB_NAME", "bucket", "source", "output", "recurse", "context"]
)
options = {"paths": ["s3://%s/%s" % (args["bucket"], args["source"])]}
asked = args["recurse"]
if asked == "true-flag":
    options["recurse"] = True
elif asked == "false-flag":
    options["recurse"] = False
elif asked != "absent":
    options["recurse"] = asked

glue_context = GlueContext(SparkContext())
job = Job(glue_context)
job.init(args["JOB_NAME"], args)
frame = glue_context.create_dynamic_frame.from_options(
    connection_type="s3",
    connection_options=options,
    format="csv",
    format_options={"withHeader": True},
    transformation_ctx=args["context"],
)
ids = sorted(str(row.asDict().get("id")) for row in frame.toDF().collect())
boto3.client("s3").put_object(
    Bucket=args["bucket"], Key=args["output"], Body=json.dumps(ids).encode("utf-8")
)
job.commit()
"#;

/// Store `body` as the object `key` of the suite's bucket. The staging seam is the shared
/// one ([`stage_script`]): an object is an object, whether a script or a row of source data.
async fn stage_object(router: &MultiServiceRouter, key: &str, body: &str) {
    stage_script(router, key, body).await;
}

/// One CSV object holding a single row under the header, whose `id` is `id`.
fn one_row(id: u32) -> String {
    format!("id,city\n{id},Berlin\n")
}

/// Create a job over `script` with `defaults` as its `DefaultArguments`.
async fn create_job(
    router: &MultiServiceRouter,
    name: &str,
    location: &str,
    defaults: Value,
) {
    ok(
        router,
        "CreateJob",
        &json!({
            "Name": name,
            "Role": ROLE_ARN,
            "Command": {
                "Name": "glueetl",
                "PythonVersion": "3",
                "ScriptLocation": location,
            },
            "GlueVersion": "4.0",
            "WorkerType": "G.1X",
            "NumberOfWorkers": 2,
            "Timeout": 5,
            "DefaultArguments": defaults,
            "ExecutionProperty": { "MaxConcurrentRuns": 5 },
        }),
    )
    .await;
}

/// The ids one run read, out of the object its script wrote — after asserting the run came to
/// rest having succeeded, so a stale object can never be read as this run's answer.
async fn ids_read(
    router: &MultiServiceRouter,
    engine: &std::sync::Arc<engine::InMemoryEngine>,
    case: &str,
    job_name: &str,
    output: &str,
) -> Vec<String> {
    let run = run_to_rest(router, engine, job_name, &json!({ "--output": output })).await;
    assert_eq!(
        run.get("JobRunState").and_then(Value::as_str),
        Some("SUCCEEDED"),
        "case {case:?}: the run must come to rest having succeeded, got {run}"
    );
    let written = object_body(router, output)
        .await
        .unwrap_or_else(|| panic!("case {case:?}: the script must have written {output:?}"));
    serde_json::from_str::<Vec<String>>(&written)
        .unwrap_or_else(|_| panic!("case {case:?}: the script writes a JSON list, got {written:?}"))
}

/// A read of Amazon S3 paths takes the objects at those paths' own level, and descends the
/// sub-prefixes under them only when its connection options ask it to.
///
/// The rows differ along the form the `recurse` option takes — absent, the boolean either
/// way, and the text a client may name it as, in either case — which is the whole span of
/// what a client can pass for it.
#[tokio::test]
async fn a_path_read_descends_sub_prefixes_only_when_it_is_asked_to() {
    // (case, what the --recurse argument asks for, the ids the read must take)
    let rows: [(&str, &str, &[&str]); 5] = [
        ("no recurse option at all", "absent", &["1"]),
        ("recurse as the boolean false", "false-flag", &["1"]),
        ("recurse as the boolean true", "true-flag", &["1", "2"]),
        ("recurse as the text 'true'", "true", &["1", "2"]),
        ("recurse as the text 'False'", "False", &["1"]),
    ];

    let (router, engine) = emulator_with_s3();
    create_bucket(&router).await;

    for (index, (case, asked, expected)) in rows.into_iter().enumerate() {
        let name = format!("recurse-{index}");
        let source = format!("data/{name}/");
        // One object at the path's own level, and one in a sub-prefix under it.
        stage_object(&router, &format!("{source}part-0.csv"), &one_row(1)).await;
        stage_object(&router, &format!("{source}nested/part-0.csv"), &one_row(2)).await;
        let location = stage_script(&router, &format!("{SCRIPTS}{name}.py"), READS_A_PATH).await;
        create_job(
            &router,
            &name,
            &location,
            json!({
                "--bucket": BUCKET,
                "--source": source,
                "--recurse": asked,
                "--context": CONTEXT,
            }),
        )
        .await;

        let output = format!("read/{name}.json");
        let read = ids_read(&router, &engine, case, &name, &output).await;
        assert_eq!(
            read,
            expected.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
            "case {case:?}: expected the read to take {expected:?}, got {read:?}"
        );
    }
}

/// What one arm of the bookmark table expects of its three runs.
#[derive(Debug)]
struct Arm {
    /// What makes the arm recognisable in an assertion.
    case: &'static str,
    /// The `--job-bookmark-option` the job names, and `None` for a job that names none.
    option: Option<&'static str>,
    /// The ids the FIRST run reads, over the two objects staged before it.
    first: &'static [&'static str],
    /// The ids the SECOND run reads, once a third object has been added.
    second: &'static [&'static str],
    /// Whether the bookmark holds a resume point once that second run has committed.
    holds_a_point: bool,
}

/// A run with the bookmark enabled reads only the objects that are new to its transformation
/// context, a reset makes the next run read them all again, and a run the bookmark is paused
/// or disabled for reads every object every time.
///
/// The rows are the three values the option documents, plus the job that names none — and
/// each is driven over the same three rounds: a first run over two objects, a second after a
/// third object was added, and a third after `ResetJobBookmark`. The bookmark the control
/// plane reports is read back beside it, so the position each arm leaves is the one
/// `GetJobBookmark` answers.
#[tokio::test]
async fn a_bookmarked_run_reads_only_what_is_new_and_a_reset_reprocesses_everything() {
    let arms: [Arm; 4] = [
        Arm {
            case: "the bookmark enabled",
            option: Some("job-bookmark-enable"),
            first: &["1", "2"],
            second: &["3"],
            holds_a_point: true,
        },
        Arm {
            case: "the bookmark paused",
            option: Some("job-bookmark-pause"),
            first: &["1", "2"],
            second: &["1", "2", "3"],
            holds_a_point: false,
        },
        Arm {
            case: "the bookmark disabled",
            option: Some("job-bookmark-disable"),
            first: &["1", "2"],
            second: &["1", "2", "3"],
            holds_a_point: false,
        },
        Arm {
            case: "a job that names no bookmark option",
            option: None,
            first: &["1", "2"],
            second: &["1", "2", "3"],
            holds_a_point: false,
        },
    ];

    let (router, engine) = emulator_with_s3();
    create_bucket(&router).await;

    for (index, arm) in arms.iter().enumerate() {
        let name = format!("bookmark-{index}");
        let source = format!("delta/{name}/");
        stage_object(&router, &format!("{source}part-0.csv"), &one_row(1)).await;
        stage_object(&router, &format!("{source}part-1.csv"), &one_row(2)).await;
        let location = stage_script(&router, &format!("{SCRIPTS}{name}.py"), READS_A_PATH).await;
        let mut defaults = json!({
            "--bucket": BUCKET,
            "--source": source,
            "--recurse": "true-flag",
            "--context": CONTEXT,
        });
        if let Some(option) = arm.option {
            defaults["--job-bookmark-option"] = json!(option);
        }
        create_job(&router, &name, &location, defaults).await;

        // Round one: every object staged so far.
        let first = ids_read(
            &router,
            &engine,
            arm.case,
            &name,
            &format!("read/{name}-1.json"),
        )
        .await;
        assert_eq!(
            first,
            arm.first.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
            "case {:?}: the first run reads {:?}, got {first:?}",
            arm.case,
            arm.first
        );

        // Round two: one further object, which is all a bookmarked run has left to read.
        stage_object(&router, &format!("{source}part-2.csv"), &one_row(3)).await;
        let second = ids_read(
            &router,
            &engine,
            arm.case,
            &name,
            &format!("read/{name}-2.json"),
        )
        .await;
        assert_eq!(
            second,
            arm.second
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
            "case {:?}: the second run reads {:?}, got {second:?}",
            arm.case,
            arm.second
        );

        // What the control plane reports of the position those runs left.
        let entry = ok(&router, "GetJobBookmark", &json!({ "JobName": name })).await;
        assert_eq!(
            entry["JobBookmarkEntry"]["JobBookmark"].is_null(),
            !arm.holds_a_point,
            "case {:?}: expected the bookmark to hold a position: {}, got {entry}",
            arm.case,
            arm.holds_a_point
        );
        let counted = entry["JobBookmarkEntry"]["Run"].as_i64().unwrap_or_default();

        // Round three: the reset drops the position, so every object is read again.
        let reset = ok(&router, "ResetJobBookmark", &json!({ "JobName": name })).await;
        assert_eq!(
            reset["JobBookmarkEntry"]["JobBookmark"].as_str(),
            Some(""),
            "case {:?}: a reset leaves an empty position for the next run to resume from, got \
             {reset}",
            arm.case
        );
        let after_reset = reset["JobBookmarkEntry"]["Run"].as_i64().unwrap_or_default();
        assert!(
            after_reset > counted,
            "case {:?}: the run counter is monotonic across a reset, so the reset entry \
             reports a count past {counted}, got {reset}",
            arm.case
        );
        let third = ids_read(
            &router,
            &engine,
            arm.case,
            &name,
            &format!("read/{name}-3.json"),
        )
        .await;
        assert_eq!(
            third,
            vec!["1".to_string(), "2".to_string(), "3".to_string()],
            "case {:?}: after a reset every object is read again, got {third:?}",
            arm.case
        );
    }
}
