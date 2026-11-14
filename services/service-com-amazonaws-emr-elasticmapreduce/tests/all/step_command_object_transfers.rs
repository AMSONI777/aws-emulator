// SPDX-License-Identifier: CC0-1.0

//! A step's command line carries its FILES to and from Amazon S3, end to end over the wire.
//!
//! THE RULE: "command-runner.jar … lets you run commands on your cluster" (Amazon EMR
//! documentation) and "for a step to be considered complete, the main function must exit with
//! a zero exit code" (`AddJobFlowSteps` doc) — so a `command-runner.jar` step's arguments are
//! a command line, the transfers that command line asks for between the cluster and Amazon S3
//! are really made against this account's object store, and the step ends in the status the
//! command exited with. A command whose transfer the store refused exits non-zero and FAILS
//! its step; a command line this emulator performs nothing of keeps the failure that says its
//! work was not run, never a `COMPLETED` for a transfer nothing made.
//!
//! The rows span what the rule generalises over: the DIRECTION of the transfer (a local file
//! up, an object down, one object to another), the command (`cp`, `mv`, `rm`), the form the
//! command line arrives in (a shell program after `-c`, the step's own argument list), whether
//! the source exists at the end it is named at, whether the bucket exists, and a command of
//! the CLI this emulator performs nothing of.
//!
//! Amazon S3 is mounted BESIDE Amazon EMR on one engine, every object a row reads is written
//! through S3's own `CreateBucket`/`PutObject`, and every object a row asserts is read back
//! through `GetObject` or `HeadObject` — so what a step wrote is a real object of the store
//! rather than anything this suite handed Amazon EMR.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use service_com_amazonaws_emr_elasticmapreduce::state::{
    COMMAND_FAILED_REASON, STEP_NOT_EXECUTED_REASON,
};
use smithy_server_runtime::MultiServiceRouter;

/// The Region both services are addressed in: the one whose `CreateBucket` needs no location
/// constraint in its body.
const REGION: &str = "us-east-1";

/// The bucket every transfer of this suite reads from and writes to.
const BUCKET: &str = "emr-step-transfers";

/// A bucket nothing ever creates, for the row whose destination does not exist.
const ABSENT_BUCKET: &str = "emr-step-transfers-absent";

/// The roles a launch names.
const INSTANCE_PROFILE: &str = "EMR_EC2_DefaultRole";
const SERVICE_ROLE: &str = "EMR_DefaultRole";

/// How long a poll waits for a step or a cluster to settle: both provisioning phases, the
/// step's own span and one command's transfers, with room to spare.
const DEADLINE: Duration = Duration::from_secs(90);

/// How long a poll sleeps between reads.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The states a step never leaves (`com.amazonaws.emr#StepState`).
const TERMINAL: [&str; 4] = ["COMPLETED", "CANCELLED", "FAILED", "INTERRUPTED"];

/// The states a cluster never leaves (`com.amazonaws.emr#ClusterState`).
const TERMINAL_CLUSTER: [&str; 2] = ["TERMINATED", "TERMINATED_WITH_ERRORS"];

/// Amazon EMR and Amazon S3 on one engine, the shape the router mounts them in.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_emr_elasticmapreduce::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
        Arc::clone(&engine),
    ));
    router
}

/// One `awsJson1_1` Amazon EMR call that must be served.
async fn emr_ok(router: &MultiServiceRouter, operation: &str, body: Value) -> Value {
    let host = format!("elasticmapreduce.{REGION}.amazonaws.com");
    let request = ::http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", host)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", format!("ElasticMapReduce.{operation}"))
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=emulator-test-key/20261109/{REGION}/\
                 elasticmapreduce/aws4_request, SignedHeaders=host, Signature=00"
            ),
        )
        .body(bytes::Bytes::from(
            serde_json::to_vec(&body).expect("the request body serializes"),
        ))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload: Value = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    assert_eq!(
        status, 200,
        "{operation} must answer 200, got {status} with {payload}"
    );
    payload
}

/// What one Amazon S3 request answered.
struct Answered {
    status: u16,
    /// The `Content-Length` it reported, which is the only place a `HEAD` answer carries the
    /// object's size.
    length: Option<String>,
    body: Vec<u8>,
}

/// One path-style Amazon S3 request.
async fn s3(router: &MultiServiceRouter, method: &str, uri: &str, body: &[u8]) -> Answered {
    let host = format!("s3.{REGION}.amazonaws.com");
    let request = ::http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{uri}"))
        .header("host", host.clone())
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=emulator-test-key/20261109/{REGION}/s3/\
                 aws4_request, SignedHeaders=host, Signature=00"
            ),
        )
        .body(bytes::Bytes::copy_from_slice(body))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let (parts, answered) = response.into_parts();
    Answered {
        status: parts.status.as_u16(),
        length: parts
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        body: answered.to_vec(),
    }
}

/// Create `bucket`, which must be served.
async fn create_bucket(router: &MultiServiceRouter, bucket: &str) {
    let answered = s3(router, "PUT", &format!("/{bucket}"), &[]).await;
    assert!(
        (200..300).contains(&answered.status),
        "CreateBucket {bucket} must succeed, got {} {}",
        answered.status,
        String::from_utf8_lossy(&answered.body)
    );
}

/// Put `body` at `key`, which must be served.
async fn put_object(router: &MultiServiceRouter, case: &str, key: &str, body: &[u8]) {
    let answered = s3(router, "PUT", &format!("/{BUCKET}/{key}"), body).await;
    assert!(
        (200..300).contains(&answered.status),
        "case {case:?}: PutObject {key} must succeed, got {} {}",
        answered.status,
        String::from_utf8_lossy(&answered.body)
    );
}

/// The object at `key`, or `None` when the store holds none.
async fn object(router: &MultiServiceRouter, key: &str) -> Option<String> {
    let answered = s3(router, "GET", &format!("/{BUCKET}/{key}"), &[]).await;
    (200..300)
        .contains(&answered.status)
        .then(|| String::from_utf8_lossy(&answered.body).to_string())
}

/// What `HeadObject` answers for `key`.
async fn head_object(router: &MultiServiceRouter, key: &str) -> Answered {
    s3(router, "HEAD", &format!("/{BUCKET}/{key}"), &[]).await
}

/// What a row expects its step to end as.
enum Ends {
    /// The command exited zero: the step completed.
    Completed,
    /// The command exited non-zero: the step failed with the reason a command's own non-zero
    /// status carries.
    CommandFailed,
    /// The command line is one this emulator performs nothing of: the step keeps the failure
    /// that says its work was not run.
    NotExecuted,
}

/// One row: the command line the step submits, the end it must reach, and what the store must
/// hold afterwards.
struct Case {
    label: &'static str,
    /// The step's `Args`, as the command line arrives.
    args: Vec<String>,
    ends: Ends,
    /// `(key, contents)` the store must hold once the step has ended.
    holds: Vec<(String, String)>,
    /// Keys the store must hold NOTHING under once the step has ended.
    holds_nothing: Vec<String>,
}

/// A command line wrapped in a shell program, which is the form the CLI's `--steps` writes.
fn shell(program: &str) -> Vec<String> {
    vec!["bash".to_string(), "-c".to_string(), program.to_string()]
}

/// A command line as the step's own argument list, with no shell at all — the words of
/// `line`, which carries no quoting of its own.
fn argv(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_string).collect()
}

/// The objects this suite seeds before any cluster is launched: `(key, contents)`.
fn seeded() -> Vec<(&'static str, &'static str)> {
    vec![
        ("in/seed.txt", "seeded bytes\n"),
        ("in/copied.txt", "copied bytes\n"),
        ("in/moved.txt", "moved bytes\n"),
        ("in/removed.txt", "removed bytes\n"),
    ]
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            label: "a file the command wrote, uploaded",
            args: shell(&format!(
                "echo hello > /tmp/out.txt && aws s3 cp /tmp/out.txt s3://{BUCKET}/output/out.txt"
            )),
            ends: Ends::Completed,
            holds: vec![("output/out.txt".to_string(), "hello\n".to_string())],
            holds_nothing: Vec::new(),
        },
        Case {
            label: "an object downloaded, read back and uploaded again",
            args: shell(&format!(
                "aws s3 cp s3://{BUCKET}/in/seed.txt /tmp/seed.txt && \
                 cat /tmp/seed.txt > /tmp/again.txt && \
                 aws s3 cp /tmp/again.txt s3://{BUCKET}/roundtrip/seed.txt"
            )),
            ends: Ends::Completed,
            holds: vec![(
                "roundtrip/seed.txt".to_string(),
                "seeded bytes\n".to_string(),
            )],
            holds_nothing: Vec::new(),
        },
        Case {
            label: "one object copied to another, as the step's own argument list",
            args: argv(&format!(
                "aws s3 cp s3://{BUCKET}/in/copied.txt s3://{BUCKET}/copies/copied.txt"
            )),
            ends: Ends::Completed,
            holds: vec![
                ("copies/copied.txt".to_string(), "copied bytes\n".to_string()),
                // A copy leaves the source where it was.
                ("in/copied.txt".to_string(), "copied bytes\n".to_string()),
            ],
            holds_nothing: Vec::new(),
        },
        Case {
            label: "one object moved to another, which takes the source away",
            args: argv(&format!(
                "aws s3 mv s3://{BUCKET}/in/moved.txt s3://{BUCKET}/moves/moved.txt"
            )),
            ends: Ends::Completed,
            holds: vec![("moves/moved.txt".to_string(), "moved bytes\n".to_string())],
            holds_nothing: vec!["in/moved.txt".to_string()],
        },
        Case {
            label: "an object removed",
            args: argv(&format!("aws s3 rm s3://{BUCKET}/in/removed.txt")),
            ends: Ends::Completed,
            holds: Vec::new(),
            holds_nothing: vec!["in/removed.txt".to_string()],
        },
        Case {
            label: "a source object the bucket holds nothing under",
            args: shell(&format!(
                "aws s3 cp s3://{BUCKET}/in/absent.txt /tmp/absent.txt"
            )),
            ends: Ends::CommandFailed,
            holds: Vec::new(),
            holds_nothing: Vec::new(),
        },
        Case {
            label: "a local path the command never wrote",
            args: shell(&format!(
                "aws s3 cp /tmp/never-written.txt s3://{BUCKET}/output/never.txt"
            )),
            ends: Ends::CommandFailed,
            holds: Vec::new(),
            holds_nothing: vec!["output/never.txt".to_string()],
        },
        Case {
            label: "a destination bucket that does not exist",
            args: shell(&format!(
                "echo stranded > /tmp/stranded.txt && \
                 aws s3 cp /tmp/stranded.txt s3://{ABSENT_BUCKET}/output/stranded.txt"
            )),
            ends: Ends::CommandFailed,
            holds: Vec::new(),
            holds_nothing: Vec::new(),
        },
        Case {
            label: "a command of the CLI this emulator performs nothing of",
            args: shell(&format!("aws s3 sync /tmp s3://{BUCKET}/synced")),
            ends: Ends::NotExecuted,
            holds: Vec::new(),
            holds_nothing: vec!["synced/out.txt".to_string()],
        },
    ]
}

/// The `StepConfig` one row submits.
fn step_config(case: &Case) -> Value {
    json!({
        "Name": case.label,
        "ActionOnFailure": "CONTINUE",
        "HadoopJarStep": { "Jar": "command-runner.jar", "Args": case.args },
    })
}

/// A cluster launched with `steps`, kept alive or auto-terminating.
async fn launch(router: &MultiServiceRouter, name: &str, steps: Value, kept_alive: bool) -> String {
    let launched = emr_ok(
        router,
        "RunJobFlow",
        json!({
            "Name": name,
            "ReleaseLabel": "emr-7.9.0",
            "JobFlowRole": INSTANCE_PROFILE,
            "ServiceRole": SERVICE_ROLE,
            "Applications": [{ "Name": "Hadoop" }],
            "Steps": steps,
            "Instances": {
                "InstanceCount": 1,
                "MasterInstanceType": "m5.xlarge",
                "KeepJobFlowAliveWhenNoSteps": kept_alive,
            },
        }),
    )
    .await;
    launched["JobFlowId"]
        .as_str()
        .expect("RunJobFlow answers a JobFlowId")
        .to_string()
}

/// Poll `ListSteps` until every step of `cluster_id` is terminal, answering them in submission
/// order.
async fn drained(case: &str, router: &MultiServiceRouter, cluster_id: &str) -> Vec<Value> {
    let started = Instant::now();
    loop {
        let listed = emr_ok(router, "ListSteps", json!({ "ClusterId": cluster_id })).await;
        let mut steps: Vec<Value> = listed["Steps"].as_array().cloned().unwrap_or_default();
        steps.reverse();
        let states: Vec<String> = steps
            .iter()
            .map(|step| {
                step["Status"]["State"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        if !states.is_empty() && states.iter().all(|state| TERMINAL.contains(&state.as_str())) {
            return steps;
        }
        assert!(
            started.elapsed() < DEADLINE,
            "case {case:?}: expected every step to reach a terminal state, got {states:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `DescribeCluster` until the cluster is terminal, answering it as last read.
async fn stopped(case: &str, router: &MultiServiceRouter, cluster_id: &str) -> Value {
    let started = Instant::now();
    loop {
        let cluster = emr_ok(router, "DescribeCluster", json!({ "ClusterId": cluster_id })).await
            ["Cluster"]
            .clone();
        let state = cluster["Status"]["State"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if TERMINAL_CLUSTER.contains(&state.as_str()) {
            return cluster;
        }
        assert!(
            started.elapsed() < DEADLINE,
            "case {case:?}: expected the cluster to stop, got {state:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Every row: the step ends in the status its command exited with, and the transfer that
/// command asked for is a real change to the object store.
#[tokio::test]
async fn a_steps_command_line_carries_its_files_to_and_from_the_object_store() {
    let router = emulator();
    let cases = cases();

    create_bucket(&router, BUCKET).await;
    for (key, contents) in seeded() {
        put_object(&router, "seed", key, contents.as_bytes()).await;
    }

    // One cluster per row, each kept alive so the step's own end is what is read rather than
    // the cluster's shutdown.
    let mut launched: Vec<String> = Vec::new();
    for case in &cases {
        launched.push(launch(&router, case.label, json!([step_config(case)]), true).await);
    }

    for (case, cluster_id) in cases.iter().zip(&launched) {
        let label = case.label;
        let steps = drained(label, &router, cluster_id).await;
        let step = steps
            .first()
            .unwrap_or_else(|| panic!("case {label:?}: expected the submitted step back"));
        let state = step["Status"]["State"].as_str().unwrap_or_default();
        let reason = step["Status"]["FailureDetails"]["Reason"]
            .as_str()
            .unwrap_or_default();
        match case.ends {
            Ends::Completed => {
                assert_eq!(
                    state, "COMPLETED",
                    "case {label:?}: a command that exited zero completes its step, got {step}"
                );
                assert!(
                    step["Status"]["FailureDetails"].is_null(),
                    "case {label:?}: a completed step reports no failure, got {step}"
                );
            }
            Ends::CommandFailed => {
                assert_eq!(
                    state, "FAILED",
                    "case {label:?}: a command that exited non-zero fails its step, got {step}"
                );
                assert_eq!(
                    reason, COMMAND_FAILED_REASON,
                    "case {label:?}: expected the command's own failure reason, got {step}"
                );
            }
            Ends::NotExecuted => {
                assert_eq!(
                    state, "FAILED",
                    "case {label:?}: a command line nothing performed fails its step, got {step}"
                );
                assert_eq!(
                    reason, STEP_NOT_EXECUTED_REASON,
                    "case {label:?}: expected the not-executed failure, got {step}"
                );
            }
        }
        for (key, expected) in &case.holds {
            let held = object(&router, key).await;
            assert_eq!(
                held.as_deref(),
                Some(expected.as_str()),
                "case {label:?}: expected {key} to hold {expected:?}, got {held:?}"
            );
        }
        for key in &case.holds_nothing {
            let held = object(&router, key).await;
            assert_eq!(
                held, None,
                "case {label:?}: expected the store to hold nothing at {key}, got {held:?}"
            );
        }
    }
}

/// An AUTO-TERMINATING cluster whose one step writes an object: the cluster reaches
/// TERMINATED, and the object the step declared is there, with bytes in it — the step's own
/// side effect, read back through `HeadObject` and `GetObject` after the shutdown.
#[tokio::test]
async fn an_auto_terminating_clusters_step_leaves_its_object_behind() {
    let router = emulator();
    create_bucket(&router, BUCKET).await;

    let label = "an auto-terminating cluster's one command step";
    let cluster_id = launch(
        &router,
        label,
        json!([{
            "Name": "write-output",
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": shell(&format!(
                    "echo hello > /tmp/out.txt && \
                     aws s3 cp /tmp/out.txt s3://{BUCKET}/output/out.txt"
                )),
            },
        }]),
        false,
    )
    .await;

    let cluster = stopped(label, &router, &cluster_id).await;
    assert_eq!(
        cluster["Status"]["State"].as_str(),
        Some("TERMINATED"),
        "case {label:?}: a cluster whose step completed stops cleanly, got {cluster}"
    );

    let head = head_object(&router, "output/out.txt").await;
    assert_eq!(
        head.status, 200,
        "case {label:?}: HeadObject of the key the step wrote must answer 200, got {}",
        head.status
    );
    let reported: usize = head
        .length
        .as_deref()
        .unwrap_or("0")
        .parse()
        .unwrap_or_default();
    assert!(
        reported > 0,
        "case {label:?}: expected a non-empty object, got a reported length of {:?}",
        head.length
    );
    let held = object(&router, "output/out.txt").await;
    assert_eq!(
        held.as_deref(),
        Some("hello\n"),
        "case {label:?}: expected the bytes the step wrote, got {held:?}"
    );
    assert_eq!(
        held.as_deref().map(str::len),
        Some(reported),
        "case {label:?}: HeadObject reports the length the object holds, got {:?}",
        head.length
    );
}
