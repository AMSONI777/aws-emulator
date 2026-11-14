// SPDX-License-Identifier: CC0-1.0

//! What a `DeleteAIBenchmarkJob` release touches, and what it leaves alone.
//!
//! Every case goes over the wire (`POST /` with `X-Amz-Target: SageMaker.<Op>`, `awsJson1_1`)
//! through the same `MultiServiceRouter` the production router uses, so what these tests
//! exercise is what a real SDK client gets. The seeding, the request body and the
//! poll-until-terminal helper are the sibling release suite's
//! (`crate::ai_benchmark_job_release`), so this target keeps ONE copy of each.
//!
//! RULE — a delete releases EXACTLY the job its `AIBenchmarkJobName` names, keyed on the whole
//! name, and reports the `AIBenchmarkJobArn` that job carries in state rather than one rebuilt
//! from the deleting request: every other job the account holds stays readable with its own
//! identity, the resources the released job referenced (its AI workload configuration and its
//! target endpoint) stay readable too, the released name holds nothing afterwards — a read and
//! a second delete of it are both refused `ResourceNotFound` — and the name is free again, so a
//! later create under it is a NEW job carrying a newly minted ARN.
//!
//! The rows span what the rule generalises over: how many jobs the account holds, which of them
//! is released (the first, one in the middle, the last, the only one), the shape of the released
//! name (`AIEntityName`'s published bounds, `len 1..63`, and a name that is a strict prefix of
//! another job's), the Region each create signed for (so the ARN the delete answers is the
//! stored one, not the deleting call's), and how the released job reached a status nothing
//! leaves on its own (a run left to end, or a stop the caller asked for).

use serde_json::json;

use crate::ai_benchmark_job_release::{create_body, seeded, settled_status, ENDPOINT, WORKLOAD_CONFIG};
use crate::inference_deployment_lifecycle::{error_code, message, str_field, ACCOUNT};

/// `AIEntityName`'s published bounds, which `AIBenchmarkJobName` targets
/// (`smithy_query(query="operation",operation="DeleteAIBenchmarkJob")` gives `len 1..63`).
const NAME_MIN_LENGTH: usize = 1;
const NAME_MAX_LENGTH: usize = 63;

/// A name of exactly `length` characters matching `AIEntityName`'s pattern
/// `^[a-zA-Z0-9](-*[a-zA-Z0-9]){0,62}$`: alphanumeric throughout, so every length in the
/// modelled range is admissible.
fn name_of_length(length: usize) -> String {
    let name: String = "ab".repeat(length.div_ceil(2))[..length].to_string();
    assert_eq!(
        name.len(),
        length,
        "case \"name shape\": the generated name must be {length} characters, got {name:?}"
    );
    name
}

/// The ARN a job created under `name` in `region` carries, as `AIBenchmarkJobArn`'s modelled
/// pattern lays it out.
fn job_arn(region: &str, name: &str) -> String {
    format!("arn:aws:sagemaker:{region}:{ACCOUNT}:ai-benchmark-job/{name}")
}

/// The sentence this family refuses an unresolvable benchmark-job reference with, which the
/// delete relays with an inner-service tail carrying a per-run request id — so a case asserts
/// this as the message's leading sentence rather than the whole of it.
fn not_found_sentence(name: &str) -> String {
    format!("AIBenchmarkJob '{name}' not found.")
}

/// One row of the release table.
struct Row {
    case: &'static str,
    /// Every job the account holds for this case, in creation order, each with the Region its
    /// create signs for.
    jobs: Vec<(String, &'static str)>,
    /// Which of `jobs` the delete names.
    released: usize,
    /// Whether the caller stops the released job (reaching `Stopped`) or leaves its run to end
    /// on its own.
    stopped: bool,
    /// The Region the later create of the released name signs for — always one the released job
    /// was not created in, so the re-minted ARN is seen to be a new one.
    recreate_region: &'static str,
}

fn release_rows() -> Vec<Row> {
    vec![
        Row {
            case: "the first of three jobs, left to end, a name on the lower length bound",
            jobs: vec![
                (name_of_length(NAME_MIN_LENGTH), "us-east-1"),
                ("scope-two".to_string(), "us-east-1"),
                ("scope-three".to_string(), "us-east-1"),
            ],
            released: 0,
            stopped: false,
            recreate_region: "eu-west-1",
        },
        Row {
            case: "the middle of three jobs, stopped by the caller, a name on the upper bound",
            jobs: vec![
                ("scope-one".to_string(), "us-east-1"),
                (name_of_length(NAME_MAX_LENGTH), "eu-west-1"),
                ("scope-three".to_string(), "ap-southeast-2"),
            ],
            released: 1,
            stopped: true,
            recreate_region: "us-west-2",
        },
        Row {
            case: "a name that is a strict prefix of two other jobs' names",
            jobs: vec![
                ("scope".to_string(), "ap-southeast-2"),
                ("scope-extra".to_string(), "us-east-1"),
                ("scoped".to_string(), "eu-central-1"),
            ],
            released: 0,
            stopped: false,
            recreate_region: "us-east-1",
        },
        Row {
            case: "the last of two jobs, stopped by the caller",
            jobs: vec![
                ("nightly-latency-benchmark-job".to_string(), "eu-west-1"),
                ("scope-last".to_string(), "eu-central-1"),
            ],
            released: 1,
            stopped: true,
            recreate_region: "ap-southeast-2",
        },
        Row {
            case: "the only job the account holds, left to end",
            jobs: vec![("solo-benchmark-job".to_string(), "us-west-2")],
            released: 0,
            stopped: false,
            recreate_region: "us-east-1",
        },
    ]
}

/// RULE: a delete releases exactly the job it names, reports the ARN that job carried, and
/// leaves every other job and every resource the job referenced alone.
#[tokio::test]
async fn a_delete_releases_only_the_job_it_names() {
    for row in release_rows() {
        let case = row.case;
        let emulator = seeded().await;

        // Every job the account holds for this case, each created in its own Region.
        for (name, region) in &row.jobs {
            let (status, created) = emulator
                .call_in(region, "CreateAIBenchmarkJob", &create_body(name, ENDPOINT))
                .await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected the create of {name} in {region} to answer 200, got \
                 {status} with {created}"
            );
            assert_eq!(
                str_field(&created, "AIBenchmarkJobArn"),
                job_arn(region, name),
                "case {case:?}: the ARN the create of {name} minted, got {created}"
            );
        }

        let (released_name, released_region) = &row.jobs[row.released];
        // Bring the job to a status nothing leaves on its own: either the caller stops it, or
        // its run is left to end. The delete stands behind that gate either way.
        if row.stopped {
            let stopping = emulator
                .ok(
                    "StopAIBenchmarkJob",
                    &json!({ "AIBenchmarkJobName": released_name }),
                )
                .await;
            assert_eq!(
                str_field(&stopping, "AIBenchmarkJobArn"),
                job_arn(released_region, released_name),
                "case {case:?}: the stop answers the stored ARN, got {stopping}"
            );
        }
        let settled = settled_status(&emulator, case, released_name).await;
        if row.stopped {
            assert_eq!(
                settled, "Stopped",
                "case {case:?}: the clock owes a stopping job the Stopped status, got \
                 {settled:?}"
            );
        }

        // The delete signs for us-east-1 whatever Region the job was created in, so the ARN it
        // answers can only have come from state.
        let (status, deleted) = emulator
            .call(
                "DeleteAIBenchmarkJob",
                &json!({ "AIBenchmarkJobName": released_name }),
            )
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected the delete of {released_name} to answer 200, got {status} \
             with {deleted}"
        );
        assert_eq!(
            str_field(&deleted, "AIBenchmarkJobArn"),
            job_arn(released_region, released_name),
            "case {case:?}: the delete must answer the ARN the job carried, got {deleted}"
        );

        // The released name holds nothing: the read and a second delete are both refused.
        let (status, gone) = emulator
            .call(
                "DescribeAIBenchmarkJob",
                &json!({ "AIBenchmarkJobName": released_name }),
            )
            .await;
        assert_eq!(
            (status, error_code(&gone).as_str()),
            (400, "ResourceNotFound"),
            "case {case:?}: the released name must read back as held by nothing, got {status} \
             with {gone}"
        );
        let (status, again) = emulator
            .call(
                "DeleteAIBenchmarkJob",
                &json!({ "AIBenchmarkJobName": released_name }),
            )
            .await;
        assert_eq!(
            (status, error_code(&again).as_str()),
            (400, "ResourceNotFound"),
            "case {case:?}: a second delete must be refused, got {status} with {again}"
        );
        let refusal = message(&again);
        assert!(
            refusal.starts_with(&not_found_sentence(released_name)),
            "case {case:?}: the refusal must state {:?}, got {refusal:?}",
            not_found_sentence(released_name)
        );

        // Every other job the account holds is untouched: still readable, still its own ARN.
        for (index, (name, region)) in row.jobs.iter().enumerate() {
            if index == row.released {
                continue;
            }
            let (status, survived) = emulator
                .call(
                    "DescribeAIBenchmarkJob",
                    &json!({ "AIBenchmarkJobName": name }),
                )
                .await;
            assert_eq!(
                status, 200,
                "case {case:?}: the delete must leave {name} readable, got {status} with \
                 {survived}"
            );
            assert_eq!(
                str_field(&survived, "AIBenchmarkJobName"),
                *name,
                "case {case:?}: {name} must still report its own name, got {survived}"
            );
            assert_eq!(
                str_field(&survived, "AIBenchmarkJobArn"),
                job_arn(region, name),
                "case {case:?}: {name} must still report its own ARN, got {survived}"
            );
        }

        // The resources the released job referenced are not released with it.
        let config = emulator
            .ok(
                "DescribeAIWorkloadConfig",
                &json!({ "AIWorkloadConfigName": WORKLOAD_CONFIG }),
            )
            .await;
        assert_eq!(
            str_field(&config, "AIWorkloadConfigName"),
            WORKLOAD_CONFIG,
            "case {case:?}: the workload configuration must survive the delete, got {config}"
        );
        let endpoint = emulator
            .ok("DescribeEndpoint", &json!({ "EndpointName": ENDPOINT }))
            .await;
        assert_eq!(
            str_field(&endpoint, "EndpointName"),
            ENDPOINT,
            "case {case:?}: the target endpoint must survive the delete, got {endpoint}"
        );

        // The released name is free again, and what a later create puts there is a NEW job:
        // its ARN is minted for the Region that create signed for.
        let recreated = row.recreate_region;
        let (status, created_again) = emulator
            .call_in(
                recreated,
                "CreateAIBenchmarkJob",
                &create_body(released_name, ENDPOINT),
            )
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the released name must be free to create again, got {status} with \
             {created_again}"
        );
        assert_eq!(
            str_field(&created_again, "AIBenchmarkJobArn"),
            job_arn(recreated, released_name),
            "case {case:?}: the re-created job must carry a newly minted ARN, got \
             {created_again}"
        );
        let read_back = emulator
            .ok(
                "DescribeAIBenchmarkJob",
                &json!({ "AIBenchmarkJobName": released_name }),
            )
            .await;
        assert_eq!(
            str_field(&read_back, "AIBenchmarkJobArn"),
            job_arn(recreated, released_name),
            "case {case:?}: the read of the re-created name must report the new job, got \
             {read_back}"
        );
    }
}
