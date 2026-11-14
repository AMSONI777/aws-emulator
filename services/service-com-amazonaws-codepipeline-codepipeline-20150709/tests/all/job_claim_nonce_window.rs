// SPDX-License-Identifier: CC0-1.0

//! The CLAIM WINDOW of a custom action's job, end to end over the wire the service
//! speaks (`awsJson1_1`, `POST /` with `X-Amz-Target:
//! CodePipeline_20150709.<Operation>`).
//!
//! The rule these tables pin: the `nonce` a dispatch published for a job is the
//! worker's handle on that job for as long as the job is in the window a worker claims
//! it in — so the first `AcknowledgeJob` carrying it claims the job and every repeat of
//! that call, while the job is still being worked on, is the no-op it asks for and
//! answers the same `InProgress`. The window closes when the job's work ends (a result
//! the worker reported), and an acknowledgement after that is refused as the receipt
//! that was already recorded (`ValidationException`, "Job with id <jobId> has already
//! been acknowledged"), while `InvalidNonceException` stays what a value no dispatch of
//! the job published is answered with.
//!
//! The rows span what the rule generalises over: how many times the worker repeats its
//! acknowledgement, which result closes the window, and — for the nonce refusal — the
//! form and length of a value the job never published, at each point of the window.
//!
//! The harness comes from `tests/all/execution_engine.rs` and the job setup from
//! `tests/all/terminal_state_refusals.rs`, so these pipelines queue their jobs by
//! really running, and every assertion goes through the router.

use serde_json::json;

use crate::execution_engine::Emulator;
use crate::terminal_state_refusals::{claimable_job, refusal, result_body, REFUSAL_STATUS};

/// `Nonce`'s modelled length bounds (`smithy_query query="shape" shape="Nonce"` ->
/// len 1..50): a value this long is a well-formed nonce, so what refuses it is that the
/// job never published it.
const NONCE_MAX: usize = 50;

/// The status `AcknowledgeJob` reports for a job a worker holds, from `JobStatus`
/// (`smithy_query query="shape" shape="JobStatus"` -> Created | Dispatched | Failed |
/// InProgress | Queued | Succeeded | TimedOut).
const IN_PROGRESS: &str = "InProgress";

/// RULE: the nonce a dispatch published claims the job and keeps reaching it for the
/// whole claim window — every repeat answers the status the job carries — and once the
/// worker's result has closed that window the acknowledgement is refused as a receipt
/// that was already recorded.
///
/// The rows differ along how many times the worker acknowledges before reporting (one
/// claim, and the retries a worker makes when it is unsure its call arrived) and along
/// which result closes the window.
#[tokio::test]
async fn a_nonce_claims_its_job_for_the_whole_claim_window() {
    // (case, how many acknowledgements the worker makes, the result that closes the
    //  window)
    let rows: Vec<(&str, usize, &str)> = vec![
        ("one claim, closed by a success", 1, "PutJobSuccessResult"),
        ("one claim, closed by a failure", 1, "PutJobFailureResult"),
        (
            "a claim retried once, closed by a success",
            2,
            "PutJobSuccessResult",
        ),
        (
            "a claim retried twice, closed by a failure",
            3,
            "PutJobFailureResult",
        ),
    ];

    for (row, (case, acknowledgements, closing_result)) in rows.into_iter().enumerate() {
        let emulator = Emulator::new();
        // The pipeline name is short because the artifact bucket is derived from it and
        // an S3 bucket name is at most 63 characters.
        let pipeline = format!("nonce-window-{row}");
        let (_, job_id, nonce) = claimable_job(&emulator, &pipeline).await;

        for attempt in 1..=acknowledgements {
            let (status, response) = emulator
                .cp("AcknowledgeJob", &json!({"jobId": job_id, "nonce": nonce}))
                .await;
            assert_eq!(
                (status, response["status"].as_str()),
                (200, Some(IN_PROGRESS)),
                "case {case:?}, acknowledgement {attempt}: the nonce the poll published \
                 must claim the job and report its status, got {status} {response}"
            );
        }

        // The result the worker reports is accepted — the claim the repeats confirmed is
        // still the one the job holds — and it closes the window.
        let (status, response) = emulator
            .cp(
                closing_result,
                &result_body(closing_result, &job_id, "the work ran"),
            )
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the claiming worker's result must be accepted, got {status} \
             {response}"
        );

        let (status, code, message) = refusal(
            &emulator,
            "AcknowledgeJob",
            &json!({"jobId": job_id, "nonce": nonce}),
        )
        .await;
        assert_eq!(
            (status, code.as_str()),
            (REFUSAL_STATUS, "ValidationException"),
            "case {case:?}: an acknowledgement past the claim window is the \
             already-recorded receipt, got {status} {code} {message:?}"
        );
        assert_eq!(
            message,
            format!("Job with id {job_id} has already been acknowledged"),
            "case {case:?}: unexpected refusal wording"
        );
    }
}

/// RULE: inside the claim window, a value no dispatch of the job published claims
/// nothing — whatever its form — and the refusal leaves the job exactly where it was,
/// whether the job is still waiting for a worker or already being worked on by one.
///
/// The rows differ along the form and the length of the presented value: the shortest a
/// `Nonce` may be, the longest, the published nonce with one digit changed, its
/// upper-cased spelling, and a value of another shape entirely.
#[tokio::test]
async fn a_value_no_dispatch_published_claims_no_job() {
    let emulator = Emulator::new();
    let pipeline = "nonce-unknown";
    let (_, job_id, nonce) = claimable_job(&emulator, pipeline).await;

    /// The presented values, as (case, value) built from the job's own nonce.
    fn unpublished(nonce: &str) -> Vec<(String, String)> {
        let flipped: String = nonce
            .chars()
            .enumerate()
            .map(|(index, character)| {
                if index == 0 {
                    if character == '0' {
                        '1'
                    } else {
                        '0'
                    }
                } else {
                    character
                }
            })
            .collect();
        vec![
            ("the shortest nonce the model admits".to_string(), "n".to_string()),
            (
                "the longest nonce the model admits".to_string(),
                "n".repeat(NONCE_MAX),
            ),
            ("the published nonce with one digit changed".to_string(), flipped),
            (
                "the published nonce upper-cased".to_string(),
                nonce.to_uppercase(),
            ),
            (
                "a value of another shape entirely".to_string(),
                "not-the-nonce".to_string(),
            ),
        ]
    }

    // While the job is still WAITING for a worker: nothing claims it, so the real nonce
    // still does afterwards.
    for (case, presented) in unpublished(&nonce) {
        let (status, code, message) = refusal(
            &emulator,
            "AcknowledgeJob",
            &json!({"jobId": job_id, "nonce": presented}),
        )
        .await;
        assert_eq!(
            (status, code.as_str()),
            (REFUSAL_STATUS, "InvalidNonceException"),
            "case \"waiting: {case}\": expected the nonce refusal, got {status} {code} \
             {message:?}"
        );
        assert_eq!(
            message,
            format!("Invalid nonce for job id {job_id}"),
            "case \"waiting: {case}\": unexpected refusal wording"
        );
    }
    let claimed = emulator
        .ok("AcknowledgeJob", &json!({"jobId": job_id, "nonce": nonce}))
        .await;
    assert_eq!(
        claimed["status"].as_str(),
        Some(IN_PROGRESS),
        "the refused values must leave the job claimable by the nonce the poll \
         published, got {claimed}"
    );

    // And while it is being WORKED ON: the claim is exclusive, so none of them takes it
    // from the worker holding it, and that worker's result is still accepted.
    for (case, presented) in unpublished(&nonce) {
        let (status, code, message) = refusal(
            &emulator,
            "AcknowledgeJob",
            &json!({"jobId": job_id, "nonce": presented}),
        )
        .await;
        assert_eq!(
            (status, code.as_str()),
            (REFUSAL_STATUS, "InvalidNonceException"),
            "case \"claimed: {case}\": expected the nonce refusal, got {status} {code} \
             {message:?}"
        );
        assert_eq!(
            message,
            format!("Invalid nonce for job id {job_id}"),
            "case \"claimed: {case}\": unexpected refusal wording"
        );
    }
    let (status, response) = emulator
        .cp(
            "PutJobSuccessResult",
            &result_body("PutJobSuccessResult", &job_id, "the work ran"),
        )
        .await;
    assert_eq!(
        status, 200,
        "the refused values must leave the claim with the worker that holds it, got \
         {status} {response}"
    );
}
