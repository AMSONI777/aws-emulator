// SPDX-License-Identifier: CC0-1.0

//! The one-open-request rule under a SIMULTANEOUS burst: what every caller that loses
//! the race is told, and that the one that wins it is still readable.
//!
//! The rule under test, over a TABLE of quotas, burst sizes, endpoint spreads and
//! desired-value spreads rather than one recorded burst: a quota plane carries at most
//! one increase request awaiting a decision, so however many calls arrive at once on one
//! plane exactly ONE is admitted and every other is refused `ResourceAlreadyExistsException`
//! on the client-fault status with the service's FIXED sentence for that fact — text that
//! interpolates nothing of the request and nothing this service minted, so every loser of
//! one burst reads back the same string, and so does a loser of any other burst on any
//! other quota.
//!
//! The consequence that ties the refusals to the write that caused them, checked for
//! every row: the admitted request is the one the plane holds — it is readable by the
//! `Id` it was minted with, through `GetRequestedServiceQuotaChange` and through
//! `ListRequestedServiceQuotaChangeHistoryByQuota`, which reports exactly that one entry
//! for the quota, carrying the `DesiredValue` the winning racer asked for.
//!
//! Each racer dispatches through its OWN router over the one shared engine, all of them
//! in flight before any answer is read, on a multi-threaded runtime: the admission
//! decision is contended rather than pre-serialised by the test.
//!
//! The harness (`client`, `emulator`, `walk_pages`) is the one
//! `quota_workflow.rs` owns, the error-body reader is `error_envelope.rs`'s, the catalog
//! lookup is `open_request_plane_scope.rs`'s and the request reader is
//! `support_cases.rs`'s.

use serde_json::{json, Value};
use service_com_amazonaws_servicequotas_servicequotasv20190624::service::refusals::ONE_OPEN_REQUEST_MESSAGE;
use tokio::task::JoinSet;

use crate::error_envelope::error_of;
use crate::open_request_plane_scope::catalog_entry;
use crate::quota_workflow::{client, emulator, walk_pages};
use crate::support_cases::read_request;

/// Every modelled client fault is HTTP 400 on this awsJson service, whatever
/// `@httpError` its shape declares — see the `error_envelope` suite.
const CLIENT_FAULT: u16 = 400;

/// The history listing, whose name is too long to repeat in every call.
const HISTORY_BY_QUOTA: &str = "ListRequestedServiceQuotaChangeHistoryByQuota";

/// The sentence a second request on one quota plane is refused with, as recorded.
/// Spelled out here so the suite pins the WORDING as well as its single sourcing:
/// comparing a refusal against the crate's constant alone would stay green if that
/// constant's own sentence drifted.
const ONE_OPEN_REQUEST_WORDING: &str =
    "Only one open service quota increase request is allowed per quota.";

/// One row: a quota, one endpoint per racer, and the spread of the values they ask for.
struct Row {
    /// Why this row is in the table.
    why: &'static str,
    service_code: &'static str,
    /// The quota, by the `QuotaName` the catalog publishes: its `QuotaCode`, AWS default
    /// `Value` and `GlobalQuota` are read through `ListAWSDefaultServiceQuotas`, so no
    /// row pins a code or a value of its own.
    quota_name: &'static str,
    /// Whether the catalog publishes this quota as counted account-wide. Asserted against
    /// the catalog's own `GlobalQuota`, so a row can never claim a scope the service does
    /// not report: an account-wide plane is the one a burst spread over regions contends
    /// for, and a per-region plane the one a burst at one endpoint contends for.
    global: bool,
    /// One endpoint per racer, so the burst size is this slice's length; a region named
    /// twice puts two racers on the same endpoint.
    endpoints: &'static [&'static str],
    /// The step between consecutive racers' `DesiredValue`: `0.0` makes every racer's
    /// request identical (the recorded burst's form), and a positive step gives each
    /// racer a distinct value that is itself a valid increase, so what is refused is the
    /// open request and never the value.
    step: f64,
}

/// The table: bursts of two to five callers, on account-wide quotas contended from
/// several regional endpoints at once and on per-region quotas contended at one endpoint,
/// with identical and with distinct desired values.
///
/// The quota names are the catalog's (`ListServices` -> `ListAWSDefaultServiceQuotas`)
/// and every row names a quota the issue did not cite.
fn rows() -> Vec<Row> {
    vec![
        Row {
            why: "five identical calls at one endpoint on a per-region quota",
            service_code: "lambda",
            quota_name: "Concurrent executions",
            global: false,
            endpoints: &["us-east-1", "us-east-1", "us-east-1", "us-east-1", "us-east-1"],
            step: 0.0,
        },
        Row {
            why: "three calls at one endpoint, each asking for a different increase",
            service_code: "vpc",
            quota_name: "VPCs per Region",
            global: false,
            endpoints: &["eu-west-1", "eu-west-1", "eu-west-1"],
            step: 10.0,
        },
        Row {
            why: "an account-wide quota contended from four regions at once",
            service_code: "iam",
            quota_name: "Users per account",
            global: true,
            endpoints: &["us-east-1", "eu-west-1", "ap-southeast-2", "sa-east-1"],
            step: 0.0,
        },
        Row {
            why: "an account-wide quota contended from two regions, with distinct values",
            service_code: "route53",
            quota_name: "Records per hosted zone",
            global: true,
            endpoints: &["eu-central-1", "us-west-2"],
            step: 1_000.0,
        },
        Row {
            why: "an account-wide quota of a service that publishes a single quota, two \
                  racers per endpoint",
            service_code: "globalaccelerator",
            quota_name: "Accelerators per account",
            global: true,
            endpoints: &["ap-northeast-1", "us-east-2", "ap-northeast-1", "us-east-2"],
            step: 2.0,
        },
    ]
}

/// What one racer did: the endpoint it called, the value it asked for, and the answer.
struct Answer {
    /// Which racer of the burst this was, so a failure names it.
    index: usize,
    region: String,
    desired: f64,
    status: u16,
    body: Value,
}

/// Fire one burst of `RequestServiceQuotaIncrease` calls, all in flight before any answer
/// is read, and return them in the order the racers were started.
async fn burst(
    engine: &std::sync::Arc<engine::InMemoryEngine>,
    row: &Row,
    quota_code: &str,
    base_value: f64,
) -> Vec<Answer> {
    let mut racers: JoinSet<Answer> = JoinSet::new();
    for (index, region) in row.endpoints.iter().enumerate() {
        // Every value is above the quota's AWS default, so each racer's request is a
        // valid increase on its own.
        let desired = base_value + 1.0 + index as f64 * row.step;
        let caller = client(engine, region);
        let request = json!({
            "ServiceCode": row.service_code,
            "QuotaCode": quota_code,
            "DesiredValue": desired,
        });
        let region = (*region).to_string();
        racers.spawn(async move {
            let (status, body) = caller.call("RequestServiceQuotaIncrease", &request).await;
            Answer {
                index,
                region,
                desired,
                status,
                body,
            }
        });
    }

    let mut answers: Vec<Answer> = Vec::with_capacity(row.endpoints.len());
    while let Some(joined) = racers.join_next().await {
        answers.push(joined.expect("case a racer: the burst task must not panic"));
    }
    answers.sort_by_key(|answer| answer.index);
    answers
}

/// A `DesiredValue` as a JSON body spells one, so a refusal can be checked for carrying
/// it.
fn value_text(value: f64) -> String {
    json!(value).to_string()
}

/// However many callers ask for an increase on one quota plane at the same instant,
/// exactly one is admitted, every other is refused with the service's one fixed sentence
/// for that fact, and the admitted request is the one the plane holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_simultaneous_burst_on_one_plane_admits_one_and_refuses_the_rest_identically() {
    // Every loser of every row, so the sentence is seen not to follow the quota, the
    // burst size, the endpoint or the value.
    let mut stated: Vec<String> = Vec::new();

    for row in rows() {
        let engine = emulator();
        let reader = client(&engine, row.endpoints[0]);
        let case = format!("{} ({}/{})", row.why, row.service_code, row.quota_name);

        let (quota_code, base_value, global) =
            catalog_entry(&reader, row.service_code, row.quota_name).await;
        assert_eq!(
            global, row.global,
            "case {case}: expected the catalog to publish GlobalQuota={}, got {global}",
            row.global
        );

        let answers = burst(&engine, &row, &quota_code, base_value).await;
        let (admitted, refused): (Vec<&Answer>, Vec<&Answer>) =
            answers.iter().partition(|answer| answer.status == 200);

        assert_eq!(
            admitted.len(),
            1,
            "case {case}: expected exactly one of {} racers to be admitted, got {:?}",
            row.endpoints.len(),
            answers
                .iter()
                .map(|answer| (answer.index, answer.status, answer.body.clone()))
                .collect::<Vec<_>>()
        );
        let winner = admitted[0];
        let minted = winner.body["RequestedQuota"]["Id"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "case {case}: expected the admitted racer to carry an Id, got {}",
                    winner.body
                )
            })
            .to_string();

        for loser in &refused {
            let racer = format!(
                "case {case}: racer {} at {} asking for {}",
                loser.index, loser.region, loser.desired
            );
            let (code, message) = error_of(&loser.body);
            let message = message
                .unwrap_or_else(|| panic!("{racer}: expected a refusal message, got {}", loser.body));
            assert_eq!(
                (loser.status, code.as_str()),
                (CLIENT_FAULT, "ResourceAlreadyExistsException"),
                "{racer}: expected HTTP {CLIENT_FAULT} ResourceAlreadyExistsException, got {} \
                 {code} with {message:?}",
                loser.status
            );
            assert_eq!(
                message, ONE_OPEN_REQUEST_MESSAGE,
                "{racer}: expected the crate's one sentence for the fact, got {message:?}"
            );
            assert_eq!(
                message, ONE_OPEN_REQUEST_WORDING,
                "{racer}: expected the sentence {ONE_OPEN_REQUEST_WORDING:?}, got {message:?}"
            );
            // Nothing this service minted and nothing of the request: not the id of the
            // request already awaiting a decision, not the quota, not the service, and
            // not any value a racer of this burst asked for.
            let forbidden: Vec<String> = [
                minted.clone(),
                quota_code.clone(),
                row.service_code.to_string(),
            ]
            .into_iter()
            .chain(answers.iter().map(|answer| value_text(answer.desired)))
            .collect();
            for part in &forbidden {
                assert!(
                    !message.contains(part.as_str()),
                    "{racer}: the refusal must carry nothing of the request or of this \
                     service's own state, but it carries {part:?}: {message:?}"
                );
            }
            stated.push(message);
        }

        // The winner is the request the plane holds: readable by the id it was minted
        // with, at the endpoint it was made at, with the value that racer asked for.
        let home = client(&engine, &winner.region);
        let stored = read_request(&home, &minted).await;
        assert_eq!(
            (
                stored["Id"].as_str(),
                stored["QuotaCode"].as_str(),
                stored["ServiceCode"].as_str(),
                stored["DesiredValue"].as_f64(),
            ),
            (
                Some(minted.as_str()),
                Some(quota_code.as_str()),
                Some(row.service_code),
                Some(winner.desired),
            ),
            "case {case}: expected the admitted request read back as minted, got {stored}"
        );

        // And it is the ONLY entry the quota's history holds: no loser of the burst left
        // a record behind.
        let history = walk_pages(
            &home,
            HISTORY_BY_QUOTA,
            &json!({"ServiceCode": row.service_code, "QuotaCode": quota_code}),
            "RequestedQuotas",
            None,
        )
        .await;
        assert_eq!(
            history
                .iter()
                .map(|entry| (entry["Id"].as_str(), entry["DesiredValue"].as_f64()))
                .collect::<Vec<_>>(),
            vec![(Some(minted.as_str()), Some(winner.desired))],
            "case {case}: expected the quota's history to hold the admitted request alone, \
             got {history:?}"
        );
    }

    // Every loser of every row — five quotas, four burst sizes, identical and distinct
    // values, one and several endpoints: ONE sentence.
    assert!(
        stated.len() >= 10,
        "case the table as a whole: expected the rows to produce a burst of losers, got \
         {stated:?}"
    );
    stated.sort();
    stated.dedup();
    assert_eq!(
        stated.len(),
        1,
        "case the table as a whole: expected one sentence for the fact, got {stated:?}"
    );
}
