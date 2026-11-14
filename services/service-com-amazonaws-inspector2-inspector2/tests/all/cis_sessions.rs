// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the CIS-session internal RPCs: `StartCisSession`,
//! `StopCisSession`, `SendCisSessionHealth` and `SendCisSessionTelemetry`.
//!
//! RULE under test: a CIS-session RPC is served only to the Amazon Inspector-managed SSM
//! plugin session the service itself dispatched a CIS scan to, whose identity carries that
//! scan's resource id; a caller whose identity carries no such resource id is refused with
//! the operation's modelled client fault — HTTP 400 `ValidationException` with the fixed
//! sentence below — decided from the calling identity ALONE, so the refusal does not vary
//! with the scan job id, the session token, the message, the signed region or the CIS scan
//! state this service holds, and it leaves no session behind for a later call to use.
//!
//! Every request goes through the real `MultiServiceRouter` — routing, restJson1
//! deserialization, modelled-constraint validation, the handler, and restJson1
//! serialization — so what is asserted here is the wire behaviour a client sees.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

// The signed-request harness this crate's suites share: `router()` builds a router over
// its own engine, `send_in` sends one restJson1 request signed for a region.
use crate::filters_and_enablement::{post_in, router, send_in};

/// The whole refusal sentence, which names no scan job, session token, account or instant.
const REFUSAL: &str = "Identity user principal does not contain valid resourceId";

/// Every `ValidationExceptionReason` token the refusal may carry.
/// Source: `smithy_query(query="shape", shape="ValidationExceptionReason")` —
/// `CANNOT_PARSE | FIELD_VALIDATION_FAILED | OTHER`.
const VALIDATION_EXCEPTION_REASONS: [&str; 3] =
    ["CANNOT_PARSE", "FIELD_VALIDATION_FAILED", "OTHER"];

/// The four CIS-session routes, every one a `PUT`.
/// Source: `smithy_query(query="operation", operation="StartCisSession,StopCisSession,
/// SendCisSessionHealth,SendCisSessionTelemetry")`.
const START: &str = "/cissession/start";
const STOP: &str = "/cissession/stop";
const HEALTH: &str = "/cissession/health/send";
const TELEMETRY: &str = "/cissession/telemetry/send";

/// A `UUID` every CIS-session member's modelled `@pattern` admits.
/// Source: `smithy_query(query="shape", shape="UUID")` —
/// `^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`.
const SCAN_JOB: &str = "0123abcd-4567-89ef-0123-456789abcdef";
const SESSION: &str = "fedcba98-7654-3210-fedc-ba9876543210";
/// The all-zero and all-f ends of that pattern's value space.
const ZEROES: &str = "00000000-0000-0000-0000-000000000000";
const EFFS: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";

/// One row: the case, the route, the region the request is signed for, the body, and the
/// request-supplied values the refusal must not quote.
struct Row {
    case: &'static str,
    uri: &'static str,
    region: &'static str,
    body: Value,
    submitted: Vec<&'static str>,
}

/// `StartCisSession`'s body.
fn start_body(scan_job_id: &str, session_token: &str) -> Value {
    json!({ "scanJobId": scan_job_id, "message": { "sessionToken": session_token } })
}

/// `StopCisSession`'s body, with the terminal `status` and the progress counts chosen.
/// Source: `smithy_query(query="shape", shape="StopCisSessionStatus,StopCisMessageProgress")`
/// — `SUCCESS | FAILED | INTERRUPTED | UNSUPPORTED_OS`, every check count 0..65536.
fn stop_body(scan_job_id: &str, session_token: &str, status: &str, progress: Value) -> Value {
    json!({
        "scanJobId": scan_job_id,
        "sessionToken": session_token,
        "message": { "status": status, "progress": progress },
    })
}

/// `SendCisSessionHealth`'s body.
fn health_body(scan_job_id: &str, session_token: &str) -> Value {
    json!({ "scanJobId": scan_job_id, "sessionToken": session_token })
}

/// `SendCisSessionTelemetry`'s body with `messages` rule results.
/// Source: `smithy_query(query="shape", shape="CisSessionMessages,CisSessionMessage,
/// CisRuleStatus")` — 1..150 messages, each `ruleId` 1..500 characters, `cisRuleDetails` a
/// blob of 0..1000 bytes, `status` one of `FAILED | PASSED | NOT_EVALUATED | INFORMATIONAL
/// | UNKNOWN | NOT_APPLICABLE | ERROR`.
fn telemetry_body(scan_job_id: &str, session_token: &str, statuses: &[&str]) -> Value {
    let messages: Vec<Value> = statuses
        .iter()
        .enumerate()
        .map(|(index, status)| {
            json!({
                "ruleId": format!("1.{}", index + 1),
                "status": status,
                // A blob renders as base64 on restJson1; the empty blob is the modelled
                // minimum length.
                "cisRuleDetails": if index == 0 { "" } else { "ZGV0YWlscw==" },
            })
        })
        .collect();
    json!({ "scanJobId": scan_job_id, "sessionToken": session_token, "messages": messages })
}

/// The rows span what the rule generalises over: WHICH of the four RPCs is called, the scan
/// job id and session token presented (including both ends of their pattern's value space
/// and the two ids being equal), the message's content and size, and the region the request
/// is signed for.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "StartCisSession with a fresh scan job id and session token",
            uri: START,
            region: "us-east-1",
            body: start_body(SCAN_JOB, SESSION),
            submitted: vec![SCAN_JOB, SESSION],
        },
        Row {
            case: "StartCisSession with the all-zero scan job id and the all-f token",
            uri: START,
            region: "us-west-2",
            body: start_body(ZEROES, EFFS),
            submitted: vec![ZEROES, EFFS],
        },
        Row {
            case: "StartCisSession whose scan job id and session token are the same UUID",
            uri: START,
            region: "eu-central-1",
            body: start_body(SCAN_JOB, SCAN_JOB),
            submitted: vec![SCAN_JOB],
        },
        Row {
            case: "StopCisSession reporting SUCCESS with no checks run",
            uri: STOP,
            region: "us-east-1",
            body: stop_body(SCAN_JOB, SESSION, "SUCCESS", json!({ "totalChecks": 0 })),
            submitted: vec![SCAN_JOB, SESSION],
        },
        Row {
            case: "StopCisSession reporting FAILED with every progress count at its bound",
            uri: STOP,
            region: "us-west-2",
            body: stop_body(
                EFFS,
                ZEROES,
                "FAILED",
                json!({
                    "totalChecks": 65536,
                    "successfulChecks": 65536,
                    "failedChecks": 65536,
                    "notEvaluatedChecks": 65536,
                    "unknownChecks": 65536,
                    "notApplicableChecks": 65536,
                    "informationalChecks": 65536,
                    "errorChecks": 65536,
                }),
            ),
            submitted: vec![EFFS, ZEROES],
        },
        Row {
            case: "StopCisSession reporting UNSUPPORTED_OS with an absent progress body",
            uri: STOP,
            region: "ap-southeast-2",
            body: stop_body(ZEROES, SESSION, "UNSUPPORTED_OS", json!({})),
            submitted: vec![ZEROES, SESSION],
        },
        Row {
            case: "SendCisSessionHealth for a session that was never started",
            uri: HEALTH,
            region: "us-east-1",
            body: health_body(SCAN_JOB, SESSION),
            submitted: vec![SCAN_JOB, SESSION],
        },
        Row {
            case: "SendCisSessionHealth signed for another region",
            uri: HEALTH,
            region: "eu-west-1",
            body: health_body(EFFS, ZEROES),
            submitted: vec![EFFS, ZEROES],
        },
        Row {
            case: "SendCisSessionTelemetry carrying the modelled minimum of one message",
            uri: TELEMETRY,
            region: "us-east-1",
            body: telemetry_body(SCAN_JOB, SESSION, &["PASSED"]),
            submitted: vec![SCAN_JOB, SESSION],
        },
        Row {
            case: "SendCisSessionTelemetry carrying one message of every rule status",
            uri: TELEMETRY,
            region: "us-west-2",
            body: telemetry_body(
                ZEROES,
                EFFS,
                &[
                    "FAILED",
                    "PASSED",
                    "NOT_EVALUATED",
                    "INFORMATIONAL",
                    "UNKNOWN",
                    "NOT_APPLICABLE",
                    "ERROR",
                ],
            ),
            submitted: vec![ZEROES, EFFS],
        },
    ]
}

/// Send one CIS-session request and answer the status, the wire error type and the body.
async fn send_cis(
    router: &MultiServiceRouter,
    region: &str,
    uri: &str,
    body: &Value,
) -> (u16, Option<String>, Value) {
    send_in(router, "PUT", region, uri, Some(body)).await
}

/// Assert `response` is the identity refusal, and that it quotes none of `submitted`.
fn assert_refused(
    case: &str,
    status: u16,
    error_type: &Option<String>,
    body: &Value,
    submitted: &[&str],
) {
    assert_eq!(
        status, 400,
        "case {case:?}: expected 400, got {status} / {body}"
    );
    assert_eq!(
        error_type.as_deref(),
        Some("ValidationException"),
        "case {case:?}: expected ValidationException, got {error_type:?} / {body}"
    );
    let message = body["message"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: the refusal carries no message: {body}"));
    assert_eq!(
        message, REFUSAL,
        "case {case:?}: expected {REFUSAL:?}, got {message:?}"
    );
    let reason = body["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: the refusal carries no reason: {body}"));
    assert!(
        VALIDATION_EXCEPTION_REASONS.contains(&reason),
        "case {case:?}: expected a modelled ValidationExceptionReason, got {reason:?}"
    );
    assert!(
        body["fields"].is_null(),
        "case {case:?}: no member of the request is at fault, so the refusal must name no \
         field, got {body}"
    );
    for value in submitted {
        assert!(
            !message.contains(value),
            "case {case:?}: the refusal must not quote the request value {value:?}, got \
             {message:?}"
        );
    }
}

/// Every CIS-session RPC refuses a caller whose identity carries no CIS scan resource id
/// with the same 400 `ValidationException` and the same sentence, whatever ids, message or
/// region the request carries.
#[tokio::test]
async fn every_cis_session_rpc_refuses_an_identity_carrying_no_scan_resource_id() {
    let router = router();
    for row in rows() {
        let (status, error_type, body) = send_cis(&router, row.region, row.uri, &row.body).await;
        assert_refused(row.case, status, &error_type, &body, &row.submitted);
    }
}

/// The refusal is decided before any scan-job lookup: it is the same whether or not this
/// service holds CIS scan state, and the same on a repeat of the identical call.
#[tokio::test]
async fn the_refusal_does_not_depend_on_stored_cis_scan_state() {
    let router = router();

    // Before any CIS scan configuration exists.
    let (status, error_type, body) =
        send_cis(&router, "us-east-1", START, &start_body(SCAN_JOB, SESSION)).await;
    assert_refused(
        "an empty store",
        status,
        &error_type,
        &body,
        &[SCAN_JOB, SESSION],
    );

    // A CIS scan configuration this service DOES hold changes nothing: the gate reads the
    // identity, not the store.
    let created = post_in(
        &router,
        "us-east-1",
        "/cis/scan-configuration/create",
        &json!({
            "scanName": "nightly",
            "securityLevel": "LEVEL_1",
            "schedule": { "oneTime": {} },
            "targets": { "accountIds": ["SELF"], "targetResourceTags": { "Fleet": ["all"] } },
        }),
    )
    .await;
    assert_eq!(
        created.0, 200,
        "case a stored configuration: CreateCisScanConfiguration: expected 200, got {} / {}",
        created.0, created.2
    );

    for attempt in ["a stored configuration", "a repeat of the same call"] {
        let (status, error_type, body) =
            send_cis(&router, "us-east-1", START, &start_body(SCAN_JOB, SESSION)).await;
        assert_refused(attempt, status, &error_type, &body, &[SCAN_JOB, SESSION]);
    }
}

/// A refused `StartCisSession` leaves no session behind: the stop, health and telemetry
/// calls for that very scan job and session token are refused identically rather than
/// reporting a session that does not exist.
#[tokio::test]
async fn a_refused_start_leaves_no_session_for_the_other_rpcs() {
    let router = router();

    let (status, error_type, body) =
        send_cis(&router, "us-east-1", START, &start_body(SCAN_JOB, SESSION)).await;
    assert_refused("the start", status, &error_type, &body, &[SCAN_JOB, SESSION]);

    let follow_ups: [(&str, &str, Value); 3] = [
        (
            "the stop of the session the start never created",
            STOP,
            stop_body(SCAN_JOB, SESSION, "INTERRUPTED", json!({ "totalChecks": 1 })),
        ),
        (
            "the health of the session the start never created",
            HEALTH,
            health_body(SCAN_JOB, SESSION),
        ),
        (
            "the telemetry of the session the start never created",
            TELEMETRY,
            telemetry_body(SCAN_JOB, SESSION, &["FAILED", "PASSED"]),
        ),
    ];

    for (case, uri, body) in follow_ups {
        let (status, error_type, response) = send_cis(&router, "us-east-1", uri, &body).await;
        assert_refused(case, status, &error_type, &response, &[SCAN_JOB, SESSION]);
    }
}

/// A scan job id or session token the member's modelled `@pattern` does not admit is still
/// a 400 `ValidationException` — the gate and the boundary agree on the class of fault, so
/// a client sees one code for every refused CIS-session call, valid-shaped id or not.
#[tokio::test]
async fn a_malformed_id_is_refused_with_the_same_fault_class() {
    let router = router();
    // Rows differ along WHICH member is malformed and HOW: case, grouping, length, and a
    // value that is not a UUID at all.
    let malformed: [(&str, Value); 5] = [
        (
            "an upper-case scan job id",
            start_body("0123ABCD-4567-89EF-0123-456789ABCDEF", SESSION),
        ),
        (
            "a scan job id that is not a UUID",
            start_body("scan-1", SESSION),
        ),
        ("an empty scan job id", start_body("", SESSION)),
        (
            "a malformed session token inside the start message",
            start_body(SCAN_JOB, "not-a-session-token"),
        ),
        (
            "a malformed session token on the stop request",
            stop_body(SCAN_JOB, "0123abcd", "SUCCESS", json!({ "totalChecks": 0 })),
        ),
    ];

    for (case, body) in malformed {
        let stops = body
            .get("message")
            .is_some_and(|message| message.get("status").is_some());
        let uri = if stops { STOP } else { START };
        let (status, error_type, response) = send_cis(&router, "us-east-1", uri, &body).await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected 400, got {status} / {response}"
        );
        assert_eq!(
            error_type.as_deref(),
            Some("ValidationException"),
            "case {case:?}: expected ValidationException, got {error_type:?} / {response}"
        );
    }
}

/// The gate is specific to the CIS-session surface: the same caller, on the same router, is
/// still served by this service's ordinary control-plane reads — the refusals above are not
/// "everything is denied".
#[tokio::test]
async fn the_gate_refuses_only_the_cis_session_surface() {
    let router = router();

    let (status, error_type, body) =
        send_cis(&router, "us-east-1", START, &start_body(SCAN_JOB, SESSION)).await;
    assert_refused(
        "the CIS-session call",
        status,
        &error_type,
        &body,
        &[SCAN_JOB, SESSION],
    );

    let (status, error_type, body) = post_in(&router, "us-east-1", "/usage/list", &json!({})).await;
    assert_eq!(
        status, 200,
        "case the positive control: ListUsageTotals: expected 200, got {status} / {body} \
         ({error_type:?})"
    );
    assert!(
        body["totals"].is_array(),
        "case the positive control: ListUsageTotals must report totals, got {body}"
    );
}
