// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of `CancelAuditTask`: the cancel of a Device Defender audit
//! that is still in progress, and the refusal of one that is not.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` over a
//! restJson1 request signed for the `iot` signing name — so what is asserted is what an
//! AWS SDK client would see, not an internal function's return value.
//!
//! The rules under test:
//!
//! * "Cancels an audit that is in progress": a task answered in the non-terminal status
//!   is cancelled, and from then on it reports the cancelled status and every check it
//!   targeted as cancelled;
//! * "If the audit isn't in progress, an InvalidRequestException occurs": a task that
//!   has reached a terminal status — completed, or already cancelled — keeps the status
//!   it reached and the cancel is refused `InvalidRequestException` (400);
//! * a task id this account started no audit under is `ResourceNotFoundException` (404).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde_json::{json, Map, Value};
use service_com_amazonaws_iot_awsiotservice::state::{
    ComAmazonawsIotAwsiotserviceState, AUDIT_SPAN, AUDIT_TASK_CANCELED, AUDIT_TASK_COMPLETED,
    AUDIT_TASK_IN_PROGRESS,
};
use service_com_amazonaws_iot_awsiotservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The region every request in this suite is signed for. An audit is account-wide, so no
/// assertion depends on it.
const REGION: &str = "eu-west-3";

/// The role the account's audit configuration names, of more than the modelled minimum
/// length (`RoleArn`, len 20..2048).
const AUDIT_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/device-defender-audit";

/// Audit checks the rows below target. Each is an entry of the emulator's catalog of
/// Device Defender audit checks
/// (`service_com_amazonaws_iot_awsiotservice::state::AUDIT_CHECK_NAMES`).
const LOGGING_DISABLED_CHECK: &str = "LOGGING_DISABLED_CHECK";
const DEVICE_CERTIFICATE_AGE_CHECK: &str = "DEVICE_CERTIFICATE_AGE_CHECK";
const IOT_POLICY_OVERLY_PERMISSIVE_CHECK: &str = "IOT_POLICY_OVERLY_PERMISSIVE_CHECK";

/// One emulator: the shared engine plus a router with this service mounted.
struct Emulator {
    engine: Arc<engine::InMemoryEngine>,
    router: MultiServiceRouter,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        router.set_request_authentication(false);
        router.register_service(EmulatedService::new(Arc::clone(&engine)));
        Self { engine, router }
    }

    async fn dispatch(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let host = format!("iot.{REGION}.amazonaws.com");
        let payload = body.map_or_else(Bytes::new, |value| Bytes::from(value.to_string()));
        let request = http::Request::builder()
            .method(method)
            .uri(format!("https://{host}{path}"))
            .header("host", host)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/iot/aws4_request, \
                     SignedHeaders=host, Signature=0123456789abcdef"
                ),
            )
            .body(payload)
            .expect("the audit request is well formed");
        Reply::of(self.router.dispatch(request).await)
    }

    /// Enable `check_names` for the account, so an audit may target them.
    async fn enable_checks(&self, case: &str, check_names: &[&str]) {
        let mut checks = Map::new();
        for check_name in check_names {
            checks.insert((*check_name).to_string(), json!({ "enabled": true }));
        }
        let reply = self
            .dispatch(
                "PATCH",
                "/audit/configuration",
                Some(&json!({
                    "roleArn": AUDIT_ROLE_ARN,
                    "auditCheckConfigurations": Value::Object(checks),
                })),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected UpdateAccountAuditConfiguration to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
    }

    /// Start an audit over `check_names`, answering its task id.
    async fn start_audit(&self, case: &str, check_names: &[&str]) -> String {
        let reply = self
            .dispatch(
                "POST",
                "/audit/tasks",
                Some(&json!({ "targetCheckNames": check_names })),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected StartOnDemandAuditTask to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
        reply.json()["taskId"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case}: no taskId in {}", reply.text()))
            .to_string()
    }

    async fn cancel_audit(&self, task_id: &str) -> Reply {
        self.dispatch("PUT", &format!("/audit/tasks/{task_id}/cancel"), None)
            .await
    }

    async fn describe_audit(&self, task_id: &str) -> Reply {
        self.dispatch("GET", &format!("/audit/tasks/{task_id}"), None)
            .await
    }

    /// Make the completion the clock owes `task_id` DUE, by moving the recorded instant
    /// into the past — the state a caller that waited out [`AUDIT_SPAN`] would find,
    /// without the test waiting for it.
    fn finish_audit(&self, task_id: &str) {
        let state = self.engine.state::<ComAmazonawsIotAwsiotserviceState>();
        let mut store = state.lock();
        let task = store
            .audit_tasks
            .get_mut(task_id)
            .expect("the started audit is on record");
        let started = SystemTime::now() - AUDIT_SPAN - Duration::from_secs(1);
        task.started_at = started;
        task.completed_at = started + AUDIT_SPAN;
    }
}

/// A dispatched response, reduced to what the assertions read.
struct Reply {
    status: u16,
    body: Bytes,
}

impl Reply {
    fn of(response: http::Response<Bytes>) -> Self {
        Self {
            status: response.status().as_u16(),
            body: response.into_body(),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("response body is not JSON ({e}): {}", self.text()))
    }

    fn error_code(&self) -> String {
        self.json()["__type"]
            .as_str()
            .unwrap_or_else(|| panic!("no __type in {}", self.text()))
            .to_string()
    }
}

/// RULE: an audit still in progress is cancelled, and the cancelled task reports the
/// cancelled status and every check it targeted as cancelled.
#[tokio::test]
async fn an_audit_in_progress_is_cancelled() {
    // The rows span what the rule generalises over: how many checks the audit targeted.
    let targets: Vec<Vec<&str>> = vec![
        vec![LOGGING_DISABLED_CHECK],
        vec![LOGGING_DISABLED_CHECK, DEVICE_CERTIFICATE_AGE_CHECK],
        vec![
            LOGGING_DISABLED_CHECK,
            DEVICE_CERTIFICATE_AGE_CHECK,
            IOT_POLICY_OVERLY_PERMISSIVE_CHECK,
        ],
    ];
    for checks in &targets {
        let case = format!("an audit over {} check(s)", checks.len());
        let emulator = Emulator::new();
        emulator.enable_checks(&case, checks).await;
        let task_id = emulator.start_audit(&case, checks).await;

        // The task is answered in the non-terminal status, which is what makes the
        // cancel admissible at all.
        let started = emulator.describe_audit(&task_id).await;
        assert_eq!(
            started.json()["taskStatus"],
            json!(AUDIT_TASK_IN_PROGRESS),
            "case {case}: a fresh audit must be in progress, got {}",
            started.text()
        );

        let cancelled = emulator.cancel_audit(&task_id).await;
        assert_eq!(
            cancelled.status,
            200,
            "case {case}: expected the cancel to answer 200, got {} body {}",
            cancelled.status,
            cancelled.text()
        );

        // What the cancel WROTE: the status, and every check the audit targeted.
        let report = emulator.describe_audit(&task_id).await;
        assert_eq!(
            report.json()["taskStatus"],
            json!(AUDIT_TASK_CANCELED),
            "case {case}: expected the cancelled status, got {}",
            report.text()
        );
        let statistics = &report.json()["taskStatistics"];
        assert_eq!(
            statistics["canceledChecks"],
            json!(checks.len()),
            "case {case}: expected every targeted check cancelled, got {}",
            report.text()
        );
        assert_eq!(
            statistics["inProgressChecks"],
            json!(0),
            "case {case}: a cancelled audit runs no check further, got {}",
            report.text()
        );
        for check_name in checks {
            assert_eq!(
                report.json()["auditDetails"][check_name]["checkRunStatus"],
                json!("CANCELED"),
                "case {case}: expected {check_name} reported cancelled, got {}",
                report.text()
            );
        }

        // The cancel does not run again: the task has reached a status it keeps.
        let again = emulator.cancel_audit(&task_id).await;
        assert_eq!(
            again.status,
            400,
            "case {case}: expected a second cancel to be refused, got {} body {}",
            again.status,
            again.text()
        );
        assert_eq!(
            again.error_code(),
            "InvalidRequestException",
            "case {case}: got {}",
            again.text()
        );
    }
}

/// RULE: an audit that is not in progress keeps the status it reached and the cancel is
/// refused; a task the account never started is a 404.
#[tokio::test]
async fn a_cancel_of_an_audit_that_is_not_in_progress_is_refused() {
    let emulator = Emulator::new();
    let checks = [LOGGING_DISABLED_CHECK, DEVICE_CERTIFICATE_AGE_CHECK];
    emulator.enable_checks("completed", &checks).await;
    let task_id = emulator.start_audit("completed", &checks).await;
    // The completion the clock owed the audit is now due, so the task has reached its
    // terminal status.
    emulator.finish_audit(&task_id);
    let completed = emulator.describe_audit(&task_id).await;
    assert_eq!(
        completed.json()["taskStatus"],
        json!(AUDIT_TASK_COMPLETED),
        "case a completed audit: the task must report completion, got {}",
        completed.text()
    );

    let refused = emulator.cancel_audit(&task_id).await;
    assert_eq!(
        refused.status,
        400,
        "case a completed audit: expected 400, got {} body {}",
        refused.status,
        refused.text()
    );
    assert_eq!(
        refused.error_code(),
        "InvalidRequestException",
        "case a completed audit: got {}",
        refused.text()
    );
    assert!(
        refused.json()["message"]
            .as_str()
            .is_some_and(|message| message.contains(&task_id)
                && message.contains(AUDIT_TASK_COMPLETED)),
        "case a completed audit: the refusal must name the task and the status it \
         reached, got {}",
        refused.text()
    );

    // The refusal changed nothing: the task still reports completion, and its checks
    // still report what they amounted to.
    let after = emulator.describe_audit(&task_id).await;
    assert_eq!(
        after.json()["taskStatus"],
        json!(AUDIT_TASK_COMPLETED),
        "case a completed audit: the status must be unchanged, got {}",
        after.text()
    );
    assert_eq!(
        after.json()["taskStatistics"]["canceledChecks"],
        json!(0),
        "case a completed audit: no check of it was cancelled, got {}",
        after.text()
    );

    // A task id this account started no audit under names no task at all.
    let missing = emulator.cancel_audit("00000000-0000-0000-0000-000000000000").await;
    assert_eq!(
        missing.status,
        404,
        "case a task the account never started: expected 404, got {} body {}",
        missing.status,
        missing.text()
    );
    assert_eq!(
        missing.error_code(),
        "ResourceNotFoundException",
        "case a task the account never started: got {}",
        missing.text()
    );
}
