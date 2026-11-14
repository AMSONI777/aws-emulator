// SPDX-License-Identifier: CC0-1.0

//! How an operation on a gateway's TARGETS is refused while the gateway that serves them is
//! in a status that cannot serve it, over the whole target family and every status a gateway
//! can be refused in.
//!
//! Each row drives the service the way the router does: an `http::Request` through
//! [`MultiServiceRouter::dispatch`], so the wire protocol (`restJson1`), the boundary
//! constraint validation and the handlers are all exercised.
//!
//! The rules under test:
//!
//! 1. An operation on a gateway's targets that the gateway's own status cannot serve is
//!    refused 400 `ValidationException` (`smithy_query(query="operation",
//!    operation="CreateGatewayTarget,UpdateGatewayTarget,DeleteGatewayTarget,\
//!    SynchronizeGatewayTargets")` — every one of them declares it with `httpError` 400)
//!    whose `message` is "Cannot perform operation <OperationName> when gateway is in
//!    <STATUS> status": fixed text, with the operation being attempted and the gateway's
//!    current status as its only variable parts, the status spelled as the raw token its
//!    enum declares (`smithy_query(query="shape",shape="GatewayStatus")`: CREATING,
//!    UPDATING, UPDATE_UNSUCCESSFUL, DELETING, READY, FAILED). The rows below span that
//!    family against each status a gateway can be driven into and refuse from.
//! 2. The sentence belongs to the target family. An operation on the GATEWAY itself is
//!    refused in the gateway family's own words ("<Operation> operation can't be performed
//!    on gateway when it is in <State> state. Retry the request when the gateway is in a
//!    valid state."), so the two families are pinned side by side here: one formatter
//!    cannot serve both.
//! 3. A refused request writes nothing: a refused `CreateGatewayTarget` mints no target.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_bedrockagentcorecontrol_amazonbedrockagentcorecontrol::EmulatedService;

/// The region every request here is signed for.
const REGION: &str = "us-east-1";

/// A role ARN inside `RoleArn`'s pattern `^arn:aws(-[^:]+)?:iam::([0-9]{12})?:role/.+$`.
const ROLE_ARN: &str = "arn:aws:iam::000000000000:role/GatewayRole";

/// A `targetId` inside `TargetId`'s pattern `^[0-9a-zA-Z]{10}$` that no row ever creates:
/// the gateway's status is judged before the target the path names is resolved, so a row
/// about a gateway that holds no target still has an id to address.
const ABSENT_TARGET_ID: &str = "ZZZZ999999";

/// How long a row waits for a clock-owed transition at the most, and how long it pauses
/// between two reads while it waits: the wait is for the CONDITION, so a host slower than
/// this one only reads again instead of failing.
const POLL_DEADLINE: Duration = Duration::from_secs(30);
const POLL_PAUSE: Duration = Duration::from_millis(20);

fn router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::default();
    router.register_service(EmulatedService::new(engine));
    router
}

/// A SigV4 `Authorization` header for this service, which is what the router routes on.
fn authorization() -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/bedrock-agentcore/\
         aws4_request, SignedHeaders=host, Signature=abc"
    )
}

/// One answer: the HTTP status and the parsed body.
struct Answer {
    status: u16,
    body: Value,
}

async fn send(
    router: &MultiServiceRouter,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> Answer {
    let payload = body.map_or_else(Bytes::new, |value| {
        Bytes::from(serde_json::to_vec(value).expect("the request body serializes"))
    });
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", authorization())
        .header("host", "bedrock-agentcore-control.us-east-1.amazonaws.com");
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request.body(payload).expect("a well-formed request");
    let response = router.dispatch(request).await;
    Answer {
        status: response.status().as_u16(),
        body: if response.body().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(response.body()).unwrap_or(Value::Null)
        },
    }
}

/// The error code `restJson1` puts in the body's `__type`.
fn error_code(body: &Value) -> String {
    body.get("__type")
        .and_then(Value::as_str)
        .unwrap_or("<no __type>")
        .rsplit('#')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn text(body: &Value, member: &str) -> String {
    body.get(member)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// A `CreateGateway`/`UpdateGateway` body for `name`, with a role every row shares.
fn gateway_body(name: &str) -> Value {
    json!({"name": name, "roleArn": ROLE_ARN, "authorizerType": "AWS_IAM"})
}

/// Create a gateway and answer its `gatewayId`, WITHOUT waiting the clock out: a new gateway
/// reports `CREATING` until the transition it is owed comes due.
async fn creating_gateway(router: &MultiServiceRouter, case: &str, name: &str) -> String {
    let created = send(router, "POST", "/gateways/", Some(&gateway_body(name))).await;
    assert_eq!(
        (created.status, text(&created.body, "status").as_str()),
        (202, "CREATING"),
        "case {case:?}: the setup create must leave the gateway CREATING, got {} {} ({})",
        created.status,
        text(&created.body, "status"),
        created.body
    );
    text(&created.body, "gatewayId")
}

/// Read the gateway again until it reports `READY`, or the deadline passes: the transition is
/// the clock's, so the wait looks for the CONDITION rather than for a fixed time.
async fn gateway_ready(router: &MultiServiceRouter, case: &str, gateway_id: &str) {
    let started = Instant::now();
    loop {
        let read = send(router, "GET", &format!("/gateways/{gateway_id}/"), None).await;
        if text(&read.body, "status") == "READY" {
            return;
        }
        assert!(
            started.elapsed() <= POLL_DEADLINE,
            "case {case:?}: the gateway never settled to READY, last read {} ({})",
            read.status,
            read.body
        );
        tokio::time::sleep(POLL_PAUSE).await;
    }
}

/// A `CreateGatewayTarget` body: an MCP target serving an inline OpenAPI schema.
fn target_create_body(name: &str) -> Value {
    json!({
        "name": name,
        "targetConfiguration": {"mcp": {"openApiSchema": {
            "inlinePayload": "{\"openapi\":\"3.0.0\"}"
        }}},
        "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}],
    })
}

/// An `UpdateGatewayTarget` body. `credentialProviderConfigurations` is `@required` with one
/// entry on the response, so every update defines one.
fn target_update_body() -> Value {
    json!({
        "targetConfiguration": {"mcp": {"openApiSchema": {
            "inlinePayload": "{\"openapi\":\"3.0.9\"}"
        }}},
        "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}],
    })
}

/// One row of the target family's refusal table.
struct Row {
    case: &'static str,
    /// The operation attempted, which is also the name its refusal carries.
    operation: &'static str,
    /// The `GatewayStatus` token the gateway reports when the operation is attempted, which
    /// is also the token its refusal carries.
    status: &'static str,
}

/// The target family against every status a gateway can refuse one of them in.
///
/// `UPDATE_UNSUCCESSFUL` and `FAILED` are `GatewayStatus` tokens no sequence of this
/// service's operations puts a gateway in, and `READY` is the status that SERVES these
/// operations, so the statuses below are the ones a row can drive a gateway into.
/// `UpdateGatewayTarget` is paired only with `UPDATING`: it resolves the target the path
/// names before it judges the gateway, so it needs a live target — and a gateway that still
/// holds one serves no deletion of its own, which is the only way to reach `DELETING`.
fn rows() -> [Row; 10] {
    [
        Row {
            case: "a target created while the gateway is still being created",
            operation: "CreateGatewayTarget",
            status: "CREATING",
        },
        Row {
            case: "a target created while an update is in flight on the gateway",
            operation: "CreateGatewayTarget",
            status: "UPDATING",
        },
        Row {
            case: "a target created once the gateway's deletion was accepted",
            operation: "CreateGatewayTarget",
            status: "DELETING",
        },
        Row {
            case: "a target deleted while the gateway is still being created",
            operation: "DeleteGatewayTarget",
            status: "CREATING",
        },
        Row {
            case: "a target deleted while an update is in flight on the gateway",
            operation: "DeleteGatewayTarget",
            status: "UPDATING",
        },
        Row {
            case: "a target deleted once the gateway's deletion was accepted",
            operation: "DeleteGatewayTarget",
            status: "DELETING",
        },
        Row {
            case: "targets synchronized while the gateway is still being created",
            operation: "SynchronizeGatewayTargets",
            status: "CREATING",
        },
        Row {
            case: "targets synchronized while an update is in flight on the gateway",
            operation: "SynchronizeGatewayTargets",
            status: "UPDATING",
        },
        Row {
            case: "targets synchronized once the gateway's deletion was accepted",
            operation: "SynchronizeGatewayTargets",
            status: "DELETING",
        },
        Row {
            case: "a target updated while an update is in flight on the gateway",
            operation: "UpdateGatewayTarget",
            status: "UPDATING",
        },
    ]
}

/// Rule 1: every operation on a gateway's targets is refused in the one sentence, naming
/// itself and the raw status token the gateway reports.
#[tokio::test]
async fn a_target_operation_is_refused_in_the_target_familys_own_sentence() {
    for (index, row) in rows().into_iter().enumerate() {
        let Row {
            case,
            operation,
            status,
        } = row;
        let router = router();
        let gateway_id = creating_gateway(&router, case, &format!("statewording{index}")).await;

        // `UpdateGatewayTarget` resolves the target before it judges the gateway, so its row
        // needs a target created while the gateway still served one.
        let target_id = if operation == "UpdateGatewayTarget" {
            gateway_ready(&router, case, &gateway_id).await;
            let created = send(
                &router,
                "POST",
                &format!("/gateways/{gateway_id}/targets/"),
                Some(&target_create_body("wordingtarget")),
            )
            .await;
            assert_eq!(
                created.status, 202,
                "case {case:?}: the setup target must be created while the gateway is READY, \
                 got {} ({})",
                created.status, created.body
            );
            text(&created.body, "targetId")
        } else {
            ABSENT_TARGET_ID.to_string()
        };

        // The gateway is driven into the status this row is about. `CREATING` is where the
        // create left it, so that row waits for nothing.
        match status {
            "CREATING" => {}
            "UPDATING" | "DELETING" => {
                if operation != "UpdateGatewayTarget" {
                    gateway_ready(&router, case, &gateway_id).await;
                }
                let (method, body) = if status == "UPDATING" {
                    ("PUT", Some(gateway_body(&format!("statewording{index}"))))
                } else {
                    ("DELETE", None)
                };
                let moved = send(
                    &router,
                    method,
                    &format!("/gateways/{gateway_id}/"),
                    body.as_ref(),
                )
                .await;
                assert_eq!(
                    (moved.status, text(&moved.body, "status").as_str()),
                    (202, status),
                    "case {case:?}: the setup call must leave the gateway in {status}, got {} {} \
                     ({})",
                    moved.status,
                    text(&moved.body, "status"),
                    moved.body
                );
            }
            other => panic!("case {case:?}: no setup drives a gateway into {other:?}"),
        }

        let refused = match operation {
            "CreateGatewayTarget" => {
                send(
                    &router,
                    "POST",
                    &format!("/gateways/{gateway_id}/targets/"),
                    Some(&target_create_body("refusedtarget")),
                )
                .await
            }
            "UpdateGatewayTarget" => {
                send(
                    &router,
                    "PUT",
                    &format!("/gateways/{gateway_id}/targets/{target_id}/"),
                    Some(&target_update_body()),
                )
                .await
            }
            "DeleteGatewayTarget" => {
                send(
                    &router,
                    "DELETE",
                    &format!("/gateways/{gateway_id}/targets/{target_id}/"),
                    None,
                )
                .await
            }
            _ => {
                send(
                    &router,
                    "PUT",
                    &format!("/gateways/{gateway_id}/synchronizeTargets"),
                    Some(&json!({"targetIdList": [target_id]})),
                )
                .await
            }
        };

        assert_eq!(
            (refused.status, error_code(&refused.body).as_str()),
            (400, "ValidationException"),
            "case {case:?}: expected HTTP 400 ValidationException, got {} {} ({})",
            refused.status,
            error_code(&refused.body),
            refused.body
        );
        let expected =
            format!("Cannot perform operation {operation} when gateway is in {status} status");
        assert_eq!(
            text(&refused.body, "message"),
            expected,
            "case {case:?}: expected {expected:?}, got {:?}",
            text(&refused.body, "message")
        );
        // `reason` is `@required` on the shape, and nothing is wrong with the request's
        // members: it is the gateway's own state that refuses it.
        assert_eq!(
            text(&refused.body, "reason"),
            "ResourceConflict",
            "case {case:?}: expected the resource-conflict reason, got {:?} ({})",
            text(&refused.body, "reason"),
            refused.body
        );
        // Rule 3: a refused create mints nothing.
        assert!(
            refused.body.get("targetId").is_none(),
            "case {case:?}: a refused request reports no target, got {}",
            refused.body
        );
    }
}

/// Rule 2: the sentence above is the TARGET family's. An operation on the gateway itself is
/// refused in the gateway family's own words, so the two are pinned side by side.
#[tokio::test]
async fn an_operation_on_the_gateway_itself_keeps_the_gateway_familys_sentence() {
    // (case, the operation attempted, its HTTP method, the status as that family's sentence
    // spells it)
    let rows: [(&str, &str, &str, &str); 2] = [
        (
            "DeleteGateway while the gateway is still being created",
            "DeleteGateway",
            "DELETE",
            "Creating",
        ),
        (
            "UpdateGateway while the gateway is still being created",
            "UpdateGateway",
            "PUT",
            "Creating",
        ),
    ];

    for (case, operation, method, status_prose) in rows {
        let router = router();
        let gateway_id = creating_gateway(&router, case, "gatewayfamily").await;
        let body = (method == "PUT").then(|| gateway_body("gatewayfamily"));
        let refused = send(
            &router,
            method,
            &format!("/gateways/{gateway_id}/"),
            body.as_ref(),
        )
        .await;
        assert_eq!(
            (refused.status, error_code(&refused.body).as_str()),
            (400, "ValidationException"),
            "case {case:?}: expected HTTP 400 ValidationException, got {} {} ({})",
            refused.status,
            error_code(&refused.body),
            refused.body
        );
        let expected = format!(
            "{operation} operation can't be performed on gateway when it is in {status_prose} \
             state. Retry the request when the gateway is in a valid state."
        );
        assert_eq!(
            text(&refused.body, "message"),
            expected,
            "case {case:?}: expected {expected:?}, got {:?}",
            text(&refused.body, "message")
        );
    }
}
