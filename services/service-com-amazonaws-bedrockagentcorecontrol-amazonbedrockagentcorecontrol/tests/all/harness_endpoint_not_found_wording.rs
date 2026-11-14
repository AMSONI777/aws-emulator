// SPDX-License-Identifier: CC0-1.0

//! How an operation that addresses ONE harness endpoint words a resource it cannot find,
//! end to end over HTTP.
//!
//! One rule, read off the Smithy model rather than off any one recorded request: an
//! operation whose route addresses a single harness endpoint binds BOTH identifiers the
//! endpoint is named by as `@required` `@httpLabel` members, so the lookup it performs is
//! the endpoint's and its `ResourceNotFoundException` (HTTP 404) is worded at endpoint
//! granularity — "Endpoint <endpointName> not found for harness <harnessId>." — with the
//! two variable parts taken from the request path. The sentence does not depend on which
//! of the two the store is missing, and it does not depend on the asking operation, so the
//! read and the delete of the same unknown endpoint answer byte for byte alike. An
//! operation whose route addresses the HARNESS instead (the create, which names the new
//! endpoint in its body) keeps the harness family's own sentence, so the granularity
//! follows the route rather than the resource family.
//!
//! Sources: `smithy_query(query="operation",operation="GetHarnessEndpoint,\
//! DeleteHarnessEndpoint,CreateHarnessEndpoint")` for the routes, the `@httpLabel` members
//! and the modelled errors with their HTTP statuses, and the `HarnessId` /
//! `HarnessEndpointName` patterns quoted below for the identifier forms the rows span.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_bedrockagentcorecontrol_amazonbedrockagentcorecontrol::EmulatedService;

/// The region every request here is signed for.
const REGION: &str = "us-east-1";

/// A role ARN inside `RoleArn`'s pattern `^arn:aws(-[^:]+)?:iam::([0-9]{12})?:role/.+$`.
const ROLE_ARN: &str = "arn:aws:iam::000000000000:role/HarnessRole";

/// A `harnessId` inside `HarnessId`'s pattern
/// `^[a-zA-Z][a-zA-Z0-9_]{0,39}-[a-zA-Z0-9]{10}$` that no row ever creates.
const ABSENT_HARNESS_ID: &str = "noSuchHarness-abcdefghij";

fn router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::default();
    router.register_service(EmulatedService::new(engine));
    router
}

/// A SigV4 `Authorization` header for this service: what the router routes on.
fn authorization() -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/bedrock-agentcore/\
         aws4_request, SignedHeaders=host, Signature=abc"
    )
}

/// One answer: the status, the error code `restJson1` puts in `__type`, the `message` the
/// body carries and the parsed body itself.
struct Answer {
    status: u16,
    code: String,
    message: String,
    body: Value,
}

async fn send(router: &MultiServiceRouter, method: &str, uri: &str, body: Option<&Value>) -> Answer {
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
    let status = response.status().as_u16();
    let parsed: Value = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    Answer {
        status,
        code: parsed
            .get("__type")
            .and_then(Value::as_str)
            .unwrap_or("<no __type>")
            .rsplit('#')
            .next()
            .unwrap_or_default()
            .to_string(),
        message: parsed
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        body: parsed,
    }
}

fn text(body: &Value, pointer: &str) -> String {
    body.pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Create one harness and return the `harnessId` the service minted for it.
async fn create_harness(router: &MultiServiceRouter, name: &str) -> String {
    let answer = send(
        router,
        "POST",
        "/harnesses",
        Some(&json!({
            "harnessName": name,
            "executionRoleArn": ROLE_ARN,
            "model": {"bedrockModelConfig": {"modelId": "amazon.nova-pro-v1:0"}},
        })),
    )
    .await;
    assert_eq!(
        answer.status, 201,
        "setup: creating the harness {name:?} must succeed for this suite to say anything, got {} \
         with {}",
        answer.status, answer.body
    );
    text(&answer.body, "/harness/harnessId")
}

/// `POST /harnesses/{harnessId}/endpoints` — the route the model binds
/// `CreateHarnessEndpoint` at, which addresses the HARNESS and names the endpoint in the
/// body.
async fn create_endpoint(router: &MultiServiceRouter, harness_id: &str, name: &str) -> Answer {
    send(
        router,
        "POST",
        &format!("/harnesses/{harness_id}/endpoints"),
        Some(&json!({"endpointName": name})),
    )
    .await
}

/// The sentence an operation addressing one endpoint owes for an endpoint it cannot find.
fn endpoint_not_found(endpoint_name: &str, harness_id: &str) -> String {
    format!("Endpoint {endpoint_name} not found for harness {harness_id}.")
}

/// The two operations whose route addresses ONE endpoint, with the HTTP method each is
/// bound to: both must answer the identical sentence, so the verb cannot appear in it.
const ENDPOINT_OPERATIONS: [(&str, &str); 2] =
    [("GetHarnessEndpoint", "GET"), ("DeleteHarnessEndpoint", "DELETE")];

/// THE RULE: every operation that addresses one endpoint reports an endpoint it cannot find
/// at endpoint granularity, whatever is missing and whichever operation asked.
///
/// The rows differ along which of the two identifiers the store does not hold (the harness,
/// the endpoint, both), along where the named endpoint does exist (nowhere, on another
/// harness), and along the identifiers' form: the shortest `HarnessEndpointName` the
/// pattern admits, one carrying digits and underscores, and the longest the pattern admits.
#[tokio::test]
async fn an_operation_addressing_one_endpoint_reports_the_endpoint() {
    let router = router();
    let owner = create_harness(&router, "ownerHarness").await;
    let other = create_harness(&router, "otherHarness").await;
    let created = create_endpoint(&router, &owner, "onlyHere").await;
    assert_eq!(
        created.status, 201,
        "setup: the endpoint create must succeed for this suite to say anything, got {} with {}",
        created.status, created.body
    );

    // `HarnessEndpointName` is `^[a-zA-Z][a-zA-Z0-9_]{0,47}$`: one leading letter plus up to
    // 47 more characters, so the longest name is 48 characters.
    let longest_endpoint_name = format!("e{}", "x".repeat(47));
    // `HarnessId` is `^[a-zA-Z][a-zA-Z0-9_]{0,39}-[a-zA-Z0-9]{10}$`: the longest id is 40
    // characters, a hyphen and 10 more.
    let longest_harness_id = format!("h{}-0123456789", "a".repeat(39));

    // (case, the harnessId the path carries, the endpointName the path carries)
    let rows: Vec<(&str, String, String)> = vec![
        (
            "neither the harness nor the endpoint is stored",
            ABSENT_HARNESS_ID.to_string(),
            "missingEndpoint".to_string(),
        ),
        (
            "the harness is stored, the endpoint it is asked for is not",
            owner.clone(),
            "neverCreated".to_string(),
        ),
        (
            "the harness is stored and the endpoint exists on ANOTHER harness",
            other.clone(),
            "onlyHere".to_string(),
        ),
        (
            "the endpoint name is stored elsewhere but this harness is not",
            ABSENT_HARNESS_ID.to_string(),
            "onlyHere".to_string(),
        ),
        (
            "a name carrying digits and underscores",
            owner.clone(),
            "canary_v2_0".to_string(),
        ),
        (
            "the shortest name the pattern admits",
            owner.clone(),
            "e".to_string(),
        ),
        (
            "the longest name the pattern admits",
            owner.clone(),
            longest_endpoint_name.clone(),
        ),
        (
            "the longest harness id the pattern admits, which nothing created",
            longest_harness_id.clone(),
            longest_endpoint_name,
        ),
    ];

    for (case, harness_id, endpoint_name) in rows {
        let expected = endpoint_not_found(&endpoint_name, &harness_id);
        let mut sentences = Vec::new();
        for (operation, method) in ENDPOINT_OPERATIONS {
            let answer = send(
                &router,
                method,
                &format!("/harnesses/{harness_id}/endpoints/{endpoint_name}"),
                None,
            )
            .await;
            assert_eq!(
                (answer.status, answer.code.as_str()),
                (404, "ResourceNotFoundException"),
                "case {case:?} ({operation}): an endpoint that is not there is the modelled 404 \
                 ResourceNotFoundException, got {} {:?} with {}",
                answer.status,
                answer.code,
                answer.body
            );
            assert_eq!(
                answer.message, expected,
                "case {case:?} ({operation}): expected {expected:?}, got {:?}",
                answer.message
            );
            sentences.push((operation, answer.message));
        }
        let (first_operation, first) = &sentences[0];
        for (operation, sentence) in &sentences[1..] {
            assert_eq!(
                sentence, first,
                "case {case:?}: {operation} must answer exactly what {first_operation} answers, \
                 so the verb cannot appear in the sentence, got {sentence:?} against {first:?}"
            );
        }
    }

    // None of the refusals above touched the store: the endpoint its own harness holds
    // still reads, and the harness that never held one still holds none.
    let held = send(
        &router,
        "GET",
        &format!("/harnesses/{owner}/endpoints/onlyHere"),
        None,
    )
    .await;
    assert_eq!(
        (held.status, text(&held.body, "/endpoint/endpointName").as_str()),
        (200, "onlyHere"),
        "case \"the endpoint its harness holds\": the refusals above changed nothing, got {} with \
         {}",
        held.status,
        held.body
    );
}

/// The granularity follows the ROUTE, not the resource family: `CreateHarnessEndpoint`
/// addresses the harness (the endpoint it names does not exist yet), so a harness it cannot
/// find is reported in the harness family's own sentence — while the two operations that
/// address an endpoint on that same unknown harness report the endpoint.
#[tokio::test]
async fn a_create_addresses_the_harness_and_reports_the_harness() {
    let router = router();

    for (case, harness_id, endpoint_name) in [
        ("a harness id nothing created", ABSENT_HARNESS_ID, "live"),
        ("another harness id nothing created", "h_probe2-0123456789", "canary"),
    ] {
        let refused = create_endpoint(&router, harness_id, endpoint_name).await;
        let harness_sentence = format!("Agent with name {harness_id} not found.");
        assert_eq!(
            (refused.status, refused.code.as_str(), refused.message.as_str()),
            (404, "ResourceNotFoundException", harness_sentence.as_str()),
            "case {case:?}: a create addresses the harness, so expected 404 \
             ResourceNotFoundException {harness_sentence:?}, got {} {:?} {:?}",
            refused.status,
            refused.code,
            refused.message
        );

        for (operation, method) in ENDPOINT_OPERATIONS {
            let answer = send(
                &router,
                method,
                &format!("/harnesses/{harness_id}/endpoints/{endpoint_name}"),
                None,
            )
            .await;
            let expected = endpoint_not_found(endpoint_name, harness_id);
            assert_eq!(
                (answer.status, answer.code.as_str(), answer.message.as_str()),
                (404, "ResourceNotFoundException", expected.as_str()),
                "case {case:?} ({operation}): an operation addressing the endpoint reports the \
                 endpoint, expected 404 ResourceNotFoundException {expected:?}, got {} {:?} {:?}",
                answer.status,
                answer.code,
                answer.message
            );
            assert_ne!(
                answer.message, harness_sentence,
                "case {case:?} ({operation}): the endpoint-granularity sentence must not be the \
                 harness's own, got {:?}",
                answer.message
            );
        }
    }
}
