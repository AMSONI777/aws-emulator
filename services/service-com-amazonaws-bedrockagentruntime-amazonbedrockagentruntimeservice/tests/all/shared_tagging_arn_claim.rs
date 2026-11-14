// SPDX-License-Identifier: CC0-1.0

//! Which `/tags/{resourceArn}` requests this service answers at all, and how it refuses
//! the ARNs it does answer but cannot resolve.
//!
//! The three tagging routes this model binds (`GET`, `POST` and
//! `DELETE /tags/{resourceArn}`) are bound IDENTICALLY by the Bedrock build-time plane,
//! which publishes a different endpoint under the same signing name, so the one
//! `@httpLabel` is all there is to tell the two apart once the request does not name an
//! endpoint host (`service_common::bedrock`).
//!
//! RULE: this service answers such a request unless the ARN is one the OTHER plane's
//! taggable-resource syntax admits — the resource types that model enumerates together
//! with the ten-alphanumeric identifier form it states for them — because it is the
//! declared owner of the space: an ARN neither syntax admits reaches THIS service, which
//! refuses it with the modelled `ValidationException` (400) quoting the expression it
//! publishes for `resourceArn`, and an ARN its own syntax admits is resolved against the
//! session store.
//!
//! The rows below drive that over the whole class: a resource type of the other plane
//! carrying an identifier no resource of that plane has, a type neither plane admits,
//! another vendor's ARN, a label that is no ARN, and — for contrast — the other plane's
//! own well-formed ARNs, which this service does not answer at all (in the full emulator
//! the build-time plane serves them; `core/router/tests/all/bedrock_signing_name_routing.rs`
//! pins who answers what).

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_bedrockagentruntime_amazonbedrockagentruntimeservice as runtime;

/// The region every request here signs for.
const REGION: &str = "us-west-2";

/// The account id every generated emulator presents (`engine::EMULATOR_ACCOUNT_ID`).
const ACCOUNT: &str = "000000000000";

/// The expression a `resourceArn` refusal of this service QUOTES: the
/// `TaggableResourcesArn` it publishes, stated as the expression the whole value must
/// match (this crate's `service::PUBLISHED_PATTERNS`, and
/// `tests/all/pattern_constraint_messages.rs` for the rule that strips the anchors).
const PUBLISHED_TAGGABLE_ARN: &str = "arn:aws(-[^:]+)?:bedrock:[a-zA-Z0-9-]+:[0-9]{12}\
                                      :(session|advanced-optimize-prompt-job)/[a-zA-Z0-9-]+";

/// The sentence this plane states when a `resourceArn` it admits names no stored session
/// (`tests/all/tagging.rs` owns that rule; it is read here only to show that the ARN
/// reached this service's store).
const SESSION_NOT_FOUND: &str = "Session resource not found.";

/// The error code the router answers when NO mounted service claims a request — not an
/// AWS error code, and here the evidence that this service left the request to the plane
/// that binds the same route.
const NOT_THIS_PLANE: &str = "UnknownService";

fn router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(runtime::EmulatedService::new(engine));
    router
}

/// One ARN percent-encoded for a non-greedy `@httpLabel`, as an SDK sends it.
fn label(arn: &str) -> String {
    arn.replace('%', "%25").replace(':', "%3A").replace('/', "%2F")
}

/// One answer: the status, the wire error code and the `message` member.
struct Answer {
    status: u16,
    error_code: String,
    message: String,
}

/// Send one tagging request for `arn`, on the route `method` names, with the members that
/// operation's own model requires so the only thing a refusal can be about is the ARN.
async fn tagging_call(router: &MultiServiceRouter, method: &str, arn: &str) -> Answer {
    let (path, body) = match method {
        "POST" => (
            format!("/tags/{}", label(arn)),
            json!({ "tags": { "estate": "claim" } }),
        ),
        "DELETE" => (
            format!("/tags/{}?tagKeys=estate", label(arn)),
            Value::Null,
        ),
        _ => (format!("/tags/{}", label(arn)), Value::Null),
    };
    let payload = if body.is_null() {
        Bytes::new()
    } else {
        Bytes::from(serde_json::to_vec(&body).expect("the test body serializes"))
    };
    let request = http::Request::builder()
        .method(method)
        .uri(&path)
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDTESTONLY/20261021/{REGION}/bedrock/aws4_request, \
                 SignedHeaders=host, Signature=0000"
            ),
        )
        .header("content-type", "application/json")
        .body(payload)
        .expect("the test request builds");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let header_code = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let bytes = response.into_body();
    let value: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    let error_code = header_code
        .or_else(|| {
            value
                .get("__type")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_default()
        .rsplit('#')
        .next()
        .unwrap_or_default()
        .to_string();
    Answer {
        status,
        error_code,
        message: value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

/// What a row expects of the answer.
enum Expected {
    /// This service answered and refused the ARN against its published expression.
    RefusedAsBadArn,
    /// This service answered and resolved the ARN against its session store.
    ResolvedAgainstSessions,
    /// This service did not claim the request: it belongs to the plane that binds the
    /// same route for the resources it mints.
    NotThisPlane,
}

/// The one-violation envelope over the published clause, for the value a request sent.
fn one_pattern_error(value: &str) -> String {
    format!(
        "1 validation error detected: Value '{value}' at 'resourceArn' failed to satisfy \
         constraint: Member must satisfy regular expression pattern: {PUBLISHED_TAGGABLE_ARN}"
    )
}

/// RULE, over a TABLE spanning the class and all three identically-bound routes: an ARN
/// the other plane's taggable-resource syntax does not admit reaches THIS service, which
/// refuses it 400 `ValidationException` quoting the expression it publishes; an ARN this
/// service's own syntax admits is resolved against its session store; and an ARN the other
/// plane's syntax admits is not this service's request at all.
///
/// The rows differ along the resource type the ARN names (the other plane's, this one's,
/// one neither admits), the identifier form (past the other plane's, short of it, absent,
/// punctuated, a uuid), the vendor field, the partition, and the shape of a label that is
/// no ARN.
#[tokio::test]
async fn the_tagging_space_this_plane_shares_is_answered_for_the_arns_it_owns() {
    let router = router();

    let rows: Vec<(&str, String, Expected)> = vec![
        (
            // The build-time plane's resource TYPE with an identifier no resource of that
            // plane carries: that plane's syntax does not admit it, and neither does this
            // one, so the declared owner answers — refusing it against ITS expression.
            "an agent ARN whose identifier is past the other plane's form",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/NOTASESSION"),
            Expected::RefusedAsBadArn,
        ),
        (
            "a knowledge-base ARN whose identifier is one character short of it",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:knowledge-base/KB1234567"),
            Expected::RefusedAsBadArn,
        ),
        (
            "a flow ARN carrying no identifier at all",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:flow/"),
            Expected::RefusedAsBadArn,
        ),
        (
            "an agent-alias ARN whose identifier carries punctuation that form excludes",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:agent-alias/AGENT-1234/ALIAS12345"),
            Expected::RefusedAsBadArn,
        ),
        (
            "a prompt ARN in another partition, with an over-long identifier",
            format!("arn:aws-us-gov:bedrock:us-gov-west-1:{ACCOUNT}:prompt/PROMPT12345"),
            Expected::RefusedAsBadArn,
        ),
        (
            "a bedrock ARN of a resource type neither plane's tagging admits",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:guardrail/gr1234567890"),
            Expected::RefusedAsBadArn,
        ),
        (
            "another vendor's ARN carrying this plane's own resource type",
            format!("arn:aws:sqs:us-east-1:{ACCOUNT}:session/0cabde93-58b4-4d68-b230-90df328e1acb"),
            Expected::RefusedAsBadArn,
        ),
        (
            "a session ARN whose body is no uuid",
            format!("arn:aws:bedrock:{REGION}:{ACCOUNT}:session/NOTAUUID"),
            Expected::RefusedAsBadArn,
        ),
        (
            "a label that is no ARN at all",
            "not-an-arn-at-all-but-long-enough".to_string(),
            Expected::RefusedAsBadArn,
        ),
        (
            "a session ARN this plane's own syntax admits",
            format!("arn:aws:bedrock:{REGION}:{ACCOUNT}:session/0cabde93-58b4-4d68-b230-90df328e1acb"),
            Expected::ResolvedAgainstSessions,
        ),
        (
            "a session ARN of another partition, which that syntax admits too",
            format!(
                "arn:aws-us-gov:bedrock:us-gov-west-1:{ACCOUNT}\
                 :session/11111111-2222-3333-4444-555555555555"
            ),
            Expected::ResolvedAgainstSessions,
        ),
        (
            // The other plane's own resources: ten alphanumerics, in either case.
            "an agent ARN the other plane's syntax admits",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/AGENT12345"),
            Expected::NotThisPlane,
        ),
        (
            "a knowledge-base ARN it admits",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:knowledge-base/KB12345678"),
            Expected::NotThisPlane,
        ),
        (
            "a lower-case flow identifier it admits",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:flow/aZ09aZ09aZ"),
            Expected::NotThisPlane,
        ),
        (
            "a prompt version ARN it admits",
            format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:prompt/PROMPT1234:3"),
            Expected::NotThisPlane,
        ),
    ];

    for (case, arn, expected) in &rows {
        for method in ["GET", "POST", "DELETE"] {
            let answer = tagging_call(&router, method, arn).await;
            let case = format!("{case} ({method})");
            match expected {
                Expected::RefusedAsBadArn => {
                    assert_eq!(
                        (answer.status, answer.error_code.as_str()),
                        (400, "ValidationException"),
                        "case {case:?} ({arn}): expected 400 ValidationException, got {} {} \
                         {:?}",
                        answer.status,
                        answer.error_code,
                        answer.message
                    );
                    let wanted = one_pattern_error(arn);
                    assert_eq!(
                        answer.message, wanted,
                        "case {case:?} ({arn}): expected message {wanted:?}, got {:?}",
                        answer.message
                    );
                }
                Expected::ResolvedAgainstSessions => {
                    assert_eq!(
                        (answer.status, answer.error_code.as_str()),
                        (404, "ResourceNotFoundException"),
                        "case {case:?} ({arn}): expected the session store's 404, got {} {} \
                         {:?}",
                        answer.status,
                        answer.error_code,
                        answer.message
                    );
                    assert_eq!(
                        answer.message, SESSION_NOT_FOUND,
                        "case {case:?} ({arn}): expected {SESSION_NOT_FOUND:?}, got {:?}",
                        answer.message
                    );
                }
                Expected::NotThisPlane => {
                    assert_eq!(
                        (answer.status, answer.error_code.as_str()),
                        (404, NOT_THIS_PLANE),
                        "case {case:?} ({arn}): this service must leave the request to the \
                         plane that mints the named resource, got {} {} {:?}",
                        answer.status,
                        answer.error_code,
                        answer.message
                    );
                }
            }
        }
    }
}

/// RULE: a tagging request that names an ENDPOINT HOST is served by that endpoint's
/// plane — AWS's own discriminator — so this service answers one addressed to its own
/// endpoint whatever ARN it carries, and leaves one addressed to the build-time plane's
/// endpoint alone, whichever syntax the ARN satisfies.
#[tokio::test]
async fn the_endpoint_the_request_addresses_decides_before_the_arn_does() {
    let router = router();

    // The other plane's own ARN, which the ARN tier would hand to that plane.
    let build_time_arn = format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/AGENT12345");
    // This plane's own ARN, which the ARN tier would keep here.
    let session_arn =
        format!("arn:aws:bedrock:{REGION}:{ACCOUNT}:session/0cabde93-58b4-4d68-b230-90df328e1acb");

    // (case, the Host the client sends, the ARN, the status, the wire error code)
    let rows: [(&str, &str, &String, u16, &str); 4] = [
        (
            "this service's own endpoint, with the other plane's ARN",
            "bedrock-agent-runtime.us-east-1.amazonaws.com",
            &build_time_arn,
            400,
            "ValidationException",
        ),
        (
            "the build-time plane's endpoint, with this plane's own ARN",
            "bedrock-agent.us-east-1.amazonaws.com",
            &session_arn,
            404,
            NOT_THIS_PLANE,
        ),
        (
            "the emulator's own endpoint: the ARN decides, and this one is the other \
             plane's",
            "localhost:4566",
            &build_time_arn,
            404,
            NOT_THIS_PLANE,
        ),
        (
            "the emulator's own endpoint with this plane's own ARN",
            "localhost:4566",
            &session_arn,
            404,
            "ResourceNotFoundException",
        ),
    ];

    for (case, host, arn, status, code) in &rows {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("/tags/{}", label(arn)))
            .header("host", *host)
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 \
                     Credential=AKIDTESTONLY/20261021/{REGION}/bedrock/aws4_request, \
                     SignedHeaders=host, Signature=0000"
                ),
            )
            .body(Bytes::new())
            .expect("the test request builds");
        let response = router.dispatch(request).await;
        let actual_status = response.status().as_u16();
        let header_code = response
            .headers()
            .get("x-amzn-errortype")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let bytes = response.into_body();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let actual_code = header_code
            .or_else(|| {
                value
                    .get("__type")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .unwrap_or_default()
            .rsplit('#')
            .next()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            (actual_status, actual_code.as_str()),
            (*status, *code),
            "case {case:?} (host {host}, {arn}): expected HTTP {status} {code}, got \
             {actual_status} {actual_code} {value:?}"
        );
    }
}
