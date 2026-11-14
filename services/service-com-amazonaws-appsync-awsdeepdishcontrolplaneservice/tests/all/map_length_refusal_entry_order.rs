// SPDX-License-Identifier: CC0-1.0

//! The MAP a constraint refusal quotes, and the ORDER its entries are stated in.
//!
//! The rule under test: a clause refusing a map-typed member for the `@length` its target
//! shape declares quotes the map the REQUEST carried — rendered `{<key>=<value>, …}` — with
//! its entries in the order the request wrote them, not in an order the service chose. The
//! entry order is a property of the request body; the built input the validating walk reads
//! holds a string map unordered, so an order recovered from it (key order) is one no caller
//! sent whenever the keys were not written that way.
//!
//! The rows differ along what the rule generalises over: the OPERATION and the map member
//! (`PutGraphqlApiEnvironmentVariables`'s `environmentVariables`, `TagResource`'s `tags`),
//! the ORDER the request wrote its entries in (ascending numeric suffix, descending, odd
//! keys before even, and keys separated by letter case — each an order lexicographic key
//! order differs from), the entry COUNT (one past the bound and well past it), and the BOUND
//! crossed (a maximum, and a minimum whose offending map is empty). A map AT the declared
//! maximum is served, so each refusal is about the bound rather than about the operation.
//!
//! Every bound and expression below is read from the model, named on the constant that
//! carries it.

use bytes::Bytes;
use serde_json::Value;
use smithy_server_runtime::MultiServiceRouter;

use crate::error_contract::router;
use crate::resource_tags::encode_label;

/// The region the test signs for.
const REGION: &str = "eu-west-1";

/// AppSync's own modelled error for a request that is not well formed, and its status:
/// `BadRequestException`, `@httpError(400)`
/// (`smithy_query(query="shape", shape="BadRequestException")`).
const BAD_REQUEST: &str = "BadRequestException";
const BAD_REQUEST_STATUS: u16 = 400;

/// The modelled maximum of `EnvironmentVariableMap`, the entries one API may carry. Source:
/// `smithy_query(query="shape", shape="EnvironmentVariableMap")` — `@length` 0..50.
const ENVIRONMENT_VARIABLES_MAX: usize = 50;

/// The modelled bounds of `TagMap`, the entries one tagging write may carry. Source:
/// `smithy_query(query="shape", shape="TagMap")` — `@length` 1..50.
const TAGS_MIN: usize = 1;
const TAGS_MAX: usize = 50;

/// One answer from the emulator: the parts a client branches on.
#[derive(Debug)]
struct Answer {
    status: u16,
    /// The `x-amzn-errortype` header restJson1 resolves the error shape from.
    error_type: String,
    /// The error body's `message`, or the empty string when there is none.
    message: String,
    body: Value,
}

/// Send one request, with the body as the EXACT text the caller wrote.
///
/// The body is text rather than a `serde_json::Value` because the rule is about the order a
/// JSON object's members were written in, which that type does not carry.
async fn call(
    router: &MultiServiceRouter,
    method: &str,
    path: &str,
    body: Option<String>,
) -> Answer {
    let payload = body.map_or_else(Bytes::new, Bytes::from);
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://appsync.{REGION}.amazonaws.com{path}"))
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIAEMULATOR/20260101/{REGION}/appsync/aws4_request, \
                 SignedHeaders=host, Signature=0000"
            ),
        )
        .body(payload)
        .expect("a well-formed request");

    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let error_type = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = response.into_body();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Answer {
        status,
        error_type,
        message,
        body,
    }
}

/// Create one GraphQL API and answer its id and its ARN.
async fn api(router: &MultiServiceRouter) -> (String, String) {
    let answer = call(
        router,
        "POST",
        "/v1/apis",
        Some(
            r#"{"name":"Api_map_entry_order","authenticationType":"API_KEY"}"#.to_string(),
        ),
    )
    .await;
    assert_eq!(
        answer.status, 200,
        "case \"fixture\": expected CreateGraphqlApi 200, got {answer:?}"
    );
    (
        answer.body["graphqlApi"]["apiId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        answer.body["graphqlApi"]["arn"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// A JSON object holding `pairs` as its members, written in exactly the order given — the
/// wire order the rule is about. Each key and value is escaped by the JSON writer.
fn object(pairs: &[(String, String)]) -> String {
    let members: Vec<String> = pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                serde_json::to_string(key).expect("a JSON string"),
                serde_json::to_string(value).expect("a JSON string")
            )
        })
        .collect();
    format!("{{{}}}", members.join(","))
}

/// A request body carrying `pairs` at `member`, in the order given.
fn body(member: &str, pairs: &[(String, String)]) -> String {
    format!(
        "{{{}:{}}}",
        serde_json::to_string(member).expect("a JSON string"),
        object(pairs)
    )
}

/// `pairs` as a clause quotes a map, in the order given: `{<key>=<value>, …}`.
fn quoted(pairs: &[(String, String)]) -> String {
    let entries: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    format!("{{{}}}", entries.join(", "))
}

/// `pairs` put into key order — the order the built input leaves a string map in, and the
/// one a clause must NOT state when the request wrote another.
fn in_key_order(pairs: &[(String, String)]) -> Vec<(String, String)> {
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|(left, _), (right, _)| left.cmp(right));
    sorted
}

/// `count` well-formed pairs, keyed `VAR<n>` with a value of its own, in ascending `n`.
///
/// Ascending `n` is NOT key order past nine entries (`VAR10` sorts before `VAR2`), which is
/// what makes these rows read on the order at all.
fn numbered(count: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|index| (format!("VAR{index}"), format!("value{index}")))
        .collect()
}

/// `pairs` with the odd positions first and the even ones after them.
fn odd_then_even(pairs: &[(String, String)]) -> Vec<(String, String)> {
    let odd = pairs.iter().skip(1).step_by(2);
    let even = pairs.iter().step_by(2);
    odd.chain(even).cloned().collect()
}

/// `count` pairs whose keys alternate between two letter cases of one stem, so ASCII key
/// order groups every `Var…` ahead of every `var…` while the request interleaves them.
fn alternating_case(count: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|index| {
            let stem = if index.is_multiple_of(2) { "Var" } else { "var" };
            (format!("{stem}_{index}"), format!("v{index}"))
        })
        .collect()
}

/// `count` tag pairs, keyed `tag<n>` in ascending `n` — past nine entries another order than
/// key order, with values drawn from the characters `TagValue` admits.
fn tags(count: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|index| (format!("tag{index}"), format!("value-{index}")))
        .collect()
}

/// One row: a map-typed member refused for its declared `@length`, the order the request
/// wrote its entries in, and the requirement the clause states.
struct Row {
    case: &'static str,
    method: &'static str,
    path: String,
    /// The member path the clause names, as the constraint walk spells it.
    member: &'static str,
    /// The requirement the clause states, as the framework words that constraint class.
    requirement: String,
    /// The entries the request carries, in the order it writes them.
    pairs: Vec<(String, String)>,
}

/// The table: every row crosses a declared `@length` on a MAP, in a different order, count,
/// member and direction.
fn rows(api_id: &str, api_arn: &str) -> Vec<Row> {
    let environment_path = format!("/v1/apis/{api_id}/environmentVariables");
    let tags_path = format!("/v1/tags/{}", encode_label(api_arn));
    let past_max = ENVIRONMENT_VARIABLES_MAX + 1;
    let environment_requirement =
        format!("Member must have length less than or equal to {ENVIRONMENT_VARIABLES_MAX}");
    let descending: Vec<(String, String)> = numbered(past_max).into_iter().rev().collect();
    vec![
        Row {
            case: "one entry past the maximum, ascending numeric suffixes",
            method: "PUT",
            path: environment_path.clone(),
            member: "environmentVariables",
            requirement: environment_requirement.clone(),
            pairs: numbered(past_max),
        },
        Row {
            case: "well past the maximum, ascending numeric suffixes",
            method: "PUT",
            path: environment_path.clone(),
            member: "environmentVariables",
            requirement: environment_requirement.clone(),
            pairs: numbered(ENVIRONMENT_VARIABLES_MAX * 2),
        },
        Row {
            case: "one entry past the maximum, descending numeric suffixes",
            method: "PUT",
            path: environment_path.clone(),
            member: "environmentVariables",
            requirement: environment_requirement.clone(),
            pairs: descending,
        },
        Row {
            case: "one entry past the maximum, odd keys before even",
            method: "PUT",
            path: environment_path.clone(),
            member: "environmentVariables",
            requirement: environment_requirement.clone(),
            pairs: odd_then_even(&numbered(past_max)),
        },
        Row {
            case: "one entry past the maximum, keys interleaving two letter cases",
            method: "PUT",
            path: environment_path,
            member: "environmentVariables",
            requirement: environment_requirement,
            pairs: alternating_case(past_max),
        },
        Row {
            case: "a tag map one entry past its maximum",
            method: "POST",
            path: tags_path.clone(),
            member: "tags",
            requirement: format!("Member must have length less than or equal to {TAGS_MAX}"),
            pairs: tags(TAGS_MAX + 1),
        },
        Row {
            case: "a tag map below its minimum, which holds no entry at all",
            method: "POST",
            path: tags_path,
            member: "tags",
            requirement: format!("Member must have length greater than or equal to {TAGS_MIN}"),
            pairs: Vec::new(),
        },
    ]
}

/// RULE: the clause quotes the map the request carried, with its entries in the order the
/// request wrote them.
#[tokio::test]
async fn a_map_length_refusal_quotes_the_map_in_the_submitted_order() {
    let router = router();
    let (api_id, api_arn) = api(&router).await;

    for row in rows(&api_id, &api_arn) {
        let Row {
            case,
            method,
            path,
            member,
            requirement,
            pairs,
        } = row;
        let answer = call(&router, method, &path, Some(body(member, &pairs))).await;
        assert_eq!(
            (answer.status, answer.error_type.as_str()),
            (BAD_REQUEST_STATUS, BAD_REQUEST),
            "case {case:?}: expected {BAD_REQUEST_STATUS} {BAD_REQUEST}, got {answer:?}"
        );
        let expected = format!(
            "1 validation error detected: Value '{}' at '{member}' failed to satisfy \
             constraint: {requirement}",
            quoted(&pairs)
        );
        assert_eq!(
            answer.message, expected,
            "case {case:?}: expected the clause {expected:?}, got {:?}",
            answer.message
        );
    }
}

/// RULE, stated the other way: where the request's order is NOT key order, the clause does
/// not state the key-ordered rendering — the order the built input the walk reads leaves the
/// map in.
#[tokio::test]
async fn a_map_length_refusal_does_not_state_the_key_order() {
    let router = router();
    let (api_id, api_arn) = api(&router).await;

    for row in rows(&api_id, &api_arn) {
        let Row {
            case, path, pairs, ..
        } = row;
        let sorted = in_key_order(&pairs);
        if sorted == pairs {
            // A row the request already wrote in key order states nothing about the
            // difference, so it is not asserted on here.
            continue;
        }
        let answer = call(&router, row.method, &path, Some(body(row.member, &pairs))).await;
        assert!(
            !answer.message.contains(&quoted(&sorted)),
            "case {case:?}: expected the clause not to carry the key-ordered rendering {:?}, \
             got {:?}",
            quoted(&sorted),
            answer.message
        );
    }
}

/// RULE: a map AT the declared maximum is served, so each row above is refused for the bound
/// it crosses rather than for the operation it names — and the refused writes left the API's
/// list and its tags untouched.
#[tokio::test]
async fn a_map_at_the_declared_maximum_is_served_and_a_refused_one_writes_nothing() {
    let router = router();
    let (api_id, api_arn) = api(&router).await;
    let environment_path = format!("/v1/apis/{api_id}/environmentVariables");
    let tags_path = format!("/v1/tags/{}", encode_label(&api_arn));

    for row in rows(&api_id, &api_arn) {
        let answer = call(
            &router,
            row.method,
            &row.path,
            Some(body(row.member, &row.pairs)),
        )
        .await;
        assert_eq!(
            answer.status, BAD_REQUEST_STATUS,
            "case {:?}: expected the row to be refused, got {answer:?}",
            row.case
        );
    }

    let listed = call(&router, "GET", &environment_path, None).await;
    assert_eq!(
        listed.body["environmentVariables"],
        serde_json::json!({}),
        "case \"a refused environment write\": expected no variables on the API, got {listed:?}"
    );
    let held = call(&router, "GET", &tags_path, None).await;
    assert_eq!(
        held.body["tags"],
        serde_json::json!({}),
        "case \"a refused tagging write\": expected no tags on the API, got {held:?}"
    );

    let at_maximum = numbered(ENVIRONMENT_VARIABLES_MAX);
    let written = call(
        &router,
        "PUT",
        &environment_path,
        Some(body("environmentVariables", &at_maximum)),
    )
    .await;
    assert_eq!(
        written.status, 200,
        "case \"a map at the declared maximum\": expected the write to be served, got \
         {written:?}"
    );
    let read = call(&router, "GET", &environment_path, None).await;
    for (key, value) in &at_maximum {
        assert_eq!(
            read.body["environmentVariables"][key].as_str(),
            Some(value.as_str()),
            "case \"a map at the declared maximum\": expected {key}={value} to round-trip, got \
             {read:?}"
        );
    }
}
