// SPDX-License-Identifier: CC0-1.0

//! WHERE this service states a constraint one of a MAP's VALUES broke, on the wire.
//!
//! The rule under test: a value one entry of a map does not satisfy is refused
//! `400 ValidationException` whose message states ONE clause at the MAP MEMBER — no entry key
//! — quoting the whole map that member held, in key order, and nesting, inside
//! `Map value must satisfy constraint: [ … ]`, every requirement a value of that map has: the
//! constraints its value shape declares, then that a value must be present at all (no map this
//! model declares is `@sparse`). Two bad entries of one map are still ONE clause, because the
//! clause is about the member and not about an entry.
//!
//! A value INSIDE the declared constraints is not refused at all, which is what the bounds of
//! a `@range` are tested on: each published bound is admitted and one past it is refused.
//!
//! The rows span what the rule generalises over: the operation that asked, whether the map
//! member sits at the top level of the input or inside a structure the input nests, the
//! constraint CLASSES the value shape declares (a numeric range on a DOUBLE value shape; a
//! length pair with a pattern on a string one), which end of a range was broken, how the
//! caller spelled a floating-point value (a decimal, a whole number, a negative one), and how
//! many of the map's entries are bad.

use std::sync::Arc;

use serde_json::{json, Value};
use service_com_amazonaws_lambda_awsgirapiservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

use crate::function_lifecycle::{
    function_arn, make_activation_due, make_update_due, package_bytes, zip_file,
};

/// Where `CreateFunction` is bound, from
/// `smithy_query(query="operation", operation="CreateFunction")`
/// (`POST /2015-03-31/functions`).
const FUNCTIONS_URI: &str = "/2015-03-31/functions";

/// Where the tag operations are bound (`/2017-03-31/tags/{Resource}`).
const TAGS_URI: &str = "/2017-03-31/tags";

/// The function the admitted-value rows publish two versions of and alias.
const IN_RANGE_FUNCTION: &str = "in-range-weights";

/// A SigV4 credential scope naming this service's signing name (`lambda`) in `us-east-1`.
/// Nothing in it is verified: the harness turns request authentication off.
const AUTHORIZATION: &str = "AWS4-HMAC-SHA256 \
     Credential=emulator-test-key/20260101/us-east-1/lambda/aws4_request, \
     SignedHeaders=host, Signature=not-verified";

/// A well-formed execution role ARN, satisfying the model's `RoleArn` pattern.
const ROLE: &str = "arn:aws:iam::000000000000:role/service-role/lambda-exec";

/// The error code the framework answers a broken input constraint with on this `restJson1`
/// service.
const VALIDATION_EXCEPTION: &str = "ValidationException";

/// The requirement every value of a map that is not `@sparse` carries beyond the constraints
/// its shape declares.
const VALUE_NOT_NULL: &str = "Member must not be null";

/// What a value of `AdditionalVersionWeights` has to satisfy: `Weight` is a DOUBLE under
/// `@range(min: 0.0, max: 1.0)`
/// (`smithy_query(query="shape", shape="AdditionalVersionWeights,Weight")`). The bounds of a
/// floating-point shape are written as the decimals a floating-point value is written with.
fn weight_value_set() -> String {
    format!(
        "Map value must satisfy constraint: [Member must have value less than or equal to \
         1.0, Member must have value greater than or equal to 0.0, {VALUE_NOT_NULL}]"
    )
}

/// What a value of `Tags` has to satisfy: `TagValue` is `@length(min: 0, max: 256)` and
/// `@pattern("^([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)$")`
/// (`smithy_query(query="shape", shape="Tags,TagValue")`). The expression is quoted without
/// the anchors a whole-value pattern wraps it in, as every `@pattern` requirement of this
/// service is.
fn tag_value_set() -> String {
    format!(
        "Map value must satisfy constraint: [Member must have length less than or equal to \
         256, Member must have length greater than or equal to 0, Member must satisfy \
         regular expression pattern: ([\\p{{L}}\\p{{Z}}\\p{{N}}_.:/=+\\-@]*), {VALUE_NOT_NULL}]"
    )
}

/// The whole message a request breaking one map's value constraints is refused with.
fn one_clause(quoted: &str, member: &str, requirement: &str) -> String {
    format!(
        "1 validation error detected: Value '{quoted}' at '{member}' failed to satisfy \
         constraint: {requirement}"
    )
}

/// What a dispatched request answered.
struct Answer {
    status: u16,
    body: bytes::Bytes,
}

impl Answer {
    /// The body as JSON, or `Value::Null` for an empty body.
    fn json(&self) -> Value {
        if self.body.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!("expected a JSON body, got {error}: {}", self.text())
        })
    }

    /// The wire error code the body names, or the empty string for a success.
    fn error_code(&self) -> String {
        self.json()
            .get("__type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    /// The `message` the refusal carries, or the empty string when it carries none.
    fn message(&self) -> String {
        let body = self.json();
        body.get("message")
            .or_else(|| body.get("Message"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    /// The status and the body, for a failure message.
    fn summary(&self) -> String {
        format!("{} {}", self.status, self.text())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// One service mounted on its own engine, reached the way the production router reaches it.
fn router_on(engine: &Arc<engine::InMemoryEngine>) -> MultiServiceRouter {
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(EmulatedService::new(Arc::clone(engine)));
    router
}

/// Dispatch one JSON request.
async fn call(router: &MultiServiceRouter, method: &str, uri: &str, body: &Value) -> Answer {
    let payload = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body).expect("the test request body must serialize")
    };
    let request = http::Request::builder()
        .method(method)
        .uri(format!("http://lambda.us-east-1.amazonaws.com{uri}"))
        .header("host", "lambda.us-east-1.amazonaws.com")
        .header("authorization", AUTHORIZATION)
        .header("content-type", "application/json")
        .body(bytes::Bytes::from(payload))
        .expect("the test request must build");
    let response = router.dispatch(request).await;
    let (parts, body) = response.into_parts();
    Answer {
        status: parts.status.as_u16(),
        body,
    }
}

/// A `CreateAlias` request naming `alias` on `function`, carrying the routing configuration
/// `weights` describes. The alias and the version it names are inside their own shapes, so
/// the only questionable member is the weights map.
fn create_alias(function: &str, alias: &str, weights: Value) -> (String, Value) {
    (
        format!("{FUNCTIONS_URI}/{function}/aliases"),
        json!({
            "Name": alias,
            "FunctionVersion": "1",
            "RoutingConfig": { "AdditionalVersionWeights": weights },
        }),
    )
}

/// An `UpdateAlias` request on `function`, carrying the same configuration.
fn update_alias(function: &str, weights: Value) -> (String, Value) {
    (
        format!("{FUNCTIONS_URI}/{function}/aliases/live"),
        json!({ "RoutingConfig": { "AdditionalVersionWeights": weights } }),
    )
}

/// A `CreateFunction` request carrying `tags`, with every other member inside its own shape.
fn create_function_with_tags(name: &str, tags: Value) -> (String, Value) {
    (
        FUNCTIONS_URI.to_string(),
        json!({
            "FunctionName": name,
            "Role": ROLE,
            "Runtime": "python3.12",
            "Handler": "lambda_function.lambda_handler",
            "Code": { "ZipFile": zip_file(&package_bytes(64)) },
            "Tags": tags,
        }),
    )
}

/// One row: a request whose maps are judged, and the message it must be refused with.
struct MapValueCase {
    label: &'static str,
    method: &'static str,
    uri: String,
    body: Value,
    expected: String,
}

/// The rows, each a real request this service refuses.
fn refused_cases() -> Vec<MapValueCase> {
    let weights = weight_value_set();
    let tags = tag_value_set();
    let member = "routingConfig.additionalVersionWeights";
    let mut cases: Vec<MapValueCase> = Vec::new();

    // (label, method, the request, the map the clause quotes, the member, the set)
    let (uri, body) = create_alias("weights-over", "live", json!({ "2": 1.5 }));
    cases.push(MapValueCase {
        label: "one weight past the range maximum, in a nested structure",
        method: "POST",
        uri,
        body,
        expected: one_clause("{2=1.5}", member, &weights),
    });

    let (uri, body) = create_alias("weights-under", "live", json!({ "2": -0.25 }));
    cases.push(MapValueCase {
        label: "one weight under the range minimum",
        method: "POST",
        uri,
        body,
        expected: one_clause("{2=-0.25}", member, &weights),
    });

    // A whole number is a floating-point value of this shape, so the clause quotes it as one.
    let (uri, body) = create_alias("weights-whole", "live", json!({ "3": 2 }));
    cases.push(MapValueCase {
        label: "a weight sent as a whole number, quoted as the decimal it is",
        method: "POST",
        uri,
        body,
        expected: one_clause("{3=2.0}", member, &weights),
    });

    let (uri, body) = create_alias("weights-two", "live", json!({ "4": 1.25, "2": 7.5 }));
    cases.push(MapValueCase {
        label: "TWO entries of one map outside the range: still one clause, in key order",
        method: "POST",
        uri,
        body,
        expected: one_clause("{2=7.5, 4=1.25}", member, &weights),
    });

    let (uri, body) = create_alias("weights-mixed", "live", json!({ "2": 0.5, "3": 1.5 }));
    cases.push(MapValueCase {
        label: "one admitted entry beside a refused one: the WHOLE map is quoted",
        method: "POST",
        uri,
        body,
        expected: one_clause("{2=0.5, 3=1.5}", member, &weights),
    });

    // The same member, reached through the OTHER operation that declares it.
    let (uri, body) = update_alias("weights-updated", json!({ "2": 1.5 }));
    cases.push(MapValueCase {
        label: "the same map on UpdateAlias",
        method: "PUT",
        uri,
        body,
        expected: one_clause("{2=1.5}", member, &weights),
    });

    // A string value shape, whose set is a length pair and a pattern.
    let (uri, body) = create_function_with_tags("tag-pattern", json!({ "owner": "bad!value" }));
    cases.push(MapValueCase {
        label: "one tag value outside its pattern, at the input's top level",
        method: "POST",
        uri,
        body,
        expected: one_clause("{owner=bad!value}", "tags", &tags),
    });

    let too_long = "v".repeat(257);
    let (uri, body) = create_function_with_tags("tag-length", json!({ "owner": too_long }));
    cases.push(MapValueCase {
        label: "one tag value past its length maximum",
        method: "POST",
        uri,
        body,
        expected: one_clause(&format!("{{owner={too_long}}}"), "tags", &tags),
    });

    let (uri, body) = create_function_with_tags(
        "tag-two",
        json!({ "owner": "bad!value", "team": "100%" }),
    );
    cases.push(MapValueCase {
        label: "TWO tag values outside the pattern: still one clause, in key order",
        method: "POST",
        uri,
        body,
        expected: one_clause("{owner=bad!value, team=100%}", "tags", &tags),
    });

    // The same map, reached through the other operation that declares it.
    let function_arn = function_arn("tagged");
    cases.push(MapValueCase {
        label: "the same map on TagResource",
        method: "POST",
        uri: format!("{TAGS_URI}/{function_arn}"),
        body: json!({ "Tags": { "owner": "bad!value" } }),
        expected: one_clause("{owner=bad!value}", "tags", &tags),
    });

    cases
}

/// RULE: a constraint one of a map's VALUES broke is stated as ONE clause at the MAP MEMBER,
/// quoting the whole map the request carried in key order and listing every requirement a
/// value of that map has.
#[tokio::test]
async fn a_broken_map_value_constraint_is_stated_once_at_the_map_member() {
    let engine = Arc::new(engine::InMemoryEngine::new());
    let router = router_on(&engine);
    for case in refused_cases() {
        let answer = call(&router, case.method, &case.uri, &case.body).await;
        assert_eq!(
            answer.status,
            400,
            "case {:?}: expected HTTP 400, got {}",
            case.label,
            answer.summary()
        );
        assert_eq!(
            answer.error_code(),
            VALIDATION_EXCEPTION,
            "case {:?}: expected {VALIDATION_EXCEPTION}, got {}",
            case.label,
            answer.summary()
        );
        let message = answer.message();
        assert_eq!(
            message, case.expected,
            "case {:?}: expected {:?}, got {message:?}",
            case.label, case.expected
        );
    }
}

/// RULE: a value INSIDE the value shape's constraints is refused by nothing and PERSISTS, at
/// each published bound of the range and for every admitted spelling — so the clause above
/// states a broken constraint and never a satisfied one.
///
/// Each row is read back through the operation that reports what was stored, so a row proves
/// the value was accepted rather than merely not refused.
#[tokio::test]
async fn a_value_inside_the_declared_constraints_is_accepted_and_read_back() {
    let engine = Arc::new(engine::InMemoryEngine::new());
    let router = router_on(&engine);
    // One function with TWO published versions, so an alias can split its invocations
    // between the version it names and a second one.
    let created = call(
        &router,
        "POST",
        FUNCTIONS_URI,
        &json!({
            "FunctionName": IN_RANGE_FUNCTION,
            "Role": ROLE,
            "Runtime": "python3.12",
            "Handler": "lambda_function.lambda_handler",
            "Code": { "ZipFile": zip_file(&package_bytes(64)) },
        }),
    )
    .await;
    assert_eq!(
        created.status,
        201,
        "CreateFunction must succeed, got {}",
        created.summary()
    );
    // The activation the clock owes, without waiting for it.
    make_activation_due(&engine);
    let published = call(
        &router,
        "POST",
        &format!("{FUNCTIONS_URI}/{IN_RANGE_FUNCTION}/versions"),
        &Value::Null,
    )
    .await;
    assert_eq!(
        published.status,
        201,
        "PublishVersion must succeed, got {}",
        published.summary()
    );
    // A second version, which is a second SNAPSHOT: Lambda publishes one for code that
    // differs from the last version's, so the second publish carries new bytes.
    let second = call(
        &router,
        "PUT",
        &format!("{FUNCTIONS_URI}/{IN_RANGE_FUNCTION}/code"),
        &json!({ "ZipFile": zip_file(&package_bytes(96)), "Publish": true }),
    )
    .await;
    assert_eq!(
        second.status,
        200,
        "UpdateFunctionCode publishing the second version must succeed, got {}",
        second.summary()
    );
    // And the update window that publish opened, which the clock owes too.
    make_update_due(&engine);
    make_activation_due(&engine);

    // (case, the alias, the weights map, the weight `GetAlias` must report for version 2) —
    // each published bound of `@range(0.0, 1.0)`, one inside it, both spellings of a bound a
    // caller can send, and a request carrying no weight at all.
    let rows: &[(&str, &str, Value, Option<f64>)] = &[
        ("the range minimum", "lowest", json!({ "2": 0.0 }), Some(0.0)),
        (
            "the range minimum as a whole number",
            "lowest-whole",
            json!({ "2": 0 }),
            Some(0.0),
        ),
        ("the range maximum", "highest", json!({ "2": 1.0 }), Some(1.0)),
        (
            "the range maximum as a whole number",
            "highest-whole",
            json!({ "2": 1 }),
            Some(1.0),
        ),
        ("inside the range", "inside", json!({ "2": 0.1 }), Some(0.1)),
        ("no weight at all", "unweighted", json!({}), None),
    ];
    for (case, alias, weights, expected) in rows {
        let (uri, body) = create_alias(IN_RANGE_FUNCTION, alias, weights.clone());
        let answer = call(&router, "POST", &uri, &body).await;
        assert_eq!(
            answer.status,
            201,
            "case {case:?}: a weight inside the declared range must be accepted, got {}",
            answer.summary()
        );
        // Read back through the alias read, so the row proves what was STORED.
        let read = call(
            &router,
            "GET",
            &format!("{FUNCTIONS_URI}/{IN_RANGE_FUNCTION}/aliases/{alias}"),
            &Value::Null,
        )
        .await;
        let reported = read
            .json()
            .get("RoutingConfig")
            .and_then(|routing| routing.get("AdditionalVersionWeights"))
            .and_then(|weights| weights.get("2"))
            .and_then(Value::as_f64);
        assert_eq!(
            reported, *expected,
            "case {case:?}: expected GetAlias to report the weight {expected:?}, got {}",
            read.summary()
        );
    }

    // And a tag value inside its own shape, for the other value shape: accepted and read
    // back through the tag read.
    let (uri, body) = create_function_with_tags("tag-admitted", json!({ "owner": "platform" }));
    let answer = call(&router, "POST", &uri, &body).await;
    assert_eq!(
        answer.status,
        201,
        "case \"an admitted tag value\": the create must be accepted, got {}",
        answer.summary()
    );
    let tags = call(
        &router,
        "GET",
        &format!("{TAGS_URI}/{}", function_arn("tag-admitted")),
        &Value::Null,
    )
    .await;
    assert_eq!(
        tags.json()
            .get("Tags")
            .and_then(|held| held.get("owner"))
            .and_then(Value::as_str),
        Some("platform"),
        "case \"an admitted tag value\": expected the tag to be read back, got {}",
        tags.summary()
    );
}
