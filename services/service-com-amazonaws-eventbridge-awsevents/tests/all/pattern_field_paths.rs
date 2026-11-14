// SPDX-License-Identifier: CC0-1.0

//! The FIELD PATH a pattern selects on, end to end over the wire (`awsJson1_1`,
//! `POST /` with `X-Amz-Target: AWSEvents.<Operation>`) through the real
//! `MultiServiceRouter`, with Amazon SQS mounted on the same engine so the routing
//! verdict is read where a client reads it: on each rule's target queue.
//!
//! The RULE asserted here: **an event pattern selects a value by the whole FIELD
//! PATH it sits at — the event is read as the set of paths its values sit at, where
//! a member of an array sits at the path its container sits at and a member name
//! carrying a dot spells the same path that nesting spells — so a pattern matches a
//! value only at the complete path it names, and never a member of the same name at
//! another depth.** `TestEventPattern` and live delivery are two surfaces of that one
//! matcher, so every row asserts both and they have to agree.
//!
//! The rows differ along what the rule generalises over: the DEPTH of the path (two,
//! three and four segments), how the path is SPELLED (by nesting, by a dotted member
//! name, by both at once, and with the dots in the pattern instead of the event),
//! whether the path runs THROUGH an array (one array, two nested arrays, one object
//! of several carrying the value), the kind of term at the end of it (a literal, a
//! `numeric` comparison, `exists` both ways), and the near misses a leaf search
//! would wrongly accept (a skipped level, the leaf at the top, a value deeper than
//! the pattern names, a member name the segment is only a prefix of).
//!
//! Everything is published onto a CUSTOM bus, which is where a client routes its own
//! events, and every queue grants the send the way a client scopes it: an
//! `events.amazonaws.com` `sqs:SendMessage` Allow conditioned on the publishing
//! rule's own ARN, since "for Lambda functions, Amazon SNS topics and Amazon SQS
//! queues, EventBridge relies on resource-based policies" (`PutTargets`).

use std::sync::Arc;

use serde_json::{json, Value};
use service_com_amazonaws_eventbridge_awsevents::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The Region every request below is signed for.
const REGION: &str = "eu-west-1";

/// The custom bus every rule below is created on and every event is published to.
const BUS: &str = "field-path-bus";

/// The `Source` and `DetailType` every event below carries, and the two envelope
/// fields every pattern below is additionally scoped by — so a rule of this suite
/// never matches another suite's traffic.
const SOURCE: &str = "com.demo.field-paths";
const DETAIL_TYPE: &str = "Field Path Probe";

/// The service principal a rule's handover to a queue is made as.
const SERVICE_PRINCIPAL: &str = "events.amazonaws.com";

/// EventBridge and Amazon SQS on one engine: a rule's target is a queue, because a
/// delivery is read back there.
struct Emulator {
    router: MultiServiceRouter,
}

fn emulator() -> Emulator {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(EmulatedService::new(Arc::clone(&engine)));
    router.register_service(service_com_amazonaws_sqs_amazonsqs::EmulatedService::new(
        Arc::clone(&engine),
    ));
    Emulator { router }
}

/// One `awsJson` RPC call against the service whose signing name is `signing_name`.
async fn rpc(
    emulator: &Emulator,
    signing_name: &str,
    target_prefix: &str,
    json_version: &str,
    operation: &str,
    body: &Value,
) -> (u16, Value) {
    let credential = format!(
        "AKIDTESTTESTTEST/20260101/{REGION}/{signing_name}/aws4_request, SignedHeaders=host, \
         Signature=0000"
    );
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("{signing_name}.{REGION}.amazonaws.com"))
        .header(
            "content-type",
            format!("application/x-amz-json-{json_version}"),
        )
        .header("x-amz-target", format!("{target_prefix}.{operation}"))
        .header(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={credential}"),
        )
        .body(bytes::Bytes::from(body.to_string()))
        .expect("the test request is well formed");
    let response = emulator.router.dispatch(request).await;
    let status = response.status().as_u16();
    let bytes = response.into_body();
    let parsed = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|error| {
            panic!(
                "{operation} answered a body that is not JSON ({error}): {:?}",
                String::from_utf8_lossy(&bytes)
            )
        })
    };
    (status, parsed)
}

async fn events(emulator: &Emulator, operation: &str, body: &Value) -> (u16, Value) {
    rpc(emulator, "events", "AWSEvents", "1.1", operation, body).await
}

async fn sqs(emulator: &Emulator, operation: &str, body: &Value) -> (u16, Value) {
    rpc(emulator, "sqs", "AmazonSQS", "1.0", operation, body).await
}

/// The custom bus every rule of a suite is created on.
async fn given_bus(emulator: &Emulator, case: &str) {
    let (status, body) = events(emulator, "CreateEventBus", &json!({ "Name": BUS })).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected CreateEventBus to answer 200, got {status} {body}"
    );
}

/// A queue called `name` that grants `sqs:SendMessage` to EventBridge only for the
/// rule `rule_arn`; answers the queue's url and the ARN a rule names it by.
async fn given_queue(
    emulator: &Emulator,
    case: &str,
    name: &str,
    rule_arn: &str,
) -> (String, String) {
    let (status, body) = sqs(emulator, "CreateQueue", &json!({ "QueueName": name })).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected CreateQueue to answer 200, got {status} {body}"
    );
    let url = body["QueueUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a QueueUrl, got {body}"))
        .to_string();
    let (status, body) = sqs(
        emulator,
        "GetQueueAttributes",
        &json!({ "QueueUrl": url, "AttributeNames": ["QueueArn"] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected GetQueueAttributes to answer 200, got {status} {body}"
    );
    let queue_arn = body["Attributes"]["QueueArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a QueueArn, got {body}"))
        .to_string();
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowThisRule",
            "Effect": "Allow",
            "Principal": { "Service": SERVICE_PRINCIPAL },
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": { "ArnEquals": { "aws:SourceArn": rule_arn } },
        }],
    })
    .to_string();
    let (status, body) = sqs(
        emulator,
        "SetQueueAttributes",
        &json!({ "QueueUrl": url, "Attributes": { "Policy": policy } }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected SetQueueAttributes to answer 200, got {status} {body}"
    );
    (url, queue_arn)
}

/// A rule named `name` on the custom bus carrying `pattern`; answers its ARN.
async fn given_rule(emulator: &Emulator, case: &str, name: &str, pattern: &Value) -> String {
    let (status, body) = events(
        emulator,
        "PutRule",
        &json!({
            "Name": name,
            "EventBusName": BUS,
            "EventPattern": pattern.to_string(),
            "State": "ENABLED",
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected PutRule to answer 200, got {status} {body}"
    );
    body["RuleArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a RuleArn, got {body}"))
        .to_string()
}

/// Point the rule `name` at the queue `queue_arn`.
async fn given_target(emulator: &Emulator, case: &str, name: &str, queue_arn: &str) {
    let (status, body) = events(
        emulator,
        "PutTargets",
        &json!({
            "Rule": name,
            "EventBusName": BUS,
            "Targets": [{ "Id": "t1", "Arn": queue_arn }],
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected PutTargets to answer 200, got {status} {body}"
    );
    assert_eq!(
        body["FailedEntryCount"],
        json!(0),
        "case {case:?}: expected PutTargets to report no failed entry, got {body}"
    );
}

/// Publish one entry per supplied detail onto the custom bus.
async fn publish(emulator: &Emulator, case: &str, details: &[Value]) {
    let entries: Vec<Value> = details
        .iter()
        .map(|detail| {
            json!({
                "EventBusName": BUS,
                "Source": SOURCE,
                "DetailType": DETAIL_TYPE,
                "Detail": detail.to_string(),
            })
        })
        .collect();
    let (status, body) = events(emulator, "PutEvents", &json!({ "Entries": entries })).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected PutEvents to answer 200, got {status} {body}"
    );
    assert_eq!(
        body["FailedEntryCount"],
        json!(0),
        "case {case:?}: expected PutEvents to report no failed entry, got {body}"
    );
}

/// The `detail` of every envelope waiting on the queue at `url`.
async fn delivered(emulator: &Emulator, case: &str, url: &str) -> Vec<Value> {
    let (status, body) = sqs(
        emulator,
        "ReceiveMessage",
        &json!({ "QueueUrl": url, "MaxNumberOfMessages": 10 }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected ReceiveMessage to answer 200, got {status} {body}"
    );
    body["Messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .map(|message| {
                    let text = message["Body"].as_str().unwrap_or_else(|| {
                        panic!("case {case:?}: expected a message Body, got {message}")
                    });
                    let envelope: Value = serde_json::from_str(text).unwrap_or_else(|error| {
                        panic!("case {case:?}: a delivered body is not JSON ({error}): {text}")
                    });
                    envelope["detail"].clone()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The envelope a client pre-flights: every field `TestEventPattern$Event` makes
/// mandatory, carrying `detail`.
fn envelope(detail: &Value) -> Value {
    json!({
        "version": "0",
        "id": "4b7f6c42-0d61-4b1d-9e2a-8f6b2d1c0a55",
        "account": engine::emulator_account_id(),
        "source": SOURCE,
        "time": "2026-03-04T10:20:30Z",
        "region": REGION,
        "resources": [],
        "detail-type": DETAIL_TYPE,
        "detail": detail,
    })
}

/// The verdict `TestEventPattern` answers for one (pattern, event) pair.
async fn preflight(emulator: &Emulator, case: &str, pattern: &Value, detail: &Value) -> bool {
    let (status, body) = events(
        emulator,
        "TestEventPattern",
        &json!({
            "EventPattern": pattern.to_string(),
            "Event": envelope(detail).to_string(),
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected TestEventPattern to answer 200, got {status} {body}"
    );
    body["Result"]
        .as_bool()
        .unwrap_or_else(|| panic!("case {case:?}: expected a boolean Result, got {body}"))
}

/// A pattern over `detail`, scoped to this suite's own source and detail-type the
/// way a client scopes a rule of its own.
fn pattern_over(detail: Value) -> Value {
    json!({ "source": [SOURCE], "detail-type": [DETAIL_TYPE], "detail": detail })
}

/// The seven details one batch below publishes, each named by the path shape it
/// carries the value at.
fn cases() -> Vec<(&'static str, Value)> {
    ::std::vec![
        ("deep", json!({ "o": { "p": { "q": "v" } } })),
        ("deep-wrong-value", json!({ "o": { "p": { "q": "w" } } })),
        ("skipped-level", json!({ "o": { "q": "v" } })),
        ("top-level", json!({ "q": "v" })),
        ("deep-in-array", json!({ "o": [{ "p": { "q": "v" } }] })),
        ("mid", json!({ "o": { "p": "v" } })),
        ("dotted-key", json!({ "o.p": "v" })),
    ]
}

/// Which of [`cases`] a delivered `detail` is, so a queue's contents can be named
/// rather than compared as opaque documents.
fn named(case: &str, delivered: &[Value]) -> Vec<String> {
    let known = cases();
    let mut names: Vec<String> = delivered
        .iter()
        .map(|detail| {
            known
                .iter()
                .find(|(_, candidate)| candidate == detail)
                .map(|(name, _)| (*name).to_string())
                .unwrap_or_else(|| {
                    panic!("case {case:?}: a delivery carried a detail nothing published: {detail}")
                })
        })
        .collect();
    names.sort();
    names
}

/// Three rules on one custom bus, one batch carrying every path shape: each rule's
/// queue receives exactly the events whose values sit at the path its pattern names,
/// and `TestEventPattern` answers the same for every pair.
#[tokio::test]
async fn a_nested_pattern_delivers_exactly_what_sits_at_its_whole_path() {
    // (the rule, its pattern, the cases AWS delivers to it)
    let rules: Vec<(&str, Value, Vec<&str>)> = ::std::vec![
        (
            "control",
            json!({ "source": [SOURCE], "detail-type": [DETAIL_TYPE] }),
            ::std::vec![
                "deep",
                "deep-in-array",
                "deep-wrong-value",
                "dotted-key",
                "mid",
                "skipped-level",
                "top-level",
            ],
        ),
        (
            "deep",
            pattern_over(json!({ "o": { "p": { "q": ["v"] } } })),
            ::std::vec!["deep", "deep-in-array"],
        ),
        (
            "mid",
            pattern_over(json!({ "o": { "p": ["v"] } })),
            ::std::vec!["dotted-key", "mid"],
        ),
    ];

    let emulator = emulator();
    given_bus(&emulator, "three rules on one bus").await;

    let mut queues: Vec<(&str, String, Vec<&str>)> = ::std::vec::Vec::new();
    for (rule, pattern, expected) in &rules {
        let arn = given_rule(&emulator, rule, rule, pattern).await;
        let (url, queue_arn) =
            given_queue(&emulator, rule, &format!("{rule}-queue"), &arn).await;
        given_target(&emulator, rule, rule, &queue_arn).await;
        queues.push((rule, url, expected.clone()));
    }

    // Every pair of the matrix, on the surface a client pre-flights with.
    for (rule, pattern, expected) in &rules {
        for (name, detail) in cases() {
            let case = format!("TestEventPattern: rule {rule:?} against case {name:?}");
            let wanted = expected.contains(&name);
            let verdict = preflight(&emulator, &case, pattern, &detail).await;
            assert_eq!(
                verdict, wanted,
                "case {case:?}: expected Result {wanted}, got {verdict}"
            );
        }
    }

    // One batch carrying all seven, then what each rule's queue holds.
    let details: Vec<Value> = cases().into_iter().map(|(_, detail)| detail).collect();
    publish(&emulator, "one batch of every path shape", &details).await;

    for (rule, url, expected) in &queues {
        let case = format!("delivery: rule {rule:?}");
        let found = named(&case, &delivered(&emulator, &case, url).await);
        let mut wanted: Vec<String> = expected.iter().map(|name| (*name).to_string()).collect();
        wanted.sort();
        assert_eq!(
            found, wanted,
            "case {case:?}: expected the queue to hold exactly {wanted:?}, got {found:?}"
        );
    }
}

/// One row of the wider table: a pattern, the detail it is matched against, and
/// whether the value the pattern names sits at the path the pattern names.
struct Row {
    case: &'static str,
    detail_pattern: Value,
    detail: Value,
    matches: bool,
}

/// Every spelling of a path, every near miss of one, on both surfaces of the one
/// matcher.
#[tokio::test]
async fn every_spelling_of_a_field_path_selects_the_same_value() {
    let rows: Vec<Row> = ::std::vec![
        Row {
            case: "a four-segment path spelled by nesting",
            detail_pattern: json!({ "a": { "b": { "c": { "d": ["x"] } } } }),
            detail: json!({ "a": { "b": { "c": { "d": "x" } } } }),
            matches: true,
        },
        Row {
            case: "the same path with a level skipped in the event",
            detail_pattern: json!({ "a": { "b": { "c": { "d": ["x"] } } } }),
            detail: json!({ "a": { "b": { "d": "x" } } }),
            matches: false,
        },
        Row {
            case: "the leaf of that path at the top of detail",
            detail_pattern: json!({ "a": { "b": { "c": { "d": ["x"] } } } }),
            detail: json!({ "d": "x" }),
            matches: false,
        },
        Row {
            case: "the separator in the pattern's member name, the event nested",
            detail_pattern: json!({ "a.b": ["x"] }),
            detail: json!({ "a": { "b": "x" } }),
            matches: true,
        },
        Row {
            case: "the separator in both the pattern's and the event's member name",
            detail_pattern: json!({ "a.b": ["x"] }),
            detail: json!({ "a.b": "x" }),
            matches: true,
        },
        Row {
            case: "a path spelled half by a dotted name and half by nesting",
            detail_pattern: json!({ "a": { "b": { "c": ["x"] } } }),
            detail: json!({ "a.b": { "c": "x" } }),
            matches: true,
        },
        Row {
            case: "a path running through one array of objects",
            detail_pattern: json!({ "items": { "sku": ["abc"] } }),
            detail: json!({ "items": [{ "sku": "zzz" }, { "sku": "abc" }] }),
            matches: true,
        },
        Row {
            case: "no member of that array carries the value",
            detail_pattern: json!({ "items": { "sku": ["abc"] } }),
            detail: json!({ "items": [{ "sku": "zzz" }, { "sku": "aaa" }] }),
            matches: false,
        },
        Row {
            case: "a path running through two nested arrays",
            detail_pattern: json!({ "a": { "b": ["x"] } }),
            detail: json!({ "a": [[{ "b": "x" }]] }),
            matches: true,
        },
        Row {
            case: "a numeric comparison at the end of a path through an array",
            detail_pattern: json!({ "items": { "count": [{ "numeric": [">", 10] }] } }),
            detail: json!({ "items": [{ "count": 4 }, { "count": 20 }] }),
            matches: true,
        },
        Row {
            case: "that comparison where no member of the array satisfies it",
            detail_pattern: json!({ "items": { "count": [{ "numeric": [">", 10] }] } }),
            detail: json!({ "items": [{ "count": 4 }, { "count": 9 }] }),
            matches: false,
        },
        Row {
            case: "exists false for a path no spelling of the event carries",
            detail_pattern: json!({ "a": { "b": [{ "exists": false }] } }),
            detail: json!({ "a": { "c": "x" } }),
            matches: true,
        },
        Row {
            case: "exists true for a path the event spells with a dotted name",
            detail_pattern: json!({ "a": { "b": [{ "exists": true }] } }),
            detail: json!({ "a.b": "x" }),
            matches: true,
        },
        Row {
            case: "the value sits deeper than the path the pattern names",
            detail_pattern: json!({ "a": { "b": ["x"] } }),
            detail: json!({ "a": { "b": { "c": "x" } } }),
            matches: false,
        },
        Row {
            case: "a member name the pattern's segment is only a prefix of",
            detail_pattern: json!({ "a": ["x"] }),
            detail: json!({ "ab": "x" }),
            matches: false,
        },
        Row {
            case: "a separator inside a compared VALUE, which is no path at all",
            detail_pattern: json!({ "a": ["x.y"] }),
            detail: json!({ "a": "x.y" }),
            matches: true,
        },
    ];

    let emulator = emulator();
    given_bus(&emulator, "one bus for every row").await;

    for (index, row) in rows.iter().enumerate() {
        let case = row.case;
        let pattern = pattern_over(row.detail_pattern.clone());

        // 1. The pre-flight a client runs before it depends on the rule.
        let verdict = preflight(&emulator, case, &pattern, &row.detail).await;
        assert_eq!(
            verdict, row.matches,
            "case {case:?}: expected TestEventPattern to answer {}, got {verdict}",
            row.matches
        );

        // 2. The delivery that verdict predicts, through the same pattern on a rule
        //    of a custom bus and the same detail through `PutEvents`.
        let name = format!("path-row-{index}");
        let arn = given_rule(&emulator, case, &name, &pattern).await;
        let (url, queue_arn) = given_queue(&emulator, case, &name, &arn).await;
        given_target(&emulator, case, &name, &queue_arn).await;
        publish(&emulator, case, ::std::slice::from_ref(&row.detail)).await;

        let found = delivered(&emulator, case, &url).await;
        let wanted = usize::from(row.matches);
        assert_eq!(
            found.len(),
            wanted,
            "case {case:?}: TestEventPattern answered {verdict}, so expected {wanted} \
             delivery/deliveries to this rule's target, got {found:?}"
        );
    }
}
