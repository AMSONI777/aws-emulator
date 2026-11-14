// SPDX-License-Identifier: CC0-1.0

//! An ARRAY-valued event field matches a pattern term when ANY of the values it
//! carries matches it, end to end over the wire through the real
//! `MultiServiceRouter` with Amazon SQS mounted beside EventBridge — so what a
//! rule routed is asserted where a client observes it, on the target queue — and
//! against `TestEventPattern`, which answers the same verdict for the same pair.
//!
//! The RULE asserted here: EventBridge compares a pattern term against the VALUES
//! an event field carries, so a field holding a list matches when some value in it
//! (at any nesting, since a nested list contributes its own values) matches the
//! term, a field holding one value matches when that value does, and a field
//! holding no value at all — an empty list — matches nothing. The rule is about
//! the term, whichever kind it is, so it holds for a literal value, for a
//! `numeric` range and for a `prefix`, `suffix` or `wildcard` content filter
//! alike; a rule whose pattern constrains only the envelope is matched by every
//! event of that source whatever its fields carry.
//!
//! The table spans the class rather than the one recorded case: the rows differ
//! along what the field CARRIES (one value, a list in which one value matches, a
//! list in which none does, a nested list, an empty list, numbers, an object, no
//! such field at all), and the rules differ along the TERM kind the pattern
//! states, so every row is asserted against every term kind at once.
//!
//! The harness (the router with EventBridge and Amazon SQS on one engine) is
//! `tests/all/target_dispatch.rs`'s, and so is the grant a target queue needs.

use serde_json::{json, Value};
use service_com_amazonaws_eventbridge_awsevents::state::{rule_arn, SERVICE_PRINCIPAL};

use crate::target_dispatch::{drain, emulator, events, sqs, Emulator, REGION};

/// The bus every rule below is created on: a custom bus, which is where a client
/// routes its own events.
const BUS: &str = "array-matching-bus";

/// The source and detail type every rule below is scoped to, so one run's events
/// reach only its own rules.
const SOURCE: &str = "com.demo.arrays";
const DETAIL_TYPE: &str = "Array Case";

/// One published event: the `detail` document it carries, named so an assertion
/// can say which one it was.
struct Case {
    name: &'static str,
    detail: Value,
}

/// Every event the table publishes, differing along what the `xs` field carries.
fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "one-of-three",
            detail: json!({ "xs": ["a", "b", "c"] }),
        },
        Case {
            name: "none-of-two",
            detail: json!({ "xs": ["a", "c"] }),
        },
        Case {
            name: "scalar",
            detail: json!({ "xs": "b" }),
        },
        Case {
            name: "nested-array",
            detail: json!({ "xs": [["b"]] }),
        },
        Case {
            name: "doubly-nested-array",
            detail: json!({ "xs": [[["b"], ["c"]]] }),
        },
        Case {
            name: "empty",
            detail: json!({ "xs": [] }),
        },
        Case {
            name: "empty-nested",
            detail: json!({ "xs": [[], []] }),
        },
        Case {
            name: "one-number-over",
            detail: json!({ "xs": [1, 20] }),
        },
        Case {
            name: "no-number-over",
            detail: json!({ "xs": [1, 2] }),
        },
        Case {
            name: "nested-number-over",
            detail: json!({ "xs": [[1, 20]] }),
        },
        Case {
            name: "one-prefixed",
            detail: json!({ "xs": ["zz", "abz"] }),
        },
        Case {
            name: "none-prefixed",
            detail: json!({ "xs": ["zz", "bz"] }),
        },
        Case {
            name: "object-member",
            detail: json!({ "xs": [{ "b": 1 }] }),
        },
        Case {
            name: "another-field",
            detail: json!({ "ys": ["b"] }),
        },
    ]
}

/// One rule of the table: its name, the term its pattern states about `detail.xs`
/// (`None` for the control rule, which constrains only the envelope) and the names
/// of the cases above it must deliver.
struct Rule {
    name: &'static str,
    term: Option<Value>,
    delivers: &'static [&'static str],
}

/// Every rule the table creates, differing along the kind of term the pattern
/// states about the array field.
fn rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "control",
            term: None,
            delivers: &[
                "one-of-three",
                "none-of-two",
                "scalar",
                "nested-array",
                "doubly-nested-array",
                "empty",
                "empty-nested",
                "one-number-over",
                "no-number-over",
                "nested-number-over",
                "one-prefixed",
                "none-prefixed",
                "object-member",
                "another-field",
            ],
        },
        Rule {
            name: "value",
            term: Some(json!(["b"])),
            delivers: &[
                "one-of-three",
                "scalar",
                "nested-array",
                "doubly-nested-array",
            ],
        },
        Rule {
            name: "numeric",
            term: Some(json!([{ "numeric": [">", 10] }])),
            delivers: &["one-number-over", "nested-number-over"],
        },
        Rule {
            name: "prefix",
            term: Some(json!([{ "prefix": "ab" }])),
            delivers: &["one-prefixed"],
        },
        Rule {
            name: "suffix",
            term: Some(json!([{ "suffix": "bz" }])),
            delivers: &["one-prefixed", "none-prefixed"],
        },
        Rule {
            name: "wildcard",
            term: Some(json!([{ "wildcard": "a*z" }])),
            delivers: &["one-prefixed"],
        },
    ]
}

/// The whole pattern a rule of the table carries: the envelope members every rule
/// is scoped by, plus the term it states about the array field.
fn pattern(rule: &Rule) -> Value {
    let mut pattern = json!({ "source": [SOURCE], "detail-type": [DETAIL_TYPE] });
    if let Some(term) = &rule.term {
        pattern["detail"] = json!({ "xs": term });
    }
    pattern
}

/// The queue policy a rule's SQS target needs, scoped by `aws:SourceArn` to the
/// ARN of the rule that delivers to it — which is how a client grants one rule's
/// deliveries and no others.
fn granting_rule(queue_arn: &str, rule: &str) -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowThisRule",
            "Effect": "Allow",
            "Principal": { "Service": SERVICE_PRINCIPAL },
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": { "ArnEquals": { "aws:SourceArn": rule_arn(REGION, BUS, rule) } },
        }],
    })
    .to_string()
}

/// A queue named for `rule`, carrying the grant that rule's deliveries need;
/// answers its url and the ARN a target names it by.
async fn given_queue(emulator: &Emulator, rule: &str) -> (String, String) {
    let name = format!("{rule}-queue");
    let (status, body) = sqs(emulator, "CreateQueue", &json!({ "QueueName": name })).await;
    assert_eq!(status, 200, "case {name:?}: CreateQueue answered {status} {body}");
    let url = body["QueueUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("case {name:?}: no QueueUrl in {body}"))
        .to_string();
    let (status, body) = sqs(
        emulator,
        "GetQueueAttributes",
        &json!({ "QueueUrl": url, "AttributeNames": ["QueueArn"] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {name:?}: GetQueueAttributes answered {status} {body}"
    );
    let arn = body["Attributes"]["QueueArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {name:?}: no QueueArn in {body}"))
        .to_string();
    let (status, body) = sqs(
        emulator,
        "SetQueueAttributes",
        &json!({
            "QueueUrl": url,
            "Attributes": { "Policy": granting_rule(&arn, rule) },
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {name:?}: SetQueueAttributes answered {status} {body}"
    );
    (url, arn)
}

/// Create [`BUS`], then every rule of the table on it with its own queue target;
/// answers each rule's queue url in the table's order.
async fn given_rules(emulator: &Emulator, rules: &[Rule]) -> Vec<String> {
    let (status, body) = events(emulator, "CreateEventBus", &json!({ "Name": BUS })).await;
    assert_eq!(status, 200, "CreateEventBus answered {status} {body}");
    let mut queues = Vec::new();
    for rule in rules {
        let (url, queue_arn) = given_queue(emulator, rule.name).await;
        let (status, body) = events(
            emulator,
            "PutRule",
            &json!({
                "Name": rule.name,
                "EventBusName": BUS,
                "EventPattern": pattern(rule).to_string(),
                "State": "ENABLED",
            }),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: PutRule answered {status} {body}",
            rule.name
        );
        let (status, body) = events(
            emulator,
            "PutTargets",
            &json!({
                "Rule": rule.name,
                "EventBusName": BUS,
                "Targets": [{ "Id": "q", "Arn": queue_arn }],
            }),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: PutTargets answered {status} {body}",
            rule.name
        );
        assert_eq!(
            body["FailedEntryCount"],
            json!(0),
            "case {:?}: PutTargets reported a failed entry: {body}",
            rule.name
        );
        queues.push(url);
    }
    queues
}

/// How many entries one `PutEvents` request may carry
/// (`PutEventsRequestEntryList`, len 1..10), which is why the cases are published
/// in batches.
const MAX_ENTRIES_PER_REQUEST: usize = 10;

/// Publish every case onto [`BUS`], in batches the request bound admits.
async fn publish(emulator: &Emulator, cases: &[Case]) {
    for batch in cases.chunks(MAX_ENTRIES_PER_REQUEST) {
        let entries: Vec<Value> = batch
            .iter()
            .map(|case| {
                json!({
                    "EventBusName": BUS,
                    "Source": SOURCE,
                    "DetailType": DETAIL_TYPE,
                    "Detail": case.detail.to_string(),
                })
            })
            .collect();
        let (status, body) = events(emulator, "PutEvents", &json!({ "Entries": entries })).await;
        assert_eq!(status, 200, "PutEvents answered {status} {body}");
        assert_eq!(
            body["FailedEntryCount"],
            json!(0),
            "PutEvents reported a failed entry: {body}"
        );
    }
}

/// The names of the cases whose `detail` the queue at `url` received, in the order
/// the table states them, so a comparison is about WHICH events arrived rather
/// than about the order a fan-out delivered them in.
async fn received(emulator: &Emulator, url: &str, cases: &[Case]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    // One receive answers at most `MaxNumberOfMessages` messages, so the queue is
    // read until it answers none: what is asserted is everything it holds.
    loop {
        let bodies = drain(emulator, url).await;
        if bodies.is_empty() {
            break;
        }
        for message in &bodies {
            let text = message["Body"].as_str().unwrap_or_default();
            let envelope: Value = serde_json::from_str(text)
                .unwrap_or_else(|error| panic!("a delivered body is not JSON ({error}): {text:?}"));
            let detail = &envelope["detail"];
            let case = cases
                .iter()
                .find(|case| &case.detail == detail)
                .unwrap_or_else(|| panic!("a delivered body carries no case's detail: {envelope}"));
            names.push(case.name.to_string());
        }
    }
    names.sort_by_key(|name| {
        cases
            .iter()
            .position(|case| case.name == name)
            .unwrap_or_default()
    });
    names
}

/// A rule delivers exactly the events whose array field carries a value its term
/// matches — at any nesting, and never for a field carrying no value at all.
#[tokio::test]
async fn an_array_field_matches_when_any_value_it_carries_matches_the_term() {
    let emulator = emulator();
    let cases = cases();
    let rules = rules();
    let queues = given_rules(&emulator, &rules).await;
    publish(&emulator, &cases).await;

    for (rule, url) in rules.iter().zip(&queues) {
        let delivered = received(&emulator, url, &cases).await;
        let expected: Vec<String> = rule.delivers.iter().map(ToString::to_string).collect();
        assert_eq!(
            delivered, expected,
            "case {:?}: expected the rule to deliver {expected:?}, got {delivered:?}",
            rule.name
        );
    }
}

/// `TestEventPattern` answers the verdict live delivery takes, for every pair of
/// the table: the two surfaces of the matcher are one matcher.
#[tokio::test]
async fn test_event_pattern_answers_what_live_delivery_does() {
    let emulator = emulator();
    let cases = cases();
    for rule in &rules() {
        for case in &cases {
            let event = json!({
                "id": "11111111-2222-3333-4444-555555555555",
                "version": "0",
                "account": engine::emulator_account_id(),
                "time": "2026-01-01T00:00:00Z",
                "region": REGION,
                "resources": [],
                "source": SOURCE,
                "detail-type": DETAIL_TYPE,
                "detail": case.detail,
            });
            let (status, body) = events(
                &emulator,
                "TestEventPattern",
                &json!({
                    "EventPattern": pattern(rule).to_string(),
                    "Event": event.to_string(),
                }),
            )
            .await;
            assert_eq!(
                status, 200,
                "case {:?}/{:?}: TestEventPattern answered {status} {body}",
                rule.name, case.name
            );
            let expected = rule.delivers.contains(&case.name);
            assert_eq!(
                body["Result"],
                json!(expected),
                "case {:?}/{:?}: expected Result {expected}, got {body}",
                rule.name,
                case.name
            );
        }
    }
}
