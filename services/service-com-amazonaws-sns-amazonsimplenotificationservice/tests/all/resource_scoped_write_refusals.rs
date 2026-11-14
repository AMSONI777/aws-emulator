// SPDX-License-Identifier: CC0-1.0

//! The sentences Amazon SNS refuses a topic or subscription WRITE with, where the
//! refusal is about the resource the write lands on rather than about the value alone,
//! driven end-to-end over the awsQuery wire.
//!
//! The RULE asserted here: every one of these refusals is the modelled
//! `InvalidParameterException` (awsQuery code `InvalidParameter`, HTTP 400 —
//! `smithy_query(query="operation",operation="SetTopicAttributes,Subscribe,SetSubscriptionAttributes")`),
//! so the SENTENCE is the only thing that says which rule the request broke, and the
//! refused write changes nothing the service holds. Three rules are asserted, each with
//! the accepted neighbour of its refused case:
//!
//! * a topic attribute whose value SNS only moves ONE WAY takes a value its domain
//!   admits only from the values that value can still be reached from;
//! * a subscription's dead-letter queue is a queue of the subscription's OWN kind
//!   ("RedrivePolicy – When specified, sends undeliverable messages to the specified
//!   Amazon SQS dead-letter queue", `SetSubscriptionAttributesInput$AttributeName` doc),
//!   so an ordered subscription dead-letters into an ordered queue;
//! * a delivery protocol SNS needs an identity to deliver as is subscribed only with the
//!   attribute naming it ("Specifying a valid ARN for this attribute is required for
//!   Firehose delivery stream subscriptions", `SubscribeInput$Attributes` doc, of
//!   `SubscriptionRoleArn`).
//!
//! The rows differ along what each rule generalises over: the value a one-way attribute
//! is moved between, the kind of the topic and of the queue a redrive policy names, the
//! call that carried the write (`Subscribe`'s attribute MAP against the attribute
//! `SetSubscriptionAttributes` is given by name), and whether the request carries the
//! attribute at all or takes it away.

use super::topics_subscriptions_publish::{attribute_map, Answer, Sns};

/// The status and awsQuery code SNS answers a write it will not perform with.
const REFUSAL_STATUS: u16 = 400;
const REFUSAL_CODE: &str = "InvalidParameter";

/// Assert that `answer` refuses the write with exactly `expected`.
fn assert_refused(case: &str, answer: &Answer, expected: &str) {
    assert_eq!(
        answer.status, REFUSAL_STATUS,
        "case {case:?}: expected HTTP {REFUSAL_STATUS}, got {} / {}",
        answer.status, answer.body
    );
    assert_eq!(
        answer.code(),
        REFUSAL_CODE,
        "case {case:?}: expected the {REFUSAL_CODE} code, got {}",
        answer.body
    );
    assert_eq!(
        answer.element("Message").as_deref(),
        Some(expected),
        "case {case:?}: expected the service's own sentence, got {}",
        answer.body
    );
}

/// Assert that `answer` served the write.
fn assert_served(case: &str, answer: &Answer) {
    assert_eq!(
        answer.status, 200,
        "case {case:?}: expected the write to be served, got {} / {}",
        answer.status, answer.body
    );
}

/// Set one topic attribute.
async fn set_topic_attribute(sns: &Sns, topic: &str, name: &str, value: &str) -> Answer {
    sns.call(
        "SetTopicAttributes",
        &[
            ("TopicArn", topic),
            ("AttributeName", name),
            ("AttributeValue", value),
        ],
    )
    .await
}

/// The attribute `name` of `topic` reads back as.
async fn topic_attribute(sns: &Sns, topic: &str, name: &str) -> Option<String> {
    attribute_map(&sns.call("GetTopicAttributes", &[("TopicArn", topic)]).await)
        .get(name)
        .cloned()
}

/// Set one subscription attribute.
async fn set_subscription_attribute(
    sns: &Sns,
    subscription: &str,
    name: &str,
    value: &str,
) -> Answer {
    sns.call(
        "SetSubscriptionAttributes",
        &[
            ("SubscriptionArn", subscription),
            ("AttributeName", name),
            ("AttributeValue", value),
        ],
    )
    .await
}

/// The attribute `name` of `subscription` reads back as.
async fn subscription_attribute(sns: &Sns, subscription: &str, name: &str) -> Option<String> {
    attribute_map(
        &sns.call(
            "GetSubscriptionAttributes",
            &[("SubscriptionArn", subscription)],
        )
        .await,
    )
    .get(name)
    .cloned()
}

/// Subscribe `endpoint` over `protocol` to `topic` with `attributes`, asking for the ARN.
async fn subscribe(
    sns: &Sns,
    topic: &str,
    protocol: &str,
    endpoint: &str,
    attributes: &[(&str, &str)],
) -> Answer {
    let mut params: Vec<(String, String)> = vec![
        ("TopicArn".to_string(), topic.to_string()),
        ("Protocol".to_string(), protocol.to_string()),
        ("Endpoint".to_string(), endpoint.to_string()),
        ("ReturnSubscriptionArn".to_string(), "true".to_string()),
    ];
    for (at, (name, value)) in attributes.iter().enumerate() {
        params.push((format!("Attributes.entry.{}.key", at + 1), (*name).to_string()));
        params.push((
            format!("Attributes.entry.{}.value", at + 1),
            (*value).to_string(),
        ));
    }
    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    sns.call("Subscribe", &borrowed).await
}

/// The ARN a served `Subscribe` answered with.
fn subscription_arn(answer: &Answer) -> String {
    answer
        .element("SubscriptionArn")
        .unwrap_or_else(|| panic!("no SubscriptionArn in {}", answer.body))
}

/// A redrive policy naming `queue` as the dead-letter target.
fn redrive(queue: &str) -> String {
    format!(r#"{{"deadLetterTargetArn":"{queue}"}}"#)
}

/// RULE: the deduplication scope of a FIFO topic moves from the whole topic down into
/// each message group and not back, and the refused write leaves the scope the topic
/// holds.
#[tokio::test]
async fn a_one_way_topic_attribute_is_refused_when_the_write_moves_it_back() {
    let sns = Sns::new();
    let scope = "FifoThroughputScope";
    let narrowing = "Invalid parameter: Modifying FifoThroughputScope from MessageGroup to \
                     Topic is not supported";

    // The whole span of the attribute, in order: the value it starts at, the value it
    // moves to, the same value again (which moves nothing), and then back.
    let topic = sns.topic("one-way-scope.fifo").await;
    for (case, value, refusal, held) in [
        ("the documented default, written explicitly", "Topic", None, "Topic"),
        ("narrowing the scope to each message group", "MessageGroup", None, "MessageGroup"),
        ("the value the attribute already holds", "MessageGroup", None, "MessageGroup"),
        ("widening the scope back to the topic", "Topic", Some(narrowing), "MessageGroup"),
    ] {
        let answer = set_topic_attribute(&sns, &topic, scope, value).await;
        match refusal {
            None => assert_served(case, &answer),
            Some(expected) => assert_refused(case, &answer, expected),
        }
        let read = topic_attribute(&sns, &topic, scope).await;
        assert_eq!(
            read.as_deref(),
            Some(held),
            "case {case:?}: the topic must hold {held:?}, got {read:?}"
        );
    }

    // The same move on a topic that never narrowed its scope is one SNS performs, so the
    // refusal is about the transition and not about the value.
    let fresh = sns.topic("one-way-fresh.fifo").await;
    assert_served(
        "the whole topic's scope on a topic that never narrowed it",
        &set_topic_attribute(&sns, &fresh, scope, "Topic").await,
    );

    // A value outside the attribute's own value set is refused on the kind of topic that
    // DOES carry the attribute, naming the value the request sent.
    for value in ["Partition", "messagegroup", "TOPIC", "Topic "] {
        let answer = set_topic_attribute(&sns, &fresh, scope, value).await;
        assert_refused(
            &format!("a throughput scope SNS does not define: {value:?}"),
            &answer,
            &format!("Invalid parameter: Invalid FifoThroughputScope: {value}"),
        );
    }
}

/// One row of the redrive table: the case, the topic's name, the endpoint the attribute
/// is written on, a second endpoint the same policy is subscribed with, the dead-letter
/// queue it names, and the reason the write is refused with (`None` when the kinds
/// agree).
type RedriveCase<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    Option<&'a str>,
);

/// RULE: a subscription's dead-letter queue is a queue of its own kind, by the same rule
/// whichever call carried the write, and a refused write leaves the stored policy as it
/// was.
#[tokio::test]
async fn a_redrive_policy_names_a_dead_letter_queue_of_the_subscriptions_own_kind() {
    let sns = Sns::new();
    let standard_queue = "arn:aws:sqs:us-east-1:000000000000:dlq-plain";
    let fifo_queue = "arn:aws:sqs:us-east-1:000000000000:dlq-ordered.fifo";
    let for_fifo = "must use a FIFO queue as DLQ for a FIFO Subscription to a FIFO Topic.";
    let for_standard =
        "must use a standard queue as DLQ for a Standard Subscription to a Standard Topic.";

    // Each row is a [`RedriveCase`].
    let rows: &[RedriveCase<'_>] = &[
        (
            "a standard queue as the DLQ of a standard subscription",
            "redrive-standard",
            "arn:aws:sqs:us-east-1:000000000000:plain-one",
            "arn:aws:sqs:us-east-1:000000000000:plain-one-mapped",
            standard_queue,
            None,
        ),
        (
            "a FIFO queue as the DLQ of a standard subscription",
            "redrive-standard-two",
            "arn:aws:sqs:us-east-1:000000000000:plain-two",
            "arn:aws:sqs:us-east-1:000000000000:plain-two-mapped",
            fifo_queue,
            Some(for_standard),
        ),
        (
            "a FIFO queue as the DLQ of a FIFO subscription",
            "redrive-ordered.fifo",
            "arn:aws:sqs:us-east-1:000000000000:ordered-one.fifo",
            "arn:aws:sqs:us-east-1:000000000000:ordered-one-mapped.fifo",
            fifo_queue,
            None,
        ),
        (
            "a standard queue as the DLQ of a FIFO subscription",
            "redrive-ordered-two.fifo",
            "arn:aws:sqs:us-east-1:000000000000:ordered-two.fifo",
            "arn:aws:sqs:us-east-1:000000000000:ordered-two-mapped.fifo",
            standard_queue,
            Some(for_fifo),
        ),
    ];

    for (case, topic_name, endpoint, mapped_endpoint, dead_letter, reason) in rows {
        let topic = sns.topic(topic_name).await;
        let subscribed = subscribe(&sns, &topic, "sqs", endpoint, &[]).await;
        assert_served(case, &subscribed);
        let arn = subscription_arn(&subscribed);
        // A policy the subscription already holds, so a refused write is seen to leave it
        // standing: the queue of the subscription's own kind, which the rule admits.
        let holdable = if topic_name.ends_with(".fifo") {
            fifo_queue
        } else {
            standard_queue
        };
        let held = redrive(holdable);
        assert_served(
            case,
            &set_subscription_attribute(&sns, &arn, "RedrivePolicy", &held).await,
        );

        let policy = redrive(dead_letter);
        // Through `SetSubscriptionAttributes`, which was given the attribute by name.
        let named = set_subscription_attribute(&sns, &arn, "RedrivePolicy", &policy).await;
        // And through `Subscribe`, which read it out of its attribute MAP — the member
        // that frames the same sentence.
        let mapped = subscribe(
            &sns,
            &topic,
            "sqs",
            mapped_endpoint,
            &[("RedrivePolicy", policy.as_str())],
        )
        .await;
        match reason {
            None => {
                assert_served(case, &named);
                assert_served(case, &mapped);
                let read = subscription_attribute(&sns, &arn, "RedrivePolicy").await;
                assert_eq!(
                    read.as_deref(),
                    Some(policy.as_str()),
                    "case {case:?}: the policy must read back as it was written, got {read:?}"
                );
            }
            Some(reason) => {
                assert_refused(
                    case,
                    &named,
                    &format!("Invalid parameter: RedrivePolicy: {reason}"),
                );
                assert_refused(
                    &format!("{case}, through Subscribe"),
                    &mapped,
                    &format!("Invalid parameter: Attributes Reason: RedrivePolicy: {reason}"),
                );
                let read = subscription_attribute(&sns, &arn, "RedrivePolicy").await;
                assert_eq!(
                    read.as_deref(),
                    Some(held.as_str()),
                    "case {case:?}: a refused write must leave the stored policy as it \
                     was, got {read:?}"
                );
            }
        }
    }
}

/// RULE: a delivery protocol SNS needs an identity to deliver as is subscribed only with
/// the attribute naming that identity, and the same write cannot take it away.
#[tokio::test]
async fn a_subscription_whose_protocol_requires_a_role_is_refused_without_it() {
    let sns = Sns::new();
    let topic = sns.topic("role-required").await;
    let stream = "arn:aws:firehose:us-east-1:000000000000:deliverystream/events";
    let role = "arn:aws:iam::000000000000:role/sns-firehose";
    let expected = "Invalid parameter: Delivery protocol firehose can only be subscribed \
                    with subscription role arn";

    // With no attributes at all, and with attributes that are not the one the protocol
    // requires: the same sentence, since neither request names the identity.
    for (case, attributes) in [
        ("a firehose subscription with no attributes", &[][..]),
        (
            "a firehose subscription carrying another attribute",
            &[("RawMessageDelivery", "true")][..],
        ),
    ] {
        let answer = subscribe(&sns, &topic, "firehose", stream, attributes).await;
        assert_refused(case, &answer, expected);
        let listed = sns
            .call("ListSubscriptionsByTopic", &[("TopicArn", &topic)])
            .await;
        assert!(
            !listed.body.contains(stream),
            "case {case:?}: a refused subscribe must create nothing, got {}",
            listed.body
        );
    }

    // The same request carrying the role is served, and the role reads back.
    let subscribed = subscribe(
        &sns,
        &topic,
        "firehose",
        stream,
        &[("SubscriptionRoleArn", role)],
    )
    .await;
    assert_served("a firehose subscription carrying its role", &subscribed);
    let arn = subscription_arn(&subscribed);
    let read = subscription_attribute(&sns, &arn, "SubscriptionRoleArn").await;
    assert_eq!(
        read.as_deref(),
        Some(role),
        "the subscription must hold the role it was created with, got {read:?}"
    );

    // And the write that would take the role away is refused by the same rule, under the
    // same sentence: what it would leave is a subscription SNS cannot deliver over.
    let cleared = sns
        .call(
            "SetSubscriptionAttributes",
            &[("SubscriptionArn", &arn), ("AttributeName", "SubscriptionRoleArn")],
        )
        .await;
    assert_refused("clearing the role the protocol requires", &cleared, expected);
    let read = subscription_attribute(&sns, &arn, "SubscriptionRoleArn").await;
    assert_eq!(
        read.as_deref(),
        Some(role),
        "a refused write must leave the role as it was, got {read:?}"
    );

    // A protocol SNS delivers as itself needs no such attribute, so the rule refuses
    // nothing there.
    assert_served(
        "an sqs subscription with no attributes",
        &subscribe(
            &sns,
            &topic,
            "sqs",
            "arn:aws:sqs:us-east-1:000000000000:role-not-required",
            &[],
        )
        .await,
    );
}
