// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for the SENTENCE an attribute whose value is not JSON at all is
//! refused with.
//!
//! The RULE asserted here: a value the JSON parser could not read is refused
//! `InvalidParameter` (HTTP 400) with `failed to parse JSON. ` followed by the parser's
//! own diagnostic, framed by the MEMBER the write arrived in: a write carried in an
//! `Attributes` MAP reads `Invalid parameter: Attributes Reason: <AttributeName>: failed
//! to parse JSON. `, while one given the attribute BY NAME names that attribute alone.
//! The attribute name in the sentence is the one the CALLER spelled, and nothing in the
//! sentence echoes the document back.
//!
//! The rows differ along what the rule generalises over: WHICH attribute carries the
//! document (three of the subscription attributes whose value is a policy document,
//! from `SUBSCRIPTION_ATTRIBUTE_NAMES`), the FORM of the value that is not JSON (a
//! bare word, a sentence of words, a template left unsubstituted, a document that ends
//! early), and which of the two write paths carried it. Which word the diagnostic names
//! and where it sits is `filter_policy_parse_diagnostic.rs`.
//!
//! Every call goes over the wire through the router the emulator serves in production,
//! so nothing but persisted state carries information between calls.

use service_com_amazonaws_sns_amazonsimplenotificationservice::state::{
    attribute_parse_refusal_opening, AttributeMember,
};

use super::topics_subscriptions_publish::{attribute_map, Answer, Sns};

/// One `SetSubscriptionAttributes` call.
async fn set(sns: &Sns, arn: &str, name: &str, value: &str) -> Answer {
    sns.call(
        "SetSubscriptionAttributes",
        &[
            ("SubscriptionArn", arn),
            ("AttributeName", name),
            ("AttributeValue", value),
        ],
    )
    .await
}

/// An http subscription of its own topic, confirmed by this service, with its ARN.
async fn subscribed(sns: &Sns, topic: &str) -> String {
    let answer = sns
        .call(
            "Subscribe",
            &[
                ("TopicArn", topic),
                ("Protocol", "https"),
                ("Endpoint", "https://example.test/hook"),
                ("ReturnSubscriptionArn", "true"),
            ],
        )
        .await;
    assert_eq!(
        answer.status, 200,
        "Subscribe must be served, got {} / {}",
        answer.status, answer.body
    );
    answer
        .element("SubscriptionArn")
        .unwrap_or_else(|| panic!("no SubscriptionArn in {}", answer.body))
}

/// The values that are not JSON at all, each with the case it stands for — the forms the
/// rule generalises over.
const NOT_JSON: &[(&str, &str)] = &[
    ("one bare word", "not"),
    ("a sentence of bare words", "this is not json"),
    ("a word a template left unsubstituted", r#"{"event": $event}"#),
    ("an object that ends early", "{"),
    ("a bare word where a member's value belongs", r#"{"event": created}"#),
];

/// A value that is not JSON is refused for the PARSE, naming the attribute it was
/// written to under the member clause of the call that carried it — whichever
/// policy-valued attribute carried it.
#[tokio::test]
async fn a_value_that_is_not_json_is_refused_naming_the_attribute_alone() {
    let sns = Sns::new();
    let topic = sns.topic("attribute-parse-refusal").await;
    let subscription = subscribed(&sns, &topic).await;

    // The subscription attributes whose value is a policy DOCUMENT, as
    // `SetSubscriptionAttributesInput$AttributeName` documents them.
    let attributes = ["FilterPolicy", "DeliveryPolicy", "ReplayPolicy"];
    // (case, a value that is not JSON at all)
    let values: &[(&str, &str)] = NOT_JSON;

    for name in attributes {
        let opening = attribute_parse_refusal_opening(name, AttributeMember::Named);
        for (case, value) in values {
            let answer = set(&sns, &subscription, name, value).await;
            assert_eq!(
                answer.status, 400,
                "{name} case {case:?}: expected HTTP 400, got {} / {}",
                answer.status, answer.body
            );
            assert_eq!(
                answer.code(),
                "InvalidParameter",
                "{name} case {case:?}: expected the InvalidParameter code, got {}",
                answer.body
            );
            let message = answer
                .element("Message")
                .unwrap_or_else(|| panic!("{name} case {case:?}: no Message in {}", answer.body));
            assert!(
                message.starts_with(&opening),
                "{name} case {case:?}: expected a refusal opening with {opening:?}, got \
                 {message:?}"
            );
            assert!(
                !message.contains("Reason:"),
                "{name} case {case:?}: an attribute written BY NAME carries no member frame, \
                 got {message:?}"
            );
            assert!(
                message.contains("REDACTED"),
                "{name} case {case:?}: the refusal must report the document's source as \
                 redacted rather than echoing it, got {message:?}"
            );
        }

        // Nothing the parse refused was stored: the attribute is still absent.
        let held = attribute_map(
            &sns.call(
                "GetSubscriptionAttributes",
                &[("SubscriptionArn", subscription.as_str())],
            )
            .await,
        );
        assert_eq!(
            held.get(name),
            None,
            "{name}: a refused document must not be stored, got {held:?}"
        );
    }
}

/// The same documents, carried in the `Attributes` MAP of a `Subscribe` request, are
/// refused for the same parse — under the member that map's entries are refused under,
/// and then the entry of it that could not be read.
#[tokio::test]
async fn a_document_carried_in_the_attributes_map_names_that_member_first() {
    let sns = Sns::new();
    let topic = sns.topic("attribute-parse-refusal-map").await;

    // The policy-valued attributes a `Subscribe` request may carry for the subscription
    // it creates (`SubscribeInput$Attributes` doc).
    for name in ["FilterPolicy", "DeliveryPolicy"] {
        let opening = attribute_parse_refusal_opening(name, AttributeMember::Map);
        for (case, value) in NOT_JSON {
            let answer = sns
                .call(
                    "Subscribe",
                    &[
                        ("TopicArn", topic.as_str()),
                        ("Protocol", "https"),
                        ("Endpoint", "https://example.test/mapped"),
                        ("ReturnSubscriptionArn", "true"),
                        ("Attributes.entry.1.key", name),
                        ("Attributes.entry.1.value", value),
                    ],
                )
                .await;
            assert_eq!(
                answer.status, 400,
                "{name} case {case:?}: expected HTTP 400, got {} / {}",
                answer.status, answer.body
            );
            assert_eq!(
                answer.code(),
                "InvalidParameter",
                "{name} case {case:?}: expected the InvalidParameter code, got {}",
                answer.body
            );
            let message = answer
                .element("Message")
                .unwrap_or_else(|| panic!("{name} case {case:?}: no Message in {}", answer.body));
            assert!(
                message.starts_with(&opening),
                "{name} case {case:?}: expected a refusal opening with {opening:?}, got \
                 {message:?}"
            );
        }
    }
}
