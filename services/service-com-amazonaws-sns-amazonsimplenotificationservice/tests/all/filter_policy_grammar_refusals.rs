// SPDX-License-Identifier: CC0-1.0

//! A filter policy naming a match SNS does not perform is refused when it is WRITTEN,
//! driven end-to-end over the awsQuery wire.
//!
//! The RULE asserted here: a stored `FilterPolicy` decides, for the life of the
//! subscription, which messages its endpoint receives ("the simple JSON object that lets
//! your subscriber receive only a subset of messages", `SubscribeInput$Attributes` doc),
//! so a condition naming a match type the service does not perform is refused at the
//! write — the modelled `InvalidParameterException` (awsQuery code `InvalidParameter`,
//! HTTP 400 — `smithy_query(query="operation",operation="SetSubscriptionAttributes")`) —
//! rather than stored to withhold every message in silence. The sentence is the reader's
//! own: the attribute, the reason, and the position in the policy the reader stopped at.
//! A refused write leaves the policy the subscription holds, and a policy of the
//! operators the service does perform round-trips byte for byte.
//!
//! The vocabulary a NEGATION may name is narrower than the vocabulary of a condition:
//! `anything-but` excludes what a STRING pattern picks out, and a match type that is not
//! a string pattern (a network, a numeric range) names nothing it can exclude.
//!
//! The rows differ along what the rule generalises over: the match type the condition
//! names, whether it stands on its own or inside the one operator that nests another,
//! and the kind of argument the reader stopped on (a string, a list, a number).

use super::topics_subscriptions_publish::{attribute_map, Answer, Sns};

/// The status and awsQuery code SNS refuses a filter policy it would not apply with.
const REFUSAL_STATUS: u16 = 400;
const REFUSAL_CODE: &str = "InvalidParameter";

/// A queue a subscription of this suite delivers to.
const QUEUE: &str = "arn:aws:sqs:us-east-1:000000000000:grammar-queue";

/// The policy a subscription of this suite holds before each refused write, so a refusal
/// is seen to leave the stored policy standing.
const HELD: &str = r#"{"kind":["alert"]}"#;

/// Write `policy` as the subscription's `FilterPolicy`.
async fn set_policy(sns: &Sns, subscription: &str, policy: &str) -> Answer {
    sns.call(
        "SetSubscriptionAttributes",
        &[
            ("SubscriptionArn", subscription),
            ("AttributeName", "FilterPolicy"),
            ("AttributeValue", policy),
        ],
    )
    .await
}

/// The `FilterPolicy` the subscription reads back as.
async fn stored_policy(sns: &Sns, subscription: &str) -> Option<String> {
    attribute_map(
        &sns.call(
            "GetSubscriptionAttributes",
            &[("SubscriptionArn", subscription)],
        )
        .await,
    )
    .get("FilterPolicy")
    .cloned()
}

/// The COLUMN the reader reports for a refusal it decided on the node written `node` in
/// `document`: the reader reports the position just past that node's first character —
/// the opening quote or bracket of a string, a list or an object, which is as much of it
/// as it had read — so the column is one past where the node begins, counting from 1.
fn column_of(document: &str, node: &str) -> usize {
    let at = document
        .find(node)
        .unwrap_or_else(|| panic!("{node:?} is not part of {document:?}"));
    at + 2
}

/// The whole sentence a policy whose grammar SNS could not read is refused with.
fn refusal(document: &str, reason: &str, node: &str) -> String {
    format!(
        "Invalid parameter: FilterPolicy: {reason}\n at [Source: (String)\"{document}\"; \
         line: 1, column: {}]",
        column_of(document, node)
    )
}

/// RULE: a condition naming a match SNS does not perform is refused at the write, and the
/// policy the subscription holds is left standing.
#[tokio::test]
async fn a_filter_policy_naming_a_match_the_service_does_not_perform_is_refused() {
    let sns = Sns::new();
    let topic = sns.topic("filter-policy-grammar").await;
    let subscribed = sns
        .call(
            "Subscribe",
            &[
                ("TopicArn", &topic),
                ("Protocol", "sqs"),
                ("Endpoint", QUEUE),
                ("ReturnSubscriptionArn", "true"),
            ],
        )
        .await;
    let arn = subscribed
        .element("SubscriptionArn")
        .unwrap_or_else(|| panic!("no SubscriptionArn in {}", subscribed.body));
    assert_eq!(
        set_policy(&sns, &arn, HELD).await.status,
        200,
        "the policy the refusals are judged against must be stored, got {}",
        subscribed.body
    );

    // (case, the policy, the reason the reader states, the node it stopped on)
    let rows: &[(&str, &str, &str, &str)] = &[
        (
            "a network inside a negation",
            r#"{"ip":[{"anything-but":{"cidr":"10.0.0.0/8"}}]}"#,
            "Unsupported anything-but pattern: cidr",
            r#""10.0.0.0/8""#,
        ),
        (
            "a numeric range inside a negation",
            r#"{"price":[{"anything-but":{"numeric":[">",7]}}]}"#,
            "Unsupported anything-but pattern: numeric",
            r#"[">",7]"#,
        ),
        (
            "a negation inside a negation",
            r#"{"kind":[{"anything-but":{"anything-but":"excluded"}}]}"#,
            "Unsupported anything-but pattern: anything-but",
            r#""excluded""#,
        ),
        (
            "a presence test whose pattern is not a flag",
            r#"{"coupon":[{"exists":"yes"}]}"#,
            "exists match pattern must be either true or false.",
            r#""yes""#,
        ),
        (
            "a numeric relation the service does not compare with",
            r#"{"price":[{"numeric":["!=",7]}]}"#,
            "Unrecognized numeric range operator: !=",
            "7",
        ),
        (
            "a match type the service does not implement",
            r#"{"price":[{"greater-than":5}]}"#,
            "Unrecognized match type greater-than",
            "5",
        ),
    ];

    for (case, policy, reason, node) in rows {
        let expected = refusal(policy, reason, node);
        let answer = set_policy(&sns, &arn, policy).await;
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
            Some(expected.as_str()),
            "case {case:?}: expected the reader's own sentence, got {}",
            answer.body
        );
        let held = stored_policy(&sns, &arn).await;
        assert_eq!(
            held.as_deref(),
            Some(HELD),
            "case {case:?}: a refused write must leave the stored policy as it was, got \
             {held:?}"
        );
    }
}

/// The other side of the rule: every pattern a negation DOES exclude, and the conditions
/// those patterns stand in on their own, are stored exactly as they were written.
#[tokio::test]
async fn a_filter_policy_of_the_matches_the_service_performs_round_trips() {
    let sns = Sns::new();
    let topic = sns.topic("filter-policy-accepted").await;
    let subscribed = sns
        .call(
            "Subscribe",
            &[
                ("TopicArn", &topic),
                ("Protocol", "sqs"),
                ("Endpoint", QUEUE),
                ("ReturnSubscriptionArn", "true"),
            ],
        )
        .await;
    let arn = subscribed
        .element("SubscriptionArn")
        .unwrap_or_else(|| panic!("no SubscriptionArn in {}", subscribed.body));

    // The string patterns a negation excludes, beside the bare value and list forms it
    // takes, and the same patterns outside a negation.
    let rows: &[(&str, &str)] = &[
        ("a negated value", r#"{"kind":[{"anything-but":"silence"}]}"#),
        ("a negated number", r#"{"price":[{"anything-but":5}]}"#),
        ("a negated list", r#"{"kind":[{"anything-but":["silence","noise"]}]}"#),
        ("a negated prefix", r#"{"kind":[{"anything-but":{"prefix":"al"}}]}"#),
        ("a negated suffix", r#"{"kind":[{"anything-but":{"suffix":"rt"}}]}"#),
        (
            "a negated case-folded value",
            r#"{"kind":[{"anything-but":{"equals-ignore-case":"ALERT"}}]}"#,
        ),
        ("a negated wildcard", r#"{"kind":[{"anything-but":{"wildcard":"al*rt"}}]}"#),
        (
            "a negated list of prefixes",
            r#"{"kind":[{"anything-but":{"prefix":["al","wa"]}}]}"#,
        ),
        ("a network", r#"{"ip":[{"cidr":"10.0.0.0/8"}]}"#),
        ("a numeric range", r#"{"price":[{"numeric":[">",7,"<=",9]}]}"#),
        ("a presence test", r#"{"coupon":[{"exists":true}]}"#),
    ];

    for (case, policy) in rows {
        let answer = set_policy(&sns, &arn, policy).await;
        assert_eq!(
            answer.status, 200,
            "case {case:?}: a match the service performs must be accepted, got {} / {}",
            answer.status, answer.body
        );
        let held = stored_policy(&sns, &arn).await;
        assert_eq!(
            held.as_deref(),
            Some(*policy),
            "case {case:?}: the policy must read back as it was written, got {held:?}"
        );
    }
}
