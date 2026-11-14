// SPDX-License-Identifier: CC0-1.0

//! What a subscribed queue's own `MaximumMessageSize` bounds, and what it does not, end to end
//! over the wire through the real `MultiServiceRouter` with Amazon SQS mounted on the same
//! engine.
//!
//! The RULE asserted here: `MaximumMessageSize` is "the limit of how many bytes a message can
//! contain before Amazon SQS rejects it" (`SetQueueAttributes$Attributes`) — a bound on what
//! THAT service's own `SendMessage` accepts from its caller, which is why a direct send past it
//! is refused with HTTP 400 `InvalidParameterValue` and the sentence naming that queue's limit.
//! A notification SNS fans out to a queue subscribed to a topic is not such a request: the
//! publish was accepted under the TOPIC's own `MaximumMessageSize`, so the subscribed queue's
//! attribute does not bound it and the message is delivered whole. Lowering a queue's attribute
//! therefore never silently changes what a topic's fan-out delivers to it.
//!
//! The rows differ along what the rule generalises over: the queue's configured
//! `MaximumMessageSize` (the documented floor, a value between the bounds, and the documented
//! ceiling) and the published body's size relative to it (well past it, one byte past it, and
//! inside it).

use serde_json::{json, Value};
use service_com_amazonaws_sqs_amazonsqs::scaffolded::{
    INVALID_PARAMETER_VALUE, INVALID_PARAMETER_VALUE_SHAPE_ID,
};
use service_com_amazonaws_sqs_amazonsqs::state::{
    integer_bounds, invalid_parameters_message, message_too_long_reason, MAXIMUM_MESSAGE_SIZE,
};

use super::sqs_subscription_delivery::{
    drain, element, emulator, grant_to_sns, queue_arn, set_queue_policy, sns, sqs, sqs_call,
    Emulator,
};

/// The error code a refusal carries, as the body states it: the shape id the request-validation
/// framework writes for a parameter class maps to this service's own code, which is how the SQS
/// suite reads it too.
fn error_code(body: &Value) -> String {
    let shape = body["__type"].as_str().unwrap_or_default();
    if shape == INVALID_PARAMETER_VALUE_SHAPE_ID {
        return INVALID_PARAMETER_VALUE.to_string();
    }
    shape.rsplit(['#', '/']).next().unwrap_or_default().to_string()
}

/// A queue called `name` carrying `maximum` as its `MaximumMessageSize`, with the policy that
/// grants an SNS topic the send: its url and its ARN.
async fn given_sized_queue(emulator: &Emulator, name: &str, maximum: i64) -> (String, String) {
    let created = sqs(
        emulator,
        "CreateQueue",
        &json!({
            "QueueName": name,
            "Attributes": {"MaximumMessageSize": maximum.to_string()},
        }),
    )
    .await;
    let url = created["QueueUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("CreateQueue {name}: no QueueUrl in {created}"))
        .to_string();
    let arn = queue_arn(emulator, &url).await;
    set_queue_policy(emulator, &url, &grant_to_sns(&arn)).await;
    (url, arn)
}

/// A direct `SendMessage` of `body` to the queue at `url`: the status and the parsed answer.
async fn send_directly(emulator: &Emulator, url: &str, body: &str) -> (u16, Value) {
    sqs_call(
        emulator,
        "SendMessage",
        &json!({"QueueUrl": url, "MessageBody": body}),
    )
    .await
}

/// A queue's `MaximumMessageSize` bounds the sends ITS OWN service accepts, and bounds nothing
/// about the notifications a topic delivers into it.
#[tokio::test]
async fn a_queues_maximum_message_size_bounds_its_own_sends_and_not_an_sns_delivery() {
    // The bounds the attribute publishes, read from the one place the SQS crate keeps them
    // rather than written out again here.
    let (floor, ceiling) = integer_bounds(MAXIMUM_MESSAGE_SIZE);
    let between = 262_144_i64;
    assert!(
        floor < between && between < ceiling,
        "case setup: the middling row must sit inside the published bounds ({floor}..={ceiling})"
    );

    let emulator = emulator();
    let topic = element(
        &sns(&emulator, "CreateTopic", &[("Name", "sized-delivery")]).await,
        "TopicArn",
    );

    // (case, the queue's MaximumMessageSize, the published body's byte count). Every body
    // stays inside the TOPIC's own default maximum, which is what bounds a publish; what
    // varies is how it compares to the SUBSCRIBED QUEUE's limit.
    let rows: &[(&str, i64, usize)] = &[
        ("a body four times the documented floor", floor, 4 * 1024),
        ("a body one byte past the documented floor", floor, 1025),
        ("a body past a limit between the published bounds", 2 * 1024, 4 * 1024),
        ("a body inside a limit between the published bounds", between, 4 * 1024),
        ("a body inside the documented ceiling", ceiling, 4 * 1024),
    ];

    for (index, (case, maximum, body_bytes)) in rows.iter().enumerate() {
        let name = format!("sized-{index}");
        let (url, arn) = given_sized_queue(&emulator, &name, *maximum).await;
        let subscription = element(
            &sns(
                &emulator,
                "Subscribe",
                &[("TopicArn", &topic), ("Protocol", "sqs"), ("Endpoint", &arn)],
            )
            .await,
            "SubscriptionArn",
        );
        // Raw delivery, so what the queue holds is the published body byte for byte and the
        // row's body size is the delivered size.
        sns(
            &emulator,
            "SetSubscriptionAttributes",
            &[
                ("SubscriptionArn", &subscription),
                ("AttributeName", "RawMessageDelivery"),
                ("AttributeValue", "true"),
            ],
        )
        .await;

        // A body of distinguishable content, so the delivery is the one this row published.
        let body = {
            let mut body = format!("row-{index}-");
            body.push_str(&"x".repeat(body_bytes.saturating_sub(body.len())));
            body
        };
        assert_eq!(
            body.len(),
            *body_bytes,
            "case {case:?}: the row's body must be {body_bytes} bytes"
        );
        let past_the_queues_bound = i64::try_from(body.len()).unwrap_or(i64::MAX) > *maximum;

        // The queue's own API, asked directly: refused exactly where the body is past that
        // queue's limit, in the sentence naming the limit, and accepted otherwise.
        let (status, answer) = send_directly(&emulator, &url, &body).await;
        if past_the_queues_bound {
            assert_eq!(
                (status, error_code(&answer).as_str()),
                (400, INVALID_PARAMETER_VALUE),
                "case {case:?}: a direct send past the queue's {maximum}-byte limit must be \
                 refused, got {status} with {answer}"
            );
            assert_eq!(
                answer["message"].as_str(),
                Some(invalid_parameters_message(&message_too_long_reason(*maximum)).as_str()),
                "case {case:?}: expected the sentence naming the queue's own limit, got {answer}"
            );
        } else {
            assert_eq!(
                status, 200,
                "case {case:?}: a direct send inside the queue's {maximum}-byte limit must be \
                 accepted, got {status} with {answer}"
            );
        }
        // Whatever the direct send came to, the queue is drained before the publish, so what
        // is read afterwards is the SNS delivery alone.
        drain(&emulator, &url).await;

        // The same body, published to the topic the queue is subscribed to: delivered whole,
        // whatever the queue's own limit says.
        sns(
            &emulator,
            "Publish",
            &[("TopicArn", &topic), ("Message", &body)],
        )
        .await;
        let delivered = drain(&emulator, &url).await;
        assert_eq!(
            delivered.len(),
            1,
            "case {case:?}: a {}-byte notification must reach the queue whose \
             MaximumMessageSize is {maximum}, got {} message(s)",
            body.len(),
            delivered.len()
        );
        assert_eq!(
            delivered[0].0.len(),
            body.len(),
            "case {case:?}: the delivered message must carry the published body whole, got {} \
             bytes",
            delivered[0].0.len()
        );
        assert_eq!(
            delivered[0].0, body,
            "case {case:?}: the delivered message must carry the published body byte for byte"
        );
    }
}
