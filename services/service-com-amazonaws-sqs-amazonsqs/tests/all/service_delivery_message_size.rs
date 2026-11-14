// SPDX-License-Identifier: CC0-1.0

//! What a queue's `MaximumMessageSize` bounds: the sends a CLIENT asks this service for, and
//! not a delivery another service hands the queue for a resource of its own.
//!
//! The rule under test: the attribute is "the limit of how many bytes a message can contain
//! before Amazon SQS rejects it" (`SetQueueAttributes$Attributes`) — a bound this API applies
//! to the request it is asked to accept, so a client's send past it is refused with HTTP 400
//! `InvalidParameterValue` and the sentence naming that queue's limit. A delivery made by
//! another service AS ITS OWN SERVICE PRINCIPAL, on behalf of one of its resources (an Amazon
//! SNS notification fanned out to a subscribed queue), is not that request: the sending service
//! accepted the payload under its own limits, so the queue's request bound does not bound the
//! hand-over and the message is enqueued whole.
//!
//! What marks the hand-over is the credential it presents, which is the one thing about a
//! request a client cannot choose for itself: the sending service records, under the access key
//! id of the credential the emulator minted it for that call, the principal it is calling as
//! and the resource it is calling for (`service_common::service_principal_calls`, the one
//! shared directory in the engine). This suite writes such a record for the key id its own
//! requests present — exactly what the calling service writes for a call it makes itself — and
//! forgets it again, so the SAME request is judged as a client's and as a service delivery.
//!
//! The rows differ along what the rule generalises over: the queue's configured
//! `MaximumMessageSize` (the documented floor and a limit between the published bounds — at the
//! documented ceiling an over-large request is refused by the transport before this bound is
//! reached, which is `send_message_size_refusals.rs`'s own rule) and which credential the call
//! presents (none of the kind, the notification service's own, and another service's).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde_json::json;
use service_com_amazonaws_sqs_amazonsqs::scaffolded::INVALID_PARAMETER_VALUE;
use service_com_amazonaws_sqs_amazonsqs::state::{
    integer_bounds, invalid_parameters_message, message_too_long_reason, MAXIMUM_MESSAGE_SIZE,
};

use crate::support::{attribute_count, call, create_ok, emulator_over_engine, error_code, ok};

/// The service principal a notification fan-out is made as: the principal an SQS queue policy
/// names to let an Amazon SNS topic deliver to it.
const SERVICE_PRINCIPAL: &str = "sns.amazonaws.com";

/// Another service's own principal, for the row that checks the exemption cannot be borrowed by
/// a call that is not a delivery into a queue at all.
const OTHER_SERVICE_PRINCIPAL: &str = "logs.amazonaws.com";

/// The access key id every request of this suite presents, as the shared harness signs them:
/// the id the directory's record is written under, so the record answers for these calls.
const PRESENTED_KEY_ID: &str = "AKIDTEST";

/// How long the record of one in-flight call stays readable — well past one in-process call,
/// as the calling service's own slack is.
const IN_FLIGHT_SLACK: Duration = Duration::from_secs(60);

/// How long a receive may wait for the messages a queue is owed.
const RECEIVE_DEADLINE: Duration = Duration::from_secs(30);

/// Record that the requests signed with [`PRESENTED_KEY_ID`] are `principal`'s own calls on
/// behalf of `source_arn` — exactly what the calling service records for a call it makes
/// itself, under the credential it minted for it.
fn delivering_as(engine: &Arc<engine::InMemoryEngine>, principal: &str, source_arn: &str) {
    let now = SystemTime::now();
    engine
        .state::<service_common::service_principal_calls::ServicePrincipalCalls>()
        .lock()
        .remember(
            PRESENTED_KEY_ID,
            service_common::service_principal_calls::ServicePrincipalCall {
                principal: principal.to_string(),
                source_arn: source_arn.to_string(),
                source_account: engine::emulator_account_id().to_string(),
                expires_at: now + IN_FLIGHT_SLACK,
            },
            now,
        );
}

/// Forget that record, as the calling service does as soon as its call returns.
fn done_delivering(engine: &Arc<engine::InMemoryEngine>) {
    engine
        .state::<service_common::service_principal_calls::ServicePrincipalCalls>()
        .lock()
        .forget(PRESENTED_KEY_ID);
}

/// Every message the queue at `url` holds, taken OFF the queue: the bodies received, with each
/// one deleted as it comes over, so what a later row reads is what that row's own call left.
///
/// Polled until one message has come over or `deadline` passes, rather than waited out: the
/// hand-over is made by the call that answered, so the message is there already.
async fn received_and_deleted(
    router: &smithy_server_runtime::MultiServiceRouter,
    url: &str,
    deadline: Instant,
) -> Vec<String> {
    let mut bodies = Vec::new();
    while bodies.is_empty() && Instant::now() < deadline {
        let reply = ok(
            router,
            "ReceiveMessage",
            json!({ "QueueUrl": url, "MaxNumberOfMessages": 10 }),
        )
        .await;
        for message in reply["Messages"].as_array().cloned().unwrap_or_default() {
            bodies.push(message["Body"].as_str().unwrap_or_default().to_string());
            ok(
                router,
                "DeleteMessage",
                json!({
                    "QueueUrl": url,
                    "ReceiptHandle": message["ReceiptHandle"].as_str().unwrap_or_default(),
                }),
            )
            .await;
        }
    }
    bodies
}

/// A queue's `MaximumMessageSize` refuses a client's over-large send and admits the same
/// payload handed over by a service for one of its own resources.
#[tokio::test]
async fn the_maximum_message_size_bounds_a_client_send_and_not_a_service_delivery() {
    // The bounds the attribute publishes, read from the one place this crate keeps them.
    let (floor, ceiling) = integer_bounds(MAXIMUM_MESSAGE_SIZE);
    let between = 262_144_i64;
    assert!(
        floor < between && between < ceiling,
        "case setup: the middling row must sit inside the published bounds ({floor}..={ceiling})"
    );

    let (router, engine) = emulator_over_engine();
    for maximum in [floor, between] {
        let name = format!("service-delivery-{maximum}");
        let url = create_ok(
            &router,
            &name,
            &json!({ "MaximumMessageSize": maximum.to_string() }),
        )
        .await;
        // Twice what this queue will carry, so every row's payload is past the bound.
        let limit = usize::try_from(maximum).expect("a published maximum fits a usize");
        let body = "x".repeat(limit * 2);
        let too_long = invalid_parameters_message(&message_too_long_reason(maximum));
        let send = json!({ "QueueUrl": url, "MessageBody": body });

        // (case, the service principal the call is recorded as, if any)
        for (case, recorded_as) in [
            ("a client's own send", None),
            (
                "the notification fan-out of a published message",
                Some(SERVICE_PRINCIPAL),
            ),
            (
                "a call of another service's principal, in flight at the same moment",
                Some(OTHER_SERVICE_PRINCIPAL),
            ),
            ("a client's own send, once that call has returned", None),
        ] {
            let fanned_out = recorded_as == Some(SERVICE_PRINCIPAL);
            match recorded_as {
                Some(principal) => delivering_as(
                    &engine,
                    principal,
                    &format!("arn:aws:sns:us-east-1:{}:orders", engine::emulator_account_id()),
                ),
                None => done_delivering(&engine),
            }

            let (status, answer) = call(&router, "SendMessage", &send).await;
            if fanned_out {
                assert_eq!(
                    status, 200,
                    "case {case:?} on a {maximum}-byte queue: a hand-over must be taken whole, \
                     got {status} with {answer}"
                );
                let delivered =
                    received_and_deleted(&router, &url, Instant::now() + RECEIVE_DEADLINE).await;
                assert_eq!(
                    delivered.len(),
                    1,
                    "case {case:?} on a {maximum}-byte queue: the queue must hold the \
                     handed-over message, got {} message(s)",
                    delivered.len()
                );
                assert_eq!(
                    delivered[0].len(),
                    body.len(),
                    "case {case:?} on a {maximum}-byte queue: the message must be carried \
                     whole, got {} bytes",
                    delivered[0].len()
                );
            } else {
                assert_eq!(
                    (status, error_code(&answer).as_str()),
                    (400, INVALID_PARAMETER_VALUE),
                    "case {case:?} on a {maximum}-byte queue: a client's send past the limit \
                     must be refused, got {status} with {answer}"
                );
                assert_eq!(
                    answer["message"].as_str(),
                    Some(too_long.as_str()),
                    "case {case:?} on a {maximum}-byte queue: expected the sentence naming the \
                     queue's own limit, got {answer}"
                );
                assert_eq!(
                    attribute_count(&router, &url, "ApproximateNumberOfMessages").await,
                    0,
                    "case {case:?} on a {maximum}-byte queue: a refused send must store no \
                     message"
                );
            }
        }
    }
}
