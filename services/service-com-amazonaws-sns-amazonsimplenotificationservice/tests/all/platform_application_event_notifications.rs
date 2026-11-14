// SPDX-License-Identifier: CC0-1.0

//! The endpoint-lifecycle EVENT NOTIFICATIONS a mobile push platform application publishes,
//! end to end over the wire through the real `MultiServiceRouter` with Amazon SQS mounted on
//! the same engine, so an event is observed where a client observes it: on the queue
//! subscribed to the topic the application names.
//!
//! The RULE asserted here: a platform application attribute named `Event<lifecycle>` holds the
//! "Topic ARN to which `<lifecycle>` event notifications are sent"
//! (`SetPlatformApplicationAttributesInput$Attributes`, the same map
//! `CreatePlatformApplication` takes), so every lifecycle change an application's endpoints
//! undergo publishes one notification to the topic the MATCHING attribute names — carrying that
//! event's own `EventType` and the `EndpointArn` of the endpoint it is about — while an
//! application naming no topic for the lifecycle that happened publishes nothing.
//!
//! The rows differ along what the rule generalises over: which lifecycle the call performs
//! (register, write, remove), which attribute configures its topic, and whether a call that
//! answers successfully changed an endpoint's life at all (the idempotent registration, and the
//! idempotent delete, each of which change nothing).
//!
//! Every subscription here asks for raw message delivery, so the body on the queue IS the
//! published event document rather than the notification envelope wrapped around it; that
//! envelope is `sqs_subscription_delivery.rs`'s own rule.

use serde_json::Value;

use super::sqs_subscription_delivery::{drain, element, emulator, given_queue, sns, Emulator};

/// The push notification service every application below targets, spelled as a client spells
/// it: the platform name is resolved to the documented spelling, which is what the endpoint
/// ARN then carries.
const PLATFORM: &str = "BAIDU";

/// The documented spelling of [`PLATFORM`], which the ARNs this emulator mints carry.
const CANONICAL_PLATFORM: &str = "Baidu";

/// The account every ARN this emulator mints carries.
const ACCOUNT: &str = "000000000000";

/// The Region the harness signs its calls for.
const REGION: &str = "us-east-1";

/// Which lifecycle change of a device endpoint a row performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    /// The registration that mints the endpoint.
    Register,
    /// A write of the endpoint's attributes.
    Write,
    /// The delete that removes it.
    Remove,
}

/// A platform application registered through the wire, carrying the credential pair its
/// platform documents and `events` as its event-topic attributes: its ARN.
async fn given_application(
    emulator: &Emulator,
    name: &str,
    events: &[(&str, &str)],
) -> String {
    let mut params: Vec<(String, String)> = vec![
        ("Name".to_string(), name.to_string()),
        ("Platform".to_string(), PLATFORM.to_string()),
        (
            "Attributes.entry.1.key".to_string(),
            "PlatformCredential".to_string(),
        ),
        (
            "Attributes.entry.1.value".to_string(),
            "client-secret-0123456789".to_string(),
        ),
        (
            "Attributes.entry.2.key".to_string(),
            "PlatformPrincipal".to_string(),
        ),
        (
            "Attributes.entry.2.value".to_string(),
            "client-id-0123456789".to_string(),
        ),
    ];
    for (index, (attribute, topic)) in events.iter().enumerate() {
        let entry = index + 3;
        params.push((
            format!("Attributes.entry.{entry}.key"),
            (*attribute).to_string(),
        ));
        params.push((
            format!("Attributes.entry.{entry}.value"),
            (*topic).to_string(),
        ));
    }
    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    element(
        &sns(emulator, "CreatePlatformApplication", &borrowed).await,
        "PlatformApplicationArn",
    )
}

/// A topic with ONE queue subscribed to it, asking for raw delivery: the topic's ARN and that
/// queue's url.
async fn given_topic_with_subscribed_queue(emulator: &Emulator, name: &str) -> (String, String) {
    let topic = element(
        &sns(emulator, "CreateTopic", &[("Name", name)]).await,
        "TopicArn",
    );
    let (url, arn) = given_queue(emulator, name).await;
    let subscription = element(
        &sns(
            emulator,
            "Subscribe",
            &[("TopicArn", &topic), ("Protocol", "sqs"), ("Endpoint", &arn)],
        )
        .await,
        "SubscriptionArn",
    );
    sns(
        emulator,
        "SetSubscriptionAttributes",
        &[
            ("SubscriptionArn", &subscription),
            ("AttributeName", "RawMessageDelivery"),
            ("AttributeValue", "true"),
        ],
    )
    .await;
    (topic, url)
}

/// Register `token` as an endpoint of `application`: the endpoint's ARN.
async fn register_endpoint(emulator: &Emulator, application: &str, token: &str) -> String {
    element(
        &sns(
            emulator,
            "CreatePlatformEndpoint",
            &[("PlatformApplicationArn", application), ("Token", token)],
        )
        .await,
        "EndpointArn",
    )
}

/// Each lifecycle of a device endpoint publishes ONE notification to the topic its own
/// application attribute names, and that notification names the lifecycle and the endpoint.
#[tokio::test]
async fn each_endpoint_lifecycle_publishes_to_the_topic_its_own_attribute_names() {
    let emulator = emulator();

    // (case, the attribute that configures the topic, the EventType the document carries,
    //  the lifecycle the row performs). The event names are the ones the attribute's own
    //  documentation gives them (`SetPlatformApplicationAttributesInput$Attributes`).
    let rows: &[(&str, &str, &str, Lifecycle)] = &[
        (
            "a registration",
            "EventEndpointCreated",
            "EndpointCreated",
            Lifecycle::Register,
        ),
        (
            "an attribute write",
            "EventEndpointUpdated",
            "EndpointUpdate",
            Lifecycle::Write,
        ),
        (
            "a removal",
            "EventEndpointDeleted",
            "EndpointDeleted",
            Lifecycle::Remove,
        ),
    ];

    for (index, (case, attribute, event_type, lifecycle)) in rows.iter().enumerate() {
        let name = format!("lifecycle-{index}");
        let (topic, queue_url) = given_topic_with_subscribed_queue(&emulator, &name).await;
        // ONLY this row's lifecycle has a topic configured, so a notification on the queue is
        // evidence that the lifecycle the row performed read ITS OWN attribute.
        let application = given_application(&emulator, &name, &[(attribute, &topic)]).await;
        let endpoint = register_endpoint(&emulator, &application, &format!("device-{index}")).await;
        let expected_prefix =
            format!("arn:aws:sns:{REGION}:{ACCOUNT}:endpoint/{CANONICAL_PLATFORM}/{name}/");
        assert!(
            endpoint.starts_with(&expected_prefix) && endpoint.len() > expected_prefix.len(),
            "case {case:?}: the endpoint ARN must be {expected_prefix}<endpoint id>, got \
             {endpoint:?}"
        );

        match lifecycle {
            Lifecycle::Register => {}
            Lifecycle::Write => {
                sns(
                    &emulator,
                    "SetEndpointAttributes",
                    &[
                        ("EndpointArn", &endpoint),
                        ("Attributes.entry.1.key", "CustomUserData"),
                        ("Attributes.entry.1.value", "re-registered"),
                    ],
                )
                .await;
            }
            Lifecycle::Remove => {
                sns(&emulator, "DeleteEndpoint", &[("EndpointArn", &endpoint)]).await;
            }
        }

        let delivered = drain(&emulator, &queue_url).await;
        assert_eq!(
            delivered.len(),
            1,
            "case {case:?}: expected exactly one event notification on the topic {attribute} \
             names, got {delivered:?}"
        );
        let body = &delivered[0].0;
        let document: Value = serde_json::from_str(body)
            .unwrap_or_else(|error| panic!("case {case:?}: body is not JSON ({error}): {body}"));
        assert_eq!(
            document["EventType"].as_str(),
            Some(*event_type),
            "case {case:?}: expected EventType {event_type:?}, got {document}"
        );
        assert_eq!(
            document["EndpointArn"].as_str(),
            Some(endpoint.as_str()),
            "case {case:?}: expected EndpointArn {endpoint:?}, got {document}"
        );
        assert_eq!(
            document["Resource"].as_str(),
            Some(application.as_str()),
            "case {case:?}: expected the application {application:?} as the resource, got \
             {document}"
        );
    }
}

/// An application that configures NO topic for the lifecycle that happened publishes nothing,
/// and a call that answers successfully without changing an endpoint's life publishes nothing
/// either.
#[tokio::test]
async fn nothing_is_published_for_a_lifecycle_no_attribute_configures_or_no_call_performed() {
    let emulator = emulator();
    let (created_topic, created_queue) =
        given_topic_with_subscribed_queue(&emulator, "created-events").await;
    let (_, unconfigured_queue) =
        given_topic_with_subscribed_queue(&emulator, "unconfigured-events").await;

    // The application names a topic for the REGISTRATION alone: every other lifecycle of its
    // endpoints has no destination.
    let application = given_application(
        &emulator,
        "created-only",
        &[("EventEndpointCreated", &created_topic)],
    )
    .await;
    let endpoint = register_endpoint(&emulator, &application, "device-token").await;
    assert_eq!(
        drain(&emulator, &created_queue).await.len(),
        1,
        "case the configured lifecycle: the registration must publish one notification"
    );

    // (case, the call to make, how many notifications the configured topic must then hold)
    let registration: Vec<(&str, &str)> = vec![
        ("PlatformApplicationArn", application.as_str()),
        ("Token", "device-token"),
    ];
    let written: Vec<(&str, &str)> = vec![
        ("EndpointArn", endpoint.as_str()),
        ("Attributes.entry.1.key", "CustomUserData"),
        ("Attributes.entry.1.value", "unchanged"),
    ];
    let removed: Vec<(&str, &str)> = vec![("EndpointArn", endpoint.as_str())];
    for (case, action, params) in [
        (
            "the idempotent registration of the same token",
            "CreatePlatformEndpoint",
            &registration,
        ),
        (
            "a write of the endpoint's attributes, with no topic for that lifecycle",
            "SetEndpointAttributes",
            &written,
        ),
        (
            "a delete of the endpoint, with no topic for that lifecycle",
            "DeleteEndpoint",
            &removed,
        ),
        (
            "the idempotent delete of an endpoint that is already gone",
            "DeleteEndpoint",
            &removed,
        ),
    ] {
        sns(&emulator, action, params).await;
        let delivered = drain(&emulator, &created_queue).await;
        assert!(
            delivered.is_empty(),
            "case {case:?}: expected no notification on the registration's topic, got \
             {delivered:?}"
        );
    }

    let unrelated = drain(&emulator, &unconfigured_queue).await;
    assert!(
        unrelated.is_empty(),
        "case a topic no attribute names: expected no notification at all, got {unrelated:?}"
    );
}
