// SPDX-License-Identifier: CC0-1.0

//! The endpoint-lifecycle events a mobile push PLATFORM APPLICATION publishes to the topics its
//! own attributes name.
//!
//! The rule: a platform application attribute named `Event<lifecycle>` holds the "Topic ARN to
//! which `<lifecycle>` event notifications are sent"
//! (`SetPlatformApplicationAttributesInput$Attributes`, the same map
//! `CreatePlatformApplication` takes), so every lifecycle change an application's endpoints
//! undergo publishes one notification to the topic the matching attribute names — and an
//! application naming no topic for that lifecycle publishes nothing. The notification is an
//! ordinary message of that topic: it reaches its subscribers over the one publishing path a
//! client's own `Publish` takes ([`super::publish_into_store`] and
//! [`super::deliver_to_endpoints`]), so a subscribed queue receives it exactly as it receives
//! any other notification of the topic.
//!
//! The document carries the event's own name and the endpoint it is about — "`EventType` …
//! `EndpointArn`" — plus the application the endpoint belongs to and the service that published
//! it. Every value comes from the request and this store: the endpoint's ARN is the one the
//! registration minted, and the application's is the one that registration named.
//!
//! The publish is made by this SERVICE rather than by the caller, so the caller's own
//! permissions decide nothing about it: a client authorized to register an endpoint does not
//! have to be authorized to publish to the application's event topic.

use crate::ops::types::PublishInput;
use crate::state;

/// The lifecycle change of a device endpoint an application notifies its configured topic of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointEvent {
    /// A registration minted a new endpoint of the application.
    Created,
    /// An endpoint of the application was removed.
    Deleted,
    /// An endpoint of the application had its attributes or its device token written.
    Updated,
}

impl EndpointEvent {
    /// The platform-application attribute naming the topic THIS event is published to, as
    /// `SetPlatformApplicationAttributesInput$Attributes` spells each one.
    const fn topic_attribute(self) -> &'static str {
        match self {
            Self::Created => "EventEndpointCreated",
            Self::Deleted => "EventEndpointDeleted",
            Self::Updated => "EventEndpointUpdated",
        }
    }

    /// The event's own name, which the published document carries under `EventType`: the name
    /// the attribute's own documentation gives the notifications it configures —
    /// "`EventEndpointCreated` – Topic ARN to which `EndpointCreated` event notifications are
    /// sent", and likewise `EndpointDeleted` and `EndpointUpdate`.
    const fn event_type(self) -> &'static str {
        match self {
            Self::Created => "EndpointCreated",
            Self::Deleted => "EndpointDeleted",
            Self::Updated => "EndpointUpdate",
        }
    }
}

/// The member naming which lifecycle change the document reports.
const EVENT_TYPE_MEMBER: &str = "EventType";

/// The member naming the endpoint the change was made to.
const ENDPOINT_ARN_MEMBER: &str = "EndpointArn";

/// The member naming the resource the event is ABOUT — the platform application the endpoint
/// belongs to — as every AWS event document names the resource it concerns.
const RESOURCE_MEMBER: &str = "Resource";

/// The member naming the service that published the event.
const SERVICE_MEMBER: &str = "Service";

/// The member carrying the instant the event was published.
const TIMESTAMP_MEMBER: &str = "Timestamp";

/// This service, as the published document names the publisher of the event.
const SERVICE_NAME: &str = "SNS";

/// Publish one `event` about the endpoint `endpoint_arn` of the platform application
/// `application_arn` to the topic that application's matching attribute names.
///
/// Nothing is published where the application names no topic for this lifecycle, where the
/// attribute is empty, or where the topic it names is not one this account holds — each a
/// configuration this service has nothing to deliver to, which is reported where an operator
/// can see it rather than to the caller: "the delivery's outcome is not part of this
/// operation's answer" ([`super::deliver_to_endpoints`]), and neither is the event's.
///
/// Call it with NO store of this service locked: the store's guard is taken here, for the
/// publish alone, and released before the subscribers of the event topic are delivered to.
pub(crate) async fn publish<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &smithy_server_runtime::OperationContext<'_>,
    event: EndpointEvent,
    application_arn: &str,
    endpoint_arn: &str,
) {
    let Some(store) = state::service_state(engine) else {
        return;
    };
    let topic_arn = {
        let store = store.lock();
        let Some(application) = store.platform_applications.get(application_arn) else {
            return;
        };
        match application
            .attributes
            .get(event.topic_attribute())
            .map(|topic| topic.trim().to_string())
            .filter(|topic| !topic.is_empty())
        {
            Some(topic_arn) => topic_arn,
            // The application configures no topic for this lifecycle, so the event has no
            // destination: AWS publishes nothing either.
            None => return,
        }
    };

    let input = PublishInput {
        topic_arn: Some(topic_arn.clone()),
        message: document(event, application_arn, endpoint_arn),
        ..PublishInput::default()
    };
    let deliveries = {
        let mut store = store.lock();
        match super::publish_into_store(ctx, &mut store, input, &topic_arn) {
            Ok((_, deliveries)) => deliveries,
            Err(_) => {
                ::tracing::warn!(
                    application = %application_arn,
                    topic = %topic_arn,
                    event = %event.event_type(),
                    "the topic a platform application names for this event took no message, so \
                     the event notification was not published"
                );
                return;
            }
        }
    };
    super::deliver_to_endpoints(ctx, engine, &deliveries).await;
}

/// The JSON document ONE endpoint-lifecycle event is published as.
fn document(event: EndpointEvent, application_arn: &str, endpoint_arn: &str) -> String {
    let mut members = ::serde_json::Map::new();
    members.insert(
        EVENT_TYPE_MEMBER.to_string(),
        ::serde_json::Value::from(event.event_type()),
    );
    members.insert(
        ENDPOINT_ARN_MEMBER.to_string(),
        ::serde_json::Value::from(endpoint_arn),
    );
    members.insert(
        RESOURCE_MEMBER.to_string(),
        ::serde_json::Value::from(application_arn),
    );
    members.insert(
        SERVICE_MEMBER.to_string(),
        ::serde_json::Value::from(SERVICE_NAME),
    );
    if let Some(timestamp) = state::rfc3339(::std::time::SystemTime::now()) {
        members.insert(
            TIMESTAMP_MEMBER.to_string(),
            ::serde_json::Value::from(timestamp),
        );
    }
    ::serde_json::Value::Object(members).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every event's document names the lifecycle it reports and the endpoint it is about, and
    /// each lifecycle is read out of its OWN application attribute: the rows differ along the
    /// lifecycle the event reports.
    #[test]
    fn each_lifecycle_has_its_own_attribute_event_name_and_document() {
        let application = "arn:aws:sns:us-east-1:000000000000:app/GCM/registry";
        let endpoint = "arn:aws:sns:us-east-1:000000000000:endpoint/GCM/registry/7";
        for (case, event, attribute, event_type) in [
            (
                "a registration",
                EndpointEvent::Created,
                "EventEndpointCreated",
                "EndpointCreated",
            ),
            (
                "a removal",
                EndpointEvent::Deleted,
                "EventEndpointDeleted",
                "EndpointDeleted",
            ),
            (
                "an attribute write",
                EndpointEvent::Updated,
                "EventEndpointUpdated",
                "EndpointUpdate",
            ),
        ] {
            assert_eq!(
                event.topic_attribute(),
                attribute,
                "case {case}: expected the topic to come from {attribute}, got {}",
                event.topic_attribute()
            );
            let document: ::serde_json::Value =
                ::serde_json::from_str(&document(event, application, endpoint))
                    .unwrap_or_else(|error| panic!("case {case}: not JSON ({error})"));
            assert_eq!(
                document[EVENT_TYPE_MEMBER].as_str(),
                Some(event_type),
                "case {case}: expected EventType {event_type}, got {document}"
            );
            assert_eq!(
                document[ENDPOINT_ARN_MEMBER].as_str(),
                Some(endpoint),
                "case {case}: expected EndpointArn {endpoint}, got {document}"
            );
            assert_eq!(
                document[RESOURCE_MEMBER].as_str(),
                Some(application),
                "case {case}: expected Resource {application}, got {document}"
            );
        }
    }
}
