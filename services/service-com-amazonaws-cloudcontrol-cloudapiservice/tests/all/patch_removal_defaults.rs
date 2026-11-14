// SPDX-License-Identifier: CC0-1.0

//! What a patch that REMOVES a property leaves behind, seen from the service that OWNS the
//! resource.
//!
//! The rule every case here holds the service to: **a write through Cloud Control API is a
//! write of the WHOLE desired model to the resource type's own provider in the service that
//! owns the resource, so a property the patched model no longer carries leaves the resource
//! carrying the OWNING service's documented default for that property — and nothing at all
//! for a property that service documents no default for — observable through that service's
//! own API, while a patch that adds the property back writes its value there again.**
//!
//! The rows differ along what the rule generalises over: which property the patch removes,
//! which form its value takes (a count, a document, a tag set, text), whether the property
//! has a documented default at all, and which service owns the resource — `AWS::SQS::Queue`
//! and `AWS::SNS::Topic`, so what the suite asserts is the write-through itself rather than
//! anything about one owning service.
//!
//! `sqs_queue_read_through` holds the same rule for a patch that SETS a property; this suite
//! is its other half.

use serde_json::{json, Map, Value};

use super::emulator::Emulator;
use super::sns_topic_read_through::{attribute, attributes, TOPIC};
use super::sqs_queue_read_through::{
    create_native, native_attribute, native_tags, queue_arn, tag, QUEUE,
};

/// One row of the removal table: the property a patch takes off the model, the value the
/// resource is created with, the text the OWNING service reports for that value, and the
/// text it reports once the property is gone.
struct Removal {
    /// What this row is about.
    case: &'static str,
    /// The property the patch removes, and then adds back.
    property: &'static str,
    /// The value the desired state carries for it, in the form the type's schema declares.
    value: Value,
    /// The text the owning service reports for that value through its own API.
    carried: String,
    /// The owning service's documented default for the property, and `None` for a property
    /// it documents no default for — which the resource then carries no value for at all.
    default: Option<&'static str>,
}

/// A patch document that removes one property of the model.
fn removal(property: &str) -> Value {
    json!([{ "op": "remove", "path": format!("/{property}") }])
}

/// A patch document that puts one property back on the model.
fn addition(property: &str, value: &Value) -> Value {
    json!([{ "op": "add", "path": format!("/{property}"), "value": value }])
}

/// A desired state naming the resource and carrying one other property.
fn desired(name_property: &str, name: &str, property: &str, value: &Value) -> Value {
    let mut model = Map::new();
    model.insert(name_property.to_string(), json!(name));
    model.insert(property.to_string(), value.clone());
    Value::Object(model)
}

/// The property value a model carries for an attribute the owning service reports as
/// `text`: a count as the number it is, anything else as that text — the form the type's
/// schema declares each property in.
fn property_value(text: &str) -> Value {
    text.parse::<i64>()
        .map_or_else(|_| Value::from(text.to_string()), Value::from)
}

#[tokio::test]
async fn a_patch_that_removes_a_property_restores_the_owning_services_default() {
    let emulator = Emulator::with_sqs();
    // One queue the document row can point a redrive policy at.
    let dead_letter = "removal-dead-letters";
    create_native(&emulator, dead_letter, &json!({})).await;
    let redrive = json!({
        "deadLetterTargetArn": queue_arn(dead_letter),
        "maxReceiveCount": 4,
    });

    // Catalog source: the defaults in the `Attributes` documentation of `CreateQueue` —
    // `DelaySeconds` "Default: 0", `VisibilityTimeout` "Default: 30",
    // `MessageRetentionPeriod` "Default: 345,600 (4 days)", `MaximumMessageSize`
    // "Default: 1,048,576 bytes (1 MiB)", `ReceiveMessageWaitTimeSeconds` "Default: 0" —
    // and `RedrivePolicy`, which that documentation gives no default for.
    let rows = [
        Removal {
            case: "a count whose default is zero",
            property: "DelaySeconds",
            value: json!(60),
            carried: "60".to_string(),
            default: Some("0"),
        },
        Removal {
            case: "a count whose default is not zero",
            property: "VisibilityTimeout",
            value: json!(90),
            carried: "90".to_string(),
            default: Some("30"),
        },
        Removal {
            case: "a count at the top of its published range",
            property: "MessageRetentionPeriod",
            value: json!(1_209_600),
            carried: "1209600".to_string(),
            default: Some("345600"),
        },
        Removal {
            case: "a count at the bottom of its published range",
            property: "MaximumMessageSize",
            value: json!(1_024),
            carried: "1024".to_string(),
            default: Some("1048576"),
        },
        Removal {
            case: "another count whose default is zero",
            property: "ReceiveMessageWaitTimeSeconds",
            value: json!(20),
            carried: "20".to_string(),
            default: Some("0"),
        },
        Removal {
            case: "a document the owning service documents no default for",
            property: "RedrivePolicy",
            value: redrive.clone(),
            carried: redrive.to_string(),
            default: None,
        },
    ];

    for (row, removed) in rows.into_iter().enumerate() {
        let Removal {
            case,
            property,
            value,
            carried,
            default,
        } = removed;
        let name = format!("removal-{row}");
        let identifier = emulator
            .provision(QUEUE, &desired("QueueName", &name, property, &value))
            .await;
        let reported = native_attribute(&emulator, &identifier, property).await;
        assert_eq!(
            reported.as_deref(),
            Some(carried.as_str()),
            "case {case:?}: expected the owning service to report {property} as {carried:?} \
             for the queue the create provisioned, got {reported:?}"
        );

        // The patch takes the property off the model, so the owning service holds the
        // resource under its own default for it.
        emulator
            .update_and_settle(QUEUE, &identifier, &removal(property))
            .await;
        let reported = native_attribute(&emulator, &identifier, property).await;
        assert_eq!(
            reported.as_deref(),
            default,
            "case {case:?}: after removing {property} expected the owning service to report \
             {default:?}, got {reported:?}"
        );
        // And a read through Cloud Control API reports the model the owning service now
        // holds: the default where there is one, and no such property where there is not.
        let model = emulator.properties(QUEUE, &identifier).await;
        match default {
            Some(default) => {
                let expected = property_value(default);
                assert_eq!(
                    model[property], expected,
                    "case {case:?}: after removing {property} expected the model to carry \
                     the default {expected:?}, got {model:?}"
                );
            }
            None => assert!(
                model.get(property).is_none(),
                "case {case:?}: after removing {property} expected the model to carry no \
                 such property, got {model:?}"
            ),
        }

        // And putting it back is a write of the value to the owning service again.
        emulator
            .update_and_settle(QUEUE, &identifier, &addition(property, &value))
            .await;
        let reported = native_attribute(&emulator, &identifier, property).await;
        assert_eq!(
            reported.as_deref(),
            Some(carried.as_str()),
            "case {case:?}: after adding {property} back expected the owning service to \
             report {carried:?}, got {reported:?}"
        );
    }
}

#[tokio::test]
async fn a_patch_that_removes_the_tag_set_leaves_the_resource_untagged() {
    let emulator = Emulator::with_sqs();
    // A tag set is the one property of the type that is no attribute of the queue, so it is
    // the row that holds the rule over a property the owning service keeps its own way.
    let tags = json!([tag("owner", "platform"), tag("tier", "gold")]);
    let identifier = emulator
        .provision(
            QUEUE,
            &desired("QueueName", "removal-tagged", "Tags", &tags),
        )
        .await;
    let expected = tags.as_array().cloned().unwrap_or_default();
    let reported = native_tags(&emulator, &identifier).await;
    assert_eq!(
        reported, expected,
        "the create must leave the owning service holding {expected:?}, got {reported:?}"
    );

    emulator
        .update_and_settle(QUEUE, &identifier, &removal("Tags"))
        .await;
    let reported = native_tags(&emulator, &identifier).await;
    assert!(
        reported.is_empty(),
        "after removing Tags the owning service must report no tag, got {reported:?}"
    );
    let model = emulator.properties(QUEUE, &identifier).await;
    assert!(
        model.get("Tags").is_none(),
        "after removing Tags the model must carry no tag set, got {model:?}"
    );

    emulator
        .update_and_settle(QUEUE, &identifier, &addition("Tags", &tags))
        .await;
    let reported = native_tags(&emulator, &identifier).await;
    assert_eq!(
        reported, expected,
        "after adding Tags back the owning service must report {expected:?}, got {reported:?}"
    );
}

#[tokio::test]
async fn a_patch_that_removes_a_property_of_another_owning_service_clears_it_there() {
    let emulator = Emulator::with_sns();
    // The same rule over a resource a DIFFERENT service owns, and over a property whose
    // value is text rather than a count: a topic's display name, which Amazon SNS reports
    // among the topic's own attributes.
    let property = "DisplayName";
    let value = json!("Before");
    let identifier = emulator
        .provision(
            TOPIC,
            &desired("TopicName", "removal-topic", property, &value),
        )
        .await;
    let carried = attribute(&attributes(&emulator, "the create", &identifier).await, property);
    assert_eq!(
        carried, "Before",
        "the create must leave the owning service holding the display name, got {carried:?}"
    );

    emulator
        .update_and_settle(TOPIC, &identifier, &removal(property))
        .await;
    let carried = attribute(&attributes(&emulator, "the removal", &identifier).await, property);
    assert_eq!(
        carried, "",
        "after removing {property} the owning service must report no display name, got \
         {carried:?}"
    );

    emulator
        .update_and_settle(TOPIC, &identifier, &addition(property, &value))
        .await;
    let carried =
        attribute(&attributes(&emulator, "the addition", &identifier).await, property);
    assert_eq!(
        carried, "Before",
        "after adding {property} back the owning service must report it again, got \
         {carried:?}"
    );
}
