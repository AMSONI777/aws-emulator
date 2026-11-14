// SPDX-License-Identifier: CC0-1.0

//! A message attribute's custom TYPE LABEL leaves its value opaque: the publish is served
//! and the value reaches every subscriber verbatim, in both delivery modes.
//!
//! The RULE asserted here: a `DataType` is one of the logical types SNS defines
//! optionally followed by a custom label ("String, String.Array, Number, and Binary …
//! You can also append custom labels", `MessageAttributeValue$DataType` doc), and the
//! model puts no constraint on what a value carries beyond the FIELD its logical type
//! names (`smithy_query(query="shape",shape="MessageAttributeValue")` reports plain
//! strings for `DataType` and `StringValue` and a blob for `BinaryValue`). So nothing of
//! a labelled value is parsed as a precondition of publishing it: the attribute is
//! accepted, and it is delivered as `{"Type": "<the data type>", "Value": "<the
//! value>"}` inside the notification envelope and as an SQS message attribute of the
//! same `DataType` on a `RawMessageDelivery` subscription.
//!
//! The rows differ along what the rule generalises over: the logical type the label sits
//! on (`String`, `Number`, `Binary`), the label itself, and the FORM of the value under
//! the service's own `String.Array` label — a JSON array, a JSON document that is no
//! array, and text that is no JSON at all.

use serde_json::Value;

use crate::sqs_subscription_delivery::{
    drain, element, emulator, given_queue, sns, sns_call, Emulator,
};

/// One attribute of the published message: the case, the attribute's name, the
/// `DataType` as the request spells it, the value, and whether the value is carried in
/// `BinaryValue` (a `Binary` attribute) rather than `StringValue`.
struct Attribute<'a> {
    case: &'a str,
    name: &'a str,
    data_type: &'a str,
    /// The value as the request carries it — for a binary attribute, the base64 text the
    /// wire form of a blob is, which is also the text the envelope reports.
    value: &'a str,
    binary: bool,
}

/// The attributes one publish carries: every logical type with a custom label on it, and
/// every form a `String.Array` value takes.
fn attributes() -> Vec<Attribute<'static>> {
    vec![
        Attribute {
            case: "the array label carrying a JSON array",
            name: "list",
            data_type: "String.Array",
            value: r#"["a",1,true,null]"#,
            binary: false,
        },
        Attribute {
            case: "the array label carrying text that is no JSON at all",
            name: "loose",
            data_type: "String.Array",
            value: "not-a-json-array",
            binary: false,
        },
        Attribute {
            case: "the array label carrying JSON that is no array",
            name: "document",
            data_type: "String.Array",
            value: r#"{"a":1}"#,
            binary: false,
        },
        Attribute {
            case: "a custom label on the number type",
            name: "ratio",
            data_type: "Number.float",
            value: "3.5",
            binary: false,
        },
        Attribute {
            case: "a custom label on the string type",
            name: "payload",
            data_type: "String.json",
            value: r#"{"kind":"alert"}"#,
            binary: false,
        },
        Attribute {
            case: "a custom label on the binary type",
            name: "icon",
            data_type: "Binary.gif",
            // "GIF89a", as the base64 a blob travels the wire as.
            value: "R0lGODlh",
            binary: true,
        },
    ]
}

/// Subscribe the queue `arn` to `topic`, asking for raw delivery when `raw`.
async fn subscribe(emulator: &Emulator, topic: &str, arn: &str, raw: bool) {
    let subscription = element(
        &sns(
            emulator,
            "Subscribe",
            &[
                ("TopicArn", topic),
                ("Protocol", "sqs"),
                ("Endpoint", arn),
                ("ReturnSubscriptionArn", "true"),
            ],
        )
        .await,
        "SubscriptionArn",
    );
    if raw {
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
    }
}

/// RULE: every labelled attribute is published and arrives verbatim in both delivery
/// modes.
#[tokio::test]
async fn a_labelled_message_attribute_is_published_and_delivered_verbatim() {
    let emulator = emulator();
    let topic = element(
        &sns(&emulator, "CreateTopic", &[("Name", "labelled-attributes")]).await,
        "TopicArn",
    );
    let (envelope_url, envelope_arn) = given_queue(&emulator, "labels-envelope").await;
    let (raw_url, raw_arn) = given_queue(&emulator, "labels-raw").await;
    subscribe(&emulator, &topic, &envelope_arn, false).await;
    subscribe(&emulator, &topic, &raw_arn, true).await;

    let rows = attributes();
    // One publish carrying every row, the way a publisher using the service's type
    // labels sends them.
    let mut params: Vec<(String, String)> = vec![
        ("TopicArn".to_string(), topic.clone()),
        ("Message".to_string(), "a labelled message".to_string()),
    ];
    for (at, row) in rows.iter().enumerate() {
        let entry = at + 1;
        params.push((
            format!("MessageAttributes.entry.{entry}.Name"),
            row.name.to_string(),
        ));
        params.push((
            format!("MessageAttributes.entry.{entry}.Value.DataType"),
            row.data_type.to_string(),
        ));
        let field = if row.binary {
            "BinaryValue"
        } else {
            "StringValue"
        };
        params.push((
            format!("MessageAttributes.entry.{entry}.Value.{field}"),
            row.value.to_string(),
        ));
    }
    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let (status, body) = sns_call(&emulator, "Publish", &borrowed).await;
    assert_eq!(
        status, 200,
        "a publish carrying every type label expected HTTP 200, got {status} / {body}"
    );
    let message_id = element(&body, "MessageId");
    assert!(
        !message_id.is_empty(),
        "the publish must report a message, got {body}"
    );

    // The envelope subscriber: the attribute map of the notification carries each
    // attribute as its type and its value.
    let delivered = drain(&emulator, &envelope_url).await;
    assert_eq!(
        delivered.len(),
        1,
        "the envelope subscriber expected one message, got {delivered:?}"
    );
    let envelope: Value = serde_json::from_str(&delivered[0].0)
        .unwrap_or_else(|error| panic!("the envelope must be JSON ({error}): {}", delivered[0].0));
    for row in &rows {
        let carried = &envelope["MessageAttributes"][row.name];
        assert_eq!(
            carried["Type"].as_str(),
            Some(row.data_type),
            "case {:?}: the envelope must carry the type as published, got {carried:?}",
            row.case
        );
        assert_eq!(
            carried["Value"].as_str(),
            Some(row.value),
            "case {:?}: the envelope must carry the value verbatim, got {carried:?}",
            row.case
        );
    }

    // The raw-delivery subscriber: the same attributes arrive as the queue's own message
    // attributes, each under the type it was published with.
    let raw = drain(&emulator, &raw_url).await;
    assert_eq!(
        raw.len(),
        1,
        "the raw-delivery subscriber expected one message, got {raw:?}"
    );
    let (raw_body, raw_attributes) = &raw[0];
    assert_eq!(
        raw_body, "a labelled message",
        "the raw-delivery subscriber must receive the published body, got {raw_body:?}"
    );
    for row in &rows {
        let carried = &raw_attributes[row.name];
        assert_eq!(
            carried["DataType"].as_str(),
            Some(row.data_type),
            "case {:?}: the queue must carry the type as published, got {carried:?}",
            row.case
        );
        let field = if row.binary {
            "BinaryValue"
        } else {
            "StringValue"
        };
        assert_eq!(
            carried[field].as_str(),
            Some(row.value),
            "case {:?}: the queue must carry the value verbatim, got {carried:?}",
            row.case
        );
    }
}
