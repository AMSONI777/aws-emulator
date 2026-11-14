// SPDX-License-Identifier: CC0-1.0

//! The sentences Amazon SNS refuses a message attribute's NAME and a `Number` value's
//! SIZE with, driven end-to-end over the awsQuery wire.
//!
//! The RULE asserted here: each rule a message attribute is held to has ONE sentence of
//! its own, because every one of these refusals carries the same error
//! (`InvalidParameterValueException`, awsQuery code `ParameterValueInvalid`, HTTP 400 —
//! `smithy_query(query="operation",operation="Publish")`), so the sentence is the only
//! thing that says which rule the request broke. A NAME is refused for its length and
//! for each place a period may not stand; a `Number` value is refused outside the
//! precision and the scale its type holds ("a number can have up to 38 digits of
//! precision, and it can be between 10^-128 to 10^+126", the Amazon SNS Developer Guide,
//! "Amazon SNS message attributes", a span its smaller power lies inside and its larger
//! power stops at), each sentence naming the attribute and — for a
//! value of the right type but the wrong size — the value, and nothing else of the
//! request. Nothing is published either way, and the value on each side of a bound is
//! served.
//!
//! The rows differ along what the rule generalises over: which rule the name breaks and
//! in what form it breaks it, how far past the bound it stands, the ATTRIBUTE the
//! sentence names, the form the number is written in (plain digits, a fraction, an
//! exponent, leading zeros), which side of each bound it falls on — and the publishing
//! call, since `Publish` and `PublishBatch` hold an attribute to the same rules.

use super::topics_subscriptions_publish::{Answer, Sns};

/// The status and awsQuery code SNS answers a message attribute it will not take with.
const REFUSAL_STATUS: u16 = 400;
const REFUSAL_CODE: &str = "ParameterValueInvalid";

/// Publish one message carrying the single attribute `(name, data_type, value)`.
async fn publish(sns: &Sns, topic: &str, name: &str, data_type: &str, value: &str) -> Answer {
    sns.call(
        "Publish",
        &[
            ("TopicArn", topic),
            ("Message", "m"),
            ("MessageAttributes.entry.1.Name", name),
            ("MessageAttributes.entry.1.Value.DataType", data_type),
            ("MessageAttributes.entry.1.Value.StringValue", value),
        ],
    )
    .await
}

/// The same attribute through the other publishing call, whose entries are held to the
/// same attribute rules.
async fn publish_batch(sns: &Sns, topic: &str, name: &str, data_type: &str, value: &str) -> Answer {
    sns.call(
        "PublishBatch",
        &[
            ("TopicArn", topic),
            ("PublishBatchRequestEntries.member.1.Id", "one"),
            ("PublishBatchRequestEntries.member.1.Message", "m"),
            (
                "PublishBatchRequestEntries.member.1.MessageAttributes.entry.1.Name",
                name,
            ),
            (
                "PublishBatchRequestEntries.member.1.MessageAttributes.entry.1.Value.DataType",
                data_type,
            ),
            (
                "PublishBatchRequestEntries.member.1.MessageAttributes.entry.1.Value.StringValue",
                value,
            ),
        ],
    )
    .await
}

/// Assert that `answer` refuses the publish with `expected`, through `call`, and that it
/// published nothing.
fn assert_refused(case: &str, call: &str, answer: &Answer, expected: &str) {
    assert_eq!(
        answer.status, REFUSAL_STATUS,
        "case {case:?} through {call}: expected HTTP {REFUSAL_STATUS}, got {} / {}",
        answer.status, answer.body
    );
    assert_eq!(
        answer.code(),
        REFUSAL_CODE,
        "case {case:?} through {call}: expected the {REFUSAL_CODE} code, got {}",
        answer.body
    );
    assert_eq!(
        answer.element("Message").as_deref(),
        Some(expected),
        "case {case:?} through {call}: expected the service's own sentence, got {}",
        answer.body
    );
    assert_eq!(
        answer.element("MessageId"),
        None,
        "case {case:?} through {call}: a refused publish must report no message, got {}",
        answer.body
    );
}

/// Assert that `answer` served the publish.
fn assert_served(case: &str, call: &str, answer: &Answer) {
    assert_eq!(
        answer.status, 200,
        "case {case:?} through {call}: expected the publish to be served, got {} / {}",
        answer.status, answer.body
    );
}

/// RULE: each place a period may not stand in a message attribute name, and the name's
/// length, is refused with the sentence SNS states for that rule alone.
#[tokio::test]
async fn a_message_attribute_name_is_refused_with_the_sentence_of_the_rule_it_breaks() {
    let sns = Sns::new();
    let topic = sns.topic("attribute-name-sentences").await;

    // The sentences, one per rule, with the bound the length sentence names.
    let too_long = "Length of message attribute name must be less than 256 bytes.";
    let leading = "Invalid message attribute name starting with character '.' was found.";
    let trailing = "Invalid message attribute name ending with character '.' was found.";
    let successive = "Message attribute name can not have successive '.' character.";

    let at_bound = "n".repeat(256);
    let past_bound = "n".repeat(257);
    let far_past_bound = "n".repeat(1_000);

    // (case, the attribute's name, the sentence it is refused with — `None` when SNS
    // takes the name)
    let rows: &[(&str, &str, Option<&str>)] = &[
        ("a name at the documented length", at_bound.as_str(), None),
        ("periods inside the name", "a.b.c", None),
        ("a name one character past the length", past_bound.as_str(), Some(too_long)),
        ("a name far past the length", far_past_bound.as_str(), Some(too_long)),
        ("a leading period", ".lead", Some(leading)),
        ("a leading period before more periods", ".a.b", Some(leading)),
        ("a trailing period", "trail.", Some(trailing)),
        ("a trailing period after more periods", "a.b.", Some(trailing)),
        ("two successive periods", "a..b", Some(successive)),
        ("a run of three periods", "x...y", Some(successive)),
        ("successive periods inside a longer name", "one..two.three", Some(successive)),
    ];

    for (case, name, refusal) in rows {
        for (call, answer) in [
            (
                "Publish",
                publish(&sns, &topic, name, "String", "v").await,
            ),
            (
                "PublishBatch",
                publish_batch(&sns, &topic, name, "String", "v").await,
            ),
        ] {
            match refusal {
                None => assert_served(case, call, &answer),
                Some(expected) => assert_refused(case, call, &answer, expected),
            }
        }
    }
}

/// RULE: a `Number` attribute outside the precision or the scale its type holds is
/// refused with the sentence SNS states for that bound, naming the attribute and the
/// value, and a value inside both bounds is published.
#[tokio::test]
async fn a_number_message_attribute_is_refused_outside_its_precision_and_scale() {
    let sns = Sns::new();
    let topic = sns.topic("number-attribute-bounds").await;

    /// The sentence a value carrying more significant digits than the type holds is
    /// refused with.
    fn precision_refusal(name: &str, value: &str) -> String {
        format!(
            "Message attribute '{name}' number value [{value}] must have less than 38 \
             precision digits."
        )
    }

    /// The sentence a value standing outside the powers of ten the type spans is refused
    /// with.
    fn scale_refusal(name: &str, value: &str) -> String {
        format!(
            "Message attribute '{name}' number value [{value}] scale must be 10^-128 and \
             10^126."
        )
    }

    let at_precision = "1".repeat(38);
    let past_precision = "1".repeat(39);
    let far_past_precision = "9".repeat(60);
    // Leading zeros carry no precision, so 38 significant digits behind a zero are still
    // 38 digits of precision — and 39 are still 39.
    let zero_led_at_precision = format!("0.{at_precision}");
    let zero_led_past_precision = format!("0.{past_precision}");
    // A magnitude written out plainly rather than with an exponent: the scale is a
    // property of the number, not of its spelling.
    let plainly_past_scale = format!("0.{}1", "0".repeat(130));

    // (case, the attribute's name, the value, the sentence it is refused with — `None`
    // when the value is one the type holds)
    let rows: &[(&str, &str, &str, Option<String>)] = &[
        ("a value at the documented precision", "n", at_precision.as_str(), None),
        (
            "a value one digit past the precision",
            "n",
            past_precision.as_str(),
            Some(precision_refusal("n", &past_precision)),
        ),
        (
            "a value far past the precision",
            "digits",
            far_past_precision.as_str(),
            Some(precision_refusal("digits", &far_past_precision)),
        ),
        (
            "significant digits at the precision behind a leading zero",
            "n",
            zero_led_at_precision.as_str(),
            None,
        ),
        (
            "significant digits past the precision behind a leading zero",
            "n",
            zero_led_past_precision.as_str(),
            Some(precision_refusal("n", &zero_led_past_precision)),
        ),
        ("the largest power the type holds", "n", "1e125", None),
        (
            "the power the span stops at",
            "n",
            "1e126",
            Some(scale_refusal("n", "1e126")),
        ),
        (
            "the first power past the span",
            "n",
            "1e127",
            Some(scale_refusal("n", "1e127")),
        ),
        (
            "a power far past the largest",
            "scale",
            "1E+200",
            Some(scale_refusal("scale", "1E+200")),
        ),
        ("the smallest power the type holds", "n", "1e-128", None),
        (
            "the first power past the smallest",
            "n",
            "1e-129",
            Some(scale_refusal("n", "1e-129")),
        ),
        (
            "a power far past the smallest",
            "n",
            "1e-400",
            Some(scale_refusal("n", "1e-400")),
        ),
        (
            "a magnitude past the smallest power, written out plainly",
            "n",
            plainly_past_scale.as_str(),
            Some(scale_refusal("n", &plainly_past_scale)),
        ),
        // The forms a number inside both bounds is written in, each of which stands at a
        // power of ten the type holds.
        ("a whole number", "n", "17", None),
        ("a fraction", "n", "1.5", None),
        ("a leading-point fraction", "n", ".5", None),
        ("a signed value", "n", "-17.25", None),
        ("zero, which stands at no power of ten", "n", "0", None),
    ];

    for (case, name, value, refusal) in rows {
        for (call, answer) in [
            (
                "Publish",
                publish(&sns, &topic, name, "Number", value).await,
            ),
            (
                "PublishBatch",
                publish_batch(&sns, &topic, name, "Number", value).await,
            ),
        ] {
            match refusal {
                None => assert_served(case, call, &answer),
                Some(expected) => assert_refused(case, call, &answer, expected),
            }
        }
    }
}
