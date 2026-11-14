// SPDX-License-Identifier: CC0-1.0

//! The rules ONE message attribute of a published message is held to.
//!
//! "Name, type, and value must not be empty or null" (`MessageAttributeValue` doc), and
//! the three parts each carry a rule of their own: a NAME is a bounded run of the
//! characters SNS admits in one, outside the prefixes it reserves for itself; a TYPE is
//! one of the logical types the service defines ("String, String.Array, Number, and
//! Binary", `MessageAttributeValue$DataType` doc), optionally with a custom label after
//! it; and a VALUE belongs in the field its type names and holds only what that type can
//! carry ("Strings are Unicode with UTF8 binary encoding",
//! `MessageAttributeValue$StringValue` doc).
//!
//! These are ARGUMENT rules — they judge the attribute map alone, with no record read —
//! so they are shared by every operation that publishes a message: an attribute map
//! `Publish` accepts cannot be one `PublishBatch` refuses. A request they refuse is
//! answered with the modelled `InvalidParameterValueException` (`ParameterValueInvalid`,
//! HTTP 400), the error SNS states for a PARAMETER VALUE it will not take, and the
//! sentence is the condition itself rather than a clause under `Invalid parameter:`.

use std::collections::HashMap;

use crate::ops::types::MessageAttributeValue;

use super::{attribute_data_type, BINARY_DATA_TYPE, NUMBER_DATA_TYPE, STRING_DATA_TYPE};

/// The longest message attribute name SNS accepts, in characters — the same bound the
/// service publishes for a message attribute's name in the Amazon SNS Developer Guide
/// ("Amazon SNS message attributes": a name "can contain up to 256 characters").
pub const MAX_ATTRIBUTE_NAME_CHARS: usize = 256;

/// The name prefixes SNS keeps for its own attributes (the Amazon SNS Developer Guide,
/// "Amazon SNS message attributes": names beginning `AWS.` or `Amazon.` are reserved for
/// use by Amazon Web Services), so a publisher may not name an attribute under one.
pub const RESERVED_NAME_PREFIXES: &[&str] = &["AWS.", "Amazon."];

/// The most significant digits a `Number` attribute's value may carry, and the decimal
/// exponents its scale lies between: "a number can have up to 38 digits of precision,
/// and it can be between 10^-128 to 10^+126" (the Amazon SNS Developer Guide, "Amazon
/// SNS message attributes", of the `Number` data type) — so a value is held to 38
/// significant digits, and its magnitude to the span those powers of ten give it: from
/// the smaller power, which is a magnitude the type holds, UP TO the larger, which is the
/// first magnitude it does not. Recorded evidence: a value at 10^-128 is published, and
/// one at 10^126 is refused for its scale.
pub const MAX_NUMBER_PRECISION: usize = 38;
pub const MIN_NUMBER_EXPONENT: i32 = -128;
pub const MAX_NUMBER_EXPONENT: i32 = 126;

/// The characters a message attribute's textual value may carry: the XML text set
/// restricted to the Basic Multilingual Plane — tab, newline, carriage return, and the
/// code points up to `#xFFFD` bar the surrogate range. A code point above the BMP is not
/// one an attribute value carries, which is what tells this set from the message BODY's.
fn is_attribute_value_character(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(c, '\u{20}'..='\u{D7FF}')
        || matches!(c, '\u{E000}'..='\u{FFFD}')
}

/// Whether `name` is made of the characters SNS admits in a message attribute name:
/// alphanumerics, underscore, hyphen and period (the Amazon SNS Developer Guide, "Amazon
/// SNS message attributes": a name "can contain ... alphanumeric characters, hyphens (-),
/// underscores (_), and periods (.)").
///
/// ALPHANUMERIC is read as the character's own class rather than as ASCII, so a letter or a
/// digit outside ASCII is one of the characters a name may carry: the rule is about what
/// the character IS, and a name of letters is a name whichever script writes them.
fn is_attribute_name_character(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// The logical data types SNS defines for a message attribute, from the
/// `MessageAttributeValue$DataType` doc ("String, String.Array, Number, and Binary").
/// `String.Array` is read as the `String` type with the service's own label, which is
/// what [`attribute_data_type`] strips, so the three type prefixes are what a value's
/// field is chosen by.
const DATA_TYPE_PREFIXES: &[&str] = &[STRING_DATA_TYPE, NUMBER_DATA_TYPE, BINARY_DATA_TYPE];

/// The sentence SNS states for a message attribute NAME it will not take.
///
/// One sentence per RULE, as the service states each: the length, the character set (with
/// the offending character's code), and each of the three places a period may not stand.
/// None of them echoes the name — the caller named it in the request — which is also how
/// the reserved-prefix sentence reads.
fn invalid_name_message(name: &str) -> Option<String> {
    let length = name.chars().count();
    if length == 0 {
        return Some("The request must contain non-empty message attribute names.".to_string());
    }
    if length > MAX_ATTRIBUTE_NAME_CHARS {
        return Some(format!(
            "Length of message attribute name must be less than \
             {MAX_ATTRIBUTE_NAME_CHARS} bytes."
        ));
    }
    if let Some(character) = name.chars().find(|c| !is_attribute_name_character(*c)) {
        // The offending character is named as the character reference SNS states it by:
        // `#x` and its code point in uppercase hex, unpadded.
        return Some(format!(
            "Invalid non-alphanumeric character '#x{:X}' was found in the message \
             attribute name. Can only include alphanumeric characters, hyphens, \
             underscores, or dots.",
            character as u32
        ));
    }
    if name.starts_with('.') {
        return Some(
            "Invalid message attribute name starting with character '.' was found.".to_string(),
        );
    }
    if name.ends_with('.') {
        return Some(
            "Invalid message attribute name ending with character '.' was found.".to_string(),
        );
    }
    if name.contains("..") {
        return Some("Message attribute name can not have successive '.' character.".to_string());
    }
    None
}

/// Why ONE message attribute is not one SNS takes: the sentence, and which modelled
/// error the service states it with.
///
/// A NAME, a TYPE, a missing value or a number outside its bounds is a parameter VALUE
/// fault (`InvalidParameterValueException`, `ParameterValueInvalid`). A value carrying a
/// character an attribute value may not hold is a plain parameter fault
/// (`InvalidParameterException`, `InvalidParameter`): the attribute is well formed and
/// what cannot be carried is the text.
#[derive(Debug, Clone)]
pub enum MessageAttributeRefusal {
    /// The attribute's name, type or value is not one the service takes.
    ParameterValue(String),
    /// The value carries a character an attribute value may not hold.
    InvalidParameter(String),
}

impl MessageAttributeRefusal {
    /// The sentence this refusal states.
    pub fn message(self) -> String {
        match self {
            Self::ParameterValue(message) | Self::InvalidParameter(message) => message,
        }
    }
}

/// The refusal a published message's attribute map answers, or `None` when every
/// attribute of it is one SNS accepts.
///
/// The attributes are judged in ascending order of name, so a map carrying several
/// faults always names the same one: a map has no order of its own, and a caller fixing
/// the first fault reported must not see a different one reported next time.
pub fn message_attributes_refusal(
    attributes: &HashMap<String, MessageAttributeValue>,
) -> Option<MessageAttributeRefusal> {
    let mut names: Vec<&String> = attributes.keys().collect();
    names.sort();
    names
        .into_iter()
        .find_map(|name| message_attribute_refusal(name, &attributes[name]))
}

/// The refusal ONE message attribute answers, or `None` when SNS accepts it.
pub fn message_attribute_refusal(
    name: &str,
    value: &MessageAttributeValue,
) -> Option<MessageAttributeRefusal> {
    if let Some(message) = attribute_name_refusal(name) {
        return Some(MessageAttributeRefusal::ParameterValue(message));
    }
    attribute_value_refusal(name, value)
}

/// The message an unacceptable attribute NAME is refused with, or `None` when the name
/// is one SNS accepts: its length and character set, the periods it may not carry at the
/// edges or in a run, and the prefixes the service reserves.
fn attribute_name_refusal(name: &str) -> Option<String> {
    if let Some(message) = invalid_name_message(name) {
        return Some(message);
    }
    RESERVED_NAME_PREFIXES
        .iter()
        .find(|prefix| name.starts_with(**prefix))
        .map(|_| {
            format!(
                "Message attribute names starting with '{}' or '{}' are reserved for use \
                 by Amazon.",
                RESERVED_NAME_PREFIXES[0], RESERVED_NAME_PREFIXES[1]
            )
        })
}

/// The refusal an unacceptable attribute TYPE or VALUE answers, or `None` when SNS
/// accepts the pair: the type names the field the value belongs in, that field has to
/// carry it, and a value has to be one the type can hold.
fn attribute_value_refusal(
    name: &str,
    value: &MessageAttributeValue,
) -> Option<MessageAttributeRefusal> {
    let data_type = attribute_data_type(value);
    if !DATA_TYPE_PREFIXES.contains(&data_type) {
        return Some(MessageAttributeRefusal::ParameterValue(format!(
            "The message attribute '{name}' has an invalid message attribute type, the \
             set of supported type prefixes is {}, {} and {}.",
            BINARY_DATA_TYPE, NUMBER_DATA_TYPE, STRING_DATA_TYPE
        )));
    }
    // A binary value belongs in the binary field and a textual one in the string field:
    // "Binary type attributes can store any binary data"
    // (`MessageAttributeValue$BinaryValue` doc), which no textual type carries.
    let (wanted_field, other_field_used) = if data_type == BINARY_DATA_TYPE {
        (BINARY_DATA_TYPE, value.string_value.is_some())
    } else {
        (STRING_DATA_TYPE, value.binary_value.is_some())
    };
    if other_field_used {
        return Some(MessageAttributeRefusal::ParameterValue(format!(
            "The message attribute '{name}' with type '{}' must use field \
             '{wanted_field}'.",
            value.data_type
        )));
    }
    // "Name, type, and value must not be empty or null" (`MessageAttributeValue` doc):
    // an attribute whose value field is absent, or present and empty, carries no value
    // at all — which is not the same request as one that carries no such attribute. The
    // sentence names the TYPE as well as the attribute, because the type is what decides
    // which field the value was looked for in.
    let empty = if data_type == BINARY_DATA_TYPE {
        value.binary_value.as_ref().is_none_or(Vec::is_empty)
    } else {
        value.string_value.as_deref().is_none_or(str::is_empty)
    };
    if empty {
        return Some(MessageAttributeRefusal::ParameterValue(format!(
            "The message attribute '{name}' must contain non-empty message attribute \
             value for message attribute type '{}'.",
            value.data_type
        )));
    }
    let text = value.string_value.as_deref().unwrap_or_default();
    if data_type != BINARY_DATA_TYPE {
        if let Some(found) = text.chars().find(|c| !is_attribute_value_character(*c)) {
            return Some(MessageAttributeRefusal::InvalidParameter(format!(
                "Invalid parameter: Invalid binary character '#x{:X}' was found in the \
                 message attribute '{name}' value, the set of allowed characters is #x9 \
                 | #xA | #xD | [#x20 to #xD7FF] | [#xE000 to #xFFFD]",
                found as u32
            )));
        }
    }
    if data_type == NUMBER_DATA_TYPE {
        return number_value_refusal(name, text).map(MessageAttributeRefusal::ParameterValue);
    }
    // Every other type carries TEXT, and `String.Array` is one of them: the service's
    // own label on the string type says what a matcher reads a value of it as ("a JSON
    // array of strings, numbers, true, false and null"), and the model puts no
    // constraint on the value itself (`smithy_query(query="shape",
    // shape="MessageAttributeValue")` reports a plain string `DataType` and a plain
    // string `StringValue`), so the value is opaque here: a labelled value SNS does not
    // read as a list is still carried verbatim to every subscriber, and the matching
    // reads it as the one text it is ([`super::filter_policy`]).
    None
}

/// The message a `Number` attribute whose value is not a number of the supported
/// precision and scale is refused with, or `None` when the value is one.
///
/// A value SNS cannot read as a number at all is refused for the CAST it could not make,
/// naming the attribute whose value it was and nothing else: the value is the caller's
/// own and the sentence does not echo it back. The two BOUNDS are refused by sentences
/// that do name the value in brackets, beside the bound it crossed — the precision in
/// digits, the scale in powers of ten — because there the value is a number and what the
/// publisher has to change is its size. The two bounds are independent: the PRECISION
/// is how many significant digits the value carries ("a number can have up to 38 digits of
/// precision"), and the SCALE is which power of ten its magnitude stands at, so a value can
/// cross either without crossing the other.
fn number_value_refusal(name: &str, text: &str) -> Option<String> {
    let Some(number) = DecimalNumber::read(text) else {
        return Some(format!(
            "Could not cast message attribute '{name}' value to number."
        ));
    };
    if number.precision > MAX_NUMBER_PRECISION {
        return Some(format!(
            "Message attribute '{name}' number value [{text}] must have less than \
             {MAX_NUMBER_PRECISION} precision digits."
        ));
    }
    // The SCALE is the power of ten the value's magnitude stands at — the exponent of
    // its leading significant digit, however the caller spelled the value — and the two
    // documented powers span it HALF OPEN: a value at the smaller power is one the type
    // holds, and the larger power is the first magnitude it does not. Zero stands at no
    // power of ten, so no bound excludes it.
    let in_scale = number
        .exponent
        .is_none_or(|exponent| (MIN_NUMBER_EXPONENT..MAX_NUMBER_EXPONENT).contains(&exponent));
    (!in_scale).then(|| {
        format!(
            "Message attribute '{name}' number value [{text}] scale must be \
             10^{MIN_NUMBER_EXPONENT} and 10^{MAX_NUMBER_EXPONENT}."
        )
    })
}

/// A decimal number as a `Number` attribute spells it, read for the properties SNS
/// bounds: how many significant digits it carries and which power of ten it stands at.
struct DecimalNumber {
    /// The significant digits of the value — its digits with the leading zeros dropped,
    /// which stand for no precision.
    precision: usize,
    /// The power of ten the value's leading significant digit stands at, so the value is
    /// at least that power and less than the next one up — `None` for a value of zero,
    /// which stands at no power of ten at all.
    exponent: Option<i32>,
}

impl DecimalNumber {
    /// Read `text` as a decimal number: an optional sign, digits with at most one
    /// decimal point, and an optional power-of-ten suffix — or `None` when the text
    /// names no number.
    fn read(text: &str) -> Option<Self> {
        let body = text.strip_prefix(['+', '-']).unwrap_or(text);
        let (mantissa, suffix) = match body.split_once(['e', 'E']) {
            Some((mantissa, suffix)) => {
                let digits = suffix.strip_prefix(['+', '-']).unwrap_or(suffix);
                if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                (mantissa, suffix.parse::<i32>().ok()?)
            }
            None => (body, 0),
        };
        let (whole, fraction) = match mantissa.split_once('.') {
            Some((whole, fraction)) => (whole, fraction),
            None => (mantissa, ""),
        };
        if whole.is_empty() && fraction.is_empty() {
            return None;
        }
        if !whole.chars().chain(fraction.chars()).all(|c| c.is_ascii_digit()) {
            return None;
        }
        let digits: String = format!("{whole}{fraction}");
        let significant = digits.trim_start_matches('0');
        // Where the leading significant digit stands: the digits before the point, less
        // the leading zeros that stand for no magnitude, less one for the digit itself —
        // and then moved by the power-of-ten suffix. Read this way, a value's exponent
        // is a property of the NUMBER rather than of its spelling, so `5e-1`, `0.5` and
        // `.5` all stand at the same power.
        let leading_zeros = digits.len() - significant.len();
        let exponent = if significant.is_empty() {
            None
        } else {
            Some(
                i32::try_from(whole.len())
                    .ok()?
                    .checked_sub(i32::try_from(leading_zeros).ok()?)?
                    .checked_sub(1)?
                    .checked_add(suffix)?,
            )
        };
        Some(Self {
            // A leading zero carries no precision, whichever side of the point it falls
            // on: `0.5` and `5` are both written to one digit, and `0.00` to none.
            precision: significant.len(),
            exponent,
        })
    }
}
