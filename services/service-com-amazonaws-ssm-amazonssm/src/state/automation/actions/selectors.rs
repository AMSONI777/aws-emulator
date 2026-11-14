// SPDX-License-Identifier: CC0-1.0

//! The values a step's declared `outputs` take out of what its action answered.
//!
//! A step of an Automation runbook declares what it produces as `outputs`, each entry a
//! `Name`, a `Selector` and a `Type` ([`super::super::runbook::StepOutput`]): the selector
//! names ONE place in the document the action answered, and the type says what the value
//! there is read as. What those selectors pick out is what `StepExecution$Outputs` reports,
//! what the rest of the runbook references as `{{ <step>.<Name> }}`, and what the document's
//! own `outputs` project ([`super::super::AutomationExecutionRecord::projected_outputs`]).
//!
//! Both actions a host run performs select the same way, so the selection is written once
//! here: the only difference is the document it is applied to — the API's own answer for an
//! `aws:executeAwsApi` step, and the handler's return value under `Payload` for an
//! `aws:executeScript` step.
//!
//! The selector is caller-supplied text, so it is evaluated by the ONE bounded reference-path
//! evaluation this workspace has (`service_common::json_reference_path`): a path that names a
//! single place, of bounded length and depth, rather than a query language in which a
//! selector could ask for the whole document many times over. A selector that names nothing
//! in the answer, and a value that is not of the type the step declared, FAIL the step —
//! nothing is reported for a value the action did not produce.

use ::std::collections::BTreeMap;

use ::serde_json::Value;

use super::super::runbook::{
    StepOutput, OUTPUT_TYPE_BOOLEAN, OUTPUT_TYPE_INTEGER, OUTPUT_TYPE_MAP_LIST,
    OUTPUT_TYPE_STRING, OUTPUT_TYPE_STRING_LIST, OUTPUT_TYPE_STRING_MAP,
};

/// Every output `declared` selects out of `answer`, or why one of them selects nothing the
/// step may report.
///
/// `AutomationParameterMap` carries a LIST of values per output, so a list-typed output is
/// reported as its own elements and a single value as a list of one — which is how a
/// document-level output of a list comes back as a list and one of a scalar as `[value]`.
pub fn selected(
    answer: &Value,
    declared: &[StepOutput],
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut selected: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for output in declared {
        let Some(value) =
            ::service_common::json_reference_path::select(&output.selector, answer)
        else {
            return Err(format!(
                "The output {} of this step selects {}, which the action's answer holds no value \
                 at",
                output.name, output.selector
            ));
        };
        selected.insert(output.name.clone(), read_as(output, value)?);
    }
    Ok(selected)
}

/// The value at an output's selector, read as the type the step declared for it.
///
/// A step declares the type so that what it produced is a value of that type: a selector
/// pointing at a list where the step declared `String`, or at text where it declared
/// `Integer`, is a step that did not produce what it said it would, so it fails rather than
/// reporting the value under a type it is not.
fn read_as(output: &StepOutput, value: &Value) -> Result<Vec<String>, String> {
    let mistyped = |what: &str| {
        Err(format!(
            "The output {} of this step is declared {} and the action answered {what} at {}",
            output.name, output.output_type, output.selector
        ))
    };
    match output.output_type.as_str() {
        OUTPUT_TYPE_INTEGER => match value {
            Value::Number(number) if number.is_i64() || number.is_u64() => {
                Ok(vec![number.to_string()])
            }
            // A JSON protocol carries a number as a number, and a runtime that answered one
            // as text still answered an integer — it is read as the integer it is.
            Value::String(text) if text.parse::<i64>().is_ok() => Ok(vec![text.clone()]),
            _ => mistyped("no integer"),
        },
        OUTPUT_TYPE_BOOLEAN => match value {
            Value::Bool(held) => Ok(vec![held.to_string()]),
            Value::String(text) if text.parse::<bool>().is_ok() => Ok(vec![text.clone()]),
            _ => mistyped("no boolean"),
        },
        OUTPUT_TYPE_STRING_LIST => match value.as_array() {
            Some(items) => Ok(items.iter().map(rendered).collect()),
            None => mistyped("no list"),
        },
        OUTPUT_TYPE_MAP_LIST => match value.as_array() {
            Some(items) if items.iter().all(Value::is_object) => {
                Ok(items.iter().map(rendered).collect())
            }
            _ => mistyped("no list of mappings"),
        },
        OUTPUT_TYPE_STRING_MAP => match value {
            Value::Object(_) => Ok(vec![rendered(value)]),
            _ => mistyped("no mapping"),
        },
        // `String` and an output whose content declares no type at all: the value is read as
        // the one text it is. A list or a mapping is NOT one text, so it is a mistyped
        // output rather than a value rendered as its own JSON.
        OUTPUT_TYPE_STRING | "" => match value {
            Value::Array(_) | Value::Object(_) => mistyped("no single value"),
            _ => Ok(vec![rendered(value)]),
        },
        // A type no runbook output is declared with names nothing to read the value as, so
        // the step declared an output this emulator cannot report.
        other => Err(format!(
            "The output {} of this step is declared {other}, which is not one of the types a \
             runbook's outputs declare",
            output.name
        )),
    }
}

/// One selected value as `AutomationParameterMap` carries it: a map of string to LIST OF
/// STRING, so a text value is its own text and anything else is the JSON it is.
fn rendered(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One declared output, for the table below.
    fn output(name: &str, selector: &str, output_type: &str) -> StepOutput {
        StepOutput {
            name: name.to_string(),
            selector: selector.to_string(),
            output_type: output_type.to_string(),
        }
    }

    /// A declared output is read as the type it declares, over one row per type a runbook's
    /// outputs may declare.
    #[test]
    fn an_output_is_read_as_the_type_the_step_declared() {
        let answer = ::serde_json::json!({
            "Payload": {
                "text": "ready",
                "count": 7,
                "flag": true,
                "items": ["a", "b"],
                "mapping": {"k": "v"},
                "rows": [{"k": "v"}, {"k": "w"}],
                "nothing": null,
            }
        });
        // (case, the declared output, the values it must select)
        let rows = vec![
            (
                "a text value",
                output("value", "$.Payload.text", OUTPUT_TYPE_STRING),
                vec!["ready".to_string()],
            ),
            (
                "an output declaring no type at all",
                output("value", "$.Payload.text", ""),
                vec!["ready".to_string()],
            ),
            (
                "a whole number",
                output("count", "$.Payload.count", OUTPUT_TYPE_INTEGER),
                vec!["7".to_string()],
            ),
            (
                "a boolean",
                output("flag", "$.Payload.flag", OUTPUT_TYPE_BOOLEAN),
                vec!["true".to_string()],
            ),
            (
                "a list of text",
                output("items", "$.Payload.items", OUTPUT_TYPE_STRING_LIST),
                vec!["a".to_string(), "b".to_string()],
            ),
            (
                "one mapping",
                output("mapping", "$.Payload.mapping", OUTPUT_TYPE_STRING_MAP),
                vec![r#"{"k":"v"}"#.to_string()],
            ),
            (
                "a list of mappings",
                output("rows", "$.Payload.rows", OUTPUT_TYPE_MAP_LIST),
                vec![r#"{"k":"v"}"#.to_string(), r#"{"k":"w"}"#.to_string()],
            ),
            (
                "a text value the answer carries as null",
                output("nothing", "$.Payload.nothing", OUTPUT_TYPE_STRING),
                vec![String::new()],
            ),
        ];

        for (case, declared, expected) in rows {
            let name = declared.name.clone();
            let selected = selected(&answer, &[declared])
                .unwrap_or_else(|why| panic!("case {case:?}: expected a selection, got {why:?}"));
            assert_eq!(
                selected.get(&name),
                Some(&expected),
                "case {case:?}: expected {expected:?}, got {selected:?}"
            );
        }
    }

    /// A selector naming nothing, and a value that is not of the declared type, are both
    /// failures of the step rather than an output reported for something the action did not
    /// produce.
    #[test]
    fn a_selection_the_answer_does_not_hold_fails_the_step() {
        let answer = ::serde_json::json!({"Payload": {"text": "ready", "items": ["a"]}});
        // (case, the declared output)
        let rows = vec![
            (
                "a selector the answer holds no value at",
                output("value", "$.Payload.absent", OUTPUT_TYPE_STRING),
            ),
            (
                "a list where the step declared one text value",
                output("value", "$.Payload.items", OUTPUT_TYPE_STRING),
            ),
            (
                "text where the step declared an integer",
                output("count", "$.Payload.text", OUTPUT_TYPE_INTEGER),
            ),
            (
                "text where the step declared a boolean",
                output("flag", "$.Payload.text", OUTPUT_TYPE_BOOLEAN),
            ),
            (
                "text where the step declared a list",
                output("items", "$.Payload.text", OUTPUT_TYPE_STRING_LIST),
            ),
            (
                "a list of text where the step declared a list of mappings",
                output("rows", "$.Payload.items", OUTPUT_TYPE_MAP_LIST),
            ),
            (
                "text where the step declared a mapping",
                output("mapping", "$.Payload.text", OUTPUT_TYPE_STRING_MAP),
            ),
            (
                "a type no runbook output declares",
                output("value", "$.Payload.text", "Decimal"),
            ),
        ];

        for (case, declared) in rows {
            let outcome = selected(&answer, &[declared]);
            assert!(
                outcome.is_err(),
                "case {case:?}: expected the selection to fail the step, got {outcome:?}"
            );
        }
    }
}
