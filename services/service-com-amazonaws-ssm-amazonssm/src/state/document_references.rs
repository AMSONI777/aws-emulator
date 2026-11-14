// SPDX-License-Identifier: CC0-1.0

//! The `{{ Name }}` REFERENCES an SSM document's content carries, and resolving them
//! against the values a call supplied.
//!
//! Every document of this service carries its parameters this way — an Automation runbook's
//! step inputs ([`super::automation::runbook`]) and a command document's script
//! ([`super::guest_execution`]) alike — so the scan and the substitution live HERE, once:
//! two readers of one reference form cannot disagree about what a reference is, where it
//! ends, or how much the substitution may grow.
//!
//! The references are read out of caller-supplied content, so the scan is the `regex`
//! crate's rather than a hand-rolled one, and it cannot nest (a reference holds no brace).
//! The expansion is MEASURED before it is built: a reference is some seven bytes of content
//! and the value it resolves to may be thousands, so what the substitution would produce is
//! accumulated reference by reference and checked against the caller's budget FIRST —
//! nothing larger than that budget is ever allocated.

use std::collections::BTreeMap;

/// The reference form a document's content carries a parameter in: `{{ Name }}`, with any
/// amount of space inside the braces.
///
/// One regular expression, compiled once for the process.
pub static REFERENCE: ::std::sync::LazyLock<::regex::Regex> = ::std::sync::LazyLock::new(|| {
    ::regex::Regex::new(r"\{\{\s*([^{}]+?)\s*\}\}").expect("the reference form is a valid regex")
});

/// The parameter `text` is ONE whole reference to, and nothing else (`{{ commands }}`), or
/// `None` when it carries anything more than that one reference.
///
/// What tells a content value that NAMES a parameter from one that merely mentions it: the
/// first resolves to that parameter's value as it is — a list stays a list — and the second
/// is a text the reference is substituted inside.
pub fn whole_reference(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    let captured = REFERENCE.captures(trimmed)?;
    let whole = captured.get(0)?;
    if whole.as_str() != trimmed {
        return None;
    }
    // A reference whose braces hold nothing but space names no parameter.
    captured
        .get(1)
        .map(|name| name.as_str().trim())
        .filter(|name| !name.is_empty())
}

/// Why a text's references could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceProblem {
    /// The FIRST name the caller holds no value for.
    Unresolved(String),
    /// The substitution would have produced more than the budget left.
    OverBudget,
}

/// `text` with every reference in it replaced by what `value_of` answers for that name, or
/// the first name it answers nothing for — or the budget the substitution would have run
/// over, in which case the budget is spent so a later call cannot attempt its own
/// full-size expansion either.
///
/// `budget` is the bytes the result may come to, and it is charged what the result holds:
/// one budget therefore spans as many texts as a caller resolves against it.
pub fn resolved_text(
    text: &str,
    value_of: &dyn Fn(&str) -> Option<String>,
    budget: &mut usize,
) -> Result<String, ReferenceProblem> {
    let mut projected = text.len();
    if projected > *budget {
        *budget = 0;
        return Err(ReferenceProblem::OverBudget);
    }
    for captured in REFERENCE.captures_iter(text) {
        let reference = captured.get(0).map_or(0, |reference| reference.len());
        let name = captured.get(1).map_or("", |name| name.as_str());
        let Some(held) = value_of(name) else {
            return Err(ReferenceProblem::Unresolved(name.to_string()));
        };
        projected = projected
            .saturating_sub(reference)
            .saturating_add(held.len());
        if projected > *budget {
            *budget = 0;
            return Err(ReferenceProblem::OverBudget);
        }
    }
    // Every reference resolves and the whole substitution fits in what is left of the
    // budget, which is what this builds.
    let resolved = REFERENCE.replace_all(text, |captured: &::regex::Captures<'_>| {
        let name = captured.get(1).map_or("", |name| name.as_str());
        value_of(name).unwrap_or_default()
    });
    *budget = budget.saturating_sub(resolved.len());
    Ok(resolved.into_owned())
}

/// [`resolved_text`] for a caller whose values are plain strings, which is the common case.
pub fn resolved_from_map(
    text: &str,
    values: &BTreeMap<String, String>,
    budget: &mut usize,
) -> Result<String, ReferenceProblem> {
    resolved_text(text, &|name| values.get(name).cloned(), budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RULE: a value that is ONE reference and nothing else NAMES the parameter; anything
    /// carrying more than that one reference does not.
    #[test]
    fn a_whole_reference_is_the_value_that_is_one_reference_and_nothing_else() {
        // (case, the content value, the name it names)
        let rows: &[(&str, &str, Option<&str>)] = &[
            ("one reference", "{{ commands }}", Some("commands")),
            ("no space inside the braces", "{{commands}}", Some("commands")),
            ("space around the value", "  {{ commands }}  ", Some("commands")),
            ("a reference inside text", "echo {{ commands }}", None),
            ("two references", "{{ one }}{{ two }}", None),
            ("no reference at all", "echo hello", None),
            ("an empty reference", "{{  }}", None),
        ];
        for (case, value, expected) in rows {
            let named = whole_reference(value);
            assert_eq!(
                named, *expected,
                "case {case:?}: expected {expected:?} from {value:?}, got {named:?}"
            );
        }
    }

    /// RULE: the substitution is charged against the caller's budget, and a text whose
    /// resolution would run past it produces nothing and spends the budget.
    #[test]
    fn the_substitution_is_measured_against_the_budget_before_it_is_built() {
        let values = BTreeMap::from([("name".to_string(), "x".repeat(64))]);
        // (case, the budget, whether the text resolves)
        let rows: &[(&str, usize, bool)] = &[
            ("a budget the result fits in", 128, true),
            ("a budget the result runs over", 32, false),
        ];
        for (case, ceiling, resolves) in rows {
            let mut budget = *ceiling;
            let answered = resolved_from_map("echo {{ name }}", &values, &mut budget);
            assert_eq!(
                answered.is_ok(),
                *resolves,
                "case {case:?}: expected resolved == {resolves}, got {answered:?}"
            );
            if !*resolves {
                assert_eq!(
                    budget, 0,
                    "case {case:?}: a text that ran over the budget spends it, got {budget}"
                );
            }
        }
    }

    /// RULE: the first name the caller holds no value for is what a resolution answers with.
    #[test]
    fn an_unresolved_reference_names_the_parameter_it_could_not_resolve() {
        let values = BTreeMap::from([("held".to_string(), "value".to_string())]);
        let mut budget = 1_024;
        let answered = resolved_from_map("{{ held }} {{ missing }}", &values, &mut budget);
        assert_eq!(
            answered,
            Err(ReferenceProblem::Unresolved("missing".to_string())),
            "expected the unresolved name, got {answered:?}"
        );
    }
}
