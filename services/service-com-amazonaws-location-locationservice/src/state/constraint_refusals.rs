// SPDX-License-Identifier: CC0-1.0

//! How this service words a request the framework refused before any handler ran.
//!
//! A modelled constraint is checked at the request boundary, so a value outside
//! one never reaches a handler and the refusal is worded here instead. Amazon
//! Location states such a refusal as one sentence about the member that failed —
//! the member as the model spells it, in single quotes, then what it had to
//! satisfy — the same shape as the sentence
//! [`super::documented_value_set_refusal`] words for a member this service checks
//! itself. The generic constraint-validator clause ("1 validation error detected:
//! Value '…' at '…' failed to satisfy constraint: …") is not this service's
//! wording, and it echoes the rejected value, which this service does not.
//!
//! Only the PATTERN violation is reworded. It is the one whose sentence this
//! service's refusals are known to word for themselves; every other violation
//! kind keeps the framework's default clause rather than being given a sentence
//! this API has not been observed to state.

use aws_smithy_schema_server::constraints::{Violation, ViolationKind};
use smithy_server_runtime::{Refusal, Refused};

/// The error code every refusal of a bad member value carries: this service's own
/// `ValidationException` shape, which every operation of this model declares.
pub const VALIDATION_EXCEPTION_CODE: &str = "ValidationException";

/// The sentence a member whose value is outside the pattern its model declares is
/// refused with: the member name in single quotes, the fixed phrase, then the
/// pattern exactly as the model writes it.
///
/// `member` is the modelled member name and `pattern` the regular expression from
/// the model; the value the request sent is never echoed.
pub fn pattern_refusal(member: &str, pattern: &str) -> String {
    format!("'{member}' must match regex {pattern}")
}

/// The member name as the MODEL spells it, from the dotted path a violation
/// carries.
///
/// A violation path is lowerCamel (`fileName`) while this model spells every
/// member in UpperCamel (`FileName`), so each segment's first letter is raised; a
/// segment that does not start with a lowercase letter — a collection index, a map
/// key — is left exactly as the walk wrote it.
pub fn modelled_member_name(path: &str) -> String {
    path.split('.')
        .map(|segment| {
            let mut characters = segment.chars();
            match characters.next() {
                Some(first) if first.is_ascii_lowercase() => {
                    first.to_ascii_uppercase().to_string() + characters.as_str()
                }
                _ => segment.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The sentence this service words for one violation, or `None` for a violation
/// kind it states no sentence of its own for.
fn sentence_for(violation: &Violation) -> Option<String> {
    match &violation.kind {
        ViolationKind::Pattern(pattern) => Some(pattern_refusal(
            &modelled_member_name(&violation.path),
            pattern,
        )),
        _ => None,
    }
}

/// How this service states `refusal`, or `None` to keep the framework's own
/// wording.
///
/// One sentence names ONE member, so a refusal carrying several violations keeps
/// the framework's clause rather than being collapsed into a sentence that would
/// name only one of them.
pub fn refused_constraint(refusal: &Refusal) -> Option<Refused> {
    let Refusal::Invalid(violations) = refusal else {
        return None;
    };
    let [violation] = violations.as_slice() else {
        return None;
    };
    Some(Refused {
        code: VALIDATION_EXCEPTION_CODE.to_string(),
        message: sentence_for(violation)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RULE: a violation's lowerCamel path names the member the way the model
    /// spells it. The rows span what the raising generalises over: a one-word
    /// member, a multi-word one, a nested path, a path through a collection index,
    /// and a segment that is already upper case.
    #[test]
    fn a_violation_path_names_the_modelled_member() {
        let rows: [(&str, &str); 5] = [
            ("key", "Key"),
            ("fileName", "FileName"),
            ("configuration.style", "Configuration.Style"),
            ("updates.1.member.deviceId", "Updates.1.Member.DeviceId"),
            ("FileName", "FileName"),
        ];
        for (path, expected) in rows {
            let named = modelled_member_name(path);
            assert_eq!(
                named, expected,
                "case {path:?}: expected {expected:?}, got {named:?}"
            );
        }
    }

    /// RULE: only a pattern violation takes this service's sentence; every other
    /// kind keeps the framework's clause, and so does a refusal naming several
    /// members at once.
    #[test]
    fn only_a_single_pattern_violation_is_reworded() {
        let pattern = Violation {
            path: "fileName".to_string(),
            kind: ViolationKind::Pattern(r"^sprites(@2x)?\.(png|json)$".to_string()),
            value: Some("unknown.png".to_string()),
            sensitive: false,
        };
        let chosen = refused_constraint(&Refusal::Invalid(vec![pattern.clone()]));
        assert_eq!(
            chosen,
            Some(Refused {
                code: VALIDATION_EXCEPTION_CODE.to_string(),
                message: r"'FileName' must match regex ^sprites(@2x)?\.(png|json)$".to_string(),
            }),
            "case \"one pattern violation\": expected this service's sentence, got {chosen:?}"
        );

        let missing = Violation {
            path: "mapName".to_string(),
            kind: ViolationKind::MissingRequiredMember,
            value: None,
            sensitive: false,
        };
        for (case, refusal) in [
            ("another violation kind", Refusal::Invalid(vec![missing.clone()])),
            (
                "several members at once",
                Refusal::Invalid(vec![pattern, missing]),
            ),
            ("an unauthenticated caller", Refusal::Unauthenticated),
        ] {
            let chosen = refused_constraint(&refusal);
            assert_eq!(
                chosen, None,
                "case {case:?}: expected the framework's own wording, got {chosen:?}"
            );
        }
    }
}
