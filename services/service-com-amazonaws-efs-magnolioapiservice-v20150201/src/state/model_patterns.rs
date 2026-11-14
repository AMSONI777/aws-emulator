// SPDX-License-Identifier: CC0-1.0

//! The modelled `@pattern` constraints this service has to apply itself, and the
//! `ValidationException` clauses a violation of one is refused with.
//!
//! RULE: every modelled constraint on an input member is enforced BEFORE the operation
//! reads or writes anything, and a violation is refused with HTTP 400
//! `ValidationException` carrying AWS's validation sentence — whichever side of the
//! request boundary measured the value.
//!
//! The walk in front of every handler enforces `@length`, `@range`, `@enum` and most
//! `@pattern` constraints already, including the ones on members nested inside an input
//! structure. It compiles a `@pattern` with the `regex` crate, which has no look-around,
//! and treats an expression it CANNOT compile as matching every value — so a member whose
//! modelled expression carries a negative look-ahead reaches a handler unchecked. Two of
//! this service's string shapes are written that way:
//!
//! * `Path` ([`ROOT_DIRECTORY_PATH_PATTERN`]), the root directory an access point
//!   exposes: the look-ahead is what makes the path absolute and bounds it at four
//!   subdirectories;
//! * `TagKey` ([`TAG_KEY_PATTERN`]), every tag key this service stores: the look-ahead is
//!   what excludes the namespace AWS keeps for its own tags, and the character class is
//!   the rest of the expression.
//!
//! The expressions are EVALUATED here, by an engine that supports the look-around they are
//! written with, so the rule applied and the constraint a refusal reports cannot drift
//! from the model. Nothing else about the refusal is restated: the clause, the member path
//! and the envelope are the framework's own ([`Violation`], [`path`], [`envelope`]), so a
//! caller cannot tell a refusal measured here from one measured at the boundary.

use ::aws_smithy_schema_server::constraints::{envelope, path, Violation, ViolationKind};

use crate::ops::types::{RootDirectory, Tag};

/// `RootDirectory$Path`'s modelled expression, as the model writes it — the one a refusal
/// REPORTS.
///
/// SOURCE: `smithy_query(query="shape",shape="Path")` — `@length 1..100` (enforced at the
/// boundary) and this `@pattern`. Its `(?!\.)` look-ahead is why the boundary cannot
/// compile it.
const ROOT_DIRECTORY_PATH_PATTERN: &str = r"^(\/|(\/(?!\.)+[^$#<>;`|&?{}^*/\n]+){1,4})$";

/// `TagKey`'s modelled expression, as the model writes it — the one a refusal REPORTS.
///
/// SOURCE: `smithy_query(query="shape",shape="TagKey")` — `@length 1..128` (enforced at
/// the boundary) and this `@pattern`. Its leading `(?![aA]{1}[wW]{1}[sS]{1}:)` look-ahead
/// is why the boundary cannot compile it.
const TAG_KEY_PATTERN: &str = r"^(?![aA]{1}[wW]{1}[sS]{1}:)([\p{L}\p{Z}\p{N}_.:/=+\-@]+)$";

/// [`ROOT_DIRECTORY_PATH_PATTERN`] as it is EVALUATED: the model's expression with the `+`
/// that REPEATS its zero-width look-ahead dropped.
///
/// A look-ahead consumes nothing and is decided at a single position, so one or more of
/// them succeed exactly when the first does — the two expressions accept the same strings
/// — while a regex engine declines to repeat a zero-width target at all. Only the
/// repetition is dropped; every other character, the look-ahead included, is the model's.
const ROOT_DIRECTORY_PATH_EXPRESSION: &str = r"^(\/|(\/(?!\.)[^$#<>;`|&?{}^*/\n]+){1,4})$";

/// The most clauses one refusal built here carries, and the most violations collected to
/// build it.
///
/// A clause is collected per ill-formed ELEMENT of a caller-supplied list, and neither
/// list this module scans is modelled with a `@length` bound on the collection — so the
/// element count is the caller's, and with no ceiling here one request body would be
/// echoed back as a response sized by it, many times over. The collectors below stop
/// pulling elements at this count and [`constraint_refusal`] truncates to it, so the
/// request is refused all the same and both the memory and the message are bounded by a
/// constant. The framework's own accumulating walk stops at the same count, for the same
/// reason, so a refusal measured here is no larger than one measured at the boundary.
const MAX_VIOLATIONS: usize = 100;

/// The member names the paths below are spelled from, as the model declares them.
const ROOT_DIRECTORY_MEMBER: &str = "RootDirectory";
/// See [`ROOT_DIRECTORY_MEMBER`].
const PATH_MEMBER: &str = "Path";
/// See [`ROOT_DIRECTORY_MEMBER`].
const TAGS_MEMBER: &str = "Tags";
/// See [`ROOT_DIRECTORY_MEMBER`].
const KEY_MEMBER: &str = "Key";
/// See [`ROOT_DIRECTORY_MEMBER`].
const TAG_KEYS_MEMBER: &str = "TagKeys";

/// Whether `value` satisfies `RootDirectory$Path`'s modelled expression.
fn root_directory_path_is_well_formed(value: &str) -> bool {
    static COMPILED: ::std::sync::OnceLock<::fancy_regex::Regex> = ::std::sync::OnceLock::new();
    matches(&COMPILED, ROOT_DIRECTORY_PATH_EXPRESSION, value)
}

/// Whether `value` satisfies `TagKey`'s modelled expression.
fn tag_key_is_well_formed(value: &str) -> bool {
    static COMPILED: ::std::sync::OnceLock<::fancy_regex::Regex> = ::std::sync::OnceLock::new();
    matches(&COMPILED, TAG_KEY_PATTERN, value)
}

/// Whether `value` satisfies `expression`, compiling it once into `slot`.
///
/// A match ERROR (the engine's backtrack limit) is read as "does not match": both members
/// are bounded by a `@length` maximum the boundary already enforced (100 and 128
/// characters), so no value that reaches here can approach that limit, and refusing a
/// value the service cannot prove legal is the side that never stores an unvalidated one.
///
/// `expect` is right on the compilation: every expression passed here is a constant of
/// this module, so a failure to compile is a fault in this file rather than anything a
/// request can provoke.
fn matches(
    slot: &'static ::std::sync::OnceLock<::fancy_regex::Regex>,
    expression: &'static str,
    value: &str,
) -> bool {
    slot.get_or_init(|| {
        ::fancy_regex::Regex::new(expression).expect("a modelled @pattern of this module compiles")
    })
    .is_match(value)
    .unwrap_or(false)
}

/// One `@pattern` violation, as the framework's own walk records one: the member path, the
/// expression the value had to satisfy, and the value the caller submitted.
///
/// The echo is bounded by the member's own `@length` maximum, which the boundary enforced
/// before this ran, so a refusal cannot be grown by the request.
fn pattern_violation(member_path: String, value: &str, pattern: &str) -> Violation {
    Violation {
        path: member_path,
        kind: ViolationKind::Pattern(pattern.to_string()),
        value: Some(value.to_string()),
        sensitive: false,
    }
}

/// Every `@pattern` violation a caller-supplied `RootDirectory` carries, at the path the
/// framework's walk spells for it (`rootDirectory.path`).
///
/// A request that names no `RootDirectory`, or one that names no `Path`, breaks no pattern
/// — the member is absent, which is a different rule (and the documented "when specifying
/// a RootDirectory, you must provide the Path" is the operation's own `BadRequest`).
pub fn root_directory_violations(root_directory: Option<&RootDirectory>) -> Vec<Violation> {
    let Some(path_value) = root_directory.and_then(|requested| requested.path.as_deref()) else {
        return Vec::new();
    };
    if root_directory_path_is_well_formed(path_value) {
        return Vec::new();
    }
    vec![pattern_violation(
        path::join(&[
            path::member(ROOT_DIRECTORY_MEMBER),
            path::member(PATH_MEMBER),
        ]),
        path_value,
        ROOT_DIRECTORY_PATH_PATTERN,
    )]
}

/// Every `@pattern` violation among the KEYS of a caller-supplied `Tags` list, at the
/// paths the framework's walk spells for a list element's member
/// (`tags.<1-based position>.member.key`).
///
/// A tag VALUE's expression carries no look-around, so the boundary enforces it already
/// and nothing is re-checked here.
///
/// At most [`MAX_VIOLATIONS`] clauses are collected, and the scan stops with them: the
/// element count is the caller's, so neither the walk nor the message it builds may be
/// sized by the request.
pub fn tag_violations(tags: &[Tag]) -> Vec<Violation> {
    tags.iter()
        .enumerate()
        .filter(|(_, tag)| !tag_key_is_well_formed(&tag.key))
        .take(MAX_VIOLATIONS)
        .map(|(index, tag)| {
            pattern_violation(
                path::join(&[
                    path::member(TAGS_MEMBER),
                    path::element(index + 1),
                    path::member(KEY_MEMBER),
                ]),
                &tag.key,
                TAG_KEY_PATTERN,
            )
        })
        .collect()
}

/// Every `@pattern` violation in a caller-supplied `TagKeys` list, at the paths the
/// framework's walk spells for a list element (`tagKeys.<1-based position>.member`).
///
/// Bounded by [`MAX_VIOLATIONS`], for the reason [`tag_violations`] states.
pub fn tag_key_list_violations(tag_keys: &[String]) -> Vec<Violation> {
    tag_keys
        .iter()
        .enumerate()
        .filter(|(_, key)| !tag_key_is_well_formed(key))
        .take(MAX_VIOLATIONS)
        .map(|(index, key)| {
            pattern_violation(
                path::join(&[path::member(TAG_KEYS_MEMBER), path::element(index + 1)]),
                key,
                TAG_KEY_PATTERN,
            )
        })
        .collect()
}

/// The `ValidationException` sentence for `violations`, or `None` when the request broke
/// none of the constraints this module applies.
///
/// The envelope is the framework's own, so one refusal cannot be told from the other:
/// `1 validation error detected: <clause>`, or
/// `N validation errors detected: <clause>; <clause>`.
///
/// At most [`MAX_VIOLATIONS`] clauses are worded, whatever the caller sent and whatever an
/// operation collected across several members, so the sentence is bounded by a constant
/// rather than by the request.
pub fn constraint_refusal(violations: &[Violation]) -> Option<String> {
    let carried = violations.len().min(MAX_VIOLATIONS);
    envelope(&violations[..carried])
}
