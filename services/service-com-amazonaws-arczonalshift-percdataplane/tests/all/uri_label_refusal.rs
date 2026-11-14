// SPDX-License-Identifier: CC0-1.0

//! A constraint violation on a member this service reads from a URI LABEL, over every
//! operation whose input shape binds one.
//!
//! The rule: a member of the operation's own input shape — which is what a `@httpLabel`
//! member always is — is refused 400 `ValidationException` whose clause states that
//! member's POSITION ALONE (`Value at '<member>'`), so the refusal carries nothing of
//! the value the caller put in the path. It holds for every operation that takes such a
//! member and for every constraint class the member's target declares, because the
//! subject the clause states is a property of the member's position in the input shape
//! and not of the request. The sibling suites assert the same rule on the two shift-id
//! operations (`refusal_disclosure.rs`, `refusal_message_rules.rs`); this one spans the
//! label-bound members of the WHOLE service — the third operation that takes a shift id
//! and the four that take a resource identifier — and both constraint classes those two
//! targets declare.
//!
//! Every binding and constraint below is the model's
//! (`smithy_query(query="digest")` for the URIs, and `smithy_query(query="shape",
//! shape="ZonalShiftId,ResourceIdentifier,CancelPracticeRunRequest,\
//! DeletePracticeRunConfigurationRequest,GetManagedResourceRequest,\
//! UpdatePracticeRunConfigurationRequest,UpdateZonalAutoshiftConfigurationRequest")`
//! for the targets): `ZonalShiftId` is `@length` 6..36 with `@pattern`
//! `^[A-Za-z0-9-]+$`, `ResourceIdentifier` is `@length` 8..1024 with no pattern.

use super::zonal_shift_lifecycle::{call, emulator, encoded, error_code};

/// `ZonalShiftId`'s `@pattern` as a refusal reports it: the expression without the
/// anchors that make the match total.
const ZONAL_SHIFT_ID_PATTERN: &str = "[A-Za-z0-9-]+";

/// The prefix of an ARN-shaped `resourceIdentifier`, so a row varies only the length of
/// the identifier it carries.
const ARN_PREFIX: &str = "arn:aws:eks:us-east-1:111111111111:cluster/";

/// One operation's binding of a member to a URI label: the request that puts a value in
/// that label.
struct Binding {
    /// The operation the row drives, named in every assertion.
    operation: &'static str,
    method: &'static str,
    /// The path the label is appended to.
    prefix: &'static str,
    /// A body satisfying this operation's OTHER required members, so the label is the
    /// row's only violation and the envelope stays singular.
    body: &'static str,
}

impl Binding {
    const fn new(
        operation: &'static str,
        method: &'static str,
        prefix: &'static str,
        body: &'static str,
    ) -> Self {
        Self {
            operation,
            method,
            prefix,
            body,
        }
    }
}

/// One value a label can carry and the requirement a clause words about it.
struct Case {
    /// What the value is a case of, named in every assertion.
    class: &'static str,
    value: String,
    /// The requirement half of the clause, as the framework words this constraint class.
    requirement: String,
}

impl Case {
    fn new(class: &'static str, value: String, requirement: &str) -> Self {
        Self {
            class,
            value,
            requirement: requirement.to_string(),
        }
    }
}

/// The operations that bind `zonalShiftId` to a URI label. `CancelPracticeRun` is the
/// one no other suite drives.
fn shift_id_bindings() -> Vec<Binding> {
    vec![
        Binding::new("CancelZonalShift", "DELETE", "/zonalshifts/", ""),
        Binding::new("UpdateZonalShift", "PATCH", "/zonalshifts/", "{}"),
        Binding::new("CancelPracticeRun", "DELETE", "/practiceruns/", ""),
    ]
}

/// The operations that bind `resourceIdentifier` to a URI label.
fn resource_identifier_bindings() -> Vec<Binding> {
    vec![
        Binding::new("GetManagedResource", "GET", "/managedresources/", ""),
        Binding::new(
            "DeletePracticeRunConfiguration",
            "DELETE",
            "/configuration/",
            "",
        ),
        Binding::new(
            "UpdatePracticeRunConfiguration",
            "PATCH",
            "/configuration/",
            "{}",
        ),
        Binding::new(
            "UpdateZonalAutoshiftConfiguration",
            "PUT",
            "/managedresources/",
            r#"{"zonalAutoshiftStatus":"ENABLED"}"#,
        ),
    ]
}

/// Values a `zonalShiftId` label can carry that break exactly ONE of its target's
/// constraints. The pattern rows sit inside `@length` 6..36 and differ in the character
/// the expression rejects and in their length; the length rows are inside the pattern
/// and sit one past each published bound.
fn shift_id_violations() -> Vec<Case> {
    let pattern =
        format!("Member must satisfy regular expression pattern: {ZONAL_SHIFT_ID_PATTERN}");
    vec![
        Case::new("an underscore", "bad_id_1".to_string(), &pattern),
        Case::new("underscores throughout", "UNDER_SCORE_ID".to_string(), &pattern),
        Case::new("dots", "dots.and.dots".to_string(), &pattern),
        Case::new("a tilde", "tilde~shift".to_string(), &pattern),
        Case::new("a star", "star*shift".to_string(), &pattern),
        Case::new(
            "one character below the minimum length",
            "a".repeat(5),
            "Member must have length greater than or equal to 6",
        ),
        Case::new(
            "one character above the maximum length",
            "a".repeat(37),
            "Member must have length less than or equal to 36",
        ),
    ]
}

/// The same for a `resourceIdentifier` label, whose target declares a `@length` bound
/// only: one value past each published end.
fn resource_identifier_violations() -> Vec<Case> {
    vec![
        Case::new(
            "one character below the minimum length",
            "a".repeat(7),
            "Member must have length greater than or equal to 8",
        ),
        Case::new(
            "one character above the maximum length",
            format!("{ARN_PREFIX}{}", "a".repeat(1025 - ARN_PREFIX.len())),
            "Member must have length less than or equal to 1024",
        ),
    ]
}

/// The message of a refusal, with its status and code checked first.
async fn refused(
    router: &smithy_server_runtime::MultiServiceRouter,
    case: &str,
    binding: &Binding,
    uri: &str,
) -> String {
    let (status, body) = call(router, binding.method, uri, binding.body).await;
    assert_eq!(
        status, 400,
        "case {case:?}: a constraint violation is refused 400, got {status} {body}"
    );
    assert_eq!(
        error_code(&body),
        "ValidationException",
        "case {case:?}: expected ValidationException, got {body}"
    );
    let rendered = body.to_string();
    body["message"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: the refusal states a message, got {rendered}"))
        .to_string()
}

/// Every refused value of a label-bound member, over every operation that takes it: the
/// clause names the member's position and states no value at all.
async fn each_refusal_states_the_position_alone(
    member: &str,
    bindings: &[Binding],
    violations: &[Case],
) {
    let (router, _engine) = emulator();
    for binding in bindings {
        for case in violations {
            let name = format!("{}/{member} with {}", binding.operation, case.class);
            let expected = format!(
                "1 validation error detected: Value at '{member}' failed to satisfy \
                 constraint: {}",
                case.requirement
            );
            let uri = format!("{}{}", binding.prefix, encoded(&case.value));
            let message = refused(&router, &name, binding, &uri).await;
            assert_eq!(
                message, expected,
                "case {name:?}: expected {expected:?}, got {message:?}"
            );
            assert!(
                !message.contains("Value '"),
                "case {name:?}: the clause states no value at all, got {message:?}"
            );
            assert!(
                !message.contains(case.value.as_str()),
                "case {name:?}: the refusal must not echo the submitted value {:?}, \
                 got {message:?}",
                case.value
            );
        }
    }
}

#[tokio::test]
async fn a_shift_id_label_is_refused_by_position_alone() {
    each_refusal_states_the_position_alone(
        "zonalShiftId",
        &shift_id_bindings(),
        &shift_id_violations(),
    )
    .await;
}

#[tokio::test]
async fn a_resource_identifier_label_is_refused_by_position_alone() {
    each_refusal_states_the_position_alone(
        "resourceIdentifier",
        &resource_identifier_bindings(),
        &resource_identifier_violations(),
    )
    .await;
}

/// The other side of the rule: each published bound of each label-bound member, from the
/// INSIDE, is not a constraint violation at all — so the refusals above are computed
/// from the constraint and not from the shape of the request. What each operation then
/// answers (a read, a denial, a conflict, or the 501 of an operation this slice leaves
/// scaffolded) is not this suite's business; that it is not a `ValidationException` is.
#[tokio::test]
async fn a_label_value_inside_its_bound_is_not_a_constraint_violation() {
    let shift_ids = [
        ("at the minimum length", "a".repeat(6)),
        ("at the maximum length", "a".repeat(36)),
        (
            "with a hyphen the pattern admits",
            "zs-0000001234".to_string(),
        ),
    ];
    let resource_identifiers = [
        ("at the minimum length", "abcdefgh".to_string()),
        (
            "at the maximum length",
            format!("{ARN_PREFIX}{}", "a".repeat(1024 - ARN_PREFIX.len())),
        ),
    ];
    each_accepted_label_is_not_a_validation_error(&shift_id_bindings(), &shift_ids).await;
    each_accepted_label_is_not_a_validation_error(
        &resource_identifier_bindings(),
        &resource_identifiers,
    )
    .await;
}

/// Each value, over each operation that takes the label it fills, answered with anything
/// but a `ValidationException`.
async fn each_accepted_label_is_not_a_validation_error(
    bindings: &[Binding],
    values: &[(&str, String)],
) {
    let (router, _engine) = emulator();
    for binding in bindings {
        for (class, value) in values {
            let name = format!("{} with a label {class}", binding.operation);
            let uri = format!("{}{}", binding.prefix, encoded(value));
            let (status, body) = call(&router, binding.method, &uri, binding.body).await;
            assert_ne!(
                error_code(&body),
                "ValidationException",
                "case {name:?}: a label inside its bound is no validation error, \
                 got {status} {body}"
            );
        }
    }
}
