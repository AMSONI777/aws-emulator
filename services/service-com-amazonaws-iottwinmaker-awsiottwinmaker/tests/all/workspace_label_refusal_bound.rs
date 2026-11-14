// SPDX-License-Identifier: CC0-1.0

//! Whether the refusal a workspace LABEL earns fits the member it travels on,
//! end to end over HTTP.
//!
//! RULE under test: a reason this service states for a workspace it does not
//! hold is rendered within the 2048 characters the modelled `ErrorMessage`
//! admits, whatever the label the request addressed the workspace by —
//! whichever shape that label targets and however wide that shape is. A reason
//! that fits is reported exactly as the service words it; one that would
//! overrun is reported at the bound, keeping its leading text and its trailing
//! clause.
//!
//! `GetWorkspace` is the operation whose `workspaceId` label targets `IdOrArn`
//! (`@length(1..2048)`, from
//! `smithy_query(query="shape",shape="IdOrArn")`) rather than `Id`
//! (`@length(1..128)`), so it is the one label of this service's workspace paths
//! that is bounded as widely as the member the reason travels on — and the only
//! one that can overrun it on its own. Every other operation's workspace label
//! is an `Id`, whose reason always fits, and those rows pin that such a reason
//! is reported whole.
//!
//! `tests/all/error_message_bounds.rs` asserts the same rule where a
//! `componentPath` is what overruns the member and
//! `tests/all/unbounded_refusal_message_bounds.rs` where an ARN or a label the
//! model does not bound does; this suite covers the workspace label itself. The
//! bound and what the rule asserts about a reported reason come from the first
//! of those suites, so this crate states them once.
//!
//! The rows differ along what the rule generalises over: WHICH operation reports
//! the reason, WHICH shape its workspace label targets, the FORM of the label (a
//! bare id, the workspace ARN) and its SIZE — a label short enough for the
//! reason to fit, one whose reason lands exactly on the member's maximum, one
//! character past it, and the label's own modelled maximum.

use serde_json::json;

use crate::error_message_bounds::{assert_within_bound, ERROR_MESSAGE_MAX};
use crate::harness::{encode_label, workspace_arn, Emulator, Resp};
use crate::unbounded_refusal_message_bounds::{padded, sizes, workspace_not_found};

/// The greatest number of characters the modelled `IdOrArn` admits —
/// `@length(1..2048)`, from `smithy_query(query="shape",shape="IdOrArn")` — which
/// is what `GetWorkspace$workspaceId` targets.
const ID_OR_ARN_MAX: usize = 2048;

/// The greatest number of characters the modelled `Id` admits —
/// `@length(1..128)`, from `smithy_query(query="shape",shape="Id")` — which is
/// what every OTHER workspace label of this service targets.
const ID_MAX: usize = 128;

/// The shortest label a row drives: short enough that the reason built from it
/// fits whatever fixed text the reason adds.
const SHORT: usize = 16;

/// The message an error body carries.
fn message(response: &Resp) -> String {
    response
        .member("message")
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A bare workspace id of exactly `length` characters that this service holds no
/// workspace for.
///
/// Every character the modelled `IdOrArn` pattern admits for a bare id
/// (`^[a-zA-Z_0-9][a-zA-Z_\-0-9]*[a-zA-Z0-9]+$`), so the value a case sends is
/// one the boundary validator passes and the handler has to resolve.
fn unheld_workspace_id(length: usize) -> String {
    "a".repeat(length)
}

/// RULE over the ONE workspace label the model bounds as widely as the member the
/// reason travels on: `GetWorkspace` states its refusal within the 2048
/// characters the modelled `ErrorMessage` admits, whatever label the request
/// carried.
#[tokio::test]
async fn a_wide_workspace_label_refusal_fits_its_modelled_member() {
    let emulator = Emulator::new();
    // A workspace this Region's store DOES hold, so a row's refusal is about the
    // label it named and not about an empty store.
    assert_eq!(
        emulator.create_workspace("heldWorkspace").await.status,
        200,
        "CreateWorkspace: the held workspace must exist"
    );

    // The sizes come from the bound the reason travels on and from the label's
    // own modelled maximum (`crate::unbounded_refusal_message_bounds::sizes`),
    // so a row is a statement about the bound rather than a literal: a label
    // that fits, one whose reason lands exactly on the member's maximum, one
    // character past it, and the modelled `IdOrArn` maximum.
    let fixed = workspace_not_found("").chars().count();
    let mut labels: Vec<(String, String)> = sizes(fixed, SHORT, ID_OR_ARN_MAX)
        .into_iter()
        .map(|(case, size)| (format!("a bare id: {case}"), unheld_workspace_id(size)))
        .collect();
    // The other FORM the same label takes: the ARN `CreateWorkspace` minted,
    // which `IdOrArn` admits as its second alternative, at that same maximum.
    labels.push((
        "the ARN form, of the characters the modelled IdOrArn caps at".to_string(),
        padded(&workspace_arn("absentWorkspace"), ID_OR_ARN_MAX),
    ));

    for (case, label) in &labels {
        let refused = emulator.get_workspace(&encode_label(label)).await;
        assert_eq!(
            (refused.status, refused.error_type.as_deref()),
            (404, Some("ResourceNotFoundException")),
            "case {case:?}: expected a 404 ResourceNotFoundException, got {refused:?}"
        );
        assert_within_bound(
            case,
            &message(&refused),
            &workspace_not_found(label),
            ERROR_MESSAGE_MAX,
        );
    }

    // The held workspace is still served: the rows above refused a label, not
    // the operation.
    let read = emulator.get_workspace("heldWorkspace").await;
    assert_eq!(
        read.status, 200,
        "case \"the held workspace\": expected 200, got {read:?}"
    );
}

/// One operation whose `workspaceId` label targets the narrower modelled `Id`,
/// driven against a workspace this service does not hold.
async fn call_against_workspace(emulator: &Emulator, operation: &str, workspace_id: &str) -> Resp {
    match operation {
        "DeleteWorkspace" => emulator.delete_workspace(workspace_id).await,
        "GetEntity" => emulator.get_entity(workspace_id, "someEntity").await,
        "GetScene" => emulator.get_scene(workspace_id, "someScene").await,
        "ListEntities" => emulator.list_entities(workspace_id, json!({})).await,
        other => panic!("the table names no operation {other:?}"),
    }
}

/// RULE, on the other side of the same bound: a workspace label the model bounds
/// at 128 characters renders a reason that fits the member whatever its size, so
/// the refusal is reported whole — the bound cuts a reason, it does not shorten
/// one that fits.
#[tokio::test]
async fn a_narrow_workspace_label_refusal_is_reported_whole() {
    let emulator = Emulator::new();

    // (operation, status, error code) — the refusal the MODEL declares for that
    // operation: a read of a resource inside the workspace is a 404
    // `ResourceNotFoundException`, a listing under it a 400
    // `ValidationException`.
    let operations: [(&str, u16, &str); 4] = [
        ("DeleteWorkspace", 404, "ResourceNotFoundException"),
        ("GetEntity", 404, "ResourceNotFoundException"),
        ("GetScene", 404, "ResourceNotFoundException"),
        ("ListEntities", 400, "ValidationException"),
    ];

    let ids: [(&str, String); 3] = [
        ("shortest", "ab".to_string()),
        ("middling", unheld_workspace_id(64)),
        (
            "the characters the modelled Id caps at",
            unheld_workspace_id(ID_MAX),
        ),
    ];

    for (operation, status, code) in operations {
        for (id_case, workspace_id) in &ids {
            let case = format!("{operation} on {id_case}");
            let refused = call_against_workspace(&emulator, operation, workspace_id).await;
            assert_eq!(
                (refused.status, refused.error_type.as_deref()),
                (status, Some(code)),
                "case {case:?}: expected {status} {code}, got {refused:?}"
            );
            let whole = workspace_not_found(workspace_id);
            assert_eq!(
                message(&refused),
                whole,
                "case {case:?}: expected the reason whole, got {refused:?}"
            );
            assert_within_bound(&case, &message(&refused), &whole, ERROR_MESSAGE_MAX);
        }
    }
}
