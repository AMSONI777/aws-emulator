// SPDX-License-Identifier: CC0-1.0

//! The sentence a Clean Rooms analysis-template lookup answers with when the identifier
//! names no template of the membership in the path.
//!
//! The rule under test: a refusal for an analysis template addressed under a membership
//! states the resource class, the identifier that resolved to nothing and the membership
//! the lookup was scoped to — `No analysis template found with id <analysisTemplateIdentifier>
//! for membership <membershipIdentifier>` — with the two variable parts taken verbatim
//! from the request path and nothing after the membership identifier. It is the same
//! sentence frame this service states a missing privacy budget template in, and it is one
//! sentence for the whole class, so every operation that addresses a stored analysis
//! template by identifier (`GetAnalysisTemplate`, `DeleteAnalysisTemplate`) answers it
//! identically.
//!
//! The table's rows differ along what the rule generalises over: which operation
//! addresses the template, the FORM of the identifier (ids nothing ever minted, an id
//! that was minted and then deleted, an id that names a template of ANOTHER membership)
//! and which membership the request addresses it through — so the recorded
//! repeat-delete case is one row among many. Requests go over the wire through the same
//! `MultiServiceRouter` the production router uses.

use serde_json::{json, Value};

use super::cleanrooms_analysis_templates::{
    create_analysis_template, get_analysis_template, membership_id,
};
use super::cleanrooms_collaboration_lifecycle::{error_code, error_message, Emulator};

/// Identifiers in the model's `AnalysisTemplateIdentifier` form (`len 36..36`, pattern
/// `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`) that no create in
/// this suite mints.
const NEVER_MINTED_IDS: [&str; 4] = [
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "0123456f-89ab-cdef-0123-456789abcdef",
    "deadbeef-0000-4000-8000-000000000001",
];

/// The fixed text of the refusal: everything that is not one of the two identifiers the
/// request carried.
const MESSAGE_HEAD: &str = "No analysis template found with id ";
const MESSAGE_JOIN: &str = " for membership ";

/// The refusal an analysis-template lookup answers with for `template` addressed through
/// `membership`. Shared with the deletion suite, so both assert ONE sentence.
pub(crate) fn expected_not_found_message(template: &str, membership: &str) -> String {
    format!("{MESSAGE_HEAD}{template}{MESSAGE_JOIN}{membership}")
}

/// `DELETE /memberships/{membershipIdentifier}/analysistemplates/{analysisTemplateIdentifier}`.
async fn delete_analysis_template(
    emulator: &Emulator,
    membership: &str,
    template: &str,
) -> (u16, Value) {
    emulator
        .call(
            "DELETE",
            &format!("/memberships/{membership}/analysistemplates/{template}"),
            None,
        )
        .await
}

/// A template under `membership`, answering its id.
async fn template_id(emulator: &Emulator, membership: &str, name: &str) -> String {
    let (status, created) = create_analysis_template(
        emulator,
        membership,
        json!({
            "name": name,
            "format": "SQL",
            "source": { "text": format!("SELECT id FROM {name}") },
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "setup {name:?}: expected CreateAnalysisTemplate 200, got {status} with {created}"
    );
    created["analysisTemplate"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("setup {name:?}: no analysisTemplate.id in {created}"))
        .to_string()
}

/// Both operations that address a stored analysis template by identifier, so each row of
/// the table is asserted on every one of them.
const ADDRESSING_OPERATIONS: [&str; 2] = ["GetAnalysisTemplate", "DeleteAnalysisTemplate"];

async fn address_template(
    emulator: &Emulator,
    operation: &str,
    membership: &str,
    template: &str,
) -> (u16, Value) {
    match operation {
        "GetAnalysisTemplate" => get_analysis_template(emulator, membership, template).await,
        "DeleteAnalysisTemplate" => delete_analysis_template(emulator, membership, template).await,
        other => panic!("no such addressing operation: {other}"),
    }
}

#[tokio::test]
async fn analysis_template_not_found_refusals_state_the_requested_id_and_membership() {
    let emulator = Emulator::new();
    let membership = membership_id(&emulator, "atnf-message-collab").await;
    let other_membership = membership_id(&emulator, "atnf-message-collab-other").await;

    // A template this test keeps reading back, one that belongs to the OTHER membership,
    // and one that is minted here and then deleted.
    let kept = template_id(&emulator, &membership, "kept").await;
    let elsewhere = template_id(&emulator, &other_membership, "elsewhere").await;
    let deleted = template_id(&emulator, &membership, "deleted").await;
    let (status, body) = delete_analysis_template(&emulator, &membership, &deleted).await;
    assert_eq!(
        status, 204,
        "setup: expected the first DeleteAnalysisTemplate 204, got {status} with {body}"
    );

    // (row label, the membership the request addresses, the identifier it addresses).
    let mut rows: Vec<(String, String, String)> = NEVER_MINTED_IDS
        .iter()
        .map(|id| {
            (
                format!("never minted {id}"),
                membership.clone(),
                id.to_string(),
            )
        })
        .collect();
    rows.push((
        "minted then deleted".to_string(),
        membership.clone(),
        deleted.clone(),
    ));
    // The same identifier through each membership: the refusal names the membership of
    // the REQUEST, not the one that stores the template.
    rows.push((
        "held by another membership".to_string(),
        membership.clone(),
        elsewhere.clone(),
    ));
    rows.push((
        "this membership's template addressed through the other one".to_string(),
        other_membership.clone(),
        kept.clone(),
    ));

    for (row, addressed_membership, template) in &rows {
        for operation in ADDRESSING_OPERATIONS {
            let case = format!("{row} via {operation}");
            let (status, refused) =
                address_template(&emulator, operation, addressed_membership, template).await;
            assert_eq!(
                status, 404,
                "case {case:?}: expected 404, got {status} with {refused}"
            );
            assert_eq!(
                error_code(&refused),
                "ResourceNotFoundException",
                "case {case:?}: expected ResourceNotFoundException, got {refused}"
            );

            let message = error_message(&refused);
            let expected = expected_not_found_message(template, addressed_membership);
            assert_eq!(
                message, expected,
                "case {case:?}: expected {expected:?}, got {message:?}"
            );
            // The two variable parts are the request's, in the frame's order, and the
            // sentence ends with the membership identifier.
            assert!(
                message.starts_with(MESSAGE_HEAD),
                "case {case:?}: expected the sentence to open with {MESSAGE_HEAD:?}, got {message:?}"
            );
            assert_eq!(
                message.matches(MESSAGE_JOIN).count(),
                1,
                "case {case:?}: expected exactly one {MESSAGE_JOIN:?} between the two identifiers, got {message:?}"
            );
            assert!(
                message.ends_with(addressed_membership.as_str()),
                "case {case:?}: expected the sentence to end with the requested membership {addressed_membership:?}, got {message:?}"
            );

            assert_eq!(
                refused["resourceId"].as_str(),
                Some(template.as_str()),
                "case {case:?}: expected the requested id as resourceId, got {:?}",
                refused.get("resourceId")
            );
            assert_eq!(
                refused["resourceType"].as_str(),
                Some("ANALYSIS_TEMPLATE"),
                "case {case:?}: expected resourceType ANALYSIS_TEMPLATE, got {:?}",
                refused.get("resourceType")
            );
        }
    }

    // Every row refused, and nothing the test created (and did not delete itself) moved:
    // each template still reads back through the membership that holds it.
    for (membership_of, template) in [(&membership, &kept), (&other_membership, &elsewhere)] {
        let (status, fetched) = get_analysis_template(&emulator, membership_of, template).await;
        assert_eq!(
            status, 200,
            "the template {template} must survive every refusal, got {status} with {fetched}"
        );
    }
}

#[tokio::test]
async fn an_unknown_membership_is_refused_about_the_membership_not_the_template() {
    let emulator = Emulator::new();
    let membership = membership_id(&emulator, "atnf-unknown-membership-collab").await;
    let kept = template_id(&emulator, &membership, "kept").await;

    for unknown in NEVER_MINTED_IDS {
        for operation in ADDRESSING_OPERATIONS {
            let case = format!("unknown membership {unknown} via {operation}");
            let (status, refused) = address_template(&emulator, operation, unknown, &kept).await;
            assert_eq!(
                status, 404,
                "case {case:?}: expected 404, got {status} with {refused}"
            );
            let message = error_message(&refused);
            assert!(
                !message.starts_with(MESSAGE_HEAD),
                "case {case:?}: a membership that holds nothing is not an analysis-template refusal, got {message:?}"
            );
            assert_eq!(
                refused["resourceType"].as_str(),
                Some("MEMBERSHIP"),
                "case {case:?}: expected resourceType MEMBERSHIP, got {:?}",
                refused.get("resourceType")
            );
        }
    }

    let (status, fetched) = get_analysis_template(&emulator, &membership, &kept).await;
    assert_eq!(
        status, 200,
        "the template must survive every refusal, got {status} with {fetched}"
    );
}
