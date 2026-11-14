// SPDX-License-Identifier: CC0-1.0

//! The TEXT `ApprovalRuleNameAlreadyExistsException` carries, over the wire.
//!
//! The rule under test: the message of this code is a CONSTANT. The exception's own
//! documentation states the rule it reports — "An approval rule with that name
//! already exists. Approval rule names must be unique within the scope of a pull
//! request."
//! (`smithy_query(query="shape",shape="ApprovalRuleNameAlreadyExistsException")`) —
//! and the sentence names nothing from the request: not the rule name the caller
//! asked for, not the pull request, not the repository. So the table varies exactly
//! what the rule generalises over — the name's shape over the 1- and 100-character
//! bounds of `ApprovalRuleName` (`smithy_query(query="shape",
//! shape="ApprovalRuleName")`: `len 1..100`, no pattern), the content the losing
//! request carries, and whether the name is held by a rule created on the pull
//! request or by one a template applied to it — and asserts the same constant on
//! every row.
//!
//! The sibling suite `pull_request_approval_rules.rs` owns which CODE each of those
//! requests raises and what the stored pull request holds afterwards; this one owns
//! the words.

use serde_json::json;

use crate::harness::error_with_message;
use crate::repository_lifecycle::{base64, emulator, ok, string_at};

/// The HTTP status the code models (`errorKind: client`, `httpError: 400`).
const CLIENT_ERROR_STATUS: u16 = 400;

/// The one sentence this code carries, whatever the request asked for.
const EXPECTED: &str = "An approval rule already exists with that name. Approval rule names must \
                        be unique within the scope of a pull request.";

/// The approval rule template a row's name may be held by, so the table covers a
/// name a TEMPLATE put on the pull request as well as one a create put there.
const TEMPLATE: &str = "review-by-template";

/// A valid approval rule document, as compact JSON text: the structure the
/// CodeCommit User Guide documents for approval rule content.
fn document(approvals: u32) -> String {
    serde_json::to_string(&json!({
        "Version": "2018-11-08",
        "Statements": [{
            "Type": "Approvers",
            "NumberOfApprovalsNeeded": approvals,
        }],
    }))
    .expect("the document serializes")
}

/// Rule names spanning what `ApprovalRuleName` allows: the 1-character minimum, the
/// 100-character maximum, and names mixing digits, dots, hyphens, underscores and
/// non-ASCII letters — none of them the name the issue cited.
fn rule_names() -> Vec<String> {
    vec![
        "r".to_string(),
        "x".repeat(100),
        "rule-with-hyphens".to_string(),
        "rule_with_underscores".to_string(),
        "Rule.With.Dots".to_string(),
        "MiXeD-Case_9.9".to_string(),
        "revisión-obligatoria".to_string(),
    ]
}

#[tokio::test]
async fn the_duplicate_approval_rule_name_message_is_a_constant() {
    let router = emulator();

    // One repository with two diverged branches, one approval rule template
    // associated with it, and one open pull request on them.
    ok(
        &router,
        "CreateApprovalRuleTemplate",
        &json!({
            "approvalRuleTemplateName": TEMPLATE,
            "approvalRuleTemplateContent": document(1),
        }),
    )
    .await;
    ok(
        &router,
        "CreateRepository",
        &json!({ "repositoryName": "rule-name-conflict" }),
    )
    .await;
    ok(
        &router,
        "AssociateApprovalRuleTemplateWithRepository",
        &json!({
            "approvalRuleTemplateName": TEMPLATE,
            "repositoryName": "rule-name-conflict",
        }),
    )
    .await;
    let destination = ok(
        &router,
        "PutFile",
        &json!({
            "repositoryName": "rule-name-conflict",
            "branchName": "main",
            "filePath": "README.md",
            "fileContent": base64(b"alpha\n"),
        }),
    )
    .await;
    let main_commit = string_at(&destination, "/commitId");
    ok(
        &router,
        "CreateBranch",
        &json!({
            "repositoryName": "rule-name-conflict",
            "branchName": "feature",
            "commitId": main_commit,
        }),
    )
    .await;
    ok(
        &router,
        "PutFile",
        &json!({
            "repositoryName": "rule-name-conflict",
            "branchName": "feature",
            "filePath": "README.md",
            "fileContent": base64(b"alpha\nbeta\n"),
            "parentCommitId": main_commit,
        }),
    )
    .await;
    let created = ok(
        &router,
        "CreatePullRequest",
        &json!({
            "title": "a change to review",
            "targets": [{
                "repositoryName": "rule-name-conflict",
                "sourceReference": "feature",
                "destinationReference": "main",
            }],
            "clientRequestToken": crate::wire::fresh_client_request_token(),
        }),
    )
    .await;
    let pull_request_id = string_at(&created, "/pullRequest/pullRequestId");

    // Every row: a name the pull request already holds a rule under, and a losing
    // create of that same name carrying DIFFERENT content, so the refusal cannot be
    // read as byte-identical-request idempotence.
    let mut cases: Vec<(String, String)> = Vec::new();
    for name in rule_names() {
        ok(
            &router,
            "CreatePullRequestApprovalRule",
            &json!({
                "pullRequestId": pull_request_id,
                "approvalRuleName": name,
                "approvalRuleContent": document(1),
            }),
        )
        .await;
        cases.push((format!("a rule created on the pull request: {name:?}"), name));
    }
    // The name a TEMPLATE put on the pull request, which the create path refuses in
    // the same terms.
    cases.push((
        "a rule a template applied".to_string(),
        TEMPLATE.to_string(),
    ));

    for (why, name) in &cases {
        let (code, message) = error_with_message(
            &router,
            "CreatePullRequestApprovalRule",
            &json!({
                "pullRequestId": pull_request_id,
                "approvalRuleName": name,
                "approvalRuleContent": document(2),
            }),
            CLIENT_ERROR_STATUS,
        )
        .await;
        assert_eq!(
            code, "ApprovalRuleNameAlreadyExistsException",
            "case {why}: expected code ApprovalRuleNameAlreadyExistsException, got {code:?} \
             saying {message:?}"
        );
        assert_eq!(
            message, EXPECTED,
            "case {why}: expected message {EXPECTED:?}, got {message:?}"
        );
    }

    // A differently-named rule is still created without conflict, and the pull
    // request holds exactly one rule per name.
    ok(
        &router,
        "CreatePullRequestApprovalRule",
        &json!({
            "pullRequestId": pull_request_id,
            "approvalRuleName": "a-name-nothing-holds",
            "approvalRuleContent": document(1),
        }),
    )
    .await;
    let read = ok(
        &router,
        "GetPullRequest",
        &json!({ "pullRequestId": pull_request_id }),
    )
    .await;
    let rules = read
        .pointer("/pullRequest/approvalRules")
        .and_then(|rules| rules.as_array())
        .cloned()
        .unwrap_or_default();
    for (why, name) in &cases {
        let held = rules
            .iter()
            .filter(|rule| rule.get("approvalRuleName").and_then(|n| n.as_str()) == Some(name))
            .count();
        assert_eq!(
            held, 1,
            "case {why}: the pull request must hold exactly one rule of that name, got {read}"
        );
    }
}
