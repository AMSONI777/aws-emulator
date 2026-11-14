// SPDX-License-Identifier: CC0-1.0

//! The default domain PREFIX a branch carries, which is the `displayName` every reader of
//! that branch reports.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` over a restJson1
//! request signed for the `amplify` signing name — so what is asserted is what an AWS SDK
//! client would see.
//!
//! The rule under test, over a TABLE spanning the class it generalises over rather than
//! over one recorded request: `Branch$displayName` "is used as the default domain prefix"
//! (`smithy_query(query="doc",shape="Branch",member="displayName")`), and a domain prefix
//! is a host label, written in letters, digits and the hyphen. So a `CreateBranch` that
//! names no `displayName` derives it from the branch name drawn into that alphabet: every
//! character of the name outside it becomes a hyphen, and a name already drawn from it is
//! its own prefix. The derivation substitutes characters and nothing else. A request that
//! names a `displayName` decides it instead, and whichever way the value was settled it is
//! what `CreateBranch`, `GetBranch` and `ListBranches` all report.

use serde_json::{json, Value};

use crate::app_branch_lifecycle::{list_member, string_member, Emulator};

/// `BranchName`'s modelled maximum length
/// (`smithy_query(query="operation",operation="CreateBranch")`: `branchName`
/// `length 1..255`), so a request may name a branch 255 characters long and the prefix
/// derived from it is as long.
const BRANCH_NAME_MAX: usize = 255;

/// One `CreateBranch` request and the `displayName` the rule says its branch carries.
struct PrefixCase {
    case: &'static str,
    branch_name: String,
    /// The `displayName` the request names, or `None` for a request that names none —
    /// the only form the derivation applies to.
    requested: Option<&'static str>,
    expected: String,
}

/// The table: one row per shape a branch name takes, spanning each symbol a branch name
/// admits beside letters and digits (`/`, `_`, `.`, `-` — the set AWS states in the
/// refusal of a name outside it), several of them at once, a name of only digits, a name
/// in mixed case, a name at the modelled length maximum, and a request that names its own
/// display name.
fn prefix_cases() -> Vec<PrefixCase> {
    let longest_name = {
        let mut name = "a/".repeat(BRANCH_NAME_MAX / 2);
        name.push('a');
        name
    };
    let longest_prefix = {
        let mut prefix = "a-".repeat(BRANCH_NAME_MAX / 2);
        prefix.push('a');
        prefix
    };
    vec![
        PrefixCase {
            case: "a name that is already a host label",
            branch_name: "main".to_string(),
            requested: None,
            expected: "main".to_string(),
        },
        PrefixCase {
            case: "a name carrying a path separator",
            branch_name: "feature/a".to_string(),
            requested: None,
            expected: "feature-a".to_string(),
        },
        PrefixCase {
            case: "a name of several path segments",
            branch_name: "team/area/topic".to_string(),
            requested: None,
            expected: "team-area-topic".to_string(),
        },
        PrefixCase {
            case: "a name carrying an underscore",
            branch_name: "feature_b".to_string(),
            requested: None,
            expected: "feature-b".to_string(),
        },
        PrefixCase {
            case: "a name carrying a dot",
            branch_name: "release.2".to_string(),
            requested: None,
            expected: "release-2".to_string(),
        },
        PrefixCase {
            case: "a name carrying every symbol a branch name admits",
            branch_name: "rel/v1_0.x-y".to_string(),
            requested: None,
            expected: "rel-v1-0-x-y".to_string(),
        },
        PrefixCase {
            case: "a name whose only punctuation is already a hyphen",
            branch_name: "Main-Two".to_string(),
            requested: None,
            expected: "Main-Two".to_string(),
        },
        PrefixCase {
            case: "a name of digits only",
            branch_name: "123".to_string(),
            requested: None,
            expected: "123".to_string(),
        },
        PrefixCase {
            case: "a name at the modelled length maximum",
            branch_name: longest_name,
            requested: None,
            expected: longest_prefix,
        },
        PrefixCase {
            case: "a request that names its own display name",
            branch_name: "feature/d".to_string(),
            requested: Some("chosen-label"),
            expected: "chosen-label".to_string(),
        },
    ]
}

/// A branch name as it reaches the service in a request PATH.
///
/// `branchName` is an `@httpLabel` of `GET /apps/{appId}/branches/{branchName}`, which a
/// client percent-encodes; of the characters a branch name admits only the path separator
/// is not an unreserved URI character, so that is the one that is written encoded.
fn in_a_path(branch_name: &str) -> String {
    branch_name.replace('/', "%2F")
}

/// Is `candidate` drawn from the ALPHABET of a host label — the characters a default
/// domain prefix has to be written in?
///
/// A label carries letters, digits and the hyphen and nothing else, which is why a branch
/// name's other punctuation cannot survive into the prefix. The derivation substitutes
/// characters and nothing else, so this is what it guarantees: the name's length and its
/// own hyphens reach the prefix as written.
fn is_in_a_label_alphabet(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

#[tokio::test]
async fn a_branch_created_without_a_display_name_carries_its_name_as_one_host_label() {
    let emulator = Emulator::new();
    let app_id = emulator.app_id_of_new_app("domain-prefix-app").await;

    for row in prefix_cases() {
        let mut request = json!({ "branchName": row.branch_name });
        if let Some(requested) = row.requested {
            request["displayName"] = Value::String(requested.to_string());
        }
        let created = emulator.create_branch(&app_id, &request).await;
        assert_eq!(
            created.status, 200,
            "case {:?}: expected HTTP 200 from CreateBranch, got {created:?}",
            row.case
        );
        let written = created.member("branch");
        assert_eq!(
            string_member(&written, "displayName"),
            row.expected,
            "case {:?}: expected displayName {:?}, got {written:?}",
            row.case,
            row.expected
        );

        // The value is PERSISTED, not just answered: the branch reads back with it.
        let read = emulator
            .get_branch(&app_id, &in_a_path(&row.branch_name))
            .await
            .member("branch");
        assert_eq!(
            string_member(&read, "displayName"),
            row.expected,
            "case {:?}: GetBranch must report the same prefix, got {read:?}",
            row.case
        );
        assert_eq!(
            string_member(&read, "branchName"),
            row.branch_name,
            "case {:?}: the branch keeps the name the request sent, got {read:?}",
            row.case
        );
        assert!(
            is_in_a_label_alphabet(&string_member(&read, "displayName")),
            "case {:?}: a domain prefix must be written in a host label's alphabet, \
             got {read:?}",
            row.case
        );

        // And the list reader reports the same prefix as the single read.
        let listed = emulator.list_branches(&app_id, "").await;
        let element = list_member(&listed.body, "branches")
            .iter()
            .find(|branch| string_member(branch, "branchName") == row.branch_name)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "case {:?}: ListBranches must list the created branch, got {listed:?}",
                    row.case
                )
            });
        assert_eq!(
            string_member(&element, "displayName"),
            row.expected,
            "case {:?}: ListBranches must report the same prefix, got {element:?}",
            row.case
        );
    }
}
