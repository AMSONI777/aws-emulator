// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for `GetEnabledIpamPolicy`, with the two operations that write what it
//! reports (`EnableIpamPolicy`, `DisableIpamPolicy`), driven over `ec2Query` (README.md /
//! OPERATIONS.md "Wire protocol").
//!
//! The rules under test:
//!
//! * `GetEnabledIpamPolicy` REPORTS the account's enablement out of the store: whether a
//!   policy is enabled, which policy it is, and the entity that manages it — the account
//!   itself when the enablement names no Organizations target, and the delegated
//!   administrator for IPAM when it names one. An account that has enabled nothing is
//!   reported as having nothing enabled rather than refused, and the report writes nothing,
//!   so repeating it answers the same.
//! * The account has ONE enabled policy or none: enabling a second policy replaces the
//!   first, and disabling the enablement a request names leaves nothing enabled.
//! * An enablement is the PAIR of a policy and the target it was enabled for, so a disable
//!   naming another policy, or that policy with another target, is refused with
//!   `IncorrectState` and changes nothing.
//! * Both writers answer an id outside the form this service ISSUES with
//!   `InvalidIpamPolicyId.Malformed` before any lookup, a well-formed id the account holds no
//!   policy for with `InvalidIpamPolicyId.NotFound`, and `DryRun` with `DryRunOperation`
//!   while writing nothing; a policy whose deletion has been asked for can be enabled from no
//!   state, and its enablement goes with it.
//!
//! Each table row is a distinct input along what those rules generalise over: which kind of
//! Organizations target the enablement names (none, an organization, an organizational unit,
//! an account), which Region and which IPAM the policy belongs to, how many policies the
//! account holds beside it, and which part of an id is outside the issued form.

use std::time::Duration;

use ec2::ops::types::{IPAM_POLICY_MANAGED_BY_VALUES, IpamPolicy, Tag};
use ec2::state::{
    ComAmazonawsEc2Amazonec2State as Ec2State, IPAM_POLICY_ID_PREFIX,
    IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR, IPAM_POLICY_STATE_CREATE_COMPLETE,
    MANAGED_BY_ACCOUNT, TRANSITION_DELAY,
};
use service_com_amazonaws_ec2_amazonec2 as ec2;
use smithy_server_runtime::MultiServiceRouter;

use super::ec2_query::{call, element, error_code};

/// The Region every call here is signed for.
const REGION: &str = "us-east-1";

/// The HTTP status EC2 answers `DryRunOperation` with.
const DRY_RUN_STATUS: u16 = 412;

/// The IPAM the seeded policies belong to by default.
const IPAM_ID: &str = "ipam-0123456789abcdef0";

/// A well-formed `IpamPolicyId` in the long (17 hexadecimal digit) form that the account
/// holds no policy for: this store mints ids from a monotonic counter, so an id from the top
/// of the hexadecimal range cannot collide with one a seeded policy was given.
const UNKNOWN_POLICY_ID: &str = "ipam-policy-0ffffffffffffffff";

/// Long enough past [`TRANSITION_DELAY`] that a move the clock owes is certainly due.
fn past_the_transition() -> Duration {
    TRANSITION_DELAY + Duration::from_millis(250)
}

/// One call of `action` signed for the Region above.
async fn invoke(
    router: &MultiServiceRouter,
    action: &str,
    params: &[(String, String)],
) -> (u16, String) {
    call(router, REGION, action, params).await
}

/// The form fields a policy-naming request carries: the `IpamPolicyId`, the
/// `OrganizationTargetId` when one is named, plus `extra` fields.
fn policy_params(
    policy_id: &str,
    organization_target_id: Option<&str>,
    extra: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut params = vec![("IpamPolicyId".to_string(), policy_id.to_string())];
    if let Some(target) = organization_target_id {
        params.push(("OrganizationTargetId".to_string(), target.to_string()));
    }
    params.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string())),
    );
    params
}

/// Seed one IPAM policy in service, and answer the id this service minted for it. The
/// account holds no policy until something stores one, so every row starts by seeding the
/// policies it names.
fn seed_policy(
    engine: &engine::InMemoryEngine,
    ipam_id: &str,
    region: &str,
    tags: &[(&str, &str)],
) -> String {
    let store = engine.state::<Ec2State>();
    let mut guard = store.lock();
    let policy_id = guard
        .insert_ipam_policy(ec2::state::IpamPolicyRecord::in_state(
            IpamPolicy {
                ipam_id: Some(ipam_id.to_string()),
                ipam_policy_region: Some(region.to_string()),
                tags: Some(
                    tags.iter()
                        .map(|(key, value)| Tag {
                            key: Some((*key).to_string()),
                            value: Some((*value).to_string()),
                        })
                        .collect(),
                ),
                ..Default::default()
            },
            IPAM_POLICY_STATE_CREATE_COMPLETE,
        ))
        .expect("the store holds the seeded policy");
    assert!(
        policy_id.starts_with(&format!("{IPAM_POLICY_ID_PREFIX}-")),
        "the minted policy id {policy_id:?} must carry the issued prefix \
         {IPAM_POLICY_ID_PREFIX:?}"
    );
    policy_id
}

/// What the account's enablement is right now, read straight out of the store: the policy id
/// and the Organizations target it was enabled for.
fn stored_enablement(engine: &engine::InMemoryEngine) -> Option<(String, Option<String>)> {
    engine
        .state::<Ec2State>()
        .lock()
        .enabled_ipam_policy()
        .map(|record| {
            (
                record.ipam_policy_id.clone(),
                record.organization_target_id.clone(),
            )
        })
}

/// What one `GetEnabledIpamPolicy` call reported: the three members of its result.
#[derive(Debug, PartialEq, Eq)]
struct Reported {
    /// `IpamPolicyEnabled` as the response carries it.
    enabled: Option<String>,
    /// `IpamPolicyId` as the response carries it.
    policy_id: Option<String>,
    /// `ManagedBy` as the response carries it.
    managed_by: Option<String>,
}

/// Report the account's enabled policy, asserting the call itself succeeded.
async fn get_enabled(router: &MultiServiceRouter, case: &str) -> Reported {
    let (status, body) = invoke(router, "GetEnabledIpamPolicy", &[]).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from GetEnabledIpamPolicy, got {status} with body \
         {body}"
    );
    Reported {
        enabled: element(&body, "ipamPolicyEnabled"),
        policy_id: element(&body, "ipamPolicyId"),
        managed_by: element(&body, "managedBy"),
    }
}

/// One enablement to make: a distinct input along what the rules generalise over.
struct Row {
    /// What this row is called in a failure message.
    case: &'static str,
    /// The `OrganizationTargetId` the enable names, or `None` for the account itself.
    target: Option<&'static str>,
    /// The `ManagedBy` the report must answer for it.
    managed_by: &'static str,
    /// The IPAM the policy belongs to.
    ipam_id: &'static str,
    /// The Region the policy is in.
    region: &'static str,
    /// The tags assigned to it.
    tags: &'static [(&'static str, &'static str)],
}

/// The enablements the rules are asserted over: one the account made for itself and three a
/// delegated administrator made for different kinds of Organizations entity — an
/// organization, an organizational unit and a member account.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "enabled by the account for itself",
            target: None,
            managed_by: MANAGED_BY_ACCOUNT,
            ipam_id: IPAM_ID,
            region: REGION,
            tags: &[],
        },
        Row {
            case: "enabled for a whole organization",
            target: Some("o-abcde12345"),
            managed_by: IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR,
            ipam_id: IPAM_ID,
            region: "eu-west-2",
            tags: &[("Name", "public-ipv4")],
        },
        Row {
            case: "enabled for an organizational unit",
            target: Some("ou-abcd-11112222"),
            managed_by: IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR,
            ipam_id: "ipam-00000000000000abc",
            region: "ap-southeast-1",
            tags: &[("Name", "edge"), ("Team", "network")],
        },
        Row {
            case: "enabled for a single member account",
            target: Some("123456789012"),
            managed_by: IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR,
            ipam_id: IPAM_ID,
            region: "us-west-2",
            tags: &[("Env", "prod")],
        },
    ]
}

/// The `ManagedBy` words this suite asserts on are the model's own: each is a member of the
/// catalog the model publishes for `IpamPolicyManagedBy`, so a row cannot pin a word the API
/// does not have.
#[test]
fn the_asserted_managed_by_words_are_the_models_own() {
    for (case, word) in [
        ("an enablement the account made", MANAGED_BY_ACCOUNT),
        (
            "an enablement made for an Organizations target",
            IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR,
        ),
    ] {
        assert!(
            IPAM_POLICY_MANAGED_BY_VALUES.contains(&word),
            "case {case:?}: expected {word:?} to be a member of the modelled catalog, which \
             carries {IPAM_POLICY_MANAGED_BY_VALUES:?}"
        );
    }
}

/// An account that has enabled nothing is REPORTED as having nothing enabled — whether it
/// holds no policy at all or holds policies it has not enabled — rather than refused, and
/// the report writes nothing.
#[tokio::test]
async fn an_account_with_no_enabled_policy_is_reported_rather_than_refused() {
    for (case, policies) in [
        ("an account holding no policy at all", 0usize),
        ("an account holding one policy it has not enabled", 1),
        ("an account holding three policies it has not enabled", 3),
    ] {
        let (router, engine) = super::ec2_query::emulator();
        for _ in 0..policies {
            seed_policy(&engine, IPAM_ID, REGION, &[]);
        }

        let reported = get_enabled(&router, case).await;
        assert_eq!(
            reported,
            Reported {
                enabled: Some("false".to_string()),
                policy_id: None,
                managed_by: None,
            },
            "case {case:?}: expected nothing enabled and no policy or manager named, got \
             {reported:?}"
        );
        // A REPORT: reading it twice answers the same, and the store still holds no
        // enablement.
        let again = get_enabled(&router, case).await;
        assert_eq!(
            again, reported,
            "case {case:?}: a second report must answer the same, got {again:?}"
        );
        assert_eq!(
            stored_enablement(&engine),
            None,
            "case {case:?}: a report must not enable anything"
        );
    }
}

/// Enabling a policy is reported back by `GetEnabledIpamPolicy` — the policy's own id and the
/// entity the enablement names — and disabling that same enablement leaves nothing enabled.
#[tokio::test]
async fn an_enabled_policy_is_reported_until_it_is_disabled() {
    for row in rows() {
        let case = row.case;
        let (router, engine) = super::ec2_query::emulator();
        let policy_id = seed_policy(&engine, row.ipam_id, row.region, row.tags);
        // A control policy the account holds beside the one it enables, so each enablement
        // is checked to name only the policy the request did.
        let control_id = seed_policy(&engine, IPAM_ID, REGION, &[("Name", "control")]);

        let (status, body) = invoke(
            &router,
            "EnableIpamPolicy",
            &policy_params(&policy_id, row.target, &[]),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from EnableIpamPolicy, got {status} with body \
             {body}"
        );
        assert_eq!(
            element(&body, "ipamPolicyId").as_deref(),
            Some(policy_id.as_str()),
            "case {case:?}: expected the enabled policy's id, got {body}"
        );

        // The round trip: the report reads back exactly what the enable stored.
        let reported = get_enabled(&router, case).await;
        assert_eq!(
            reported,
            Reported {
                enabled: Some("true".to_string()),
                policy_id: Some(policy_id.clone()),
                managed_by: Some(row.managed_by.to_string()),
            },
            "case {case:?}: expected the enabled policy and its manager, got {reported:?}"
        );
        assert_eq!(
            stored_enablement(&engine),
            Some((policy_id.clone(), row.target.map(str::to_string))),
            "case {case:?}: the store must hold the enablement the response reported"
        );

        // Disabling the enablement the request names answers `true` and leaves nothing
        // enabled; the control policy was never enabled and is untouched.
        let (status, body) = invoke(
            &router,
            "DisableIpamPolicy",
            &policy_params(&policy_id, row.target, &[]),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from DisableIpamPolicy, got {status} with body \
             {body}"
        );
        assert_eq!(
            element(&body, "return").as_deref(),
            Some("true"),
            "case {case:?}: expected the disable to report success, got {body}"
        );
        let reported = get_enabled(&router, case).await;
        assert_eq!(
            reported.enabled.as_deref(),
            Some("false"),
            "case {case:?}: a disabled policy must not be reported as enabled, got \
             {reported:?}"
        );
        assert_eq!(
            reported.policy_id, None,
            "case {case:?}: no policy is enabled, so none is named, got {reported:?}"
        );
        assert_eq!(
            stored_enablement(&engine),
            None,
            "case {case:?}: the store must hold no enablement after the disable"
        );
        assert_ne!(
            control_id, policy_id,
            "case {case:?}: the control policy must be a second policy of the account"
        );
    }
}

/// The account has ONE enabled policy or none: enabling a second policy replaces the first,
/// whichever kind of target each enablement names.
#[tokio::test]
async fn enabling_a_second_policy_replaces_the_first() {
    let table = rows();
    for first in &table {
        for second in &table {
            let case = format!("{} then {}", first.case, second.case);
            let (router, engine) = super::ec2_query::emulator();
            let first_id = seed_policy(&engine, first.ipam_id, first.region, first.tags);
            let second_id = seed_policy(&engine, second.ipam_id, second.region, second.tags);

            for (policy_id, row) in [(&first_id, first), (&second_id, second)] {
                let (status, body) = invoke(
                    &router,
                    "EnableIpamPolicy",
                    &policy_params(policy_id, row.target, &[]),
                )
                .await;
                assert_eq!(
                    status, 200,
                    "case {case:?}: expected HTTP 200 from EnableIpamPolicy, got {status} \
                     with body {body}"
                );
            }

            let reported = get_enabled(&router, &case).await;
            assert_eq!(
                reported,
                Reported {
                    enabled: Some("true".to_string()),
                    policy_id: Some(second_id.clone()),
                    managed_by: Some(second.managed_by.to_string()),
                },
                "case {case:?}: the second enable must replace the first, got {reported:?}"
            );
        }
    }
}

/// A disable names an enablement — the policy AND the target it was enabled for — so one
/// naming anything else is refused with `IncorrectState` and leaves the enablement standing.
#[tokio::test]
async fn disabling_an_enablement_the_account_does_not_hold_is_refused() {
    // The enablement every row makes first: a policy enabled for one organizational unit.
    const HELD_TARGET: &str = "ou-abcd-11112222";

    for (case, name_other_policy, target) in [
        ("the enabled policy, with no target named", false, None),
        (
            "the enabled policy, with another target named",
            false,
            Some("ou-abcd-33334444"),
        ),
        (
            "another policy of the account, with the held target",
            true,
            Some(HELD_TARGET),
        ),
        ("another policy of the account, with no target", true, None),
    ] {
        let (router, engine) = super::ec2_query::emulator();
        let enabled_id = seed_policy(&engine, IPAM_ID, REGION, &[]);
        let other_id = seed_policy(&engine, IPAM_ID, "eu-west-2", &[("Name", "other")]);
        let (status, body) = invoke(
            &router,
            "EnableIpamPolicy",
            &policy_params(&enabled_id, Some(HELD_TARGET), &[]),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the enablement every row starts from must be made, got {status} \
             with body {body}"
        );

        let named = if name_other_policy {
            other_id.as_str()
        } else {
            enabled_id.as_str()
        };
        let (status, body) = invoke(
            &router,
            "DisableIpamPolicy",
            &policy_params(named, target, &[]),
        )
        .await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected HTTP 400, got {status} with body {body}"
        );
        assert_eq!(
            error_code(&body),
            "IncorrectState",
            "case {case:?}: expected IncorrectState, got body {body}"
        );
        assert_eq!(
            stored_enablement(&engine),
            Some((enabled_id.clone(), Some(HELD_TARGET.to_string()))),
            "case {case:?}: a refused disable must leave the enablement as it was"
        );
    }
}

/// What one refusal row sends, and the code it must be refused with.
struct Refusal {
    /// What this row is called in a failure message.
    case: &'static str,
    /// The `IpamPolicyId` to send.
    policy_id: &'static str,
    /// The EC2 error code the request must be refused with.
    code: &'static str,
}

/// Both writers read an id against the form this service ISSUES before anything else: an id
/// outside it is refused as malformed, and an id of that form naming no policy of the account
/// as not found. Neither enables or disables anything.
#[tokio::test]
async fn an_unresolvable_id_is_refused_by_both_writers() {
    // Every id below is read against the form this service issues: `<prefix>-<8 or 17
    // lowercase hex digits>` under this resource's own prefix.
    let refusals = [
        Refusal {
            case: "a suffix of the long form under a prefix this API does not issue",
            policy_id: "ipam-pol-0000000000000000f",
            code: "InvalidIpamPolicyId.Malformed",
        },
        Refusal {
            case: "an id of another resource kind",
            policy_id: "ipam-pool-0000000000000000f",
            code: "InvalidIpamPolicyId.Malformed",
        },
        Refusal {
            case: "a suffix that is not hexadecimal",
            policy_id: "ipam-policy-0000000000000000g",
            code: "InvalidIpamPolicyId.Malformed",
        },
        Refusal {
            case: "an uppercase suffix",
            policy_id: "ipam-policy-000000000000000FF",
            code: "InvalidIpamPolicyId.Malformed",
        },
        Refusal {
            case: "a suffix of neither published length",
            policy_id: "ipam-policy-000000000",
            code: "InvalidIpamPolicyId.Malformed",
        },
        Refusal {
            case: "not an id at all",
            policy_id: "my-policy",
            code: "InvalidIpamPolicyId.Malformed",
        },
        Refusal {
            case: "a well-formed long-form id the account holds no policy for",
            policy_id: UNKNOWN_POLICY_ID,
            code: "InvalidIpamPolicyId.NotFound",
        },
        Refusal {
            case: "a well-formed short-form id the account holds no policy for",
            policy_id: "ipam-policy-0fffffff",
            code: "InvalidIpamPolicyId.NotFound",
        },
    ];

    for action in ["EnableIpamPolicy", "DisableIpamPolicy"] {
        for row in &refusals {
            let case = format!("{action}: {}", row.case);
            let (router, engine) = super::ec2_query::emulator();
            let held_id = seed_policy(&engine, IPAM_ID, REGION, &[("Name", "kept")]);
            let (status, body) = invoke(
                &router,
                "EnableIpamPolicy",
                &policy_params(&held_id, None, &[]),
            )
            .await;
            assert_eq!(
                status, 200,
                "case {case:?}: the enablement the row starts from must be made, got {status} \
                 with body {body}"
            );

            let (status, body) =
                invoke(&router, action, &policy_params(row.policy_id, None, &[])).await;
            assert_eq!(
                status, 400,
                "case {case:?}: expected HTTP 400, got {status} with body {body}"
            );
            assert_eq!(
                error_code(&body),
                row.code,
                "case {case:?}: expected the code {expected:?}, got body {body}",
                expected = row.code,
            );
            assert_eq!(
                stored_enablement(&engine),
                Some((held_id.clone(), None)),
                "case {case:?}: a refused request must leave the account's enablement as it \
                 was"
            );
        }
    }
}

/// A `DryRun` request answers the permission question with `DryRunOperation` and writes
/// nothing — for the report and for both writers; an id that is not of this kind at all is
/// still refused as malformed, because that is a question about the request's own form.
#[tokio::test]
async fn a_dry_run_answers_the_permission_question_and_writes_nothing() {
    for (case, action, requested, expected_status, expected_code) in [
        (
            "the report",
            "GetEnabledIpamPolicy",
            None,
            DRY_RUN_STATUS,
            "DryRunOperation",
        ),
        (
            "an enable of a policy the account holds",
            "EnableIpamPolicy",
            None,
            DRY_RUN_STATUS,
            "DryRunOperation",
        ),
        (
            "a disable of the enabled policy",
            "DisableIpamPolicy",
            None,
            DRY_RUN_STATUS,
            "DryRunOperation",
        ),
        (
            "an enable naming a well-formed id the account holds no policy for",
            "EnableIpamPolicy",
            Some(UNKNOWN_POLICY_ID),
            DRY_RUN_STATUS,
            "DryRunOperation",
        ),
        (
            "a disable naming an id outside the issued form",
            "DisableIpamPolicy",
            Some("ipam-pol-0000000000000000f"),
            400,
            "InvalidIpamPolicyId.Malformed",
        ),
    ] {
        let (router, engine) = super::ec2_query::emulator();
        let held_id = seed_policy(&engine, IPAM_ID, REGION, &[]);
        let (status, body) = invoke(
            &router,
            "EnableIpamPolicy",
            &policy_params(&held_id, None, &[]),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the enablement the row starts from must be made, got {status} with \
             body {body}"
        );

        let params = if action == "GetEnabledIpamPolicy" {
            vec![("DryRun".to_string(), "true".to_string())]
        } else {
            policy_params(
                requested.unwrap_or(held_id.as_str()),
                None,
                &[("DryRun", "true")],
            )
        };
        let (status, body) = invoke(&router, action, &params).await;
        assert_eq!(
            status, expected_status,
            "case {case:?}: expected HTTP {expected_status}, got {status} with body {body}"
        );
        assert_eq!(
            error_code(&body),
            expected_code,
            "case {case:?}: expected the code {expected_code:?}, got body {body}"
        );
        assert_eq!(
            stored_enablement(&engine),
            Some((held_id.clone(), None)),
            "case {case:?}: a dry run must write nothing"
        );
    }
}

/// A policy whose deletion has been asked for is on its way out: it can be enabled from
/// neither delete state, and the enablement of one that WAS enabled goes with it, so the
/// report answers that nothing is enabled.
#[tokio::test]
async fn a_policy_on_its_way_out_is_not_an_enabled_policy() {
    for (case, wait) in [
        ("while the deletion is still under way", false),
        ("once the clock has finished the deletion", true),
    ] {
        let (router, engine) = super::ec2_query::emulator();
        let policy_id = seed_policy(&engine, IPAM_ID, REGION, &[]);
        let (status, body) = invoke(
            &router,
            "EnableIpamPolicy",
            &policy_params(&policy_id, None, &[]),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the policy must be enabled first, got {status} with body {body}"
        );

        let (status, body) = invoke(
            &router,
            "DeleteIpamPolicy",
            &policy_params(&policy_id, None, &[]),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from DeleteIpamPolicy, got {status} with body \
             {body}"
        );
        if wait {
            tokio::time::sleep(past_the_transition()).await;
        }

        let reported = get_enabled(&router, case).await;
        assert_eq!(
            reported,
            Reported {
                enabled: Some("false".to_string()),
                policy_id: None,
                managed_by: None,
            },
            "case {case:?}: a policy being deleted is not an enabled policy, got {reported:?}"
        );
        assert_eq!(
            stored_enablement(&engine),
            None,
            "case {case:?}: the deletion must have taken the enablement with it"
        );

        // And it can be enabled from neither delete state.
        let (status, body) = invoke(
            &router,
            "EnableIpamPolicy",
            &policy_params(&policy_id, None, &[]),
        )
        .await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected HTTP 400, got {status} with body {body}"
        );
        assert_eq!(
            error_code(&body),
            "IncorrectState",
            "case {case:?}: expected IncorrectState, got body {body}"
        );
        assert_eq!(
            stored_enablement(&engine),
            None,
            "case {case:?}: a refused enable must enable nothing"
        );
    }
}
