// SPDX-License-Identifier: CC0-1.0

//! What a client that WAITS on, and SELECTS on, a listed instance's lifecycle sees over the
//! `ListInstances` enumeration, on the `awsJson1_1` wire.
//!
//! THE RULE: every instance an enumeration serves carries, beside its flat `Status`, a
//! `State` structure whose `Name` is that same lifecycle value, read off the instance being
//! served at the instant of the read — so a client that reads a listed instance's lifecycle
//! out of `State.Name` alone reaches exactly the conclusion the flat `Status` supports,
//! while a transition the clock owes is still in flight and once it has fallen due alike.
//!
//! The sibling suites pin that the member is SERVED and mirrors the status, over seeded
//! records (`instance_state_view.rs`, `listed_instance_state_source.rs`), listing sizes,
//! enablement paths, names, Region counts and read edge cases. This suite adds the two USES
//! of the member, which none of them drives:
//!
//! * a WAIT LOOP keyed on `State.Name` alone, over an instance's own activation span with no
//!   stored instant moved: every pass has to see an admissible lifecycle value mirroring the
//!   entry's `Status`, and the loop has to terminate once the activation falls due. A loop
//!   that dereferences a member no entry carries, or that never terminates, is the defect;
//! * a FILTER keyed on `State.Name` over a multi-instance listing: the entries it selects
//!   have to be exactly the instances whose stored status it names, for every lifecycle
//!   value the model's enum declares (`ops::types::INSTANCE_STATUS_VALUES`) and over listing
//!   sizes up to the published maximum of the listing's own shape (`InstanceList`,
//!   `length min 0 max 10`).
//!
//! The deletion row is read on both sides of the instant the removal falls due, so the
//! transient `DELETE_IN_PROGRESS` an entry carries is observed for certain rather than
//! raced: the test moves the STORED instant — to a fixed point, never to one read off the
//! host's clock — and the service's own transition applies it, exactly as in production.
//!
//! Every call goes through `MultiServiceRouter::dispatch`; the harness is the one
//! `ssoadmin_permission_sets.rs` owns, and the enumeration and the rule assertion are the
//! ones `instance_state_view.rs` owns. Nothing here sleeps outside a poll loop, and no
//! assertion is made on elapsed time: a wait is bounded by a generous deadline and ends on
//! the CONDITION it waits for.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aws_smithy_types::DateTime;
use serde_json::{json, Value};
use service_com_amazonaws_ssoadmin_swbexternalservice::ops::types::INSTANCE_STATUS_VALUES;
use service_com_amazonaws_ssoadmin_swbexternalservice::state;
use smithy_server_runtime::MultiServiceRouter;

use crate::instance_state_view::{assert_state_mirrors_status, listed_pages};
use crate::ssoadmin_permission_sets::{
    empty_account, hold_deletion, router_over, served_in_region, with_store,
};

/// How long a wait loop below may run before it is called non-terminating. Generous on
/// purpose: the transitions it waits for are owed in well under a second, and this bound is
/// only here so a broken loop fails instead of hanging. No assertion is made on how long a
/// wait actually took.
const WAIT_DEADLINE: Duration = Duration::from_secs(60);

/// How long a wait loop pauses between two looks. It only spaces the polls out; the loop
/// ends on its CONDITION, never on this value.
const LOOK_AGAIN: Duration = Duration::from_millis(10);

/// A stored due instant that is NOT yet due: a fixed point far beyond any run of this
/// suite, so the transition it holds back stays held back whatever the host's clock reads.
/// Offset from the epoch rather than from the clock, so no row here depends on when it ran.
fn not_yet_due() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000)
}

/// A stored due instant that IS due: the epoch, which is behind every clock the suite can
/// run against, so the transition it owes is owed on the next request.
const ALREADY_DUE: SystemTime = SystemTime::UNIX_EPOCH;

/// The `CreatedDate` a seeded instance carries: a fixed stamp, because when a record was
/// created is no part of the rule under test.
const SEEDED_CREATED_DATE_SECS: i64 = 1_700_000_000;

/// A router over an account that holds exactly `instances`.
///
/// An account holds ONE instance and no call of this API enables a second, so a listing of
/// several is seeded through the service's own `state::Instance` constructor; everything the
/// test then asserts goes over the wire.
fn account_holding(instances: Vec<state::Instance>) -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    with_store(&engine, |store| {
        store.instances.clear();
        for instance in instances {
            store.instances.insert(instance.instance_arn.clone(), instance);
        }
        // The account's ambient instance has been enabled already, so no later request
        // enables one beside the records seeded here.
        store.ambient_instance_enabled = true;
    });
    router_over(engine)
}

/// The entries one enumeration serves, following every `NextToken` it hands out, for a store
/// that holds `held` instances.
///
/// The walk is bounded by the pages the smallest admissible page size can need plus the
/// empty page the enumeration ends on.
async fn listed(
    case: &str,
    router: &MultiServiceRouter,
    region: &str,
    max_results: Option<i64>,
    held: usize,
) -> Vec<Value> {
    listed_pages(case, router, region, max_results, held + 2)
        .await
        .concat()
}

/// The entry `instance_arn` names in one enumeration, or `None` once the instance is gone.
///
/// THE RULE is asserted on the entry as it is read, so every pass of a wait loop below
/// checks it.
async fn listed_entry(
    case: &str,
    router: &MultiServiceRouter,
    region: &str,
    max_results: Option<i64>,
    held: usize,
    instance_arn: &str,
) -> Option<Value> {
    let entries = listed(case, router, region, max_results, held).await;
    let entry = entries
        .into_iter()
        .find(|entry| entry["InstanceArn"].as_str() == Some(instance_arn))?;
    assert_state_mirrors_status(case, &entry);
    Some(entry)
}

/// The `State.Name` of that entry, which THE RULE requires it to carry.
fn state_name(case: &str, entry: &Value) -> String {
    entry["State"]["Name"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: the entry carries no State.Name: {entry}"))
        .to_string()
}

/// The wait loop a client writes when it reads a listed instance's lifecycle out of
/// `State.Name`: look again until that value is `target`, asserting on every pass that the
/// entry is served, that its `State` mirrors its `Status` and that the value is one of
/// `admissible`.
///
/// Ends on the CONDITION; [`WAIT_DEADLINE`] is only the bound past which the loop is called
/// non-terminating. The values observed are kept only to name them in a failure.
async fn wait_on_state_name(
    case: &str,
    router: &MultiServiceRouter,
    region: &str,
    max_results: Option<i64>,
    instance_arn: &str,
    target: &str,
    admissible: &[&str],
) {
    let deadline = Instant::now() + WAIT_DEADLINE;
    let mut observed: Vec<String> = Vec::new();
    loop {
        let entry = listed_entry(case, router, region, max_results, 1, instance_arn)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "case {case:?}: the enumeration no longer serves {instance_arn}; \
                     observed {observed:?}"
                )
            });
        let name = state_name(case, &entry);
        assert!(
            admissible.contains(&name.as_str()),
            "case {case:?}: expected State.Name to be one of {admissible:?}, got {name:?} in \
             {entry}"
        );
        observed.push(name.clone());
        if name == target {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: a wait loop on State.Name never reached {target:?}; observed \
             {observed:?}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// THE RULE under a wait loop keyed on `State.Name` alone: a client that polls the listing
/// after `CreateInstance` sees the lifecycle advance through the member and the loop ends
/// once the activation the clock owes has fallen due — with the same value the entry's flat
/// `Status` reports on every pass, and `ACTIVE` on every read after it settles.
///
/// Nothing here moves a stored instant: the span is the instance's own, so this is the loop
/// the issue's client runs.
#[tokio::test]
async fn a_wait_loop_on_state_name_terminates_when_the_activation_falls_due() {
    // The Region the instance is enabled in, in two- and three-prefix spellings of the
    // model's `RegionName` pattern `^([a-z]+-){2,3}\d$`, paired with the page size the
    // enumeration asks for: both published bounds of `MaxResults` (`range 1..100`) and the
    // request that names none. None of these is the Region of the recorded case.
    let rows = [
        ("us-east-2", None),
        ("ap-southeast-4", Some(1)),
        ("eu-west-2", Some(100)),
    ];

    for (region, max_results) in rows {
        let case = format!("wait loop in {region} / MaxResults {max_results:?}");
        let (router, _engine) = empty_account();
        let created = served_in_region(
            &case,
            &router,
            region,
            "CreateInstance",
            &json!({"Name": "PollingClient"}),
        )
        .await;
        let instance_arn = created["InstanceArn"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: no InstanceArn in {created}"))
            .to_string();

        // A created instance is `CREATE_IN_PROGRESS` until its activation falls due and
        // `ACTIVE` from then on, so those are the only two values this loop may see.
        wait_on_state_name(
            &case,
            &router,
            region,
            max_results,
            &instance_arn,
            "ACTIVE",
            &["CREATE_IN_PROGRESS", "ACTIVE"],
        )
        .await;

        // Settled means settled: a client that keeps polling goes on reading `ACTIVE`,
        // because the member is read off the stored status rather than consumed by a read.
        for read in 0..2 {
            let case = format!("{case} / read {read} after it settled");
            let entry = listed_entry(&case, &router, region, max_results, 1, &instance_arn)
                .await
                .unwrap_or_else(|| panic!("case {case:?}: {instance_arn} is no longer served"));
            assert_eq!(
                state_name(&case, &entry),
                "ACTIVE",
                "case {case:?}: an activated instance stays ACTIVE, got {entry}"
            );
        }
    }
}

/// THE RULE through the OTHER transition a listed instance passes through: once
/// `DeleteInstance` has started the removal, every entry the enumeration serves for that
/// instance reports `DELETE_IN_PROGRESS` in `State.Name` as in `Status`, and a client
/// polling on `State.Name` goes on seeing that one value until the removal falls due and
/// the instance leaves the listing.
#[tokio::test]
async fn a_wait_loop_on_state_name_sees_a_deletion_through_to_the_end() {
    let region = "eu-central-1";
    let (router, engine) = empty_account();
    let case = "deletion wait loop";
    let created = served_in_region(
        case,
        &router,
        region,
        "CreateInstance",
        &json!({"Name": "PollingClient"}),
    )
    .await;
    let instance_arn = created["InstanceArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: no InstanceArn in {created}"))
        .to_string();
    wait_on_state_name(
        case,
        &router,
        region,
        None,
        &instance_arn,
        "ACTIVE",
        &["CREATE_IN_PROGRESS", "ACTIVE"],
    )
    .await;

    served_in_region(
        case,
        &router,
        region,
        "DeleteInstance",
        &json!({"InstanceArn": instance_arn}),
    )
    .await;
    // The removal is held well out, so the transient the model declares is observed for
    // certain rather than raced. Only the stored INSTANT is this test's doing: the status
    // itself is applied by the service's own transition.
    hold_deletion(&engine, not_yet_due());
    // The hold landed on a record that is still there with its removal not yet due: without
    // that, the reads below would be asserting about an instance that had already gone.
    assert!(
        with_store(&engine, |store| store
            .instances
            .values()
            .any(|instance| instance.deleted_due == Some(not_yet_due()))),
        "case {case:?}: the instance whose deletion was started is still held, with its \
         removal not yet due"
    );

    // Read at both published bounds of `MaxResults` and at no page size at all: the entry
    // reports the deletion in both views whichever page it arrives on.
    for max_results in [None, Some(1), Some(100)] {
        let case = format!("{case} / held / MaxResults {max_results:?}");
        let entry = listed_entry(&case, &router, region, max_results, 1, &instance_arn)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "case {case:?}: an instance whose removal is held well out is still \
                     enumerated"
                )
            });
        assert_eq!(
            state_name(&case, &entry),
            "DELETE_IN_PROGRESS",
            "case {case:?}: the removal has not fallen due yet, got {entry}"
        );
    }

    // The clock has moved past the removal. The client's loop ends when the instance leaves
    // the listing, and every entry it still sees reports the deletion in both views.
    hold_deletion(&engine, ALREADY_DUE);
    let case = "deletion wait loop / removal due";
    let deadline = Instant::now() + WAIT_DEADLINE;
    let mut passes = 0usize;
    loop {
        match listed_entry(case, &router, region, None, 1, &instance_arn).await {
            Some(entry) => {
                assert_eq!(
                    state_name(case, &entry),
                    "DELETE_IN_PROGRESS",
                    "case {case:?}: an instance on its way out reports the deletion in both \
                     views, got {entry}"
                );
            }
            None => break,
        }
        passes += 1;
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the instance never left the listing after its removal fell due \
             ({passes} passes)"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
    let gone = listed(case, &router, region, None, 1).await;
    assert!(
        gone.is_empty(),
        "case {case:?}: the account holds no instance once the removal fell due, got {gone:?}"
    );
}

/// THE RULE under a filter keyed on `State.Name`: the entries a client selects by that value
/// are exactly the instances whose stored status it names — for every value the model's enum
/// declares, over listing sizes up to the published maximum of `InstanceList`, and whichever
/// page an entry arrives on.
#[tokio::test]
async fn a_filter_on_state_name_selects_exactly_the_instances_in_that_status() {
    let region = "ap-northeast-3";

    // `InstanceList` is `length min 0 max 10`: one instance, a pair, and the published
    // maximum, so a filter is exercised on a listing that fits one page and on one that
    // cannot.
    for held in [1usize, 2, 10] {
        // Which status each seeded instance holds: the model-generated value list cycled, so
        // every value it declares appears and no listing of more than one is uniform.
        let instances: Vec<state::Instance> = (0..held)
            .map(|index| {
                seeded_instance(
                    index,
                    INSTANCE_STATUS_VALUES[index % INSTANCE_STATUS_VALUES.len()],
                    region,
                )
            })
            .collect();
        // What the filter has to select, per status: the ARNs of the records seeded in it.
        let mut expected: BTreeMap<&str, BTreeSet<String>> = INSTANCE_STATUS_VALUES
            .iter()
            .map(|status| (*status, BTreeSet::new()))
            .collect();
        for instance in &instances {
            expected
                .get_mut(instance.status.as_str())
                .expect("every seeded status is a modeled InstanceStatus value")
                .insert(instance.instance_arn.clone());
        }
        let router = account_holding(instances);

        for max_results in [Some(1), Some(10), Some(100), None] {
            let case = format!("{held} instances / MaxResults {max_results:?}");
            let entries = listed(&case, &router, region, max_results, held).await;
            assert_eq!(
                entries.len(),
                held,
                "case {case:?}: every seeded instance is enumerated, got {entries:?}"
            );
            for entry in &entries {
                assert_state_mirrors_status(&case, entry);
            }
            for (status, arns) in &expected {
                let selected: BTreeSet<String> = entries
                    .iter()
                    .filter(|entry| entry["State"]["Name"].as_str() == Some(*status))
                    .map(|entry| {
                        entry["InstanceArn"]
                            .as_str()
                            .unwrap_or_else(|| {
                                panic!("case {case:?}: the entry reports no InstanceArn: {entry}")
                            })
                            .to_string()
                    })
                    .collect();
                assert_eq!(
                    &selected, arns,
                    "case {case:?}: a filter on State.Name {status:?} selects the instances \
                     stored in it, got {selected:?}"
                );
            }
        }
    }
}

/// One stored instance whose status is `status`, enabled in `region`.
///
/// Nothing is owed on the record: the status seeded here IS the instance's status, so no
/// transition the clock owes can move it out from under a read. The identifiers follow the
/// model's own forms — `InstanceArn`'s `ssoins-` plus 16 of `[a-zA-Z0-9-.]`, and
/// `InstanceIdentityStoreArn`'s `d-` plus 10 hex digits.
fn seeded_instance(index: usize, status: &str, region: &str) -> state::Instance {
    let mut instance = state::Instance::active(
        &format!("ssoins-{:016}", index + 1),
        &format!("d-{:010}", index + 1),
        state::InstanceType::Organization,
        Some(format!("Selected{index}")),
        DateTime::from_secs(SEEDED_CREATED_DATE_SECS),
        region,
    );
    instance.status = status.to_string();
    instance.active_due = None;
    instance.deleted_due = None;
    instance
}
