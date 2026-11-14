// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for `DeleteTransitGatewayMeteringPolicy`, driven over the wire this service
//! speaks (`ec2Query`), with `DescribeTransitGatewayMeteringPolicies` reading back what the
//! delete recorded (README.md / OPERATIONS.md "Wire protocol").
//!
//! The rule under test is the one every EC2 delete of a resource whose own state catalog carries
//! both a transient and a terminal delete member follows: the call RECORDS the deletion rather
//! than performing it at once — the resource is left in the transient delete state, reported with
//! every other member the store holds for it, and the clock owes it the terminal one, which it
//! reaches whether or not anybody calls again. Nothing else in the store moves, and a resource a
//! delete has already been asked for is refused rather than deleted twice.
//!
//! Each table row is a distinct input along what that rule generalises over: WHICH state the
//! policy is in when the delete arrives (the transient state of a create, the state a settled
//! policy is in, and one being modified), how many middlebox attachments it names (none, one,
//! several) and how many tags it carries (none, one, two) — and, for the refusals, which id of
//! the request is unusable and how.
//!
//! The middlebox attachments a policy meters are seeded through the store's own writer
//! (`insert_transit_gateway_attachment`), as every transit gateway suite in this crate does,
//! because `CreateTransitGatewayVpcAttachment` is still a scaffold stub; the policies themselves
//! are created over the wire through `CreateTransitGatewayMeteringPolicy`, except the one row
//! whose state no implemented operation can produce, which is seeded through
//! `insert_transit_gateway_metering_policy`.

use std::time::{Duration, Instant};

use ec2::ops::types::{
    TRANSIT_GATEWAY_METERING_POLICY_STATE_VALUES, Tag, TransitGatewayMeteringPolicy,
    TransitGatewayVpcAttachment,
};
use ec2::state::{
    ComAmazonawsEc2Amazonec2State as Ec2State, DRY_RUN_OPERATION, INCORRECT_STATE,
    INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_MALFORMED,
    INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_NOT_FOUND,
    RESOURCE_TYPE_TRANSIT_GATEWAY_METERING_POLICY, TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE,
    TRANSITION_DELAY, TransitGatewayAttachmentView,
};
use service_com_amazonaws_ec2_amazonec2 as ec2;
use smithy_server_runtime::MultiServiceRouter;

use super::ec2_query::{as_timestamp, element, error_code, indexed};
use super::wire::{Param, child, child_text, document, param, set_items};

/// The Region every call here is signed for.
const REGION: &str = "us-east-1";

/// The ec2Query `Action` under test.
const ACTION: &str = "DeleteTransitGatewayMeteringPolicy";

/// The create that mints the policies this suite deletes.
const CREATE: &str = "CreateTransitGatewayMeteringPolicy";

/// The describe that reads a deleted policy back.
const DESCRIBE: &str = "DescribeTransitGatewayMeteringPolicies";

/// The HTTP status EC2 answers `DryRunOperation` with.
const DRY_RUN_STATUS: u16 = 412;

/// The HTTP status EC2 answers a refused request with.
const REFUSAL_STATUS: u16 = 400;

/// How many middlebox attachments every case seeds, so a row can name a subset of them.
const SEEDED_ATTACHMENTS: usize = 4;

/// The deadline the polls below give up at: a large multiple of the service's own transition
/// span, so the assertion is about the state the clock owes and never about how fast the host
/// runs.
fn move_deadline() -> Duration {
    TRANSITION_DELAY * 60
}

/// How long one look waits before looking again — a fraction of the span, so a poll inside the
/// deadline above costs many looks rather than one.
fn poll_interval() -> Duration {
    TRANSITION_DELAY / 10
}

/// A member of `TransitGatewayMeteringPolicyState`, from the modelled catalog
/// (`smithy_query(query="shape",shape="TransitGatewayMeteringPolicyState")`, whose values are
/// `available | deleted | deleting | modifying | pending`) rather than written out here.
fn policy_state(name: &str) -> &'static str {
    TRANSIT_GATEWAY_METERING_POLICY_STATE_VALUES
        .iter()
        .find(|value| **value == name)
        .unwrap_or_else(|| panic!("{name:?} is no TransitGatewayMeteringPolicyState member"))
}

/// One call of `action` signed for the Region above.
async fn invoke(router: &MultiServiceRouter, action: &str, params: &[Param]) -> (u16, String) {
    super::ec2_query::call(router, REGION, action, params).await
}

/// A transit gateway created through the wire, as its `TransitGatewayId`.
async fn transit_gateway(router: &MultiServiceRouter) -> String {
    let (status, body) = invoke(router, "CreateTransitGateway", &[]).await;
    assert_eq!(
        status, 200,
        "CreateTransitGateway must succeed, got {status} with body {body}"
    );
    element(&body, "transitGatewayId").expect("a created transit gateway reports its own id")
}

/// Store [`SEEDED_ATTACHMENTS`] VPC attachments of `gateway_id`, in service, and answer their
/// `TransitGatewayAttachmentId`s — the attachments a policy may meter.
fn seed_attachments(engine: &engine::InMemoryEngine, gateway_id: &str) -> Vec<String> {
    let store = engine.state::<Ec2State>();
    let mut guard = store.lock();
    (0..SEEDED_ATTACHMENTS)
        .map(|index| {
            guard
                .insert_transit_gateway_attachment(TransitGatewayAttachmentView::Vpc(
                    TransitGatewayVpcAttachment {
                        transit_gateway_id: Some(gateway_id.to_string()),
                        vpc_id: Some(format!("vpc-0123456789abcde{index:0>2x}")),
                        vpc_owner_id: Some("210987654321".to_string()),
                        state: Some(TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE.to_string()),
                        ..Default::default()
                    },
                ))
                .expect("the store holds the seeded VPC attachment")
        })
        .collect()
}

/// The emulator with one transit gateway and the middlebox attachments above: the router to call,
/// the engine to read the store through, the gateway's id, and the attachment ids.
async fn seeded() -> (
    MultiServiceRouter,
    std::sync::Arc<engine::InMemoryEngine>,
    String,
    Vec<String>,
) {
    let (router, engine) = super::ec2_query::emulator();
    let gateway_id = transit_gateway(&router).await;
    let attachment_ids = seed_attachments(&engine, &gateway_id);
    (router, engine, gateway_id, attachment_ids)
}

/// `MiddleboxAttachmentId.N` form fields for `ids`, as ec2Query flattens that list
/// (`CreateTransitGatewayMeteringPolicyRequest$MiddleboxAttachmentIds` is bound to the
/// `MiddleboxAttachmentId` xmlName).
fn middlebox_params(ids: &[String]) -> Vec<Param> {
    indexed(
        "MiddleboxAttachmentId",
        &ids.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

/// The `TagSpecifications` form fields that tag the policy one create mints.
fn tag_params(tags: &[(&str, &str)]) -> Vec<Param> {
    let mut params = vec![param(
        "TagSpecifications.1.ResourceType",
        RESOURCE_TYPE_TRANSIT_GATEWAY_METERING_POLICY,
    )];
    for (position, (key, value)) in tags.iter().enumerate() {
        let nth = position + 1;
        params.push(param(&format!("TagSpecifications.1.Tag.{nth}.Key"), key));
        params.push(param(&format!("TagSpecifications.1.Tag.{nth}.Value"), value));
    }
    params
}

/// Read something off the one metering policy a response carries — the element that has a
/// `transitGatewayMeteringPolicyId` child.
fn with_policy<T>(case: &str, body: &str, read: impl FnOnce(roxmltree::Node<'_, '_>) -> T) -> T {
    let parsed = document(case, body);
    let policy = parsed
        .descendants()
        .find(|node| node.is_element() && child(*node, "transitGatewayMeteringPolicyId").is_some())
        .unwrap_or_else(|| panic!("case {case:?}: no metering policy in {body}"));
    read(policy)
}

/// A member of the one metering policy a response carries, or `None` when it carries no such
/// member.
fn policy_member(case: &str, body: &str, name: &str) -> Option<String> {
    with_policy(case, body, |policy| child_text(policy, name))
}

/// Whether the one metering policy a response carries has a `name` child ELEMENT at all.
fn has_member(case: &str, body: &str, name: &str) -> bool {
    with_policy(case, body, |policy| child(policy, name).is_some())
}

/// The middlebox attachment ids of the one metering policy a response carries, in document
/// order.
fn reported_middlebox_attachments(case: &str, body: &str) -> Vec<String> {
    with_policy(case, body, |policy| {
        set_items(policy, "middleboxAttachmentIdSet")
            .into_iter()
            .map(|item| item.text().unwrap_or_default().to_string())
            .collect()
    })
}

/// The (key, value) pairs of the one metering policy a response carries.
fn reported_tags(case: &str, body: &str) -> Vec<(String, String)> {
    with_policy(case, body, |policy| {
        set_items(policy, "tagSet")
            .into_iter()
            .map(|item| {
                (
                    child_text(item, "key").unwrap_or_default(),
                    child_text(item, "value").unwrap_or_default(),
                )
            })
            .collect()
    })
}

/// How many metering policies the store holds.
fn stored_policies(engine: &engine::InMemoryEngine) -> usize {
    engine
        .state::<Ec2State>()
        .lock()
        .transit_gateway_metering_policies
        .len()
}

/// The state the store holds for one metering policy, or `None` when it holds none.
fn stored_state(engine: &engine::InMemoryEngine, metering_policy_id: &str) -> Option<String> {
    engine
        .state::<Ec2State>()
        .lock()
        .transit_gateway_metering_policies
        .get(metering_policy_id)
        .and_then(|policy| policy.state.clone())
}

/// The `DeleteTransitGatewayMeteringPolicy` call for `metering_policy_id`.
async fn delete(router: &MultiServiceRouter, metering_policy_id: &str) -> (u16, String) {
    invoke(
        router,
        ACTION,
        &[param("TransitGatewayMeteringPolicyId", metering_policy_id)],
    )
    .await
}

/// The `DescribeTransitGatewayMeteringPolicies` call narrowed to `metering_policy_id`.
async fn describe(router: &MultiServiceRouter, metering_policy_id: &str) -> (u16, String) {
    invoke(
        router,
        DESCRIBE,
        &indexed("TransitGatewayMeteringPolicyIds", &[metering_policy_id]),
    )
    .await
}

/// The state the describe reports for one policy.
async fn described_state(
    case: &str,
    router: &MultiServiceRouter,
    metering_policy_id: &str,
) -> String {
    let (status, body) = describe(router, metering_policy_id).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from {DESCRIBE}, got {status} with body {body}"
    );
    policy_member(case, &body, "state")
        .unwrap_or_else(|| panic!("case {case:?}: the describe must report the policy's state"))
}

/// Look at the policy AGAIN until the describe reports it in `wanted`, or a deadline far past the
/// service's own transition span passes — the condition is waited for, never a fixed time, so
/// nothing here depends on how fast the host runs. Answers the whole body of the last look.
async fn poll_until_state(
    case: &str,
    router: &MultiServiceRouter,
    metering_policy_id: &str,
    wanted: &str,
) -> String {
    let deadline = Instant::now() + move_deadline();
    loop {
        let (status, body) = describe(router, metering_policy_id).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from {DESCRIBE}, got {status} with body {body}"
        );
        let state = policy_member(case, &body, "state");
        if state.as_deref() == Some(wanted) {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected the policy to reach {wanted:?}, got {state:?} in {body}"
        );
        tokio::time::sleep(poll_interval()).await;
    }
}

/// One deleted policy: the facts the policy carries before the delete and the state it is in when
/// the delete arrives.
struct Case {
    /// What the row is, for the assertion messages.
    name: &'static str,
    /// The positions in the seeded attachment list the policy meters.
    attachments: &'static [usize],
    /// The tags it carries, as (key, value) pairs.
    tags: &'static [(&'static str, &'static str)],
    /// The state the policy must be in when the delete arrives.
    state_when_deleted: &'static str,
}

/// The deletes this suite is written against: a policy still in the transient state of its create,
/// one the clock has settled into service, one being modified — the state no implemented operation
/// leaves a policy in, so that row is seeded — with no middlebox attachment, one, and several, and
/// with no tags, one tag and two.
const CASES: &[Case] = &[
    Case {
        name: "a policy still pending, metering nothing, untagged",
        attachments: &[],
        tags: &[],
        state_when_deleted: "pending",
    },
    Case {
        name: "a policy in force, metering one attachment, with one tag",
        attachments: &[0],
        tags: &[("Name", "north")],
        state_when_deleted: "available",
    },
    Case {
        name: "a policy in force, metering three attachments, with two tags",
        attachments: &[2, 0, 3],
        tags: &[("Name", "south"), ("Team", "network")],
        state_when_deleted: "available",
    },
    Case {
        name: "a policy being modified, metering every attachment, untagged",
        attachments: &[0, 1, 2, 3],
        tags: &[],
        state_when_deleted: "modifying",
    },
];

/// The attachment ids at `positions` in the seeded list.
fn at(attachment_ids: &[String], positions: &[usize]) -> Vec<String> {
    positions
        .iter()
        .map(|position| attachment_ids[*position].clone())
        .collect()
}

/// The tags one case assigns, as owned pairs.
fn expected_tags(case: &Case) -> Vec<(String, String)> {
    case.tags
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// The policy one case deletes, in the state that case's delete must find it in: created over the
/// wire and, for the row whose state no implemented operation produces, seeded in it through the
/// store's own writer. Answers its `TransitGatewayMeteringPolicyId`.
async fn policy_for(
    case: &Case,
    router: &MultiServiceRouter,
    engine: &engine::InMemoryEngine,
    gateway_id: &str,
    attachment_ids: &[String],
) -> String {
    let name = case.name;
    if case.state_when_deleted == policy_state("modifying") {
        let store = engine.state::<Ec2State>();
        let mut guard = store.lock();
        return guard
            .insert_transit_gateway_metering_policy(TransitGatewayMeteringPolicy {
                transit_gateway_metering_policy_id: None,
                transit_gateway_id: Some(gateway_id.to_string()),
                middlebox_attachment_ids: Some(at(attachment_ids, case.attachments)),
                state: Some(policy_state("modifying").to_string()),
                update_effective_at: None,
                tags: (!case.tags.is_empty()).then(|| {
                    case.tags
                        .iter()
                        .map(|(key, value)| Tag {
                            key: Some((*key).to_string()),
                            value: Some((*value).to_string()),
                        })
                        .collect()
                }),
            })
            .unwrap_or_else(|| panic!("case {name:?}: the store holds the seeded policy"));
    }

    let mut params = vec![param("TransitGatewayId", gateway_id)];
    params.extend(middlebox_params(&at(attachment_ids, case.attachments)));
    if !case.tags.is_empty() {
        params.extend(tag_params(case.tags));
    }
    let (status, body) = invoke(router, CREATE, &params).await;
    assert_eq!(
        status, 200,
        "case {name:?}: expected HTTP 200 from {CREATE}, got {status} with body {body}"
    );
    let metering_policy_id = policy_member(name, &body, "transitGatewayMeteringPolicyId")
        .unwrap_or_else(|| panic!("case {name:?}: the create must report the policy's id"));
    if case.state_when_deleted == policy_state("available") {
        poll_until_state(name, router, &metering_policy_id, policy_state("available")).await;
    }
    metering_policy_id
}

/// Whether `state` is one of the two delete states this resource's catalog carries: what a policy
/// a delete has been recorded for is in, before or after the move the clock owes it.
fn is_a_delete_state(state: Option<&str>) -> bool {
    state == Some(policy_state("deleting")) || state == Some(policy_state("deleted"))
}

/// A delete reports the policy as the store now holds it: the transient delete state its own
/// catalog carries, every other member the store held for it unchanged, and the instant the change
/// takes effect — and the describe reads back the same record. One row per case, so no single
/// request is the specification.
#[tokio::test]
async fn a_delete_records_the_deletion_and_reports_the_policy_the_store_now_holds() {
    let (router, engine, gateway_id, attachment_ids) = seeded().await;

    for case in CASES {
        let name = case.name;
        let metering_policy_id =
            policy_for(case, &router, &engine, &gateway_id, &attachment_ids).await;
        let before = described_state(name, &router, &metering_policy_id).await;
        // A policy the clock still owes a move could have reached it by the time this look
        // happens on a loaded host, so only the states nothing is owed on are pinned exactly;
        // what every row asserts is that the delete below arrives at a policy no delete has
        // been recorded for.
        if case.state_when_deleted == policy_state("pending") {
            assert!(
                !is_a_delete_state(Some(before.as_str())),
                "case {name:?}: the delete must arrive at a policy no delete was recorded for, \
                 got {before:?}"
            );
        } else {
            assert_eq!(
                before,
                case.state_when_deleted,
                "case {name:?}: the delete must arrive at a policy in {expected:?}, got \
                 {before:?}",
                expected = case.state_when_deleted
            );
        }

        let (status, body) = delete(&router, &metering_policy_id).await;
        assert_eq!(
            status, 200,
            "case {name:?}: expected HTTP 200 from {ACTION}, got {status} with body {body}"
        );

        let reported_id = policy_member(name, &body, "transitGatewayMeteringPolicyId");
        assert_eq!(
            reported_id.as_deref(),
            Some(metering_policy_id.as_str()),
            "case {name:?}: expected the deleted policy's own id, got {reported_id:?} in {body}"
        );
        let reported_gateway = policy_member(name, &body, "transitGatewayId");
        assert_eq!(
            reported_gateway.as_deref(),
            Some(gateway_id.as_str()),
            "case {name:?}: expected the gateway the policy metered, got {reported_gateway:?} in \
             {body}"
        );
        let reported_state = policy_member(name, &body, "state");
        assert_eq!(
            reported_state.as_deref(),
            Some(policy_state("deleting")),
            "case {name:?}: expected the transient state of a delete, got {reported_state:?} in \
             {body}"
        );
        let reported_effective = policy_member(name, &body, "updateEffectiveAt");
        assert!(
            reported_effective.as_deref().and_then(as_timestamp).is_some(),
            "case {name:?}: expected the instant the change takes effect, got \
             {reported_effective:?} in {body}"
        );

        let expected_attachments = at(&attachment_ids, case.attachments);
        if expected_attachments.is_empty() {
            assert!(
                !has_member(name, &body, "middleboxAttachmentIdSet"),
                "case {name:?}: a policy metering no attachment reports no \
                 <middleboxAttachmentIdSet>, got {body}"
            );
        } else {
            let actual = reported_middlebox_attachments(name, &body);
            assert_eq!(
                actual, expected_attachments,
                "case {name:?}: expected the attachments the policy metered, got {actual:?} in \
                 {body}"
            );
        }
        let actual_tags = if case.tags.is_empty() {
            Vec::new()
        } else {
            reported_tags(name, &body)
        };
        assert_eq!(
            actual_tags,
            expected_tags(case),
            "case {name:?}: expected the tags the policy carried, got {actual_tags:?} in {body}"
        );

        // The store holds the deletion the call recorded — in the transient state or already in
        // the terminal one the clock owes it, never in the state the delete found it in.
        let held = stored_state(&engine, &metering_policy_id);
        assert!(
            is_a_delete_state(held.as_deref()),
            "case {name:?}: the store must hold the policy in a delete state, got {held:?}"
        );

        // The round trip: the describe reports the record the delete wrote rather than the one it
        // found, so the writer and every later reader cannot drift apart.
        let (status, read_back) = describe(&router, &metering_policy_id).await;
        assert_eq!(
            status, 200,
            "case {name:?}: expected HTTP 200 from {DESCRIBE}, got {status} with body {read_back}"
        );
        let read_back_state = policy_member(name, &read_back, "state");
        assert!(
            is_a_delete_state(read_back_state.as_deref()),
            "case {name:?}: expected a delete state from {DESCRIBE}, got {read_back_state:?} in \
             {read_back}"
        );
        for element_name in ["transitGatewayMeteringPolicyId", "transitGatewayId"] {
            let expected = policy_member(name, &body, element_name);
            let actual = policy_member(name, &read_back, element_name);
            assert_eq!(
                actual, expected,
                "case {name:?}: expected <{element_name}> {expected:?} from {DESCRIBE}, got \
                 {actual:?} in {read_back}"
            );
        }
        let read_back_attachments = if expected_attachments.is_empty() {
            Vec::new()
        } else {
            reported_middlebox_attachments(name, &read_back)
        };
        assert_eq!(
            read_back_attachments, expected_attachments,
            "case {name:?}: expected the stored attachments from {DESCRIBE}, got \
             {read_back_attachments:?} in {read_back}"
        );
        let read_back_tags = if case.tags.is_empty() {
            Vec::new()
        } else {
            reported_tags(name, &read_back)
        };
        assert_eq!(
            read_back_tags,
            expected_tags(case),
            "case {name:?}: expected the stored tags from {DESCRIBE}, got {read_back_tags:?} in \
             {read_back}"
        );
    }

    assert_eq!(
        stored_policies(&engine),
        CASES.len(),
        "a delete records the deletion rather than dropping the record, so the store must still \
         hold one policy per case"
    );
}

/// The move the clock owes a delete: a policy handed back `deleting` is `deleted` once the
/// transition span has passed, whether or not anybody called again, and it still reports every
/// other member the store holds for it. Driven for a policy metering nothing and one metering
/// several, so the move does not depend on what the policy carries.
#[tokio::test]
async fn the_clock_owes_a_deleted_policy_the_terminal_state_of_its_catalog() {
    let (router, engine, gateway_id, attachment_ids) = seeded().await;

    for case in [&CASES[0], &CASES[2]] {
        let name = case.name;
        let metering_policy_id =
            policy_for(case, &router, &engine, &gateway_id, &attachment_ids).await;
        let (status, body) = delete(&router, &metering_policy_id).await;
        assert_eq!(
            status, 200,
            "case {name:?}: expected HTTP 200 from {ACTION}, got {status} with body {body}"
        );

        let settled =
            poll_until_state(name, &router, &metering_policy_id, policy_state("deleted")).await;
        assert_eq!(
            stored_state(&engine, &metering_policy_id).as_deref(),
            Some(policy_state("deleted")),
            "case {name:?}: the store must hold the state the describe reported"
        );
        let expected_attachments = at(&attachment_ids, case.attachments);
        let settled_attachments = if expected_attachments.is_empty() {
            Vec::new()
        } else {
            reported_middlebox_attachments(name, &settled)
        };
        assert_eq!(
            settled_attachments, expected_attachments,
            "case {name:?}: a deleted policy still reports what it metered, got \
             {settled_attachments:?} in {settled}"
        );
    }
}

/// Deleting one policy records that one deletion and nothing else: every other policy of the
/// account is left in the state it was in, and the store still holds them all.
#[tokio::test]
async fn a_delete_leaves_every_other_policy_of_the_account_alone() {
    let (router, engine, gateway_id, attachment_ids) = seeded().await;
    let case = &CASES[1];
    let mut ids: Vec<String> = Vec::new();
    for _ in 0..3 {
        ids.push(policy_for(case, &router, &engine, &gateway_id, &attachment_ids).await);
    }

    let deleted = ids[1].clone();
    let (status, body) = delete(&router, &deleted).await;
    assert_eq!(
        status, 200,
        "expected HTTP 200 deleting {deleted}, got {status} with body {body}"
    );

    for untouched in [&ids[0], &ids[2]] {
        let state = described_state("the policies not named", &router, untouched).await;
        assert_eq!(
            state,
            policy_state("available"),
            "the policy {untouched} was not named by the delete, so it must still be in force, \
             got {state:?}"
        );
    }
    assert_eq!(
        stored_policies(&engine),
        ids.len(),
        "a delete records one deletion and drops no record, so the store must still hold every \
         policy"
    );
}

/// One refused delete: what the request names and the refusal it must answer.
struct Refusal {
    /// What the row is, for the assertion messages.
    name: &'static str,
    /// The `TransitGatewayMeteringPolicyId` the request names, or `None` for the policy the
    /// fixture created.
    metering_policy_id: Option<&'static str>,
    /// Whether the request asks for a dry run.
    dry_run: bool,
    /// The HTTP status it must answer.
    status: u16,
    /// The EC2 error code it must answer.
    code: &'static str,
}

/// The refusal every row below starts from: the fixture's own policy, nothing else.
const CLEAN: Refusal = Refusal {
    name: "",
    metering_policy_id: None,
    dry_run: false,
    status: REFUSAL_STATUS,
    code: "",
};

/// The refusals this suite is written against: three values that are not a metering policy id at
/// all (a word, the prefix with too few hex digits, and a hex body that is not hex), a well-formed
/// id this account holds no policy for, and a dry run — which is answered about PERMISSION, so it
/// wins over a policy that cannot be resolved but not over a request whose own form is wrong.
fn refusals() -> Vec<Refusal> {
    vec![
        Refusal {
            name: "a value that is no resource id at all",
            metering_policy_id: Some("metering-policy-one"),
            code: INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_MALFORMED,
            ..CLEAN
        },
        Refusal {
            name: "this resource's prefix with too few hex digits",
            metering_policy_id: Some("tgw-mp-0123"),
            code: INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_MALFORMED,
            ..CLEAN
        },
        Refusal {
            name: "this resource's prefix with a body that is not hexadecimal",
            metering_policy_id: Some("tgw-mp-0123456789abcdefg"),
            code: INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_MALFORMED,
            ..CLEAN
        },
        Refusal {
            name: "another resource's id",
            metering_policy_id: Some("tgw-ptb-0123456789abcdef0"),
            code: INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_MALFORMED,
            ..CLEAN
        },
        Refusal {
            name: "a well-formed id this account holds no policy for",
            metering_policy_id: Some("tgw-mp-0123456789abcdef0"),
            code: INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_NOT_FOUND,
            ..CLEAN
        },
        Refusal {
            name: "a well-formed short id this account holds no policy for",
            metering_policy_id: Some("tgw-mp-01234567"),
            code: INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_NOT_FOUND,
            ..CLEAN
        },
        Refusal {
            name: "a dry run naming the policy the fixture holds",
            dry_run: true,
            status: DRY_RUN_STATUS,
            code: DRY_RUN_OPERATION,
            ..CLEAN
        },
        Refusal {
            name: "a dry run naming an id this account holds no policy for",
            metering_policy_id: Some("tgw-mp-0123456789abcdef0"),
            dry_run: true,
            status: DRY_RUN_STATUS,
            code: DRY_RUN_OPERATION,
        },
        Refusal {
            name: "a dry run naming a value that is no resource id at all",
            metering_policy_id: Some("metering-policy-one"),
            dry_run: true,
            code: INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_MALFORMED,
            ..CLEAN
        },
    ]
}

/// A request this operation refuses answers that refusal's own code and records NOTHING: the
/// policy the account holds is left in the state it was in.
#[tokio::test]
async fn an_unusable_delete_is_refused_and_records_nothing() {
    let (router, engine, gateway_id, attachment_ids) = seeded().await;
    let case = &CASES[1];
    let metering_policy_id =
        policy_for(case, &router, &engine, &gateway_id, &attachment_ids).await;

    for refusal in refusals() {
        let name = refusal.name;
        let mut params = vec![param(
            "TransitGatewayMeteringPolicyId",
            refusal
                .metering_policy_id
                .unwrap_or(metering_policy_id.as_str()),
        )];
        if refusal.dry_run {
            params.push(param("DryRun", "true"));
        }

        let (status, body) = invoke(&router, ACTION, &params).await;
        assert_eq!(
            status, refusal.status,
            "case {name:?}: expected HTTP {expected} from {ACTION}, got {status} with body {body}",
            expected = refusal.status
        );
        let code = error_code(&body);
        assert_eq!(
            code, refusal.code,
            "case {name:?}: expected the {expected:?} refusal, got {code:?} in {body}",
            expected = refusal.code
        );
        // The sentence AWS words for this resource's `.NotFound`: fixed text with the id the
        // REQUEST carried interpolated, and nothing else.
        if refusal.code == INVALID_TRANSIT_GATEWAY_METERING_POLICY_ID_NOT_FOUND {
            let named = refusal
                .metering_policy_id
                .unwrap_or(metering_policy_id.as_str());
            let message = element(&body, "Message").unwrap_or_default();
            assert_eq!(
                message,
                format!("Transit Gateway Metering Policy Id {named} was deleted or does not exist."),
                "case {name:?}: expected this resource's own not-found sentence, got {message:?}"
            );
        }
        let held = stored_state(&engine, &metering_policy_id);
        assert_eq!(
            held.as_deref(),
            Some(policy_state("available")),
            "case {name:?}: a refused delete must leave the policy in the state it was in, got \
             {held:?}"
        );
    }

    assert_eq!(
        stored_policies(&engine),
        1,
        "a refused delete must drop no record"
    );
}

/// A policy a delete has already been recorded for is refused rather than deleted again — in the
/// transient delete state and in the terminal one the clock owes it, because either means the
/// deletion has been asked for. The refusal names the policy and the state it is in.
#[tokio::test]
async fn a_second_delete_of_the_same_policy_is_refused_for_the_state_it_is_in() {
    let (router, engine, gateway_id, attachment_ids) = seeded().await;
    let case = &CASES[1];
    let metering_policy_id =
        policy_for(case, &router, &engine, &gateway_id, &attachment_ids).await;
    let (status, body) = delete(&router, &metering_policy_id).await;
    assert_eq!(
        status, 200,
        "the first delete must succeed, got {status} with body {body}"
    );

    // The transient delete state, then the terminal one: the second row waits for the move the
    // clock owes, so what it names is the state nothing is owed on any more. The first row
    // names whichever delete state the policy is in when the call lands, because a loaded host
    // may have let the move fall due in between — either way the deletion has been asked for.
    for (case, settled) in [
        ("while the deletion is under way", false),
        ("once it has settled", true),
    ] {
        if settled {
            poll_until_state(case, &router, &metering_policy_id, policy_state("deleted")).await;
        }
        let (status, body) = delete(&router, &metering_policy_id).await;
        assert_eq!(
            status, REFUSAL_STATUS,
            "case {case:?}: expected HTTP {REFUSAL_STATUS} from a second {ACTION}, got {status} \
             with body {body}"
        );
        let code = error_code(&body);
        assert_eq!(
            code, INCORRECT_STATE,
            "case {case:?}: expected the {INCORRECT_STATE:?} refusal, got {code:?} in {body}"
        );
        let message = element(&body, "Message").unwrap_or_default();
        assert!(
            message.contains(&metering_policy_id),
            "case {case:?}: the refusal must name the policy {metering_policy_id}, got \
             {message:?}"
        );
        let named = if settled {
            message.contains(policy_state("deleted"))
        } else {
            message.contains(policy_state("deleting")) || message.contains(policy_state("deleted"))
        };
        assert!(
            named,
            "case {case:?}: the refusal must name the delete state the policy is in, got \
             {message:?}"
        );
        let held = stored_state(&engine, &metering_policy_id);
        assert!(
            is_a_delete_state(held.as_deref()),
            "case {case:?}: a refused second delete must leave the recorded deletion in place, \
             got {held:?}"
        );
    }
}
