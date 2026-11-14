// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for `DeleteTransitGatewayVpcAttachment` and the describes it is read back
//! through, driven over the wire the service actually speaks: `ec2Query` — an
//! `application/x-www-form-urlencoded` POST whose body carries
//! `Action=DeleteTransitGatewayVpcAttachment`, answered with XML (README.md / OPERATIONS.md
//! "Wire protocol").
//!
//! The rule under test: a delete of a VPC attachment WRITES THE STORED ATTACHMENT into the
//! transient `deleting` member of its own state catalog with the clock owing it the terminal
//! `deleted`, and answers the record as the store then holds it — every other member unchanged
//! — so both describes report what the delete answered; an attachment that attaches nothing any
//! more neither blocks a new attachment of its VPC nor holds its transit gateway. It refuses
//! rather than reporting a deletion it did not perform: a value that is not an attachment id at
//! all with that resource's `Malformed` code, an id no VPC attachment of the account is held
//! under — including one naming an attachment of another kind — with its `NotFound` code naming
//! the VPC attachment this action's subject is, and an
//! attachment already leaving or finished with `IncorrectState`.
//!
//! Every table row is a distinct input along what that rule generalises over: which state the
//! attachment is in when the delete arrives (five non-terminal members of the catalog, one of
//! them reached by `CreateTransitGatewayVpcAttachment` itself rather than seeded), how many
//! subnets it names (none, one, two), whether it carries tags and how many, and whether it
//! carries an options block — plus one refusal row per unresolvable id form and per state that
//! admits no delete.
//!
//! Nothing here waits a fixed time for a state the clock owes: each look is taken again until
//! the describe reports the state, or a deadline far past the service's own transition span
//! passes.

use std::time::{Duration, Instant, SystemTime};

use ec2::ops::types::{
    TRANSIT_GATEWAY_ATTACHMENT_STATE_VALUES, Tag, TransitGatewayPeeringAttachment,
    TransitGatewayVpcAttachment, TransitGatewayVpcAttachmentOptions,
};
use ec2::state::{
    ComAmazonawsEc2Amazonec2State as Ec2State, INCORRECT_STATE,
    INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_MALFORMED,
    INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_MESSAGE,
    INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_NOT_FOUND, OPTION_DISABLE, OPTION_ENABLE,
    TRANSITION_DELAY, TransitGatewayAttachmentView, system_time_to_date_time,
};
use service_com_amazonaws_ec2_amazonec2 as ec2;
use smithy_server_runtime::MultiServiceRouter;

use super::ec2_query::{call, element, error_code, error_message, indexed};
use super::wire::{Param, child, child_text, document, param, set_items};

/// The Region every call here is signed for.
const REGION: &str = "us-east-1";

/// The ec2Query `Action` under test.
const ACTION: &str = "DeleteTransitGatewayVpcAttachment";

/// The describe this delete is read back through.
const DESCRIBE: &str = "DescribeTransitGatewayVpcAttachments";

/// The whole-family describe, which reports the same record.
const FAMILY_DESCRIBE: &str = "DescribeTransitGatewayAttachments";

/// The HTTP status EC2 answers `DryRunOperation` with.
const DRY_RUN_STATUS: u16 = 412;

/// The HTTP status EC2 answers a refused request with.
const REFUSAL_STATUS: u16 = 400;

/// A well-formed EC2 id suffix — 17 lowercase hex digits — that nothing in this store mints, so
/// an id built from it is well formed and names no resource.
const UNKNOWN_SUFFIX: &str = "00000000000000000";

/// The account the peering fixture names as the owner of the peer gateway, so the attachment of
/// the OTHER kind the refusals use is a complete record.
const PEER_ACCOUNT: &str = "210987654321";

/// The deadline the polls below give up at: a large multiple of the service's own transition
/// span, so the assertion is about the state the clock owes and never about how fast the host
/// runs.
fn move_deadline() -> Duration {
    TRANSITION_DELAY * 60
}

/// How long one look waits before looking again — a fraction of that span, so a poll inside the
/// deadline above costs many looks rather than one.
fn poll_interval() -> Duration {
    TRANSITION_DELAY / 10
}

/// The value `name` names in the modelled `TransitGatewayAttachmentState` catalog
/// (`smithy_query(query="shape",shape="TransitGatewayAttachmentState")`, re-exported from
/// `ec2::ops::types`), or a panic — so every state written into a fixture or asserted on comes
/// from the model rather than from this file.
fn attachment_state(name: &str) -> &'static str {
    TRANSIT_GATEWAY_ATTACHMENT_STATE_VALUES
        .iter()
        .find(|value| **value == name)
        .unwrap_or_else(|| panic!("{name:?} is no TransitGatewayAttachmentState member"))
}

/// One call of `action` signed for the Region above.
async fn invoke(router: &MultiServiceRouter, action: &str, params: &[Param]) -> (u16, String) {
    call(router, REGION, action, params).await
}

/// One successful call of `action`, as its body.
async fn ok_body(case: &str, router: &MultiServiceRouter, action: &str, params: &[Param]) -> String {
    let (status, body) = invoke(router, action, params).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from {action}, got {status} with body {body}"
    );
    body
}

/// One reported `TransitGatewayVpcAttachment`, read out of the XML by the document rather than
/// by string surgery — the delete answers one and the describe answers a set of them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reported {
    attachment_id: String,
    transit_gateway_id: String,
    vpc_id: String,
    vpc_owner_id: String,
    state: String,
    subnet_ids: Vec<String>,
    creation_time: String,
    options: Vec<(String, String)>,
    tags: Vec<(String, String)>,
}

/// The text of every `item` of the `name` set of `node`, in document order.
fn item_texts(node: roxmltree::Node<'_, '_>, name: &str) -> Vec<String> {
    set_items(node, name)
        .into_iter()
        .map(|entry| entry.text().unwrap_or_default().to_string())
        .collect()
}

/// Every VPC attachment a response carries, in document order: the elements that have both a
/// `transitGatewayAttachmentId` and a `vpcOwnerId` child, whether the response is the delete's
/// single `transitGatewayVpcAttachment` or a describe's set.
fn reported_all(case: &str, body: &str) -> Vec<Reported> {
    let parsed = document(case, body);
    parsed
        .descendants()
        .filter(|node| {
            node.is_element()
                && child(*node, "transitGatewayAttachmentId").is_some()
                && child(*node, "vpcOwnerId").is_some()
        })
        .map(|item| Reported {
            attachment_id: child_text(item, "transitGatewayAttachmentId").unwrap_or_default(),
            transit_gateway_id: child_text(item, "transitGatewayId").unwrap_or_default(),
            vpc_id: child_text(item, "vpcId").unwrap_or_default(),
            vpc_owner_id: child_text(item, "vpcOwnerId").unwrap_or_default(),
            state: child_text(item, "state").unwrap_or_default(),
            subnet_ids: item_texts(item, "subnetIds"),
            creation_time: child_text(item, "creationTime").unwrap_or_default(),
            options: child(item, "options")
                .map(|options| {
                    options
                        .children()
                        .filter(roxmltree::Node::is_element)
                        .map(|member| {
                            (
                                member.tag_name().name().to_string(),
                                member.text().unwrap_or_default().to_string(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            tags: set_items(item, "tagSet")
                .into_iter()
                .map(|tag| {
                    (
                        child_text(tag, "key").unwrap_or_default(),
                        child_text(tag, "value").unwrap_or_default(),
                    )
                })
                .collect(),
        })
        .collect()
}

/// The one VPC attachment a response carries, or a panic naming the case.
fn reported(case: &str, body: &str) -> Reported {
    let mut all = reported_all(case, body);
    assert_eq!(
        all.len(),
        1,
        "case {case:?}: expected exactly one VPC attachment, got {all:?} in {body}"
    );
    all.remove(0)
}

/// The one VPC attachment the describe reports for `attachment_id`.
async fn described(case: &str, router: &MultiServiceRouter, attachment_id: &str) -> Reported {
    let body = ok_body(
        case,
        router,
        DESCRIBE,
        &indexed("TransitGatewayAttachmentIds", &[attachment_id]),
    )
    .await;
    reported(case, &body)
}

/// Look at the attachment AGAIN until the describe reports it in `wanted`, or a deadline far
/// past the service's own transition span passes — the condition is waited for, never a fixed
/// time, so nothing here depends on how fast the host runs.
async fn poll_until_state(
    case: &str,
    router: &MultiServiceRouter,
    attachment_id: &str,
    wanted: &str,
) -> Reported {
    let deadline = Instant::now() + move_deadline();
    loop {
        let seen = described(case, router, attachment_id).await;
        if seen.state == wanted {
            return seen;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected {attachment_id} to reach {wanted:?}, got {state:?}",
            state = seen.state
        );
        tokio::time::sleep(poll_interval()).await;
    }
}

/// The options block every seeded attachment carries, so the delete's answer is compared over a
/// record that holds one. The four members are each a value of their own modelled catalog, taken
/// from the shared `enable`/`disable` constants this crate reads such an option through.
fn seeded_options() -> TransitGatewayVpcAttachmentOptions {
    TransitGatewayVpcAttachmentOptions {
        dns_support: Some(OPTION_ENABLE.to_string()),
        security_group_referencing_support: Some(OPTION_DISABLE.to_string()),
        ipv6_support: Some(OPTION_ENABLE.to_string()),
        appliance_mode_support: Some(OPTION_DISABLE.to_string()),
    }
}

/// The emulator with one transit gateway, one VPC and two subnets of it: the router to call and
/// the engine to read the store through.
struct Fixture {
    router: MultiServiceRouter,
    engine: std::sync::Arc<engine::InMemoryEngine>,
    transit_gateway_id: String,
    vpc_id: String,
    subnet_ids: Vec<String>,
}

impl Fixture {
    async fn new() -> Self {
        let (router, engine) = super::ec2_query::emulator();
        let gateway_body = ok_body("the gateway", &router, "CreateTransitGateway", &[]).await;
        let transit_gateway_id = element(&gateway_body, "transitGatewayId")
            .expect("a created transit gateway reports its own id");

        let vpc_body = ok_body(
            "the network",
            &router,
            "CreateVpc",
            &[param("CidrBlock", "10.70.0.0/16")],
        )
        .await;
        let vpc_id = element(&vpc_body, "vpcId").expect("a created VPC reports its own id");

        let mut subnet_ids = Vec::new();
        for (index, zone) in ["us-east-1a", "us-east-1b"].into_iter().enumerate() {
            let body = ok_body(
                "the network",
                &router,
                "CreateSubnet",
                &[
                    param("VpcId", &vpc_id),
                    param("CidrBlock", &format!("10.70.{index}.0/24")),
                    param("AvailabilityZone", zone),
                ],
            )
            .await;
            subnet_ids.push(element(&body, "subnetId").expect("a created subnet reports its id"));
        }

        Self {
            router,
            engine,
            transit_gateway_id,
            vpc_id,
            subnet_ids,
        }
    }

    /// Seed one VPC attachment of the fixture's VPC in `state`, naming the first `subnets` of
    /// the fixture's subnets and carrying `tags`, straight through the store's own writer — so a
    /// row can put the attachment in a state no implemented operation leaves one in. Answers its
    /// `TransitGatewayAttachmentId`.
    fn seed(&self, state: &str, subnets: usize, tags: &[(&str, &str)]) -> String {
        let tag_list: Vec<Tag> = tags
            .iter()
            .map(|(key, value)| Tag {
                key: Some((*key).to_string()),
                value: Some((*value).to_string()),
            })
            .collect();
        self.engine
            .state::<Ec2State>()
            .lock()
            .insert_transit_gateway_attachment(TransitGatewayAttachmentView::Vpc(
                TransitGatewayVpcAttachment {
                    transit_gateway_attachment_id: None,
                    transit_gateway_id: Some(self.transit_gateway_id.clone()),
                    vpc_id: Some(self.vpc_id.clone()),
                    vpc_owner_id: Some(engine::emulator_account_id().to_string()),
                    state: Some(state.to_string()),
                    subnet_ids: Some(self.subnet_ids[..subnets].to_vec()),
                    creation_time: Some(system_time_to_date_time(SystemTime::now())),
                    options: Some(seeded_options()),
                    tags: (!tag_list.is_empty()).then_some(tag_list),
                },
            ))
            .expect("the attachment store has room for one seeded attachment")
    }

    /// Seed one attachment of ANOTHER kind — a transit gateway peering attachment — so a refusal
    /// row can name an id this operation cannot act on.
    fn seed_peering(&self) -> String {
        self.engine
            .state::<Ec2State>()
            .lock()
            .insert_transit_gateway_attachment(TransitGatewayAttachmentView::Peering(
                TransitGatewayPeeringAttachment {
                    state: Some(attachment_state("available").to_string()),
                    accepter_tgw_info: None,
                    requester_tgw_info: None,
                    creation_time: Some(system_time_to_date_time(SystemTime::now())),
                    tags: Some(vec![Tag {
                        key: Some("Owner".to_string()),
                        value: Some(PEER_ACCOUNT.to_string()),
                    }]),
                    ..Default::default()
                },
            ))
            .expect("the attachment store has room for one seeded peering attachment")
    }

    /// Every attachment the store holds, by the id it is held under and the state it is in, as
    /// the store ACTUALLY holds them — what a refusal must leave untouched.
    fn stored_states(&self) -> Vec<(String, String)> {
        self.engine
            .state::<Ec2State>()
            .lock()
            .transit_gateway_attachments
            .iter()
            .map(|(attachment_id, record)| {
                (
                    attachment_id.clone(),
                    record.view.state().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }

    /// The state and the owed move the store holds for `attachment_id`, read straight off the
    /// record rather than through a describe, so what the delete WROTE is asserted without
    /// depending on how much of the clock's span has passed.
    fn stored_move(&self, attachment_id: &str) -> (String, Option<String>) {
        let handle = self.engine.state::<Ec2State>();
        let store = handle.lock();
        let record = store
            .transit_gateway_attachments
            .get(attachment_id)
            .unwrap_or_else(|| panic!("the store must still hold {attachment_id}"));
        (
            record.view.state().unwrap_or_default().to_string(),
            record
                .pending
                .as_ref()
                .map(|pending| pending.to.clone()),
        )
    }

    /// One `DeleteTransitGatewayVpcAttachment` call naming `attachment_id`, with `extra` form
    /// fields beside it.
    async fn delete(&self, attachment_id: &str, extra: &[Param]) -> (u16, String) {
        let mut params = vec![param("TransitGatewayAttachmentId", attachment_id)];
        params.extend_from_slice(extra);
        invoke(&self.router, ACTION, &params).await
    }
}

/// One attachment to delete: the state it is in when the delete arrives, how many subnets it
/// names and the tags it carries.
struct Case {
    label: &'static str,
    /// The `TransitGatewayAttachmentState` member the attachment is in, or `None` for the row
    /// whose attachment `CreateTransitGatewayVpcAttachment` itself makes.
    seeded_state: Option<&'static str>,
    subnets: usize,
    tags: &'static [(&'static str, &'static str)],
}

/// Every non-terminal state a VPC attachment can be in when a delete arrives admits it: the
/// record is written into `deleting` with the clock owing it `deleted`, the answer carries the
/// stored record with every other member unchanged, and both describes report the same.
#[tokio::test]
async fn a_delete_writes_the_attachment_into_deleting_and_owes_it_deleted() {
    let cases = [
        Case {
            label: "an attachment in service, two subnets, two tags",
            seeded_state: Some("available"),
            subnets: 2,
            tags: &[("Name", "north"), ("Team", "network")],
        },
        Case {
            label: "an attachment still pending, one subnet, one tag",
            seeded_state: Some("pending"),
            subnets: 1,
            tags: &[("Name", "south")],
        },
        Case {
            label: "an attachment waiting for acceptance, no subnets, no tags",
            seeded_state: Some("pendingAcceptance"),
            subnets: 0,
            tags: &[],
        },
        Case {
            label: "an attachment being modified, two subnets, no tags",
            seeded_state: Some("modifying"),
            subnets: 2,
            tags: &[],
        },
        Case {
            label: "an attachment rolling back, one subnet, no tags",
            seeded_state: Some("rollingBack"),
            subnets: 1,
            tags: &[],
        },
        Case {
            label: "an attachment the create itself made",
            seeded_state: None,
            subnets: 1,
            tags: &[],
        },
    ];

    for case in &cases {
        let label = case.label;
        let fixture = Fixture::new().await;
        let attachment_id = match case.seeded_state {
            Some(state) => fixture.seed(attachment_state(state), case.subnets, case.tags),
            None => {
                let mut params = vec![
                    param("TransitGatewayId", &fixture.transit_gateway_id),
                    param("VpcId", &fixture.vpc_id),
                ];
                params.extend(indexed(
                    "SubnetIds",
                    &fixture.subnet_ids[..case.subnets]
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                ));
                let body = ok_body(label, &fixture.router, "CreateTransitGatewayVpcAttachment", &params)
                    .await;
                reported(label, &body).attachment_id
            }
        };

        let before = described(label, &fixture.router, &attachment_id).await;

        let (status, body) = fixture.delete(&attachment_id, &[]).await;
        assert_eq!(
            status, 200,
            "case {label:?}: expected HTTP 200, got {status} with body {body}"
        );
        let answered = reported(label, &body);
        assert_eq!(
            answered.state,
            attachment_state("deleting"),
            "case {label:?}: expected the answer to carry the transient delete state, got \
             {answered:?}"
        );
        // Every member but the state is the one the store already held: the delete reports the
        // record, it does not rebuild it.
        assert_eq!(
            Reported {
                state: before.state.clone(),
                ..answered.clone()
            },
            before,
            "case {label:?}: expected every member but the state to be the stored one, got \
             {answered:?} where {before:?} was held"
        );

        // What the delete WROTE, read straight off the record: the transient state now, the
        // terminal one owed. No span has to have passed for this to hold.
        let (stored_state, owed) = fixture.stored_move(&attachment_id);
        assert_eq!(
            stored_state,
            attachment_state("deleting"),
            "case {label:?}: expected the store to hold the transient delete state, got \
             {stored_state:?}"
        );
        assert_eq!(
            owed.as_deref(),
            Some(attachment_state("deleted")),
            "case {label:?}: expected the clock to owe the terminal delete state, got {owed:?}"
        );

        // And the move the clock owed lands, on both describes.
        let settled = poll_until_state(
            label,
            &fixture.router,
            &attachment_id,
            attachment_state("deleted"),
        )
        .await;
        assert_eq!(
            Reported {
                state: before.state.clone(),
                ..settled.clone()
            },
            before,
            "case {label:?}: expected the settled record to differ from the stored one only in \
             its state, got {settled:?}"
        );
        let family = ok_body(
            label,
            &fixture.router,
            FAMILY_DESCRIBE,
            &indexed("TransitGatewayAttachmentIds", &[&attachment_id]),
        )
        .await;
        let family_state = element(&family, "state");
        assert_eq!(
            family_state.as_deref(),
            Some(attachment_state("deleted")),
            "case {label:?}: expected {FAMILY_DESCRIBE} to report the deleted state, got \
             {family_state:?} in {family}"
        );
    }
}

/// A second delete of the same attachment is refused with the attachment family's own
/// `IncorrectState`, whether the first delete is still under way or has settled.
#[tokio::test]
async fn a_second_delete_of_one_attachment_is_refused() {
    let fixture = Fixture::new().await;
    let attachment_id = fixture.seed(attachment_state("available"), 1, &[]);
    let (status, body) = fixture.delete(&attachment_id, &[]).await;
    assert_eq!(
        status, 200,
        "the first delete must succeed, got {status} with body {body}"
    );

    for case in ["straight after the first delete", "once the move has landed"] {
        if case == "once the move has landed" {
            poll_until_state(
                case,
                &fixture.router,
                &attachment_id,
                attachment_state("deleted"),
            )
            .await;
        }
        let (status, body) = fixture.delete(&attachment_id, &[]).await;
        assert_eq!(
            status, REFUSAL_STATUS,
            "case {case:?}: expected HTTP {REFUSAL_STATUS}, got {status} with body {body}"
        );
        let code = error_code(&body);
        assert_eq!(
            code, INCORRECT_STATE,
            "case {case:?}: expected the code {INCORRECT_STATE:?}, got {code:?} with body {body}"
        );
        let message = error_message(&body);
        let expected = format!("{attachment_id} is in invalid state");
        assert_eq!(
            message, expected,
            "case {case:?}: expected the message {expected:?}, got {message:?}"
        );
    }
}

/// One refusal to drive: the id it names, and the code and sentence EC2 answers it with.
struct Refusal {
    label: String,
    attachment_id: String,
    code: String,
    message: String,
}

/// Every refusal of this delete carries EC2's own code and sentence, and writes nothing.
#[tokio::test]
async fn the_delete_refuses_what_it_cannot_delete() {
    let fixture = Fixture::new().await;
    // One attachment per state that admits no delete, beside a live one the refusals must leave
    // exactly as it is.
    let live = fixture.seed(attachment_state("available"), 2, &[("Name", "live")]);
    let mut refusals: Vec<Refusal> = Vec::new();

    // Not a transit gateway attachment id at all: the wrong resource's prefix, no prefix, a
    // digit count outside the id form, upper-case hex and an empty suffix. The sentence is
    // entirely fixed — this refusal interpolates nothing a caller sent.
    for malformed in [
        "tgw-0123456789abcdef0",
        "not-an-attachment-id",
        "tgw-attach-0123456789ab",
        "tgw-attach-0123456789ABCDEF0",
        "tgw-attach-",
    ] {
        refusals.push(Refusal {
            label: format!("malformed attachment id {malformed:?}"),
            attachment_id: malformed.to_string(),
            code: INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_MALFORMED.to_string(),
            message: INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_MESSAGE.to_string(),
        });
    }

    // Well formed, but no attachment of the account is held under it. The sentence names the
    // VPC attachment this action's subject is, which is the resource the transit gateway family
    // words this refusal about.
    let unknown = format!("tgw-attach-{UNKNOWN_SUFFIX}");
    refusals.push(Refusal {
        label: "an attachment id naming nothing".to_string(),
        attachment_id: unknown.clone(),
        code: INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_NOT_FOUND.to_string(),
        message: format!("Transit Gateway VPC Attachment {unknown} was deleted or does not exist."),
    });

    // An attachment of ANOTHER kind: every kind shares one id space, so this id names no
    // attachment THIS operation can delete.
    let peering = fixture.seed_peering();
    refusals.push(Refusal {
        label: "an attachment of another kind".to_string(),
        attachment_id: peering.clone(),
        code: INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_NOT_FOUND.to_string(),
        message: format!(
            "Transit Gateway VPC Attachment {peering} was deleted or does not exist."
        ),
    });

    // Every state in which the attachment attaches nothing any more, so there is nothing left
    // for a delete to take away: the terminal ones that are not "in service", and the transient
    // ones on the way to each of them.
    for state in [
        "deleting",
        "deleted",
        "rejecting",
        "rejected",
        "failing",
        "failed",
    ] {
        let attachment_id = fixture.seed(attachment_state(state), 1, &[]);
        refusals.push(Refusal {
            label: format!("an attachment in {state:?}"),
            attachment_id: attachment_id.clone(),
            code: INCORRECT_STATE.to_string(),
            message: format!("{attachment_id} is in invalid state"),
        });
    }

    let before = fixture.stored_states();
    for refusal in &refusals {
        let label = &refusal.label;
        let (status, body) = fixture.delete(&refusal.attachment_id, &[]).await;
        assert_eq!(
            status, REFUSAL_STATUS,
            "case {label:?}: expected HTTP {REFUSAL_STATUS}, got {status} with body {body}"
        );
        let code = error_code(&body);
        assert_eq!(
            code, refusal.code,
            "case {label:?}: expected the code {:?}, got {code:?} with body {body}",
            refusal.code
        );
        let message = error_message(&body);
        assert_eq!(
            message, refusal.message,
            "case {label:?}: expected the message {:?}, got {message:?}",
            refusal.message
        );
        let now = fixture.stored_states();
        assert_eq!(
            now, before,
            "case {label:?}: a refusal must write nothing, got {now:?} where {before:?} was held"
        );
    }

    // The live attachment is untouched by every refusal above, and its own delete still works.
    let (status, body) = fixture.delete(&live, &[]).await;
    assert_eq!(
        status, 200,
        "the live attachment must still be deletable, got {status} with body {body}"
    );
}

/// A dry run of a request that would have succeeded is refused with `DryRunOperation` and writes
/// nothing; the id's own form is read before the permission check.
#[tokio::test]
async fn a_dry_run_writes_nothing() {
    let case = "DryRun";
    let fixture = Fixture::new().await;
    let attachment_id = fixture.seed(attachment_state("available"), 2, &[("Name", "kept")]);
    let before = fixture.stored_states();

    let (status, body) = fixture
        .delete(&attachment_id, &[param("DryRun", "true")])
        .await;
    assert_eq!(
        status, DRY_RUN_STATUS,
        "case {case:?}: expected HTTP {DRY_RUN_STATUS}, got {status} with body {body}"
    );
    let now = fixture.stored_states();
    assert_eq!(
        now, before,
        "case {case:?}: a dry run must write nothing, got {now:?} where {before:?} was held"
    );

    // The id's own form precedes the permission answer, so a dry run naming something that is
    // no attachment id is refused for the request instead.
    let (status, body) = fixture
        .delete("not-an-attachment-id", &[param("DryRun", "true")])
        .await;
    assert_eq!(
        status, REFUSAL_STATUS,
        "case {case:?}: a malformed id must be refused before the dry run, got {status} with \
         body {body}"
    );
    let code = error_code(&body);
    assert_eq!(
        code, INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_MALFORMED,
        "case {case:?}: expected the code \
         {INVALID_TRANSIT_GATEWAY_ATTACHMENT_ID_MALFORMED:?}, got {code:?}"
    );
}

/// An attachment this delete has finished with attaches nothing: the VPC it named can be
/// attached to the same transit gateway again, and the gateway it was on can itself be deleted.
#[tokio::test]
async fn a_deleted_attachment_holds_neither_its_vpc_nor_its_gateway() {
    let case = "a deleted attachment holds nothing";
    let fixture = Fixture::new().await;
    let params = [
        param("TransitGatewayId", &fixture.transit_gateway_id),
        param("VpcId", &fixture.vpc_id),
        param("SubnetIds.1", &fixture.subnet_ids[0]),
    ];
    let created = ok_body(
        case,
        &fixture.router,
        "CreateTransitGatewayVpcAttachment",
        &params,
    )
    .await;
    let attachment_id = reported(case, &created).attachment_id;

    let (status, body) = fixture.delete(&attachment_id, &[]).await;
    assert_eq!(
        status, 200,
        "case {case:?}: the delete must succeed, got {status} with body {body}"
    );
    poll_until_state(
        case,
        &fixture.router,
        &attachment_id,
        attachment_state("deleted"),
    )
    .await;

    // The same VPC on the same gateway is a new attachment, not a duplicate of the deleted one.
    let again = ok_body(
        case,
        &fixture.router,
        "CreateTransitGatewayVpcAttachment",
        &params,
    )
    .await;
    let replacement = reported(case, &again).attachment_id;
    assert_ne!(
        replacement, attachment_id,
        "case {case:?}: expected a freshly minted attachment, got the deleted one"
    );

    // That replacement holds the gateway, so the gateway's own delete is refused for it; once it
    // too is deleted, nothing holds the gateway any more.
    let (status, body) = invoke(
        &fixture.router,
        "DeleteTransitGateway",
        &[param("TransitGatewayId", &fixture.transit_gateway_id)],
    )
    .await;
    assert_eq!(
        status, REFUSAL_STATUS,
        "case {case:?}: a gateway with a live attachment must not be deletable, got {status} \
         with body {body}"
    );
    let code = error_code(&body);
    assert_eq!(
        code, INCORRECT_STATE,
        "case {case:?}: expected the code {INCORRECT_STATE:?}, got {code:?} with body {body}"
    );

    let (status, body) = fixture.delete(&replacement, &[]).await;
    assert_eq!(
        status, 200,
        "case {case:?}: the replacement must be deletable, got {status} with body {body}"
    );
    poll_until_state(
        case,
        &fixture.router,
        &replacement,
        attachment_state("deleted"),
    )
    .await;

    let body = ok_body(
        case,
        &fixture.router,
        "DeleteTransitGateway",
        &[param("TransitGatewayId", &fixture.transit_gateway_id)],
    )
    .await;
    let state = element(&body, "state");
    assert_eq!(
        state.as_deref(),
        Some("deleting"),
        "case {case:?}: expected the gateway's own delete to report its transient state, got \
         {state:?} in {body}"
    );
}
