// SPDX-License-Identifier: CC0-1.0

//! The authorization gate `AssociateVPCWithHostedZone` applies before it associates
//! anything, end to end over the router.
//!
//! The rule under test, from the operation's own documentation ("If you want to associate a
//! VPC that was created by using one Amazon Web Services account with a private hosted zone
//! that was created by using a different account, the Amazon Web Services account that
//! created the private hosted zone must first submit a CreateVPCAssociationAuthorization
//! request. Then the account that created the VPC must submit an AssociateVPCWithHostedZone
//! request."): a request may associate a VPC the calling account CREATED — one its Amazon
//! EC2 inventory holds — and a VPC it did not create only while the zone carries an
//! authorization for that VPC; anything else is `NotAuthorizedException` (HTTP 401) and
//! leaves the zone reporting exactly the VPCs it legitimately holds.
//!
//! Asserted over tables rather than one request, spanning what the rule generalises over:
//!
//! 1. whether the account holds the VPC, whether the zone authorizes it and whether some
//!    OTHER zone authorizes it, across both VPC id forms and several regions of the
//!    modelled `VPCRegion` enum;
//! 2. the permission an authorization opens is CLOSED again by
//!    `DeleteVPCAssociationAuthorization`, whether or not the VPC was associated in
//!    between;
//! 3. the refusal's message, which is built from the caller's identity and the request —
//!    the principal `sts:GetCallerIdentity` answers for the credential, the action
//!    `route53:AssociateVPCWithHostedZone`, and the VPC's own Amazon EC2 ARN in the region
//!    the request named;
//! 4. a zone the service cannot resolve is still the not-found refusal: a zone's
//!    authorizations cannot be consulted before the zone is.
//!
//! The harness (`router_holding_vpcs`, `call`, `Reply`) and every request builder come from
//! the suites that own those operations, so these tests drive the service through the same
//! router a socket-served request goes through.

use service_com_amazonaws_sts_awssecuritytokenservicev20110615::state as sts_state;

use crate::hosted_zone_records::router_holding_vpcs;
use crate::refusal_message_rules::message_of;
use crate::vpc_association_authorizations::authorize_ok;
use crate::vpc_associations::{
    associate, associations, create_private_zone, create_zone, get_zone, vpc_block, CREATION_VPC,
    HOME_REGION,
};
use crate::vpc_authorization_deletion::deauthorize_ok;
use crate::vpc_disassociation::disassociate;

/// The wire error code of the refusal under test, and the status the model gives it
/// (`smithy_query(query="operation",operation="AssociateVPCWithHostedZone")`:
/// `NotAuthorizedException`, httpError 401).
const NOT_AUTHORIZED: &str = "NotAuthorizedException";
const NOT_AUTHORIZED_STATUS: u16 = 401;

/// The message the service refuses an association the caller may not make with, with this
/// request's values filled in.
///
/// Written out here rather than called out of the service, so the form itself is asserted:
/// the principal the token service reports for the request's credential, the IAM action
/// (`<arnNamespace>:<operation>`) and the VPC as an Amazon EC2 resource ARN carrying the
/// region the request named and this emulator's account.
fn expected_message(vpc_id: &str, vpc_region: &str) -> String {
    let caller = sts_state::ambient_identity().arn;
    let account = ::engine::emulator_account_id();
    format!(
        "User: {caller} is not authorized to perform: route53:AssociateVPCWithHostedZone on \
         resource: arn:aws:ec2:{vpc_region}:{account}:vpc/{vpc_id}"
    )
}

// ---------------------------------------------------------------------------
// Rule 1: held by the account, or authorized by the zone — nothing else
// ---------------------------------------------------------------------------

/// Which zone, if any, authorizes the VPC of a row before it is associated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Authorization {
    /// No authorization anywhere.
    None,
    /// An authorization on the zone the request addresses.
    ThisZone,
    /// An authorization on ANOTHER private zone of the account, which permits nothing
    /// here: an authorization is held ON the zone it was created for.
    AnotherZone,
}

/// One row of the gate table.
struct GateRow {
    case: &'static str,
    vpc_id: &'static str,
    region: &'static str,
    /// Whether the account's Amazon EC2 inventory holds the VPC — whether it created it.
    held: bool,
    authorization: Authorization,
    /// Whether the association must be applied.
    accepted: bool,
}

#[tokio::test]
async fn only_a_vpc_the_account_holds_or_the_zone_authorizes_is_associated() {
    // The rows differ along the two halves of the decision, along the VPC id form (the
    // 8-character original and the 17-character long form) and along the region, drawn
    // from the modelled `VPCRegion` enum
    // (smithy_query(query="shape",shape="VPCRegion")) — including another partition's.
    let rows = [
        GateRow {
            case: "a VPC the account created, in the long id form",
            vpc_id: "vpc-0a1b2c3d4e5f60718",
            region: "ca-central-1",
            held: true,
            authorization: Authorization::None,
            accepted: true,
        },
        GateRow {
            case: "a VPC the account created, in the 8-character id form",
            vpc_id: "vpc-1a2b3c4d",
            region: "ap-southeast-2",
            held: true,
            authorization: Authorization::None,
            accepted: true,
        },
        GateRow {
            case: "a VPC of another account the zone authorizes",
            vpc_id: "vpc-00112233445566778",
            region: "il-central-1",
            held: false,
            authorization: Authorization::ThisZone,
            accepted: true,
        },
        GateRow {
            case: "a VPC the account did not create and nothing authorizes",
            vpc_id: "vpc-deadbeef",
            region: "cn-north-1",
            held: false,
            authorization: Authorization::None,
            accepted: false,
        },
        GateRow {
            case: "a VPC in the long id form that nothing authorizes",
            vpc_id: "vpc-0fedcba9876543210",
            region: "us-gov-west-1",
            held: false,
            authorization: Authorization::None,
            accepted: false,
        },
        GateRow {
            case: "a VPC only another zone authorizes",
            vpc_id: "vpc-5e6f7a8b",
            region: "eu-west-1",
            held: false,
            authorization: Authorization::AnotherZone,
            accepted: false,
        },
        GateRow {
            case: "a VPC the account created AND the zone authorizes",
            vpc_id: "vpc-00ff00ff00ff00ff0",
            region: "sa-east-1",
            held: true,
            authorization: Authorization::ThisZone,
            accepted: true,
        },
    ];

    // The account holds the VPC its private zone was created with, plus every row's VPC
    // the row says it created. Everything else is a VPC of some other account.
    let mut held: Vec<(&str, &str)> = vec![(CREATION_VPC, HOME_REGION)];
    held.extend(
        rows.iter()
            .filter(|row| row.held)
            .map(|row| (row.vpc_id, row.region)),
    );
    let router = router_holding_vpcs(&held);
    let zone_id = create_private_zone(
        &router,
        "gated.example.com",
        "associate-gate",
        CREATION_VPC,
    )
    .await;
    // A second zone, so an authorization held on the WRONG zone is a case of its own.
    let other_zone = create_private_zone(
        &router,
        "gated-other.example.com",
        "associate-gate-other",
        CREATION_VPC,
    )
    .await;

    // The zone starts with the association `CreateHostedZone` made, and grows by exactly
    // the accepted rows.
    let mut expected = vec![(CREATION_VPC.to_string(), HOME_REGION.to_string())];
    for row in &rows {
        match row.authorization {
            Authorization::None => {}
            Authorization::ThisZone => {
                authorize_ok(&router, &zone_id, row.vpc_id, row.region).await;
            }
            Authorization::AnotherZone => {
                authorize_ok(&router, &other_zone, row.vpc_id, row.region).await;
            }
        }

        let reply = associate(
            &router,
            &zone_id,
            &vpc_block(Some(row.vpc_id), Some(row.region)),
            None,
        )
        .await;
        if row.accepted {
            assert_eq!(
                reply.status, 200,
                "case {:?}: expected 200 from AssociateVPCWithHostedZone, got {} with body {}",
                row.case, reply.status, reply.body
            );
            assert!(
                reply.first("ChangeInfo/Id").is_some(),
                "case {:?}: an accepted association must answer with a change; body {}",
                row.case,
                reply.body
            );
            expected.push((row.vpc_id.to_string(), row.region.to_string()));
        } else {
            assert_eq!(
                reply.status, NOT_AUTHORIZED_STATUS,
                "case {:?}: expected HTTP {NOT_AUTHORIZED_STATUS}, got {} with body {}",
                row.case, reply.status, reply.body
            );
            assert_eq!(
                reply.error_code(),
                NOT_AUTHORIZED,
                "case {:?}: expected {NOT_AUTHORIZED}, got {:?}; body {}",
                row.case,
                reply.error_code(),
                reply.body
            );
            assert!(
                reply.first("ChangeInfo/Id").is_none(),
                "case {:?}: a refusal must answer with no change; body {}",
                row.case,
                reply.body
            );
        }

        // Whatever the row did, the zone reports exactly the associations it was
        // legitimately given.
        let read = get_zone(&router, &zone_id).await;
        let got = associations(&read);
        assert_eq!(
            got, expected,
            "case {:?}: GetHostedZone must report {expected:?}, got {got:?}; body {}",
            row.case, read.body
        );
    }

    // The zone that merely AUTHORIZED a VPC for another zone holds no association of it.
    let read = get_zone(&router, &other_zone).await;
    let got = associations(&read);
    assert_eq!(
        got,
        vec![(CREATION_VPC.to_string(), HOME_REGION.to_string())],
        "an authorization is no association: expected the other zone to hold only its \
         creation VPC, got {got:?}; body {}",
        read.body
    );
}

// ---------------------------------------------------------------------------
// Rule 2: a withdrawn authorization closes the permission it opened
// ---------------------------------------------------------------------------

#[tokio::test]
async fn withdrawing_an_authorization_refuses_the_association_it_had_permitted() {
    // The rows differ along what happened while the authorization was in force: nothing,
    // and an association that was then disassociated again — so the permission is read
    // off the authorization list in both.
    let rows = [
        (
            "an authorization that was never used",
            "vpc-1a2b3c4d",
            "eu-central-1",
            false,
        ),
        (
            "an authorization whose association was removed again",
            "vpc-0a1b2c3d4e5f60718",
            "eu-central-1",
            true,
        ),
    ];

    // Only the zone's own creation VPC belongs to this account: every row's VPC is
    // another account's, so the authorization is the whole permission.
    let router = router_holding_vpcs(&[(CREATION_VPC, HOME_REGION)]);
    let zone_id = create_private_zone(
        &router,
        "withdrawn.example.com",
        "associate-withdrawn",
        CREATION_VPC,
    )
    .await;
    let creation_only = vec![(CREATION_VPC.to_string(), HOME_REGION.to_string())];

    for (case, vpc_id, region, associate_first) in rows {
        authorize_ok(&router, &zone_id, vpc_id, region).await;
        if associate_first {
            let reply = associate(
                &router,
                &zone_id,
                &vpc_block(Some(vpc_id), Some(region)),
                None,
            )
            .await;
            assert_eq!(
                reply.status, 200,
                "case {case:?}: an authorized association must be accepted, got {} with \
                 body {}",
                reply.status, reply.body
            );
            let reply = disassociate(
                &router,
                &zone_id,
                &vpc_block(Some(vpc_id), Some(region)),
                None,
            )
            .await;
            assert_eq!(
                reply.status, 200,
                "case {case:?}: expected 200 from DisassociateVPCFromHostedZone, got {} with \
                 body {}",
                reply.status, reply.body
            );
        }

        deauthorize_ok(&router, &zone_id, vpc_id, region, case).await;
        let reply = associate(
            &router,
            &zone_id,
            &vpc_block(Some(vpc_id), Some(region)),
            None,
        )
        .await;
        assert_eq!(
            reply.status, NOT_AUTHORIZED_STATUS,
            "case {case:?}: expected HTTP {NOT_AUTHORIZED_STATUS} once the authorization was \
             withdrawn, got {} with body {}",
            reply.status, reply.body
        );
        assert_eq!(
            reply.error_code(),
            NOT_AUTHORIZED,
            "case {case:?}: expected {NOT_AUTHORIZED}, got {:?}; body {}",
            reply.error_code(),
            reply.body
        );

        let read = get_zone(&router, &zone_id).await;
        let got = associations(&read);
        assert_eq!(
            got, creation_only,
            "case {case:?}: the refused association must leave the zone at {creation_only:?}, \
             got {got:?}; body {}",
            read.body
        );
    }
}

// ---------------------------------------------------------------------------
// Rule 3: the refusal names the caller, the action and the VPC
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_refusal_names_the_calling_principal_the_action_and_the_vpc() {
    // The rows differ along the VPC id form and along the region the request named,
    // including regions of other partitions — the message carries the region the request
    // asked about, never the zone's own.
    let rows = [
        ("the 8-character id form", "vpc-7a8b9c0d", HOME_REGION),
        (
            "the 17-character long id form",
            "vpc-0123456789abcdef0",
            "eu-west-2",
        ),
        ("a China-partition region", "vpc-feedface", "cn-northwest-1"),
        (
            "a GovCloud region",
            "vpc-1111222233334444a",
            "us-gov-east-1",
        ),
    ];

    let router = router_holding_vpcs(&[(CREATION_VPC, HOME_REGION)]);
    let zone_id = create_private_zone(
        &router,
        "denial-text.example.com",
        "associate-denial-text",
        CREATION_VPC,
    )
    .await;

    for (case, vpc_id, region) in rows {
        let reply = associate(
            &router,
            &zone_id,
            &vpc_block(Some(vpc_id), Some(region)),
            None,
        )
        .await;
        assert_eq!(
            reply.status, NOT_AUTHORIZED_STATUS,
            "case {case:?}: expected HTTP {NOT_AUTHORIZED_STATUS}, got {} with body {}",
            reply.status, reply.body
        );
        let got = message_of(&reply, case);
        let expected = expected_message(vpc_id, region);
        assert_eq!(
            got, expected,
            "case {case:?}: expected message {expected:?}, got {got:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Rule 4: the zone is resolved before its authorizations are
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_zone_that_does_not_exist_is_still_the_not_found_refusal() {
    // A zone's authorization list cannot be consulted before the zone is resolved, so a
    // request naming no zone of the account is `NoSuchHostedZone` (HTTP 404) whichever VPC
    // it names. The rows differ along the VPC — one the account created and one it did not
    // — and along the id shape the zone was addressed by.
    let held = "vpc-0abcdef012345678a";
    let router = router_holding_vpcs(&[(CREATION_VPC, HOME_REGION), (held, HOME_REGION)]);
    // A public zone of the account, so the refusal is not merely "no zones exist".
    let public = create_zone(&router, "public.example.com", "gate-public", "").await;
    assert_eq!(
        public.status, 201,
        "expected 201 from CreateHostedZone, got {} with body {}",
        public.status, public.body
    );

    for (case, zone_id, vpc_id) in [
        ("a well-shaped id no zone carries", "ZNOSUCHZONE0001", held),
        ("an id of another shape", "not-a-zone-id", held),
        (
            "a VPC the account did not create either",
            "ZNOSUCHZONE0002",
            "vpc-aabbccdd",
        ),
    ] {
        let reply = associate(
            &router,
            zone_id,
            &vpc_block(Some(vpc_id), Some(HOME_REGION)),
            None,
        )
        .await;
        assert_eq!(
            reply.status, 404,
            "case {case:?}: expected HTTP 404, got {} with body {}",
            reply.status, reply.body
        );
        assert_eq!(
            reply.error_code(),
            "NoSuchHostedZone",
            "case {case:?}: expected NoSuchHostedZone, got {:?}; body {}",
            reply.error_code(),
            reply.body
        );
    }
}
