// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for `DeleteTransitGatewayConnectPeer`, driven over the wire the service
//! speaks — `ec2Query`, an `application/x-www-form-urlencoded` POST answered with XML
//! (README.md / OPERATIONS.md "Wire protocol") — together with the
//! `CreateTransitGatewayConnectPeer` that puts the peer there and the
//! `DescribeTransitGatewayConnectPeers` that reads it back.
//!
//! The rule under test: deleting a Connect peer records the deletion on the STORED peer the
//! request names and on nothing else, so the call answers that record in the transient state of
//! the peer's own state catalog with every other member exactly as it was stored, the clock then
//! owes it the terminal one, and the describe reports both of those states in turn. An id of the
//! wrong form is refused as malformed before anything is resolved, a well-formed id this account
//! holds no peer for as that resource's own not-found, a peer whose deletion has already been
//! asked for as being in the wrong state, and a dry run reports the outcome without recording
//! it. Once a deletion has settled, the interior ranges and the transit gateway address that peer
//! held are free for the next peer of the same transit gateway.
//!
//! Each table row is a distinct input along what that generalises over: whether the peer is still
//! `pending` or already `available` when the delete arrives, how many inside ranges it peers over
//! and of which families, whether its transit gateway address was named by the request or
//! assigned, and whether it carries tags.

use std::time::Duration;

use ec2::ops::types::{TransitGatewayConnect, TransitGatewayConnectOptions};
use ec2::state::{
    CONNECT_PEER_STATE_AVAILABLE, CONNECT_PEER_STATE_DELETED, CONNECT_PEER_STATE_DELETING,
    CONNECT_PEER_STATE_PENDING, ComAmazonawsEc2Amazonec2State as Ec2State, PROTOCOL_VALUE_GRE,
    RESOURCE_TYPE_TRANSIT_GATEWAY_CONNECT_PEER, TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE,
    TRANSIT_GATEWAY_CONNECT_PEER_ID_PREFIX, TransitGatewayAttachmentView,
};
use service_com_amazonaws_ec2_amazonec2 as ec2;
use smithy_server_runtime::MultiServiceRouter;

use super::ec2_query::{call, elements, error_code, error_message, indexed};
use super::wire::{Param, child, child_text, document, param, set_items};

/// The Region every call here is signed for.
const REGION: &str = "us-east-1";

/// The IPv4 CIDR block the fixture's transit gateway carries, which an unnamed
/// `TransitGatewayAddress` is assigned out of.
const GATEWAY_IPV4_BLOCK: &str = "10.100.0.0/24";

/// The IPv6 CIDR block the fixture's transit gateway carries, for the peers whose two GRE outer
/// addresses are IPv6.
const GATEWAY_IPV6_BLOCK: &str = "2001:db8:1::/64";

/// The HTTP status EC2 answers `DryRunOperation` with.
const DRY_RUN_STATUS: u16 = 412;

/// `InvalidTransitGatewayConnectPeerID.Malformed`: the request named something that is no
/// Connect peer id at all.
const MALFORMED_CODE: &str = "InvalidTransitGatewayConnectPeerID.Malformed";

/// `InvalidTransitGatewayConnectPeerID.NotFound`: a well-formed id this account holds no peer
/// for.
const NOT_FOUND_CODE: &str = "InvalidTransitGatewayConnectPeerID.NotFound";

/// `IncorrectState`: the peer exists but is not in a state that admits a delete.
const INCORRECT_STATE_CODE: &str = "IncorrectState";

/// Long enough past the span a clock-owed move takes that it is certainly overdue: the deadline
/// the polls below give up at, generous because what is under test is the state a peer reaches
/// rather than how fast it reaches it.
const MOVE_DEADLINE: Duration = Duration::from_secs(60);

/// How long a poll below waits between two reads of a peer's state.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The emulator, a transit gateway with one CIDR block of each family, and one Connect
/// attachment on it in service.
struct Fixture {
    router: MultiServiceRouter,
    engine: std::sync::Arc<engine::InMemoryEngine>,
    attachment_id: String,
}

impl Fixture {
    /// A fresh emulator holding nothing but the gateway and the attachment a peer needs.
    ///
    /// The transit gateway is created over the wire, so the CIDR blocks a peer's transit gateway
    /// address is assigned out of are the ones that operation really stored; the Connect
    /// attachment is seeded straight into the store in the one state a create admits, the way
    /// the Connect peer suite beside this one seeds it.
    async fn new() -> Self {
        let (router, engine) = super::ec2_query::emulator();
        let (status, body) = call(
            &router,
            REGION,
            "CreateTransitGateway",
            &[
                param("Options.TransitGatewayCidrBlocks.1", GATEWAY_IPV4_BLOCK),
                param("Options.TransitGatewayCidrBlocks.2", GATEWAY_IPV6_BLOCK),
            ],
        )
        .await;
        assert_eq!(
            status, 200,
            "the fixture's transit gateway must be created, got {status} with body {body}"
        );
        let transit_gateway_id = elements(&body, "transitGatewayId")
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("no transitGatewayId in {body}"));
        let attachment_id = engine
            .state::<Ec2State>()
            .lock()
            .insert_transit_gateway_attachment(TransitGatewayAttachmentView::Connect(
                TransitGatewayConnect {
                    transport_transit_gateway_attachment_id: Some(
                        "tgw-attach-0123456789abcdef0".to_string(),
                    ),
                    transit_gateway_id: Some(transit_gateway_id),
                    state: Some(TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE.to_string()),
                    options: Some(TransitGatewayConnectOptions {
                        protocol: Some(PROTOCOL_VALUE_GRE.to_string()),
                    }),
                    ..Default::default()
                },
            ))
            .expect("the attachment store has room for one Connect attachment");
        Self {
            router,
            engine,
            attachment_id,
        }
    }

    /// The state the STORE holds for `peer_id`, or `None` when it holds no such peer.
    fn stored_state(&self, peer_id: &str) -> Option<String> {
        self.engine
            .state::<Ec2State>()
            .lock()
            .transit_gateway_connect_peers
            .get(peer_id)
            .and_then(|record| record.view.state.clone())
    }
}

/// One `CreateTransitGatewayConnectPeer` call.
async fn create_peer(router: &MultiServiceRouter, params: &[Param]) -> (u16, String) {
    call(router, REGION, "CreateTransitGatewayConnectPeer", params).await
}

/// One `DeleteTransitGatewayConnectPeer` call.
async fn delete_peer(router: &MultiServiceRouter, params: &[Param]) -> (u16, String) {
    call(router, REGION, "DeleteTransitGatewayConnectPeer", params).await
}

/// One `DescribeTransitGatewayConnectPeers` call.
async fn describe_peers(router: &MultiServiceRouter, params: &[Param]) -> (u16, String) {
    call(
        router,
        REGION,
        "DescribeTransitGatewayConnectPeers",
        params,
    )
    .await
}

/// Every member of a reported Connect peer EXCEPT its state — what a delete must leave exactly
/// as the store held it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rest {
    peer_id: String,
    attachment_id: String,
    creation_time: String,
    transit_gateway_address: String,
    peer_address: String,
    inside_cidr_blocks: Vec<String>,
    protocol: String,
    /// One row per reported `TransitGatewayAttachmentBgpConfiguration`: the two ASNs, the two
    /// addresses and the BGP status.
    bgp: Vec<(String, String, String, String, String)>,
    tags: Vec<(String, String)>,
}

/// One reported Connect peer: the state a call answers, beside everything else it reports.
#[derive(Debug, Clone)]
struct Peer {
    state: String,
    rest: Rest,
}

/// The one Connect peer a response carries, read out of the XML document rather than by string
/// surgery — `peerAddress` and `transitGatewayAddress` appear both on the configuration and
/// inside every BGP configuration.
fn peer_of(case: &str, body: &str) -> Peer {
    let parsed = document(case, body);
    let peer = parsed
        .descendants()
        .find(|node| node.is_element() && child(*node, "transitGatewayConnectPeerId").is_some())
        .unwrap_or_else(|| panic!("case {case:?}: no Connect peer in {body}"));
    let configuration = child(peer, "connectPeerConfiguration")
        .unwrap_or_else(|| panic!("case {case:?}: no connectPeerConfiguration in {body}"));
    Peer {
        state: child_text(peer, "state").unwrap_or_default(),
        rest: Rest {
            peer_id: child_text(peer, "transitGatewayConnectPeerId").unwrap_or_default(),
            attachment_id: child_text(peer, "transitGatewayAttachmentId").unwrap_or_default(),
            creation_time: child_text(peer, "creationTime").unwrap_or_default(),
            transit_gateway_address: child_text(configuration, "transitGatewayAddress")
                .unwrap_or_default(),
            peer_address: child_text(configuration, "peerAddress").unwrap_or_default(),
            inside_cidr_blocks: set_items(configuration, "insideCidrBlocks")
                .into_iter()
                .map(|item| item.text().unwrap_or_default().to_string())
                .collect(),
            protocol: child_text(configuration, "protocol").unwrap_or_default(),
            bgp: set_items(configuration, "bgpConfigurations")
                .into_iter()
                .map(|item| {
                    (
                        child_text(item, "transitGatewayAsn").unwrap_or_default(),
                        child_text(item, "peerAsn").unwrap_or_default(),
                        child_text(item, "transitGatewayAddress").unwrap_or_default(),
                        child_text(item, "peerAddress").unwrap_or_default(),
                        child_text(item, "bgpStatus").unwrap_or_default(),
                    )
                })
                .collect(),
            tags: set_items(peer, "tagSet")
                .into_iter()
                .map(|item| {
                    (
                        child_text(item, "key").unwrap_or_default(),
                        child_text(item, "value").unwrap_or_default(),
                    )
                })
                .collect(),
        },
    }
}

/// The peer `peer_id` as the describe reports it right now.
async fn described(case: &str, router: &MultiServiceRouter, peer_id: &str) -> Peer {
    let (status, body) =
        describe_peers(router, &indexed("TransitGatewayConnectPeerIds", &[peer_id])).await;
    assert_eq!(
        status, 200,
        "case {case:?}: the describe of {peer_id} must succeed, got {status} with body {body}"
    );
    peer_of(case, &body)
}

/// Look at the peer AGAIN until the describe reports it in `wanted`, or a deadline far past the
/// span the clock owes a move passes.
///
/// Polls for that STATE rather than waiting out a span, so neither a loaded nor a fast host can
/// be the reason this reads the peer before the move has been applied.
async fn polled_state(
    case: &str,
    router: &MultiServiceRouter,
    peer_id: &str,
    wanted: &str,
) -> Peer {
    let deadline = tokio::time::Instant::now() + MOVE_DEADLINE;
    loop {
        let peer = described(case, router, peer_id).await;
        if peer.state == wanted {
            return peer;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "case {case:?}: the Connect peer {peer_id} must reach {wanted:?}, last read \
             {actual:?}",
            actual = peer.state,
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// One peer this suite creates, as a row of the table below.
#[derive(Debug, Clone)]
struct Case<'a> {
    /// The case name every assertion of the row quotes.
    name: &'a str,
    /// "The range of inside IP addresses that are used for BGP peering" the request names.
    inside: &'a [&'a str],
    /// "The peer IP address (GRE outer IP address) on the appliance side".
    peer_address: &'a str,
    /// The transit gateway side's GRE outer address, or `None` to have it assigned.
    transit_gateway_address: Option<&'a str>,
    /// "The tags to apply to the Connect peer".
    tags: &'a [(&'a str, &'a str)],
    /// Whether the clock-owed `available` move is let fall due before the delete, so the peer is
    /// deleted from the terminal state rather than from the transient one a create leaves it in.
    delete_when_available: bool,
}

impl Case<'_> {
    /// The form fields of this row's create against `attachment_id`.
    fn params(&self, attachment_id: &str) -> Vec<Param> {
        let mut params = vec![
            param("TransitGatewayAttachmentId", attachment_id),
            param("PeerAddress", self.peer_address),
        ];
        params.extend(indexed("InsideCidrBlocks", self.inside));
        if let Some(address) = self.transit_gateway_address {
            params.push(param("TransitGatewayAddress", address));
        }
        if !self.tags.is_empty() {
            params.push(param(
                "TagSpecification.1.ResourceType",
                RESOURCE_TYPE_TRANSIT_GATEWAY_CONNECT_PEER,
            ));
            for (position, (key, value)) in self.tags.iter().enumerate() {
                let index = position + 1;
                params.push(param(&format!("TagSpecification.1.Tag.{index}.Key"), key));
                params.push(param(
                    &format!("TagSpecification.1.Tag.{index}.Value"),
                    value,
                ));
            }
        }
        params
    }
}

/// Create this row's peer and answer it as the create reported it.
async fn created_peer(fixture: &Fixture, case: &Case<'_>) -> Peer {
    let (status, body) = create_peer(&fixture.router, &case.params(&fixture.attachment_id)).await;
    assert_eq!(
        status, 200,
        "case {name:?}: the peer must be created, got {status} with body {body}",
        name = case.name,
    );
    peer_of(case.name, &body)
}

#[tokio::test]
async fn a_delete_records_the_deletion_on_the_stored_peer() {
    // Each row differs along what the rule generalises over: the state the peer is in when the
    // delete arrives, how many inside ranges it peers over and of which families, whether its
    // transit gateway address was named or assigned, and whether it carries tags.
    let cases = [
        Case {
            name: "one IPv4 inside range, deleted while still pending",
            inside: &["169.254.6.0/29"],
            peer_address: "192.0.2.10",
            transit_gateway_address: None,
            tags: &[],
            delete_when_available: false,
        },
        Case {
            name: "one IPv4 inside range, deleted once available",
            inside: &["169.254.7.0/29"],
            peer_address: "192.0.2.11",
            transit_gateway_address: None,
            tags: &[],
            delete_when_available: true,
        },
        Case {
            name: "an IPv4 and an IPv6 inside range, a named transit gateway address",
            inside: &["169.254.8.0/29", "fd00:1::/125"],
            peer_address: "2001:db8:ff::10",
            transit_gateway_address: Some("2001:db8:1::9"),
            tags: &[],
            delete_when_available: true,
        },
        Case {
            name: "a tagged peer, deleted while still pending",
            inside: &["169.254.9.0/29"],
            peer_address: "192.0.2.13",
            transit_gateway_address: Some("10.100.0.7"),
            tags: &[("Name", "appliance"), ("Team", "network")],
            delete_when_available: false,
        },
    ];

    for case in cases {
        let name = case.name;
        let fixture = Fixture::new().await;
        let created = created_peer(&fixture, &case).await;
        let peer_id = created.rest.peer_id.clone();
        assert!(
            peer_id.starts_with(TRANSIT_GATEWAY_CONNECT_PEER_ID_PREFIX),
            "case {name:?}: expected a Connect peer id, got {peer_id:?}"
        );

        // The state the peer is in when the delete arrives, and the record the delete must
        // answer unchanged.
        let before = if case.delete_when_available {
            polled_state(name, &fixture.router, &peer_id, CONNECT_PEER_STATE_AVAILABLE).await
        } else {
            let read = described(name, &fixture.router, &peer_id).await;
            assert_eq!(
                read.state, CONNECT_PEER_STATE_PENDING,
                "case {name:?}: a fresh peer is reported in the state its create answered"
            );
            read
        };

        let (status, body) =
            delete_peer(&fixture.router, &[param("TransitGatewayConnectPeerId", &peer_id)]).await;
        assert_eq!(
            status, 200,
            "case {name:?}: expected HTTP 200 from the delete, got {status} with body {body}"
        );
        let deleted = peer_of(name, &body);
        assert_eq!(
            deleted.state, CONNECT_PEER_STATE_DELETING,
            "case {name:?}: expected the delete to answer {expected:?}, got {actual:?}",
            expected = CONNECT_PEER_STATE_DELETING,
            actual = deleted.state,
        );
        // "Information about the deleted Connect peer": the record as it was stored, with only
        // the state this call changes.
        assert_eq!(
            deleted.rest, before.rest,
            "case {name:?}: expected the delete to answer the stored peer {expected:?}, got \
             {actual:?}",
            expected = before.rest,
            actual = deleted.rest,
        );
        assert_eq!(
            deleted.rest, created.rest,
            "case {name:?}: expected the delete to answer what the create stored {expected:?}, \
             got {actual:?}",
            expected = created.rest,
            actual = deleted.rest,
        );

        // A read straight after the delete corroborates it, and the store holds what the
        // describe reported.
        let read = described(name, &fixture.router, &peer_id).await;
        assert_eq!(
            read.state, CONNECT_PEER_STATE_DELETING,
            "case {name:?}: expected the describe to report {expected:?} right after the \
             delete, got {actual:?}",
            expected = CONNECT_PEER_STATE_DELETING,
            actual = read.state,
        );
        assert_eq!(
            fixture.stored_state(&peer_id).as_deref(),
            Some(CONNECT_PEER_STATE_DELETING),
            "case {name:?}: the stored peer must be the one the describe reported"
        );

        // Nothing is called to make it happen: the clock owes the terminal state, so the peer
        // is READ until it reports it.
        let settled = polled_state(name, &fixture.router, &peer_id, CONNECT_PEER_STATE_DELETED)
            .await;
        assert_eq!(
            settled.rest, before.rest,
            "case {name:?}: a settled deletion changes only the state, got {actual:?}",
            actual = settled.rest,
        );
        assert_eq!(
            fixture.stored_state(&peer_id).as_deref(),
            Some(CONNECT_PEER_STATE_DELETED),
            "case {name:?}: the store must hold the settled deletion"
        );
    }
}

#[tokio::test]
async fn a_delete_leaves_every_other_peer_of_the_attachment_alone() {
    let case = "three peers on one Connect attachment, the second deleted";
    let fixture = Fixture::new().await;
    let mut ids = Vec::new();
    for index in 0..3u8 {
        let inside = format!("169.254.{block}.0/29", block = 30 + u16::from(index));
        let peer_address = format!("192.0.2.{address}", address = 100 + u16::from(index));
        let row = Case {
            name: case,
            inside: &[inside.as_str()],
            peer_address: peer_address.as_str(),
            transit_gateway_address: None,
            tags: &[],
            delete_when_available: false,
        };
        ids.push(created_peer(&fixture, &row).await.rest.peer_id);
    }
    let kept: Vec<Peer> = {
        let mut kept = Vec::new();
        for peer_id in [&ids[0], &ids[2]] {
            kept.push(polled_state(case, &fixture.router, peer_id, CONNECT_PEER_STATE_AVAILABLE).await);
        }
        kept
    };

    let (status, body) =
        delete_peer(&fixture.router, &[param("TransitGatewayConnectPeerId", &ids[1])]).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200, got {status} with body {body}"
    );
    for (position, untouched) in [(0usize, &kept[0]), (2usize, &kept[1])] {
        let read = described(case, &fixture.router, &ids[position]).await;
        assert_eq!(
            read.state, CONNECT_PEER_STATE_AVAILABLE,
            "case {case:?}: the peer {id} must be untouched, got {actual:?}",
            id = ids[position],
            actual = read.state,
        );
        assert_eq!(
            read.rest, untouched.rest,
            "case {case:?}: the peer {id} must report what it reported before the delete, got \
             {actual:?}",
            id = ids[position],
            actual = read.rest,
        );
    }
    // Every peer is still stored: a delete records a deletion, it does not drop rows.
    let (_, body) = describe_peers(&fixture.router, &[]).await;
    let mut reported = elements(&body, "transitGatewayConnectPeerId");
    reported.sort();
    let mut expected = ids.clone();
    expected.sort();
    assert_eq!(
        reported, expected,
        "case {case:?}: expected every peer to still be reported, got body {body}"
    );
}

#[tokio::test]
async fn an_id_the_service_cannot_resolve_is_refused_and_records_nothing() {
    /// One refused delete.
    struct Refusal<'a> {
        label: &'a str,
        peer_id: &'a str,
        status: u16,
        code: &'a str,
        message: String,
    }
    // Both published id forms are 8 or 17 lowercase hexadecimal digits after the kind's prefix
    // (`crate::state::prefixed_id_is_well_formed`), so each row below is a value outside that
    // form — a bare prefix, the wrong digit count, a non-hexadecimal digit, another resource
    // kind's prefix, an uppercase suffix — or inside it with no peer behind it.
    let refusals = [
        Refusal {
            label: "the bare prefix",
            peer_id: "tgw-connect-peer",
            status: 400,
            code: MALFORMED_CODE,
            message: "Invalid id: \"tgw-connect-peer\"".to_string(),
        },
        Refusal {
            label: "sixteen hexadecimal digits, one short of the long form",
            peer_id: "tgw-connect-peer-0123456789abcdef",
            status: 400,
            code: MALFORMED_CODE,
            message: "Invalid id: \"tgw-connect-peer-0123456789abcdef\"".to_string(),
        },
        Refusal {
            label: "a digit outside hexadecimal",
            peer_id: "tgw-connect-peer-0123456789abcdefg",
            status: 400,
            code: MALFORMED_CODE,
            message: "Invalid id: \"tgw-connect-peer-0123456789abcdefg\"".to_string(),
        },
        Refusal {
            label: "an uppercase suffix",
            peer_id: "tgw-connect-peer-0123456789ABCDEF0",
            status: 400,
            code: MALFORMED_CODE,
            message: "Invalid id: \"tgw-connect-peer-0123456789ABCDEF0\"".to_string(),
        },
        Refusal {
            label: "another resource kind's id",
            peer_id: "tgw-attach-0123456789abcdef0",
            status: 400,
            code: MALFORMED_CODE,
            message: "Invalid id: \"tgw-attach-0123456789abcdef0\"".to_string(),
        },
        Refusal {
            label: "a well-formed long id no peer is stored for",
            peer_id: "tgw-connect-peer-0123456789abcdef0",
            status: 400,
            code: NOT_FOUND_CODE,
            message: "The transit gateway Connect peer ID 'tgw-connect-peer-0123456789abcdef0' \
                      does not exist"
                .to_string(),
        },
        Refusal {
            label: "a well-formed short id no peer is stored for",
            peer_id: "tgw-connect-peer-0123abcd",
            status: 400,
            code: NOT_FOUND_CODE,
            message: "The transit gateway Connect peer ID 'tgw-connect-peer-0123abcd' does not \
                      exist"
                .to_string(),
        },
    ];

    let fixture = Fixture::new().await;
    let live = Case {
        name: "the peer a refused delete must not touch",
        inside: &["169.254.6.0/29"],
        peer_address: "192.0.2.10",
        transit_gateway_address: None,
        tags: &[],
        delete_when_available: false,
    };
    let peer_id = created_peer(&fixture, &live).await.rest.peer_id;

    for refusal in refusals {
        let Refusal {
            label,
            peer_id: named,
            status: want_status,
            code,
            message,
        } = refusal;
        let (status, body) =
            delete_peer(&fixture.router, &[param("TransitGatewayConnectPeerId", named)]).await;
        assert_eq!(
            status, want_status,
            "case {label:?}: expected HTTP {want_status}, got {status} with body {body}"
        );
        assert_eq!(
            error_code(&body),
            code,
            "case {label:?}: expected {code}, got body {body}"
        );
        assert_eq!(
            error_message(&body),
            message,
            "case {label:?}: expected the sentence {message:?}, got body {body}"
        );
        assert!(
            matches!(
                fixture.stored_state(&peer_id).as_deref(),
                Some(CONNECT_PEER_STATE_PENDING | CONNECT_PEER_STATE_AVAILABLE)
            ),
            "case {label:?}: a refused delete must leave the stored peer live, got {actual:?}",
            actual = fixture.stored_state(&peer_id),
        );
    }
}

#[tokio::test]
async fn a_dry_run_reports_the_outcome_and_records_nothing() {
    let case = "DryRun on a delete that would have succeeded";
    let fixture = Fixture::new().await;
    let live = Case {
        name: case,
        inside: &["169.254.6.0/29"],
        peer_address: "192.0.2.10",
        transit_gateway_address: None,
        tags: &[],
        delete_when_available: false,
    };
    let peer_id = created_peer(&fixture, &live).await.rest.peer_id;
    let before = polled_state(case, &fixture.router, &peer_id, CONNECT_PEER_STATE_AVAILABLE).await;

    let (status, body) = delete_peer(
        &fixture.router,
        &[
            param("TransitGatewayConnectPeerId", &peer_id),
            param("DryRun", "true"),
        ],
    )
    .await;
    assert_eq!(
        status, DRY_RUN_STATUS,
        "case {case:?}: expected HTTP {DRY_RUN_STATUS}, got {status} with body {body}"
    );
    assert_eq!(
        error_code(&body),
        "DryRunOperation",
        "case {case:?}: expected DryRunOperation, got body {body}"
    );
    let after = described(case, &fixture.router, &peer_id).await;
    assert_eq!(
        after.state, before.state,
        "case {case:?}: a dry run must not move the peer, got {actual:?}",
        actual = after.state,
    );
    assert_eq!(
        after.rest, before.rest,
        "case {case:?}: a dry run must leave the stored peer as it was, got {actual:?}",
        actual = after.rest,
    );
}

#[tokio::test]
async fn a_second_delete_is_refused_in_both_delete_states() {
    // A peer a delete has already been asked for has nothing left to delete, whether that
    // delete is still being carried out or has settled: one row per delete state of the peer's
    // own catalog.
    for wanted in [CONNECT_PEER_STATE_DELETING, CONNECT_PEER_STATE_DELETED] {
        let case = format!("a second delete of a peer in {wanted:?}");
        let fixture = Fixture::new().await;
        let live = Case {
            name: case.as_str(),
            inside: &["169.254.6.0/29"],
            peer_address: "192.0.2.10",
            transit_gateway_address: None,
            tags: &[],
            delete_when_available: false,
        };
        let peer_id = created_peer(&fixture, &live).await.rest.peer_id;
        let (status, body) =
            delete_peer(&fixture.router, &[param("TransitGatewayConnectPeerId", &peer_id)]).await;
        assert_eq!(
            status, 200,
            "case {case:?}: the first delete must succeed, got {status} with body {body}"
        );
        let before = polled_state(&case, &fixture.router, &peer_id, wanted).await;

        let (status, body) =
            delete_peer(&fixture.router, &[param("TransitGatewayConnectPeerId", &peer_id)]).await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected HTTP 400, got {status} with body {body}"
        );
        assert_eq!(
            error_code(&body),
            INCORRECT_STATE_CODE,
            "case {case:?}: expected {INCORRECT_STATE_CODE}, got body {body}"
        );
        let expected =
            format!("Transit Gateway Connect Peer '{peer_id}' is in the '{wanted}' state.");
        assert_eq!(
            error_message(&body),
            expected,
            "case {case:?}: expected the sentence {expected:?}, got body {body}"
        );
        let after = described(&case, &fixture.router, &peer_id).await;
        assert_eq!(
            after.rest, before.rest,
            "case {case:?}: a refused second delete must leave the peer as it was, got \
             {actual:?}",
            actual = after.rest,
        );
    }
}

#[tokio::test]
async fn the_allocations_of_a_settled_delete_are_free_for_the_next_peer() {
    // The interior ranges and the transit gateway's GRE outer address are allocations of the
    // gateway: a second peer cannot claim what a live peer holds, and CAN claim what a peer
    // whose deletion has settled held.
    let case = "the inside range and the assigned address of a deleted peer";
    let fixture = Fixture::new().await;
    let first = Case {
        name: case,
        inside: &["169.254.6.0/29"],
        peer_address: "192.0.2.10",
        transit_gateway_address: None,
        tags: &[],
        delete_when_available: false,
    };
    let created = created_peer(&fixture, &first).await;
    let peer_id = created.rest.peer_id.clone();
    let address = created.rest.transit_gateway_address.clone();

    // While the first peer holds them, the same inside range is refused.
    let (status, body) = create_peer(
        &fixture.router,
        &Case {
            peer_address: "192.0.2.11",
            ..first.clone()
        }
        .params(&fixture.attachment_id),
    )
    .await;
    assert_eq!(
        status, 400,
        "case {case:?}: a live peer's inside range must not be claimable, got {status} with \
         body {body}"
    );
    assert_eq!(
        error_code(&body),
        "InvalidParameterValue",
        "case {case:?}: expected InvalidParameterValue, got body {body}"
    );

    let (status, body) =
        delete_peer(&fixture.router, &[param("TransitGatewayConnectPeerId", &peer_id)]).await;
    assert_eq!(
        status, 200,
        "case {case:?}: the delete must succeed, got {status} with body {body}"
    );
    polled_state(case, &fixture.router, &peer_id, CONNECT_PEER_STATE_DELETED).await;

    // Once the deletion has settled, the next peer gets exactly what the deleted one held.
    let second = Case {
        peer_address: "192.0.2.11",
        ..first
    };
    let replacement = created_peer(&fixture, &second).await;
    assert_eq!(
        replacement.rest.inside_cidr_blocks,
        vec!["169.254.6.0/29".to_string()],
        "case {case:?}: expected the freed inside range, got {actual:?}",
        actual = replacement.rest.inside_cidr_blocks,
    );
    assert_eq!(
        replacement.rest.transit_gateway_address, address,
        "case {case:?}: expected the freed transit gateway address {address:?}, got {actual:?}",
        actual = replacement.rest.transit_gateway_address,
    );
    assert_ne!(
        replacement.rest.peer_id, peer_id,
        "case {case:?}: the replacement must be a peer of its own"
    );
}
