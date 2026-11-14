// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for the PROPAGATED routes of a transit gateway route table: what
//! `EnableTransitGatewayRouteTablePropagation` puts in a table and what
//! `SearchTransitGatewayRoutes` then reports, driven over `ec2Query` (README.md /
//! OPERATIONS.md "Wire protocol").
//!
//! The rule under test: a search of a transit gateway route table reports the routes that table
//! holds NOW — the static routes created in it, and one `propagated` route, `active`, for every
//! address prefix held by the resource of each attachment whose propagation INTO THAT TABLE is
//! in force, naming that attachment, its resource and its resource type. So a prefix is
//! reported by the tables that propagate it and by no other, a propagation that is not in force
//! contributes nothing, and a destination the table holds a static route for is reported as
//! that static route.
//!
//! Each table row is a distinct input along what that rule generalises over: how many prefixes
//! the propagating resource holds and of which address family, which kind of attachment
//! propagates (and so which `ResourceType` and `ResourceId` the route names, and whether this
//! emulator holds any prefix of its resource at all), which of two route tables the propagation
//! is into, which state the propagation is in, and whether the table also holds a static route
//! for the propagated prefix.
//!
//! Nothing here waits out a fixed span: every assertion about a state the clock owes looks
//! AGAIN until the condition holds or a deadline far past the service's own transition span
//! passes, so no outcome depends on how fast the host runs.

use std::time::Duration;

use ec2::ops::types::{
    ClientVpnEndpoint, PeeringTgwInfo, TransitGatewayClientVpnAttachment, TransitGatewayConnect,
    TransitGatewayPeeringAttachment, TransitGatewayVpcAttachment,
};
use ec2::state::{
    ComAmazonawsEc2Amazonec2State as Ec2State, PROPAGATION_STATE_DISABLING,
    PROPAGATION_STATE_ENABLED, PROPAGATION_STATE_ENABLING,
    TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_CLIENT_VPN,
    TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_CONNECT,
    TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_PEERING, TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_VPC,
    TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE, TRANSIT_GATEWAY_ATTACHMENT_STATE_PENDING,
    TRANSIT_GATEWAY_ROUTE_STATE_ACTIVE, TRANSIT_GATEWAY_ROUTE_TYPE_PROPAGATED,
    TRANSIT_GATEWAY_ROUTE_TYPE_STATIC, TRANSITION_DELAY, TransitGatewayAttachmentView,
    TransitGatewayPropagationRecord,
};
use service_com_amazonaws_ec2_amazonec2 as ec2;
use smithy_server_runtime::MultiServiceRouter;

use super::ec2_query::{call, element, filters};
use super::wire::{Param, child_text, document, param, set_items};

/// The Region every call here is signed for.
const REGION: &str = "us-east-1";

/// The deadline every poll below gives up at: a large multiple of the service's own transition
/// span, so a loaded host is never the reason one fails, and all it bounds is a hang.
fn poll_deadline() -> Duration {
    TRANSITION_DELAY * 120
}

/// One look inside that deadline. Short enough that the deadline costs many looks rather than
/// one, and it bounds nothing the assertions depend on.
fn poll_interval() -> Duration {
    Duration::from_millis(20)
}

/// One call of `action` signed for the Region above.
async fn invoke(
    router: &MultiServiceRouter,
    action: &str,
    params: &[Param],
) -> (u16, String) {
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

/// One element of a successful call's body, or a panic naming the case.
async fn ok_element(
    case: &str,
    router: &MultiServiceRouter,
    action: &str,
    params: &[Param],
    name: &str,
) -> String {
    let body = ok_body(case, router, action, params).await;
    element(&body, name)
        .unwrap_or_else(|| panic!("case {case:?}: {action} answered no <{name}>: {body}"))
}

/// A transit gateway created over the wire, as its `TransitGatewayId`.
async fn transit_gateway(case: &str, router: &MultiServiceRouter) -> String {
    ok_element(case, router, "CreateTransitGateway", &[], "transitGatewayId").await
}

/// An additional route table of `transit_gateway_id` ("You can use
/// CreateTransitGatewayRouteTable to create additional transit gateway route tables" —
/// `CreateTransitGateway`), as its `TransitGatewayRouteTableId`.
async fn route_table(case: &str, router: &MultiServiceRouter, transit_gateway_id: &str) -> String {
    ok_element(
        case,
        router,
        "CreateTransitGatewayRouteTable",
        &[param("TransitGatewayId", transit_gateway_id)],
        "transitGatewayRouteTableId",
    )
    .await
}

/// A VPC created over the wire for `cidr_block`, as its `VpcId`.
async fn vpc(case: &str, router: &MultiServiceRouter, cidr_block: &str) -> String {
    ok_element(
        case,
        router,
        "CreateVpc",
        &[param("CidrBlock", cidr_block)],
        "vpcId",
    )
    .await
}

/// A subnet of `vpc_id`, as its `SubnetId` — what a VPC attachment attaches through.
async fn subnet(case: &str, router: &MultiServiceRouter, vpc_id: &str, cidr_block: &str) -> String {
    ok_element(
        case,
        router,
        "CreateSubnet",
        &[
            param("VpcId", vpc_id),
            param("CidrBlock", cidr_block),
            // One zone of the Region every call here is signed for; an attachment admits one
            // subnet per zone, and every row attaches exactly one.
            param("AvailabilityZone", "us-east-1a"),
        ],
        "subnetId",
    )
    .await
}

/// `CreateTransitGatewayVpcAttachment` of `vpc_id` to `transit_gateway_id`, as the
/// `TransitGatewayAttachmentId` it mints.
async fn attach_vpc(
    case: &str,
    router: &MultiServiceRouter,
    transit_gateway_id: &str,
    vpc_id: &str,
    subnet_id: &str,
) -> String {
    ok_element(
        case,
        router,
        "CreateTransitGatewayVpcAttachment",
        &[
            param("TransitGatewayId", transit_gateway_id),
            param("VpcId", vpc_id),
            param("SubnetIds.1", subnet_id),
        ],
        "transitGatewayAttachmentId",
    )
    .await
}

/// `EnableTransitGatewayRouteTablePropagation` of `attachment_id` into `route_table_id`.
async fn enable_propagation(
    case: &str,
    router: &MultiServiceRouter,
    route_table_id: &str,
    attachment_id: &str,
) {
    let body = ok_body(
        case,
        router,
        "EnableTransitGatewayRouteTablePropagation",
        &[
            param("TransitGatewayRouteTableId", route_table_id),
            param("TransitGatewayAttachmentId", attachment_id),
        ],
    )
    .await;
    assert_eq!(
        element(&body, "state").as_deref(),
        Some(PROPAGATION_STATE_ENABLING),
        "case {case:?}: an enable answers the transient state of the move it started, got {body}"
    );
}

/// `DisableTransitGatewayRouteTablePropagation` of `attachment_id` from `route_table_id`.
async fn disable_propagation(
    case: &str,
    router: &MultiServiceRouter,
    route_table_id: &str,
    attachment_id: &str,
) {
    ok_body(
        case,
        router,
        "DisableTransitGatewayRouteTablePropagation",
        &[
            param("TransitGatewayRouteTableId", route_table_id),
            param("TransitGatewayAttachmentId", attachment_id),
        ],
    )
    .await;
}

/// One attachment a route of the search names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportedAttachment {
    /// `TransitGatewayRouteAttachment$TransitGatewayAttachmentId`.
    attachment_id: String,
    /// `TransitGatewayRouteAttachment$ResourceId`.
    resource_id: String,
    /// `TransitGatewayRouteAttachment$ResourceType`.
    resource_type: String,
}

/// One route a search reports, as the members `TransitGatewayRoute` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportedRoute {
    /// `TransitGatewayRoute$DestinationCidrBlock`.
    destination: String,
    /// `TransitGatewayRoute$Type` — `propagated` or `static`.
    route_type: String,
    /// `TransitGatewayRoute$State`.
    state: String,
    /// `TransitGatewayRoute$TransitGatewayAttachments`, in the order reported.
    attachments: Vec<ReportedAttachment>,
}

/// Every route a search body reports, in the order reported: the `<item>`s of its `routeSet`,
/// read through the document rather than by string surgery, so an attachment's own
/// `resourceId` is never read as a member of the route.
fn reported_routes(case: &str, body: &str) -> Vec<ReportedRoute> {
    let document = document(case, body);
    let route_set = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "routeSet");
    let Some(route_set) = route_set else {
        return Vec::new();
    };
    route_set
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|route| ReportedRoute {
            destination: child_text(route, "destinationCidrBlock").unwrap_or_default(),
            route_type: child_text(route, "type").unwrap_or_default(),
            state: child_text(route, "state").unwrap_or_default(),
            attachments: set_items(route, "transitGatewayAttachments")
                .into_iter()
                .map(|attachment| ReportedAttachment {
                    attachment_id: child_text(attachment, "transitGatewayAttachmentId")
                        .unwrap_or_default(),
                    resource_id: child_text(attachment, "resourceId").unwrap_or_default(),
                    resource_type: child_text(attachment, "resourceType").unwrap_or_default(),
                })
                .collect(),
        })
        .collect()
}

/// `SearchTransitGatewayRoutes` of `route_table_id` narrowed by `narrow_by`, as the routes it
/// reports.
async fn searched(
    case: &str,
    router: &MultiServiceRouter,
    route_table_id: &str,
    narrow_by: &[(&str, &[&str])],
) -> Vec<ReportedRoute> {
    let mut params = vec![param("TransitGatewayRouteTableId", route_table_id)];
    params.extend(filters(narrow_by));
    let body = ok_body(case, router, "SearchTransitGatewayRoutes", &params).await;
    reported_routes(case, &body)
}

/// Every route of `route_table_id`, with no filter narrowing the search: the one filter EC2
/// documents for "every route" is the type catalog itself, so the search is narrowed by the
/// two types a route can have rather than by nothing — `Filters` is `@required`.
async fn all_routes(
    case: &str,
    router: &MultiServiceRouter,
    route_table_id: &str,
) -> Vec<ReportedRoute> {
    searched(
        case,
        router,
        route_table_id,
        &[(
            "type",
            &[
                TRANSIT_GATEWAY_ROUTE_TYPE_PROPAGATED,
                TRANSIT_GATEWAY_ROUTE_TYPE_STATIC,
            ],
        )],
    )
    .await
}

/// Look at `route_table_id` AGAIN until the destinations it reports are exactly `wanted`, or a
/// deadline far past the service's own transition span passes. Answers the routes last seen, so
/// the caller asserts on the state the table ACTUALLY settled in.
async fn poll_until_destinations(
    case: &str,
    router: &MultiServiceRouter,
    route_table_id: &str,
    wanted: &[&str],
) -> Vec<ReportedRoute> {
    let deadline = tokio::time::Instant::now() + poll_deadline();
    loop {
        let routes = all_routes(case, router, route_table_id).await;
        let destinations: Vec<&str> = routes
            .iter()
            .map(|route| route.destination.as_str())
            .collect();
        if destinations == wanted || tokio::time::Instant::now() >= deadline {
            assert_eq!(
                destinations, wanted,
                "case {case:?}: expected the table to report {wanted:?}, got {routes:?}"
            );
            return routes;
        }
        tokio::time::sleep(poll_interval()).await;
    }
}

/// Store a Client VPN endpoint holding `client_cidr_block` and answer its
/// `ClientVpnEndpointId`.
fn seed_client_vpn_endpoint(engine: &engine::InMemoryEngine, client_cidr_block: &str) -> String {
    engine
        .state::<Ec2State>()
        .lock()
        .insert_client_vpn_endpoint(ClientVpnEndpoint {
            client_cidr_block: Some(client_cidr_block.to_string()),
            ..Default::default()
        })
        .expect("the store holds the seeded Client VPN endpoint")
}

/// Store `view` as an attachment and answer its `TransitGatewayAttachmentId`.
fn seed_attachment(engine: &engine::InMemoryEngine, view: TransitGatewayAttachmentView) -> String {
    engine
        .state::<Ec2State>()
        .lock()
        .insert_transit_gateway_attachment(view)
        .expect("the store holds the seeded attachment")
}

/// Store a propagation of `attachment_id` into `route_table_id` already in `state`, with NO move
/// owed, so what the search makes of a propagation in that state does not depend on the clock.
fn seed_propagation(
    engine: &engine::InMemoryEngine,
    route_table_id: &str,
    attachment_id: &str,
    resource_id: &str,
    resource_type: &str,
    state: &str,
) {
    engine
        .state::<Ec2State>()
        .lock()
        .transit_gateway_propagations
        .insert(
            (route_table_id.to_string(), attachment_id.to_string()),
            TransitGatewayPropagationRecord {
                transit_gateway_route_table_id: route_table_id.to_string(),
                transit_gateway_attachment_id: attachment_id.to_string(),
                resource_id: Some(resource_id.to_string()),
                resource_type: resource_type.to_string(),
                transit_gateway_route_table_announcement_id: None,
                state: state.to_string(),
                pending: None,
            },
        );
}

/// The prefixes a VPC holds are what its attachment propagates: one route per block the VPC has
/// associated, of either address family, each reported `propagated` and `active` and naming the
/// attachment, its VPC and the `vpc` resource type.
#[tokio::test]
async fn a_vpc_attachment_propagates_every_prefix_its_vpc_holds() {
    // Rows differ along how many prefixes the VPC holds and of which address family.
    let rows: [(&str, &[&str], bool); 3] = [
        ("one IPv4 block", &["10.20.0.0/16"], false),
        (
            "a secondary IPv4 block",
            &["10.21.0.0/16", "10.22.0.0/16"],
            false,
        ),
        ("an IPv4 block and an IPv6 block", &["10.23.0.0/16"], true),
    ];

    for (case, blocks, with_ipv6) in rows {
        let (router, _engine) = super::ec2_query::emulator();
        let transit_gateway_id = transit_gateway(case, &router).await;
        let route_table_id = route_table(case, &router, &transit_gateway_id).await;

        let vpc_id = vpc(case, &router, blocks[0]).await;
        for block in &blocks[1..] {
            ok_body(
                case,
                &router,
                "AssociateVpcCidrBlock",
                &[param("VpcId", &vpc_id), param("CidrBlock", block)],
            )
            .await;
        }
        let mut expected: Vec<String> = blocks.iter().map(|block| block.to_string()).collect();
        if with_ipv6 {
            let body = ok_body(
                case,
                &router,
                "AssociateVpcCidrBlock",
                &[
                    param("VpcId", &vpc_id),
                    param("AmazonProvidedIpv6CidrBlock", "true"),
                ],
            )
            .await;
            expected.push(
                element(&body, "ipv6CidrBlock")
                    .unwrap_or_else(|| panic!("case {case:?}: no IPv6 block in {body}")),
            );
        }
        // The search reports a table in destination order, which is the order it pages over.
        expected.sort();
        // A subnet of the VPC's PRIMARY block, which is the one every row's first entry is:
        // "the CIDR block … must be within the CIDR of the VPC"
        // (`CreateSubnetRequest$CidrBlock`).
        let subnet_cidr = blocks[0].replace("/16", "/24");
        let subnet_id = subnet(case, &router, &vpc_id, &subnet_cidr).await;
        let attachment_id =
            attach_vpc(case, &router, &transit_gateway_id, &vpc_id, &subnet_id).await;

        // Nothing propagates into the table yet, so it holds no route at all.
        assert_eq!(
            all_routes(case, &router, &route_table_id).await,
            Vec::new(),
            "case {case:?}: a table nothing propagates into holds no route"
        );

        enable_propagation(case, &router, &route_table_id, &attachment_id).await;
        let wanted: Vec<&str> = expected.iter().map(String::as_str).collect();
        let routes = poll_until_destinations(case, &router, &route_table_id, &wanted).await;
        for route in &routes {
            assert_eq!(
                route.route_type, TRANSIT_GATEWAY_ROUTE_TYPE_PROPAGATED,
                "case {case:?}: a route an attachment's prefixes put in the table is \
                 propagated, got {route:?}"
            );
            assert_eq!(
                route.state, TRANSIT_GATEWAY_ROUTE_STATE_ACTIVE,
                "case {case:?}: a propagated route carries its traffic, got {route:?}"
            );
            assert_eq!(
                route.attachments,
                vec![ReportedAttachment {
                    attachment_id: attachment_id.clone(),
                    resource_id: vpc_id.clone(),
                    resource_type: TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_VPC.to_string(),
                }],
                "case {case:?}: the route must name the propagating attachment, got {route:?}"
            );
        }
    }
}

/// What an attachment propagates is the address space of the resource it attaches, so the kind
/// of attachment decides both what the route names and whether there is a prefix to report at
/// all: a VPC attachment announces its VPC's blocks and a Client VPN attachment the client
/// range of its endpoint, while a peering or Connect attachment holds no prefix of its own here
/// and so puts NO route in the table rather than a made-up one.
#[tokio::test]
async fn each_attachment_kind_propagates_the_prefixes_of_its_own_resource() {
    let (router, engine) = super::ec2_query::emulator();
    let case = "the attachment kinds";
    let transit_gateway_id = transit_gateway(case, &router).await;

    // The resources the seeded attachments attach, created the way a caller would.
    let vpc_id = vpc(case, &router, "10.30.0.0/16").await;
    let client_vpn_endpoint_id = seed_client_vpn_endpoint(&engine, "10.31.0.0/22");

    /// One kind of attachment: what it attaches, and the prefixes the table must report for it.
    struct Kind {
        /// The case name every assertion of the row quotes.
        name: &'static str,
        /// The attachment, as it is stored.
        view: TransitGatewayAttachmentView,
        /// The resource a route of this attachment names.
        resource_id: String,
        /// That resource's `TransitGatewayAttachmentResourceType`.
        resource_type: &'static str,
        /// The destinations the attachment propagates.
        destinations: Vec<String>,
    }

    let kinds = vec![
        Kind {
            name: "a VPC attachment",
            view: TransitGatewayAttachmentView::Vpc(TransitGatewayVpcAttachment {
                transit_gateway_id: Some(transit_gateway_id.clone()),
                vpc_id: Some(vpc_id.clone()),
                state: Some(TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE.to_string()),
                ..Default::default()
            }),
            resource_id: vpc_id.clone(),
            resource_type: TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_VPC,
            destinations: vec!["10.30.0.0/16".to_string()],
        },
        Kind {
            name: "a Client VPN attachment",
            view: TransitGatewayAttachmentView::ClientVpn(TransitGatewayClientVpnAttachment {
                transit_gateway_id: Some(transit_gateway_id.clone()),
                client_vpn_endpoint_id: Some(client_vpn_endpoint_id.clone()),
                state: Some(TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE.to_string()),
                ..Default::default()
            }),
            resource_id: client_vpn_endpoint_id.clone(),
            resource_type: TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_CLIENT_VPN,
            destinations: vec!["10.31.0.0/22".to_string()],
        },
        Kind {
            name: "a peering attachment",
            view: TransitGatewayAttachmentView::Peering(TransitGatewayPeeringAttachment {
                requester_tgw_info: Some(PeeringTgwInfo {
                    transit_gateway_id: Some(transit_gateway_id.clone()),
                    region: Some(REGION.to_string()),
                    ..Default::default()
                }),
                accepter_tgw_info: Some(PeeringTgwInfo {
                    transit_gateway_id: Some("tgw-00000000000000aaa".to_string()),
                    region: Some("us-west-2".to_string()),
                    ..Default::default()
                }),
                state: Some(TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE.to_string()),
                ..Default::default()
            }),
            resource_id: "tgw-00000000000000aaa".to_string(),
            resource_type: TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_PEERING,
            destinations: Vec::new(),
        },
        Kind {
            name: "a Connect attachment",
            view: TransitGatewayAttachmentView::Connect(TransitGatewayConnect {
                transit_gateway_id: Some(transit_gateway_id.clone()),
                transport_transit_gateway_attachment_id: Some(
                    "tgw-attach-00000000000000aaa".to_string(),
                ),
                state: Some(TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE.to_string()),
                ..Default::default()
            }),
            resource_id: "tgw-attach-00000000000000aaa".to_string(),
            resource_type: TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_CONNECT,
            destinations: Vec::new(),
        },
    ];

    for kind in kinds {
        let case = kind.name;
        // A table of its own per row, so one row's propagations cannot be read as another's.
        let route_table_id = route_table(case, &router, &transit_gateway_id).await;
        let attachment_id = seed_attachment(&engine, kind.view);
        enable_propagation(case, &router, &route_table_id, &attachment_id).await;

        let wanted: Vec<&str> = kind.destinations.iter().map(String::as_str).collect();
        let routes = poll_until_destinations(case, &router, &route_table_id, &wanted).await;
        for route in &routes {
            assert_eq!(
                route.attachments,
                vec![ReportedAttachment {
                    attachment_id: attachment_id.clone(),
                    resource_id: kind.resource_id.clone(),
                    resource_type: kind.resource_type.to_string(),
                }],
                "case {case:?}: the route must name the propagating attachment and its own \
                 resource, got {route:?}"
            );
        }
    }
}

/// A propagated prefix is reported by the tables that propagate it and by no other: the return
/// route of a VPC is missing from a route table that attachment does not propagate into, even
/// while the other table of the same gateway reports it.
#[tokio::test]
async fn a_prefix_is_reported_only_by_the_tables_that_propagate_it() {
    let (router, _engine) = super::ec2_query::emulator();
    let case = "two tables of one gateway";
    let transit_gateway_id = transit_gateway(case, &router).await;
    let propagating = route_table(case, &router, &transit_gateway_id).await;
    let unpropagated = route_table(case, &router, &transit_gateway_id).await;

    let first_vpc = vpc(case, &router, "10.40.0.0/16").await;
    let first_subnet = subnet(case, &router, &first_vpc, "10.40.0.0/24").await;
    let first_attachment =
        attach_vpc(case, &router, &transit_gateway_id, &first_vpc, &first_subnet).await;

    let second_vpc = vpc(case, &router, "10.41.0.0/16").await;
    let second_subnet = subnet(case, &router, &second_vpc, "10.41.0.0/24").await;
    let second_attachment = attach_vpc(
        case,
        &router,
        &transit_gateway_id,
        &second_vpc,
        &second_subnet,
    )
    .await;

    // Only the first VPC propagates, and only into the first table.
    enable_propagation(case, &router, &propagating, &first_attachment).await;
    poll_until_destinations(case, &router, &propagating, &["10.40.0.0/16"]).await;

    // The table nothing propagates into has no route back to that VPC: at the very instant the
    // propagating table reports the prefix, this one reports nothing.
    assert_eq!(
        all_routes(case, &router, &unpropagated).await,
        Vec::new(),
        "case {case:?}: a table the attachment does not propagate into holds no return route"
    );

    // The second attachment propagating into the second table does not widen the first.
    enable_propagation(case, &router, &unpropagated, &second_attachment).await;
    poll_until_destinations(case, &router, &unpropagated, &["10.41.0.0/16"]).await;
    assert_eq!(
        all_routes(case, &router, &propagating)
            .await
            .into_iter()
            .map(|route| route.destination)
            .collect::<Vec<String>>(),
        vec!["10.40.0.0/16".to_string()],
        "case {case:?}: each table reports the prefixes propagated into IT"
    );

    // And the prefix goes when the propagation that put it there does.
    disable_propagation(case, &router, &propagating, &first_attachment).await;
    poll_until_destinations(case, &router, &propagating, &[]).await;
}

/// Only a propagation IN FORCE puts routes in a table: a pair still `enabling`, or one
/// finishing a disable, contributes nothing, and the attachment must be in service — which is
/// asserted of a propagation the clock owes no move, so none of it depends on timing.
#[tokio::test]
async fn only_an_enabled_propagation_of_an_available_attachment_contributes_routes() {
    let (router, engine) = super::ec2_query::emulator();
    let case = "the propagation states";
    let transit_gateway_id = transit_gateway(case, &router).await;
    let vpc_id = vpc(case, &router, "10.50.0.0/16").await;

    /// A stored attachment of `vpc_id` in `state`.
    fn attachment_in(
        transit_gateway_id: &str,
        vpc_id: &str,
        state: &str,
    ) -> TransitGatewayAttachmentView {
        TransitGatewayAttachmentView::Vpc(TransitGatewayVpcAttachment {
            transit_gateway_id: Some(transit_gateway_id.to_string()),
            vpc_id: Some(vpc_id.to_string()),
            state: Some(state.to_string()),
            ..Default::default()
        })
    }

    // Rows differ along the propagation's own state, and along the state of the attachment that
    // propagates: the prefix is in the table only for the row where both are in force.
    let rows: [(&str, &str, &str, &[&str]); 4] = [
        (
            "an enabling propagation",
            PROPAGATION_STATE_ENABLING,
            TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE,
            &[],
        ),
        (
            "a disabling propagation",
            PROPAGATION_STATE_DISABLING,
            TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE,
            &[],
        ),
        (
            "an enabled propagation of an attachment still being made",
            PROPAGATION_STATE_ENABLED,
            TRANSIT_GATEWAY_ATTACHMENT_STATE_PENDING,
            &[],
        ),
        (
            "an enabled propagation of an available attachment",
            PROPAGATION_STATE_ENABLED,
            TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE,
            &["10.50.0.0/16"],
        ),
    ];

    for (case, propagation_state, attachment_state, wanted) in rows {
        let route_table_id = route_table(case, &router, &transit_gateway_id).await;
        let attachment_id = seed_attachment(
            &engine,
            attachment_in(&transit_gateway_id, &vpc_id, attachment_state),
        );
        seed_propagation(
            &engine,
            &route_table_id,
            &attachment_id,
            &vpc_id,
            TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_VPC,
            propagation_state,
        );

        let routes = all_routes(case, &router, &route_table_id).await;
        let destinations: Vec<&str> = routes
            .iter()
            .map(|route| route.destination.as_str())
            .collect();
        assert_eq!(
            destinations, wanted,
            "case {case:?}: expected the table to report {wanted:?}, got {routes:?}"
        );
    }
}

/// A destination the table holds a STATIC route for is reported as that static route, and the
/// documented filters narrow the propagated routes exactly as they narrow the static ones.
#[tokio::test]
async fn a_static_route_wins_its_destination_and_the_filters_select_propagated_routes() {
    let (router, engine) = super::ec2_query::emulator();
    let case = "a static route beside the propagated ones";
    let transit_gateway_id = transit_gateway(case, &router).await;
    let route_table_id = route_table(case, &router, &transit_gateway_id).await;

    let vpc_id = vpc(case, &router, "10.60.0.0/16").await;
    ok_body(
        case,
        &router,
        "AssociateVpcCidrBlock",
        &[param("VpcId", &vpc_id), param("CidrBlock", "10.61.0.0/16")],
    )
    .await;
    let attachment_id = seed_attachment(
        &engine,
        TransitGatewayAttachmentView::Vpc(TransitGatewayVpcAttachment {
            transit_gateway_id: Some(transit_gateway_id.clone()),
            vpc_id: Some(vpc_id.clone()),
            state: Some(TRANSIT_GATEWAY_ATTACHMENT_STATE_AVAILABLE.to_string()),
            ..Default::default()
        }),
    );
    enable_propagation(case, &router, &route_table_id, &attachment_id).await;
    poll_until_destinations(
        case,
        &router,
        &route_table_id,
        &["10.60.0.0/16", "10.61.0.0/16"],
    )
    .await;

    // A static route for one of those destinations: the table's own entry for it, so the
    // destination is reported ONCE, as the static route.
    ok_body(
        case,
        &router,
        "CreateTransitGatewayRoute",
        &[
            param("TransitGatewayRouteTableId", &route_table_id),
            param("DestinationCidrBlock", "10.61.0.0/16"),
            param("Blackhole", "true"),
        ],
    )
    .await;
    let routes = all_routes(case, &router, &route_table_id).await;
    assert_eq!(
        routes
            .iter()
            .map(|route| (route.destination.as_str(), route.route_type.as_str()))
            .collect::<Vec<(&str, &str)>>(),
        vec![
            ("10.60.0.0/16", TRANSIT_GATEWAY_ROUTE_TYPE_PROPAGATED),
            ("10.61.0.0/16", TRANSIT_GATEWAY_ROUTE_TYPE_STATIC),
        ],
        "case {case:?}: a destination the table holds a static route for is that route, got \
         {routes:?}"
    );

    // Each documented filter relates to the propagated route exactly as it does to a static
    // one: its type, the resource of the attachment it names, and the CIDR relation its
    // destination stands in to the value.
    for (filter, values, expected) in [
        (
            "type",
            &[TRANSIT_GATEWAY_ROUTE_TYPE_PROPAGATED][..],
            vec!["10.60.0.0/16"],
        ),
        (
            "type",
            &[TRANSIT_GATEWAY_ROUTE_TYPE_STATIC][..],
            vec!["10.61.0.0/16"],
        ),
        ("attachment.resource-id", &[vpc_id.as_str()][..], vec!["10.60.0.0/16"]),
        (
            "attachment.resource-type",
            &[TRANSIT_GATEWAY_ATTACHMENT_RESOURCE_TYPE_VPC][..],
            vec!["10.60.0.0/16"],
        ),
        (
            "attachment.transit-gateway-attachment-id",
            &[attachment_id.as_str()][..],
            vec!["10.60.0.0/16"],
        ),
        (
            "route-search.exact-match",
            &["10.60.0.0/16"][..],
            vec!["10.60.0.0/16"],
        ),
        (
            "route-search.subnet-of-match",
            &["10.0.0.0/8"][..],
            vec!["10.60.0.0/16", "10.61.0.0/16"],
        ),
        ("state", &[TRANSIT_GATEWAY_ROUTE_STATE_ACTIVE][..], vec!["10.60.0.0/16"]),
    ] {
        let narrowed = searched(case, &router, &route_table_id, &[(filter, values)]).await;
        assert_eq!(
            narrowed
                .iter()
                .map(|route| route.destination.as_str())
                .collect::<Vec<&str>>(),
            expected,
            "case {case:?}: the filter {filter:?} on {values:?} must report {expected:?}, got \
             {narrowed:?}"
        );
    }
}
