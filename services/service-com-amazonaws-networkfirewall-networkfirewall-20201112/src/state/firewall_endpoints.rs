// SPDX-License-Identifier: CC0-1.0

//! The firewall endpoint a firewall subnet carries, instantiated in the service that
//! OWNS it.
//!
//! "In each configured subnet, Network Firewall instantiates a firewall endpoint to handle
//! network traffic" (`smithy_query(query="shape",shape="Attachment")`), and what that
//! endpoint IS is a Gateway Load Balancer VPC endpoint in the caller's own VPC: the id the
//! attachment reports is "the identifier of the firewall endpoint that Network Firewall has
//! instantiated in the subnet. You use this to identify the firewall endpoint in the VPC
//! route tables, when you redirect traffic to it" (`Attachment$EndpointId`). A VPC endpoint
//! is Amazon EC2's resource, and a route target has to be one EC2 holds — EC2 resolves
//! `CreateRoute`'s `VpcEndpointId` against its own endpoints — so this service does not mint
//! a firewall endpoint id of its own: it asks EC2 to create the endpoint and reports the id
//! EC2 answered, and it asks EC2 to delete that endpoint when the attachment holding it goes
//! away.
//!
//! The ask goes over the in-process callback
//! ([`smithy_server_runtime::OperationContext::callback`]), the seam every service of this
//! emulator reaches another one through: this crate names no other service's crate, no
//! socket is opened, no host name is resolved and nothing leaves the process. The
//! credentials are the callback's own, which sign the hop and never appear in a response.
//!
//! An ask that does not answer an endpoint is an ask this emulator could not make: there was
//! no EC2 in this process (the assembled emulator mounts every service, so this is a process
//! running Network Firewall alone), or EC2 refused the create — because the subnet or the VPC
//! names nothing of this account, or for any other reason. This service holds nothing of the
//! placement beyond the ids the request carried and it does not resolve a placement against
//! EC2 (no refusal of this service's is grounded in what EC2 answered), so nothing is refused
//! here either: the attachment falls back to an id this service mints, which no EC2 holds and
//! no route can resolve, and the attempt is traced at `warn`.
//!
//! Nothing here holds this service's store: every function takes the values it needs and is
//! awaited with no guard held, so an endpoint can never be created or deleted behind a lock.

/// The `VpcEndpointType` a firewall endpoint is created as: a Gateway Load Balancer
/// endpoint, the one type a route can name as its `VpcEndpointId` target ("The ID of a VPC
/// endpoint. Supported for Gateway Load Balancer endpoints only",
/// `com.amazonaws.ec2#CreateRouteRequest$VpcEndpointId`).
const FIREWALL_ENDPOINT_TYPE: ::aws_sdk_ec2::types::VpcEndpointType =
    ::aws_sdk_ec2::types::VpcEndpointType::GatewayLoadBalancer;

/// The id prefix of an endpoint service of an account (`vpce-svc-…`), which is what the
/// endpoint service behind a firewall's endpoints is named by.
const ENDPOINT_SERVICE_ID_PREFIX: &str = "vpce-svc";

/// The endpoint service id behind ONE firewall's endpoints (`vpce-svc-` plus 17 hex digits,
/// the shape an endpoint service id takes).
///
/// Every firewall endpoint of a firewall is an endpoint TO the one Gateway Load Balancer
/// endpoint service that firewall is reached through, so the id is minted once per firewall
/// and kept on its record; `vpce-svc-` ids are minted the way every other server-generated
/// id of this service is ([`crate::state::new_endpoint_id`]).
pub fn new_endpoint_service_id() -> String {
    let digits = ::hex::encode(super::fresh_bytes());
    format!("{ENDPOINT_SERVICE_ID_PREFIX}-{}", &digits[..17])
}

/// The endpoint service NAME an endpoint to the service `service_id` names it by:
/// `com.amazonaws.vpce.<region>.<service-id>`, the form an endpoint service that Amazon Web
/// Services itself does not publish is named by (`com.amazonaws.ec2#ServiceDetail$ServiceName`
/// — "the name of the service", whose `vpce` label carries the owner's own service id).
pub fn endpoint_service_name(region: &str, service_id: &str) -> String {
    format!("com.amazonaws.vpce.{region}.{service_id}")
}

/// Ask Amazon EC2 to instantiate the firewall endpoint for `subnet_id`, and answer the id it
/// minted — or `None` where it created none (see the module docs).
///
/// `vpc_id` is the VPC the firewall filters in and `service_name` the endpoint service all of
/// that firewall's endpoints are endpoints to ([`endpoint_service_name`]). The endpoint is
/// created with the firewall's own service id and subnet as its client token, so an ask
/// repeated for one firewall subnet replays EC2's own create rather than standing up a second
/// endpoint.
pub async fn instantiate(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    vpc_id: &str,
    subnet_id: &str,
    service_name: &str,
) -> Option<String> {
    let Some(client) = ec2_client(ctx, region) else {
        unasked(subnet_id, "there is no Amazon EC2 in this process to ask");
        return None;
    };
    let answer = client
        .create_vpc_endpoint()
        .vpc_endpoint_type(FIREWALL_ENDPOINT_TYPE)
        .vpc_id(vpc_id)
        .subnet_ids(subnet_id)
        .service_name(service_name)
        .client_token(format!("{service_name}-{subnet_id}"))
        .send()
        .await;
    match answer {
        Ok(output) => {
            let created = output
                .vpc_endpoint()
                .and_then(::aws_sdk_ec2::types::VpcEndpoint::vpc_endpoint_id)
                .map(str::to_string);
            if created.is_none() {
                // EC2 answered the create but reported no endpoint, so there is no endpoint
                // id to report.
                unasked(subnet_id, "Amazon EC2 reported no endpoint for the create");
            }
            created
        }
        Err(error) => {
            unasked(
                subnet_id,
                &::aws_smithy_types::error::display::DisplayErrorContext(&error).to_string(),
            );
            None
        }
    }
}

/// Trace a firewall endpoint Amazon EC2 did not create, which leaves the attachment carrying
/// an id no EC2 holds (see the module docs).
///
/// At `warn`: a deployment where this ask does not answer is one where no firewall endpoint
/// can be routed to, which is worth seeing, and `why` is what the SDK reported. The subnet id
/// is the caller's own value, rendered in its escaped `Debug` form so a value carrying a
/// newline cannot forge a log line.
fn unasked(subnet_id: &str, why: &str) {
    ::tracing::warn!(
        subnet_id = ?subnet_id,
        why = %why,
        "the firewall endpoint for a firewall subnet was not instantiated in Amazon EC2"
    );
}

/// Instantiate the firewall endpoint of every subnet of `subnet_ids`, and answer the
/// endpoints EC2 created, keyed by the subnet each one serves. A subnet EC2 created none for
/// is absent from the answer, and its attachment falls back to a minted id.
///
/// `subnet_ids` is bounded HERE rather than by each caller: one endpoint is asked for per
/// entry, so a list longer than the number of Availability Zones a firewall spans ("you can
/// specify one subnet for each of the Availability Zones that the VPC spans",
/// `AssociateSubnets`) has no endpoint asked for at all — both callers hold the request to
/// that ceiling and refuse past it before reaching here, so this is the bound stated at the
/// growth site rather than a second refusal.
pub async fn instantiate_all(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    vpc_id: &str,
    service_name: &str,
    subnet_ids: &[String],
) -> ::std::collections::HashMap<String, String> {
    let mut created = ::std::collections::HashMap::new();
    if subnet_ids.len() > crate::state::MAX_AVAILABILITY_ZONES {
        return created;
    }
    for subnet_id in subnet_ids {
        if let Some(endpoint_id) = instantiate(ctx, region, vpc_id, subnet_id, service_name).await
        {
            created.insert(subnet_id.clone(), endpoint_id);
        }
    }
    created
}

/// Ask Amazon EC2 to delete the firewall endpoints `endpoint_ids` names, as the attachment
/// each one belongs to goes away: "this removes the firewall endpoints from the subnets"
/// (`DisassociateSubnets`), and a deleted firewall takes its own endpoints with it.
///
/// There is nothing to report back: the attachment is gone from this service's record either
/// way, and an endpoint EC2 could not be asked about is traced at `warn` rather than failing
/// the delete that owns it.
pub async fn remove(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    endpoint_ids: Vec<String>,
) {
    if endpoint_ids.is_empty() {
        return;
    }
    let Some(client) = ec2_client(ctx, region) else {
        ::tracing::warn!(
            "there is no Amazon EC2 in this process to delete a firewall endpoint in"
        );
        return;
    };
    let answer = client
        .delete_vpc_endpoints()
        .set_vpc_endpoint_ids(Some(endpoint_ids))
        .send()
        .await;
    match answer {
        Ok(output) if output.unsuccessful().is_empty() => {}
        Ok(output) => ::tracing::warn!(
            unsuccessful = output.unsuccessful().len(),
            "Amazon EC2 did not delete every firewall endpoint it was asked to"
        ),
        Err(error) => ::tracing::warn!(
            error = %::aws_smithy_types::error::display::DisplayErrorContext(&error),
            "the firewall endpoints of a removed attachment could not be deleted in Amazon EC2"
        ),
    }
}

/// An AWS SDK client for Amazon EC2 over the in-process callback into this same emulator, or
/// `None` when `region` is not a Region LABEL.
///
/// The callback is the framework's documented seam for calling another emulated service: it
/// dispatches IN PROCESS to a service registered in this very emulator, so no socket is
/// opened and nothing leaves the host. The endpoint URL is only the address the SDK needs to
/// name the service and the Region it is addressing — the callback's HTTP client never
/// resolves or connects to it — which is also why there is nothing to retry, time out, watch
/// for a stalled stream or cache an identity for.
///
/// The Region a request is signed for is CALLER-SUPPLIED text, and here it ends up in that
/// URL's authority, so it is read as a Region label (`service_common::arn::region_label`, the
/// one place this tree states that grammar) instead of being interpolated as given: a value
/// carrying a host or path delimiter would name an authority the caller chose rather than the
/// peer service this emulator asks.
fn ec2_client(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
) -> Option<::aws_sdk_ec2::Client> {
    let region = ::service_common::arn::region_label(region)?;
    let config = ::aws_sdk_ec2::Config::builder()
        .behavior_version(::aws_sdk_ec2::config::BehaviorVersion::latest())
        .http_client(ctx.callback().http_client())
        .credentials_provider(ctx.callback().aws_credentials_provider())
        .region(::aws_sdk_ec2::config::Region::new(region.to_string()))
        .endpoint_url(format!("https://ec2.{region}.amazonaws.com"))
        .retry_config(::aws_sdk_ec2::config::retry::RetryConfig::disabled())
        .timeout_config(::aws_sdk_ec2::config::timeout::TimeoutConfig::disabled())
        .identity_cache(::aws_sdk_ec2::config::IdentityCache::no_cache())
        .stalled_stream_protection(::aws_sdk_ec2::config::StalledStreamProtectionConfig::disabled())
        .build();
    Some(::aws_sdk_ec2::Client::from_conf(config))
}
