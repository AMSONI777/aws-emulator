// SPDX-License-Identifier: CC0-1.0

//! The ONE reading of the host this service ANNOUNCES in a `DnsEntry`, and the entry
//! built on it.
//!
//! `DnsEntry` "describes the DNS information of a service", and its `domainName` is "the
//! domain name of the service"
//! (`smithy_query(query="shape",shape="DnsEntry")`); `CreateService`'s `dnsEntry` member
//! is documented "The public DNS name of the service." It is not a label a caller reads
//! back: it is the address a client in the VPC then DIALS to reach the service, so the one
//! requirement on it is that the responder actually answers there. The name the real
//! service hands out lives in a zone AWS serves, which resolves nowhere near this process
//! — or, worse, to genuine AWS infrastructure — so announcing one sends every
//! service-to-service call out of the emulated environment.
//!
//! What this emulator answers on is therefore what it announces, read through the tree's
//! one reading of that question ([`::service_common::data_plane_addressing`]), in the order
//! every announced address there resolves it: the emulator's OWN endpoint when the request
//! addressed it — a client configured with one local endpoint resolves nothing else, so it
//! is handed the very authority it is already talking to, port included — and otherwise
//! the address this process is served at, which is what a caller that resolves AWS's own
//! hostnames (an SDK pointed at the service's published host, or an in-process call of
//! another service) can reach too.
//!
//! The entry is built on every read as well as on the create, so nothing persists a host
//! this emulator may no longer be served at; the hosted-zone id of the entry is the
//! resource's own, minted once and kept on its record.

/// The `host[:port]` every `DnsEntry` of this service announces: the authority this
/// emulator answers the request being served on (see the module docs).
///
/// An emulator served on no port at all has no address of its own, and
/// [`::smithy_server_runtime::OperationContext::endpoint`] names its unserved base, whose
/// host is one nothing resolves — so even then the announced name leads no caller out of
/// this process.
pub fn announced_dns_host(ctx: &::smithy_server_runtime::OperationContext<'_>) -> String {
    let parts = ctx.parts();
    let host_header = parts
        .headers
        .get(::http::header::HOST)
        .and_then(|value| value.to_str().ok());
    ::service_common::data_plane_addressing::reached_emulator_endpoint(
        &parts.uri.to_string(),
        host_header,
    )
    .unwrap_or_else(|| ::service_common::data_plane_addressing::emulator_endpoint_authority(ctx))
}

/// The `DnsEntry` a response carries for a resource whose hosted zone is
/// `hosted_zone_id`: the host this emulator answers on ([`announced_dns_host`]) and the
/// resource's own stored hosted-zone id.
///
/// Every operation of this service that serializes a `DnsEntry` builds it here, so a
/// create, a read and a listing announce one address.
pub fn announced_dns_entry(
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    hosted_zone_id: &str,
) -> crate::ops::types::DnsEntry {
    crate::ops::types::DnsEntry {
        domain_name: Some(announced_dns_host(ctx)),
        hosted_zone_id: Some(hosted_zone_id.to_string()),
    }
}
