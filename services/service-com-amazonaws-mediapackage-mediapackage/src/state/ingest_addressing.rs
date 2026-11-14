// SPDX-License-Identifier: CC0-1.0

//! WHERE a channel's HLS ingest endpoints are ANNOUNCED: the origin every ingest URL
//! `CreateChannel` publishes for a channel is rooted at.
//!
//! `IngestEndpoint$Url` is "The ingest URL to which the source stream should be sent"
//! (`smithy_query(query="shape",shape="com.amazonaws.mediapackage#IngestEndpoint",model_path="services/service-com-amazonaws-mediapackage-mediapackage/smithy-model/com-amazonaws-mediapackage-mediapackage.json")`),
//! so it is an address an encoder DIALS afterwards — and a Digest client is driven
//! entirely by what that address answers ([`super::data_plane`]). It therefore has to name
//! a host this emulator answers on. AWS publishes a channel's ingest on a per-account
//! hostname beneath its own regional domain ([`super::media_hostname`]), and a client on
//! the machine this emulator runs on resolves none of those names: announcing one sends
//! that encoder off this process entirely, where it is never challenged and can never
//! push. The address announced is therefore the endpoint the creating request reached, in
//! three cases:
//!
//! * a request that reached the EMULATOR'S OWN endpoint comes from a client configured
//!   with that one endpoint and resolving nothing else, so the channel is announced there;
//! * a request that addressed some other host on an emulator that IS served on a port is
//!   announced that port — the one address this process answers on — so a channel minted
//!   by an in-process call of another service publishes an address its caller can reach
//!   too;
//! * a request that addressed one of AWS's own hosts on an emulator served on no port at
//!   all comes from a client that resolves them, and there is no own address to announce,
//!   so the hostname AWS itself would publish stands.
//!
//! The choice is made ONCE, when the channel is created, and persisted in the ingest
//! endpoints stored on the channel record: the create answer, every `DescribeChannel`,
//! every `ListChannels` element, `UpdateChannel`, `ConfigureLogs` and both credential
//! rotations project those stored endpoints ([`super::ChannelRecord::to_channel`]), so a
//! channel is announced at one stable address however it is read.

use super::*;

/// The scheme-and-separator prefix an announced ingest origin carries. Ingest is TLS-only,
/// so the prefix is always this one; it carries the `://` separator, so the path below the
/// origin ([`super::data_plane::ingest_path`]) is appended and no scheme is re-added.
pub const INGEST_ORIGIN_PREFIX: &str = "https://";

/// The origin the ingest URLs of a channel created by `parts` are ANNOUNCED under — the
/// scheme and authority every one of that channel's ingest URLs is rooted at.
///
/// See the module docs for the three cases. `parts` is the request that creates the
/// channel and `served_base` the base URL
/// [`::smithy_server_runtime::OperationContext::endpoint`] reports for this emulator.
pub fn announced_ingest_origin(
    parts: &::http::request::Parts,
    served_base: &str,
    region: &str,
) -> String {
    let authority = reached_emulator_endpoint(parts)
        .or_else(|| served_endpoint_authority(served_base))
        .unwrap_or_else(|| media_hostname(region));
    format!("{INGEST_ORIGIN_PREFIX}{authority}")
}

/// The EMULATOR'S OWN endpoint this request reached — an address or a loopback name, which
/// is what a client configured with one local endpoint URL sends — and `None` for a request
/// whose host names a service, which is a client that resolves AWS's own hosts.
///
/// The tree's one reading of that question, taken off the request parts a handler is given
/// (`service_common::data_plane_addressing::reached_emulator_endpoint_of_parts`), so this
/// service writes no second rule for which host is the emulator's own and repeats no
/// extraction of where a request carries it.
fn reached_emulator_endpoint(parts: &::http::request::Parts) -> Option<String> {
    ::service_common::data_plane_addressing::reached_emulator_endpoint_of_parts(parts)
}

/// The `host[:port]` this emulator is SERVED at, or `None` for one served on no port at
/// all — the tree's one reading of that question
/// (`service_common::data_plane_addressing::served_endpoint_authority`).
fn served_endpoint_authority(served_base: &str) -> Option<String> {
    ::service_common::data_plane_addressing::served_endpoint_authority(served_base)
}
