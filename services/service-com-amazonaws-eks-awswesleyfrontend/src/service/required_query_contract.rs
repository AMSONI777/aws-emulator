// SPDX-License-Identifier: CC0-1.0

//! The request this service answers BEFORE its router can name an operation: one
//! sent to an operation of this API that omits a query-string parameter the model
//! marks `@required`.
//!
//! RULE: a request whose method and path name an operation Amazon EKS serves IS
//! that operation's request. A query-string parameter the operation requires and
//! the request omits is a complaint about the REQUEST — refused with the
//! `InvalidParameterException` (400) the operation declares, in the sentence this
//! API states for that parameter — and never an answer that the operation does
//! not exist.
//!
//! WHY it is answered here: a `@required` `@httpQuery` member is part of the
//! route the framework matches, so a route whose required query binding is absent
//! from the request is not selected at all
//! (`vendor/smithy-schema-server/src/rest_xml.rs`'s `route_lookup`, shared by this
//! service's restJson1 protocol). With no route selected, the request reaches the
//! unknown-operation tail, which answers 501 `NotImplemented` — a server-fault
//! class a client retries or escalates, telling it the operation is unsupported
//! rather than that its own request is incomplete. That tail is the framework's,
//! so the only place to answer such a request is the seam this service has before
//! dispatch (`smithy_server_runtime::Service::override_operation`, reached through
//! [`super::request_pipeline`]), which is where this module is asked.
//!
//! NOTHING about the operation is written out here. Which requests an operation
//! addresses is read off its generated input schema by the shared reader every
//! service with such a route uses
//! ([`::service_common::addresses_modeled_http_route`]), and WHICH member the
//! request left out is read off the same model by the codec dispatch would have
//! used: the generated input carries the model's `@required` members, so the
//! deserializer that cannot build it names the absent one. The table below
//! therefore holds no URI, no method and no member name — only the operations
//! whose model binds a required member to the query string.
//!
//! Disambiguation is NOT at stake: each operation below binds a method and path
//! of its own, so a request matching one of them names that operation whatever
//! its query string carries.

use aws_smithy_runtime_api::http::{Request as RtRequest, Response as RtResponse};
use aws_smithy_schema::serde::SerdeError;
use aws_smithy_schema::Schema;
use aws_smithy_schema_server::ProtocolError;
use smithy_server_runtime::{
    DeserializableStruct, ErasedServiceDefinition, Refused, ServerHttpProtocol,
};

use crate::ops::types::{
    DescribeAddonConfigurationInput, DESCRIBE_ADDON_CONFIGURATION_INPUT_SCHEMA,
};

/// The error code this service states a refused request parameter in, and the one
/// every operation below declares for it (`@httpError 400`).
const INVALID_PARAMETER_EXCEPTION: &str = "InvalidParameterException";

/// Reads the request one candidate operation was sent to and names the member the
/// model requires and the request left out, or `None` when it left out none.
///
/// One per candidate rather than one generic function, because the member list is
/// the generated input TYPE's — which is where the model's `@required` members
/// live — and that type is named at the call site.
type MissingMemberReader = fn(&dyn ServerHttpProtocol, &RtRequest) -> Option<String>;

/// The operations of this service whose model binds a `@required` member to the
/// QUERY STRING, as `(the operation's generated input schema, its reader)`.
///
/// Source: the model itself —
/// `smithy_query(query="operation",operation="DescribeAddonConfiguration",
/// model_path="services/service-com-amazonaws-eks-awswesleyfrontend/smithy-model/com-amazonaws-eks-awswesleyfrontend.json")`
/// reports `GET /addons/configuration-schemas` with `addonName` and
/// `addonVersion` both `httpQuery` and `required`, and it is the only operation of
/// this service that requires a query parameter at all. The ROW is the schema, so
/// the method, the URI pattern and the member names stay the model's: an entry
/// cannot fall out of step with it.
const ROUTES_WITH_REQUIRED_QUERY: &[(&Schema, MissingMemberReader)] = &[(
    DESCRIBE_ADDON_CONFIGURATION_INPUT_SCHEMA,
    describe_addon_configuration_missing_member,
)];

/// See [`ROUTES_WITH_REQUIRED_QUERY`].
fn describe_addon_configuration_missing_member(
    protocol: &dyn ServerHttpProtocol,
    req: &RtRequest,
) -> Option<String> {
    missing_member::<DescribeAddonConfigurationInput>(
        protocol,
        DESCRIBE_ADDON_CONFIGURATION_INPUT_SCHEMA,
        req,
    )
}

/// The member `T` requires and this request left out, read by the codec the
/// dispatch sequence would have read the request with.
///
/// The generated input carries the model's `@required` members as non-optional
/// fields, so a request that omits one cannot be built at all and the
/// deserializer reports it as `SerdeError::MissingMember` with the member's own
/// name — the same failure the framework's own refusal tail words
/// (`vendor/smithy-server-runtime/src/pre_dispatch.rs`). Any other read failure
/// is not this module's question and leaves the request to the answer it had.
fn missing_member<T: DeserializableStruct>(
    protocol: &dyn ServerHttpProtocol,
    schema: &'static Schema,
    req: &RtRequest,
) -> Option<String> {
    let mut deserializer = protocol.deserialize_input(req, schema).ok()?;
    match T::deserialize(&mut *deserializer) {
        Ok(_) => None,
        Err(SerdeError::MissingMember { member_name }) => Some(member_name),
        Err(_) => None,
    }
}

/// Whether this request addresses one of the operations above — the decision
/// `crate::service::EmulatedService::override_operation` makes for a request the
/// routing table could not name an operation for.
///
/// Method and path are matched against the operation's own `@http` binding
/// through [`::service_common::addresses_modeled_http_route`], the one reader
/// every service with such a route shares, so this layer and the framework's
/// routing table cannot disagree about which requests the table already resolves.
pub fn has_a_question(req: &RtRequest) -> bool {
    addressed(req).is_some()
}

/// The candidate operation this request addresses, as
/// `(its input schema, its reader)`.
fn addressed(req: &RtRequest) -> Option<(&'static Schema, MissingMemberReader)> {
    ROUTES_WITH_REQUIRED_QUERY
        .iter()
        .find(|(schema, _)| ::service_common::addresses_modeled_http_route(req, schema))
        .map(|(schema, reader)| (*schema, *reader))
}

/// The member the operation this request addresses requires and the request left
/// out, or `None` when it addresses none of them or left out none.
pub fn missing_required_query(protocol: &dyn ServerHttpProtocol, req: &RtRequest) -> Option<String> {
    let (_, reader) = addressed(req)?;
    reader(protocol, req)
}

/// The refusal a request that omits a required query parameter earns, rendered in
/// this service's own envelope — or `None` when the request omits none, which
/// leaves it to the answer a request naming no operation earns.
///
/// It is rendered through the same call the framework's refusal tail makes
/// (`ErasedServiceDefinition::refusal_response` with this service's chosen code
/// and message), so a parameter refused here and one the validating walk refuses
/// are indistinguishable on the wire: 400, the `InvalidParameterException` this
/// API states that class in, and the sentence Amazon EKS publishes for the
/// parameter that was left out ([`crate::state::parameter_required_message`]).
pub fn refusal_response(
    definition: &dyn ErasedServiceDefinition,
    protocol: &dyn ServerHttpProtocol,
    req: &RtRequest,
) -> Option<RtResponse> {
    let member = missing_required_query(protocol, req)?;
    Some(definition.refusal_response(
        ProtocolError::Invalid(Vec::new()),
        Some(Refused {
            code: INVALID_PARAMETER_EXCEPTION.to_string(),
            message: crate::state::parameter_required_message(&member),
        }),
        req,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ::aws_smithy_types::body::SdkBody;

    /// A request to `method` `uri` with no body.
    fn request(method: &str, uri: &str) -> RtRequest {
        let mut req = RtRequest::new(SdkBody::empty());
        req.set_method(method).expect("the method must be valid");
        req.set_uri(uri).expect("the uri must be valid");
        req
    }

    /// RULE: only a method and path one of these operations binds is claimed.
    #[test]
    fn only_a_modeled_route_of_a_candidate_operation_is_claimed() {
        for (case, method, uri, expected) in [
            (
                "the operation's own route",
                "GET",
                "/addons/configuration-schemas",
                true,
            ),
            (
                "its own route, with a query string",
                "GET",
                "/addons/configuration-schemas?addonName=vpc-cni",
                true,
            ),
            (
                "another operation's route",
                "GET",
                "/addons/supported-versions",
                false,
            ),
            (
                "the same path with another method",
                "POST",
                "/addons/configuration-schemas",
                false,
            ),
            ("a cluster read", "GET", "/clusters/probe", false),
            (
                "a longer path under the same prefix",
                "GET",
                "/addons/configuration-schemas/extra",
                false,
            ),
        ] {
            assert_eq!(
                has_a_question(&request(method, uri)),
                expected,
                "case {case:?}: expected {expected} for {method} {uri}"
            );
        }
    }
}
