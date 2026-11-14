// SPDX-License-Identifier: CC0-1.0

//! The request-claim rule for the SIX emulated services whose SigV4 signing name is
//! `bedrock`, stated once here and read by every one of them.
//!
//! `aws.auth#sigv4` names `bedrock` on all six Bedrock-family models, while each one
//! serves its own endpoint (`smithy_query(query="service_info")` on each model gives the
//! endpoint prefixes `bedrock`, `bedrock-runtime`, `bedrock-agent`,
//! `bedrock-agent-runtime`, `bedrock-data-automation` and
//! `bedrock-data-automation-runtime` against that ONE signing name). The router resolves
//! a request's routing key from the SigV4 credential scope first, so all six see the key
//! `bedrock`: a service that claims on the signing name ALONE claims every sibling's
//! traffic too, the router finds six claimants and — refusing to serve a request by an
//! arbitrary one — answers `500 AmbiguousService`, a code no AWS model carries, for every
//! Bedrock request. AWS separates them by endpoint HOST, which an emulator cannot read: a
//! client configured with one local endpoint sends the same `Host` for all six.
//!
//! The claim is therefore [`crate::claims_request`]'s rule — the signing name AND the
//! request's own modelled wire surface, which is the first URI path segment for a REST
//! model and the service the `X-Amz-Target` names for the `awsJson1_1` one — narrowed by
//! the split below wherever MORE THAN ONE of these models publishes the same first path
//! segment. Source for every segment named here: `smithy_query(query="digest")` on each
//! of the six models.

use smithy_server_runtime::ErasedServiceDefinition;

/// The `aws.api#service$arnNamespace` every Bedrock-family model shares
/// (`smithy_query(query="service_info")` on each of the six reports `bedrock`), and so
/// the only service field an ARN any of them addresses can carry.
pub const ARN_NAMESPACE: &str = "bedrock";

/// The Smithy shape id of each emulated service that signs as `bedrock`, as
/// `definition().identity().shape_id()` reports it. A member names itself by its shape id
/// rather than by a flag the call site passes, so the ownership table below cannot
/// disagree with the service reading it.
pub const CONTROL_PLANE: &str = "com.amazonaws.bedrock#AmazonBedrockControlPlaneService";
/// The `bedrock-runtime` data plane (`Converse`, `InvokeModel`, `ApplyGuardrail`).
pub const RUNTIME: &str = "com.amazonaws.bedrockruntime#AmazonBedrockFrontendService";
/// The `bedrock-agent` build-time control plane (agents, knowledge bases, flows, prompts).
pub const AGENT: &str = "com.amazonaws.bedrockagent#AmazonBedrockAgentBuildTimeLambda";
/// The `bedrock-agent-runtime` data plane (`InvokeAgent`, `Retrieve`, `InvokeFlow`).
pub const AGENT_RUNTIME: &str =
    "com.amazonaws.bedrockagentruntime#AmazonBedrockAgentRunTimeService";
/// The `bedrock-data-automation` build-time control plane (blueprints, projects).
pub const DATA_AUTOMATION: &str =
    "com.amazonaws.bedrockdataautomation#AmazonBedrockKeystoneBuildTimeService";
/// The `bedrock-data-automation-runtime` data plane — the one `awsJson1_1` model of the
/// six, which publishes no `smithy.api#http` bindings and so posts every operation to `/`.
pub const DATA_AUTOMATION_RUNTIME: &str =
    "com.amazonaws.bedrockdataautomationruntime#AmazonBedrockKeystoneRuntimeService";

/// How a first path segment that more than one Bedrock-family model publishes is split
/// between its sharers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shared {
    /// The sharers bind DIFFERENT routes under this segment, so the whole route — method
    /// plus URI pattern — tells them apart: each one claims only a request its own model
    /// binds a route for ([`crate::addresses_modeled_route`]).
    ///
    /// A path under such a segment that NO model binds therefore reaches nobody, and the
    /// router answers it `404 UnknownService` rather than one service's protocol routing
    /// error. That is the narrow cost of not guessing: no AWS operation lives on such a
    /// path, while handing the whole segment to one sharer would make every one of the
    /// other's operations in it unreachable.
    ByRoute,
    /// The sharers bind the SAME routes under this segment, so no part of the request
    /// tells them apart (AWS tells them apart by endpoint host, which is not on the
    /// wire here). The named service answers the whole segment; its sharer's operations
    /// there are unreachable, which keeps the owner's working instead of refusing both
    /// with `500 AmbiguousService`.
    OwnedBy(&'static str),
    /// The sharers bind the SAME routes under this segment and the route's one
    /// `@httpLabel` is the ARN OF THE RESOURCE being tagged, whose syntax each sharer's
    /// model spells out in its own taggable-resource shape — the resource TYPES it
    /// enumerates and the IDENTIFIER form it states for them — and those syntaxes are
    /// DISJOINT, each admitting only resources that sharer's plane mints.
    ///
    /// So the request is placed in two tiers ([`tagging_sharer`]): the endpoint HOST names
    /// the sharer when it names one at all, which is AWS's own discriminator; otherwise the
    /// ARN does — the sharer whose taggable-resource syntax ADMITS it claims the request
    /// ([`tagged_resource_owner`]), and an ARN no sharer's syntax admits, which neither can
    /// resolve, goes to the segment's declared owner.
    ByTaggedResourceType,
}

/// Every first URI path segment more than one Bedrock-family model publishes, and how it
/// is split. Each sharer reads this one table, so the claims cannot drift into a path
/// with two claimants (the `AmbiguousService` refusal) or none.
///
/// * `agents`, `flows`, `knowledgebases` — `bedrock-agent` (build time) and
///   `bedrock-agent-runtime` both publish them and bind different routes underneath
///   (`PUT /knowledgebases/` and `POST /knowledgebases/{knowledgeBaseId}/datasources/`
///   against `POST /knowledgebases/{knowledgeBaseId}/retrieve`), so the route decides.
/// * `tags` — the same two both bind `GET`, `POST` and `DELETE /tags/{resourceArn}`, the
///   identical three routes, so neither the method nor the URI template decides. What DOES
///   decide is first the endpoint HOST, and then the ARN the one `@httpLabel` carries,
///   judged against the whole taggable-resource syntax each of the two models spells out —
///   the resource types its own tagging admits AND the identifier form it states for them.
///   Those syntaxes are disjoint: the build-time plane's taggable resources are the ones it
///   mints (an agent, an agent alias, a knowledge base, a flow, a prompt, a retrieval
///   instruction, each identified by ten alphanumeric characters) and the data plane's are
///   the ones it mints (a session, an advanced-optimize-prompt job). Each endpoint ANSWERS
///   an ARN its own model admits and refuses one it does not — the recorded
///   `bedrock-agent-runtime` refusal of an ARN outside the runtime's syntax quotes the
///   RUNTIME's pattern, whatever resource type that ARN names — so the plane whose syntax
///   admits the ARN is the one that serves the request ([`Shared::ByTaggedResourceType`]).
///   An ARN neither model's syntax admits falls to the declared owner, as the three
///   identically-bound tagging segments below do: the data plane.
/// * `listTagsForResource`, `tagResource`, `untagResource` — the `bedrock` control plane
///   and `bedrock-data-automation` both bind `POST` on each of these three, again
///   identically, and the control plane is the member every Bedrock tagging flow uses.
const SHARED_SEGMENTS: &[(&str, Shared)] = &[
    ("agents", Shared::ByRoute),
    ("flows", Shared::ByRoute),
    ("knowledgebases", Shared::ByRoute),
    ("listTagsForResource", Shared::OwnedBy(CONTROL_PLANE)),
    ("tagResource", Shared::OwnedBy(CONTROL_PLANE)),
    ("tags", Shared::ByTaggedResourceType),
    ("untagResource", Shared::OwnedBy(CONTROL_PLANE)),
];

/// Whether the Bedrock-family service whose generated `ServiceDefinition` is `definition`
/// claims `parts`.
///
/// * `path_segments` — that service's generated `crate::ROUTE_PATH_SEGMENTS`, the first
///   URI path segments its model declares.
/// * `rpc_service_shape_id` — `Some(definition.identity().shape_id())` for the one model
///   of the six that declares an RPC protocol (`awsJson1_1`), whose wire form names its
///   service out of band; `None` for the five `restJson1` models, which are discriminated
///   by their path space.
///
/// The signing name is read off `definition`, so a member cannot claim under a name its
/// model does not declare.
pub fn claims_request(
    parts: &http::request::Parts,
    definition: &dyn ErasedServiceDefinition,
    path_segments: &[&str],
    rpc_service_shape_id: Option<&str>,
) -> bool {
    let identity = definition.identity();
    if !crate::claims_request(
        parts,
        identity.signing_name(),
        path_segments,
        rpc_service_shape_id,
    ) {
        return false;
    }
    match shared_split(parts.uri.path()) {
        None => true,
        Some(Shared::ByRoute) => {
            crate::addresses_modeled_route(parts, definition)
                && trailing_slash_owner(parts)
                    .is_none_or(|owner| identity.shape_id() == owner)
        }
        Some(Shared::OwnedBy(owner)) => identity.shape_id() == owner,
        Some(Shared::ByTaggedResourceType) => identity.shape_id() == tagging_sharer(parts),
    }
}

/// One sharer of the identically-bound `/tags/{resourceArn}` routes, as the two tiers that
/// place such a request read it.
#[derive(Debug, Clone, Copy)]
struct TaggingSharer {
    /// The sharer's Smithy shape id, as `definition().identity().shape_id()` reports it.
    shape_id: &'static str,
    /// Its `aws.api#service$endpointPrefix` — the host AWS itself tells the two apart by.
    endpoint_prefix: &'static str,
    /// The `resource-type` fields its own taggable-resource expression enumerates.
    resource_types: &'static [&'static str],
    /// Whether the identifier that follows such a type is of the form that same expression
    /// states for it.
    admits_identifier: fn(&str) -> bool,
}

/// The two sharers of the identically-bound `/tags/{resourceArn}` routes, each with the
/// taggable-resource syntax its OWN model spells out
/// (`smithy_query(query="shape",shape="TaggableResourcesArn")` on each of the two) and the
/// endpoint it is served on (`smithy_query(query="service_info")` on each): the build-time
/// plane's taggable resources are the ones it mints, and the data plane's are the ones it
/// mints — the published expression of the second widening the modelled `session` with the
/// optimization job that plane also mints (see that service's own `PUBLISHED_PATTERNS`).
///
/// The two syntaxes are disjoint, so an ARN is admitted by at most one sharer.
const TAGGING_SHARERS: &[TaggingSharer] = &[
    TaggingSharer {
        shape_id: AGENT,
        endpoint_prefix: "bedrock-agent",
        resource_types: &[
            "agent",
            "agent-alias",
            "knowledge-base",
            "flow",
            "prompt",
            "retrieval-instruction",
        ],
        admits_identifier: is_build_time_identifier,
    },
    TaggingSharer {
        shape_id: AGENT_RUNTIME,
        endpoint_prefix: "bedrock-agent-runtime",
        resource_types: &["session", "advanced-optimize-prompt-job"],
        admits_identifier: is_runtime_identifier,
    },
];

/// Characters in an identifier of a resource the BUILD-TIME plane mints: its
/// taggable-resource expression spells every one of them as ten characters
/// (`[A-Z0-9]{10}`, and `[a-z0-9]{10}` for a retrieval instruction), which is the `Id`
/// shape that model's own resources carry (`^[0-9a-zA-Z]{10}$`).
const BUILD_TIME_IDENTIFIER_LENGTH: usize = 10;

/// Whether `identifier` is of the form the build-time plane's taggable-resource expression
/// states: [`BUILD_TIME_IDENTIFIER_LENGTH`] alphanumeric characters, in either case,
/// because that expression spells the same identifier upper-case in three of its
/// alternatives and lower-case in the fourth while the `Id` shape behind it admits both.
///
/// A prompt ARN may carry the prompt's VERSION after a `:` (`prompt/<id>:<version>`),
/// which that expression states separately and which is not part of the identifier.
fn is_build_time_identifier(identifier: &str) -> bool {
    let id = identifier
        .split_once(':')
        .map_or(identifier, |(id, _version)| id);
    id.len() == BUILD_TIME_IDENTIFIER_LENGTH
        && id.chars().all(|character| character.is_ascii_alphanumeric())
}

/// Whether `identifier` is of the form the DATA plane's published taggable-resource
/// expression states for both resource kinds it admits (`[a-zA-Z0-9-]+`): a session's uuid
/// and an optimization job's identifier are both of it.
fn is_runtime_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

/// The sharer a tagging request whose ARN is admitted by NEITHER plane's taggable-resource
/// syntax belongs to: the segment's declared owner, as the three identically-bound tagging
/// segments of the other pair are owned. Neither plane can resolve such an ARN, so the
/// request still reaches exactly one claimant rather than none or both — and the one it
/// reaches refuses it against its own published expression.
const TAGGED_RESOURCE_DECLARED_OWNER: &str = AGENT_RUNTIME;

/// Which sharer of the identically-bound `/tags/{resourceArn}` routes `parts` belongs to,
/// in the two tiers [`Shared::ByTaggedResourceType`] states: the endpoint HOST where it
/// names one of them, and otherwise the ARN in the one `@httpLabel`.
fn tagging_sharer(parts: &http::request::Parts) -> &'static str {
    tagging_endpoint_addressed(parts).unwrap_or_else(|| tagged_resource_owner(parts.uri.path()))
}

/// The sharer whose ENDPOINT the request addresses, or `None` when its host names neither
/// — a loopback or IP endpoint, which is what a client pointed at the emulator sends, and
/// every recorded request.
///
/// This is AWS's own discriminator between two endpoints that serve the identical route,
/// read exactly as [`crate::endpoint_family`] reads it (`emulator_server`'s host readers,
/// and the `:authority` an HTTP/2 request carries on the URI instead of a `Host`), so a
/// client pointed at one of the two real endpoint hosts reaches that endpoint's service
/// whatever ARN it sends — including an ARN that endpoint itself refuses.
fn tagging_endpoint_addressed(parts: &http::request::Parts) -> Option<&'static str> {
    let host = ::emulator_server::service_from_host(&parts.headers)
        .or_else(|| ::emulator_server::service_from_authority(&parts.uri))?;
    TAGGING_SHARERS
        .iter()
        .find(|sharer| host.eq_ignore_ascii_case(sharer.endpoint_prefix))
        .map(|sharer| sharer.shape_id)
}

/// Which sharer the ARN on `path` names: the plane whose own taggable-resource syntax
/// ADMITS it ([`TAGGING_SHARERS`]), and otherwise [`TAGGED_RESOURCE_DECLARED_OWNER`].
///
/// The label is read as the codec that deserializes the request reads it, percent escapes
/// resolved ([`crate::percent_decode_path_label`]), because a non-greedy `@httpLabel`
/// carrying an ARN reaches the wire percent-encoded.
fn tagged_resource_owner(path: &str) -> &'static str {
    let Some(label) = super::nth_path_segment(path, 1).map(crate::percent_decode_path_label) else {
        return TAGGED_RESOURCE_DECLARED_OWNER;
    };
    let Some((resource_type, identifier)) = tagged_resource(&label) else {
        return TAGGED_RESOURCE_DECLARED_OWNER;
    };
    TAGGING_SHARERS
        .iter()
        .find(|sharer| {
            sharer.resource_types.contains(&resource_type) && (sharer.admits_identifier)(identifier)
        })
        .map_or(TAGGED_RESOURCE_DECLARED_OWNER, |sharer| sharer.shape_id)
}

/// The `resource-type` field of `arn` and the identifier that follows it, where `arn` is an
/// ARN of this family's namespace; `None` for anything else.
///
/// Read through [`crate::arn`], the one ARN parse of this crate: the resource field of
/// every taggable resource of this family is `<resource-type>/<resource-id>` (an agent
/// alias and a flow alias append a further segment, which leaves both the type and the
/// first identifier where they are, and a prompt version appends `:<version>` to the
/// identifier). The comparison is case-sensitive, as an ARN's resource type is.
fn tagged_resource(arn: &str) -> Option<(&str, &str)> {
    let parsed = crate::arn::parse_of(arn, ARN_NAMESPACE)?;
    let (resource_type, rest) = parsed.resource.split_once('/')?;
    Some((
        resource_type,
        rest.split_once('/').map_or(rest, |(first, _rest)| first),
    ))
}

/// The ONE route shape both `agents` sharers bind, which [`Shared::ByRoute`] cannot split:
/// the build-time plane's `POST /agents/{agentId}/` (`PrepareAgent`) and the data plane's
/// `POST /agents/{sessionId}` (`InvokeInlineAgent`). Source:
/// `smithy_query(query="digest")` on each of the two models.
const AGENTS_SEGMENT: &str = "agents";

/// The sharer a request on that one route shape belongs to, or `None` when the request is
/// not on it — in which case the route alone already names one claimant.
///
/// The framework's route matcher trims a trailing `/` from both the request path and the
/// URI template, so the two templates above match the SAME requests and both models bind
/// one: the route rule leaves two claimants, which the router answers `500 AmbiguousService`
/// rather than serving either. AWS separates the two by endpoint host, which is not on the
/// wire here; what IS on the wire is the spelling a client renders from the model's own URI,
/// and those two URIs differ in the trailing slash. So the request's own trailing slash
/// decides: `/agents/<id>/` is the build-time plane's `PrepareAgent`, `/agents/<id>` the
/// data plane's `InvokeInlineAgent`.
fn trailing_slash_owner(parts: &http::request::Parts) -> Option<&'static str> {
    if parts.method != http::Method::POST {
        return None;
    }
    let path = parts.uri.path();
    let ends_with_slash = path.ends_with('/');
    let mut segments = path.trim_matches('/').split('/');
    let (Some(AGENTS_SEGMENT), Some(_label), None) =
        (segments.next(), segments.next(), segments.next())
    else {
        // Anything else is not this route shape: `/agents/` and `/agents` carry no
        // identifier (both models bind `PUT`/`POST /agents/`, which the method and the
        // route already separate), and a deeper path is a route only one of them binds.
        return None;
    };
    Some(if ends_with_slash { AGENT } else { AGENT_RUNTIME })
}

/// How the first segment of `path` is split, or `None` when only one Bedrock-family model
/// publishes it (the overwhelmingly common case, where the first segment already names
/// exactly one member). Matching is exact segment equality, as the framework's own
/// discriminator is.
fn shared_split(path: &str) -> Option<Shared> {
    let segment = super::first_path_segment(path)?;
    SHARED_SEGMENTS
        .iter()
        .find(|(shared, _)| *shared == segment)
        .map(|(_, split)| *split)
}

#[cfg(test)]
mod tests {
    //! The parts of the rule that need no built service: which segments are shared, and
    //! how each one is split.

    use super::*;

    /// Every segment in the table is split exactly one way, and a segment only one model
    /// publishes is not in it at all.
    #[test]
    fn the_shared_segments_are_declared_once_each() {
        // (case, path, expected split)
        let rows: [(&str, &str, Option<Shared>); 14] = [
            ("the agent pair's agents", "/agents/", Some(Shared::ByRoute)),
            (
                "a deep path under it",
                "/agents/AGENT1/agentversions/1/knowledgebases/",
                Some(Shared::ByRoute),
            ),
            ("flows", "/flows/f-1/aliases", Some(Shared::ByRoute)),
            (
                "knowledgebases",
                "/knowledgebases/kb-1/retrieve",
                Some(Shared::ByRoute),
            ),
            (
                "the agent pair's identical tagging routes",
                "/tags/arn%3Aaws%3Abedrock%3A%3A%3Aagent%2Fa1",
                Some(Shared::ByTaggedResourceType),
            ),
            (
                "the same tagging space addressed with a session ARN",
                "/tags/arn%3Aaws%3Abedrock%3A%3A%3Asession%2Fs1",
                Some(Shared::ByTaggedResourceType),
            ),
            (
                "the same tagging space addressed with no ARN at all",
                "/tags/not-an-arn",
                Some(Shared::ByTaggedResourceType),
            ),
            (
                "the control plane's tagging routes",
                "/tagResource",
                Some(Shared::OwnedBy(CONTROL_PLANE)),
            ),
            (
                "untagResource",
                "/untagResource",
                Some(Shared::OwnedBy(CONTROL_PLANE)),
            ),
            (
                "listTagsForResource",
                "/listTagsForResource",
                Some(Shared::OwnedBy(CONTROL_PLANE)),
            ),
            // Segments exactly one of the six models publishes: not shared, so the first
            // segment alone already names one claimant.
            ("the control plane's guardrails", "/guardrails", None),
            ("the data plane's model invocations", "/model/m-1/invoke", None),
            ("a near miss on a shared segment", "/agentsextra", None),
            ("the root path", "/", None),
        ];

        for (case, path, expected) in rows {
            let actual = shared_split(path);
            assert_eq!(
                actual, expected,
                "case {case:?}: {path:?} expected {expected:?}, got {actual:?}"
            );
        }
    }

    /// A shared segment owned by one member is owned by a member of this family, and no
    /// segment is declared twice.
    #[test]
    fn every_owner_is_a_member_and_no_segment_repeats() {
        let members = [
            CONTROL_PLANE,
            RUNTIME,
            AGENT,
            AGENT_RUNTIME,
            DATA_AUTOMATION,
            DATA_AUTOMATION_RUNTIME,
        ];
        let mut seen: Vec<&str> = Vec::new();
        for (segment, split) in SHARED_SEGMENTS {
            assert!(
                !seen.contains(segment),
                "segment {segment:?} is declared more than once"
            );
            seen.push(segment);
            match split {
                Shared::OwnedBy(owner) => assert!(
                    members.contains(owner),
                    "segment {segment:?} is owned by {owner:?}, which is not a member of \
                     the bedrock family"
                ),
                Shared::ByRoute | Shared::ByTaggedResourceType => {}
            }
        }

        // The tagging split names members of this family too, and its two syntaxes are
        // DISJOINT in their resource types — which is what makes an ARN admitted by at
        // most one sharer.
        let mut claimed: Vec<&str> = Vec::new();
        for sharer in TAGGING_SHARERS {
            assert!(
                members.contains(&sharer.shape_id),
                "the tagging split names {:?}, which is not a member of the bedrock family",
                sharer.shape_id
            );
            for resource_type in sharer.resource_types {
                assert!(
                    !claimed.contains(resource_type),
                    "resource type {resource_type:?} is claimed by more than one sharer"
                );
                claimed.push(resource_type);
            }
        }
        assert!(
            members.contains(&TAGGED_RESOURCE_DECLARED_OWNER),
            "the declared owner of the tagging space is a member of the bedrock family"
        );
    }

    /// RULE: on the tagging path space the sharers bind IDENTICALLY, the ARN in the
    /// `@httpLabel` names the plane whose own taggable-resource syntax ADMITS it — the
    /// resource types that plane's model enumerates and the identifier form it states for
    /// them, the two syntaxes being disjoint — and an ARN neither syntax admits goes to
    /// the segment's declared owner.
    ///
    /// The rows differ along the resource type the ARN names (each enumeration, both
    /// sharers), the partition, the spelling of the label's separators, the identifier
    /// form (admitted, too long, too short, empty, punctuated), the casing of the fields,
    /// another vendor's ARN, and the labels that name no resource at all.
    #[test]
    fn the_tagging_path_belongs_to_the_plane_whose_syntax_admits_the_arn() {
        /// The label as a client that percent-encodes a non-greedy `@httpLabel` sends it.
        fn encoded(arn: &str) -> String {
            arn.replace(':', "%3A").replace('/', "%2F")
        }

        const SESSION: &str =
            "arn:aws:bedrock:us-west-2:000000000000:session/0cabde93-58b4-4d68-b230-90df328e1acb";

        let rows: Vec<(&str, String, &'static str)> = vec![
            (
                "a session ARN, percent-encoded as an SDK sends it",
                format!("/tags/{}", encoded(SESSION)),
                AGENT_RUNTIME,
            ),
            (
                "the same session ARN sent raw",
                format!("/tags/{SESSION}"),
                AGENT_RUNTIME,
            ),
            (
                "a session ARN in another partition",
                format!(
                    "/tags/{}",
                    encoded(
                        "arn:aws-us-gov:bedrock:us-gov-west-1:000000000000:session/\
                         11111111-2222-3333-4444-555555555555"
                    )
                ),
                AGENT_RUNTIME,
            ),
            (
                "a non-canonically cased session ARN, which is no resource type either \
                 model names",
                format!(
                    "/tags/{}",
                    encoded(
                        "arn:aws:bedrock:us-west-2:000000000000:Session/\
                         0cabde93-58b4-4d68-b230-90df328e1acb"
                    )
                ),
                AGENT_RUNTIME,
            ),
            (
                "an ARN of the other resource kind the data plane's tagging admits",
                format!(
                    "/tags/{}",
                    encoded(
                        "arn:aws:bedrock:us-east-1:000000000000\
                         :advanced-optimize-prompt-job/job-1"
                    )
                ),
                AGENT_RUNTIME,
            ),
            (
                "an agent ARN, naming a build-time plane resource",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:agent/AGENT12345")
                ),
                AGENT,
            ),
            (
                // The recorded `bedrock-agent-runtime` refusal of exactly this ARN quotes
                // the RUNTIME's own expression: an identifier outside the build-time
                // plane's form names no resource that plane mints, so the ARN is admitted
                // by neither syntax and the declared owner answers it.
                "an agent ARN whose identifier is one character past the build-time form",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:agent/NOTASESSION")
                ),
                AGENT_RUNTIME,
            ),
            (
                "a knowledge-base ARN whose identifier is one character short of it",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:knowledge-base/KB1234567")
                ),
                AGENT_RUNTIME,
            ),
            (
                "a flow ARN carrying no identifier at all",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:flow/")
                ),
                AGENT_RUNTIME,
            ),
            (
                "an agent ARN whose identifier carries punctuation that form excludes",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:agent/AGENT-1234")
                ),
                AGENT_RUNTIME,
            ),
            (
                "an agent alias ARN, whose resource field carries two identifiers",
                format!(
                    "/tags/{}",
                    encoded(
                        "arn:aws:bedrock:us-east-1:000000000000:agent-alias/AGENT12345/ALIAS12345"
                    )
                ),
                AGENT,
            ),
            (
                "a knowledge-base ARN",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:knowledge-base/KB12345678")
                ),
                AGENT,
            ),
            (
                "a flow alias ARN",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:flow/FLOW123456/alias/AL12345678")
                ),
                AGENT,
            ),
            (
                "a prompt version ARN, whose identifier carries the version",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:prompt/PROMPT1234:3")
                ),
                AGENT,
            ),
            (
                "a retrieval-instruction ARN",
                format!(
                    "/tags/{}",
                    encoded(
                        "arn:aws:bedrock:us-east-1:000000000000:retrieval-instruction/ri123456ab"
                    )
                ),
                AGENT,
            ),
            (
                // The build-time plane's identifiers are ten alphanumerics in EITHER case:
                // the taggable expression spells three of its alternatives upper-case and
                // one lower-case, while the `Id` shape behind them admits both.
                "a lower-case agent identifier",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:agent/aZ09aZ09aZ")
                ),
                AGENT,
            ),
            (
                "another service's ARN",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:sqs:us-east-1:000000000000:session/q")
                ),
                AGENT_RUNTIME,
            ),
            (
                "a bedrock ARN naming a resource type neither model's tagging admits",
                format!(
                    "/tags/{}",
                    encoded("arn:aws:bedrock:us-east-1:000000000000:guardrail/gr1234567890")
                ),
                AGENT_RUNTIME,
            ),
            (
                "a label that is not an ARN",
                "/tags/not-an-arn".to_string(),
                AGENT_RUNTIME,
            ),
            ("no label at all", "/tags".to_string(), AGENT_RUNTIME),
        ];

        for (case, path, expected) in rows {
            let split = shared_split(&path);
            assert_eq!(
                split,
                Some(Shared::ByTaggedResourceType),
                "case {case:?} ({path}): expected the segment to be split by the tagged \
                 resource's syntax, got {split:?}"
            );
            let actual = tagged_resource_owner(&path);
            assert_eq!(
                actual, expected,
                "case {case:?} ({path}): expected {expected:?}, got {actual:?}"
            );
        }
    }

    /// RULE: the first tier of that split is the endpoint the request addresses — a host
    /// naming one sharer's `endpointPrefix` hands it that sharer, whatever ARN the label
    /// carries, and a host naming neither leaves the ARN to decide.
    ///
    /// The rows span both sharers' endpoint hosts, a regional and a global spelling of
    /// one, a host carrying a port, another family member's endpoint, the loopback host a
    /// client pointed at the emulator sends, and no host at all — each with an ARN the
    /// OTHER tier would place elsewhere, so every row shows which tier decided.
    #[test]
    fn the_endpoint_the_tagging_request_addresses_names_the_sharer() {
        /// One `GET /tags/<arn>` request, as `can_handle` is handed it.
        fn parts(host: Option<&str>, arn: &str) -> ::http::request::Parts {
            let mut builder = ::http::Request::builder()
                .method("GET")
                .uri(format!("/tags/{}", arn.replace(':', "%3A").replace('/', "%2F")));
            if let Some(host) = host {
                builder = builder.header("host", host);
            }
            builder
                .body(())
                .expect("the request builds")
                .into_parts()
                .0
        }

        const SESSION: &str =
            "arn:aws:bedrock:us-west-2:000000000000:session/0cabde93-58b4-4d68-b230-90df328e1acb";
        const AGENT_ARN: &str = "arn:aws:bedrock:us-east-1:000000000000:agent/AGENT12345";

        // (case, the request's Host, the ARN in the label, the sharer it belongs to)
        let rows: [(&str, Option<&str>, &str, &str); 8] = [
            (
                "the build-time plane's endpoint, addressed with a session ARN",
                Some("bedrock-agent.us-east-1.amazonaws.com"),
                SESSION,
                AGENT,
            ),
            (
                "its global spelling, addressed with an ARN it refuses",
                Some("bedrock-agent.amazonaws.com"),
                "arn:aws:bedrock:us-east-1:000000000000:knowledge-base/",
                AGENT,
            ),
            (
                "the data plane's endpoint, addressed with an agent ARN",
                Some("bedrock-agent-runtime.us-east-1.amazonaws.com"),
                AGENT_ARN,
                AGENT_RUNTIME,
            ),
            (
                "the same endpoint carrying a port",
                Some("bedrock-agent-runtime.us-east-1.amazonaws.com:443"),
                AGENT_ARN,
                AGENT_RUNTIME,
            ),
            (
                "another family member's endpoint: the ARN decides",
                Some("bedrock.us-east-1.amazonaws.com"),
                AGENT_ARN,
                AGENT,
            ),
            (
                "the loopback host a client pointed at the emulator sends",
                Some("localhost:4566"),
                AGENT_ARN,
                AGENT,
            ),
            (
                "the same, with an ARN neither syntax admits",
                Some("127.0.0.1:4566"),
                "arn:aws:bedrock:us-east-1:000000000000:agent/NOTASESSION",
                AGENT_RUNTIME,
            ),
            ("no host at all", None, SESSION, AGENT_RUNTIME),
        ];

        for (case, host, arn, expected) in rows {
            let actual = tagging_sharer(&parts(host, arn));
            assert_eq!(
                actual, expected,
                "case {case:?} (host {host:?}, {arn}): expected {expected:?}, got {actual:?}"
            );
        }
    }

    /// RULE: where the two sharers' URI templates differ in NOTHING but a trailing slash —
    /// the one route shape the framework's matcher cannot tell apart — the request's own
    /// trailing slash names the sharer, and every other request on the segment is left to
    /// the route rule (`None` here).
    ///
    /// The rows span the two spellings of that shape, the methods that are not it, the
    /// paths with no identifier, a deeper path under the same segment, and another shared
    /// segment entirely.
    #[test]
    fn the_one_route_shape_both_agent_models_bind_is_split_by_the_trailing_slash() {
        // (case, method, path, the sharer the request belongs to)
        let rows: [(&str, &str, &str, Option<&str>); 9] = [
            (
                "the data plane's inline-agent invocation",
                "POST",
                "/agents/probe-session-0a1f2a1d",
                Some(AGENT_RUNTIME),
            ),
            (
                "a session id that looks like an agent id",
                "POST",
                "/agents/ABCDEFGHIJ",
                Some(AGENT_RUNTIME),
            ),
            (
                "the build-time plane's PrepareAgent, with the slash its URI carries",
                "POST",
                "/agents/ABCDEFGHIJ/",
                Some(AGENT),
            ),
            // Not this route shape: the route rule already names one claimant.
            ("the agent listing, no identifier", "POST", "/agents/", None),
            ("the same segment with no slash", "POST", "/agents", None),
            ("the agent read, another method", "GET", "/agents/a-1/", None),
            (
                "the agent creation, another method",
                "PUT",
                "/agents/a-1/",
                None,
            ),
            (
                "a deeper path under the same segment",
                "POST",
                "/agents/a-1/agentaliases/",
                None,
            ),
            ("another shared segment", "POST", "/flows/f-1", None),
        ];

        for (case, method, path, expected) in rows {
            let parts = parts_for(method, path);
            let actual = trailing_slash_owner(&parts);
            assert_eq!(
                actual, expected,
                "case {case:?} ({method} {path}): expected {expected:?}, got {actual:?}"
            );
        }
    }

    /// The request parts for one method and path, which is all this rule reads.
    fn parts_for(method: &str, path: &str) -> http::request::Parts {
        http::Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .expect("the test request builds")
            .into_parts()
            .0
    }
}
