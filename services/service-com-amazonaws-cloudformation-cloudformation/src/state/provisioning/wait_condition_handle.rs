// SPDX-License-Identifier: CC0-1.0

//! WAIT CONDITION HANDLES: the pre-signed write target an `AWS::CloudFormation::WaitConditionHandle`
//! IS, and the signal document a client PUTs to it.
//!
//! ## The rule this module implements
//!
//! A wait condition handle is not a resource of any owning service: what it IS is an
//! address. Its physical resource id — and therefore `Ref` on it, the `PhysicalResourceId`
//! the per-resource reads report, and any stack output built from it — is a PRE-SIGNED
//! HTTPS URL that accepts one `PUT`: scheme `https`, an Amazon S3 write target of the
//! stack's Region (the bucket CloudFormation keys wait-condition signals under, and an
//! object key naming the stack and the handle), and a signing query. A client signals the
//! wait conditions declared with that handle by PUTting a signal document to it —
//! `{"Status":"SUCCESS","UniqueId":"1","Data":"ok"}` — which is the standard way an
//! instance's bootstrap releases an `AWS::CloudFormation::WaitCondition`, and the only way
//! that does not need a client credential at all.
//!
//! The parts of that URL a client depends on are its SHAPE: an absolute `https` URL it can
//! `PUT` to, carrying the pre-signing parameters. The bucket, the key and the signature are
//! per-run values.
//!
//! ## Where the URL points, and why
//!
//! At THIS EMULATOR'S OWN endpoint ([`::smithy_server_runtime::OperationContext::endpoint`])
//! — exactly as the `ResponseURL` a custom resource provider answers at is published
//! ([`super::custom_resource`]). A host of AWS's own naming resolves to the real service or
//! to nothing at all, so a URL naming one would be an address no client of this emulator can
//! reach.
//!
//! What AWS puts in that host is the S3 ENDPOINT of the write target; the PATH is the object
//! key. So the published URL keeps the key as the path, verbatim — the stack's own ARN and
//! then the handle's logical id ([`signal_path`]) — and names the S3 endpoint the target lives
//! at in its query instead ([`S3_ENDPOINT_PARAMETER`]), which is the one part of the address
//! this emulator cannot serve under. That endpoint is TEXT this service publishes and nothing
//! more: nothing here resolves it, connects to it or addresses anything by it, and the one
//! address the URL leads to is this emulator's own.
//!
//! The write itself is served by [`crate::service::wait_condition_plane`], which reads the
//! path back ([`parse_signal_path`]) and records the signal
//! ([`crate::state::ComAmazonawsCloudformationCloudformationState::record_handle_signal`]).
//!
//! ## Bounds
//!
//! One URL per handle of a stack, so the set is bounded by the resources of the stacks the
//! store keeps. Nothing a client PUTs sizes this store: a document past
//! [`MAX_SIGNAL_DOCUMENT_BYTES`] is not read at all, the `UniqueId` a signal is keyed by is
//! held to the length the model states for one (`ResourceSignalUniqueId`, `len 1..64`), and
//! the `Data` a signal leaves on a wait condition is held to
//! [`MAX_SIGNAL_DATA_CHARS`].

use serde_json::Value;

use super::percent_encoded;

/// The resource type whose physical id is that URL.
pub const WAIT_CONDITION_HANDLE: &str = "AWS::CloudFormation::WaitConditionHandle";

/// Whether `resource_type` is the type this module provisions.
pub fn is_handle(resource_type: &str) -> bool {
    resource_type == WAIT_CONDITION_HANDLE
}

/// The S3 ENDPOINT the write target a handle stands for lives at on AWS:
/// `cloudformation-waitcondition-<region>.s3.<region>.amazonaws.com`, whose first label is the
/// bucket CloudFormation keys a Region's wait-condition signals under.
///
/// AWS publishes that endpoint as the published URL's HOST. A client of this emulator
/// resolves no host of AWS's naming — the only address it can reach is the endpoint it is
/// already talking to — so the URL is published on THIS emulator's endpoint and names the S3
/// endpoint it stands for in its query instead ([`S3_ENDPOINT_PARAMETER`]), leaving the PATH
/// to be the object key exactly as AWS keys it.
pub fn s3_endpoint(region: &str) -> String {
    format!(
        "{bucket}.s3.{region}.amazonaws.com",
        bucket = signal_bucket(region),
    )
}

/// The query parameter the published URL names that endpoint in. Signed with the rest of the
/// URL, so it is part of what the signature covers rather than something a caller can restate.
pub const S3_ENDPOINT_PARAMETER: &str = "s3-endpoint";

/// The bucket CloudFormation keys a Region's wait-condition signals under, as its own
/// published handle URLs name it: `cloudformation-waitcondition-<region>`.
pub fn signal_bucket(region: &str) -> String {
    format!("cloudformation-waitcondition-{region}")
}

/// How long a published handle URL may be written to: "the maximum expiration time for the
/// signed URL is one week" (AWS General Reference, *Authenticating requests: using query
/// parameters*), the longest window a query-authenticated URL can state — and longer than
/// any wait a stack operation holds a resource at, so the window never closes before the
/// wait that URL signals has run out.
const SIGNAL_URL_EXPIRY: ::std::time::Duration = ::std::time::Duration::from_secs(604_800);

/// The most bytes one signal document may carry. A DEFENSIVE ceiling: a well-formed signal
/// is four short members, and a document past this is not read at all, so nothing a client
/// sends sizes this store.
pub const MAX_SIGNAL_DOCUMENT_BYTES: usize = 4096;

/// How many characters of a signal's `Data` a wait condition keeps — the same ceiling every
/// other value this service records off a client's document is held to
/// ([`super::custom_resource::MAX_DATA_VALUE_CHARS`]).
pub const MAX_SIGNAL_DATA_CHARS: usize = super::custom_resource::MAX_DATA_VALUE_CHARS;

/// The longest `UniqueId` a signal may be keyed by: `ResourceSignalUniqueId`, `len 1..64`
/// (this service's own Smithy model, `SignalResourceInput$UniqueId`), which is the same
/// identifier a client's own `SignalResource` call carries.
pub const MAX_UNIQUE_ID_CHARS: usize = 64;

/// What a write to a published handle URL names: the stack the handle belongs to and the
/// handle itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalTarget {
    /// The `StackId` of the stack whose template declares the handle.
    pub stack_id: String,
    /// The `LogicalResourceId` the handle is declared under.
    pub logical_resource_id: String,
}

/// The PATH a published handle URL addresses one handle by, decoded: the OBJECT KEY of the
/// write target, which is the stack's own ARN and then the handle's logical id, exactly as
/// CloudFormation keys a wait-condition signal.
///
/// The key is the whole path, with no prefix of this emulator's own: it is the one the real
/// service publishes, and the stack ARN it begins with can collide with no route of this
/// service — every modelled operation of it is served at `/` (awsQuery), and the other plane
/// it serves has a path space of its own
/// ([`super::custom_resource::parse_response_path`]).
///
/// The one spelling of that address, read back by [`parse_signal_path`] — and the address a
/// suite writing to this plane uses, rather than spelling it again.
pub fn signal_path(stack_id: &str, logical_id: &str) -> String {
    format!("/{stack_id}/{logical_id}")
}

/// The URL one handle publishes as its physical resource id: a pre-signed `PUT` target on
/// THIS EMULATOR'S OWN endpoint whose path is the object key of the write target and whose
/// query names the S3 endpoint that target lives at ([`s3_endpoint`]).
///
/// Query-signed by the framework's own signer ([`::smithy_server_runtime::UrlSigner`]), which
/// is how any URL this emulator hands a caller to fetch later is signed, for the longest
/// window such a URL may state ([`SIGNAL_URL_EXPIRY`]). The write itself is served UNSIGNED,
/// as a pre-signed URL is followed: the plane answers it before the request is authenticated,
/// which is why the published URL is also what that plane holds a write to
/// ([`crate::state::ComAmazonawsCloudformationCloudformationState::published_handle_url`]).
pub fn signal_url(
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    region: &str,
    stack_id: &str,
    logical_id: &str,
) -> String {
    let path = signal_path(stack_id, logical_id);
    let endpoint = s3_endpoint(region);
    let request = ::smithy_server_runtime::SignedUrlRequest::new(
        ::smithy_server_runtime::http::Method::PUT,
        crate::state::ARN_NAMESPACE,
        &path,
    )
    .query(S3_ENDPOINT_PARAMETER, &endpoint);
    match ctx.url_signer().sign(request, SIGNAL_URL_EXPIRY) {
        Ok(signed) => signed.as_str().to_string(),
        // The path is this service's own and the window a constant, so nothing a caller
        // sends can reach here. A URL that cannot be signed is still the address this plane
        // serves — the write is served unsigned — so the target is published without the
        // signing query rather than as an address that leads nowhere.
        Err(error) => {
            ::tracing::warn!(%error, "a wait condition handle URL could not be signed");
            format!(
                "{base}/{key}?{S3_ENDPOINT_PARAMETER}={endpoint}",
                // The key begins with its own `/`, so an endpoint that ends in one would
                // publish a path with an empty first segment, which names no key.
                base = ctx.endpoint().as_str().trim_end_matches('/'),
                key = percent_encoded(&format!("{stack_id}/{logical_id}")),
            )
        }
    }
}

/// What a request to a published handle URL names, or `None` when the path is not one.
///
/// Reading the path back is a syntax check only: whether it names a handle this service
/// published a URL for is the store's judgement
/// ([`crate::state::ComAmazonawsCloudformationCloudformationState::published_handle_url`]).
/// The key must name a STACK of this service by its own ARN ([`target_region`]), which is what
/// keeps this plane's claim to its own URLs.
pub fn parse_signal_path(path: &str) -> Option<SignalTarget> {
    // The query is not part of what the URL names: a pre-signed URL carries its signing
    // parameters there, and the target is the path alone.
    let path = path.split('?').next().unwrap_or(path);
    let addressed = path.strip_prefix('/')?;
    if addressed.is_empty() {
        return None;
    }
    let decoded = ::percent_encoding::percent_decode_str(addressed)
        .decode_utf8()
        .ok()?;
    // The LAST segment of the key is the handle's logical id; everything before it is the
    // stack's ARN, which carries `/` itself.
    let (stack_id, logical_resource_id) = decoded.rsplit_once('/')?;
    if stack_id.is_empty() || logical_resource_id.is_empty() {
        return None;
    }
    let target = SignalTarget {
        stack_id: stack_id.to_string(),
        logical_resource_id: logical_resource_id.to_string(),
    };
    target_region(&target).is_some().then_some(target)
}

/// The Region of the stack a signal target names: the Region segment of that stack's own ARN.
///
/// A write to this plane carries no credential — a pre-signed URL is followed unsigned — so
/// the Region it is about comes from what the URL itself names. The stack's ARN is the
/// authority on it, read through the workspace's one reading of a caller-supplied ARN's
/// Region ([`::service_common::arn::region_of`]), which holds the field to the grammar every
/// model's ARN pattern states for it: a target whose first part is no CloudFormation ARN, or
/// whose Region field could re-point an authority, names no stack of this service at all.
pub fn target_region(target: &SignalTarget) -> Option<&str> {
    let region = ::service_common::arn::region_of(&target.stack_id, crate::state::ARN_NAMESPACE)?;
    // ...and the ARN must name a STACK, by the resource path a stack ARN carries:
    // `stack/<name>/<id>` and nothing else. This plane answers for a handle of one, and the
    // path a longer resource part would admit is one this service published no URL for.
    let mut resource = target.stack_id.split(':').nth(5)?.split('/');
    let (Some("stack"), Some(name), Some(id), None) = (
        resource.next(),
        resource.next(),
        resource.next(),
        resource.next(),
    ) else {
        return None;
    };
    (!name.is_empty() && !id.is_empty()).then_some(region)
}

/// One signal document a client PUT to a published handle URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleSignal {
    /// `Status`: `SUCCESS` or `FAILURE`, the two statuses a resource signal carries
    /// (`ResourceSignalStatus`).
    pub status: String,
    /// `UniqueId`: "a unique ID of the signal … if you send multiple signals to a single
    /// resource (such as signaling a wait condition), each signal requires a different
    /// unique ID" (`SignalResourceInput$UniqueId`), which is what the signal is keyed by.
    pub unique_id: String,
    /// `Data`: the data the signal carries, which is what the wait condition's own `Data`
    /// return value reports against this signal's unique id.
    pub data: Option<String>,
}

/// The member name a signal document states each part under.
const STATUS: &str = "Status";
const UNIQUE_ID: &str = "UniqueId";
const DATA: &str = "Data";

/// The attribute a wait condition publishes the signals it received under: "a JSON object
/// that contains the `UniqueId` and `Data` values from the wait condition signal(s) for the
/// specified wait condition", which `Fn::GetAtt` reads.
pub const SIGNAL_DATA_ATTRIBUTE: &str = "Data";

impl HandleSignal {
    /// Read one signal out of the document a client PUT, or `Err(member)` naming what a
    /// well-formed signal must carry that this document does not.
    ///
    /// Only the two statuses a resource signal has are read, because they are the only two
    /// that mean anything: a document stating anything else states no signal status at all.
    /// The values are bounded where they are read, since the document is a client's.
    pub fn read(document: &Value) -> Result<Self, &'static str> {
        let status = document
            .get(STATUS)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|status| {
                [
                    crate::state::resource_signal_status::SUCCESS,
                    crate::state::resource_signal_status::FAILURE,
                ]
                .contains(status)
            })
            .ok_or(STATUS)?;
        let unique_id = document
            .get(UNIQUE_ID)
            .and_then(signal_text)
            .filter(|unique_id| !unique_id.is_empty())
            .map(|unique_id| bounded(&unique_id, MAX_UNIQUE_ID_CHARS))
            .ok_or(UNIQUE_ID)?;
        Ok(Self {
            status: status.to_string(),
            unique_id,
            data: document
                .get(DATA)
                .and_then(signal_text)
                .map(|data| bounded(&data, MAX_SIGNAL_DATA_CHARS)),
        })
    }
}

/// One member of a signal document as TEXT: the string a document states, or the scalar it
/// states spelled as one — a client writes a document, and a number or a boolean there is
/// the value it wrote, not an absent member.
fn signal_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// `value` cut to `chars` characters, by CHARACTER so a multi-byte value is never split.
fn bounded(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RULE: every path a published handle URL carries is read back whole — the stack's own
    /// ARN and the handle's logical id the object key names — in each spelling the one path
    /// travels in.
    #[test]
    fn every_published_path_is_read_back_whole() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "a stack of the default Region",
                "arn:aws:cloudformation:us-east-1:000000000000:stack/app/0123",
                "Handle",
            ),
            (
                "a stack of another Region, and a long logical id",
                "arn:aws:cloudformation:ap-southeast-2:000000000000:stack/s/89ab",
                "AVeryLongLogicalResourceIdDeclaredByATemplate0123456789",
            ),
        ];
        for (case, stack_id, logical_id) in cases {
            let expected = Some(SignalTarget {
                stack_id: (*stack_id).to_string(),
                logical_resource_id: (*logical_id).to_string(),
            });
            let path = signal_path(stack_id, logical_id);
            let encoded = format!(
                "/{}",
                percent_encoded(&format!("{stack_id}/{logical_id}"))
            );
            for spelling in [path.clone(), encoded, format!("{path}?X-Amz-Signature=ab")] {
                let read = parse_signal_path(&spelling);
                assert_eq!(
                    read, expected,
                    "case {case:?}: expected {spelling} to read back whole, got {read:?}"
                );
            }
        }
    }

    /// RULE: a path this module did not publish names no handle — another plane's space, a key
    /// missing a part, and a key whose first part is no stack ARN of this service.
    #[test]
    fn a_path_this_module_did_not_publish_names_nothing() {
        let stack = "arn:aws:cloudformation:us-east-1:000000000000:stack/app/0123";
        let cases: &[(&str, String)] = &[
            (
                "the custom resource response plane's own space",
                format!("/_aws/cloudformation/{stack}%7CThing%7Cid"),
            ),
            ("the key without the handle", format!("/{stack}")),
            ("no key at all", "/".to_string()),
            ("an empty logical id", format!("/{stack}/")),
            (
                "a key with more than the handle after the stack",
                format!("/{stack}/Handle/extra"),
            ),
            (
                "a target that names no stack",
                "/arn:aws:cloudformation:us-east-1:0:changeSet/c/Handle".to_string(),
            ),
            (
                "a target that names another service's resource",
                "/arn:aws:s3:us-east-1:0:stack/app/0123/Handle".to_string(),
            ),
            (
                "a target that is no ARN at all",
                "/app/0123/Handle".to_string(),
            ),
        ];
        for (case, path) in cases {
            let read = parse_signal_path(path);
            assert!(
                read.is_none(),
                "case {case:?}: expected no handle to be named, got {read:?}"
            );
        }
    }

    /// RULE: the S3 endpoint the published URL names its write target at is the bucket
    /// CloudFormation keys a Region's wait-condition signals under, at that Region's S3
    /// endpoint.
    #[test]
    fn the_published_url_names_the_s3_endpoint_of_the_stacks_region() {
        for (case, region, expected) in [
            (
                "the Region a stack of the default endpoint belongs to",
                "us-east-1",
                "cloudformation-waitcondition-us-east-1.s3.us-east-1.amazonaws.com",
            ),
            (
                "another Region",
                "eu-west-1",
                "cloudformation-waitcondition-eu-west-1.s3.eu-west-1.amazonaws.com",
            ),
        ] {
            let endpoint = s3_endpoint(region);
            assert_eq!(
                endpoint, expected,
                "case {case:?}: expected {expected}, got {endpoint}"
            );
        }
    }

    /// RULE: a signal is the `Status` and the `UniqueId` it states, with the `Data` it
    /// carries; a document that states no status a resource signal has, or no unique id,
    /// states no signal at all.
    #[test]
    fn a_signal_is_the_status_the_unique_id_and_the_data() {
        let read = |document: ::serde_json::Value| HandleSignal::read(&document);
        let signal = read(::serde_json::json!({
            "Status": "SUCCESS",
            "UniqueId": "1",
            "Data": "ok",
        }));
        assert_eq!(
            signal,
            Ok(HandleSignal {
                status: "SUCCESS".to_string(),
                unique_id: "1".to_string(),
                data: Some("ok".to_string()),
            }),
            "a well-formed success signal is read whole"
        );
        let failure = read(::serde_json::json!({
            "Status": "FAILURE",
            "UniqueId": "i-0abc",
        }));
        assert_eq!(
            failure,
            Ok(HandleSignal {
                status: "FAILURE".to_string(),
                unique_id: "i-0abc".to_string(),
                data: None,
            }),
            "a failure signal carrying no data is read whole"
        );
        let numeric = read(::serde_json::json!({
            "Status": "SUCCESS",
            "UniqueId": 7,
            "Data": 42,
        }));
        assert_eq!(
            numeric,
            Ok(HandleSignal {
                status: "SUCCESS".to_string(),
                unique_id: "7".to_string(),
                data: Some("42".to_string()),
            }),
            "a scalar a document states is the value it wrote"
        );
        for (case, document, member) in [
            (
                "no status",
                ::serde_json::json!({ "UniqueId": "1" }),
                STATUS,
            ),
            (
                "a status no resource signal has",
                ::serde_json::json!({ "Status": "MAYBE", "UniqueId": "1" }),
                STATUS,
            ),
            (
                "no unique id",
                ::serde_json::json!({ "Status": "SUCCESS" }),
                UNIQUE_ID,
            ),
            (
                "an empty unique id",
                ::serde_json::json!({ "Status": "SUCCESS", "UniqueId": "" }),
                UNIQUE_ID,
            ),
        ] {
            let read = HandleSignal::read(&document);
            assert_eq!(
                read,
                Err(member),
                "case {case:?}: expected the document to name {member}, got {read:?}"
            );
        }
    }

    /// RULE: nothing a client sends sizes this store — a unique id and a data value are cut
    /// to the lengths this module bounds them at.
    #[test]
    fn a_signal_is_bounded_where_it_is_read() {
        let long = "x".repeat(MAX_SIGNAL_DATA_CHARS + MAX_UNIQUE_ID_CHARS + 10);
        let signal = HandleSignal::read(&::serde_json::json!({
            "Status": "SUCCESS",
            "UniqueId": long.clone(),
            "Data": long,
        }))
        .expect("the document states a status and a unique id");
        assert_eq!(
            signal.unique_id.chars().count(),
            MAX_UNIQUE_ID_CHARS,
            "expected the unique id to be bounded, got {:?}",
            signal.unique_id.chars().count()
        );
        assert_eq!(
            signal.data.as_ref().map(|data| data.chars().count()),
            Some(MAX_SIGNAL_DATA_CHARS),
            "expected the data to be bounded, got {:?}",
            signal.data.map(|data| data.chars().count())
        );
    }
}
