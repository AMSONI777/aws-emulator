// SPDX-License-Identifier: CC0-1.0

//! The `POST /transform-data` surface of the data-transformation endpoint: the
//! SYNCHRONOUS transform, which converts the clinical data the request itself
//! carries into a FHIR R4 Bundle with a stored profile's mapping and answers that
//! Bundle in band — no job, no Amazon S3, nothing to poll.
//!
//! # Why this is not a generated operation
//!
//! The shipped model DOES declare the operation — `TransformData`, `POST
//! /transform-data`, code 200 — but under the
//! `com.amazon.awshealthlakedatatransformationfrontendservice` namespace, OUTSIDE
//! the closure of the service shape this crate serves
//! (`com.amazonaws.healthlake#HealthLake`, whose bound operations
//! `smithy_query(query="digest")` lists and which does not include it). So no module
//! is generated for it and nothing is in the routing table. Like its sibling
//! out-of-closure surfaces ([`super::validate_source`], [`super::rest_tagging`]) it
//! is reached through [`super::EmulatedService::override_operation`]: by PATH, which
//! is how the recorded wire addresses it (a plain JSON body and no `X-Amz-Target`),
//! and by the RPC target an SDK generated from the full model would send instead, so
//! the operation answers wherever it is addressed.
//!
//! # The contract
//!
//! Taken from the model shapes rather than invented
//! (`smithy_query(query="closure",operation="TransformData")`):
//!
//! * the request carries `ProfileId` (`@required`, `@length(32, 32)`,
//!   `@pattern(^[a-f0-9]{32}$)`) and `InputData` (`@required`, the `@sensitive` union
//!   `TransformInputData` of `CcdaInput` — one C-CDA document — and `CsvInput` — a
//!   `FileInputMap` of file name to file content), plus the flags
//!   `DriftDetectionEnabled` (which the model declares with NO default, so a request
//!   that leaves it out asks for no drift report) and `ProvenanceEnabled` (which the
//!   model declares `@default true`);
//! * the answer is HTTP 200 carrying the `@required` `TransformedData`, the FHIR R4
//!   Bundle the profile's mapping produced, and `DriftReport` when the caller asked
//!   for drift detection;
//! * a `ProfileId` no profile is held for is refused with the modelled
//!   `ResourceNotFoundException` at the HTTP 404 its `@httpError` names, stating the
//!   same sentence every other profile-not-found path of this crate states
//!   ([`crate::state::profile_not_found_message`]); a request outside a rule the
//!   model declares, input the profile does not convert, or input this emulator
//!   could not read, with `ValidationException` at 400; and a failure of the service
//!   itself with `InternalServerException` at 500.
//!
//! The transform ITSELF is not here: reading a profile's mapping and applying it to
//! submitted data is [`crate::state::profile_transform`], beside the state that
//! holds the mapping, so the rules a profile declares are read in one place
//! whichever surface applies them.
//!
//! A read: the only state this surface writes is the lifecycle settle every reader
//! of this store performs, which is the clock catching up and was owed at this
//! instant whether or not anybody called.

use std::collections::BTreeMap;
use std::sync::Arc;

use aws_smithy_runtime_api::http::{Request as RtRequest, Response as RtResponse, StatusCode};
use aws_smithy_types::body::SdkBody;
use smithy_server_runtime::{
    BoxFuture, ErasedOperation, OperationContext, Service, Violation, ViolationKind,
};

use super::non_rpc::{
    bound, bounded, entry_at, member_path, missing_member, modelled_error, not_of_modelled_type,
    request_members,
};

/// The path this surface publishes, as the first (and only) segment of the request
/// URI, from the modelled `@http(uri: "/transform-data")`. The
/// `datatransformation.` host prefix a client injects addresses the endpoint and
/// does not change the path.
pub const TRANSFORM_DATA_PATH_SEGMENT: &str = "transform-data";

/// The routing key an RPC client names this operation with: the operation's own
/// name, which is what this service's awsJson1_0 protocol resolves an
/// `X-Amz-Target` to.
pub const TRANSFORM_DATA: &str = "TransformData";

/// The member the request names the profile with, as `TransformDataRequest$ProfileId`
/// spells it.
const PROFILE_ID_MEMBER: &str = "ProfileId";

/// The member the request carries the source data in, as
/// `TransformDataRequest$InputData` spells it.
const INPUT_DATA_MEMBER: &str = "InputData";

/// The member the request asks for drift detection with.
const DRIFT_DETECTION_MEMBER: &str = "DriftDetectionEnabled";

/// The member the request asks for provenance with.
const PROVENANCE_MEMBER: &str = "ProvenanceEnabled";

/// The union member carrying one C-CDA document, as `TransformInputData$CcdaInput`
/// spells it.
const CCDA_INPUT_MEMBER: &str = "CcdaInput";

/// The union member carrying CSV files by name, as `TransformInputData$CsvInput`
/// spells it.
const CSV_INPUT_MEMBER: &str = "CsvInput";

/// The member the answer carries the Bundle in, as
/// `TransformDataResponse$TransformedData` spells it.
const TRANSFORMED_DATA_MEMBER: &str = "TransformedData";

/// The member the answer carries the drift report in.
const DRIFT_REPORT_MEMBER: &str = "DriftReport";

/// The `@default` the model declares on `ProvenanceEnabled`, which is what a request
/// that leaves it out asks for.
const PROVENANCE_ENABLED_BY_DEFAULT: bool = true;

/// What a request that leaves `DriftDetectionEnabled` out asks for.
///
/// The model declares that member with NO `@default`
/// (`smithy_query(query="operation",operation="TransformData")` -> `DriftDetectionEnabled:
/// "Boolean"`, beside `ProvenanceEnabled`'s `default: true`), so an absent flag asks
/// for nothing and the answer carries no `DriftReport`.
const DRIFT_DETECTION_ENABLED_BY_DEFAULT: bool = false;

/// The `@pattern` the modelled `ProfileIdString` declares, as the refusal of a value
/// outside it states the rule.
const PROFILE_ID_PATTERN: &str = "^[a-f0-9]{32}$";

/// The `@length` the modelled `ProfileIdString` declares, both bounds.
const PROFILE_ID_LEN: usize = 32;

/// The shortest file name `CsvInput` admits, from the modelled `FileName`
/// `@length(min: 1, max: 255)`.
const MIN_FILE_NAME_LEN: usize = 1;

/// The longest file name `CsvInput` admits, from that same `@length`.
const MAX_FILE_NAME_LEN: usize = 255;

/// The `@pattern` the modelled `FileName` declares.
const FILE_NAME_PATTERN: &str = "^[\\w\\-\\.]+$";

/// Which member of the modelled `TransformInputData` union carries the data of a
/// profile's `SourceFormat`: `CsvInput` carries comma-separated values and
/// `CcdaInput` a Consolidated Clinical Document Architecture document, as those
/// member names and the `SourceFormat` enum's values
/// (`smithy_query(query="shape",shape="SourceFormat")` -> `[CCDA, CSV]`) spell them.
///
/// Read only through [`input_member_for`]: a profile converts FROM one format, so the
/// request has to carry the data in the member that format travels in.
const INPUT_MEMBER_FOR_SOURCE_FORMAT: &[(&str, &str)] =
    &[("CSV", CSV_INPUT_MEMBER), ("CCDA", CCDA_INPUT_MEMBER)];

/// The shape name the modelled server fault is reported under.
const INTERNAL_SERVER_EXCEPTION: &str = "InternalServerException";

/// The media type this surface's answers travel as. The answer is not a FHIR
/// resource — it is the operation's own output, carrying the Bundle as a string — so
/// it travels as the ordinary JSON media type, exactly as
/// [`super::validate_source`]'s report does.
const JSON_CONTENT_TYPE: &str = "application/json";

/// The success status the operation declares (`@http(code: 200)`).
const SUCCESS_STATUS: u16 = 200;

/// The longest one transform may take to answer before the request is answered as a
/// server fault instead.
///
/// A server-side ceiling of this emulator's, not a duration AWS documents: every
/// factor a transform multiplies is already bounded (see
/// [`crate::state::profile_transform`]), so a bounded transform answers in
/// milliseconds and this is the backstop that keeps one request from holding its
/// answer open — generous enough that a loaded host never reaches it.
const TRANSFORM_DEADLINE: ::std::time::Duration = ::std::time::Duration::from_secs(30);

/// Whether `path` addresses this surface.
///
/// The ONE reader of this path space: [`super::EmulatedService::override_operation`]
/// routes with it and [`TransformData`] is reached through it, so the routing
/// decision and the handler cannot read a request differently.
pub(crate) fn addresses_transform_data(path: &str) -> bool {
    super::non_rpc::addresses_segment(path, TRANSFORM_DATA_PATH_SEGMENT)
}

/// The synchronous transform, as the one [`ErasedOperation`] the service holds for
/// it.
///
/// Owns the shared engine exactly as a generated operation does, so the profile it
/// transforms with is the one the control plane's handlers wrote.
pub struct TransformData<Eng> {
    engine: Arc<Eng>,
}

impl<Eng> TransformData<Eng> {
    /// Build the surface from the shared engine.
    pub fn new(engine: Arc<Eng>) -> Self {
        Self { engine }
    }
}

impl<Eng: Send + Sync + 'static> ErasedOperation for TransformData<Eng> {
    fn run<'r>(
        &'r self,
        _svc: &'r dyn Service,
        req: &'r RtRequest,
        _ctx: &'r OperationContext<'r>,
    ) -> BoxFuture<'r, RtResponse> {
        Box::pin(async move {
            // The router buffers every request before dispatch, so a body it cannot
            // hand back in memory is a server-side failure, never a caller's
            // malformed request.
            match req.body().bytes() {
                Some(body) => self.transform(body).await,
                None => unreadable_body(),
            }
        })
    }
}

impl<Eng: Send + Sync + 'static> TransformData<Eng> {
    /// Serve one transform.
    async fn transform(&self, body: &[u8]) -> RtResponse {
        let requested = match requested_transform(body) {
            Ok(requested) => requested,
            Err(refused) => return validation_exception(&refused),
        };
        let Some(state) = crate::state::service_state(&*self.engine) else {
            return store_unavailable();
        };

        // What the store holds about the profile, read under the lock and nothing
        // else: the transform itself is driven by the submitted input, so it runs
        // after the lock is released rather than holding every other caller up for
        // the length of one caller's data.
        //
        // The version read is the one a read that names none resolves to — the
        // latest published version, and the DRAFT while the profile has none —
        // which is the version `GetDataTransformationProfile` reads back for the
        // same profile.
        let held = {
            let mut store = state.lock();
            store.settle_lifecycle();
            store.profiles.get(&requested.profile_id).map(|profile| {
                let version = profile.latest_readable();
                HeldProfile {
                    arn: profile.arn.clone(),
                    source_format: profile.source_format.clone(),
                    version: version.version,
                    mapping: version.mapping.clone(),
                }
            })
        };
        let Some(held) = held else {
            return resource_not_found(&crate::state::profile_not_found_message(
                &requested.profile_id,
            ));
        };

        let rules = crate::state::mapping_rules(&held.mapping);
        if rules.is_empty() {
            return validation_exception(&no_mapping_message(
                &requested.profile_id,
                held.version,
            ));
        }
        let expected = match input_member_for(&held.source_format) {
            Some(expected) => expected,
            None => {
                return validation_exception(&format_not_transformable_message(
                    &held.source_format,
                ))
            }
        };
        if requested.input.member() != expected {
            return validation_exception(&input_does_not_match_message(
                expected,
                &held.source_format,
            ));
        }

        // The transform itself is CPU work over the submitted data, bounded but not
        // instant, so it runs on the BLOCKING pool rather than on the async worker
        // this request arrived on, under a server-side DEADLINE: an await point is
        // left here, so the request stays cancellable, nothing else the runtime is
        // serving is held up by it, and a transform that somehow does not answer is
        // answered as a server fault rather than held open. The work is handed OWNED
        // values, which is why the snapshot above exists.
        //
        // Provenance is what the produced resources record themselves as coming
        // from: the profile that produced them, named by the ARN this service minted
        // for it. The drift comparison is work only a caller that asked for the
        // report reads, so the flag goes to the transform rather than being
        // discarded after it.
        let provenance = requested
            .provenance_enabled
            .then(|| held.arn.clone());
        let detect_drift = requested.drift_detection_enabled;
        let input = requested.input;
        let transformed = ::tokio::time::timeout(
            TRANSFORM_DEADLINE,
            ::tokio::task::spawn_blocking(move || {
                let options = crate::state::TransformOptions {
                    provenance: provenance.as_deref(),
                    detect_drift,
                };
                match input {
                    RequestedInput::Csv(files) => {
                        crate::state::transform_csv(&rules, &files, options)
                    }
                    RequestedInput::Ccda(document) => {
                        crate::state::transform_ccda(&rules, &document, options)
                    }
                }
            }),
        )
        .await;
        let transformed = match transformed {
            Ok(Ok(transformed)) => transformed,
            // The blocking task panicked, or the deadline passed before it answered:
            // nothing ran to completion, so this is a failure of the service rather
            // than of the request, and no Bundle is reported for work that did not
            // finish.
            Ok(Err(error)) => {
                tracing::warn!(
                    operation = TRANSFORM_DATA,
                    %error,
                    "the synchronous transform did not run to completion"
                );
                return transform_unperformed();
            }
            Err(elapsed) => {
                tracing::warn!(
                    operation = TRANSFORM_DATA,
                    %elapsed,
                    "the synchronous transform did not answer inside its deadline"
                );
                return transform_unperformed();
            }
        };
        match transformed {
            Ok(transformed) => {
                // One attribution record per served transform: which profile and
                // which version of it answered. The `@sensitive` `InputData` and the
                // Bundle built from it are deliberately absent — a record of the
                // call, not of the clinical data it carried.
                tracing::debug!(
                    operation = TRANSFORM_DATA,
                    profile_id = %requested.profile_id,
                    profile_version = held.version,
                    source_format = %held.source_format,
                    status = SUCCESS_STATUS,
                    "served a synchronous data transformation"
                );
                transformed_response(&transformed, detect_drift)
            }
            Err(refused) => validation_exception(&refused),
        }
    }
}

/// What the store holds about the profile one transform applies.
///
/// Read out of the store in one place, so the transform below works from a snapshot
/// rather than from a borrow of the shared state — see [`TransformData::transform`].
/// The mapping it carries is bounded by what one profile version retains
/// ([`crate::state::MAX_PROFILE_MAPPING_BYTES`]).
#[derive(Debug)]
struct HeldProfile {
    /// The ARN this service minted for the profile, which a produced resource
    /// records as its source.
    arn: String,
    /// The format the profile converts FROM.
    source_format: String,
    /// The version the transform resolved.
    version: i32,
    /// That version's content: file path to file content.
    mapping: ::std::collections::BTreeMap<String, String>,
}

/// What one request asked for.
#[derive(Debug)]
struct RequestedTransform {
    /// The profile whose mapping the transform applies.
    profile_id: String,
    /// The source data the request carries.
    input: RequestedInput,
    /// Whether the caller asked for the drift report.
    drift_detection_enabled: bool,
    /// Whether the caller asked the produced resources to record where they came
    /// from.
    provenance_enabled: bool,
}

/// The source data one request carries: the member of the modelled input union it
/// sent, and that member's value.
#[derive(Debug)]
enum RequestedInput {
    /// `CsvInput`: file name to file content.
    Csv(BTreeMap<String, String>),
    /// `CcdaInput`: one C-CDA document.
    Ccda(String),
}

impl RequestedInput {
    /// The union member this input was sent in.
    fn member(&self) -> &'static str {
        match self {
            Self::Csv(_) => CSV_INPUT_MEMBER,
            Self::Ccda(_) => CCDA_INPUT_MEMBER,
        }
    }
}

/// What the request asked for, or the sentence its refusal states.
///
/// Every rule applied is one the model declares on the request shape. They are
/// stated here because this surface is routed by path and so never passes through
/// the generated operations' schema-driven gate (see the input-validation note in
/// [`crate::service`]); the wording is that gate's own
/// ([`crate::service::validation_envelope`]), so a refusal here reads exactly like a
/// refusal of any other HealthLake member.
fn requested_transform(body: &[u8]) -> Result<RequestedTransform, String> {
    let members = request_members(body)?;
    let profile_id = requested_profile_id(&members)?;
    let input = requested_input(&members)?;
    Ok(RequestedTransform {
        profile_id,
        input,
        drift_detection_enabled: requested_flag(
            &members,
            DRIFT_DETECTION_MEMBER,
            DRIFT_DETECTION_ENABLED_BY_DEFAULT,
        )?,
        provenance_enabled: requested_flag(
            &members,
            PROVENANCE_MEMBER,
            PROVENANCE_ENABLED_BY_DEFAULT,
        )?,
    })
}

/// The `ProfileId` the request names, held to the `@required` member's own
/// `@length` and `@pattern`.
fn requested_profile_id(
    members: &::serde_json::Map<String, ::serde_json::Value>,
) -> Result<String, String> {
    let Some(sent) = members.get(PROFILE_ID_MEMBER) else {
        return Err(missing_member(PROFILE_ID_MEMBER));
    };
    let Some(sent) = sent.as_str() else {
        return Err(not_of_modelled_type(
            &member_path(PROFILE_ID_MEMBER),
            "a profile identifier, as a JSON string",
        ));
    };
    let length = sent.chars().count();
    let kind = if length < PROFILE_ID_LEN {
        Some(ViolationKind::MinLength(bound(PROFILE_ID_LEN)))
    } else if length > PROFILE_ID_LEN {
        Some(ViolationKind::MaxLength(bound(PROFILE_ID_LEN)))
    } else if crate::state::is_profile_id(sent) {
        None
    } else {
        Some(ViolationKind::Pattern(PROFILE_ID_PATTERN.to_string()))
    };
    match kind {
        None => Ok(sent.to_string()),
        Some(kind) => Err(super::validation_envelope(&[Violation {
            path: member_path(PROFILE_ID_MEMBER),
            kind,
            value: Some(bounded(sent)),
            sensitive: false,
        }])),
    }
}

/// The source data the request carries, or the sentence its refusal states.
///
/// `InputData` is `@required` and is a UNION, so exactly one of its members carries
/// the data; a request carrying neither, or both, has not named which form it sent.
///
/// The submitted data is held to the ceiling one transform reads
/// ([`crate::state::MAX_TRANSFORM_INPUT_BYTES`]) HERE, before any of it is copied out
/// of the body the router has already buffered, so what this process takes on from
/// one request is bounded by that constant rather than by how much a caller sent.
fn requested_input(
    members: &::serde_json::Map<String, ::serde_json::Value>,
) -> Result<RequestedInput, String> {
    let Some(sent) = members.get(INPUT_DATA_MEMBER) else {
        return Err(missing_member(INPUT_DATA_MEMBER));
    };
    let Some(sent) = sent.as_object() else {
        return Err(not_of_modelled_type(
            &member_path(INPUT_DATA_MEMBER),
            &union_member_sentence(),
        ));
    };
    let ccda = sent.get(CCDA_INPUT_MEMBER);
    let csv = sent.get(CSV_INPUT_MEMBER);
    match (ccda, csv) {
        (Some(ccda), None) => {
            let Some(document) = ccda.as_str() else {
                return Err(not_of_modelled_type(
                    &union_member_path(CCDA_INPUT_MEMBER),
                    "a C-CDA document, as a JSON string",
                ));
            };
            if document.len() > crate::state::MAX_TRANSFORM_INPUT_BYTES {
                return Err(crate::state::input_too_large_message(document.len()));
            }
            Ok(RequestedInput::Ccda(document.to_string()))
        }
        (None, Some(csv)) => {
            let Some(files) = csv.as_object() else {
                return Err(not_of_modelled_type(
                    &union_member_path(CSV_INPUT_MEMBER),
                    "a JSON object of file name to file content",
                ));
            };
            // The COUNT is decided before any entry is walked: the work a transform
            // does is the product of how many files it reads and how many rules the
            // mapping declares, so a request past the ceiling is refused rather than
            // read in part — and nothing after this point, the violations this walk
            // may collect included, is sized by a count the caller chose.
            if files.len() > crate::state::MAX_TRANSFORM_INPUT_FILES {
                return Err(too_many_files_message(files.len()));
            }
            let mut requested = BTreeMap::new();
            let mut violations = Vec::new();
            let mut bytes = 0usize;
            for (name, content) in files {
                let Some(content) = content.as_str() else {
                    return Err(not_of_modelled_type(
                        &entry_at(&union_member_path(CSV_INPUT_MEMBER), name),
                        "a file's content, as a JSON string",
                    ));
                };
                // A file's NAME is input too, so it is charged beside its content:
                // the ceiling then bounds what the request carries rather than only
                // what its files hold.
                bytes = bytes.saturating_add(name.len()).saturating_add(content.len());
                if bytes > crate::state::MAX_TRANSFORM_INPUT_BYTES {
                    return Err(crate::state::input_too_large_message(bytes));
                }
                violations.extend(file_name_violations(name));
                requested.insert(name.clone(), content.to_string());
            }
            if !violations.is_empty() {
                return Err(super::validation_envelope(&violations));
            }
            Ok(RequestedInput::Csv(requested))
        }
        // Neither member, or both: the union names no single form the data was sent
        // in, which is not a constraint violation of either member.
        _ => Err(not_of_modelled_type(
            &member_path(INPUT_DATA_MEMBER),
            &union_member_sentence(),
        )),
    }
}

/// Everything the file name `name` breaks, from the modelled `FileName`'s own
/// `@length` and `@pattern`.
///
/// A map KEY has no path of its own — an entry is identified BY its key — so a key
/// outside its shape's rules is reported at the map member, quoting the key as the
/// offending value.
fn file_name_violations(name: &str) -> Vec<Violation> {
    let path = union_member_path(CSV_INPUT_MEMBER);
    let length = name.chars().count();
    let kind = if length < MIN_FILE_NAME_LEN {
        ViolationKind::MinLength(bound(MIN_FILE_NAME_LEN))
    } else if length > MAX_FILE_NAME_LEN {
        ViolationKind::MaxLength(bound(MAX_FILE_NAME_LEN))
    } else if is_file_name(name) {
        return Vec::new();
    } else {
        // This service's pattern clause quotes no value; see
        // `crate::service::clause_for`.
        return vec![Violation {
            path,
            kind: ViolationKind::Pattern(FILE_NAME_PATTERN.to_string()),
            value: None,
            sensitive: false,
        }];
    };
    vec![Violation {
        path,
        kind,
        value: Some(bounded(name)),
        sensitive: false,
    }]
}

/// Whether `name` satisfies the modelled `FileName` `@pattern` `^[\w\-\.]+$`: the
/// ASCII word characters `\w` admits, plus `-` and `.`, and at least one of them.
fn is_file_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
}

/// The violation path of one member of the `InputData` union.
fn union_member_path(member: &str) -> String {
    ::aws_smithy_schema_server::constraints::path::join(&[
        member_path(INPUT_DATA_MEMBER),
        member.to_string(),
    ])
}

/// What `InputData` must be, as a refusal states it: exactly one of the union's
/// members, named from the model rather than written out here.
fn union_member_sentence() -> String {
    format!("a union carrying exactly one of {CCDA_INPUT_MEMBER} or {CSV_INPUT_MEMBER}")
}

/// The boolean member `member` as the request sent it, or `default` when the request
/// left it out.
fn requested_flag(
    members: &::serde_json::Map<String, ::serde_json::Value>,
    member: &str,
    default: bool,
) -> Result<bool, String> {
    match members.get(member) {
        None | Some(::serde_json::Value::Null) => Ok(default),
        Some(sent) => sent.as_bool().ok_or_else(|| {
            not_of_modelled_type(&member_path(member), "a boolean, true or false")
        }),
    }
}

/// Which member of the input union carries the data of the source format `format`,
/// or `None` for a format no member of it carries.
fn input_member_for(format: &str) -> Option<&'static str> {
    INPUT_MEMBER_FOR_SOURCE_FORMAT
        .iter()
        .find(|(source_format, _)| *source_format == format)
        .map(|(_, member)| *member)
}

/// The answer one transform produced: HTTP 200 carrying the Bundle in the
/// `@required` `TransformedData`, and the drift report beside it when the caller
/// asked for drift detection.
///
/// A caller that did not ask for drift detection is sent no `DriftReport` at all,
/// rather than an empty one: the member is optional, and a report nobody asked for
/// would claim the comparison was made.
fn transformed_response(
    transformed: &crate::state::Transformed,
    drift_detection_enabled: bool,
) -> RtResponse {
    let mut body = ::serde_json::Map::new();
    body.insert(
        TRANSFORMED_DATA_MEMBER.to_string(),
        ::serde_json::Value::String(transformed.bundle.to_string()),
    );
    if drift_detection_enabled {
        body.insert(
            DRIFT_REPORT_MEMBER.to_string(),
            ::serde_json::Value::String(crate::state::drift_report(&transformed.drift)),
        );
    }
    let mut response = RtResponse::new(
        StatusCode::try_from(SUCCESS_STATUS).expect("200 is a valid status"),
        SdkBody::from(::serde_json::Value::Object(body).to_string()),
    );
    response
        .headers_mut()
        .insert("content-type", JSON_CONTENT_TYPE);
    response
}

/// The sentence a transform is refused with when the profile's content declares no
/// mapping to apply, naming the profile and the version the transform resolved.
fn no_mapping_message(profile_id: &str, version: i32) -> String {
    format!(
        "Profile '{profile_id}' version {version} declares no data transformation mapping, so \
         no FHIR R4 resource could be produced"
    )
}

/// The sentence a transform is refused with when the profile converts FROM a format
/// no member of the input union carries.
fn format_not_transformable_message(format: &str) -> String {
    format!(
        "Synchronous transformation is not available for a profile whose SourceFormat is {}",
        bounded(format)
    )
}

/// The sentence a transform is refused with when the request carries its data in
/// another member than the one the profile's source format travels in.
fn input_does_not_match_message(expected: &str, format: &str) -> String {
    format!(
        "{} must carry {expected} for a profile whose SourceFormat is {}",
        member_path(INPUT_DATA_MEMBER),
        bounded(format)
    )
}

/// The sentence a transform is refused with when the request names more files than
/// this emulator reads in one call.
fn too_many_files_message(files: usize) -> String {
    format!(
        "{} must carry at most {} files, got {files}",
        union_member_path(CSV_INPUT_MEMBER),
        crate::state::MAX_TRANSFORM_INPUT_FILES
    )
}

/// The modelled `ValidationException`, at the HTTP 400 its `@httpError` names.
fn validation_exception(message: &str) -> RtResponse {
    modelled_error(400, "ValidationException", message)
}

/// The modelled `ResourceNotFoundException`, at the HTTP 404 its `@httpError` names,
/// stating the sentence every profile-not-found path of this crate states.
fn resource_not_found(message: &str) -> RtResponse {
    modelled_error(404, "ResourceNotFoundException", message)
}

/// The answer when this service's store cannot be reached: a server fault, never a
/// fresh store and never an empty Bundle.
fn store_unavailable() -> RtResponse {
    modelled_error(
        500,
        INTERNAL_SERVER_EXCEPTION,
        "The HealthLake data transformation profile registry is unavailable",
    )
}

/// The answer when the request body cannot be read in memory at all: the modelled
/// server fault, for the reason [`super::validate_source`] answers one.
fn unreadable_body() -> RtResponse {
    modelled_error(
        500,
        INTERNAL_SERVER_EXCEPTION,
        "The server could not read the submitted data from the request body",
    )
}

/// The answer when the transform itself did not run to completion: the modelled
/// server fault, never a Bundle, because nothing produced one.
fn transform_unperformed() -> RtResponse {
    modelled_error(
        500,
        INTERNAL_SERVER_EXCEPTION,
        "The server did not complete the synchronous transformation of the submitted data",
    )
}

#[cfg(test)]
mod tests {
    //! The path rule this surface is routed on, and the request rules it reads, over
    //! the shapes a client sends them in. The transform's end-to-end behaviour is in
    //! `tests/all/transform_data.rs`, over the wire a client reaches it on.

    use super::*;

    /// A request body carrying one CSV file under `name`, for the file-name rules a
    /// `json!` literal cannot spell a key for.
    fn csv_request(profile_id: &str, name: &str, content: &str) -> ::serde_json::Value {
        let files: ::serde_json::Map<String, ::serde_json::Value> =
            ::serde_json::Map::from_iter([(
                name.to_string(),
                ::serde_json::Value::from(content),
            )]);
        ::serde_json::json!({
            "ProfileId": profile_id,
            "InputData": { "CsvInput": ::serde_json::Value::Object(files) },
        })
    }

    /// RULE: the surface is addressed by its one path segment, and nothing else is.
    #[test]
    fn only_the_transform_data_segment_addresses_the_transform() {
        // (case, request path, addresses /transform-data)
        let rows: [(&str, &str, bool); 7] = [
            ("the path as sent", "/transform-data", true),
            ("with a trailing separator", "/transform-data/", true),
            ("with no leading separator", "transform-data", true),
            ("a deeper path", "/transform-data/CSV", false),
            ("the sibling check", "/validate-source", false),
            ("a tagging path", "/tags/arn", false),
            ("the control plane's root path", "/", false),
        ];

        for (case, path, expected) in rows {
            let actual = addresses_transform_data(path);
            assert_eq!(
                actual, expected,
                "case {case:?} ({path}): expected addresses_transform_data == {expected}, got \
                 {actual}"
            );
        }
    }

    /// RULE: the request's members are read as the model declares them — the two
    /// required ones, the union's one member, and each flag's own default.
    #[test]
    fn a_request_is_read_as_the_model_declares_it() {
        let profile_id = "0".repeat(PROFILE_ID_LEN);
        // (case, the request body, what it asked for: (member, drift, provenance))
        /// One row: the case, the request body, and what it asked for — the input
        /// union member, whether drift detection was asked for, and whether
        /// provenance was.
        type Row = (
            &'static str,
            ::serde_json::Value,
            Option<(&'static str, bool, bool)>,
        );
        let rows: Vec<Row> = vec![
            (
                "CSV input, with both flags left out",
                ::serde_json::json!({
                    "ProfileId": profile_id,
                    "InputData": { "CsvInput": { "patients": "A\n1\n" } },
                }),
                Some((CSV_INPUT_MEMBER, false, PROVENANCE_ENABLED_BY_DEFAULT)),
            ),
            (
                "C-CDA input, with both flags sent",
                ::serde_json::json!({
                    "ProfileId": profile_id,
                    "InputData": { "CcdaInput": "<ClinicalDocument/>" },
                    "DriftDetectionEnabled": true,
                    "ProvenanceEnabled": false,
                }),
                Some((CCDA_INPUT_MEMBER, true, false)),
            ),
            (
                "no ProfileId",
                ::serde_json::json!({ "InputData": { "CcdaInput": "x" } }),
                None,
            ),
            (
                "a ProfileId outside the member's length",
                ::serde_json::json!({
                    "ProfileId": "abc",
                    "InputData": { "CcdaInput": "x" },
                }),
                None,
            ),
            (
                "a ProfileId outside the member's pattern",
                ::serde_json::json!({
                    "ProfileId": "A".repeat(PROFILE_ID_LEN),
                    "InputData": { "CcdaInput": "x" },
                }),
                None,
            ),
            (
                "no InputData",
                ::serde_json::json!({ "ProfileId": profile_id }),
                None,
            ),
            (
                "an InputData carrying both members",
                ::serde_json::json!({
                    "ProfileId": profile_id,
                    "InputData": { "CcdaInput": "x", "CsvInput": { "a": "b" } },
                }),
                None,
            ),
            (
                "an InputData carrying neither member",
                ::serde_json::json!({ "ProfileId": profile_id, "InputData": {} }),
                None,
            ),
            (
                "a file name outside the modelled pattern",
                csv_request(&profile_id, "pat ients", "A\n1\n"),
                None,
            ),
            (
                "a file name past the modelled length",
                csv_request(
                    &profile_id,
                    &"a".repeat(MAX_FILE_NAME_LEN + 1),
                    "A\n1\n",
                ),
                None,
            ),
            (
                "a file name at the modelled length",
                csv_request(&profile_id, &"a".repeat(MAX_FILE_NAME_LEN), "A\n1\n"),
                Some((CSV_INPUT_MEMBER, false, PROVENANCE_ENABLED_BY_DEFAULT)),
            ),
            (
                // `\w` admits the ASCII word characters only, so a name outside
                // them is outside the member's pattern.
                "a file name carrying a non-ASCII letter",
                csv_request(&profile_id, "pati\u{e9}nts", "A\n1\n"),
                None,
            ),
            (
                "submitted data past the ceiling one transform reads",
                csv_request(
                    &profile_id,
                    "patients",
                    &"A\n".repeat(crate::state::MAX_TRANSFORM_INPUT_BYTES),
                ),
                None,
            ),
            (
                "a flag that is not a boolean",
                ::serde_json::json!({
                    "ProfileId": profile_id,
                    "InputData": { "CcdaInput": "x" },
                    "DriftDetectionEnabled": "yes",
                }),
                None,
            ),
        ];

        for (case, body, expected) in rows {
            let read = requested_transform(
                ::serde_json::to_vec(&body)
                    .expect("the request body serializes")
                    .as_slice(),
            );
            let actual = read.as_ref().ok().map(|requested| {
                (
                    requested.input.member(),
                    requested.drift_detection_enabled,
                    requested.provenance_enabled,
                )
            });
            assert_eq!(
                actual, expected,
                "case {case:?}: expected {expected:?}, got {actual:?} ({read:?})"
            );
        }
    }
}
