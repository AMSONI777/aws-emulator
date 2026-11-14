// SPDX-License-Identifier: CC0-1.0

//! The wait condition SIGNAL plane: the target an `AWS::CloudFormation::WaitConditionHandle`
//! publishes as its physical resource id.
//!
//! # Not a modelled operation
//!
//! A client releases an `AWS::CloudFormation::WaitCondition` by sending its signal document
//! to the URL the wait condition's handle publishes — a plain HTTP `PUT` that names no
//! modelled operation, carries no `X-Amz-Target`, and presents no credential of its own, as a
//! pre-signed URL is followed. Nothing in the generated routing table can name it, so it is
//! reached through the two seams any emulated data plane uses, exactly as the custom resource
//! response plane beside it is ([`super::custom_resource_plane`]):
//!
//! * [`crate::service::EmulatedService::can_handle`] also claims a request whose PATH is one
//!   of the handle URLs this service published
//!   ([`crate::state::provisioning::wait_condition_handle::parse_signal_path`]);
//! * [`smithy_server_runtime::Service::override_routing_error`] serves it, and the router
//!   reaches that seam BEFORE authentication — which is what lets the published URL be
//!   followed unsigned.
//!
//! # What is served
//!
//! `PUT /<stack-id>/<logical-id>?<pre-signing query>` records the signal document against the
//! wait conditions declared with that handle, which releases a wait that now has the signals
//! its `Count` asks for ([`crate::state::handle_signals`]). The path is the OBJECT KEY of the
//! handle's write target, exactly as CloudFormation keys one, and the S3 endpoint that target
//! lives at is named in the query
//! ([`crate::state::provisioning::wait_condition_handle`]). The URL is single-purpose: it
//! signals the wait conditions of ONE handle of one stack, and a write that does not present
//! the signature this service published for that handle is refused
//! ([`crate::state::ComAmazonawsCloudformationCloudformationState::published_handle_url`]) —
//! the path alone would admit a target a caller assembled, and this seam is reached before
//! the request is authenticated, so the comparison is this service's own, exactly as a
//! pre-signed URL whose signature does not verify is refused rather than served.
//!
//! The write itself is otherwise accepted whether or not anything is still waiting for that
//! signal, exactly as a pre-signed `PUT` is — a client signalling a wait a concluded operation
//! no longer holds is not told its own write failed — and a signal nothing waits for is simply
//! recorded against nothing.
//!
//! Every other method on this path space is refused: the published URL describes the one
//! write a client makes, and answering a read on it would serve a document the URL grants no
//! read of.
//!
//! # The error envelope
//!
//! This plane is plain HTTPS rather than a modelled operation, so a refusal is answered in its
//! own small JSON envelope carrying the code and a reason — never in this service's awsQuery
//! shapes, which belong to the modelled operations. Every message is built from the constants
//! below and carries nothing from the request, so a caller cannot probe for the targets it was
//! not handed.

use aws_smithy_runtime_api::http::{Request as RtRequest, Response as RtResponse, StatusCode};
use aws_smithy_types::body::SdkBody;

use crate::state::handle_signals::SignalOutcome;
use crate::state::provisioning::custom_resource;
use crate::state::provisioning::wait_condition_handle::{
    HandleSignal, SignalTarget, MAX_SIGNAL_DOCUMENT_BYTES,
};

/// The media type a refusal of this plane is stated in.
const ERROR_CONTENT_TYPE: &str = "application/json";

/// What this plane says to a method the published URL does not describe.
const METHOD_NOT_ALLOWED_MESSAGE: &str = "A wait condition signal is sent with PUT";

/// What this plane says to a body that is not a wait condition signal document, naming the
/// members a well-formed one must carry.
const MALFORMED_SIGNAL_MESSAGE: &str =
    "A wait condition signal must be a JSON document carrying a Status of SUCCESS or FAILURE \
     and a UniqueId; this one does not state";

/// What this plane says to a document larger than one a signal may carry: the document is not
/// read at all, so nothing a caller sends sizes this store.
const SIGNAL_TOO_LONG_MESSAGE: &str = "A wait condition signal document is too long to read";

/// What this plane says to a write whose signature is not the one published for the handle it
/// names: the answer a pre-signed URL whose signature does not verify gives. One sentence
/// carrying nothing from the request.
const SIGNATURE_MISMATCH_MESSAGE: &str =
    "The request signature does not match the signature of this signal target";

/// What this plane says when the body could not be read at all. The router buffers every
/// request before dispatch, so a body it cannot hand back in memory is a failure of the
/// server, never a caller's malformed document.
const UNREADABLE_BODY_MESSAGE: &str = "The server could not read the signal document";

/// What this plane says when this service's store is not reachable.
const STORE_UNAVAILABLE_MESSAGE: &str = "The CloudFormation store is unavailable";

/// Serve one write to a published handle URL, and say whether the signal RELEASED the wait
/// the operation in flight was held at: `true` is the one write that changed that operation
/// from waiting for signals to not waiting, which is what makes the work behind it due
/// ([`crate::state::provider_driver`]); `false` is every other write — a wait still short of
/// its `Count`, one already satisfied, a signal under a unique id already recorded, and a
/// target nothing is waiting at. So at most ONE write per stack operation sets that work off,
/// however many writes arrive.
///
/// Whether anything was waiting for the signal is the store's judgement
/// ([`crate::state::ComAmazonawsCloudformationCloudformationState::record_handle_signal`]):
/// this function reads the request, reads the signal out of its body, and hands that signal to
/// the store. The WRITE is accepted either way — the URL is the target a pre-signed `PUT` goes
/// to — so the only thing refused here is a write this plane cannot read as one.
pub fn serve<Eng: Send + Sync + 'static>(
    engine: &Eng,
    req: &RtRequest,
    region: &str,
    target: &SignalTarget,
) -> (RtResponse, bool) {
    if req.method() != "PUT" {
        return (
            refusal(405, "MethodNotAllowed", METHOD_NOT_ALLOWED_MESSAGE),
            false,
        );
    }
    // The URL authorises ONE write, and its signature is what says so: a target assembled by
    // a caller carries no signature this service published for it. A write about a handle
    // this service published no URL for is accepted and recorded against nothing — a
    // pre-signed `PUT` is not told the stack has moved on — so there is a published signature
    // to hold it to only where such a URL stands.
    let Some(state) = crate::state::service_state(engine) else {
        return (
            refusal(500, "InternalFailure", STORE_UNAVAILABLE_MESSAGE),
            false,
        );
    };
    let query = req.uri().split('?').nth(1).unwrap_or_default();
    if let Some(published) = state.lock().published_handle_url(region, target) {
        let published = published.split('?').nth(1).unwrap_or_default().to_string();
        if custom_resource::presented_signature(query)
            != custom_resource::presented_signature(&published)
        {
            return (
                refusal(403, "SignatureDoesNotMatch", SIGNATURE_MISMATCH_MESSAGE),
                false,
            );
        }
    }
    let Some(body) = req.body().bytes() else {
        return (
            refusal(500, "InternalFailure", UNREADABLE_BODY_MESSAGE),
            false,
        );
    };
    if body.len() > MAX_SIGNAL_DOCUMENT_BYTES {
        return (refusal(400, "InvalidRequest", SIGNAL_TOO_LONG_MESSAGE), false);
    }
    let Ok(document) = ::serde_json::from_slice::<::serde_json::Value>(body) else {
        return (malformed("a well-formed JSON document"), false);
    };
    let signal = match HandleSignal::read(&document) {
        Ok(signal) => signal,
        Err(member) => return (malformed(member), false),
    };
    let outcome = state.lock().record_handle_signal(
        region,
        target,
        &signal,
        ::std::time::SystemTime::now(),
    );
    (recorded(), outcome == SignalOutcome::Released)
}

/// The answer to a body that is not a well-formed signal document, naming `member` — the
/// member of the document a client must send, which is not something read off the request.
fn malformed(member: &str) -> RtResponse {
    one_refusal(
        400,
        "InvalidRequest",
        format!("{MALFORMED_SIGNAL_MESSAGE} {member}"),
    )
}

/// The answer to a signal this plane recorded: the signal is in hand, and there is nothing to
/// report back about it — the empty 200 a pre-signed `PUT` is answered with.
fn recorded() -> RtResponse {
    let mut resp = RtResponse::new(
        StatusCode::try_from(200u16).expect("200 is a valid status"),
        SdkBody::empty(),
    );
    resp.headers_mut().insert("content-length", "0");
    resp
}

/// One signal-plane refusal stated in this module's own fixed words.
fn refusal(status: u16, code: &str, message: &str) -> RtResponse {
    one_refusal(status, code, message.to_string())
}

/// One signal-plane refusal: the status, the code in `x-amzn-errortype`, and a JSON body
/// carrying the reason.
fn one_refusal(status: u16, code: &str, message: String) -> RtResponse {
    let body = ::serde_json::json!({ "code": code, "message": message }).to_string();
    let mut resp = RtResponse::new(
        StatusCode::try_from(status).expect("the status is a constant of this module"),
        SdkBody::from(body),
    );
    resp.headers_mut().insert("content-type", ERROR_CONTENT_TYPE);
    resp.headers_mut().insert("x-amzn-errortype", code.to_string());
    resp
}
