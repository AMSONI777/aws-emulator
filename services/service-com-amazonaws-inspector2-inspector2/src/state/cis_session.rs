// SPDX-License-Identifier: CC0-1.0

//! The identity gate the CIS-session RPCs — `StartCisSession`, `StopCisSession`,
//! `SendCisSessionHealth` and `SendCisSessionTelemetry` — answer their callers with, in
//! ONE place so the four refusals cannot drift apart.

/// The sentence a CIS-session RPC refuses a caller whose identity carries no CIS scan
/// resource id with.
///
/// FIXED text: the refusal is decided by the calling identity, so it names no scan job, no
/// session token, no account and no instant, and is therefore the same sentence for every
/// such call.
pub const CIS_SESSION_IDENTITY_REFUSAL_MESSAGE: &str =
    "Identity user principal does not contain valid resourceId";

/// The `ValidationExceptionReason` that refusal carries: no member of the request failed
/// validation — what the request lacks is a caller identity carrying a scan resource id —
/// so the reason is the catch-all token rather than the field-validation one.
///
/// Source: `smithy_query(query="shape", shape="ValidationExceptionReason")` —
/// `CANNOT_PARSE | FIELD_VALIDATION_FAILED | OTHER`.
pub const CIS_SESSION_IDENTITY_REFUSAL_REASON: &str = "OTHER";

/// The refusal a CIS-session RPC answers its caller with.
///
/// RULE: a CIS-session RPC is served only to the Amazon Inspector-managed SSM plugin
/// session the service itself dispatched a CIS scan to, whose identity carries that scan's
/// resource id; a caller whose identity carries no such resource id is refused with the
/// operation's modelled client fault, decided from the identity ALONE — ahead of any scan
/// job id lookup and any session write, so the answer depends neither on the scan job id
/// and session token the request presents nor on whether a CIS scan job of that id exists.
///
/// This API models no operation that dispatches a CIS scan to an instance, so this
/// emulator mints no plugin session and every identity that can sign a request against it
/// is an ordinary IAM user or STS session. Each of them fails the gate, which is also what
/// makes the absence of an effect observable: no session is ever started, and a stop,
/// health or telemetry call for one is refused the same way rather than reporting a session
/// that does not exist.
pub fn cis_session_identity_refusal() -> crate::ops::types::ValidationException {
    crate::ops::types::ValidationException {
        message: CIS_SESSION_IDENTITY_REFUSAL_MESSAGE.to_string(),
        reason: CIS_SESSION_IDENTITY_REFUSAL_REASON.to_string(),
        // No member of the request is at fault, so the refusal names no field.
        fields: None,
    }
}
