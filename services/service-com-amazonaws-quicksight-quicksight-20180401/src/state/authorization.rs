// SPDX-License-Identifier: CC0-1.0

//! WHAT a call this account does not authorize reads.
//!
//! QuickSight reuses the modelled `AccessDeniedException` (HTTP 401) for every refusal
//! an account's own configuration or credentials cause, so the reason a particular call
//! was refused is carried only in the message: a client that has to tell "this account
//! holds no identity store for the identity type you asked for" from "your credentials
//! could not be validated" has nothing else to read. A handler therefore hands this
//! builder the sentence stating its reason, rendered by the templates in
//! [`super::refusals`] so every handler refusing for the same reason words it the same
//! way — the reason the conflict and not-found wordings live there too.

use super::*;

/// The modelled `AccessDeniedException` a refused call carries, reporting `message` as
/// the reason it was refused.
pub fn access_denied(message: String, request_id: &str) -> AccessDeniedException {
    AccessDeniedException {
        message: Some(message),
        request_id: Some(request_id.to_string()),
    }
}
