// SPDX-License-Identifier: CC0-1.0

//! The refusals this service answers whose wire identity its own model does not
//! express, and the error channel that carries them.
//!
//! Two things about an answer are decided by the MODEL for a modelled error: the
//! shape — and with it the `__type` a client branches on — and the `@httpError`
//! status. Amazon Translate reports a resource that is not there under the
//! modelled shape but NOT at the status that shape declares: its API reference
//! publishes `ResourceNotFoundException` as an HTTP 400 client error, while the
//! model's `@httpError` on that shape says 404 (`smithy_query query=shape
//! shape=ResourceNotFoundException`). A refusal at the published status
//! therefore cannot be constructed as a plain variant of an operation's
//! `#[operation_error]` enum, so it lives here as [`WireRefusal`].
//!
//! It lives here once, rather than in each operation's file: what a refusal
//! looks like on the wire is a property of the SERVICE, and the operations that
//! report a resource absent — the terminology readers and the delete, the two
//! synchronous translate calls, the batch-job readers and the submission, and
//! the three ARN-addressed tag operations — must not answer one condition two
//! ways. An operation carries it by declaring its error channel [`Refusable`],
//! which widens that operation's own modelled channel without changing how any
//! modelled error is rendered.

use ::aws_smithy_schema::serde::SerializableStruct;
use ::aws_smithy_schema::Schema;
use ::smithy_server_runtime::OperationError;

use crate::ops::types::ResourceNotFoundException;

/// The status this service answers a resource-not-found refusal with: the 400 of
/// a client error, as Amazon Translate's own API reference publishes it for this
/// error class, rather than the 404 the modelled shape's `@httpError` declares.
///
/// Clients, and the proxies in front of them, branch on the status CLASS before
/// they parse a body, and the two are classified differently — a 404 as "no such
/// route or endpoint", retried and surfaced unlike a client error — so the
/// status is part of the answer, not a detail of it.
const RESOURCE_NOT_FOUND_STATUS: u16 = 400;

/// The `__type` such a refusal is named by, which is the modelled shape's own
/// name: only the STATUS of this refusal differs from the model's declaration,
/// and a client branches on the code.
const RESOURCE_NOT_FOUND_CODE: &str = "ResourceNotFoundException";

/// A refusal this service words itself, carrying the ONE mapping from the
/// refusal class to the wire code, the HTTP status and the body it answers with.
#[derive(Debug)]
pub enum WireRefusal {
    /// A resource the request addressed — by name, by job id or by ARN — that
    /// this account holds nothing for. The body is the modelled
    /// `ResourceNotFoundException` the operation would have carried, so the
    /// sentence each operation words stays that operation's own.
    ResourceNotFound(ResourceNotFoundException),
}

impl WireRefusal {
    /// The refusal reporting that the resource a request addressed is not there,
    /// stating `body` — whichever of this service's not-found wordings the
    /// calling operation uses.
    pub fn not_found(body: ResourceNotFoundException) -> Self {
        Self::ResourceNotFound(body)
    }

    /// The body this refusal serializes: the modelled shape itself, so its own
    /// schema decides which members the answer carries.
    fn as_serializable(&self) -> &dyn SerializableStruct {
        match self {
            Self::ResourceNotFound(body) => body,
        }
    }

    /// The schema the answer is written against.
    fn variant_schema(&self) -> &'static Schema {
        match self {
            Self::ResourceNotFound(_) => &crate::ops::types::SCHEMA_RESOURCE_NOT_FOUND_EXCEPTION,
        }
    }

    /// The code on the wire, which the framework reads from an operation's
    /// `shape_name` rather than from the schema.
    fn error_code(&self) -> &'static str {
        match self {
            Self::ResourceNotFound(_) => RESOURCE_NOT_FOUND_CODE,
        }
    }

    /// The HTTP status this refusal answers with.
    fn http_status(&self) -> u16 {
        match self {
            Self::ResourceNotFound(_) => RESOURCE_NOT_FOUND_STATUS,
        }
    }

    /// The sentence the body states, for the [`std::fmt::Display`] rendering
    /// below.
    fn message(&self) -> &str {
        match self {
            Self::ResourceNotFound(body) => body.message.as_deref().unwrap_or_default(),
        }
    }
}

impl ::std::fmt::Display for WireRefusal {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}: {}", self.error_code(), self.message())
    }
}

impl ::std::error::Error for WireRefusal {}

/// One operation's error channel, widened by the refusals above.
///
/// `Channel` is the operation's own channel — its modelled errors, the scaffold's
/// 501 and the framework's synthetic `ValidationException` — rendered exactly as
/// it is rendered without this wrapper. `Refused` is one of the service's own
/// refusals, rendered by [`WireRefusal`]. An operation declares
/// `type Error = Refusable<{Op}ErrorModeled>` and keeps writing
/// `Err(SomeModeledError.into())` for every modelled failure.
#[derive(Debug)]
pub enum Refusable<E> {
    /// The operation's own error channel.
    Channel(crate::scaffolded::Scaffolded<E>),
    /// A refusal this service words itself.
    Refused(WireRefusal),
}

impl<E> From<crate::scaffolded::Scaffolded<E>> for Refusable<E> {
    fn from(channel: crate::scaffolded::Scaffolded<E>) -> Self {
        Self::Channel(channel)
    }
}

impl<E> From<WireRefusal> for Refusable<E> {
    fn from(refusal: WireRefusal) -> Self {
        Self::Refused(refusal)
    }
}

impl<E: ::std::fmt::Display> ::std::fmt::Display for Refusable<E> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            Self::Channel(error) => write!(f, "{error}"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// `source()` forwards to the wrapped failure rather than taking the default
/// `None`.
impl<E: ::std::error::Error + 'static> ::std::error::Error for Refusable<E> {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            Self::Channel(error) => error.source(),
            Self::Refused(refusal) => refusal.source(),
        }
    }
}

/// Every method delegates: the operation's own channel renders a modelled error
/// exactly as it would without this wrapper, and a refusal renders as
/// [`WireRefusal`] states it — so every operation that carries this channel
/// answers one of those conditions exactly as its siblings do.
impl<E: OperationError> OperationError for Refusable<E> {
    fn as_serializable(&self) -> &dyn SerializableStruct {
        match self {
            Self::Channel(error) => error.as_serializable(),
            Self::Refused(refusal) => refusal.as_serializable(),
        }
    }

    fn variant_schema(&self) -> &'static Schema {
        match self {
            Self::Channel(error) => error.variant_schema(),
            Self::Refused(refusal) => refusal.variant_schema(),
        }
    }

    fn shape_name(&self) -> &'static str {
        match self {
            Self::Channel(error) => error.shape_name(),
            Self::Refused(refusal) => refusal.error_code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::Channel(error) => error.http_status(),
            Self::Refused(refusal) => refusal.http_status(),
        }
    }

    fn query_error_code(&self) -> Option<&'static str> {
        match self {
            Self::Channel(error) => error.query_error_code(),
            // Nothing to honour: the modelled `ResourceNotFoundException`
            // carries no `awsQueryError` trait, and this service speaks
            // `awsJson1_1` in any case.
            Self::Refused(_) => None,
        }
    }
}
