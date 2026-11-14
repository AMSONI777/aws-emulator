// SPDX-License-Identifier: CC0-1.0

//! The refusal this service answers whose wire identity its own error list does not
//! express, and the error channel that carries it.
//!
//! Two things about an answer are decided by the MODEL for a modelled error: the shape —
//! and with it the `__type` a client branches on — and the `@httpError` status. A request
//! this account is not authorized to make is neither: no operation of this service
//! declares an authorization error, because authorization is not a property of the request
//! the model describes. AWS answers it from its common-error table
//! (`AccessDeniedException`, "You do not have sufficient access to perform this action",
//! HTTP 400 for this service's recorded refusal), so it cannot be constructed as a plain
//! variant of an operation's `#[operation_error]` enum.
//!
//! It lives here, once, rather than in each operation's file: what a refusal looks like on
//! the wire is a property of the SERVICE, and two operations that reach the same decision
//! must not word it two ways. An operation carries it by declaring its error channel
//! [`Refusable`], which widens that operation's own modelled channel without changing how
//! any modelled error is rendered.

use ::aws_smithy_schema::serde::{SerdeError, SerializableStruct, ShapeSerializer};
use ::aws_smithy_schema::{Schema, ShapeId, ShapeType};
use ::smithy_server_runtime::OperationError;

/// The `__type` an access-denied refusal is named by, as the AWS "Common Errors" table
/// names it.
const ACCESS_DENIED_CODE: &str = "AccessDeniedException";

/// The status such a refusal is answered at: the 4xx of a client error, which is what this
/// service's recorded refusal of a cross-account resource carries. Every error this
/// service's own model declares is a 400 too, so one status answers a client's mistake
/// whatever the reason for it.
const ACCESS_DENIED_STATUS: u16 = 400;

/// The IAM action namespace this service publishes its actions under — the model's own
/// `arnNamespace` and sigv4 signing name (`smithy_query(query="service_info")`), which are
/// the same word.
const ACTION_NAMESPACE: &str = "codebuild";

/// The IAM action an operation of this service asks for: `codebuild:<ApiName>`, the name
/// the operation is called by.
pub fn action_of(operation: &str) -> String {
    format!("{ACTION_NAMESPACE}:{operation}")
}

/// The IAM principal a request to this emulator speaks for — the identity the account
/// holds and `sts:GetCallerIdentity` reports — which is the principal an authorization
/// refusal names.
///
/// Read from the workspace's shared definition of that identity, so the principal this
/// service refuses in the name of is the one every other service of this emulator names.
pub fn caller_principal() -> String {
    ::service_common::caller_principal::ambient_user_arn()
}

/// The `Message` member of the access-denied refusal's shape.
///
/// Spelled `Message`: this service speaks `awsJson1_1`, whose codec takes the wire key
/// from the member NAME, and the AWS common-error envelope carries its sentence under that
/// capitalized key — unlike the error shapes this service's own model declares, whose
/// member is the lowercase `message`. A client reading the common-error envelope finds
/// nothing under any other name.
static ACCESS_DENIED_MESSAGE: Schema = Schema::new_member(
    ShapeId::from_static(
        "smithy.framework#AccessDeniedException$Message",
        "smithy.framework",
        "Message",
    ),
    ShapeType::String,
    "Message",
    0,
)
.with_xml_name("Message")
.with_json_name("Message");

/// Schema for the access-denied refusal's shape.
///
/// In the `smithy.framework` namespace for the same reason as the scaffold's synthetic
/// shapes (`crate::scaffolded`): this shape is in no service's model, so it must not
/// collide with a modelled one. The wire `__type` comes from
/// [`OperationError::shape_name`], not from here.
static ACCESS_DENIED_SCHEMA: Schema = Schema::new_struct(
    ShapeId::from_static(
        "smithy.framework#AccessDeniedException",
        "smithy.framework",
        "AccessDeniedException",
    ),
    ShapeType::Structure,
    &[&ACCESS_DENIED_MESSAGE],
);

/// The body of an access-denied refusal: the one sentence it states.
#[derive(Debug, Clone)]
pub struct AccessDenied {
    /// The sentence — [`WireRefusal::access_denied`].
    pub message: String,
}

impl SerializableStruct for AccessDenied {
    fn serialize_members(&self, s: &mut dyn ShapeSerializer) -> Result<(), SerdeError> {
        s.write_string(&ACCESS_DENIED_MESSAGE, self.message.as_str())?;
        Ok(())
    }
}

/// A refusal this service words itself, carrying the ONE mapping from the refusal class to
/// the wire code, the HTTP status and the body it answers with.
#[derive(Debug)]
pub enum WireRefusal {
    /// A request addressing a resource of ANOTHER account, which no resource-based policy
    /// readable here grants this account.
    AccessDenied(AccessDenied),
}

impl WireRefusal {
    /// The refusal of `operation` on `resource_arn`, a resource of another account.
    ///
    /// Every part of the sentence comes from the request — the principal from the
    /// credential it was signed with, the action from the operation it named, the resource
    /// from the ARN it supplied — so nothing about the resource is looked up to state it,
    /// and the same words answer every account this one cannot read.
    pub fn access_denied(operation: &str, resource_arn: &str) -> Self {
        Self::AccessDenied(AccessDenied {
            message: ::service_common::iam_authorization::not_authorized_by_resource_policy(
                &caller_principal(),
                &action_of(operation),
                resource_arn,
            ),
        })
    }

    /// The body this refusal serializes.
    fn as_serializable(&self) -> &dyn SerializableStruct {
        match self {
            Self::AccessDenied(e) => e,
        }
    }

    /// The schema the answer is written against.
    fn variant_schema(&self) -> &'static Schema {
        match self {
            Self::AccessDenied(_) => &ACCESS_DENIED_SCHEMA,
        }
    }

    /// The code on the wire, which the framework reads from an operation's `shape_name`
    /// rather than from the schema.
    fn error_code(&self) -> &'static str {
        match self {
            Self::AccessDenied(_) => ACCESS_DENIED_CODE,
        }
    }

    /// The HTTP status this refusal answers with.
    fn http_status(&self) -> u16 {
        match self {
            Self::AccessDenied(_) => ACCESS_DENIED_STATUS,
        }
    }

    /// The sentence the body states, for the [`std::fmt::Display`] rendering below.
    fn message(&self) -> &str {
        match self {
            Self::AccessDenied(e) => &e.message,
        }
    }
}

impl ::std::fmt::Display for WireRefusal {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}: {}", self.error_code(), self.message())
    }
}

impl ::std::error::Error for WireRefusal {}

/// One operation's error channel, widened by the refusal above.
///
/// `Channel` is the operation's own channel — its modelled errors, the scaffold's 501 and
/// the framework's synthetic `ValidationException` — rendered exactly as it is rendered
/// without this wrapper. `Refused` is the refusal this service words itself. An operation
/// declares `type Error = Refusable<{Op}ErrorModeled>` and keeps writing
/// `Err(SomeModeledError.into())`.
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
            Self::Channel(e) => write!(f, "{e}"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// `source()` forwards to the wrapped failure rather than taking the default `None`.
impl<E: ::std::error::Error + 'static> ::std::error::Error for Refusable<E> {
    fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
        match self {
            Self::Channel(e) => e.source(),
            Self::Refused(refusal) => refusal.source(),
        }
    }
}

/// Every method delegates: the operation's own channel renders a modelled error exactly as
/// it would without this wrapper, and a refusal renders as [`WireRefusal`] states it — so
/// an operation that carries this channel answers either condition exactly as its siblings
/// do.
impl<E: OperationError> OperationError for Refusable<E> {
    fn as_serializable(&self) -> &dyn SerializableStruct {
        match self {
            Self::Channel(e) => e.as_serializable(),
            Self::Refused(refusal) => refusal.as_serializable(),
        }
    }

    fn variant_schema(&self) -> &'static Schema {
        match self {
            Self::Channel(e) => e.variant_schema(),
            Self::Refused(refusal) => refusal.variant_schema(),
        }
    }

    fn shape_name(&self) -> &'static str {
        match self {
            Self::Channel(e) => e.shape_name(),
            Self::Refused(refusal) => refusal.error_code(),
        }
    }

    fn http_status(&self) -> u16 {
        match self {
            Self::Channel(e) => e.http_status(),
            Self::Refused(refusal) => refusal.http_status(),
        }
    }

    fn query_error_code(&self) -> Option<&'static str> {
        match self {
            Self::Channel(e) => e.query_error_code(),
            // The refusal's shape is in no model, so it carries no `awsQueryError` trait
            // to honour — and this service speaks no query protocol.
            Self::Refused(_) => None,
        }
    }
}
