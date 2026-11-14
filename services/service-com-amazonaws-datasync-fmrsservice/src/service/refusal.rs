// SPDX-License-Identifier: CC0-1.0

//! How this service words a request its boundary refused — and the two halves of that
//! wording the boundary seam cannot state on its own.
//!
//! # What this service answers a refused request with
//!
//! This model declares exactly ONE client error, `InvalidRequestException` (400), carrying
//! `message` plus two code members that always hold the same value. So the CLASS of a
//! refusal travels in those code members rather than in the error's name, and a client
//! branching on "the location is gone", "the task is gone" or "that parameter is not one I
//! take" reads them.
//!
//! One refusal class is decided from the model's own constraints, before any handler runs,
//! and is still the SERVICE's own rather than the validation layer's: a value that is not a
//! well-formed ARN of one of this service's resources. It is answered as the modelled client
//! error — carrying the parameter class in `errorCode` and the sentence naming the value
//! that is not an ARN — serialized through the model's own schema in the envelope of the
//! protocol the request is served in, the same path a handler-raised
//! `InvalidRequestException` takes, so a caller cannot tell which layer refused it. The raw
//! expression the value had to match is not disclosed.
//!
//! Every OTHER refusal decided before a handler runs is the validation layer's, under the
//! code that layer answers with, and keeps its envelope clause for clause — with three
//! differences this service owns:
//!
//! * a `@required` member carrying a nested CONFIGURATION STRUCTURE that the request omitted
//!   is reported by the sentence naming that member, where a required member holding a value
//!   of its own keeps the clause about that value's absence;
//! * an enumerated type's admissible values are listed in the order the TABLE holding them
//!   is walked, in ascending bucket of each value's own string hash
//!   (`service_common::validation_message::in_hashed_enum_order`, the tree's one home for
//!   that order), whatever order the model declares them in; and
//! * a clause about a COLLECTION member quotes the collection the request carried
//!   (`service_common::validation_message::quoting_the_submitted_collection`), where the
//!   framework's walk has only a summary of that collection's SIZE — which is not a value
//!   any caller sent.
//!
//! # Why a per-operation wrapper
//!
//! [`Service::override_refusal`](smithy_server_runtime::Service::override_refusal) is handed
//! the violations ALONE — never the request they were found in, and never the operation
//! whose input schema declares the members they name. The submitted collection and the
//! model's own spelling of an omitted member are both unreachable from there, so
//! [`StatingItsOwnRefusals`] is where this wording lives: a per-operation wrapper, which has
//! the request and can re-read it.
//!
//! Nothing is re-implemented and no check is repeated in other words: the violations come
//! from the tree's shared collecting walk
//! (`service_common::validation::refusing_violations_with_echoes`, which runs the protocol's
//! own deserializer and the framework's own `constraints::validate` and owns every bound on
//! what one clause may quote), each clause is the framework's own `Violation::message`, the
//! envelope over them is the framework's own
//! (`service_common::validation_message::envelope_over`), and the status and the wire
//! envelope come from the framework's refusal channel. A request that breaks nothing is
//! handed to the wrapped operation untouched.

use aws_smithy_runtime_api::http::{Request as RtRequest, Response as RtResponse};
use aws_smithy_schema::{Schema, ShapeType};
use aws_smithy_schema_server::constraints::path;
use aws_smithy_schema_server::ProtocolError;
use service_common::validation::{refusing_violations_with_echoes, SubmittedEcho};
use service_common::validation_message::{
    envelope_over, in_hashed_enum_order, quoting_the_submitted_collection,
};
use smithy_server_runtime::{
    BoxFuture, ErasedOperation, Operation, OperationContext, Refusal, Refused, Service, Violation,
    ViolationKind,
};

use crate::ops::types::InvalidRequestException;

/// The wire code (`__type`) the one modelled client error of this service renders under.
const INVALID_REQUEST_EXCEPTION: &str = "InvalidRequestException";

/// The status that error declares (`httpError` 400 on
/// `com.amazonaws.datasync#InvalidRequestException`).
const REFUSED_STATUS: u16 = 400;

/// The code the framework's own refusal channel names for a value outside a modelled
/// constraint. Kept for every constraint class this service has no sentence of its own for,
/// so such a refusal reads exactly as it did before this layer existed.
const VALIDATION_EXCEPTION: &str = "ValidationException";

/// The ARN namespace segment every ARN addressing one of THIS service's resources carries
/// (`arn:<partition>:datasync:<region>:<account>:<resource>`), as each of this model's
/// resource-ARN patterns spells it.
///
/// Read off the broken `@pattern` expression itself, so the model decides which members are
/// this service's own ARNs: an ARN belonging to another service (an IAM role, an S3 bucket,
/// an EFS file system) names that service's namespace instead and keeps the framework's own
/// constraint clause.
const DATASYNC_ARN_NAMESPACE: &str = ":datasync:";

/// How this service words a request `Op`'s own modelled constraints refuse, or `None` when
/// the request breaks none of them — in which case the operation behind this layer is served.
///
/// The one class answered as the modelled client error comes first; everything else is the
/// validation layer's envelope, restated only where this service words a sentence of its
/// own, lists an enumerated value set in its own order or quotes a collection the request
/// carried.
pub fn stated_refusal<Op: Operation>(svc: &dyn Service, req: &RtRequest) -> Option<RtResponse> {
    let refusing = refusing_violations_with_echoes::<Op>(svc.definition().protocol(), req);
    if refusing.is_empty() {
        return None;
    }
    if let Some(refusal) = malformed_resource_arn(&refusing) {
        if let Some(response) = modelled_refusal_response(svc, req, refusal) {
            return Some(response);
        }
    }
    constraint_refusal::<Op>(svc, req, refusing)
}

/// The refusal this service states for one the framework raised with no request at hand —
/// [`Service::override_refusal`](smithy_server_runtime::Service::override_refusal)'s seam,
/// which is handed the violations alone.
///
/// The one restatement that needs neither the request nor the operation: an enumerated
/// type's value set belongs to the TYPE, so it is listed in this service's order wherever
/// that type is carried. A clause about a collection states the framework's own value here,
/// because the collection itself is only in the request. `None` keeps the framework's whole
/// wording.
pub fn stated_violations(refusal: &Refusal) -> Option<Refused> {
    let Refusal::Invalid(violations) = refusal else {
        return None;
    };
    let stated: Vec<Violation> = violations.iter().map(in_hashed_enum_order).collect();
    let clauses: Vec<String> = stated.iter().map(Violation::message).collect();
    Some(Refused {
        code: VALIDATION_EXCEPTION.to_string(),
        message: envelope_over(&clauses)?,
    })
}

/// The modelled client error a value that is not a well-formed ARN of one of this service's
/// resources earns, or `None` when `refusing` holds no such violation.
///
/// The first one decides the refusal: it is the same refusal whichever of a request's ARN
/// members held the value, so there is nothing to choose between two of them.
fn malformed_resource_arn(
    refusing: &[(Violation, SubmittedEcho)],
) -> Option<InvalidRequestException> {
    refusing
        .iter()
        .find_map(|(violation, echo)| match &violation.kind {
            ViolationKind::Pattern(expression) if expression.contains(DATASYNC_ARN_NAMESPACE) => {
                Some(datasync_arn_refusal(&submitted(violation, echo)?))
            }
            _ => None,
        })
}

/// The value the request carried at the member `violation` is about, as a sentence quoting it
/// states it: the submitted value when the collecting walk could render it, and otherwise
/// whatever the framework's own walk stored on the violation.
///
/// The walk's rendering is asked first because the framework's is elided past a ceiling of
/// its own, and a sentence that quotes an ARN quotes the ARN the request sent.
fn submitted(violation: &Violation, echo: &SubmittedEcho) -> Option<String> {
    match echo {
        SubmittedEcho::Rendered(value) => Some(value.clone()),
        _ => violation.value.clone(),
    }
}

/// The refusal a value that is not a well-formed ARN of one of this service's resources
/// earns: the parameter class, and the sentence naming the value that is not one.
///
/// The fixed text is the sentence around the single slot, which holds the value the request
/// carried; the raw expression the value had to match is not part of it, and is not
/// disclosed. This class carries the parameter code member alone: an ARN's SHAPE is read
/// ahead of the layer that resolves a DataSync resource, and that layer is the one which
/// sets the second code member as well.
fn datasync_arn_refusal(arn: &str) -> InvalidRequestException {
    InvalidRequestException {
        message: Some(format!(
            "Invalid parameter: DataSync ARN ({arn}) must match datasync resource regex."
        )),
        error_code: Some(crate::state::INVALID_PARAMETER_CODE.to_string()),
        datasync_error_code: None,
    }
}

/// The whole message a request that omitted a required CONFIGURATION STRUCTURE is refused
/// with: fixed text around the member's name, spelled as the MODEL declares it rather than
/// as a violation path spells one.
fn must_specify(member: &str) -> String {
    format!("Must specify {member}")
}

/// The member name an absent-required-member violation is reported by the sentence above
/// rather than by the validation layer's constraint clause, or `None` when no violation in
/// `violations` is one of those.
///
/// WHICH absent member is: one whose target is a nested CONFIGURATION STRUCTURE — the member
/// carries no value of its own, so there is nothing for a clause to quote and this service
/// names the member instead. A required member holding a VALUE (an ARN, a name, a list)
/// keeps the validation layer's own clause, which quotes that value's absence. Both facts are
/// read off the operation's input schema, so the model decides which members each sentence
/// covers.
///
/// A member nested inside a request structure keeps the clause too: its own shape is not
/// reachable from a member schema, so this layer cannot spell it as the model does.
fn absent_configuration(input_schema: &Schema, violations: &[Violation]) -> Option<String> {
    let absent = violations
        .iter()
        .find(|violation| matches!(violation.kind, ViolationKind::MissingRequiredMember))?;
    input_schema.members().iter().find_map(|member| {
        let name = member.member_name()?;
        (path::member(name) == absent.path && matches!(member.shape_type(), ShapeType::Structure))
            .then(|| name.to_string())
    })
}

/// `refusing` as the validation layer's own report, with the three halves this service
/// states differently: the sentence an absent configuration structure is named by, an
/// enumerated type's value set in this service's order, and a clause about a collection
/// quoting the collection the request carried.
///
/// Every other clause is the framework's own sentence over the violation as stated, and the
/// envelope over them is the framework's own, so nothing else about the report moves — the
/// code stays the one that layer answers with, because this is that layer's refusal and not
/// one of the service's own modelled failures.
fn constraint_refusal<Op: Operation>(
    svc: &dyn Service,
    req: &RtRequest,
    refusing: Vec<(Violation, SubmittedEcho)>,
) -> Option<RtResponse> {
    let stated: Vec<Violation> = refusing
        .into_iter()
        .map(|(violation, echo)| {
            quoting_the_submitted_collection(in_hashed_enum_order(&violation), echo)
        })
        .collect();
    let message = match absent_configuration(Op::INPUT_SCHEMA, &stated) {
        Some(member) => must_specify(&member),
        None => {
            let clauses: Vec<String> = stated.iter().map(Violation::message).collect();
            envelope_over(&clauses)?
        }
    };
    Some(svc.definition().refusal_response(
        ProtocolError::Invalid(stated),
        Some(Refused {
            code: VALIDATION_EXCEPTION.to_string(),
            message,
        }),
        req,
    ))
}

/// `refusal` as this service answers it: the modelled client error, serialized through the
/// model's own schema in the envelope of the protocol `req` is served in — the same path a
/// handler-raised `InvalidRequestException` takes, so both code members and the message
/// reach the wire the one way.
fn modelled_refusal_response(
    svc: &dyn Service,
    req: &RtRequest,
    refusal: InvalidRequestException,
) -> Option<RtResponse> {
    svc.definition()
        .wire_protocol(req)
        .protocol()
        .serialize_error(
            &refusal,
            &crate::ops::types::SCHEMA_INVALID_REQUEST_EXCEPTION,
            INVALID_REQUEST_EXCEPTION,
            REFUSED_STATUS,
        )
        .ok()
}

/// One modelled operation, served so that a request its own modelled constraints refuse is
/// worded the way THIS service words such a refusal.
///
/// It makes no routing decision and holds no state of its own: the operation it wraps is the
/// one the generated routing table names for the same key, built from the SAME shared engine,
/// and a request this wrapper does not refuse is handed to it untouched — so the framework
/// still owns the whole deserialize -> validate -> handle -> serialize sequence and every
/// status, shape and message it answers with.
///
/// The cost is DELIBERATE: an accepted request's body is read twice, here and in the
/// operation's own sequence, because the framework hands no already-built input to an
/// operation.
pub struct StatingItsOwnRefusals<Op> {
    operation: Op,
}

impl<Op> StatingItsOwnRefusals<Op> {
    /// Wrap one operation, already constructed from the shared engine.
    pub fn new(operation: Op) -> Self {
        Self { operation }
    }
}

impl<Op> ErasedOperation for StatingItsOwnRefusals<Op>
where
    Op: Operation + ErasedOperation,
{
    fn run<'r>(
        &'r self,
        svc: &'r dyn Service,
        req: &'r RtRequest,
        ctx: &'r OperationContext<'r>,
    ) -> BoxFuture<'r, RtResponse> {
        Box::pin(async move {
            // The whole refusal is decided — and the borrow of the definition it is
            // rendered through taken and dropped — BEFORE the await below:
            // `&dyn ErasedServiceDefinition` is not `Sync`, so holding one across that
            // await would make this future non-`Send`.
            if let Some(refused) = stated_refusal::<Op>(svc, req) {
                return refused;
            }
            self.operation.run(svc, req, ctx).await
        })
    }

    /// The wrapped operation's modelled auth schemes: wrapping an operation must not change
    /// which schemes sign it.
    fn auth_schemes(&self) -> Option<&'static [&'static str]> {
        self.operation.auth_schemes()
    }
}
