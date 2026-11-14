// SPDX-License-Identifier: CC0-1.0

//! The refusals every zonal-shift mutation answers, each worded once.
//!
//! `StartZonalShift`, `UpdateZonalShift` and `CancelZonalShift` refuse a request for
//! reasons the model does not express as a constraint — a shift that is no longer
//! running, a resource that already has a shift, a zone the resource is not deployed in,
//! a length of time a shift cannot be active for — and ARC states each of those classes
//! as ONE sentence that is a property of the CLASS: the same words for every shift, every
//! resource, every caller and every operation that reaches the class. A refusal therefore
//! carries nothing of the request or of the store — no shift id, no resource ARN, no
//! status token, no rejected value — and the identifiers a client needs are the modelled
//! members that carry them (`ConflictException$reason`,
//! `ConflictException$zonalShiftId`, `ValidationException$reason`), not text spliced into
//! the sentence.
//!
//! Each sentence lives here, next to the reason the model names for it, so the operations
//! that share a class cannot drift apart on its wording: the status precondition is the
//! same refusal whether an update or a cancel ran into it, and the length-of-time rule is
//! the same whether a shift is being started or re-expired.

use crate::ops::types::{ConflictException, ValidationException};

/// The message ARC answers when the shift a call names is no longer running (`CANCELED`,
/// or `EXPIRED` because its expiry time has passed).
///
/// One sentence for the whole class, with no variable part: ARC says the same thing to a
/// cancel and to an update, and names neither the shift nor the status it reached, so the
/// status token and the shift id stay out of the text. The shift the conflict is about is
/// carried by `ConflictException$zonalShiftId`.
pub const ZONAL_SHIFT_NOT_ACTIVE_MESSAGE: &str =
    "You can't update this zonal shift because it's no longer active";

/// The `ConflictExceptionReason` the model names for that precondition
/// (`smithy_query(query="shape", shape="ConflictExceptionReason")`).
pub const ZONAL_SHIFT_NOT_ACTIVE_REASON: &str = "ZonalShiftStatusNotActive";

/// The message ARC answers when a resource that already has an active customer-initiated
/// zonal shift is asked for another.
///
/// One sentence for the whole class, with no variable part: it speaks of "that resource",
/// the one the request already named, and of neither the shift that holds it nor the zone
/// either shift moves traffic away from. The shift already held is carried by
/// `ConflictException$zonalShiftId`.
pub const ACTIVE_ZONAL_SHIFT_EXISTS_MESSAGE: &str =
    "There's already an active zonal shift for that resource.";

/// The `ConflictExceptionReason` the model names for that conflict
/// (`smithy_query(query="shape", shape="ConflictExceptionReason")`).
pub const ZONAL_SHIFT_ALREADY_EXISTS_REASON: &str = "ZonalShiftAlreadyExists";

/// The message ARC answers when `awayFrom` does not name an Availability Zone the
/// resource is deployed in.
///
/// One sentence for the whole class, with no variable part: the zone the request asked to
/// move traffic away from is not restated, and neither is the resource or the set of zones
/// it is deployed in — which is also what keeps a refusal from describing a resource's
/// deployment to a caller.
pub const INVALID_AVAILABILITY_ZONE_MESSAGE: &str = "Invalid availability zone.";

/// The `ValidationExceptionReason` the model names for a zone the resource is not
/// deployed in (`smithy_query(query="shape", shape="ValidationExceptionReason")`): the
/// zone exists but is not one this shift can be moved away from.
pub const UNSUPPORTED_AZ_REASON: &str = "UnsupportedAz";

/// The message ARC answers when `expiresIn` is of the modelled form but names no length
/// of time a zonal shift can be active for.
///
/// `expiresIn`'s `@pattern` and `@length` are refused at the boundary before a handler
/// runs, so what is left for this class is the rule the DOCUMENTATION states and the model
/// does not: "You can set a zonal shift to be active initially for up to three days (72
/// hours)" (`StartZonalShiftRequest$expiresIn`). Like every other refusal of this service
/// it states the rule and nothing of the request, so the value the caller sent is not
/// echoed back.
pub const INVALID_EXPIRES_IN_MESSAGE: &str =
    "expiresIn must be a whole number of minutes (m) or hours (h), up to three days (72 hours).";

/// The `ValidationExceptionReason` the model names for a length of time a shift cannot be
/// active for (`smithy_query(query="shape", shape="ValidationExceptionReason")`).
pub const INVALID_EXPIRES_IN_REASON: &str = "InvalidExpiresIn";

/// The refusal a caller gets for acting on a shift that is no longer running.
///
/// `zonal_shift_id` is the shift the conflict is about, which the modelled
/// `ConflictException$zonalShiftId` carries — the message states the class alone.
#[must_use]
pub fn zonal_shift_not_active(zonal_shift_id: &str) -> ConflictException {
    ConflictException {
        message: ZONAL_SHIFT_NOT_ACTIVE_MESSAGE.to_string(),
        reason: ZONAL_SHIFT_NOT_ACTIVE_REASON.to_string(),
        zonal_shift_id: Some(zonal_shift_id.to_string()),
    }
}

/// The refusal a caller gets for starting a second zonal shift for a resource that
/// already has one.
///
/// `held_zonal_shift_id` is the shift the resource already has, carried by the modelled
/// `ConflictException$zonalShiftId` — the message states the class alone.
#[must_use]
pub fn active_zonal_shift_exists(held_zonal_shift_id: &str) -> ConflictException {
    ConflictException {
        message: ACTIVE_ZONAL_SHIFT_EXISTS_MESSAGE.to_string(),
        reason: ZONAL_SHIFT_ALREADY_EXISTS_REASON.to_string(),
        zonal_shift_id: Some(held_zonal_shift_id.to_string()),
    }
}

/// The refusal a caller gets for an `awayFrom` that is not one of the resource's
/// Availability Zones.
#[must_use]
pub fn invalid_availability_zone() -> ValidationException {
    ValidationException {
        message: INVALID_AVAILABILITY_ZONE_MESSAGE.to_string(),
        reason: UNSUPPORTED_AZ_REASON.to_string(),
    }
}

/// The refusal a caller gets for an `expiresIn` that names no length of time a zonal
/// shift can be active for — one past the documented maximum, or one this service cannot
/// turn into an expiry time at all, which is the same rule reached from either end.
#[must_use]
pub fn invalid_expires_in() -> ValidationException {
    ValidationException {
        message: INVALID_EXPIRES_IN_MESSAGE.to_string(),
        reason: INVALID_EXPIRES_IN_REASON.to_string(),
    }
}
