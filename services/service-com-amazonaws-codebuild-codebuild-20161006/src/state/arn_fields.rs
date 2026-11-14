// SPDX-License-Identifier: CC0-1.0

//! The FIELDS of an ARN an operation that addresses a resource by ARN is handed, and the
//! FIRST one of them that cannot be read.
//!
//! An ARN is `arn:<partition>:<service>:<region>:<account>:<resource>`, and the fields
//! are read in that order: the field a refusal names is the first one that is not well
//! formed, so a value whose region field cannot be a Region name is refused ON THE
//! REGION and the resource behind it is never examined at all. The refusal states which
//! field is at fault and quotes THAT FIELD's value out of the request, which is what
//! tells a caller repairing an ARN which segment to fix — unlike the fixed sentences the
//! resource-kind refusals carry ([`super::INVALID_TOKEN_ARN_MESSAGE`] and the ones
//! beside it), which are reached only once every field before the resource reads.
//!
//! This is one rule for every operation of this service whose input is an ARN, so the
//! field order and the wording cannot drift from one of them to the next.

use super::ARN_NAMESPACE;

/// Whether `value` NAMES an AWS Region.
///
/// Asked against the catalogue of Region codes the workspace already carries
/// (`emulator_telemetry::policy::KNOWN_REGIONS`, "every AWS region the wire may carry",
/// already a dependency of this crate) rather than a second copy of that list here. It is
/// a CATALOGUE and not a shape rule because a value written like a Region code but naming
/// no Region (`us-east-9`) is not a Region at all: an ARN carrying it is malformed, where
/// an ARN carrying a real Region is merely one this account holds no record in.
///
/// Whether this emulator SERVES that Region is still a different question: a Region in the
/// catalogue resolves to nothing rather than being refused, which is what keeps a
/// well-formed ARN of another partition a lookup miss.
pub fn is_region_name(value: &str) -> bool {
    ::emulator_telemetry::policy::KNOWN_REGIONS.contains(&value)
}

/// The REGION field of `arn` — the fourth of its six colon-separated fields — or `None`
/// when the value does not have an ARN's six fields.
///
/// The counterpart of [`super::arn_account`] for the field read before it, and read the
/// same way: walked field by field, so nothing is allocated. The field is handed back as
/// written, empty field included — an ARN naming no Region names no regional resource of
/// any Region — so the question "is this field a Region name" ([`is_region_name`]) and the
/// question "is it the Region this request is signed for" are both answered by the caller.
pub fn arn_region(arn: &str) -> Option<&str> {
    let mut fields = arn.splitn(6, ':');
    if fields.next()? != "arn" {
        return None;
    }
    // The partition and the service, then the region.
    fields.next()?;
    fields.next()?;
    let region = fields.next()?;
    // The account and the resource must be PRESENT for the value to be an ARN at all.
    fields.next()?;
    fields.next()?;
    Some(region)
}

/// The region field of `arn` when that field is the FIRST field of the ARN that cannot
/// be read, or `None` when it reads.
///
/// Every field BEFORE the region has to read for the region to be the first one at
/// fault: the literal `arn`, a non-empty partition and this service's own namespace. The
/// account and the resource fields must be PRESENT — a value with fewer than the six
/// fields of an ARN is no ARN at all, so no single field of it is the one at fault — but
/// they are not read here, because they come after the region.
///
/// Walked field by field rather than collected, so reading an ARN allocates nothing.
fn invalid_arn_region(arn: &str) -> Option<&str> {
    let mut fields = arn.splitn(6, ':');
    if fields.next()? != "arn" || fields.next()?.is_empty() || fields.next()? != ARN_NAMESPACE {
        return None;
    }
    let region = fields.next()?;
    fields.next()?;
    fields.next()?;
    (!is_region_name(region)).then_some(region)
}

/// What CodeBuild states as the reason the REGION field of an ARN it was handed is not a
/// Region, carried by the modelled `InvalidInputException`.
///
/// Recorded behaviour; the model states no message for the error. The fixed text is
/// `Invalid ARN: region ` and ` is invalid`, and the one variable part is the region
/// field taken verbatim out of the ARN in the request — the field the caller has to
/// repair, which a fixed sentence could not point at.
pub fn invalid_arn_region_message(region: &str) -> String {
    format!("Invalid ARN: region {region} is invalid")
}

/// The sentence an operation addressing a resource by ARN refuses `arn` with when its
/// region field is the first field at fault, or `None` when the refusal belongs to a
/// later field.
///
/// The one call site shape for every such operation: it is asked BEFORE the resource
/// field is read, so an ARN whose region cannot be a Region is never refused for the
/// resource kind behind it.
pub fn arn_region_violation(arn: &str) -> Option<String> {
    invalid_arn_region(arn).map(invalid_arn_region_message)
}
