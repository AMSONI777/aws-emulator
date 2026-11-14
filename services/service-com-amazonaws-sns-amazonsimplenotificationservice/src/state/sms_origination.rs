// SPDX-License-Identifier: CC0-1.0

//! Whether this account has anything to send an SMS message FROM.
//!
//! An SMS message leaves AWS from an ORIGINATION ENTITY — a short code, a toll-free
//! number, a ten-digit long code or another sender identity the account holds. The
//! inventory of the account's DEDICATED entities lives in
//! [`super::ComAmazonawsSnsAmazonsimplenotificationserviceState::origination_numbers`],
//! is acquired OUT OF BAND (no SNS API adds one, as
//! [`super::OriginationNumberRecord`] sets out) and is therefore EMPTY unless something
//! put a number there — which is what `ListOriginationNumbers` reports.
//!
//! An account holding no dedicated entity is not an account that cannot be sent to: the
//! one-time password of an SMS sandbox verification is sent by AWS itself, so
//! `CreateSMSSandboxPhoneNumber` is judged on its own input and on the sandbox rather
//! than on this inventory.
//!
//! This module holds what the inventory's records MEAN, so the reading does not depend
//! on which call asked.

/// The capability an origination entity has to carry for SNS to send an SMS message
/// from it: `SMS`, one of the values the modelled `NumberCapability` enum accepts
/// (`crate::ops::types::NUMBER_CAPABILITY_VALUES`). A number that can only place a
/// voice call or carry MMS cannot send a text message.
pub const SMS_CAPABILITY: &str = "SMS";
