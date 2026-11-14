// SPDX-License-Identifier: CC0-1.0

//! The MFA CHALLENGE a mint presents, and what decides it: the device the account holds
//! under the serial a request names, the one-time pass codes that device answers, and the
//! refusal a challenge it does not answer earns.
//!
//! One concern, in one file, because every mint that can be MFA-gated decides it the same
//! way: `GetSessionToken` and `AssumeRole` both read the caller's device out of the IAM store
//! of the same engine ([`held_mfa_device`]) and both ask [`mfa_challenge_failure`] whether the
//! challenge the request presents is satisfied.

use super::*;

/// An MFA device the account holds, reduced to what an MFA challenge is decided by.
///
/// Read from the IAM store in the same engine ([`held_mfa_device`]), so a challenge is
/// decided against the devices the account actually holds rather than against anything
/// the request asserts.
#[derive(Debug, Clone)]
pub struct HeldMfaDevice {
    /// The serial number the device is addressed by — the value a request's
    /// `SerialNumber` names it as.
    pub serial_number: String,
    /// [`::service_com_amazonaws_iam_awsidentitymanagementv20100508::state::name_key`] of
    /// the IAM user the device is enabled for: the challenge is the CALLER's, so a device
    /// enabled for another user answers none of the caller's codes.
    pub user_key: String,
    /// What one-time pass codes this device answers, which is what a presented `TokenCode`
    /// is authenticated against.
    pub pass_codes: PassCodes,
}

impl HeldMfaDevice {
    /// Whether this device emits `token_code` at `now` — the proof a request presenting an
    /// MFA challenge has to carry.
    #[must_use]
    pub fn answers(&self, token_code: &str, now: SystemTime) -> bool {
        match &self.pass_codes {
            PassCodes::None => false,
            PassCodes::TimeBased(base32_string_seed) => {
                ::service_com_amazonaws_iam_awsidentitymanagementv20100508::state::virtual_mfa_device_answers(
                    base32_string_seed,
                    token_code,
                    now,
                )
            }
        }
    }
}

/// Whether an MFA device answers a one-time pass code at all, and what the codes it answers
/// are computed from.
///
/// `Debug` is written out rather than derived, so no formatter of a resolved device can print
/// the seed — the same treatment the IAM store's own device record gives it.
#[derive(Clone)]
pub enum PassCodes {
    /// A device that answers no one-time pass code: a FIDO security key authenticates by
    /// challenge and response, so no six-digit code presented against one is a code it emits.
    None,
    /// A virtual MFA device, which emits the time-based pass codes of the seed it was
    /// provisioned with ("the base32 seed", `VirtualMFADevice$Base32StringSeed`).
    TimeBased(String),
}

impl ::std::fmt::Debug for PassCodes {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::TimeBased(_) => f.write_str("TimeBased(..)"),
        }
    }
}

/// The MFA device the account holds under `serial_number`, or `None` when it holds none.
///
/// A READ of the IAM store, which holds the two kinds of device a serial number can name: a
/// FIDO security key of its own device registry, and a VIRTUAL MFA device `iam:EnableMFADevice`
/// enabled for a user — addressed, as the model says, by the device's ARN
/// (`VirtualMFADevice$SerialNumber`). A virtual device no user holds is enabled for nobody, so
/// it answers no caller's challenge.
pub fn held_mfa_device(iam: &IamState, serial_number: &str) -> Option<HeldMfaDevice> {
    if let Some(device) = iam.fido_security_key(serial_number) {
        return Some(HeldMfaDevice {
            serial_number: device.serial_number.clone(),
            user_key: device.user_key.clone(),
            pass_codes: PassCodes::None,
        });
    }
    let device = iam.virtual_mfa_device(serial_number)?;
    Some(HeldMfaDevice {
        serial_number: serial_number.to_string(),
        user_key: device.user_key.clone()?,
        pass_codes: PassCodes::TimeBased(device.base32_string_seed.clone()),
    })
}

/// The key the IAM store holds the user named by `arn` under, or `None` when `arn` is not
/// an IAM user's ARN — which an assumed-role or federated-user ARN is not, and no MFA
/// device is enabled for one.
pub fn iam_user_key(arn: &str) -> Option<String> {
    let named = ::service_com_amazonaws_iam_awsidentitymanagementv20100508::state::parse_entity_arn(
        arn,
    )?;
    matches!(
        named.kind,
        ::service_com_amazonaws_iam_awsidentitymanagementv20100508::state::EntityKind::User
    )
    .then(|| {
        ::service_com_amazonaws_iam_awsidentitymanagementv20100508::state::name_key(&named.name)
    })
}

/// Why an MFA challenge failed, and how AWS words each case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaChallengeFailure {
    /// The request named no device the code could be validated against: no serial number,
    /// or a serial number naming no MFA device enabled for the calling identity.
    SerialNotAssociated,
    /// A device of the calling identity answers that serial number, but not the code the
    /// request presented.
    InvalidPassCode,
}

impl MfaChallengeFailure {
    /// The sentence AWS refuses this case with — fixed text, carrying neither the serial
    /// number nor the code the request presented.
    ///
    /// Each is reproduced byte for byte, the padding AWS words them with included: the
    /// unassociated-serial sentence carries two spaces between its two sentences, and the
    /// invalid-code sentence ENDS in one. A client that tells an MFA-code rejection from
    /// every other `AccessDenied` on these operations — which carry no code of their own
    /// for it — compares that string, so a byte the emulator drops is a classification it
    /// loses.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::SerialNotAssociated => {
                "MultiFactorAuthentication failed, unable to validate MFA code.  Please verify \
                 your MFA serial number is valid and associated with this user."
            }
            Self::InvalidPassCode => {
                "MultiFactorAuthentication failed with invalid MFA one time pass code. "
            }
        }
    }
}

/// Decide the MFA challenge a request presents, against the device the account holds.
///
/// "MFA-enabled IAM users must call `GetSessionToken` and submit an MFA code that is
/// associated with their MFA device … an incorrect MFA code causes the API to return an
/// access denied error" (`GetSessionToken`, this service's model), and "if the role being
/// assumed requires MFA and if the `TokenCode` value is missing or expired, the
/// `AssumeRole` call returns an 'access denied' error"
/// (`AssumeRoleRequest$TokenCode`) — so a request that presents an MFA challenge is
/// authenticated against the device enabled for the CALLING identity, and `Some(..)` is
/// the refusal the caller gets instead of a credential.
///
/// `None` when the request presents no challenge at all (neither member), which is every
/// request of an identity no policy requires MFA of, and when it presents one the device
/// ANSWERS — the case a session is MFA-authenticated by. `device` is the record
/// [`held_mfa_device`] read for the serial the request named, and `now` the instant the
/// presented code is checked at.
///
/// Which codes a device answers is the device's own property ([`HeldMfaDevice::answers`]): a
/// virtual MFA device emits the time-based pass codes of the seed it was provisioned with,
/// while a FIDO security key authenticates by challenge and response and emits none, so no
/// code presented against one is a code it would answer.
pub fn mfa_challenge_failure(
    device: Option<&HeldMfaDevice>,
    identity: &Identity,
    serial_number: Option<&str>,
    token_code: Option<&str>,
    now: SystemTime,
) -> Option<MfaChallengeFailure> {
    let (serial_number, token_code) = match (serial_number, token_code) {
        // No challenge: nothing to validate, and nothing MFA-gated is claimed either.
        (None, None) => return None,
        (Some(serial_number), Some(presented)) => (serial_number, presented),
        // Half a challenge cannot be validated: a code with no device named to validate it
        // against, or a device named with no code to validate.
        _ => return Some(MfaChallengeFailure::SerialNotAssociated),
    };
    let enabled = device.filter(|device| {
        device.serial_number == serial_number
            && iam_user_key(&identity.arn).is_some_and(|user| user == device.user_key)
    });
    match enabled {
        // The account holds no device of this identity under that serial, which is what
        // the refusal tells the caller to check.
        None => Some(MfaChallengeFailure::SerialNotAssociated),
        // The serial IS this identity's, so what is validated is the CODE: the challenge is
        // satisfied exactly when the device emits the one presented.
        Some(device) => (!device.answers(token_code, now)).then_some(MfaChallengeFailure::InvalidPassCode),
    }
}
