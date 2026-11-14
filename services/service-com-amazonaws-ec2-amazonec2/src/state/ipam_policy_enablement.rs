// SPDX-License-Identifier: CC0-1.0

//! Which IPAM policy of the account is ENABLED: the one record `EnableIpamPolicy` writes,
//! `DisableIpamPolicy` clears and `GetEnabledIpamPolicy` reports.
//!
//! Split out of the [`crate::state`] module root so each file holds one concern, and
//! re-exported from it, so a handler reaches these as `crate::state::<item>` like every
//! other primitive there. The POLICIES themselves are a store of their own
//! ([`ComAmazonawsEc2Amazonec2State::ipam_policies`], whose section of the module root holds
//! their ids, states and refusal codes): a policy is a resource with an id, while being
//! enabled is one fact about the account.
//!
//! There is at most ONE such fact, because `GetEnabledIpamPolicy` reports a single
//! `IpamPolicyId` for the caller: the account has one enabled policy or none, so enabling a
//! second policy replaces the first rather than adding to it.
//!
//! An enablement also records the Organizations target it was made for, when one was named:
//! "This parameter is required only when IPAM is integrated with Amazon Web Services
//! Organizations. When IPAM is not integrated with Amazon Web Services Organizations, omit
//! this parameter and the policy will apply to the current account"
//! (`EnableIpamPolicyRequest$OrganizationTargetId`) — which is exactly the difference the
//! `IpamPolicyManagedBy` enum names, so [`EnabledIpamPolicyRecord::managed_by`] reads it off
//! that one stored fact rather than from anything a reader decides.

use super::*;

/// The `IpamPolicyManagedBy` enum's `delegated-administrator-for-ipam` member: an enablement
/// made for an entity within Amazon Web Services Organizations rather than by the account for
/// itself, which is what naming an `OrganizationTargetId` means
/// (`EnableIpamPolicyRequest$OrganizationTargetId`).
///
/// The enum's other member is `account`, which this crate already spells once
/// ([`MANAGED_BY_ACCOUNT`]); the whole generated catalog is
/// [`crate::ops::types::IPAM_POLICY_MANAGED_BY_VALUES`], so neither word is spelled twice.
pub const IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR: &str =
    "delegated-administrator-for-ipam";

/// The account's enabled IPAM policy: which policy, and the Organizations target the
/// enablement was made for.
///
/// Not the modelled `IpamPolicy` shape, because nothing here is a copy of the policy — the
/// policy itself lives once in [`ComAmazonawsEc2Amazonec2State::ipam_policies`] and this
/// record only names it, so the two cannot disagree about one policy's state, ARN or tags.
#[derive(Debug, Clone)]
pub struct EnabledIpamPolicyRecord {
    /// The `IpamPolicyId` of the enabled policy — a key of
    /// [`ComAmazonawsEc2Amazonec2State::ipam_policies`].
    pub ipam_policy_id: String,
    /// "The ID of the Amazon Web Services Organizations target for which to enable the IPAM
    /// policy" (`EnableIpamPolicyRequest$OrganizationTargetId`), or `None` for an enablement
    /// the account made for itself.
    pub organization_target_id: Option<String>,
}

impl EnabledIpamPolicyRecord {
    /// "The entity that manages the IPAM policy" (`GetEnabledIpamPolicyResult$ManagedBy`), as
    /// a member of the modelled `IpamPolicyManagedBy` catalog.
    ///
    /// An enablement that names an Organizations target was made by the delegated
    /// administrator for IPAM applying the policy to an entity of the organization
    /// ([`IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR`]); one that names none is the
    /// account's own ([`MANAGED_BY_ACCOUNT`]) — "omit this parameter and the policy will
    /// apply to the current account" (`EnableIpamPolicyRequest$OrganizationTargetId`).
    pub fn managed_by(&self) -> &'static str {
        if self.organization_target_id.is_some() {
            IPAM_POLICY_MANAGED_BY_DELEGATED_ADMINISTRATOR
        } else {
            MANAGED_BY_ACCOUNT
        }
    }

    /// Whether this enablement is the one a request naming `policy_id` and
    /// `organization_target_id` asks about — the PAIR, because the same policy can be enabled
    /// for the account itself or for an entity of its organization and those are different
    /// enablements.
    pub fn is_for(&self, policy_id: &str, organization_target_id: Option<&str>) -> bool {
        self.ipam_policy_id == policy_id
            && self.organization_target_id.as_deref() == organization_target_id
    }
}

/// The bytes one stored enablement holds: the Organizations target id it carries, the only
/// caller-chosen text in it.
///
/// The ONE definition of that charge, the way [`ipam_policy_payload_bytes`] is for a policy.
/// The policy id it names is this service's own ([`IPAM_POLICY_ID_PREFIX`]) and the record
/// is a single slot rather than a stored resource, so nothing else about it is charged.
pub fn ipam_policy_enablement_payload_bytes(record: &EnabledIpamPolicyRecord) -> usize {
    record
        .organization_target_id
        .as_deref()
        .map_or(0, str::len)
}

impl ComAmazonawsEc2Amazonec2State {
    /// The enablement the account holds right now, or `None` when no policy of it is enabled.
    ///
    /// A policy whose deletion has been asked for is not a policy in service — it is one
    /// `DeleteIpamPolicy` refuses a second delete of, in `delete-in-progress` or
    /// `delete-complete` ([`IpamPolicyRecord::is_deleting`]) — so an enablement naming it
    /// reports nothing enabled. A pure READ: the stale row is left where it is, so two
    /// callers reading either side of this see the same thing.
    pub fn enabled_ipam_policy(&self) -> Option<&EnabledIpamPolicyRecord> {
        let held = self.enabled_ipam_policy.as_ref()?;
        let policy = self.ipam_policies.get(&held.ipam_policy_id)?;
        (!policy.is_deleting()).then_some(held)
    }

    /// Enable the policy `policy_id` names for `organization_target_id` (the account itself
    /// when it names none), replacing whatever was enabled before, and answer the
    /// `IpamPolicyId` the store now holds as enabled.
    ///
    /// The id is answered out of the stored record rather than echoed from the request, so
    /// the enable reports exactly what `GetEnabledIpamPolicy` will.
    ///
    /// The target id is caller-chosen text, charged to the store's budget like every other
    /// byte it retains; the enablement this one replaces gives its bytes back, so at most one
    /// target id is ever held.
    pub fn enable_ipam_policy(
        &mut self,
        policy_id: &str,
        organization_target_id: Option<&str>,
    ) -> String {
        let released = self
            .enabled_ipam_policy
            .as_ref()
            .map_or(0, ipam_policy_enablement_payload_bytes);
        let record = EnabledIpamPolicyRecord {
            ipam_policy_id: policy_id.to_string(),
            organization_target_id: organization_target_id.map(str::to_string),
        };
        let charged = ipam_policy_enablement_payload_bytes(&record);
        let enabled_id = record.ipam_policy_id.clone();
        self.enabled_ipam_policy = Some(record);
        self.release_stored_bytes(released);
        self.add_stored_bytes(charged);
        enabled_id
    }

    /// Clear the enablement of `policy_id` for `organization_target_id`, and answer whether
    /// there was one to clear.
    ///
    /// Only the enablement the request NAMES is cleared ([`EnabledIpamPolicyRecord::is_for`]),
    /// so disabling one policy can never turn off another, and only an enablement
    /// [`Self::enabled_ipam_policy`] reports is one there is to clear — the two cannot
    /// disagree about whether a policy is enabled.
    pub fn disable_ipam_policy(
        &mut self,
        policy_id: &str,
        organization_target_id: Option<&str>,
    ) -> bool {
        if !self
            .enabled_ipam_policy()
            .is_some_and(|held| held.is_for(policy_id, organization_target_id))
        {
            return false;
        }
        let released = self
            .enabled_ipam_policy
            .as_ref()
            .map_or(0, ipam_policy_enablement_payload_bytes);
        self.enabled_ipam_policy = None;
        self.release_stored_bytes(released);
        true
    }
}
