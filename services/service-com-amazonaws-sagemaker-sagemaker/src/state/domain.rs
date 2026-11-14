// SPDX-License-Identifier: CC0-1.0

//! The STUDIO DOMAIN slice of this service's state: the domain `CreateDomain` writes,
//! `DescribeDomain` replays and `ListDomains` pages over, with its ARN kind, its id
//! mint, its Studio address, its statuses, the clock span it moves on, its store bound
//! and the sentence its not-found refusal is worded with.
//!
//! Its own file, like the other resource slices here, so the parent module stays inside
//! the project's file-length limit. Every name is re-exported from [`super`], so a
//! handler keeps naming `crate::state::…`.

use super::*;
use crate::ops::types::{DefaultSpaceSettings, DomainSettings, UserSettings};

/// The ARN resource kind a domain carries, i.e. the `<kind>` in [`resource_arn`]. Fixed
/// by `DomainArn`'s modelled pattern
/// (`^arn:aws[a-z\-]*:sagemaker:[a-z0-9\-]*:[0-9]{12}:domain/`), and named once here so
/// the create and every reader mint and match the same ARN.
pub const DOMAIN_ARN_KIND: &str = "domain";

/// See [`MODEL_QUOTA`]. Bounds the domain store the same way, and is what `CreateDomain`
/// answers `ResourceLimitExceeded` past, so a caller creating domain after domain cannot
/// grow the store without end.
pub const DOMAIN_QUOTA: usize = 1_000;

/// `DomainStatus`'s members a domain of this emulator moves through. The modelled enum
/// also carries the update, delete and failure states, which no implemented operation
/// reaches yet.
pub const DOMAIN_STATUS_PENDING: &str = "Pending";
/// See [`DOMAIN_STATUS_PENDING`].
pub const DOMAIN_STATUS_IN_SERVICE: &str = "InService";
/// See [`DOMAIN_STATUS_PENDING`]. The terminal status a domain whose provisioning could not
/// complete settles in — a placement the account's network does not admit
/// ([`crate::state::domain_network`]) — beside the `FailureReason` that states why.
pub const DOMAIN_STATUS_FAILED: &str = "Failed";

/// How long after `CreateDomain` the clock owes the `Pending` -> `InService` transition.
///
/// Three seconds, so a caller that describes or lists the domain straight after creating
/// it still observes `Pending`, and one that waits observes `InService`. Real SageMaker
/// takes minutes to provision a Studio domain; the span is compressed, never zero, and
/// the due instant is stored rather than slept on ([`Domain::settle_status`]).
pub const DOMAIN_IN_SERVICE_AFTER: Duration = Duration::from_secs(3);

/// The page `ListDomains` serves when the request names no `MaxResults`: its
/// `MaxResults` doc says "The default value for MaxResults is 10". [`MAX_PAGE_SIZE`]
/// still caps the page above it, as it does for every listing here.
pub const DOMAIN_DEFAULT_PAGE_SIZE: i32 = 10;

/// `AppNetworkAccessType`'s documented default: "Specifies the VPC used for non-EFS
/// traffic. The default value is PublicInternetOnly."
pub const DEFAULT_APP_NETWORK_ACCESS_TYPE: &str = "PublicInternetOnly";

/// `HomeEfsFileSystemCreation`'s documented default: "Indicates whether to create a home
/// EFS file system for the domain. Defaults to Enabled."
pub const DEFAULT_HOME_EFS_FILE_SYSTEM_CREATION: &str = "Enabled";

/// `TagPropagation`'s documented default: "Indicates whether custom tag propagation is
/// supported for the domain. Defaults to DISABLED."
pub const DEFAULT_TAG_PROPAGATION: &str = "DISABLED";

/// A fresh `DomainId`: `d-` and the twelve lowercase characters the modelled `DomainId`
/// pattern admits after it (`^d-(-*[a-z0-9]){1,61}$`).
///
/// The caller never supplies it — a domain is addressed by the id SageMaker mints, so the
/// id is the server's to generate and is derived from nothing in the request. Same scheme
/// as every other id in this crate ([`mint_short_id`]), whose digits are lowercase hex
/// and so inside this pattern's alphabet.
pub fn mint_domain_id() -> String {
    format!("d-{}", mint_short_id())
}

/// Where the Studio domain `domain_id` is served in `region`: the host SageMaker gives
/// one Studio domain, which `CreateDomain`, `DescribeDomain` and `ListDomains` all report
/// as the domain's `Url`.
///
/// Derived from the domain's own id and the Region the caller signed for, so it is stable
/// across reads and distinct per domain — the same way [`notebook_instance_url`] gives one
/// notebook instance its host.
pub fn studio_domain_url(region: &str, domain_id: &str) -> String {
    format!("https://{domain_id}.studio.{region}.sagemaker.aws")
}

/// How the domain operations state a `DomainId` this account holds no domain under: the
/// entity, then the ARN the requested id resolves to in the Region the request signed for
/// IN SQUARE BRACKETS, then `does not exist` — the sentence the Studio family of
/// resources words this fact with (see [`app_image_config_not_found`]), carrying no
/// closing period.
///
/// Stated once here so the reader and whichever update or delete resolves the same id
/// later cannot word the one fact differently.
pub fn domain_not_found(region: &str, domain_id: &str) -> String {
    format!(
        "Domain [{}] does not exist",
        resource_arn(region, DOMAIN_ARN_KIND, domain_id)
    )
}

/// A Studio domain created by `CreateDomain`, as `DescribeDomain` replays it and
/// `ListDomains` summarises it.
///
/// `in_service_due_at` is the instant the clock owes this domain its move out of
/// `Pending` — into `InService`, or into [`DOMAIN_STATUS_FAILED`] where the create
/// resolved a placement the account's network does not admit; it is stored, never slept
/// on, and materialised by whichever reporting call first runs at or after it
/// ([`Domain::settle_status`]).
///
/// The members the request did not carry stay `None`: the model documents a default for
/// `AppNetworkAccessType`, `HomeEfsFileSystemCreation` and `TagPropagation` only, so
/// those three are resolved ONCE here on the write path and every other optional member
/// is reported exactly as the create sent it rather than as a value nobody asked for.
/// `tags` is stored so a later `ListTags` reports what the create carried.
#[derive(Debug, Clone)]
pub struct Domain {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub url: String,
    pub auth_mode: String,
    pub default_user_settings: UserSettings,
    pub domain_settings: Option<DomainSettings>,
    pub default_space_settings: Option<DefaultSpaceSettings>,
    pub subnet_ids: Option<Vec<String>>,
    pub vpc_id: Option<String>,
    pub kms_key_id: Option<String>,
    pub home_efs_file_system_kms_key_id: Option<String>,
    pub app_network_access_type: String,
    pub app_security_group_management: Option<String>,
    pub home_efs_file_system_creation: String,
    pub tag_propagation: String,
    pub status: String,
    /// Why this domain is in a failure status, i.e. the `FailureReason` a reader reports
    /// beside the status. `None` until the clock settles a domain whose provisioning could
    /// not complete, because only a domain in a failure status has a reason to report.
    pub failure_reason: Option<String>,
    /// Why this domain's provisioning will NOT complete, as the create resolved it against
    /// the account's own network ([`crate::state::domain_network_failure_reason`]), or `None`
    /// for a placement that holds together. Kept apart from [`Domain::failure_reason`]
    /// because it is what the clock still owes the domain rather than what the domain
    /// already reports: the create is served and the domain is `Pending` either way, and
    /// this decides WHICH status [`Domain::settle_status`] materialises.
    pub creation_failure_reason: Option<String>,
    pub tags: Vec<Tag>,
    pub creation_time: SystemTime,
    pub last_modified_time: SystemTime,
    pub in_service_due_at: SystemTime,
}

impl Domain {
    /// Materialise the transition out of `Pending` the clock already owes, the way
    /// [`Endpoint::settle_status`] does for an endpoint: it was due at `in_service_due_at`
    /// whether or not anybody read the domain, so the observer makes no difference to the
    /// result, and `LastModifiedTime` moves to the instant the transition was due rather
    /// than to "now".
    ///
    /// WHICH status it lands in is what the create already resolved: `InService` for a
    /// domain whose provisioning completes, and [`DOMAIN_STATUS_FAILED`] with the
    /// `FailureReason` beside it for one whose placement the account's network does not
    /// admit ([`Domain::creation_failure_reason`]).
    ///
    /// Answers whether the transition happened on this call, so the caller can record it.
    pub fn settle_status(&mut self, now: SystemTime) -> bool {
        if self.status == DOMAIN_STATUS_PENDING && now >= self.in_service_due_at {
            self.last_modified_time = self.in_service_due_at;
            // What the create resolved about the domain's placement decides WHICH status the
            // clock owed: a domain whose network the account does not admit fails with the
            // reason that create recorded, and never comes up.
            if let Some(reason) = self.creation_failure_reason.clone() {
                self.status = DOMAIN_STATUS_FAILED.to_string();
                self.failure_reason = Some(reason);
                return true;
            }
            self.status = DOMAIN_STATUS_IN_SERVICE.to_string();
            return true;
        }
        false
    }
}

impl ComAmazonawsSagemakerSagemakerState {
    /// Whether another domain fits, i.e. the store is below [`DOMAIN_QUOTA`].
    pub fn domains_below_quota(&self) -> bool {
        self.domains.len() < DOMAIN_QUOTA
    }
}
