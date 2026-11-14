// SPDX-License-Identifier: CC0-1.0

//! WHO a request to a cluster's Kubernetes API server speaks for.
//!
//! An IAM principal reaches a cluster's Kubernetes API with a bearer token it builds
//! out of its own AWS credential — the `k8s-aws-v1.` token a kubeconfig's
//! credential plugin produces, which carries a presigned
//! `sts:GetCallerIdentity` request — and the cluster maps that principal to a
//! Kubernetes identity through its ACCESS ENTRIES: `AccessEntry$username` is "the
//! name of a user that can authenticate to your cluster" and
//! `AccessEntry$kubernetesGroups` "the value of `kubernetesGroups` is a list of
//! Kubernetes groups that the principal is a member of". So the username and the
//! groups a request is authorized and audited under are the ENTRY's, never anything
//! derived from the request's own text.
//!
//! Which IAM principal the credential speaks for is the same question
//! `sts:GetCallerIdentity` answers, resolved from the same registries
//! ([`super::request_caller_principal_arn`] answers it for a control-plane call):
//! the session the access key id was minted for — a role session speaks for its
//! ROLE, the permanent principal an access entry can be filed under — else the IAM
//! user that holds the long-term key, else the credential this emulator publishes at
//! start. A request that presents no credential at all therefore speaks for that
//! published credential's principal, exactly as an unsigned call to any other
//! emulated service does; this service never checks a signature, which is the
//! emulator's own authentication layer's work.
//!
//! A principal NO access entry of the cluster names authenticates as nobody, and is
//! answered the `401 Unauthorized` the API server answers a credential it cannot map.

use super::kubernetes_objects::ApiRefusal;
use super::kubernetes_rbac::{AccessPolicyGrant, SubjectIdentity};
use super::ComAmazonawsEksAwswesleyfrontendState as ServiceStore;
use ::service_com_amazonaws_sts_awssecuritytokenservicev20110615::state as sts_store;
use ::std::time::SystemTime;

/// The prefix the bearer token of an EKS kubeconfig carries, and the version of that
/// token this API server reads.
const EKS_BEARER_TOKEN_PREFIX: &str = "k8s-aws-v1.";

/// The scheme a bearer token is presented under in the `Authorization` header.
const BEARER_SCHEME: &str = "Bearer ";

/// The registries that answer which IAM principal an access key id speaks for, held
/// for as long as the cluster's API address is open.
///
/// They are the stores of the OTHER services in the same shared engine — the session
/// registry STS writes and the users and roles IAM holds — so the API server resolves
/// a credential against the very records `sts:AssumeRole` and `iam:CreateUser` wrote,
/// and an emulator that mounts neither resolves every credential to the published
/// one.
#[derive(Clone)]
pub struct ApiServerPrincipals {
    sessions: Option<::engine::ServiceState<sts_store::StsState>>,
    identities: Option<::engine::ServiceState<sts_store::IamState>>,
}

/// Written by hand rather than derived: what is diagnosable is whether the registries
/// are there at all, not what they hold.
impl ::std::fmt::Debug for ApiServerPrincipals {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter
            .debug_struct("ApiServerPrincipals")
            .field("sessions", &self.sessions.is_some())
            .field("identities", &self.identities.is_some())
            .finish()
    }
}

impl ApiServerPrincipals {
    /// The registries in `engine`.
    #[must_use]
    pub fn of<Eng: Send + Sync + 'static>(engine: &Eng) -> Self {
        Self {
            sessions: sts_store::service_state(engine),
            identities: sts_store::iam_state(engine),
        }
    }

    /// The ARN of the IAM principal the access key id `access_key_id` speaks for,
    /// and `None` for a credential that speaks for nobody — one naming a session
    /// whose window has run out.
    ///
    /// Reading only: no session is minted, moved or pruned here — a request to a
    /// cluster's API server is not what expires a credential. Call it with no store
    /// of THIS service held: it takes the other services' locks.
    #[must_use]
    pub fn principal_arn(&self, access_key_id: &str, now: SystemTime) -> Option<String> {
        // A request that presents NO credential names no session and no key any
        // registry holds, so it speaks for the identity this emulator publishes and
        // neither of the other services' stores is asked at all: the common request on
        // this address does not queue behind their locks.
        if access_key_id == no_credential_key_id() {
            return Some(sts_store::long_term_identity(None, access_key_id).arn);
        }
        if let Some(sessions) = &self.sessions {
            let store = sessions.lock();
            if let Some(session) = store.session(access_key_id) {
                if session.is_expired(now) {
                    // The credential named a session that has run out: it speaks for
                    // nobody rather than for the identity behind it.
                    return None;
                }
                // "The temporary security credentials … have the permissions of the
                // role": the permanent principal behind a role session is that role,
                // and the role is what an access entry is filed under.
                return Some(
                    session
                        .role_arn
                        .clone()
                        .unwrap_or_else(|| session.identity.arn.clone()),
                );
            }
        }
        let identity = match &self.identities {
            Some(identities) => {
                sts_store::long_term_identity(Some(&identities.lock()), access_key_id)
            }
            None => sts_store::long_term_identity(None, access_key_id),
        };
        Some(identity.arn)
    }
}

/// The access key id the `Authorization` header of a Kubernetes API request presents,
/// and `None` for a header this server cannot read a credential out of at all.
///
/// The token is `k8s-aws-v1.` followed by the base64url form of a presigned
/// `sts:GetCallerIdentity` URL, so the credential it was built from is the one that
/// URL's own SigV4 credential scope names — read through the SAME readers every
/// service in this tree reads them with: `service_common::jwt::decode_base64url` for
/// the segment, the one base64url codec of this workspace, and
/// `service_common::request_access_key_id` for the scope, so a token and a presigned
/// call resolve to one credential.
///
/// A request carrying NO `Authorization` header presents no credential, which reads as
/// the sentinel that reader answers for an unsigned request — the identity an unsigned
/// call to any other emulated service is served as. A header that IS there but carries
/// no credential this server can read — another scheme, a token of another version, a
/// segment that is not base64url, a URL with no credential scope — is answered
/// `None`, which the caller turns into the `401 Unauthorized` the API server answers a
/// credential it cannot map: a presented token that reads as nothing is not the same
/// thing as presenting none.
#[must_use]
pub fn presented_access_key_id(authorization: Option<&str>) -> Option<String> {
    let Some(header) = authorization else {
        return Some(no_credential_key_id());
    };
    let token = header
        .strip_prefix(BEARER_SCHEME)
        .and_then(|token| token.trim().strip_prefix(EKS_BEARER_TOKEN_PREFIX))?;
    let url = ::service_common::jwt::decode_base64url(token)
        .and_then(|bytes| String::from_utf8(bytes).ok())?;
    let (parts, ()) = ::http::Request::builder()
        .uri(url)
        .body(())
        .ok()?
        .into_parts();
    let access_key_id = ::service_common::request_access_key_id(&parts);
    // The scope the presigned URL carries, and nothing when it carries none: that URL
    // is the whole credential the token presents.
    (access_key_id != no_credential_key_id()).then_some(access_key_id)
}

/// What [`presented_access_key_id`] answers for a request that presents no
/// credential: the sentinel the one reader answers for a request carrying none,
/// taken from that reader rather than restated here.
fn no_credential_key_id() -> String {
    let (parts, ()) = ::http::Request::new(()).into_parts();
    ::service_common::request_access_key_id(&parts)
}

/// The Kubernetes identity the cluster keyed `key` maps the IAM principal
/// `principal_arn` to, or the `401 Unauthorized` a principal the cluster maps to
/// nobody is answered with.
pub fn authenticate(
    store: &ServiceStore,
    key: &(String, String),
    principal_arn: &str,
) -> Result<SubjectIdentity, ApiRefusal> {
    let entry = store
        .clusters
        .get(key)
        .and_then(|record| record.access_entries.get(principal_arn))
        .ok_or_else(ApiRefusal::unauthorized)?;
    let grants = entry
        .associated_policies
        .values()
        .filter_map(|association| {
            Some(AccessPolicyGrant {
                policy_name: super::access_policy_name(&association.policy_arn)?.to_string(),
                namespaces: (association.scope_type == super::ACCESS_SCOPE_TYPE_NAMESPACE)
                    .then(|| association.namespaces.clone()),
            })
        })
        .collect();
    Ok(SubjectIdentity {
        username: entry.username.clone(),
        groups: SubjectIdentity::authenticated_groups(&entry.kubernetes_groups),
        grants,
    })
}
