// SPDX-License-Identifier: CC0-1.0

//! Whether the CALLING PRINCIPAL may read the Amazon S3 object a request addresses BY
//! REFERENCE — the question answered before the object behind a `TemplateURL`, a
//! `StackPolicyURL` or any other reference is fetched.
//!
//! ## The rule this module implements
//!
//! A reference says WHERE a document is, and CloudFormation goes and reads it: "CloudFormation
//! uses the credentials you provide" for that read, so the object is fetched AS THE CALLER and
//! not with permissions of the service's own. A principal that may not read the object
//! therefore cannot submit it either — the fetch is refused, and the operation is refused with
//! it, before a stack, a change set or a policy is written. That is the whole of what this
//! module decides; [`super::template_url`] words the refusal, because what CloudFormation
//! reports for a read Amazon S3 would not serve is the same sentence whichever reason that
//! read was not served for.
//!
//! The three pieces, each held in exactly one place:
//!
//! 1. **who** — the principal the request's access key id speaks for, read from the SAME
//!    place `sts:GetCallerIdentity` answers from (`sts_store::resolve_request_caller`, over
//!    the long-term identity `sts_store::long_term_identity` resolves an IAM user's own key
//!    to), so the principal judged is the one the caller reads back for the credentials it
//!    signed with;
//! 2. **what it may do** — the identity-based policy documents in force on that principal and
//!    the permissions boundary that caps them, read through the IAM service's OWN accessors
//!    (`principal_policies`, `permissions_boundary_document`), where the collection rule
//!    lives — so a policy `iam:PutUserPolicy` wrote takes effect on the next request and
//!    deleting it lifts it again;
//! 3. **the decision** — [`::service_common::iam_authorization`], the tree's ONE evaluation of
//!    those documents against `(action, resource)`, so this service and the service that owns
//!    the object cannot answer differently about the same documents.
//!
//! WHICH action is asked about is the one the read itself needs: `s3:GetObject` for the
//! current version of an object and `s3:GetObjectVersion` for a reference that names a
//! version, which is a permission of its own. The resource is the ARN of the object the
//! reference addressed, built from the bucket and key the URL named — never resolved out of a
//! store, so the decision is the same whether or not the object is there and a refusal tells
//! an unauthorized caller nothing about what the account holds.
//!
//! ## The callers this decision cannot refuse
//!
//! * **The account's own published credential.** A request whose access key id neither STS nor
//!   IAM holds a record for speaks for the account itself — the position AWS account root
//!   credentials are in, which no identity-based policy bounds. This is also what every
//!   in-process call another emulated service makes presents.
//! * **A principal holding an attachment this emulator cannot read.** An AWS-managed policy is
//!   owned by AWS rather than by the account, so the account's store holds no document for it;
//!   refusing on a grant this emulator cannot see would deny a read AWS permits. An explicit
//!   `Deny` in a document that CAN be read still refuses.
//! * **An engine carrying no IAM store**, where no identity can hold a policy at all.
//!
//! An expired session credential speaks for nobody: it carries no document, so the read it
//! asks for is refused.
//!
//! ## What one decision costs
//!
//! The work is bounded by what IAM holds for ONE principal and does not grow with the request:
//! that principal's inline policies, the managed policies attached to it and — for a user —
//! the groups it belongs to, each collected once by IAM's own accessor and read once by the
//! shared evaluator. It is taken with no store of this service locked and writes nothing to
//! either store it reads.

use std::time::SystemTime;

use ::service_com_amazonaws_sts_awssecuritytokenservicev20110615::state as sts_store;
use ::service_common::iam_authorization::{self as iam, Decision};

/// The IAM action reading the CURRENT version of one object asks for: "you must have the
/// `s3:GetObject` permission" (`GetObject`'s own documentation of the permissions a read
/// needs).
const GET_OBJECT: &str = "s3:GetObject";

/// The action a read that names an object VERSION asks for instead: "if you include a
/// `versionId` in your request header, you must have the `s3:GetObjectVersion` permission …
/// The `s3:GetObject` permission is not required in this scenario" (`GetObject`) — so a
/// reference carrying `?versionId=` is decided on THIS action and a reference without one on
/// [`GET_OBJECT`].
const GET_OBJECT_VERSION: &str = "s3:GetObjectVersion";

/// Whether the account's IAM records show the calling principal may NOT read `object`.
///
/// `true` is the one answer that refuses a reference: the documents in force deny the read, or
/// none of them grants it and the caller is not one this decision cannot bound (see the module
/// docs). `false` is every other case, the ones where nothing establishes that the read would
/// be refused.
///
/// Asked with NO store of this service locked, and before the object is read.
pub fn read_is_unauthorized<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    object: &super::template_url::Object,
) -> bool {
    let action = if object.version.is_some() {
        GET_OBJECT_VERSION
    } else {
        GET_OBJECT
    };
    let resource = object_arn(&object.bucket, &object.key);
    let caller = caller(engine, ctx);
    // An identity-based document states no `Principal` element, so the decision rests on the
    // action and the resource the reference addressed.
    let request = iam::Request::new(action, &resource, &[]);
    let said = iam::identity_decision(&caller.documents, &request);
    // IAM's order: an explicit `Deny` in a document that CAN be read refuses the read whatever
    // else the principal carries; otherwise a grant is needed, which a caller this decision
    // does not bound has by definition; and a grant is capped by the permissions boundary,
    // since "a permissions boundary sets the maximum permissions that an identity-based policy
    // can grant" (IAM, permissions boundaries).
    if said == Decision::Denied {
        return true;
    }
    if !(iam::is_allowed(said, Decision::NotStated) || caller.identity_is_unbounded()) {
        return true;
    }
    let Some(boundary) = caller.boundary.as_ref() else {
        return false;
    };
    iam::identity_decision(::std::slice::from_ref(boundary), &request) != Decision::Allowed
}

/// The ARN of the object `key` in `bucket`: `arn:aws:s3:::<bucket>/<key>`.
///
/// An Amazon S3 ARN carries no Region and no account segment — "because Amazon S3 bucket names
/// are global, you don't specify the AWS Region or account ID" — so the bucket name opens the
/// resource field and the key follows it, which is how a policy statement names one object.
fn object_arn(bucket: &str, key: &str) -> String {
    format!("arn:aws:s3:::{bucket}/{key}")
}

/// The principal a request speaks for, and everything the decision is made from.
#[derive(Debug, Clone, Default)]
struct Caller {
    /// The identity-based policy documents in force on the principal.
    documents: Vec<String>,
    /// The permissions boundary in force on it, when it carries one whose document this
    /// emulator holds.
    boundary: Option<String>,
    /// Set when this request presents the account's own published credential, which holds no
    /// IAM policies (see the module docs).
    account_credential: bool,
    /// Set when the principal has a policy attached whose document the IAM store does not hold
    /// — an AWS-managed policy (see the module docs).
    unreadable_attachment: bool,
    /// Set when this engine carries NO IAM store, where no identity can hold a policy at all,
    /// so nothing could be read about what this caller may do (see the module docs).
    no_identity_records: bool,
}

impl Caller {
    /// Whether nothing this decision found can refuse the caller once no readable document
    /// DENIES the read: the account's own credential, which holds no IAM policies, a principal
    /// carrying a grant this emulator cannot read, or an engine holding no identity records at
    /// all.
    fn identity_is_unbounded(&self) -> bool {
        self.account_credential || self.unreadable_attachment || self.no_identity_records
    }
}

/// The principal this request speaks for, with the identity-based policies in force on it.
///
/// Resolving the caller goes through STS's own resolution, which materialises the session
/// expiries the clock has already made due before it answers: that write is owed at the same
/// instant whether or not anybody called.
fn caller<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
) -> Caller {
    let access_key_id = ::engine::extract_akid(&ctx.parts().headers);
    let iam = sts_store::iam_state(engine);
    // A LONG-TERM access key speaks for the IAM user that holds it — the map `iam:GetUser`
    // resolves a caller through — and a key no store holds is the account's own published
    // credential.
    let long_term = match &iam {
        Some(iam) => sts_store::long_term_identity(Some(&iam.lock()), &access_key_id),
        None => sts_store::ambient_identity(),
    };
    let resolved = match sts_store::service_state(engine) {
        Some(sts) => sts_store::resolve_request_caller(
            &mut sts.lock(),
            &access_key_id,
            SystemTime::now(),
            ctx.credential_store(),
            long_term.clone(),
        )
        .map(|caller| {
            (
                caller.identity.arn.clone(),
                // WHOSE identity-based documents are in force for this credential is not
                // always the principal it speaks for: the role behind an assumed-role session,
                // the IAM user behind a federated-user session, read through STS's one answer
                // for it.
                caller.identity_policies_arn().to_string(),
            )
        }),
        // No STS store on this engine: the credential names no session, so it speaks for the
        // long-term identity it was resolved to and is judged on that identity's documents.
        None => Ok((long_term.arn.clone(), long_term.arn.clone())),
    };
    // An expired session credential speaks for nobody: it carries no document, so the read it
    // asks for is refused.
    let Ok((arn, policies_arn)) = resolved else {
        return Caller::default();
    };
    let mut caller = Caller {
        account_credential: arn == sts_store::ambient_identity().arn,
        ..Caller::default()
    };
    let Some(iam) = iam else {
        // No IAM store on this engine: no identity can hold a policy at all, so there is
        // nothing to read about what this caller may do and nothing withholds the read.
        caller.no_identity_records = true;
        return caller;
    };
    let held = iam.lock();
    // The documents are IAM's OWN collection of what an identity carries — its inline policies,
    // the documents of the policies attached to it and, for a user, its groups' — called rather
    // than re-derived, so this decision reads exactly what IAM itself judges that principal on.
    if let Some(policies) = held.principal_policies(&policies_arn) {
        caller.documents = policies.documents;
        // An attachment the collection resolved no document for is an entry of AWS's own
        // catalog this emulator does not carry: a grant it cannot read.
        caller.unreadable_attachment = !policies.uncarried.is_empty();
    }
    caller.boundary = held.permissions_boundary_document(&policies_arn);
    caller
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What one stored document says about reading one object, through the shared evaluator
    /// this decision consults.
    fn decision(document: &str, action: &str, bucket: &str, key: &str) -> Decision {
        iam::identity_decision(
            &[document.to_string()],
            &iam::Request::new(action, &object_arn(bucket, key), &[]),
        )
    }

    /// RULE: the read is decided on the ARN of the object the reference addressed, so a grant
    /// scoped to one prefix of one bucket covers the objects under it and nothing else.
    #[test]
    fn a_grant_is_read_for_the_object_the_reference_addressed() {
        let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::staging/templates/*"}]}"#;
        // (case, bucket, key, allowed)
        let rows: &[(&str, &str, &str, bool)] = &[
            ("the granted prefix", "staging", "templates/main.json", true),
            (
                "a nested key under it",
                "staging",
                "templates/nested/child.json",
                true,
            ),
            ("another prefix of the bucket", "staging", "other.json", false),
            ("another bucket", "elsewhere", "templates/main.json", false),
        ];
        for (case, bucket, key, expected) in rows {
            let said = decision(document, GET_OBJECT, bucket, key);
            let actual = iam::is_allowed(said, Decision::NotStated);
            assert_eq!(
                actual, *expected,
                "case {case:?}: expected allowed == {expected}, got {actual} ({said:?})"
            );
        }
    }

    /// RULE: naming a VERSION asks for `s3:GetObjectVersion`, which a grant of `s3:GetObject`
    /// alone does not cover.
    #[test]
    fn a_versioned_read_asks_for_its_own_action() {
        let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Action":"s3:GetObject","Resource":"*"}]}"#;
        let current = decision(document, GET_OBJECT, "staging", "main.json");
        assert_eq!(
            current,
            Decision::Allowed,
            "case \"the current version\": expected Allowed, got {current:?}"
        );
        let versioned = decision(document, GET_OBJECT_VERSION, "staging", "main.json");
        assert_eq!(
            versioned,
            Decision::NotStated,
            "case \"a named version\": expected the grant to state nothing, got {versioned:?}"
        );
    }

    /// RULE: an explicit `Deny` is final, whatever else the principal carries.
    #[test]
    fn an_explicit_deny_wins_over_a_wildcard_grant() {
        let document = r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"s3:*","Resource":"*"},
            {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::staging/*"}]}"#;
        let denied = decision(document, GET_OBJECT, "staging", "main.json");
        assert_eq!(
            denied,
            Decision::Denied,
            "case \"the denied bucket\": expected Denied, got {denied:?}"
        );
        let allowed = decision(document, GET_OBJECT, "elsewhere", "main.json");
        assert_eq!(
            allowed,
            Decision::Allowed,
            "case \"a bucket the deny does not name\": expected Allowed, got {allowed:?}"
        );
    }
}
