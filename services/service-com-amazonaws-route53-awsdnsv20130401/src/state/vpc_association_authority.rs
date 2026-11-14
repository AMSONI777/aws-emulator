// SPDX-License-Identifier: CC0-1.0

//! WHO may associate the VPC a request names with a private hosted zone, and the sentence
//! the service refuses a caller that may not with.
//!
//! `AssociateVPCWithHostedZone`'s own documentation states the permission the association
//! needs: "If you want to associate a VPC that was created by using one Amazon Web Services
//! account with a private hosted zone that was created by using a different account, the
//! Amazon Web Services account that created the private hosted zone must first submit a
//! CreateVPCAssociationAuthorization request. Then the account that created the VPC must
//! submit an AssociateVPCWithHostedZone request." So a VPC the calling account CREATED is
//! associable on its own, and a VPC it did not create is associable only while the zone
//! carries an authorization for exactly that VPC. Everything else is the association the
//! model carries a refusal of its own for — `NotAuthorizedException`, "Associating the
//! specified VPC with the specified hosted zone has not been authorized" (HTTP 401) — and
//! nothing about the zone changes.
//!
//! Neither half of the decision is invented here; each is read from the store that OWNS it:
//!
//! * which VPCs the account created is a fact of its Amazon EC2 inventory, the one
//!   `DescribeVpcs` answers from ([`super::account_vpcs`]);
//! * which VPCs a zone authorizes is the zone's own authorization list, the one
//!   `CreateVPCAssociationAuthorization` writes to, `DeleteVPCAssociationAuthorization`
//!   removes from and `ListVPCAssociationAuthorizations` reports
//!   ([`super::StoredZone::vpc_authorization_position`]) — so withdrawing an authorization
//!   closes the permission it opened, without any second record to disagree with it.
//!
//! WHO the caller is comes from the same source `sts:GetCallerIdentity` answers from — the
//! session registry in the SAME shared engine, keyed by the access key id the request was
//! signed with — so the principal a refusal blames is the principal the caller reads back
//! for its own credentials, never a name spelled out here. It is resolved BEFORE this
//! service's store is locked, exactly as [`super::account_vpcs`] and
//! [`super::monitored_alarm`] are: no handler holds two services' locks at once.

use std::time::SystemTime;

use ::service_com_amazonaws_sts_awssecuritytokenservicev20110615::state as sts_state;

/// The IAM service prefix this service's actions carry (`route53:AssociateVPCWithHostedZone`).
///
/// It is this service's ARN namespace — `smithy_query(query="service_info")` ->
/// `awsService.arnNamespace` — so the action a refusal names is the one a policy grants.
const ACTION_PREFIX: &str = "route53";

/// The service segment of an Amazon VPC's ARN: a VPC is an Amazon EC2 resource, so the
/// resource a Route 53 association is refused ON belongs to that service's namespace, not
/// to this one's.
const VPC_ARN_SERVICE: &str = "ec2";

/// The resource kind of an Amazon VPC ARN (`arn:aws:ec2:<region>:<account>:vpc/<id>`).
const VPC_ARN_RESOURCE_KIND: &str = "vpc";

/// The sentence Route 53 refuses an association the caller is not authorized to make with
/// (`NotAuthorizedException`, HTTP 401).
///
/// Built wholly from the REQUEST and the caller's identity: the principal that signed it,
/// the action it performs — `operation` is the operation's own name, so the action is the
/// one a policy would have to allow — and the VPC it names, as the ARN that VPC is
/// addressed by in the Region the request said it was created in. A client reads the
/// principal and the resource out of it to decide whether to ask the zone's account for an
/// authorization or to fail closed.
pub fn not_authorized_message(
    caller_arn: &str,
    operation: &str,
    vpc_id: &str,
    vpc_region: &str,
) -> String {
    let resource = ::engine::emulator_arn(
        VPC_ARN_SERVICE,
        vpc_region,
        &format!("{VPC_ARN_RESOURCE_KIND}/{vpc_id}"),
    );
    format!(
        "User: {caller_arn} is not authorized to perform: {ACTION_PREFIX}:{operation} on \
         resource: {resource}"
    )
}

/// The ARN of the principal THIS request speaks for, as `sts:GetCallerIdentity` reports it.
///
/// One resolution of the request's access key id — the token service's own — so the
/// principal a refusal blames is the principal the caller reads as itself: a credential
/// that registry minted speaks for the session it was minted for, a long-term key speaks
/// for the IAM user that holds it, and a key no store holds a record of (the position the
/// credential this emulator publishes at start is in) speaks for the account's own
/// principal. A session the clock has expired speaks for nobody, and resolves to the
/// long-term identity instead; materialising that expiry is a write the clock already owed.
///
/// An engine carrying no session registry at all can hold no session, so the only identity
/// a request can present there is the one its long-term key resolves to.
pub fn caller_arn<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
) -> String {
    let access_key_id = ::engine::extract_akid(&ctx.parts().headers);
    let long_term = long_term_identity(engine, &access_key_id);
    let Some(registry) = sts_state::service_state(engine) else {
        return long_term.arn;
    };
    let resolved = sts_state::resolve_request_caller(
        &mut registry.lock(),
        &access_key_id,
        SystemTime::now(),
        ctx.credential_store(),
        long_term.clone(),
    )
    .map(|caller| caller.identity);
    resolved.unwrap_or(long_term).arn
}

/// The identity a LONG-TERM access key speaks for: the token service's OWN resolution of
/// such a key against the account's IAM records — the user the account holds the key for,
/// and, for a key no IAM record names, the account's own principal.
///
/// Called rather than reproduced, so a caller reading its identity through
/// `sts:GetCallerIdentity` and a caller reading the principal this service blamed see one
/// ARN.
fn long_term_identity<Eng: Send + Sync + 'static>(
    engine: &Eng,
    access_key_id: &str,
) -> sts_state::Identity {
    let iam = sts_state::iam_state(engine);
    let guard = iam.as_ref().map(|iam| iam.lock());
    sts_state::long_term_identity(guard.as_deref(), access_key_id)
}
