// SPDX-License-Identifier: CC0-1.0

//! The identity ONE hand-over of a notification to a subscribed queue is made under: this
//! service's own principal ([`super::SNS_SERVICE_PRINCIPAL`]), acting for the topic the
//! message was published to.
//!
//! A notification handed to a subscribed endpoint is the fan-out of a publish — made by this
//! service on behalf of the topic — and not a request the endpoint's owner made of its own
//! service. The serving service has to be able to tell the two apart, because what it accepts
//! from a CLIENT is not the same question as what another service hands it on behalf of one of
//! its own resources.
//!
//! WHICH credential the hand-over presents is what says so, exactly as it does for every other
//! cross-service call an emulated service makes as its own service principal
//! ([`::service_common::service_principal_calls`]): a credential minted in the emulator's own
//! credential store for the one call, recorded in the shared directory under this service's
//! principal and the topic's ARN, and forgotten — with the credential deleted — as soon as the
//! call returns. The access key id a call presents is the one thing about a request a client
//! cannot choose for itself, so the serving service reads the record for that key id alone.
//!
//! Where no such credential can be minted — an engine carrying no directory, a store that
//! minted no secret, a directory already holding as many in-flight calls as it records — the
//! hand-over is made with the callback's own credentials instead: the narrower identity, and
//! the one every queue that does not ask who is calling already took.

use ::service_common::service_principal_calls::{ServicePrincipalCall, ServicePrincipalCalls};

use super::SNS_SERVICE_PRINCIPAL;

/// How long a record of one in-flight hand-over stays readable.
///
/// What ENDS a record is [`InFlightDelivery`] being dropped, which happens on every path out
/// of the hand-over; the deadline is the floor that bounds a record nothing dropped (see
/// [`::service_common::service_principal_calls`]). It sits well past one in-process call, so a
/// record can never expire while the queue's own handler is still deciding the call.
const IN_FLIGHT_RECORD_SLACK: ::std::time::Duration = ::std::time::Duration::from_secs(60);

/// The shared directory of in-flight service-principal calls, in the one shared engine:
/// written here and read by the service serving the hand-over.
///
/// `None` for an engine carrying no such directory, which is evidence of nothing: the
/// hand-over is then made with the callback's own credentials.
pub(super) fn in_flight_calls<Eng: Send + Sync + 'static>(
    engine: &Eng,
) -> Option<::engine::ServiceState<ServicePrincipalCalls>> {
    (engine as &dyn ::std::any::Any)
        .downcast_ref::<::engine::InMemoryEngine>()
        .map(::engine::InMemoryEngine::state::<ServicePrincipalCalls>)
}

/// One hand-over's own credential and in-flight record, held for as long as that hand-over is
/// being made.
///
/// Dropping it forgets the record and DELETES the credential, so the identity the call was
/// made under exists only while the queue's service is answering it: a credential nothing
/// holds can sign nothing, and a record nothing holds decides nothing.
pub(super) struct InFlightDelivery<'ctx> {
    directory: ::engine::ServiceState<ServicePrincipalCalls>,
    credentials: &'ctx ::emulator_server::CredentialStore,
    /// The access key id the call presents, which the directory holds its record under.
    access_key_id: String,
    /// The secret that key signs with.
    secret_access_key: String,
}

impl InFlightDelivery<'_> {
    /// The credentials the hand-over signs with: the pair this record was minted for.
    pub(super) fn credentials(&self) -> ::aws_sdk_sqs::config::Credentials {
        ::aws_sdk_sqs::config::Credentials::new(
            self.access_key_id.clone(),
            self.secret_access_key.clone(),
            None,
            None,
            SNS_SERVICE_PRINCIPAL,
        )
    }
}

impl Drop for InFlightDelivery<'_> {
    fn drop(&mut self) {
        self.directory.lock().forget(&self.access_key_id);
        let _ = self.credentials.delete(&self.access_key_id);
    }
}

/// Mint the credential ONE hand-over is made under and record, under its access key id, that
/// this is a call of [`SNS_SERVICE_PRINCIPAL`] acting for the topic `topic_arn` names.
///
/// `None` where the call cannot be made as the principal at all, in which case the caller
/// makes the ordinary in-process call instead (see the module docs).
pub(super) fn as_the_service_principal<'ctx>(
    ctx: &'ctx smithy_server_runtime::OperationContext<'_>,
    directory: Option<&::engine::ServiceState<ServicePrincipalCalls>>,
    topic_arn: &str,
) -> Option<InFlightDelivery<'ctx>> {
    let directory = directory?.clone();
    let minted = ctx
        .credential_store()
        .create(&::emulator_server::aws_credentials::AWS_ACCESS_KEY);
    let secret_access_key = minted
        .secret(::emulator_server::aws_credentials::SECRET_ACCESS_KEY)
        .map(str::to_string);
    let now = ::std::time::SystemTime::now();
    let recorded = secret_access_key.is_some()
        && directory.lock().remember(
            minted.id.clone(),
            ServicePrincipalCall {
                principal: SNS_SERVICE_PRINCIPAL.to_string(),
                // The resource the hand-over is made ON BEHALF OF: the topic whose publish
                // this notification is the fan-out of.
                source_arn: topic_arn.to_string(),
                source_account: ::engine::emulator_account_id().to_string(),
                expires_at: now + IN_FLIGHT_RECORD_SLACK,
            },
            now,
        );
    match secret_access_key.filter(|_| recorded) {
        Some(secret_access_key) => Some(InFlightDelivery {
            directory,
            credentials: ctx.credential_store(),
            access_key_id: minted.id.clone(),
            secret_access_key,
        }),
        None => {
            let _ = ctx.credential_store().delete(&minted.id);
            None
        }
    }
}
