// SPDX-License-Identifier: CC0-1.0

//! Whether a send is a DELIVERY another AWS service is handing a queue as its own service
//! principal, on behalf of one of its own resources, rather than a `SendMessage` request a
//! client made of Amazon SQS.
//!
//! The distinction matters because the two are not the same request. `MaximumMessageSize` is
//! "the limit of how many bytes a message can contain before Amazon SQS rejects it"
//! (`SetQueueAttributes$Attributes`) — a bound on what this service's own API accepts from the
//! sender that calls it, which is why `SendMessage` refuses a body past it with
//! `InvalidParameterValue`. A notification Amazon SNS fans out to a subscribed queue, or any
//! other delivery a service makes for a resource of its own, is not such a request: the
//! sending service accepted the payload under ITS OWN limits and hands the queue the result,
//! so the queue's request bound does not bound it and a client that lowers the attribute does
//! not silently change what the fan-out delivers.
//!
//! WHICH credential the call presents is what says so, and nothing a client can set: the
//! sending service mints a credential in the emulator's own credential store for the one call
//! and records, under that credential's access key id, the principal it is calling as and the
//! resource it is calling for ([`::service_common::service_principal_calls`], the one shared
//! directory in the engine). This reads that record back for the access key id the call
//! presents — the id the emulator's verifier checks the signature against — and only for a call
//! of the account this service serves. A call the directory holds no live record for is an
//! ordinary client request, judged by every rule the API publishes.

use std::time::SystemTime;

/// The service principal a NOTIFICATION FAN-OUT into a queue is made as: Amazon SNS handing a
/// message published to a topic to each queue subscribed to it, which is the principal a queue
/// policy names to grant that delivery (`sqs:SendMessage` for `sns.amazonaws.com`).
///
/// The ONE principal this service treats a hand-over of: a rule about what a client's own
/// request may carry is relaxed only for the delivery path whose recorded behaviour says so, so
/// an in-flight call of any other service principal is decided like any other request.
pub const NOTIFICATION_FAN_OUT_PRINCIPAL: &str = "sns.amazonaws.com";

/// Whether this request is the notification fan-out of a published message rather than a send a
/// client asked this service for: a delivery recorded as a call of
/// [`NOTIFICATION_FAN_OUT_PRINCIPAL`] acting for the topic it was published to.
#[must_use]
pub fn is_a_notification_fan_out<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
) -> bool {
    delivering_service(engine, ctx)
        .is_some_and(|delivery| delivery.principal == NOTIFICATION_FAN_OUT_PRINCIPAL)
}

/// One delivery a service is making as its own service principal.
#[derive(Debug, Clone)]
pub struct ServiceDelivery {
    /// The service principal the delivery is made as (`sns.amazonaws.com`).
    pub principal: String,
    /// `aws:SourceArn`: the resource the delivery is made on behalf of — the topic a
    /// notification was published to.
    pub source_arn: String,
}

/// The service DELIVERING this message as its own service principal, or `None` for every
/// other request: one whose access key id the shared directory holds no live record of, one
/// recorded for another account, and one on an engine carrying no such directory.
///
/// LOCKING: this takes the directory's lock and no other, so a handler may ask it while
/// holding this service's own store guard.
#[must_use]
pub fn delivering_service<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
) -> Option<ServiceDelivery> {
    let directory = in_flight_service_principal_calls(engine)?;
    let access_key_id = ::engine::extract_akid(&ctx.parts().headers);
    let held = directory.lock();
    let call = held.call(
        &access_key_id,
        ::engine::emulator_account_id(),
        SystemTime::now(),
    )?;
    Some(ServiceDelivery {
        principal: call.principal.clone(),
        source_arn: call.source_arn.clone(),
    })
}

/// The shared directory of the cross-service calls another service is making as its own
/// service principal, in the one shared engine: written by that service, read here.
fn in_flight_service_principal_calls<Eng: Send + Sync + 'static>(
    engine: &Eng,
) -> Option<
    ::engine::ServiceState<::service_common::service_principal_calls::ServicePrincipalCalls>,
> {
    (engine as &dyn ::std::any::Any)
        .downcast_ref::<::engine::InMemoryEngine>()
        .map(
            ::engine::InMemoryEngine::state::<
                ::service_common::service_principal_calls::ServicePrincipalCalls,
            >,
        )
}
