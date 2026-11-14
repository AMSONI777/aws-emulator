// SPDX-License-Identifier: CC0-1.0

//! Receiving a SIGNAL at a published wait condition handle URL: the one write that URL
//! performs on this store.
//!
//! ## The rule this module implements
//!
//! An `AWS::CloudFormation::WaitConditionHandle` IS a pre-signed write target
//! ([`super::provisioning::wait_condition_handle`]), and what a client PUTs to it is a signal
//! document. That signal is a RESOURCE SIGNAL of the wait conditions declared with that
//! handle — the resources whose `Handle` property names it — so it is recorded exactly as a
//! client's own `SignalResource` call records one: keyed by the signalled resource and the
//! signal's `UniqueId` ([`StoredStack::record_signal`]), reported as an event on that
//! resource while the operation that waits is in flight, and counted towards the `Count` the
//! wait condition waits for ([`super::wait_conditions`]). A wait condition that now has the
//! success signals it waits for proceeds ([`StoredStack::release_wait_conditions`]).
//!
//! The `Data` a signal carries is what that wait condition publishes: "a JSON object that
//! contains the `UniqueId` and `Data` values from the wait condition signal(s) for the
//! specified wait condition", which `Fn::GetAtt` reads off it — so a landed signal leaves it
//! on the resource's own attributes, where every other `Fn::GetAtt` value of a stack's
//! resources is read from.
//!
//! The plane that receives the write is [`crate::service::wait_condition_plane`]; what a
//! released wait then owes the services that own the stack's resources is
//! [`super::provisioning::advance_stabilisations`]'s, which is the one place those calls can
//! be made from.
//!
//! ## Bounds
//!
//! The signal itself goes into the stack's own bounded log ([`super::MAX_SIGNALS_PER_STACK`]),
//! and what a signal may leave on a wait condition is bounded where the document is read
//! ([`super::provisioning::wait_condition_handle::MAX_SIGNAL_DATA_CHARS`]) and by
//! [`MAX_SIGNAL_DATA_ENTRIES`] entries — a client is what sends these, so nothing it sends
//! sizes this store.

use std::time::SystemTime;

use super::provisioning::wait_condition_handle::{
    self, HandleSignal, SignalTarget, SIGNAL_DATA_ATTRIBUTE,
};
use super::{ComAmazonawsCloudformationCloudformationState, StoredResource, StoredStack};

/// How many signals' `Data` one wait condition publishes: the same ceiling every other
/// resource's attribute set is held to
/// ([`super::template::MAX_ATTRIBUTES_PER_RESOURCE`]), since the object this builds is
/// exactly what `Fn::GetAtt` resolves against for this type.
pub const MAX_SIGNAL_DATA_ENTRIES: usize = super::template::MAX_ATTRIBUTES_PER_RESOURCE;

/// The property an `AWS::CloudFormation::WaitCondition` names its handle with: "a reference
/// to the wait condition handle used to signal this wait condition"
/// (`AWS::CloudFormation::WaitCondition`'s `Handle`), whose evaluated value is therefore the
/// URL that handle publishes.
pub const HANDLE_PROPERTY: &str = "Handle";

/// How a write to a published handle URL was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalOutcome {
    /// The signal RELEASED the wait the operation in flight was held at: that wait was short
    /// of the signals its `Count` asks for before this write and is not any longer, which is
    /// the one transition that makes the work behind it due. At most ONE write per operation
    /// can report it — the operation is no longer waiting for signals afterwards — so what a
    /// landed signal sets off is bounded by the operations a client started rather than by
    /// how many times anybody writes to the URL.
    Released,
    /// The signal is recorded and released nothing: a wait still short of its `Count`, one
    /// already satisfied, or a signal under a unique id already recorded.
    Recorded,
    /// The URL names no handle of a live stack of this store, or no wait condition of that
    /// stack is declared with it: nothing about the stack turns on this write.
    NothingAwaits,
}

impl ComAmazonawsCloudformationCloudformationState {
    /// The handle URL this service published for the handle `target` names, or `None` when it
    /// published none.
    ///
    /// What the plane holds an arriving write to: the published URL is the ONE address that
    /// handle is signalled at, so a write presenting another signature — or none — is a write
    /// to an address this service did not hand out. A target naming no handle of a live stack
    /// has no published URL, and such a write is accepted and recorded against nothing,
    /// exactly as a pre-signed `PUT` to a target nothing holds any longer is.
    pub fn published_handle_url(&self, region: &str, target: &SignalTarget) -> Option<String> {
        let stack = self.resolve(region, &target.stack_id)?;
        if !stack.is_live() {
            return None;
        }
        let published = stack
            .current_resources()
            .into_iter()
            .find(|resource| {
                resource.logical_id == target.logical_resource_id
                    && wait_condition_handle::is_handle(&resource.resource_type)
            })
            .map(|handle| handle.physical_resource_id)?;
        (!published.is_empty()).then_some(published)
    }

    /// Record one signal that arrived at a published handle URL.
    ///
    /// Addressed exactly as that URL addresses it: the stack and the handle it names. The
    /// signal is recorded for every wait condition of that stack whose `Handle` names the
    /// handle — a template may declare several waiting on one handle, and a signal to the
    /// handle is a signal to each of them — and a wait the signals now satisfy proceeds.
    ///
    /// `SignalOutcome::Released` is the one answer that says work is owed, and only the write
    /// that CHANGED the operation from waiting to not waiting gets it.
    pub fn record_handle_signal(
        &mut self,
        region: &str,
        target: &SignalTarget,
        signal: &HandleSignal,
        now: SystemTime,
    ) -> SignalOutcome {
        let Some(published) = self.published_handle_url(region, target) else {
            return SignalOutcome::NothingAwaits;
        };
        let Some(stack) = self.resolve_mut(region, &target.stack_id) else {
            return SignalOutcome::NothingAwaits;
        };
        let signalled = waiting_on_the_handle(stack, &published);
        if signalled.is_empty() {
            return SignalOutcome::NothingAwaits;
        }
        // Whether the operation in flight was HELD at one of its wait conditions before this
        // write: the half of the release that decides whether anything is owed. A write that
        // finds it already satisfied — or that nothing is waiting at — releases nothing,
        // however many of them arrive.
        let was_waiting = stack.waiting_for_signals();
        for logical_id in signalled {
            // Keyed by the signalled resource and the signal's unique id, so a write repeated
            // under one id is the same signal and not a second one — which is what lets a
            // client retry the `PUT` ([`StoredStack::record_signal`]).
            let first_time =
                stack.record_signal(&logical_id, &signal.unique_id, &signal.status, now);
            // The `Data` the signal carries is what the wait condition publishes against that
            // unique id, so it is recorded whether or not the signal itself is new: a retried
            // write carries the same document.
            if let Some(data) = &signal.data {
                record_signal_data(stack, &logical_id, &signal.unique_id, data);
            }
            if !first_time {
                continue;
            }
            report_the_signal(stack, &logical_id, signal, now);
        }
        // A wait condition the operation is waiting AT proceeds once the signals it waits for
        // have arrived: this is what makes the terminal status due, and it is a no-op while
        // any of the operation's wait conditions is short of its `Count`
        // ([`super::wait_conditions`]).
        let released = was_waiting && stack.release_wait_conditions(now);
        // ...and an OUTPUT built on what a wait condition publishes reports what the signals
        // left on it, so the outputs are evaluated again over the records as they now stand —
        // the same re-evaluation a resource whose identity its owning service minted gets
        // ([`StoredStack::reevaluate_outputs`]).
        if signal.data.is_some() {
            stack.reevaluate_outputs();
        }
        if released {
            SignalOutcome::Released
        } else {
            SignalOutcome::Recorded
        }
    }
}

/// The logical ids of the wait conditions of `stack` that are declared with the handle whose
/// published URL is `published`.
///
/// Read off the resources the stack has right now, whose `Handle` property carries the
/// EVALUATED reference — the URL the handle really publishes, which is what a declaration's
/// `{"Ref": "<handle>"}` resolves to.
fn waiting_on_the_handle(stack: &StoredStack, published: &str) -> Vec<String> {
    stack
        .current_resources()
        .into_iter()
        .filter(|resource| {
            resource.resource_type == super::wait_conditions::WAIT_CONDITION_TYPE
                && declared_handle(resource).as_deref() == Some(published)
        })
        .map(|resource| resource.logical_id)
        .collect()
}

/// The handle one wait condition's declaration names, as its evaluated properties carry it.
fn declared_handle(resource: &StoredResource) -> Option<String> {
    resource
        .properties
        .get(HANDLE_PROPERTY)
        .and_then(::serde_json::Value::as_str)
        .map(str::to_string)
}

/// Report one landed signal on the resource it was sent to, worded as every signal this
/// service records is ([`super::wait_conditions::signal_received`]).
///
/// Only while something is WAITING for it: "CloudFormation doesn't proceed with a stack
/// creation or update until resources receive the required number of signals", so a signal
/// that arrives while no operation of the stack is in flight is recorded and reported on
/// nothing, exactly as `SignalResource` records one.
fn report_the_signal(
    stack: &mut StoredStack,
    logical_id: &str,
    signal: &HandleSignal,
    now: SystemTime,
) {
    let in_flight = stack.pending.is_some()
        && matches!(
            stack.status.as_str(),
            super::status::CREATE_IN_PROGRESS | super::status::UPDATE_IN_PROGRESS
        );
    if !in_flight {
        return;
    }
    let updating = stack.status == super::status::UPDATE_IN_PROGRESS;
    let held = stack
        .current_resources()
        .into_iter()
        .find(|resource| resource.logical_id == logical_id);
    let physical_resource_id = held
        .as_ref()
        .map(|resource| resource.physical_resource_id.clone())
        .filter(|physical| !physical.is_empty());
    let resource_properties = held.as_ref().and_then(StoredResource::properties_blob);
    let resource_status = if updating {
        super::resource_status::UPDATE_IN_PROGRESS
    } else {
        super::resource_status::CREATE_IN_PROGRESS
    };
    let operation_id = stack
        .last_operation()
        .map(|operation| operation.operation_id.clone());
    let client_request_token = stack.client_request_token.clone();
    stack.record_resource_event(
        now,
        logical_id,
        physical_resource_id,
        super::wait_conditions::WAIT_CONDITION_TYPE,
        resource_status,
        Some(super::wait_conditions::signal_received(
            &signal.status,
            &signal.unique_id,
        )),
        resource_properties,
        operation_id,
        client_request_token,
    );
}

/// Record the `Data` one signal carried on the wait condition it was sent to, under the
/// signal's own unique id.
///
/// The attribute is the JSON object the type publishes ([`SIGNAL_DATA_ATTRIBUTE`]), built
/// from the object already in force so every signal's data is reported beside the others, and
/// bounded at [`MAX_SIGNAL_DATA_ENTRIES`] entries.
fn record_signal_data(stack: &mut StoredStack, logical_id: &str, unique_id: &str, data: &str) {
    for resource in resources_in_force(stack) {
        if resource.logical_id != logical_id {
            continue;
        }
        let mut published = resource
            .attributes
            .get(SIGNAL_DATA_ATTRIBUTE)
            .and_then(|held| ::serde_json::from_str::<::serde_json::Value>(held).ok())
            .and_then(|held| match held {
                ::serde_json::Value::Object(entries) => Some(entries),
                _ => None,
            })
            .unwrap_or_default();
        if !published.contains_key(unique_id) && published.len() >= MAX_SIGNAL_DATA_ENTRIES {
            continue;
        }
        published.insert(
            unique_id.to_string(),
            ::serde_json::Value::String(data.to_string()),
        );
        resource.attributes.insert(
            SIGNAL_DATA_ATTRIBUTE.to_string(),
            ::serde_json::Value::Object(published).to_string(),
        );
    }
}

/// Every resource record of the stack a write may MATERIALISE something on: the ones the
/// operation in flight is about to install while it is still in flight, else the ones its
/// last completed operation left — the same set [`StoredStack::current_resources`] reports,
/// reached mutably.
fn resources_in_force(stack: &mut StoredStack) -> Vec<&mut StoredResource> {
    match &mut stack.pending_deployment {
        Some(deployment) => deployment.resources.iter_mut().collect(),
        None => stack
            .resources
            .iter_mut()
            .map(|deployed| &mut deployed.resource)
            .collect(),
    }
}
