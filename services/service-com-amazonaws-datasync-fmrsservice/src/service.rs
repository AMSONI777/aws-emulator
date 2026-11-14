// SPDX-License-Identifier: CC0-1.0

//! The `com-amazonaws-datasync-fmrsservice` service: how it claims requests and how it words the
//! failures the framework hands back.
//!
//! EDIT THIS FILE. It is emitted once with working defaults and is never
//! regenerated, so a choice made here survives adding another service or
//! re-running the generator.
//!
//! `EmulatedService` is what the router mounts (`EmulatedService::new(engine)`).
//! It wraps the generated [`ServiceDefinition`], which carries the model-derived half
//! of this service — its identity, its wire protocol, and its operation routing
//! table — built from the Smithy model at compile time. You do not edit the
//! entry; you edit the behavioral seams below.
//!
//! Five opt-in seams are yours to change; every one defaults to the framework's
//! own behaviour, so an unedited service still routes and answers correctly:
//!
//! - `can_handle` — which requests this service claims. The default matches the
//!   request's resolved route key against this service's signing name. Edit it
//!   for anything the model does not express: a signing name shared by several
//!   services, or routing that keys on the access-key id.
//! - `override_operation` — serve a request the model's routing key cannot name
//!   correctly. The default returns `None`, so every request resolves through the
//!   generated routing table. Return `Some(op)` to route one yourself.
//! - `override_refusal` — how this service words a request the framework refused
//!   before any handler ran. The default returns `None`, keeping the framework's
//!   wording. See the inline note on that method for how to reword.
//! - `override_routing_error` — how this service words a request that reached it
//!   but named no modeled operation. The default returns `None`, so the entry
//!   renders the protocol-correct default (query -> 400 InvalidAction, awsJson ->
//!   404, …). Return `Some(resp)` to answer in your own envelope if desired.
//! - `override_framework_error` — how this service words a transport-level
//!   failure the orchestrator detects up front (e.g. a malformed `aws-chunked`
//!   body). The default returns `None`, keeping the entry's protocol-correct
//!   rendering. Return `Some(resp)` to reword it if desired.
//!
//! The model-derived half of this service — its identity, wire protocol, routing
//! table, and the default error renderers — lives in the generated `ServiceDefinition`
//! and is reached, not edited, through the one `definition` method below. You
//! do not write it; editing the entry would let this file drift from the model.

pub mod refusal;

use smithy_server_runtime::{
    http, ErasedOperation, OperationRoutingTable, Refusal, Refused, Service,
};
use std::sync::Arc;

use refusal::StatingItsOwnRefusals;

/// Wire one `crate::ops::<module>::<Operation>` per line into `table`, each wrapped in
/// [`StatingItsOwnRefusals`] and keyed by its operation shape name — the routing key
/// `ServerHttpProtocol::routing_key` resolves and the generated table is keyed by.
macro_rules! wrap_operations {
    ($table:expr, $engine:expr, $($module:ident :: $operation:ident),+ $(,)?) => {
        $(
            $table.add_operation(
                stringify!($operation),
                ::std::boxed::Box::new(StatingItsOwnRefusals::new(
                    crate::ops::$module::$operation::new(::std::sync::Arc::clone(&$engine)),
                )) as ::std::boxed::Box<dyn ErasedOperation>,
            );
        )+
    };
}

/// The `com-amazonaws-datasync-fmrsservice` emulated service: the generated [`ServiceDefinition`] plus
/// the behavioral seams this file owns.
///
/// Generic over the engine type `Eng` so this file names no concrete engine; the
/// router builds one shared engine and hands it to `new`.
pub struct EmulatedService<Eng: Send + Sync + 'static> {
    entry: crate::ServiceDefinition<Eng>,
    /// The same modelled operations the generated table holds, each wrapped in
    /// [`StatingItsOwnRefusals`]. Keyed by the routing key the protocol resolves — the key
    /// the generated table uses — and built from the SAME shared engine, so a wrapped
    /// operation reads and writes the one store. Held on the service because
    /// [`Service::override_operation`] hands back a borrow of `self`.
    stating_its_own_refusals: OperationRoutingTable,
}

impl<Eng: Send + Sync + 'static> EmulatedService<Eng> {
    /// Build this service from the shared engine. The engine is threaded into the
    /// generated [`ServiceDefinition`], which constructs each operation from it; the
    /// operation's behaviour lives in that operation's own `impl Operation`.
    pub fn new(engine: Arc<Eng>) -> Self {
        // EVERY modelled operation is wrapped, rather than the few whose refusals a
        // report happens to name: how this service words a refused request is a fact
        // about the service, so an operation left out would word one refusal class two
        // ways depending on which operation was called.
        let mut stating_its_own_refusals = OperationRoutingTable::new();
        wrap_operations!(
            stating_its_own_refusals,
            engine,
            cancel_task_execution::CancelTaskExecution,
            create_agent::CreateAgent,
            create_location_azure_blob::CreateLocationAzureBlob,
            create_location_efs::CreateLocationEfs,
            create_location_fsx_lustre::CreateLocationFsxLustre,
            create_location_fsx_ontap::CreateLocationFsxOntap,
            create_location_fsx_open_zfs::CreateLocationFsxOpenZfs,
            create_location_fsx_windows::CreateLocationFsxWindows,
            create_location_hdfs::CreateLocationHdfs,
            create_location_nfs::CreateLocationNfs,
            create_location_object_storage::CreateLocationObjectStorage,
            create_location_s3::CreateLocationS3,
            create_location_smb::CreateLocationSmb,
            create_task::CreateTask,
            delete_agent::DeleteAgent,
            delete_location::DeleteLocation,
            delete_task::DeleteTask,
            describe_agent::DescribeAgent,
            describe_location_azure_blob::DescribeLocationAzureBlob,
            describe_location_efs::DescribeLocationEfs,
            describe_location_fsx_lustre::DescribeLocationFsxLustre,
            describe_location_fsx_ontap::DescribeLocationFsxOntap,
            describe_location_fsx_open_zfs::DescribeLocationFsxOpenZfs,
            describe_location_fsx_windows::DescribeLocationFsxWindows,
            describe_location_hdfs::DescribeLocationHdfs,
            describe_location_nfs::DescribeLocationNfs,
            describe_location_object_storage::DescribeLocationObjectStorage,
            describe_location_s3::DescribeLocationS3,
            describe_location_smb::DescribeLocationSmb,
            describe_task::DescribeTask,
            describe_task_execution::DescribeTaskExecution,
            list_agents::ListAgents,
            list_locations::ListLocations,
            list_tags_for_resource::ListTagsForResource,
            list_task_executions::ListTaskExecutions,
            list_tasks::ListTasks,
            start_task_execution::StartTaskExecution,
            tag_resource::TagResource,
            untag_resource::UntagResource,
            update_agent::UpdateAgent,
            update_location_azure_blob::UpdateLocationAzureBlob,
            update_location_efs::UpdateLocationEfs,
            update_location_fsx_lustre::UpdateLocationFsxLustre,
            update_location_fsx_ontap::UpdateLocationFsxOntap,
            update_location_fsx_open_zfs::UpdateLocationFsxOpenZfs,
            update_location_fsx_windows::UpdateLocationFsxWindows,
            update_location_hdfs::UpdateLocationHdfs,
            update_location_nfs::UpdateLocationNfs,
            update_location_object_storage::UpdateLocationObjectStorage,
            update_location_s3::UpdateLocationS3,
            update_location_smb::UpdateLocationSmb,
            update_task::UpdateTask,
            update_task_execution::UpdateTaskExecution,
        );
        Self {
            entry: crate::ServiceDefinition::new(Arc::clone(&engine)),
            stating_its_own_refusals,
        }
    }
}

impl<Eng: Send + Sync + 'static> Service for EmulatedService<Eng> {
    fn definition(&self) -> &dyn smithy_server_runtime::ErasedServiceDefinition {
        // The model-derived half of this service — identity, protocol, routing
        // table, and the default error renderers — lives in the generated entry.
        // The router reads it through this one accessor. Do not edit the entry.
        &self.entry
    }

    fn can_handle(&self, parts: &http::request::Parts) -> bool {
        // Claim a request whose resolved route key is this service's signing
        // name. Edit this for anything the model does not express — a signing
        // name shared by several services, or access-key-id-based routing.
        match smithy_server_runtime::resolve_route_key(parts) {
            Some(key) => key == self.entry.identity().signing_name(),
            None => false,
        }
    }

    fn override_operation(
        &self,
        req: &aws_smithy_runtime_api::http::Request,
    ) -> Option<&dyn ErasedOperation> {
        // Serve the operation the generated routing table names, through the wrapper that
        // words a refused request the way this service words one (see
        // [`refusal::StatingItsOwnRefusals`]). The routing DECISION is not overridden: the
        // key is resolved by the model's own protocol, and a request the generated table
        // cannot serve is declined here so the framework's routing-error path stays exactly
        // as it was.
        let operation = self.definition().protocol().routing_key(req).ok()?;
        self.definition().routing_table().get(operation)?;
        self.stating_its_own_refusals.get(operation)
    }

    fn override_refusal(&self, refusal: &Refusal) -> Option<Refused> {
        // The centralized walk calls this on a framework-level refusal (an absent
        // required member, or a value outside a declared bound) to let this service
        // reword it. Every request to a modelled operation of this service is served
        // through [`refusal::StatingItsOwnRefusals`], which has the request and therefore
        // states the two halves this seam cannot; what is left for this seam is the one
        // restatement that needs neither — an enumerated type's admissible values, which
        // this service lists in the order the table holding them is walked rather than in
        // the order the model declares them.
        //
        // The code stays `ValidationException` (HTTP 400), which is what the framework
        // would have answered; this seam replaces the code and the message together, so
        // the refusal is restated rather than reclassified. An authentication refusal is
        // the framework's 403 to word, not this service's.
        refusal::stated_violations(refusal)
    }

    fn override_routing_error(
        &self,
        req: &aws_smithy_runtime_api::http::Request,
    ) -> Option<aws_smithy_runtime_api::http::Response> {
        // The router calls this when a request reached this service but named no
        // modeled operation — neither `override_operation` nor the generated
        // routing table resolved it. Returning `None` renders the protocol-correct
        // default for this service's envelope (query -> 400 InvalidAction text/xml,
        // awsJson -> 404, rpcv2Cbor -> 404, rest -> 501). Return `Some(resp)` to
        // word that routing failure in your own envelope instead.
        let _ = req;
        None
    }

    fn override_framework_error(
        &self,
        error: &aws_smithy_schema_server::ProtocolError,
    ) -> Option<aws_smithy_runtime_api::http::Response> {
        // The router calls this on a transport-level failure it detects up front —
        // before (or instead of) naming an operation — such as a malformed
        // `aws-chunked` body. Returning `None` keeps the entry's protocol-correct
        // rendering. Return `Some(resp)` to reword that failure in your own
        // envelope. The error is borrowed, so the default renderer can still
        // consume it on `None`.
        let _ = error;
        None
    }
}
