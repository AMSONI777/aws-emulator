// SPDX-License-Identifier: CC0-1.0

//! Which WORKSPACES a metadata transfer job names, and which jobs still have a
//! transfer outstanding against one.
//!
//! One concern of [`crate::state`], kept in its own file: a job is stored BESIDE
//! the workspaces rather than inside one ([`RegionalState::metadata_transfer_jobs`]),
//! so the reference from a job to a workspace is the only thing that ties the
//! two together — and every reader of that reference asks about it here.
//!
//! The reference is read in two directions, and both are this module's:
//!
//! * from a job to the workspaces it names
//!   ([`referenced_workspaces`]), which is what a create has to resolve before
//!   it accepts a transfer and what the run then reads or writes;
//! * from a workspace to the jobs whose transfer is still outstanding against
//!   it ([`RegionalState::unfinished_transfer_jobs_for`]), which is what a
//!   delete of that workspace has to be refused for.

use super::*;

/// Every workspace ARN the ends of a transfer name, in the order they name them:
/// the workspace of each IoT TwinMaker source, then of an IoT TwinMaker
/// destination.
///
/// The other end types name an Amazon S3 location or an IoT SiteWise asset model
/// instead, neither of which is a resource this service holds, so neither
/// contributes a reference.
///
/// Taken from the modelled request shapes a job is stored as, so the create that
/// resolves these references before accepting a transfer and the delete that
/// refuses to break one read the SAME ends of the same job.
pub fn referenced_workspaces<'ends>(
    sources: &'ends [crate::ops::types::SourceConfiguration],
    destination: &'ends crate::ops::types::DestinationConfiguration,
) -> Vec<&'ends str> {
    sources
        .iter()
        .filter_map(|source| source.iot_twin_maker_configuration.as_ref())
        .map(|configuration| configuration.workspace.as_str())
        .chain(
            destination
                .iot_twin_maker_configuration
                .as_ref()
                .map(|configuration| configuration.workspace.as_str()),
        )
        .collect()
}

impl MetadataTransferJob {
    /// Every workspace ARN this stored job names, as
    /// [`referenced_workspaces`] reads them off its ends.
    pub fn referenced_workspaces(&self) -> Vec<&str> {
        referenced_workspaces(&self.sources, &self.destination)
    }
}

impl RegionalState {
    /// The ids of the metadata transfer jobs that still have a transfer
    /// OUTSTANDING against the workspace `workspace_id` — the jobs naming it at
    /// either end that have not reached a terminal state — each listed once and
    /// in id order.
    ///
    /// A job whose state is terminal
    /// ([`metadata_transfer_job_state_is_terminal`]) is NOT one of them: its
    /// transfer is over, and what it reports is the request it was accepted
    /// with rather than work still to come. Whatever the clock already owes each
    /// job is materialised first ([`MetadataTransferJob::settle`]), exactly as
    /// every other reader of a job does, so a job the clock finished before the
    /// call is read as the finished job it already was.
    ///
    /// Each end names its workspace by ARN, and an id-or-ARN resolves through
    /// the one resolution every reader of such a value uses
    /// ([`resolve_workspace_id`](Self::resolve_workspace_id)), so a job and a
    /// delete cannot disagree about which workspace a reference points at.
    pub fn unfinished_transfer_jobs_for(
        &mut self,
        workspace_id: &str,
        now: SystemTime,
    ) -> Vec<String> {
        for job in self.metadata_transfer_jobs.values_mut() {
            job.settle(now);
        }
        self.metadata_transfer_jobs
            .values()
            .filter(|job| !job.is_terminal())
            .filter(|job| {
                job.referenced_workspaces().into_iter().any(|workspace| {
                    self.resolve_workspace_id(workspace).as_deref() == Some(workspace_id)
                })
            })
            .map(|job| job.metadata_transfer_job_id.clone())
            .collect()
    }
}

/// The message a delete of the workspace `workspace_id` is refused with while
/// the metadata transfer jobs `metadata_transfer_job_ids` still have a transfer
/// outstanding against it, and `None` when none do.
///
/// Built like every other in-use refusal of this service
/// ([`ComponentTypeReferences::in_use_message`]): it names the JOBS that hold
/// the delete up, as a bracketed, comma-separated list of their ids, and asks
/// for what clears them — a transfer either finishes on its own or is stopped
/// with `CancelMetadataTransferJob`, which is the remediation a caller can drive
/// off the refusal. The reason names as many ids as reference the workspace, so
/// it is stated within the bound the member it travels on declares
/// ([`clamped_message`]).
pub fn workspace_in_transfer_message(
    workspace_id: &str,
    metadata_transfer_job_ids: &[String],
) -> Option<String> {
    (!metadata_transfer_job_ids.is_empty()).then(|| {
        clamped_message(
            format!(
                "Workspace {workspace_id} is being used by metadata transfer jobs [{}], please \
                 wait for them to finish or cancel them first.",
                metadata_transfer_job_ids.join(", ")
            ),
            ERROR_MESSAGE_MAX_CHARS,
        )
    })
}
