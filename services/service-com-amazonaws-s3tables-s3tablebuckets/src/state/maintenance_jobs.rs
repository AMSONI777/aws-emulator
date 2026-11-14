// SPDX-License-Identifier: CC0-1.0

//! The maintenance jobs S3 Tables runs on a table, and the status each of them
//! reports.
//!
//! A maintenance job is the RUN of a maintenance task: the configuration says
//! whether the task runs and under which settings, and the job status says what
//! became of its last run. So everything here is derived from two records this
//! store already holds — the task's configuration and the schedule it has been
//! running under — plus the clock: nothing is canned, and a read of a job's
//! status writes nothing.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use super::{
    default_bucket_maintenance, default_table_maintenance, effective_bucket_task_maintenance,
    effective_task_maintenance, MaintenanceStatus, Table, TableBucket, TableBucketMaintenanceType,
    TableMaintenanceType,
};

/// How long after a maintenance task becomes eligible its first run of that
/// eligible period completes.
///
/// CHOSEN, not an AWS-published figure: S3 Tables runs maintenance on a
/// schedule of its own, which it publishes no interval for. What matters is
/// that the span is NOT zero — a caller that reads the status straight after
/// creating a table still sees the job it has not run yet — and that it is
/// short enough for a caller to wait for the run rather than poll for hours.
pub const MAINTENANCE_JOB_FIRST_RUN_DELAY: Duration = Duration::from_secs(3);

/// `JobStatus` — what became of a maintenance job's last run. Values from
/// `com.amazonaws.s3tables#JobStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceJobStatus {
    /// The task runs, but no run of it has completed yet.
    NotYetRun,
    /// The task's last run completed.
    Successful,
    /// The task's last run failed.
    Failed,
    /// The task does not run on the table, so no job runs for it.
    Disabled,
}

impl MaintenanceJobStatus {
    /// Every modeled value, for exhaustiveness checks.
    pub const ALL: &'static [Self] = &[
        Self::NotYetRun,
        Self::Successful,
        Self::Failed,
        Self::Disabled,
    ];

    /// The value as it goes on the wire.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::NotYetRun => "Not_Yet_Run",
            Self::Successful => "Successful",
            Self::Failed => "Failed",
            Self::Disabled => "Disabled",
        }
    }
}

/// `TableMaintenanceJobType` — the maintenance jobs that run on ONE table.
/// Values from `com.amazonaws.s3tables#TableMaintenanceJobType`.
///
/// It names one job more than [`TableMaintenanceType`] does: removing the files
/// a table no longer references is configured on the table BUCKET
/// ([`TableBucketMaintenanceType`]) and runs on each of its tables, so the job
/// is reported per table while its configuration lives on the bucket.
///
/// Ordered, so a read reports a table's jobs in one stable order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TableMaintenanceJobType {
    /// Rewriting a table's small data files into fewer, larger ones.
    IcebergCompaction,
    /// Expiring a table's older snapshots.
    IcebergSnapshotManagement,
    /// Removing the files a table no longer references.
    IcebergUnreferencedFileRemoval,
}

impl TableMaintenanceJobType {
    /// Every modeled value, for exhaustiveness checks.
    pub const ALL: &'static [Self] = &[
        Self::IcebergCompaction,
        Self::IcebergSnapshotManagement,
        Self::IcebergUnreferencedFileRemoval,
    ];

    /// The value as it goes on the wire.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::IcebergCompaction => "icebergCompaction",
            Self::IcebergSnapshotManagement => "icebergSnapshotManagement",
            Self::IcebergUnreferencedFileRemoval => "icebergUnreferencedFileRemoval",
        }
    }

    /// Parse a wire value, or `None` when it names no modeled value.
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_wire() == value)
    }

    /// The table-level maintenance task this job runs, for the jobs configured
    /// on the table itself.
    pub fn table_task(self) -> Option<TableMaintenanceType> {
        match self {
            Self::IcebergCompaction => Some(TableMaintenanceType::IcebergCompaction),
            Self::IcebergSnapshotManagement => Some(TableMaintenanceType::IcebergSnapshotManagement),
            Self::IcebergUnreferencedFileRemoval => None,
        }
    }

    /// The bucket-level maintenance task this job runs, for the jobs configured
    /// on the table bucket.
    pub fn bucket_task(self) -> Option<TableBucketMaintenanceType> {
        match self {
            Self::IcebergUnreferencedFileRemoval => {
                Some(TableBucketMaintenanceType::IcebergUnreferencedFileRemoval)
            }
            Self::IcebergCompaction | Self::IcebergSnapshotManagement => None,
        }
    }
}

/// The schedule ONE maintenance task runs under: since when it has been
/// eligible to run, and — when it is not eligible any more — when it stopped
/// being.
///
/// This is what makes a job's status a fact about the task rather than a guess:
/// a task is eligible from the moment the resource it runs on exists, a put
/// that turns it off ends that eligible period, and a put that turns it back on
/// starts a new one. A put that leaves the task's status alone leaves the
/// schedule alone too, so changing a task's settings does not erase the run it
/// already completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceSchedule {
    /// The task runs, and has been eligible to since this instant.
    Eligible { since: SystemTime },
    /// The task does not run; its last eligible period ran from `since` until
    /// `until`.
    Suspended { since: SystemTime, until: SystemTime },
}

impl MaintenanceSchedule {
    /// When the task's current (or last) eligible period began.
    pub fn since(self) -> SystemTime {
        match self {
            Self::Eligible { since } | Self::Suspended { since, .. } => since,
        }
    }

    /// Whether the task runs under this schedule.
    pub fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible { .. })
    }

    /// The schedule the task runs under once a put has left its effective
    /// status at `enabled`, as of `now`.
    ///
    /// A status that did not change leaves the schedule as it stands, so a put
    /// of new settings neither re-runs a completed job nor keeps a suspended
    /// task from reporting the run it completed before it was suspended.
    pub fn with_status(self, enabled: bool, now: SystemTime) -> Self {
        match (self, enabled) {
            (Self::Suspended { .. }, true) => Self::Eligible { since: now },
            (Self::Eligible { since }, false) => Self::Suspended { since, until: now },
            (unchanged, _) => unchanged,
        }
    }
}

/// The schedule a task of a resource created at `created_at` runs under when no
/// put ever changed its status: the task's own default status decides whether
/// it has been eligible since the resource was created.
fn schedule_from_default(status: Option<MaintenanceStatus>, created_at: SystemTime) -> MaintenanceSchedule {
    if status == Some(MaintenanceStatus::Enabled) {
        MaintenanceSchedule::Eligible { since: created_at }
    } else {
        MaintenanceSchedule::Suspended {
            since: created_at,
            until: created_at,
        }
    }
}

/// The schedule one maintenance task of `table` currently runs under.
pub fn table_task_schedule(table: &Table, task: TableMaintenanceType) -> MaintenanceSchedule {
    table
        .maintenance_schedules
        .get(&task)
        .copied()
        .unwrap_or_else(|| {
            schedule_from_default(default_table_maintenance(task).status, table.created_at)
        })
}

/// The schedule one maintenance task of `bucket` currently runs under.
pub fn bucket_task_schedule(
    bucket: &TableBucket,
    task: TableBucketMaintenanceType,
) -> MaintenanceSchedule {
    bucket
        .maintenance_schedules
        .get(&task)
        .copied()
        .unwrap_or_else(|| {
            schedule_from_default(default_bucket_maintenance(task).status, bucket.created_at)
        })
}

/// Whether one maintenance task of `table` is in force — the effective status
/// of the configuration the store holds for it.
pub fn table_task_is_enabled(table: &Table, task: TableMaintenanceType) -> bool {
    effective_task_maintenance(task, table.maintenance.get(&task)).status
        == Some(MaintenanceStatus::Enabled)
}

/// Whether one maintenance task of `bucket` is in force — the effective status
/// of the configuration the store holds for it.
pub fn bucket_task_is_enabled(bucket: &TableBucket, task: TableBucketMaintenanceType) -> bool {
    effective_bucket_task_maintenance(task, bucket.maintenance.get(&task)).status
        == Some(MaintenanceStatus::Enabled)
}

/// What one maintenance job of a table reports: the status of its last run, and
/// the instant that run completed at when one has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceJobReport {
    pub status: MaintenanceJobStatus,
    /// `None` for a job no run of which has completed, so the member is left
    /// out rather than claiming an instant for work nothing performed.
    pub last_run_at: Option<SystemTime>,
}

/// The status one job reports, from the schedule its task runs under.
///
/// `not_before` is the instant the job could first have run on the table at
/// all — a table is not maintained before it exists, whatever its bucket's
/// configuration says. Exactly ONE run is scheduled per eligible period, so the
/// instant a completed run reports is stable across reads: it does not move
/// because somebody asked again.
fn report_from_schedule(
    schedule: MaintenanceSchedule,
    not_before: SystemTime,
    at: SystemTime,
) -> MaintenanceJobReport {
    let eligible_since = schedule.since().max(not_before);
    // `checked_add`, so a clock far enough in the future that the span does not
    // fit cannot panic a read: such a run is treated as already completed.
    let completes_at = eligible_since
        .checked_add(MAINTENANCE_JOB_FIRST_RUN_DELAY)
        .unwrap_or(eligible_since);
    // The run completed if the eligible period lasted long enough for it: up to
    // now for a task that still runs, up to its suspension for one that does
    // not.
    let completed = match schedule {
        MaintenanceSchedule::Eligible { .. } => at >= completes_at,
        MaintenanceSchedule::Suspended { until, .. } => until >= completes_at,
    };
    let status = match (schedule.is_eligible(), completed) {
        (false, _) => MaintenanceJobStatus::Disabled,
        (true, true) => MaintenanceJobStatus::Successful,
        (true, false) => MaintenanceJobStatus::NotYetRun,
    };
    MaintenanceJobReport {
        status,
        last_run_at: completed.then_some(completes_at),
    }
}

/// The status of every maintenance job of `table`, as of `at`.
///
/// S3 Tables maintains every table from the moment it is created, so there is
/// one entry per modeled job: the two jobs configured on the table are read
/// from the table's own configuration, and the job configured on the bucket
/// from the bucket's.
pub fn table_maintenance_job_status(
    bucket: &TableBucket,
    table: &Table,
    at: SystemTime,
) -> BTreeMap<TableMaintenanceJobType, MaintenanceJobReport> {
    TableMaintenanceJobType::ALL
        .iter()
        .copied()
        .map(|job| {
            let schedule = match (job.table_task(), job.bucket_task()) {
                (Some(task), _) => table_task_schedule(table, task),
                (_, Some(task)) => bucket_task_schedule(bucket, task),
                // Every modeled job is configured by one task or the other;
                // a job that is configured by neither runs under nothing, so
                // it is reported as not running rather than as having run.
                (None, None) => MaintenanceSchedule::Suspended {
                    since: table.created_at,
                    until: table.created_at,
                },
            };
            (job, report_from_schedule(schedule, table.created_at, at))
        })
        .collect()
}
