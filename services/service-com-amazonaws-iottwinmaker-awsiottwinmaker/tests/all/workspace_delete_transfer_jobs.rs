// SPDX-License-Identifier: CC0-1.0

//! What an outstanding metadata transfer does to `DeleteWorkspace`, end to end
//! over HTTP.
//!
//! Every case drives the real request path — `MultiServiceRouter::dispatch`, the
//! same entry the served emulator uses — so a route, a status code and a
//! serialized body are all exercised, not just a handler body.
//!
//! RULE under test: a workspace is deleted only once nothing the service still
//! holds has work outstanding against it, so a metadata transfer job that names
//! the workspace at either of its IoT TwinMaker ends and has NOT reached a
//! terminal `MetadataTransferJobState` refuses the delete with the modelled
//! `ValidationException`, naming the jobs that hold it up — and a job whose
//! transfer is OVER holds nothing up, keeping the `sources` and `destination` it
//! was accepted with for both of its reads to report back.
//!
//! The rows span what the rule generalises over: which END names the workspace
//! (its source, its destination, both, another workspace, or no IoT TwinMaker
//! end at all) and which of the seven modelled states the job is in — the state
//! being what decides it, never the shape of the request. The refusal's own
//! wording is measured against the member it travels on too, since it names one
//! id per job holding the delete up.

use std::time::{Duration, Instant, SystemTime};

use serde_json::json;
use service_com_amazonaws_iottwinmaker_awsiottwinmaker::ops::types::METADATA_TRANSFER_JOB_STATE_VALUES;
use service_com_amazonaws_iottwinmaker_awsiottwinmaker::state::{
    metadata_transfer_job_state_is_terminal, METADATA_TRANSFER_JOB_STATE_CANCELLING,
    METADATA_TRANSFER_JOB_STATE_VALIDATING,
};

use crate::error_message_bounds::{assert_within_bound, ERROR_MESSAGE_MAX};
use crate::harness::{workspace_arn, Emulator, Resp, REGION};

/// The workspace every case below tries to delete.
const TARGET: &str = "transferTarget";

/// A second workspace, so a row can name a workspace OTHER than the one it
/// deletes and the rule is shown to be per workspace rather than per store.
const OTHER: &str = "otherTransferTarget";

/// The Amazon S3 object an Amazon S3 SOURCE of a row reads.
///
/// No object store is mounted beside this service here, so a run that reads it
/// finds nothing — which is immaterial to every case below: what each row parks
/// the job in is its own state, and the outcome of the run never falls due
/// inside a case.
const S3_SOURCE_LOCATION: &str = "arn:aws:s3:::metadata-bucket/entities.json";

/// The Amazon S3 prefix an Amazon S3 DESTINATION of a row writes under.
///
/// Stated apart from [`S3_SOURCE_LOCATION`] because the two are modelled apart:
/// `S3DestinationLocation`'s pattern admits only `[/a-zA-Z0-9_-]` after the ARN
/// prefix, so a destination names a bucket and a prefix rather than an object
/// (`smithy_query(query="shape",shape="S3DestinationLocation")`).
const S3_DESTINATION_LOCATION: &str = "arn:aws:s3:::metadata-bucket/exports";

/// How far out a parked job's owed transition is held.
///
/// Generous on purpose: the instant is stored and never slept for, so holding it
/// beyond any run of this suite is what makes a row exercise the DELETE's rule
/// instead of racing the clock that would settle the job.
const UNREACHED_SETTLEMENT: Duration = Duration::from_secs(600);

/// How long a case waits for a transition the clock owes before it gives up.
///
/// Generous on purpose: the emulator's own span is a fraction of this, and what
/// the wait is for is the CONDITION (the job reaching a terminal state), so a
/// slow or loaded host makes the wait longer rather than the test fail.
const SETTLE_DEADLINE: Duration = Duration::from_secs(30);

/// How long the poll loop pauses between looks.
const POLL_PAUSE: Duration = Duration::from_millis(20);

/// Which ends of a transfer name [`TARGET`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ends {
    /// The workspace is read FROM: an IoT TwinMaker source, an Amazon S3
    /// destination.
    Source,
    /// The workspace is written TO: an Amazon S3 source, an IoT TwinMaker
    /// destination.
    Destination,
    /// Both ends of the transfer are the workspace itself.
    Both,
    /// An IoT TwinMaker end, naming the OTHER workspace.
    AnotherWorkspace,
    /// Neither end is an IoT TwinMaker one, so the job names no workspace at
    /// all.
    NoWorkspace,
}

impl Ends {
    /// The `sources` and `destination` members a create carries for these ends.
    fn request(self) -> (serde_json::Value, serde_json::Value) {
        let s3_source =
            json!([{"type": "s3", "s3Configuration": {"location": S3_SOURCE_LOCATION}}]);
        let s3_destination = json!({
            "type": "s3",
            "s3Configuration": {"location": S3_DESTINATION_LOCATION},
        });
        let twin_maker_source = |workspace_id: &str| {
            json!([{
                "type": "iottwinmaker",
                "iotTwinMakerConfiguration": {"workspace": workspace_arn(workspace_id)},
            }])
        };
        let twin_maker_destination = |workspace_id: &str| {
            json!({
                "type": "iottwinmaker",
                "iotTwinMakerConfiguration": {"workspace": workspace_arn(workspace_id)},
            })
        };
        match self {
            Ends::Source => (twin_maker_source(TARGET), s3_destination),
            Ends::Destination => (s3_source, twin_maker_destination(TARGET)),
            Ends::Both => (twin_maker_source(TARGET), twin_maker_destination(TARGET)),
            Ends::AnotherWorkspace => (twin_maker_source(OTHER), s3_destination),
            Ends::NoWorkspace => (s3_source, s3_destination),
        }
    }

    /// Whether a transfer with these ends names [`TARGET`], which is what makes
    /// an unfinished job of it hold the delete up.
    fn names_target(self) -> bool {
        matches!(self, Ends::Source | Ends::Destination | Ends::Both)
    }
}

/// The refusal the service words for `job_ids` holding up the delete of
/// `workspace_id`, in full — before the bound of the member it travels on is
/// applied.
///
/// It names the JOBS, as a bracketed, comma-separated list of their ids in id
/// order, and asks for what clears them, which is what lets a caller drive the
/// remediation off the refusal.
fn in_transfer_message(workspace_id: &str, job_ids: &[String]) -> String {
    format!(
        "Workspace {workspace_id} is being used by metadata transfer jobs [{}], please wait for \
         them to finish or cancel them first.",
        job_ids.join(", ")
    )
}

/// An emulator holding the two workspaces the rows name.
async fn emulator_with_workspaces() -> Emulator {
    let emulator = Emulator::new();
    for workspace_id in [TARGET, OTHER] {
        assert_eq!(
            emulator.create_workspace(workspace_id).await.status,
            200,
            "the workspace {workspace_id:?} the cases name must exist"
        );
    }
    emulator
}

/// Accept a job with `ends` through the API, asserted created.
async fn create_job(emulator: &Emulator, case: &str, job_id: &str, ends: Ends) {
    let (sources, destination) = ends.request();
    let created = emulator
        .create_metadata_transfer_job(json!({
            "metadataTransferJobId": job_id,
            "sources": sources,
            "destination": destination,
        }))
        .await;
    assert_eq!(
        created.status, 200,
        "case {case:?}: the job the case parks must be accepted, got {created:?}"
    );
}

/// Hold the job `job_id` in `state`, with the transition the clock owes it far
/// enough out that nothing falls due while the case runs.
///
/// The emulator's own operations produce four of the seven modelled states
/// (`VALIDATING` from a create, `ERROR` from its outcome, `CANCELLING` and
/// `CANCELLED` from a cancel), so the rest of the enum is reached by parking an
/// accepted job in each value through the store the handlers read — the seam
/// `Emulator::state` exists for. `None` leaves the state the create answered
/// exactly as it is and only holds its owed outcome out.
fn park_job(emulator: &Emulator, job_id: &str, state: Option<&str>) {
    let handle = emulator.state();
    let mut store = handle.lock();
    let job = store
        .region_mut(REGION)
        .metadata_transfer_jobs
        .get_mut(job_id)
        .expect("the accepted job is in the store");
    if let Some(state) = state {
        job.state = state.to_string();
    }
    job.settles_at = SystemTime::now() + UNREACHED_SETTLEMENT;
}

/// The `status.state` a response reports for a job.
fn reported_state(resp: &Resp) -> Option<&str> {
    resp.member("status")["state"].as_str()
}

/// The job once the clock has made its terminal state due.
///
/// The emulator stores the instant and never sleeps for it, so a case that
/// wants the settled job is the one that looks again until it is there — waiting
/// for the CONDITION and not for a span.
async fn settled_job(emulator: &Emulator, job_id: &str) -> Resp {
    let deadline = Instant::now() + SETTLE_DEADLINE;
    loop {
        let read = emulator.get_metadata_transfer_job(job_id).await;
        if reported_state(&read).is_some_and(metadata_transfer_job_state_is_terminal) {
            return read;
        }
        assert!(
            Instant::now() < deadline,
            "job {job_id:?}: the clock must settle the job, last read {read:?}"
        );
        tokio::time::sleep(POLL_PAUSE).await;
    }
}

/// RULE: `DeleteWorkspace` is refused for a workspace a metadata transfer job
/// that has not finished names at either end, and allowed once every job naming
/// it has reached a terminal state — whichever end named it and whichever state
/// the job is in.
#[tokio::test]
async fn an_unfinished_transfer_holds_up_its_workspaces_delete() {
    // The table spans every value the model's `MetadataTransferJobState` enum
    // defines, so a value added to the model fails here rather than going
    // untested.
    assert_eq!(
        METADATA_TRANSFER_JOB_STATE_VALUES.len(),
        7,
        "the table must span every modelled state, got {METADATA_TRANSFER_JOB_STATE_VALUES:?}"
    );
    let ends = [
        Ends::Source,
        Ends::Destination,
        Ends::Both,
        Ends::AnotherWorkspace,
        Ends::NoWorkspace,
    ];

    for (index, state) in METADATA_TRANSFER_JOB_STATE_VALUES.iter().enumerate() {
        for ends in ends {
            let case = format!("{ends:?} in {state}");
            let case = case.as_str();
            // An emulator of its own per row: a row whose delete SUCCEEDS takes
            // the workspace the next row needs with it.
            let emulator = emulator_with_workspaces().await;
            let job_id = format!("parkedJob{index}");
            create_job(&emulator, case, &job_id, ends).await;
            park_job(&emulator, &job_id, Some(state));

            let deleted = emulator.delete_workspace(TARGET).await;
            let outstanding = ends.names_target() && !metadata_transfer_job_state_is_terminal(state);
            if outstanding {
                assert_eq!(
                    (deleted.status, deleted.error_type.as_deref()),
                    (400, Some("ValidationException")),
                    "case {case:?}: an unfinished transfer must hold the delete up, got \
                     {deleted:?}"
                );
                assert_eq!(
                    deleted.member("message").as_str(),
                    Some(in_transfer_message(TARGET, std::slice::from_ref(&job_id)).as_str()),
                    "case {case:?}: the refusal must name the job holding the delete up, got \
                     {deleted:?}"
                );
                assert_eq!(
                    emulator.get_workspace(TARGET).await.status,
                    200,
                    "case {case:?}: a refused delete must change nothing"
                );
                // The rule is about the workspace the job NAMES: the other one
                // is nothing to this job, so it is deletable while this one is
                // not.
                let other = emulator.delete_workspace(OTHER).await;
                assert_eq!(
                    other.status,
                    200,
                    "case {case:?}: a workspace no unfinished transfer names must be deletable, \
                     got {other:?}"
                );
                continue;
            }

            assert_eq!(
                deleted.status, 200,
                "case {case:?}: no outstanding transfer names this workspace, so the delete must \
                 be served, got {deleted:?}"
            );
            let gone = emulator.get_workspace(TARGET).await;
            assert_eq!(
                (gone.status, gone.error_type.as_deref()),
                (404, Some("ResourceNotFoundException")),
                "case {case:?}: the deleted workspace must be gone, got {gone:?}"
            );
            // The job itself is untouched by the delete: a finished job reports
            // the request it was accepted with, which is what both of its reads
            // report back.
            let (sources, destination) = ends.request();
            let read = emulator.get_metadata_transfer_job(&job_id).await;
            assert_eq!(
                (read.status, reported_state(&read)),
                (200, Some(*state)),
                "case {case:?}: the job must still be reported in its own state, got {read:?}"
            );
            assert_eq!(
                (read.member("sources"), read.member("destination")),
                (&sources, &destination),
                "case {case:?}: the job must still report the ends it was accepted with, got \
                 {read:?}"
            );
        }
    }
}

/// RULE (the same rule, driven end to end through the operations alone): the
/// refusal says what clears it — a transfer either finishes or is cancelled, and
/// the workspace is deletable once it has.
#[tokio::test]
async fn cancelling_the_transfer_clears_the_workspaces_delete() {
    let emulator = emulator_with_workspaces().await;
    let job_id = "heldTransfer";
    create_job(&emulator, "cancelled", job_id, Ends::Destination).await;
    // The outcome the create owes the job is held out, so the job stays in the
    // non-terminal state the create answered with for the whole case rather
    // than settling at whatever instant the host gets to the next call.
    park_job(&emulator, job_id, None);
    let read = emulator.get_metadata_transfer_job(job_id).await;
    assert_eq!(
        (read.status, reported_state(&read)),
        (200, Some(METADATA_TRANSFER_JOB_STATE_VALIDATING)),
        "the accepted job must still be in flight, got {read:?}"
    );

    let refused = emulator.delete_workspace(TARGET).await;
    assert_eq!(
        (
            refused.status,
            refused.error_type.as_deref(),
            refused.member("message").as_str(),
        ),
        (
            400,
            Some("ValidationException"),
            Some(in_transfer_message(TARGET, &[job_id.to_string()]).as_str()),
        ),
        "a workspace an accepted transfer is still going to write must not be deletable, got \
         {refused:?}"
    );

    let cancelled = emulator.cancel_metadata_transfer_job(job_id).await;
    assert_eq!(
        (cancelled.status, reported_state(&cancelled)),
        (200, Some(METADATA_TRANSFER_JOB_STATE_CANCELLING)),
        "the transfer the refusal names must be cancellable, got {cancelled:?}"
    );
    let settled = settled_job(&emulator, job_id).await;

    let deleted = emulator.delete_workspace(TARGET).await;
    assert_eq!(
        deleted.status, 200,
        "with the transfer over the workspace must be deletable, got {deleted:?} after {settled:?}"
    );
    let gone = emulator.get_workspace(TARGET).await;
    assert_eq!(
        (gone.status, gone.error_type.as_deref()),
        (404, Some("ResourceNotFoundException")),
        "the deleted workspace must be gone, got {gone:?}"
    );
    // The job outlives the workspace it named, reporting the destination the
    // create supplied: the stored request is the record of what was asked for.
    let read = emulator.get_metadata_transfer_job(job_id).await;
    assert_eq!(
        (
            read.status,
            read.member("destination")["iotTwinMakerConfiguration"]["workspace"].as_str(),
        ),
        (200, Some(workspace_arn(TARGET).as_str())),
        "the finished job must still report the end it was accepted with, got {read:?}"
    );
}

/// RULE: the refusal is stated within the `@length` maximum of the modelled
/// member it travels on — `ErrorMessage`, 2048 characters — however many
/// unfinished transfers name the workspace and however long their ids are.
///
/// The same rule [`crate::component_type_delete_in_use_message_bound`] asserts
/// for the other in-use refusal of this service, over the reason this delete
/// grows one id per job.
#[tokio::test]
async fn the_in_transfer_refusal_fits_its_modelled_member() {
    // `(case, how many jobs name the workspace, how long each id is)`. The rows
    // differ along the NUMBER of unfinished transfers and the SIZE of their ids,
    // including one id at the modelled maximum and enough of them that the
    // reason naming all of them cannot fit the member it travels on.
    let rows: &[(&str, usize, usize)] = &[
        ("one transfer with a short id", 1, 12),
        ("one transfer with an id at the modelled maximum", 1, ID_MAX),
        ("three transfers with ids at the modelled maximum", 3, ID_MAX),
        ("twenty transfers with ids at the modelled maximum", 20, ID_MAX),
    ];
    for (case, count, id_length) in rows {
        let emulator = emulator_with_workspaces().await;
        let mut job_ids: Vec<String> = Vec::new();
        for index in 0..*count {
            let job_id = padded_id(index, *id_length);
            create_job(&emulator, case, &job_id, Ends::Destination).await;
            park_job(&emulator, &job_id, None);
            job_ids.push(job_id);
        }
        // The service names the jobs in id order, each once.
        job_ids.sort();
        let whole = in_transfer_message(TARGET, &job_ids);

        let refused = emulator.delete_workspace(TARGET).await;
        assert_eq!(
            (refused.status, refused.error_type.as_deref()),
            (400, Some("ValidationException")),
            "case {case:?}: expected 400 ValidationException, got {refused:?}"
        );
        let reported = refused
            .member("message")
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_within_bound(case, &reported, &whole, ERROR_MESSAGE_MAX);
        assert_eq!(
            emulator.get_workspace(TARGET).await.status,
            200,
            "case {case:?}: a refused delete must leave the workspace in place"
        );
    }
}

/// The greatest number of characters the modelled `Id` — the shape a
/// `metadataTransferJobId` is — admits: `@length(1..128)`, from
/// `smithy_query(query="shape",shape="Id")`.
const ID_MAX: usize = 128;

/// One `metadataTransferJobId` of `length` characters, distinguished from its
/// siblings by `index`.
///
/// Zero-padded, so the ids sort in the order their indexes were handed out and
/// the refusal's id order is a statement rather than an accident. Every
/// character is one the modelled `Id` pattern admits.
fn padded_id(index: usize, length: usize) -> String {
    let base = format!("heldJob{index:03}");
    assert!(
        length >= base.chars().count(),
        "an id of {length} characters cannot carry the prefix {base:?}"
    );
    let mut id = base;
    while id.chars().count() < length {
        id.push('x');
    }
    id
}
