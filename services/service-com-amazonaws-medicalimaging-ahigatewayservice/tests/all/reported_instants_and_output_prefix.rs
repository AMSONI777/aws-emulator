// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for two things every reporting operation of this service states about a
//! job or an image set: the FORM of the instants it reports, and the output prefix an
//! import job reports as its own.
//!
//! RULE 1: every modelled `Date` member this service serves carries an instant at
//! MILLISECOND precision — the form the model documents for them ("The time an image set is
//! created. Sample creation date is provided in `1985-04-12T23:20:50.52Z` format") — so a
//! client that round-trips one of these timestamps reads back an instant of the documented
//! precision rather than whatever the clock this emulator read it from resolves to. It
//! holds for every such member, whichever operation reports it: a job's `submittedAt` and
//! `endedAt`, an image set's `createdAt`, `updatedAt`, `deletedAt` and `lastAccessedAt`, in
//! a response body and in a search summary alike.
//!
//! RULE 2: `GetDICOMImportJob` reports in `jobProperties.outputS3Uri` the prefix THIS job's
//! results are written under — the prefix the submit named with the one folder per job
//! appended, `<datastoreId>-DicomImport-<jobId>/` — and not the request's value echoed
//! back, so two jobs pointed at one output prefix report two prefixes and a client reading
//! the reported one finds that job's own manifests.
//! `crate::import_job_output_manifest` drives the same rule over the forms an `S3Uri` takes;
//! what the rows here pin is what the READ reports.
//!
//! Each suite is a TABLE whose rows differ along what its rule generalises over: for rule 1
//! the member and the operation reporting it; for rule 2 the shape of the output prefix the
//! submit named and how many jobs were submitted against it. Every case drives real HTTP
//! through the production front door, so what is asserted is the wire behaviour a
//! `medical-imaging` SDK client sees.

use std::time::{Duration, Instant};

use serde_json::json;

use service_com_amazonaws_medicalimaging_ahigatewayservice::state::service_state;

use crate::datastore_lifecycle::{Answer, Emulator, ACCOUNT};
use crate::image_set_copy::{get_image_set, seed_image_set};
use crate::image_set_deletion::delete_image_set;
use crate::image_set_search::search;

/// The most digits a reported instant may carry after the decimal point: an instant of
/// millisecond precision carries at most three.
const MAX_FRACTIONAL_DIGITS: usize = 3;

/// How long a poll waits for a condition the clock owes. Generous on purpose: it bounds a
/// hung emulator rather than the spans this service promises.
const POLL_DEADLINE: Duration = Duration::from_secs(120);

/// How long a poll waits between looks.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The role an import runs as. `RoleArn` is `^arn:aws(-[^:]+)?:iam::[0-9]{12}:role/.+$`, and
/// this emulator mounts no IAM beside this service here, so nothing is established about the
/// role and the submission is admitted.
fn data_access_role_arn() -> String {
    format!("arn:aws:iam::{ACCOUNT}:role/HealthImagingImport")
}

/// How many digits the JSON number `member` carries after its decimal point in `body`, or
/// `None` when the body carries no such member or carries something other than a number
/// there.
///
/// Read off the RAW response body rather than through a parsed `f64`, because the form a
/// number was SERIALIZED in is exactly what this rule is about: a parse would hand back a
/// double whatever the wire carried.
fn fractional_digits(body: &[u8], member: &str) -> Option<usize> {
    let text = std::str::from_utf8(body).ok()?;
    let at = text.find(&format!("\"{member}\":"))? + member.len() + 3;
    let number: String = text[at..]
        .chars()
        .take_while(|character| {
            character.is_ascii_digit() || matches!(character, '.' | '-' | '+' | 'e' | 'E')
        })
        .collect();
    if number.is_empty() {
        return None;
    }
    Some(match number.split_once('.') {
        Some((_, fraction)) => fraction.len(),
        None => 0,
    })
}

/// Assert that `member` is reported in `answer` as an instant of the documented precision:
/// a number, at or after the epoch, carrying at most [`MAX_FRACTIONAL_DIGITS`] digits after
/// the decimal point. `reported` is the value the caller read for it.
fn assert_instant(answer: &Answer, case: &str, member: &str, reported: Option<f64>) {
    assert!(
        reported.is_some_and(|instant| instant > 0.0),
        "case {case:?}: expected {member} to report an instant, got {answer:?}"
    );
    let digits = fractional_digits(&answer.body_bytes, member).unwrap_or_else(|| {
        panic!("case {case:?}: expected {member} to be serialized as a number, got {answer:?}")
    });
    assert!(
        digits <= MAX_FRACTIONAL_DIGITS,
        "case {case:?}: expected {member} at millisecond precision \
         ({MAX_FRACTIONAL_DIGITS} fractional digit(s) at most), got {digits} in {answer:?}"
    );
}

/// Submit one import job against `datastore_id` and answer its identifier.
async fn start_import(
    emulator: &Emulator,
    case: &str,
    datastore_id: &str,
    token: &str,
    output_s3_uri: &str,
) -> Answer {
    let started = emulator
        .start_import_job(
            datastore_id,
            json!({
                "clientToken": token,
                "dataAccessRoleArn": data_access_role_arn(),
                "inputS3Uri": "s3://healthimaging-shelf/in/",
                "outputS3Uri": output_s3_uri,
            }),
        )
        .await;
    assert_eq!(
        started.status, 200,
        "case {case:?}: expected HTTP 200 from StartDICOMImportJob, got {started:?}"
    );
    started
}

/// Make the import job `job_id` fall due now, so a case can read a job that has ENDED
/// without sleeping out the span the service promises.
///
/// The only write these cases make into the state struct, and it changes no status: it
/// moves the due instants the handler itself recorded, exactly as
/// `crate::image_set_deletion::move_due_instant` moves a retirement's.
fn make_job_due(emulator: &Emulator, case: &str, datastore_id: &str, job_id: &str) {
    let now = std::time::SystemTime::now();
    let state = service_state(emulator.engine()).expect("the medical-imaging state store");
    let mut store = state.lock();
    let job = store
        .datastores
        .get_mut(datastore_id)
        .expect("the created data store")
        .import_jobs
        .get_mut(job_id)
        .unwrap_or_else(|| panic!("case {case:?}: expected the submitted import job"));
    job.in_progress_due_at = now;
    job.completed_due_at = now;
}

/// Poll `GetDICOMImportJob` until the job has ENDED, and answer that answer.
async fn poll_until_ended(
    emulator: &Emulator,
    case: &str,
    datastore_id: &str,
    job_id: &str,
) -> Answer {
    let deadline = Instant::now() + POLL_DEADLINE;
    loop {
        let answer = emulator.get_import_job(datastore_id, job_id).await;
        if answer.status == 200 && !answer.field(&["jobProperties", "endedAt"]).is_null() {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the import job never reported an endedAt, last answer {answer:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `GetImageSet` until the deletion of `image_set_id` has landed, and answer that
/// answer — the one read that reports a `deletedAt`.
async fn poll_until_deleted(
    emulator: &Emulator,
    case: &str,
    datastore_id: &str,
    image_set_id: &str,
) -> Answer {
    let deadline = Instant::now() + POLL_DEADLINE;
    loop {
        let answer = get_image_set(emulator, datastore_id, image_set_id, None).await;
        if answer.status == 200 && !answer.field(&["deletedAt"]).is_null() {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the deletion never reported a deletedAt, last answer {answer:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// RULE 1 (above), over every operation of this service that reports a modelled `Date`.
#[tokio::test]
async fn every_reported_instant_is_served_at_millisecond_precision() {
    let emulator = Emulator::new();
    let datastore_id = emulator
        .active_datastore("instant.store", "token-instant-store")
        .await;

    // The submit itself reports one instant.
    let case = "StartDICOMImportJob";
    let started = start_import(
        &emulator,
        case,
        &datastore_id,
        "token-instant-job",
        "s3://healthimaging-shelf/out/",
    )
    .await;
    assert_instant(
        &started,
        case,
        "submittedAt",
        started.field(&["submittedAt"]).as_f64(),
    );
    let job_id = started.string(&["jobId"]);

    // The job read reports two: the instant it was submitted at and the instant it ended.
    let case = "GetDICOMImportJob";
    make_job_due(&emulator, case, &datastore_id, &job_id);
    let ended = poll_until_ended(&emulator, case, &datastore_id, &job_id).await;
    for member in ["submittedAt", "endedAt"] {
        assert_instant(
            &ended,
            case,
            member,
            ended.field(&["jobProperties", member]).as_f64(),
        );
    }

    // The image set read reports three while the image set stands, and a fourth once its
    // deletion has landed.
    let image_set_id = seed_image_set(&emulator, &datastore_id, 2);
    let case = "GetImageSet";
    let read = get_image_set(&emulator, &datastore_id, &image_set_id, None).await;
    assert_eq!(
        read.status, 200,
        "case {case:?}: expected HTTP 200 from GetImageSet, got {read:?}"
    );
    for member in ["createdAt", "updatedAt", "lastAccessedAt"] {
        assert_instant(&read, case, member, read.field(&[member]).as_f64());
    }

    // The search summary reports the same three, through its own projection.
    let case = "SearchImageSets";
    let found = search(&emulator, &datastore_id, None, "").await;
    assert_eq!(
        found.status, 200,
        "case {case:?}: expected HTTP 200 from SearchImageSets, got {found:?}"
    );
    let summary = found
        .field(&["imageSetsMetadataSummaries"])
        .as_array()
        .and_then(|summaries| summaries.first())
        .cloned()
        .unwrap_or_else(|| panic!("case {case:?}: expected the image set in the search, got {found:?}"));
    for member in ["createdAt", "updatedAt", "lastAccessedAt"] {
        assert_instant(&found, case, member, summary[member].as_f64());
    }

    // And the one instant only a landed deletion reports.
    let case = "GetImageSet after DeleteImageSet";
    let deleted = delete_image_set(&emulator, &datastore_id, &image_set_id).await;
    assert_eq!(
        deleted.status, 200,
        "case {case:?}: expected HTTP 200 from DeleteImageSet, got {deleted:?}"
    );
    let tombstone = poll_until_deleted(&emulator, case, &datastore_id, &image_set_id).await;
    assert_instant(
        &tombstone,
        case,
        "deletedAt",
        tombstone.field(&["deletedAt"]).as_f64(),
    );
}

/// RULE 2 (above): the output prefix a job reports is its OWN.
#[tokio::test]
async fn an_import_job_reports_the_output_prefix_of_its_own_results() {
    // (the case, the `outputS3Uri` the submit names)
    let rows = [
        ("the bucket alone", "s3://healthimaging-results"),
        (
            "a prefix ending in a slash",
            "s3://healthimaging-results/out/",
        ),
        ("a prefix ending in no slash", "s3://healthimaging-results/out"),
        (
            "a nested prefix",
            "s3://healthimaging-results/out/2026/01/",
        ),
        (
            "a prefix whose last segment reads like a file",
            "s3://healthimaging.results-1/manifest.json",
        ),
    ];

    for (index, (case, output_s3_uri)) in rows.iter().enumerate() {
        let emulator = Emulator::new();
        let datastore_id = emulator
            .active_datastore("output.store", "token-output-store")
            .await;

        // TWO jobs against the one output prefix, so the rule that each reports its own
        // folder is what is asserted rather than that the prefix comes back at all.
        let mut reported = Vec::new();
        for job in 0..2 {
            let token = format!("token-output-{index}-{job}");
            let started =
                start_import(&emulator, case, &datastore_id, &token, output_s3_uri).await;
            let job_id = started.string(&["jobId"]);
            let read = emulator.get_import_job(&datastore_id, &job_id).await;
            assert_eq!(
                read.status, 200,
                "case {case:?} job {job}: expected HTTP 200 from GetDICOMImportJob, got {read:?}"
            );
            // The prefix the submit named, with THIS job's folder under it — `/` added
            // only where the named prefix does not already end in one.
            let folder = format!("{datastore_id}-DicomImport-{job_id}/");
            let expected = if output_s3_uri.ends_with('/') {
                format!("{output_s3_uri}{folder}")
            } else {
                format!("{output_s3_uri}/{folder}")
            };
            let answered = read.string(&["jobProperties", "outputS3Uri"]);
            assert_eq!(
                answered, expected,
                "case {case:?} job {job}: expected the job's own output prefix {expected:?}, \
                 got {read:?}"
            );
            reported.push(answered);
        }
        assert_ne!(
            reported[0], reported[1],
            "case {case:?}: two jobs under one output prefix must report two prefixes, got \
             {reported:?}"
        );
    }
}
