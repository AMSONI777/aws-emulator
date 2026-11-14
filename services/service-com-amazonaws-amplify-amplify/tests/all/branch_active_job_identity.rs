// SPDX-License-Identifier: CC0-1.0

//! How a branch IDENTIFIES the job that is active on it.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` over a restJson1
//! request signed for the `amplify` signing name, and every upload follows the URL the
//! service published — so what is asserted is what an AWS SDK client would see.
//!
//! The rule under test, over a TABLE spanning the class it generalises over rather than
//! over one recorded job: a member that REPORTS a job's number carries it bare
//! (`JobSummary$jobId`, modelled `pattern ^[0-9]+$`), while a member that IDENTIFIES a
//! job's place among its branch's jobs carries that number in a fixed field of ten digits
//! — the last segment of `JobSummary$jobArn` and `Branch$activeJobId` (modelled
//! `length 0..1000` with no pattern, so the form is the service's rather than the model's,
//! `smithy_query(query="shape",shape="Branch")`). The two forms therefore agree digit for
//! digit once the padding is stripped, which is the correlation a client performs, and the
//! rule holds whatever the width of the number and whichever call started the job.

use serde_json::{json, Value};

use crate::app_branch_lifecycle::{string_member, Emulator, Reply};

/// How wide the fixed job-number field is.
///
/// Recorded rather than modelled: `JobArn` is free text and `ActiveJobId` carries no
/// pattern, and Amplify writes the job number into a ten-digit field of leading zeroes in
/// both.
const JOB_NUMBER_FIELD_DIGITS: usize = 10;

/// How many jobs each row of the table starts, which carries the number past its first
/// decade so the field is asserted at more than one width of number.
const JOBS_PER_BRANCH: u64 = 11;

/// The job number in the fixed field every identifying member carries it in.
fn in_the_number_field(job_id: &str) -> String {
    format!("{job_id:0>width$}", width = JOB_NUMBER_FIELD_DIGITS)
}

/// `StartJob` over the wire.
async fn start_job(emulator: &Emulator, app_id: &str, branch: &str, request: &Value) -> Reply {
    emulator
        .call(
            "POST",
            &format!("/apps/{app_id}/branches/{branch}/jobs"),
            Some(request),
        )
        .await
}

/// `CreateDeployment` over the wire.
async fn create_deployment(emulator: &Emulator, app_id: &str, branch: &str) -> Reply {
    emulator
        .call(
            "POST",
            &format!("/apps/{app_id}/branches/{branch}/deployments"),
            Some(&json!({})),
        )
        .await
}

/// `StartDeployment` over the wire.
async fn start_deployment(
    emulator: &Emulator,
    app_id: &str,
    branch: &str,
    job_id: &str,
) -> Reply {
    emulator
        .call(
            "POST",
            &format!("/apps/{app_id}/branches/{branch}/deployments/start"),
            Some(&json!({ "jobId": job_id })),
        )
        .await
}

/// `StopJob` over the wire.
async fn stop_job(emulator: &Emulator, app_id: &str, branch: &str, job_id: &str) -> Reply {
    emulator
        .call(
            "DELETE",
            &format!("/apps/{app_id}/branches/{branch}/jobs/{job_id}/stop"),
            None,
        )
        .await
}

/// Follow an upload destination exactly as a client does: the `PUT` the service
/// published, against the URL it published.
async fn upload(emulator: &Emulator, case: &str, url: &str, body: &[u8]) {
    let request = http::Request::builder()
        .method("PUT")
        .uri(url)
        .body(bytes::Bytes::copy_from_slice(body))
        .expect("an upload destination is a well-formed URL");
    let status = emulator.dispatch(request).await.status().as_u16();
    assert_eq!(
        status, 200,
        "case {case:?}: the destination {url:?} must accept the upload, got {status}"
    );
}

/// A `.zip` carrying one entry per path named, as a real archive a deployment can be.
fn zip_of(paths: &[&str]) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut buffer);
    for path in paths {
        writer
            .start_file(*path, zip::write::SimpleFileOptions::default())
            .expect("an archive entry starts");
        std::io::Write::write_all(&mut writer, b"deployed").expect("an archive entry is written");
    }
    writer.finish().expect("the archive closes");
    buffer.into_inner()
}

/// A branch on `app_id`, and the ARN it answers with.
async fn branch_arn_of_new_branch(emulator: &Emulator, app_id: &str, branch: &str) -> String {
    let created = emulator
        .create_branch(app_id, &json!({ "branchName": branch }))
        .await;
    assert_eq!(
        created.status, 200,
        "app {app_id}: expected HTTP 200 from CreateBranch on {branch:?}, got {created:?}"
    );
    string_member(&created.member("branch"), "branchArn")
}

/// The three readings of one job's identity, asserted together: the summary's bare number,
/// the fixed field of its ARN, and the branch's own view of its active job.
async fn assert_one_identity(
    emulator: &Emulator,
    case: &str,
    app_id: &str,
    branch: &str,
    branch_arn: &str,
    summary: &Value,
    expected_number: &str,
) {
    let job_id = string_member(summary, "jobId");
    assert_eq!(
        job_id, expected_number,
        "case {case:?}: jobId reports the branch's bare job number, got {summary:?}"
    );
    let field = in_the_number_field(&job_id);
    assert_eq!(
        string_member(summary, "jobArn"),
        format!("{branch_arn}/jobs/{field}"),
        "case {case:?}: the ARN carries the number in its ten-digit field, got {summary:?}"
    );

    let record = emulator.get_branch(app_id, branch).await.member("branch");
    let active = string_member(&record, "activeJobId");
    assert_eq!(
        active, field,
        "case {case:?}: activeJobId identifies the job in the same ten-digit field, \
         got {record:?}"
    );
    // The correlation a client performs: the identified job and the reported number are
    // the same job once the field's padding is stripped.
    assert_eq!(
        active.trim_start_matches('0'),
        job_id,
        "case {case:?}: the identified job must be the job that was started, got {record:?}"
    );
}

#[tokio::test]
async fn a_started_build_is_identified_by_its_number_in_the_ten_digit_field() {
    let emulator = Emulator::new();
    // A repository app, because `StartJob` builds the app's connected repository.
    let app_id = emulator
        .app_id_of_new_repository_app("active-job-identity")
        .await;
    let branch_arn = branch_arn_of_new_branch(&emulator, &app_id, "main").await;

    for number in 1..=JOBS_PER_BRANCH {
        let case = format!("build {number}");
        let started = start_job(&emulator, &app_id, "main", &json!({ "jobType": "RELEASE" })).await;
        assert_eq!(
            started.status, 200,
            "case {case:?}: expected HTTP 200 from StartJob, got {started:?}"
        );
        assert_one_identity(
            &emulator,
            &case,
            &app_id,
            "main",
            &branch_arn,
            &started.member("jobSummary"),
            &number.to_string(),
        )
        .await;
    }
}

#[tokio::test]
async fn a_started_manual_deployment_is_identified_the_same_way() {
    let emulator = Emulator::new();
    let app_id = emulator.app_id_of_new_app("active-deployment-identity").await;

    // Two branches, so the deployment that is started runs under a one-digit number on
    // one and a two-digit number on the other: a branch numbers its own jobs, and the
    // second branch is carried past its first decade by reservations it then cancels —
    // which spends the numbers without leaving a job in flight.
    for (branch, spent, expected_number) in [("main", 0u64, "1"), ("second", 10u64, "11")] {
        let branch_arn = branch_arn_of_new_branch(&emulator, &app_id, branch).await;
        for number in 1..=spent {
            let case = format!("{branch}: spending number {number}");
            let reserved = create_deployment(&emulator, &app_id, branch).await;
            assert_eq!(
                reserved.status, 200,
                "case {case:?}: expected HTTP 200 from CreateDeployment, got {reserved:?}"
            );
            let stopped = stop_job(
                &emulator,
                &app_id,
                branch,
                &string_member(&reserved.body, "jobId"),
            )
            .await;
            assert_eq!(
                stopped.status, 200,
                "case {case:?}: expected HTTP 200 from StopJob, got {stopped:?}"
            );
        }

        let case = format!("{branch}: the deployment that is started");
        let reserved = create_deployment(&emulator, &app_id, branch).await;
        assert_eq!(
            reserved.status, 200,
            "case {case:?}: expected HTTP 200 from CreateDeployment, got {reserved:?}"
        );
        let job_id = string_member(&reserved.body, "jobId");
        upload(
            &emulator,
            &case,
            &string_member(&reserved.body, "zipUploadUrl"),
            &zip_of(&["index.html"]),
        )
        .await;
        let started = start_deployment(&emulator, &app_id, branch, &job_id).await;
        assert_eq!(
            started.status, 200,
            "case {case:?}: expected HTTP 200 from StartDeployment, got {started:?}"
        );
        assert_one_identity(
            &emulator,
            &case,
            &app_id,
            branch,
            &branch_arn,
            &started.member("jobSummary"),
            expected_number,
        )
        .await;
    }
}
