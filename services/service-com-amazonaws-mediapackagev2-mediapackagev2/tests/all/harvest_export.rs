// SPDX-License-Identifier: CC0-1.0

//! What a harvest job LEAVES BEHIND in its destination, and which terminal status that
//! decides.
//!
//! THE RULE UNDER TEST. A harvest job exports the manifests it names to the S3 destination
//! the submission carried: `CreateHarvestJob` "Creates a new harvest job to export content
//! from a MediaPackage v2 channel to an S3 bucket", `S3DestinationConfig$BucketName` is
//! "The name of an S3 bucket within which harvested content will be exported" and its
//! `DestinationPath` "The path within the specified S3 bucket where the harvested content
//! will be placed"
//! (`smithy_query(query="shape",shape="com.amazonaws.mediapackagev2#S3DestinationConfig",model_path="services/service-com-amazonaws-mediapackagev2-mediapackagev2/smithy-model/com-amazonaws-mediapackagev2-mediapackagev2.json")`).
//! So once the clock has made a job's harvest due, one manifest per harvested name IS an
//! object beneath that path of that bucket, and the job's terminal status is the OUTCOME of
//! that export: `COMPLETED` with no `ErrorMessage` where the object store took them, and
//! `FAILED` carrying the destination requirement where it could not.
//!
//! Every case drives real HTTP through the `MultiServiceRouter` over ONE engine carrying
//! this service's store and Amazon S3's — the way the assembled emulator runs them — so
//! each destination bucket is created with a real `CreateBucket` and each harvested manifest
//! is read back with a real `GetObject`.
//!
//! The rows differ along what the rule generalises over: the harvested FAMILY (HLS,
//! low-latency HLS, DASH, and several at once), how many names one family carries, the shape
//! of the destination path (nested, bare, trailing separator) and which bucket it is in. The
//! failure side varies how the destination stops being writable AFTER the submission was
//! accepted. A destination that could not be written to WHEN THE JOB WAS SUBMITTED is
//! refused outright rather than submitted — `tests/all/harvest_destination.rs` is the suite
//! for that pre-flight.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use service_com_amazonaws_mediapackagev2_mediapackagev2::state;
use smithy_server_runtime::MultiServiceRouter;

/// The Region every request below is signed for, and the one its buckets are created in.
const REGION: &str = "us-west-2";

/// The channel group and channel every endpoint under test hangs off, matching the model's
/// `ResourceName` pattern `^[a-zA-Z0-9_-]+$`.
const GROUP: &str = "export-group";
/// See [`GROUP`].
const CHANNEL: &str = "export-channel";

/// `HarvestJobStatus` values this suite waits for, from the model's enum.
const QUEUED: &str = "QUEUED";
/// See [`QUEUED`].
const COMPLETED: &str = "COMPLETED";
/// See [`QUEUED`].
const FAILED: &str = "FAILED";

/// The media types a harvested manifest is stored under, as the service writes them.
const HLS_MEDIA_TYPE: &str = "application/vnd.apple.mpegurl";
/// See [`HLS_MEDIA_TYPE`].
const DASH_MEDIA_TYPE: &str = "application/dash+xml";

/// How often a row looks for the status the clock owes a job, and how long it keeps
/// looking.
///
/// The deadline is generous: it bounds a condition that has already been reached on an
/// idle machine in a few seconds, so a loaded or slower host only polls more times. What is
/// asserted is the CONDITION, never the elapsed time.
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// See [`POLL_INTERVAL`].
const POLL_DEADLINE: Duration = Duration::from_secs(120);

/// One emulator: this service and Amazon S3 on a single shared engine behind the production
/// router — what `core/router` assembles, narrowed to the two services the rule spans.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    // This suite signs nothing: it exercises handler behaviour, not authentication.
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_mediapackagev2_mediapackagev2::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
        Arc::clone(&engine),
    ));
    router
}

/// What one request to a service's front door answered: the status, the `Content-Type` it
/// was served with, and the body bytes.
struct Answer {
    status: u16,
    media_type: String,
    body: Vec<u8>,
}

/// One request to the front door of `signing_name`, signed for [`REGION`].
async fn send(
    router: &MultiServiceRouter,
    method: &str,
    signing_name: &str,
    path: &str,
    body: &[u8],
) -> Answer {
    let host = format!("{signing_name}.{REGION}.amazonaws.com");
    let request = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", &host)
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDTEST/20260101/{REGION}/{signing_name}/\
                 aws4_request, SignedHeaders=host, Signature=0123456789abcdef"
            ),
        )
        .header("content-type", "application/json")
        .body(bytes::Bytes::copy_from_slice(body))
        .expect("a well-formed test request");
    let response = router.dispatch(request).await;
    Answer {
        status: response.status().as_u16(),
        media_type: response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        body: response.body().to_vec(),
    }
}

/// One MediaPackageV2 control-plane request, with the body parsed as JSON.
async fn call(
    router: &MultiServiceRouter,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let payload = body.map(|value| value.to_string()).unwrap_or_default();
    let answered = send(router, method, "mediapackagev2", path, payload.as_bytes()).await;
    let parsed = if answered.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&answered.body).unwrap_or(Value::Null)
    };
    (answered.status, parsed)
}

/// `PUT /<bucket>` — `CreateBucket` through Amazon S3's own front door.
async fn create_bucket(router: &MultiServiceRouter, bucket: &str) {
    let body = format!(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <LocationConstraint>{REGION}</LocationConstraint>\
         </CreateBucketConfiguration>"
    );
    let answered = send(router, "PUT", "s3", &format!("/{bucket}"), body.as_bytes()).await;
    assert_eq!(
        answered.status,
        200,
        "the destination bucket {bucket:?} must be created first, got {} {:?}",
        answered.status,
        String::from_utf8_lossy(&answered.body)
    );
}

/// `DELETE /<bucket>` — `DeleteBucket`, which a bucket holding no object accepts.
async fn delete_bucket(router: &MultiServiceRouter, bucket: &str) {
    let answered = send(router, "DELETE", "s3", &format!("/{bucket}"), &[]).await;
    assert_eq!(
        answered.status,
        204,
        "the destination bucket {bucket:?} must be removable, got {} {:?}",
        answered.status,
        String::from_utf8_lossy(&answered.body)
    );
}

/// `GET /<bucket>/<key>` — `GetObject` through Amazon S3's own front door.
async fn get_object(router: &MultiServiceRouter, bucket: &str, key: &str) -> Answer {
    send(router, "GET", "s3", &format!("/{bucket}/{key}"), &[]).await
}

/// Create the channel group and channel every endpoint under test hangs off.
async fn provision(router: &MultiServiceRouter) {
    let (status, body) = call(
        router,
        "POST",
        "/channelGroup",
        Some(json!({"ChannelGroupName": GROUP})),
    )
    .await;
    assert_eq!(status, 200, "setup: CreateChannelGroup got {status} {body}");
    let (status, body) = call(
        router,
        "POST",
        &format!("/channelGroup/{GROUP}/channel"),
        Some(json!({"ChannelName": CHANNEL})),
    )
    .await;
    assert_eq!(status, 200, "setup: CreateChannel got {status} {body}");
}

/// Epoch seconds, `offset` from now.
fn epoch_seconds_from_now(offset: f64) -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs_f64()
        + offset
}

/// One harvest under test: the endpoint it exports from, what it harvests, where it writes,
/// and which objects that must leave in the destination.
struct Row {
    /// What a failing assertion calls this row.
    case: &'static str,
    endpoint: &'static str,
    job: &'static str,
    /// The container type the endpoint packages with, which decides the manifest families
    /// it may publish.
    container_type: &'static str,
    /// The manifest names the endpoint publishes, per family.
    hls: &'static [&'static str],
    low_latency_hls: &'static [&'static str],
    dash: &'static [&'static str],
    /// The names the job harvests, per family — a subset of what the endpoint publishes.
    harvested_hls: &'static [&'static str],
    harvested_low_latency_hls: &'static [&'static str],
    harvested_dash: &'static [&'static str],
    bucket: &'static str,
    path: &'static str,
    /// Every object the harvest must leave, as `(key, media type)`.
    expected: &'static [(&'static str, &'static str)],
}

/// The harvests this suite drives, one row per point of the class the rule generalises
/// over.
const ROWS: &[Row] = &[
    Row {
        case: "one HLS manifest, a nested path",
        endpoint: "export-hls",
        job: "export-hls-job",
        container_type: "TS",
        hls: &["index"],
        low_latency_hls: &[],
        dash: &[],
        harvested_hls: &["index"],
        harvested_low_latency_hls: &[],
        harvested_dash: &[],
        bucket: "export-harvests",
        path: "harvests/2026/01/01/",
        expected: &[("harvests/2026/01/01/index.m3u8", HLS_MEDIA_TYPE)],
    },
    Row {
        case: "two HLS manifests of one endpoint, a bare path",
        endpoint: "export_two_hls",
        job: "export-two-hls-job",
        container_type: "TS",
        hls: &["primary", "secondary"],
        low_latency_hls: &[],
        dash: &[],
        harvested_hls: &["primary", "secondary"],
        harvested_low_latency_hls: &[],
        harvested_dash: &[],
        bucket: "export-harvests",
        path: "out",
        expected: &[
            ("out/primary.m3u8", HLS_MEDIA_TYPE),
            ("out/secondary.m3u8", HLS_MEDIA_TYPE),
        ],
    },
    Row {
        case: "one DASH manifest, a dotted bucket",
        endpoint: "Export3Dash",
        job: "Export3DashJob",
        container_type: "CMAF",
        hls: &["unharvested"],
        low_latency_hls: &[],
        dash: &["presentation"],
        harvested_hls: &[],
        harvested_low_latency_hls: &[],
        harvested_dash: &["presentation"],
        bucket: "export.harvests.two",
        path: "replay/",
        expected: &[("replay/presentation.mpd", DASH_MEDIA_TYPE)],
    },
    Row {
        case: "every harvestable family at once",
        endpoint: "export-all-families",
        job: "export-all-families-job",
        container_type: "CMAF",
        hls: &["hls-one"],
        low_latency_hls: &["ll-one"],
        dash: &["dash-one"],
        harvested_hls: &["hls-one"],
        harvested_low_latency_hls: &["ll-one"],
        harvested_dash: &["dash-one"],
        bucket: "export-harvests-third",
        path: "all/families/",
        expected: &[
            ("all/families/hls-one.m3u8", HLS_MEDIA_TYPE),
            ("all/families/ll-one.m3u8", HLS_MEDIA_TYPE),
            ("all/families/dash-one.mpd", DASH_MEDIA_TYPE),
        ],
    },
];

/// The manifest list a create or a harvest body carries for one family.
fn manifest_list(names: &[&str]) -> Value {
    Value::Array(
        names
            .iter()
            .map(|name| json!({"ManifestName": name}))
            .collect(),
    )
}

/// Create the origin endpoint `row` harvests, publishing the manifests it names.
async fn create_endpoint(router: &MultiServiceRouter, row: &Row) {
    let mut body = json!({
        "OriginEndpointName": row.endpoint,
        "ContainerType": row.container_type,
    });
    for (member, names) in [
        ("HlsManifests", row.hls),
        ("LowLatencyHlsManifests", row.low_latency_hls),
        ("DashManifests", row.dash),
    ] {
        if !names.is_empty() {
            body[member] = manifest_list(names);
        }
    }
    let (status, answered) = call(
        router,
        "POST",
        &format!("/channelGroup/{GROUP}/channel/{CHANNEL}/originEndpoint"),
        Some(body),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {:?}: CreateOriginEndpoint expected 200, got {status} {answered}",
        row.case
    );
}

/// The job collection of `row`'s endpoint.
fn jobs_path(endpoint: &str) -> String {
    format!("/channelGroup/{GROUP}/channel/{CHANNEL}/originEndpoint/{endpoint}/harvestJob")
}

/// Submit `row`'s harvest job to `bucket`, over a window that has opened and closes almost
/// at once, so the export the clock owes falls due while the row runs.
async fn submit(router: &MultiServiceRouter, row: &Row, bucket: &str) {
    let now = epoch_seconds_from_now(0.0);
    let mut harvested = json!({});
    for (member, names) in [
        ("HlsManifests", row.harvested_hls),
        ("LowLatencyHlsManifests", row.harvested_low_latency_hls),
        ("DashManifests", row.harvested_dash),
    ] {
        if !names.is_empty() {
            harvested[member] = manifest_list(names);
        }
    }
    let (status, created) = call(
        router,
        "POST",
        &jobs_path(row.endpoint),
        Some(json!({
            "HarvestJobName": row.job,
            "HarvestedManifests": harvested,
            "ScheduleConfiguration": {"StartTime": now - 5.0, "EndTime": now + 1.0},
            "Destination": {"S3Destination": {
                "BucketName": bucket,
                "DestinationPath": row.path,
            }},
        })),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {:?}: CreateHarvestJob expected 200, got {status} {created}",
        row.case
    );
    assert_eq!(
        created["Status"].as_str().unwrap_or_default(),
        QUEUED,
        "case {:?}: a submitted job is accepted QUEUED, got {created}",
        row.case
    );
}

/// `GetHarvestJob` on `row`'s job.
async fn read_job(router: &MultiServiceRouter, row: &Row) -> Value {
    let (status, body) = call(
        router,
        "GET",
        &format!("{}/{}", jobs_path(row.endpoint), row.job),
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "case {:?}: GetHarvestJob expected 200, got {status} {body}",
        row.case
    );
    body
}

/// Read `row`'s job until the clock has taken it to a status it cannot leave, and answer
/// that reading.
///
/// Waits for the CONDITION rather than for a time: a job that has not reached one yet is
/// looked at again, until [`POLL_DEADLINE`] passes.
async fn await_terminal(router: &MultiServiceRouter, row: &Row) -> Value {
    let deadline = std::time::Instant::now() + POLL_DEADLINE;
    let mut last = Value::Null;
    while std::time::Instant::now() < deadline {
        last = read_job(router, row).await;
        let status = last["Status"].as_str().unwrap_or_default();
        if status == COMPLETED || status == FAILED || status == "CANCELLED" {
            return last;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!(
        "case {:?}: the job never reached a terminal status, last read {last}",
        row.case
    )
}

/// The status `ListHarvestJobs` reports for `row`'s job — the OTHER reporting path through
/// the same settlement.
async fn listed_status(router: &MultiServiceRouter, row: &Row) -> String {
    let (status, body) = call(
        router,
        "GET",
        &format!("/channelGroup/{GROUP}/harvestJob?maxResults=100"),
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "case {:?}: ListHarvestJobs expected 200, got {status} {body}",
        row.case
    );
    let items = body["Items"].as_array().cloned().unwrap_or_default();
    let item = items
        .iter()
        .find(|item| item["HarvestJobName"] == json!(row.job))
        .unwrap_or_else(|| panic!("case {:?}: the list must report the job: {body}", row.case));
    item["Status"].as_str().unwrap_or_default().to_string()
}

#[tokio::test]
async fn a_due_harvest_writes_its_manifests_and_then_reports_completed() {
    let router = emulator();
    provision(&router).await;
    for bucket in [
        "export-harvests",
        "export.harvests.two",
        "export-harvests-third",
    ] {
        create_bucket(&router, bucket).await;
    }

    // Every job is submitted first, so the clock runs each row's window down at once.
    for row in ROWS {
        create_endpoint(&router, row).await;
        submit(&router, row, row.bucket).await;
        // Before the clock has made the harvest due the destination holds nothing: the
        // export is work the clock owes, not something the submit did.
        for (key, _) in row.expected {
            let answered = get_object(&router, row.bucket, key).await;
            assert_eq!(
                answered.status, 404,
                "case {:?}: {key} must not be in the destination while the job is still \
                 {QUEUED}, got {}",
                row.case, answered.status
            );
        }
    }

    for row in ROWS {
        let case = row.case;
        let settled = await_terminal(&router, row).await;
        assert_eq!(
            settled["Status"].as_str().unwrap_or_default(),
            COMPLETED,
            "case {case:?}: a harvest whose manifests the destination took must report \
             {COMPLETED}, got {settled}"
        );
        assert_eq!(
            settled["ErrorMessage"], Value::Null,
            "case {case:?}: a job that met no issue reports no error message, got {settled}"
        );
        assert_eq!(
            listed_status(&router, row).await,
            COMPLETED,
            "case {case:?}: ListHarvestJobs must agree with GetHarvestJob about the status"
        );

        // The objects are in the destination, readable through Amazon S3's own front door,
        // each under the media type its family's manifest is served as.
        for (key, media_type) in row.expected {
            let answered = get_object(&router, row.bucket, key).await;
            let document = String::from_utf8_lossy(&answered.body).to_string();
            assert_eq!(
                answered.status, 200,
                "case {case:?}: the harvested manifest must be readable at {}/{key}, got {} \
                 {document:?}",
                row.bucket, answered.status
            );
            assert_eq!(
                answered.media_type, *media_type,
                "case {case:?}: expected {key} served as {media_type:?}, got {:?}",
                answered.media_type
            );
            // The document is the top-level manifest of its family: a closed playlist for
            // the HLS families, a static presentation for DASH.
            let marker = if *media_type == DASH_MEDIA_TYPE {
                "mediaPresentationDuration"
            } else {
                "#EXTM3U"
            };
            assert!(
                document.contains(marker),
                "case {case:?}: {key} must carry {marker:?}, got {document:?}"
            );
        }

        // And it stays there: a terminal job owes nothing further, so a later read neither
        // moves the status nor rotates the version of the job.
        let again = read_job(&router, row).await;
        for member in ["Status", "ETag", "ModifiedAt", "ErrorMessage"] {
            assert_eq!(
                again[member], settled[member],
                "case {case:?}: reading again must not move {member}, got {} where {} was \
                 reported",
                again[member], settled[member]
            );
        }
    }
}

#[tokio::test]
async fn a_harvest_whose_manifests_cannot_be_placed_reports_failed() {
    let router = emulator();
    provision(&router).await;
    // Each row's destination IS created — a submission naming a bucket the object store does
    // not hold is refused outright — and then DELETED while the job is still harvesting, so
    // by the time the clock makes the export due the manifests have nowhere to go. The
    // buckets differ in the form of their names, so the outcome is not a property of one
    // spelling.
    let doomed = ["export-doomed", "export.doomed.two", "doomed3", "dmd"];

    for (row, bucket) in ROWS.iter().zip(doomed) {
        create_endpoint(&router, row).await;
        create_bucket(&router, bucket).await;
        submit(&router, row, bucket).await;
        delete_bucket(&router, bucket).await;
    }

    for (row, bucket) in ROWS.iter().zip(doomed) {
        let case = row.case;
        let settled = await_terminal(&router, row).await;
        assert_eq!(
            settled["Status"].as_str().unwrap_or_default(),
            FAILED,
            "case {case:?}: a harvest whose manifests the destination {bucket:?} could not \
             take must report {FAILED}, got {settled}"
        );
        assert_eq!(
            settled["ErrorMessage"].as_str().unwrap_or_default(),
            state::harvest_destination::writable_destination_requirement(),
            "case {case:?}: a failed harvest reports the destination requirement it did not \
             meet, got {settled}"
        );
        for (key, _) in row.expected {
            let answered = get_object(&router, bucket, key).await;
            assert_ne!(
                answered.status, 200,
                "case {case:?}: a failed harvest must have left nothing at {bucket}/{key}"
            );
        }
    }
}
