// SPDX-License-Identifier: CC0-1.0

//! Carrying a due harvest OUT: what it writes to the destination, and which modelled
//! terminal status the outcome of that write decides.
//!
//! A harvest job EXPORTS the manifests it names to the caller's bucket. `CreateHarvestJob`
//! "Creates a new harvest job to export content from a MediaPackage v2 channel to an S3
//! bucket", `S3DestinationConfig$BucketName` is "The name of an S3 bucket within which
//! harvested content will be exported" and its `DestinationPath` "The path within the
//! specified S3 bucket where the harvested content will be placed"
//! (`smithy_query(query="shape",shape="com.amazonaws.mediapackagev2#S3DestinationConfig",model_path="services/service-com-amazonaws-mediapackagev2-mediapackagev2/smithy-model/com-amazonaws-mediapackagev2-mediapackagev2.json")`).
//! So a job this service carries out PRODUCES objects: one manifest per harvested name,
//! beneath that path of that bucket, which a client can then read back with `GetObject`.
//!
//! ## What decides the terminal status
//!
//! `HarvestJobStatus` is `QUEUED | IN_PROGRESS | CANCELLED | COMPLETED | FAILED` and
//! `HarvestJob$ErrorMessage` is "An error message if the harvest job encountered any
//! issues", so the status a job the clock has ended reports is the OUTCOME of its export:
//! `COMPLETED`, carrying no error, when the object store took every object the job owed,
//! and `FAILED` when it did not — the bucket the submission named is one the store no
//! longer holds, the write was refused, or nothing answered the write at all (an assembly
//! with no object store). Every one of those is the same fact about the harvest: its output
//! is not where the submission said it would be, which is the destination requirement
//! `CreateHarvestJob` pre-flights a submission against
//! ([`super::harvest_destination::writable_destination_requirement`]) — so the sentence a
//! failed job reports is that same requirement rather than prose of this emulator's own.
//!
//! ## Where the destination is reached
//!
//! Amazon S3 is reached the way any emulated service reaches another: the AWS SDK driven
//! over the operation callback ([`smithy_server_runtime::OperationContext::callback`]),
//! through the tree's ONE construction of that client
//! (`service_common::s3_client::s3_client`), which routes IN PROCESS — no socket, no
//! outbound request, no host resolution. The object a harvest writes is therefore the
//! object a client's own `GetObject` reads, and the per-bucket rules of the write (does the
//! bucket exist, what does it take) stay the object store's own, asked through its front
//! door rather than re-decided here.
//!
//! ## What a harvested manifest says
//!
//! Each object is the top-level manifest of its family, named as this service names that
//! family's manifest file ([`super::ManifestKind`]: an `.m3u8` playlist for the HLS
//! families, an `.mpd` for DASH), and it states only what this emulator knows: the window
//! the job was scheduled for, and the segment duration the endpoint was created with. What
//! a channel of this emulator ingests is served to a viewer as it was pushed and is never
//! repackaged (see `crate::service`), so no rendition or segment of a harvested window
//! exists here, and a manifest naming segments or bitrates would describe content that is
//! not in the destination.

use super::*;

/// The media type each family's top-level manifest is written as: the type registered for
/// an HLS playlist, and the one registered for an MPEG-DASH MPD.
pub const HLS_MANIFEST_MEDIA_TYPE: &str = "application/vnd.apple.mpegurl";
/// See [`HLS_MANIFEST_MEDIA_TYPE`].
pub const DASH_MANIFEST_MEDIA_TYPE: &str = "application/dash+xml";

/// The most harvests ONE call carries out, which is what bounds the work a single request
/// pays for. The rest keep the instant they were owed at and are taken by the next call.
const MAX_HARVESTS_PER_CALL: usize = 8;

/// Where one stored harvest job lives: its Region and the containment path that addresses
/// it, so the outcome of its export is recorded against that job and no other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestJobKey {
    pub region: String,
    pub group: String,
    pub channel: String,
    pub endpoint: String,
    pub job: String,
}

/// One object a harvest writes: where in the destination bucket it goes, its bytes, and
/// the media type it is stored under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestedObject {
    /// The key within the destination bucket, beneath the submission's `DestinationPath`.
    pub key: String,
    pub body: Vec<u8>,
    pub media_type: &'static str,
}

/// One harvest the clock has made due, with the export it owes.
///
/// Taken out of the store under its guard
/// ([`ComAmazonawsMediapackagev2Mediapackagev2State::take_due_harvests`]) and carried out
/// with no guard held, which is why it owns everything it needs.
#[derive(Debug, Clone)]
pub struct DueHarvest {
    /// The stored job this export belongs to.
    pub job: HarvestJobKey,
    /// `S3DestinationConfig$BucketName`.
    pub bucket: String,
    /// One object per manifest name the submission harvested, in family order.
    pub objects: Vec<HarvestedObject>,
    /// The instant the export fell due, which the commit recording its outcome carries.
    pub due_at: ::aws_smithy_types::DateTime,
}

/// Which stored jobs one call settles: the Region and channel group it addressed, narrowed
/// by the names it carried.
///
/// A call settles the jobs it could report — the job a read names, the endpoint a write
/// touches, the group a list pages — so the work one request does is bounded by what that
/// request addressed rather than by everything the store holds.
#[derive(Debug, Clone, Copy)]
pub struct HarvestScope<'a> {
    pub region: &'a str,
    pub group: &'a str,
    pub channel: Option<&'a str>,
    pub endpoint: Option<&'a str>,
    pub job: Option<&'a str>,
}

impl<'a> HarvestScope<'a> {
    /// Every job of one channel group — what `ListHarvestJobs` reports over.
    pub fn group(region: &'a str, group: &'a str) -> Self {
        Self {
            region,
            group,
            channel: None,
            endpoint: None,
            job: None,
        }
    }

    /// Every job of one origin endpoint — what an update to that endpoint is judged
    /// against.
    pub fn endpoint(region: &'a str, group: &'a str, channel: &'a str, endpoint: &'a str) -> Self {
        Self {
            region,
            group,
            channel: Some(channel),
            endpoint: Some(endpoint),
            job: None,
        }
    }

    /// The ONE job a request names.
    pub fn job(
        region: &'a str,
        group: &'a str,
        channel: &'a str,
        endpoint: &'a str,
        job: &'a str,
    ) -> Self {
        Self {
            region,
            group,
            channel: Some(channel),
            endpoint: Some(endpoint),
            job: Some(job),
        }
    }
}

impl ComAmazonawsMediapackagev2Mediapackagev2State {
    /// Materialise what the clock owed every job in `scope` by `at`, and report the
    /// harvests whose EXPORT is now due, as the objects each one owes.
    ///
    /// Called under this store's guard by [`settle_due_harvests`], which then carries each
    /// export out with NO guard held. Only what was already owed at `at` is applied or
    /// reported — the work was due at that instant whether or not anybody called.
    ///
    /// A reported harvest keeps the instant it was owed at until its outcome is recorded
    /// ([`Self::record_harvest_outcome`], which is what ends the job), so an export whose
    /// call never finished — the request serving it was cancelled — is still owed and is
    /// carried out by the next call, rather than leaving the job reporting work in progress
    /// that nothing will ever finish. The cost of that choice is that two calls racing the
    /// same due harvest may both carry it out: both write the same manifests to the same
    /// keys, so the destination holds what it would have held either way.
    pub fn take_due_harvests(
        &mut self,
        scope: HarvestScope<'_>,
        at: ::aws_smithy_types::DateTime,
    ) -> Vec<DueHarvest> {
        let region = scope.region.to_string();
        let Some(group) = self.channel_group_mut(scope.region, scope.group) else {
            return Vec::new();
        };
        let mut due = Vec::new();
        let channels = group
            .channels
            .values_mut()
            .filter(|channel| scope.channel.is_none_or(|wanted| channel.name == wanted));
        for channel in channels {
            let endpoints = channel
                .origin_endpoints
                .values_mut()
                .filter(|endpoint| scope.endpoint.is_none_or(|wanted| endpoint.name == wanted));
            for endpoint in endpoints {
                // The endpoint's own packaging, read before its jobs are held for writing:
                // what the manifests a harvest of it writes state about its segments.
                let segment_duration_seconds = endpoint
                    .segment
                    .segment_duration_seconds
                    .unwrap_or(DEFAULT_SEGMENT_DURATION_SECONDS);
                let jobs = endpoint
                    .harvest_jobs
                    .values_mut()
                    .filter(|job| scope.job.is_none_or(|wanted| job.name == wanted));
                for job in jobs {
                    job.materialise_due_transitions(at);
                    let Some(due_at) = job.export_due_at(at) else {
                        continue;
                    };
                    if due.len() >= MAX_HARVESTS_PER_CALL {
                        return due;
                    }
                    due.push(DueHarvest {
                        job: HarvestJobKey {
                            region: region.clone(),
                            group: job.group_name.clone(),
                            channel: job.channel_name.clone(),
                            endpoint: job.endpoint_name.clone(),
                            job: job.name.clone(),
                        },
                        bucket: job.destination.s3_destination.bucket_name.clone(),
                        objects: harvested_objects(job, segment_duration_seconds),
                        due_at,
                    });
                }
            }
        }
        due
    }

    /// Record what a harvest this service carried out did: the modelled terminal status the
    /// outcome of its export decides, committed with the instant that export fell due.
    ///
    /// `exported` is whether the object store took every object the job owed, which is the
    /// one thing the status reports (see the module docs). A job that completed reports no
    /// error message; a job that failed reports the destination requirement it did not
    /// meet.
    ///
    /// A job that reached a terminal status while its export ran — it was cancelled, or
    /// another call carrying out the same due harvest got there first — keeps the status
    /// that gave it: a job never leaves a status it cannot leave.
    pub fn record_harvest_outcome(
        &mut self,
        key: &HarvestJobKey,
        exported: bool,
        due_at: ::aws_smithy_types::DateTime,
    ) {
        let Some(job) = self
            .channel_group_mut(&key.region, &key.group)
            .and_then(|group| group.channels.get_mut(&key.channel))
            .and_then(|channel| channel.origin_endpoints.get_mut(&key.endpoint))
            .and_then(|endpoint| endpoint.harvest_jobs.get_mut(&key.job))
        else {
            return;
        };
        if job.is_terminal() {
            return;
        }
        if exported {
            job.status = HARVEST_JOB_COMPLETED.to_string();
            job.error_message = None;
        } else {
            job.status = HARVEST_JOB_FAILED.to_string();
            job.error_message = Some(harvest_destination::writable_destination_requirement());
        }
        job.commit(due_at);
    }
}

/// Materialise every harvest in `scope` the clock has already made due: carry the export
/// out and record the terminal status its outcome decides.
///
/// Called FIRST by every handler that reports or acts on a harvest job's status, a read
/// included. It applies only what was owed at `at` whether or not anybody called, so what a
/// reader sees is decided by the clock and never by the read itself.
///
/// The store's guard is taken to collect the due harvests and again to record each outcome,
/// and is NOT held across the write: the export goes out through the object store's own
/// front door, which must not wait on this service's lock.
pub async fn settle_due_harvests<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    scope: HarvestScope<'_>,
    at: ::aws_smithy_types::DateTime,
) {
    let Some(state) = service_state(engine) else {
        return;
    };
    let due = state.lock().take_due_harvests(scope, at);
    for harvest in due {
        let exported = export(ctx, &harvest).await;
        state
            .lock()
            .record_harvest_outcome(&harvest.job, exported, harvest.due_at);
    }
}

/// Write one harvest's objects to its destination, answering whether the object store took
/// them ALL.
///
/// `false` for every answer that is not the store reporting an object stored, because they
/// all say the same thing about the harvest: its output is not beneath the path the
/// submission named. A submission that named no manifest owes no object, so there is
/// nothing the destination could refuse and the harvest is carried out in full.
async fn export(
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    harvest: &DueHarvest,
) -> bool {
    // The Region ends up in the AUTHORITY of the endpoint URL the client below is addressed
    // by, so it is held to the Region-label grammar first (the shared reading every service
    // that puts a stored Region in an authority uses); anything outside it addresses this
    // service's default Region instead. The transport is the in-process callback either
    // way.
    let region = ::service_common::arn::region_label(&harvest.job.region).unwrap_or(DEFAULT_REGION);
    let client = ::service_common::s3_client::s3_client(ctx.callback(), region);
    for object in &harvest.objects {
        let answer = client
            .put_object()
            .bucket(&harvest.bucket)
            .key(&object.key)
            .content_type(object.media_type)
            .body(::aws_sdk_s3::primitives::ByteStream::from(
                object.body.clone(),
            ))
            .send()
            .await;
        if let Err(error) = answer {
            // The destination's own values are rendered in their escaped `Debug` form, so a
            // value carrying a newline cannot forge a log line.
            ::tracing::debug!(
                bucket = ?harvest.bucket,
                key = ?object.key,
                error = %::aws_smithy_types::error::display::DisplayErrorContext(&error),
                "a harvest job's manifest was not written to its destination, so the job \
                 failed"
            );
            return false;
        }
    }
    true
}

/// The families a harvest job can name, which is what decides a harvested manifest's file
/// name and its media type.
///
/// The model's `HarvestedManifests` carries the HLS, low-latency HLS and DASH families
/// only, and the low-latency family publishes the same `.m3u8` playlist as plain HLS (see
/// [`super::ManifestKind`]), so the two share one entry here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HarvestedFamily {
    Hls,
    Dash,
}

impl HarvestedFamily {
    /// The manifest file this family publishes, which is what names the object a harvest of
    /// it writes: read off the ONE place this service names a manifest file, so a harvested
    /// object and the endpoint's own published URL cannot disagree about the suffix.
    fn kind(self) -> ManifestKind {
        match self {
            Self::Hls => ManifestKind::Hls,
            Self::Dash => ManifestKind::Dash,
        }
    }

    /// The media type this family's manifest is written as.
    fn media_type(self) -> &'static str {
        match self {
            Self::Hls => HLS_MANIFEST_MEDIA_TYPE,
            Self::Dash => DASH_MANIFEST_MEDIA_TYPE,
        }
    }
}

/// The objects a harvest of `job` writes: one top-level manifest per manifest name the
/// submission harvested, in the family order the model lists them in.
///
/// `segment_duration_seconds` is the duration the harvested endpoint was created with,
/// which the HLS playlist states as its target duration; the window is the one the job was
/// scheduled for.
///
/// One object per KEY: a submission may name the same manifest more than once (the model
/// puts no uniqueness constraint on the harvested lists), and the destination holds one
/// object per key however often it was named, so a repeat is not written again. That is
/// also what bounds this list — every harvested name resolves against a manifest the
/// endpoint publishes, and an endpoint publishes at most
/// [`MAX_MANIFESTS_PER_ORIGIN_ENDPOINT`] of them — rather than by how long a list the
/// submission carried.
pub fn harvested_objects(
    job: &HarvestJobRecord,
    segment_duration_seconds: i32,
) -> Vec<HarvestedObject> {
    let path = &job.destination.s3_destination.destination_path;
    let window_seconds = harvest_window_seconds(job);
    let mut objects: Vec<HarvestedObject> = Vec::new();
    let mut written: BTreeSet<String> = BTreeSet::new();
    let harvested = &job.harvested_manifests;
    let names = harvested
        .hls_manifests
        .iter()
        .flatten()
        .map(|manifest| (HarvestedFamily::Hls, manifest.manifest_name.as_str()))
        .chain(
            harvested
                .low_latency_hls_manifests
                .iter()
                .flatten()
                .map(|manifest| (HarvestedFamily::Hls, manifest.manifest_name.as_str())),
        )
        .chain(
            harvested
                .dash_manifests
                .iter()
                .flatten()
                .map(|manifest| (HarvestedFamily::Dash, manifest.manifest_name.as_str())),
        );
    for (family, name) in names {
        let key = destination_key(path, name, family.kind());
        if !written.insert(key.clone()) {
            continue;
        }
        objects.push(HarvestedObject {
            key,
            body: match family {
                HarvestedFamily::Hls => hls_playlist(segment_duration_seconds),
                HarvestedFamily::Dash => dash_manifest(window_seconds),
            }
            .into_bytes(),
            media_type: family.media_type(),
        });
    }
    objects
}

/// The key one harvested manifest is written at: the submission's `DestinationPath`, then
/// the manifest's own file name.
///
/// The path is a prefix within the bucket (`S3DestinationConfig$DestinationPath`: "The path
/// within the specified S3 bucket where the harvested content will be placed"), so one `/`
/// separates it from the file name however the caller wrote it — with a trailing separator,
/// without one, or as an absolute-looking path. A path of separators alone names the
/// bucket's own root.
pub fn destination_key(path: &str, manifest_name: &str, kind: ManifestKind) -> String {
    let prefix = path.trim_matches('/');
    let file = format!("{manifest_name}{}", kind.suffix());
    if prefix.is_empty() {
        file
    } else {
        format!("{prefix}/{file}")
    }
}

/// How long the window `job` was scheduled for is, in seconds — never negative: the create
/// refuses a submission whose end is not after its start.
fn harvest_window_seconds(job: &HarvestJobRecord) -> f64 {
    let start = job.schedule_configuration.start_time.as_secs_f64();
    let end = job.schedule_configuration.end_time.as_secs_f64();
    (end - start).max(0.0)
}

/// The playlist a harvest of an HLS or low-latency HLS manifest writes: a complete
/// presentation (`VOD`, closed with `EXT-X-ENDLIST`) whose target duration is the segment
/// duration the harvested endpoint was created with.
///
/// It names no segment, because this emulator repackages nothing it was pushed (see the
/// module docs): naming one would describe media that is not in the destination.
fn hls_playlist(segment_duration_seconds: i32) -> String {
    format!(
        "#EXTM3U\n\
         #EXT-X-VERSION:3\n\
         #EXT-X-PLAYLIST-TYPE:VOD\n\
         #EXT-X-TARGETDURATION:{segment_duration_seconds}\n\
         #EXT-X-ENDLIST\n"
    )
}

/// The MPD a harvest of a DASH manifest writes.
///
/// A harvested presentation is complete rather than live, which is what `type="static"`
/// says, and its length is the window the job was scheduled for:
/// `mediaPresentationDuration` and the one period's `duration` are that window. It carries
/// no adaptation set for the same reason the playlist above carries no segment.
fn dash_manifest(window_seconds: f64) -> String {
    let duration = iso8601_duration(window_seconds);
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\" \
         profiles=\"urn:mpeg:dash:profile:isoff-main:2011\" type=\"static\" \
         mediaPresentationDuration=\"{duration}\">\n\
         \x20 <Period id=\"1\" start=\"PT0S\" duration=\"{duration}\"/>\n\
         </MPD>\n"
    )
}

/// `seconds` as an ISO 8601 duration, which is the form a DASH manifest states one in. The
/// fractional part is written only when the span carries one, to the millisecond — the
/// resolution this service stores an instant at ([`super::now`]).
fn iso8601_duration(seconds: f64) -> String {
    let millis = (seconds * 1000.0).round().max(0.0) as i64;
    let whole = millis / 1000;
    let fraction = millis % 1000;
    if fraction == 0 {
        format!("PT{whole}S")
    } else {
        format!("PT{whole}.{fraction:03}S")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::types::{
        HarvestedDashManifest, HarvestedHlsManifest, HarvestedLowLatencyHlsManifest,
        HarvesterScheduleConfiguration, S3DestinationConfig,
    };

    /// A stored job harvesting `hls`, `low_latency` and `dash` to `path` over a window
    /// `length` seconds long, as `CreateHarvestJob` would have stored one.
    fn job(
        path: &str,
        length: f64,
        hls: &[&str],
        low_latency: &[&str],
        dash: &[&str],
    ) -> HarvestJobRecord {
        let start = ::aws_smithy_types::DateTime::from_secs_f64(1_767_225_600.0);
        HarvestJobRecord {
            name: "job".to_string(),
            group_name: "group".to_string(),
            channel_name: "channel".to_string(),
            endpoint_name: "endpoint".to_string(),
            arn: String::new(),
            description: None,
            harvested_manifests: HarvestedManifests {
                hls_manifests: Some(
                    hls.iter()
                        .map(|name| HarvestedHlsManifest {
                            manifest_name: (*name).to_string(),
                        })
                        .collect(),
                ),
                low_latency_hls_manifests: Some(
                    low_latency
                        .iter()
                        .map(|name| HarvestedLowLatencyHlsManifest {
                            manifest_name: (*name).to_string(),
                        })
                        .collect(),
                ),
                dash_manifests: Some(
                    dash.iter()
                        .map(|name| HarvestedDashManifest {
                            manifest_name: (*name).to_string(),
                        })
                        .collect(),
                ),
            },
            schedule_configuration: HarvesterScheduleConfiguration {
                start_time: start,
                end_time: ::aws_smithy_types::DateTime::from_secs_f64(
                    start.as_secs_f64() + length,
                ),
            },
            destination: Destination {
                s3_destination: S3DestinationConfig {
                    bucket_name: "bucket".to_string(),
                    destination_path: path.to_string(),
                },
            },
            status: HARVEST_JOB_IN_PROGRESS.to_string(),
            error_message: None,
            created_at: start,
            modified_at: start,
            in_progress_at: start,
            version: 1,
            etag: String::new(),
            tags: HashMap::new(),
            client_token: None,
            fingerprint: String::new(),
        }
    }

    /// A harvest writes one manifest per name it harvests, keyed beneath the submission's
    /// destination path and named as the family's manifest file is.
    ///
    /// The rows span what the rule generalises over: each harvestable family and several at
    /// once, the number of names in a family, and the FORM of the destination path (nested,
    /// bare, with and without a trailing separator, absolute-looking, separators alone).
    #[test]
    fn a_harvest_writes_one_manifest_per_harvested_name_beneath_the_destination_path() {
        /// One submitted harvest and the keys it must leave in the destination.
        struct Row {
            case: &'static str,
            path: &'static str,
            hls: &'static [&'static str],
            low_latency: &'static [&'static str],
            dash: &'static [&'static str],
            expected: &'static [&'static str],
        }
        let rows: &[Row] = &[
            Row {
                case: "one HLS manifest, a nested path",
                path: "harvests/2026/01/01/",
                hls: &["index"],
                low_latency: &[],
                dash: &[],
                expected: &["harvests/2026/01/01/index.m3u8"],
            },
            Row {
                case: "one HLS manifest, a bare path with no separator",
                path: "out",
                hls: &["index"],
                low_latency: &[],
                dash: &[],
                expected: &["out/index.m3u8"],
            },
            Row {
                case: "two DASH manifests, an absolute-looking path",
                path: "/replay/",
                hls: &[],
                low_latency: &[],
                dash: &["main", "backup"],
                expected: &["replay/main.mpd", "replay/backup.mpd"],
            },
            Row {
                case: "every family at once",
                path: "all",
                hls: &["hls-one"],
                low_latency: &["ll-one"],
                dash: &["dash-one"],
                expected: &["all/hls-one.m3u8", "all/ll-one.m3u8", "all/dash-one.mpd"],
            },
            Row {
                case: "a path of separators alone, which is the bucket root",
                path: "/",
                hls: &["index"],
                low_latency: &[],
                dash: &[],
                expected: &["index.m3u8"],
            },
            Row {
                case: "a name harvested twice, which is one object",
                path: "repeat/",
                hls: &["index", "index"],
                low_latency: &[],
                dash: &[],
                expected: &["repeat/index.m3u8"],
            },
            Row {
                case: "no manifest at all",
                path: "out/",
                hls: &[],
                low_latency: &[],
                dash: &[],
                expected: &[],
            },
        ];
        for Row {
            case,
            path,
            hls,
            low_latency,
            dash,
            expected,
        } in rows
        {
            let written = harvested_objects(&job(path, 60.0, hls, low_latency, dash), 6);
            let keys: Vec<&str> = written.iter().map(|object| object.key.as_str()).collect();
            assert_eq!(
                keys, *expected,
                "case {case:?}: expected the keys {expected:?}, got {keys:?}"
            );
            for object in &written {
                let expected_type = if object.key.ends_with(".mpd") {
                    DASH_MANIFEST_MEDIA_TYPE
                } else {
                    HLS_MANIFEST_MEDIA_TYPE
                };
                assert_eq!(
                    object.media_type, expected_type,
                    "case {case:?}: expected {} written as {expected_type:?}, got {:?}",
                    object.key, object.media_type
                );
                assert!(
                    !object.body.is_empty(),
                    "case {case:?}: {} must carry a manifest",
                    object.key
                );
            }
        }
    }

    /// What each manifest STATES: the HLS playlist is a closed VOD playlist whose target
    /// duration is the endpoint's segment duration, and the MPD states the window the job
    /// was scheduled for.
    ///
    /// The rows differ in the segment duration (both published bounds of the member's
    /// `@range` 1..30 and a value between them) and in the window's length and whether it
    /// carries a fraction.
    #[test]
    fn a_harvested_manifest_states_the_window_and_the_segment_duration() {
        let rows: &[(&str, i32, f64, &str)] = &[
            ("a minute, the default segment duration", 6, 60.0, "PT60S"),
            ("half an hour, the smallest segment duration", 1, 1800.0, "PT1800S"),
            ("ten and a quarter seconds, the largest", 30, 10.25, "PT10.250S"),
            ("a day", 4, 86_400.0, "PT86400S"),
        ];
        for (case, segment_duration, length, expected_duration) in rows {
            let record = job("out/", *length, &["index"], &[], &["dash"], );
            let written = harvested_objects(&record, *segment_duration);
            let playlist = String::from_utf8(written[0].body.clone())
                .unwrap_or_else(|_| panic!("case {case:?}: a playlist is text"));
            let target = format!("#EXT-X-TARGETDURATION:{segment_duration}\n");
            assert!(
                playlist.contains(&target) && playlist.contains("#EXT-X-ENDLIST"),
                "case {case:?}: the playlist must state {target:?} and be closed, got \
                 {playlist:?}"
            );
            let mpd = String::from_utf8(written[1].body.clone())
                .unwrap_or_else(|_| panic!("case {case:?}: an MPD is text"));
            let duration = format!("mediaPresentationDuration=\"{expected_duration}\"");
            assert!(
                mpd.contains(&duration) && mpd.contains("type=\"static\""),
                "case {case:?}: the MPD must state {duration:?}, got {mpd:?}"
            );
        }
    }
}
