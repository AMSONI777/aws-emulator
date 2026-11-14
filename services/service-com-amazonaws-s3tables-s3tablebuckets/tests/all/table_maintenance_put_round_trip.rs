// SPDX-License-Identifier: CC0-1.0

//! Generated coverage of what `PutTableMaintenanceConfiguration` persists.
//!
//! The rule under test is an invariant, so the rows are GENERATED rather than
//! listed: a put persists exactly the configuration it carries for exactly the
//! maintenance task it names, so a later read reports that configuration with
//! every member the put left out filled in from that task's service default,
//! reports the task the put did not address under its own default, and answers
//! the same again when the identical put is replayed (the put is idempotent)
//! and when nothing but a read happens in between (the read writes nothing).
//!
//! The generator varies everything the rule generalises over — which task is
//! addressed, whether a status travels and which one, whether settings travel
//! at all and which of their members do, and the value of each member — so the
//! configurations graded here are a sample of the whole modeled value space
//! rather than any one recorded request. Its seed is printed, it is bounded to
//! [`CASES`] configurations, and it writes nothing outside the emulator's own
//! in-memory state.
//!
//! The table-driven rows of the same rule, the modeled refusals and the
//! defaults a table is maintained under live in `table_maintenance_configuration.rs`,
//! whose helpers this suite drives rather than restating.

use std::ops::RangeInclusive;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{json, Map, Value};
use service_com_amazonaws_s3tables_s3tablebuckets as s3tables;

use s3tables::state::TableMaintenanceType;

use super::harness::Emulator;
use super::table_maintenance_configuration::{
    create_table, reported_task, stored_tasks, Reported, DEFAULT_COMPACTION,
    DEFAULT_SNAPSHOT_MANAGEMENT,
};

/// How many generated configurations one run grades. Bounded, so the suite
/// stays a fast in-process suite rather than an open-ended search.
const CASES: usize = 24;

/// The seed the generator runs from when the environment names none, so a run
/// is reproducible by default and a failure is reproducible from the seed the
/// test prints.
const DEFAULT_SEED: u64 = 0x5331_5441_424c_4553;

/// The environment variable that replays another seed.
const SEED_VARIABLE: &str = "S3TABLES_MAINTENANCE_SEED";

/// Every value of `com.amazonaws.s3tables#MaintenanceStatus`.
const STATUSES: &[&str] = &["enabled", "disabled"];

/// Every value of `com.amazonaws.s3tables#IcebergCompactionStrategy`.
const STRATEGIES: &[&str] = &["auto", "binpack", "sort", "z-order"];

/// The compaction target file sizes the generator draws from: the window the S3
/// Tables maintenance documentation states compaction supports, whose upper
/// bound is also the default target size. Staying inside it keeps every
/// generated row a configuration the service accepts, so the invariant under
/// test is about what a put persists and not about which sizes it refuses.
const SUPPORTED_TARGET_FILE_SIZE_MB: RangeInclusive<i64> = 64..=512;

/// The snapshot counts the generator draws from — small, since the invariant is
/// about the value travelling through unchanged and not about the number
/// itself.
const GENERATED_MIN_SNAPSHOTS_TO_KEEP: RangeInclusive<i64> = 1..=10;

/// The snapshot ages, in hours, the generator draws from: a month either side
/// of the 120-hour default.
const GENERATED_MAX_SNAPSHOT_AGE_HOURS: RangeInclusive<i64> = 1..=720;

/// The seed this run generates from.
fn seed() -> u64 {
    std::env::var(SEED_VARIABLE)
        .ok()
        .and_then(|named| named.parse().ok())
        .unwrap_or(DEFAULT_SEED)
}

/// One generated configuration: the task it addresses, the `value` member it
/// travels as, and what a read must report for that task once it is persisted.
struct Generated {
    task: TableMaintenanceType,
    status: Option<&'static str>,
    settings: Option<Value>,
    expected: Reported,
}

impl Generated {
    /// The `value` member of the `PutTableMaintenanceConfiguration` request.
    fn value(&self) -> Value {
        let mut value = Map::new();
        if let Some(status) = self.status {
            value.insert("status".to_string(), json!(status));
        }
        if let Some(settings) = &self.settings {
            value.insert("settings".to_string(), settings.clone());
        }
        Value::Object(value)
    }
}

/// One in `1 / denominator` draws leaves a member out, so a generated
/// configuration carries most of its members most of the time and every subset
/// of them over a run.
fn present(rng: &mut StdRng) -> bool {
    rng.random_bool(0.75)
}

/// One element of `choices`.
fn one_of<'a>(rng: &mut StdRng, choices: &[&'a str]) -> &'a str {
    choices[rng.random_range(0..choices.len())]
}

/// A configuration for the compaction task, with the configuration a read must
/// report for it.
fn generated_compaction(rng: &mut StdRng, status: Option<&'static str>) -> Generated {
    let (default_status, default_target, default_strategy) = DEFAULT_COMPACTION;
    let carries_settings = present(rng);
    let target = (carries_settings && present(rng))
        .then(|| rng.random_range(SUPPORTED_TARGET_FILE_SIZE_MB.clone()));
    let strategy = (carries_settings && present(rng)).then(|| one_of(rng, STRATEGIES));

    let settings = carries_settings.then(|| {
        let mut members = Map::new();
        if let Some(target) = target {
            members.insert("targetFileSizeMB".to_string(), json!(target));
        }
        if let Some(strategy) = strategy {
            members.insert("strategy".to_string(), json!(strategy));
        }
        json!({ "icebergCompaction": Value::Object(members) })
    });

    Generated {
        task: TableMaintenanceType::IcebergCompaction,
        status,
        settings,
        expected: Reported::Compaction(
            Some(status.unwrap_or(default_status).to_string()),
            Some(target.unwrap_or(default_target)),
            Some(strategy.unwrap_or(default_strategy).to_string()),
        ),
    }
}

/// A configuration for the snapshot management task, with the configuration a
/// read must report for it.
fn generated_snapshot_management(rng: &mut StdRng, status: Option<&'static str>) -> Generated {
    let (default_status, default_minimum, default_age) = DEFAULT_SNAPSHOT_MANAGEMENT;
    let carries_settings = present(rng);
    let minimum = (carries_settings && present(rng))
        .then(|| rng.random_range(GENERATED_MIN_SNAPSHOTS_TO_KEEP.clone()));
    let age = (carries_settings && present(rng))
        .then(|| rng.random_range(GENERATED_MAX_SNAPSHOT_AGE_HOURS.clone()));

    let settings = carries_settings.then(|| {
        let mut members = Map::new();
        if let Some(minimum) = minimum {
            members.insert("minSnapshotsToKeep".to_string(), json!(minimum));
        }
        if let Some(age) = age {
            members.insert("maxSnapshotAgeHours".to_string(), json!(age));
        }
        json!({ "icebergSnapshotManagement": Value::Object(members) })
    });

    Generated {
        task: TableMaintenanceType::IcebergSnapshotManagement,
        status,
        settings,
        expected: Reported::SnapshotManagement(
            Some(status.unwrap_or(default_status).to_string()),
            Some(minimum.unwrap_or(default_minimum)),
            Some(age.unwrap_or(default_age)),
        ),
    }
}

/// One generated configuration.
fn generate(rng: &mut StdRng) -> Generated {
    // A configuration that carries no status at all is as modeled as one that
    // carries either value, so the status is drawn from the modeled values plus
    // absence.
    let status = present(rng).then(|| one_of(rng, STATUSES));
    if rng.random_bool(0.5) {
        generated_compaction(rng, status)
    } else {
        generated_snapshot_management(rng, status)
    }
}

/// The configuration the task the put did not address runs under: its own
/// default, since no put ever touched it.
fn untouched(kind: TableMaintenanceType) -> Reported {
    match kind {
        TableMaintenanceType::IcebergCompaction => Reported::default_compaction(),
        TableMaintenanceType::IcebergSnapshotManagement => Reported::default_snapshot_management(),
    }
}

#[tokio::test]
async fn a_generated_put_is_what_the_read_reports_for_the_task_it_addressed() {
    let seed = seed();
    // The seed, so a failing run is replayed by setting it back.
    println!("{SEED_VARIABLE}={seed}");
    let mut rng = StdRng::seed_from_u64(seed);

    let emulator = Emulator::new();
    let region = "us-east-1";
    let namespace = "generated";

    for index in 0..CASES {
        let generated = generate(&mut rng);
        let bucket = format!("maintenance-generated-{index}");
        let table = format!("t{index}");
        let (bucket_arn, table_arn) =
            create_table(&emulator, region, &bucket, namespace, &table).await;
        let value = generated.value();
        let case = format!(
            "seed {seed} case {index}: {task} {value}",
            task = generated.task.as_wire()
        );

        let put = emulator
            .put_table_maintenance_configuration(
                region,
                &bucket_arn,
                namespace,
                &table,
                generated.task.as_wire(),
                &value,
            )
            .await;
        assert_eq!(
            put.status, 204,
            "case {case:?}: the put must answer the modeled 204, got {status} {body}",
            status = put.status,
            body = put.body
        );
        assert_eq!(
            put.body,
            Value::Null,
            "case {case:?}: the put must carry no body, got {body}",
            body = put.body
        );

        // The put persists the task it addressed, and nothing else: the store
        // holds one configuration, under that task's key.
        let stored = stored_tasks(&emulator, &table_arn);
        assert_eq!(
            stored,
            vec![generated.task.as_wire().to_string()],
            "case {case:?}: expected the store to hold only {task:?}, got {stored:?}",
            task = generated.task.as_wire()
        );

        let read = emulator
            .get_table_maintenance_configuration(region, &bucket_arn, namespace, &table)
            .await;
        let actual = reported_task(&read, &case, generated.task);
        assert_eq!(
            actual, generated.expected,
            "case {case:?}: expected {expected:?}, got {actual:?}",
            expected = generated.expected
        );

        // The put settles ONE task: the other still runs under its default.
        for other in TableMaintenanceType::ALL
            .iter()
            .copied()
            .filter(|kind| *kind != generated.task)
        {
            let expected = untouched(other);
            let reported = reported_task(&read, &case, other);
            assert_eq!(
                reported, expected,
                "case {case:?}: {kind} was not addressed, so expected {expected:?}, got \
                 {reported:?}",
                kind = other.as_wire()
            );
        }

        // Replaying the identical put leaves the same configuration in force:
        // the put is idempotent, so a client that retries it reads back what
        // the first one persisted.
        let replayed = emulator
            .put_table_maintenance_configuration(
                region,
                &bucket_arn,
                namespace,
                &table,
                generated.task.as_wire(),
                &value,
            )
            .await;
        assert_eq!(
            replayed.status, 204,
            "case {case:?}: replaying the put must answer the modeled 204, got {status} {body}",
            status = replayed.status,
            body = replayed.body
        );
        let after_replay = reported_task(
            &emulator
                .get_table_maintenance_configuration(region, &bucket_arn, namespace, &table)
                .await,
            &case,
            generated.task,
        );
        assert_eq!(
            after_replay, generated.expected,
            "case {case:?}: replaying the same put must leave {expected:?} in force, got \
             {after_replay:?}",
            expected = generated.expected
        );

        // And a read changes nothing a later caller sees.
        let read_again = reported_task(
            &emulator
                .get_table_maintenance_configuration(region, &bucket_arn, namespace, &table)
                .await,
            &case,
            generated.task,
        );
        assert_eq!(
            read_again, after_replay,
            "case {case:?}: a second read must report {after_replay:?}, got {read_again:?}"
        );
        let stored_after_reads = stored_tasks(&emulator, &table_arn);
        assert_eq!(
            stored_after_reads,
            vec![generated.task.as_wire().to_string()],
            "case {case:?}: the reads must have persisted nothing, got {stored_after_reads:?}"
        );
    }
}
