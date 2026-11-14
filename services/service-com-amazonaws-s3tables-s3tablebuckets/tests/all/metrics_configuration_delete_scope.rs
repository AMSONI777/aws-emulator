// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of what `DeleteTableBucketMetricsConfiguration`
//! reaches, and of what it must leave alone.
//!
//! The rule under test: the delete of a sub-resource addressed by one table
//! bucket's ARN is refused with the bucket's own not-found when the store holds
//! no bucket at that ARN, and otherwise clears exactly that bucket's metrics
//! configuration — being `@idempotent` it answers the modeled 204 with no body
//! however many times it is called and whether or not a configuration was there
//! — while every other bucket's configuration and every other member of the
//! addressed bucket's own record are left exactly as they were.
//!
//! `table_bucket_metrics_configuration.rs` pins the put/read/delete round trip
//! on one bucket at a time; this suite pins the delete's REACH, which that
//! round trip cannot observe: the tables below span the ARNs a store does not
//! hold (never created, deleted, the same name in another region, another
//! account's), the buckets a store holds beside the addressed one, and the
//! other sub-resources of the addressed bucket.
//!
//! Every case drives the real wire path through the harness, so what is
//! asserted is what an AWS SDK client would see.

use serde_json::{json, Value};
use service_com_amazonaws_s3tables_s3tablebuckets as s3tables;

use s3tables::state::ComAmazonawsS3tablesS3tablebucketsState as S3TablesState;

use super::harness::{expected_bucket_arn, Emulator, Reply};

/// The fixed sentence this service states a table bucket that has no metrics
/// configuration with.
const NO_METRICS_CONFIGURATION: &str = "No such metric configuration exists";

/// The fixed sentence this service states a table bucket the store does not
/// hold with.
const NO_BUCKET: &str = "The specified bucket does not exist.";

/// One bucket a row of the reach table configures.
#[derive(Debug)]
struct Bucket {
    label: &'static str,
    region: &'static str,
    name: &'static str,
    /// How many times the delete is repeated once its turn comes. More than one
    /// exercises the operation's `@idempotent` trait.
    deletes: usize,
}

/// The buckets the reach table holds at once: they differ in region, in the
/// shape and length of the name (`TableBucketName` is `@length(3, 63)`), and in
/// how often the delete is repeated.
fn buckets() -> Vec<Bucket> {
    vec![
        Bucket {
            label: "a plain bucket, deleted once",
            region: "us-east-1",
            name: "metrics-reach-east",
            deletes: 1,
        },
        Bucket {
            label: "another region, the delete repeated",
            region: "eu-west-1",
            name: "metrics-reach-west",
            deletes: 2,
        },
        Bucket {
            // The shortest name a bucket can carry.
            label: "the shortest name a bucket can carry",
            region: "ap-south-1",
            name: "m3r",
            deletes: 3,
        },
        Bucket {
            label: "a long hyphenated name",
            region: "us-west-2",
            name: "metrics-reach-on-a-rather-long-table-bucket-name-here",
            deletes: 1,
        },
        Bucket {
            label: "the same name as the first row, in another region",
            region: "eu-central-1",
            name: "metrics-reach-east",
            deletes: 2,
        },
    ]
}

/// The id a read reports for `arn`, asserting the read succeeded.
async fn reported_id(emulator: &Emulator, region: &str, arn: &str, case: &str) -> String {
    let read = emulator
        .get_table_bucket_metrics_configuration(region, arn)
        .await;
    assert_eq!(
        read.status, 200,
        "case {case:?}: the read must succeed, got {status} {body}",
        status = read.status,
        body = read.body
    );
    let id = read.text("id");
    assert!(
        !id.is_empty(),
        "case {case:?}: expected a non-empty id, got {id:?}"
    );
    id
}

/// Asserts a reply is the modeled 204 with no body.
fn assert_empty_204(reply: &Reply, case: &str) {
    assert_eq!(
        reply.status, 204,
        "case {case:?}: expected the modeled 204, got {status} {body}",
        status = reply.status,
        body = reply.body
    );
    assert_eq!(
        reply.body,
        Value::Null,
        "case {case:?}: expected no body, got {body}",
        body = reply.body
    );
}

/// Asserts a reply is the bucket's own modeled not-found.
fn assert_bucket_not_found(reply: &Reply, case: &str) {
    assert_eq!(
        reply.status, 404,
        "case {case:?}: expected 404, got {status} {body}",
        status = reply.status,
        body = reply.body
    );
    assert_eq!(
        reply.error_code.as_deref(),
        Some("NotFoundException"),
        "case {case:?}: expected NotFoundException, got {actual:?}",
        actual = reply.error_code
    );
    assert_eq!(
        reply.message(),
        NO_BUCKET,
        "case {case:?}: expected the fixed not-found sentence, got {actual:?}",
        actual = reply.message()
    );
}

/// The ARNs of the buckets the store currently holds a metrics configuration
/// for, sorted, read straight from the service's own state.
fn configured_arns(emulator: &Emulator) -> Vec<String> {
    let store = emulator.engine.state::<S3TablesState>();
    let store = store.lock();
    let mut arns: Vec<String> = store
        .table_buckets
        .values()
        .filter(|bucket| bucket.metrics.is_some())
        .map(|bucket| bucket.arn.clone())
        .collect();
    arns.sort();
    arns
}

#[tokio::test]
async fn a_delete_clears_only_the_addressed_buckets_configuration() {
    let emulator = Emulator::new();

    // Every row's bucket is created and configured first, so each delete below
    // runs against a store that holds several configurations at once.
    let rows = buckets();
    let mut resident: Vec<(&Bucket, String, String)> = Vec::new();
    for row in &rows {
        let created = emulator
            .create_table_bucket(row.region, &json!({ "name": row.name }))
            .await;
        assert_eq!(
            created.status,
            200,
            "case {label:?}: the create must succeed, got {status} {body}",
            label = row.label,
            status = created.status,
            body = created.body
        );
        let arn = created.text("arn");
        assert_eq!(
            arn,
            expected_bucket_arn(row.region, row.name),
            "case {label:?}: the create must mint the modeled ARN, got {arn:?}",
            label = row.label
        );

        let put = emulator
            .put_table_bucket_metrics_configuration(row.region, &arn)
            .await;
        assert_empty_204(&put, row.label);
        let id = reported_id(&emulator, row.region, &arn, row.label).await;
        resident.push((row, arn, id));
    }

    let mut remaining: Vec<(&Bucket, String, String)> = resident;
    while !remaining.is_empty() {
        let (row, arn, _) = remaining.remove(0);

        for attempt in 1..=row.deletes {
            let deleted = emulator
                .delete_table_bucket_metrics_configuration(row.region, &arn)
                .await;
            assert_eq!(
                deleted.status, 204,
                "case {label:?}: delete {attempt} must answer the modeled 204, got {status} \
                 {body}",
                label = row.label,
                status = deleted.status,
                body = deleted.body
            );
            assert_eq!(
                deleted.body,
                Value::Null,
                "case {label:?}: delete {attempt} must carry no body, got {body}",
                label = row.label,
                body = deleted.body
            );
        }

        // The addressed bucket now collects no metrics, and its record holds
        // nothing for them.
        let read = emulator
            .get_table_bucket_metrics_configuration(row.region, &arn)
            .await;
        assert_eq!(
            read.status, 404,
            "case {label:?}: expected 404 after the delete, got {status} {body}",
            label = row.label,
            status = read.status,
            body = read.body
        );
        assert_eq!(
            read.message(),
            NO_METRICS_CONFIGURATION,
            "case {label:?}: expected the fixed not-configured sentence, got {actual:?}",
            label = row.label,
            actual = read.message()
        );

        // And nothing else moved: every bucket whose turn has not come still
        // reports the very id its own put persisted.
        for (other, other_arn, other_id) in &remaining {
            let still = reported_id(&emulator, other.region, other_arn, other.label).await;
            assert_eq!(
                &still, other_id,
                "case {label:?}: deleting {arn:?} must leave {other_arn:?} reporting \
                 {other_id:?}, got {still:?}",
                label = other.label
            );
        }

        let mut expected: Vec<String> = remaining
            .iter()
            .map(|(_, other_arn, _)| other_arn.clone())
            .collect();
        expected.sort();
        let actual = configured_arns(&emulator);
        assert_eq!(
            actual, expected,
            "case {label:?}: after the delete the store must hold configurations for \
             {expected:?}, got {actual:?}",
            label = row.label
        );
    }
}

#[tokio::test]
async fn a_delete_against_a_bucket_the_store_does_not_hold_is_refused() {
    let emulator = Emulator::new();

    // One resident, configured bucket, so each refusal below is about the ARN it
    // names and not about an empty store.
    let resident = emulator
        .create_table_bucket("us-east-1", &json!({ "name": "metrics-delete-resident" }))
        .await
        .text("arn");
    let put = emulator
        .put_table_bucket_metrics_configuration("us-east-1", &resident)
        .await;
    assert_empty_204(&put, "the resident bucket");
    let id = reported_id(&emulator, "us-east-1", &resident, "the resident bucket").await;

    // A bucket that existed, carried a configuration, and was deleted whole.
    let doomed = emulator
        .create_table_bucket("us-east-1", &json!({ "name": "metrics-delete-doomed" }))
        .await
        .text("arn");
    let put = emulator
        .put_table_bucket_metrics_configuration("us-east-1", &doomed)
        .await;
    assert_empty_204(&put, "the doomed bucket");
    let deleted = emulator.delete_table_bucket("us-east-1", &doomed).await;
    assert_empty_204(&deleted, "the doomed bucket");

    let cases: Vec<(&str, String, &str)> = vec![
        (
            "a bucket that was never created",
            expected_bucket_arn("us-east-1", "metrics-delete-absent"),
            "us-east-1",
        ),
        (
            "a bucket that was deleted whole",
            doomed.clone(),
            "us-east-1",
        ),
        (
            "the resident bucket's name in another region",
            expected_bucket_arn("eu-west-1", "metrics-delete-resident"),
            "eu-west-1",
        ),
        (
            "another account's bucket of the same name",
            resident.replace("000000000000", "123456789012"),
            "us-east-1",
        ),
        (
            "the shortest name a bucket can carry, never created",
            expected_bucket_arn("ap-south-1", "m3x"),
            "ap-south-1",
        ),
    ];

    for (label, arn, region) in &cases {
        let reply = emulator
            .delete_table_bucket_metrics_configuration(region, arn)
            .await;
        assert_bucket_not_found(&reply, label);

        // A refused delete changes nothing: the one configuration the store
        // holds is still the resident bucket's, under the same id.
        let actual = configured_arns(&emulator);
        assert_eq!(
            actual,
            vec![resident.clone()],
            "case {label:?}: only the resident bucket may carry a configuration, got {actual:?}"
        );
        let still = reported_id(&emulator, "us-east-1", &resident, label).await;
        assert_eq!(
            still, id,
            "case {label:?}: the refused delete must leave the resident id {id:?}, got {still:?}"
        );
    }
}

#[tokio::test]
async fn a_delete_leaves_the_buckets_other_sub_resources_alone() {
    let emulator = Emulator::new();
    let region = "us-east-1";

    let created = emulator
        .create_table_bucket(
            region,
            &json!({
                "name": "metrics-delete-neighbours",
                "encryptionConfiguration": { "sseAlgorithm": "AES256" },
                "storageClassConfiguration": { "storageClass": "INTELLIGENT_TIERING" },
                "tags": { "team": "data" }
            }),
        )
        .await;
    assert_eq!(
        created.status, 200,
        "case \"the configured bucket\": the create must succeed, got {status} {body}",
        status = created.status,
        body = created.body
    );
    let arn = created.text("arn");

    let maintenance = emulator
        .put_table_bucket_maintenance_configuration(
            region,
            &arn,
            "icebergUnreferencedFileRemoval",
            &json!({
                "status": "enabled",
                "settings": {
                    "icebergUnreferencedFileRemoval": {
                        "unreferencedDays": 7,
                        "nonCurrentDays": 14
                    }
                }
            }),
        )
        .await;
    assert_empty_204(&maintenance, "the maintenance put");
    let put = emulator
        .put_table_bucket_metrics_configuration(region, &arn)
        .await;
    assert_empty_204(&put, "the metrics put");

    // Each neighbouring sub-resource of the SAME bucket, read before and after
    // the metrics delete: the delete reaches none of them.
    let neighbours: Vec<&str> = vec![
        "GetTableBucket",
        "GetTableBucketEncryption",
        "GetTableBucketStorageClass",
        "GetTableBucketMaintenanceConfiguration",
    ];
    async fn read_neighbour(emulator: &Emulator, region: &str, arn: &str, which: &str) -> Value {
        let reply = match which {
            "GetTableBucket" => emulator.get_table_bucket(region, arn).await,
            "GetTableBucketEncryption" => emulator.get_table_bucket_encryption(region, arn).await,
            "GetTableBucketStorageClass" => {
                emulator.get_table_bucket_storage_class(region, arn).await
            }
            "GetTableBucketMaintenanceConfiguration" => {
                emulator
                    .get_table_bucket_maintenance_configuration(region, arn)
                    .await
            }
            other => panic!("case {other:?}: the table names no such read"),
        };
        assert_eq!(
            reply.status, 200,
            "case {which:?}: the read must succeed, got {status} {body}",
            status = reply.status,
            body = reply.body
        );
        reply.body
    }

    let mut before: Vec<(&str, Value)> = Vec::new();
    for which in &neighbours {
        before.push((which, read_neighbour(&emulator, region, &arn, which).await));
    }

    let deleted = emulator
        .delete_table_bucket_metrics_configuration(region, &arn)
        .await;
    assert_empty_204(&deleted, "the metrics delete");

    for (which, expected) in &before {
        let actual = read_neighbour(&emulator, region, &arn, which).await;
        assert_eq!(
            &actual, expected,
            "case {which:?}: the metrics delete must leave this read reporting {expected}, got \
             {actual}"
        );
    }

    // Only the metrics member went: the bucket reads as collecting none, and a
    // fresh put turns them on again under a fresh id.
    let read = emulator
        .get_table_bucket_metrics_configuration(region, &arn)
        .await;
    assert_eq!(
        read.status, 404,
        "case \"the metrics read after the delete\": expected 404, got {status} {body}",
        status = read.status,
        body = read.body
    );
    assert_eq!(
        read.message(),
        NO_METRICS_CONFIGURATION,
        "case \"the metrics read after the delete\": expected the fixed not-configured sentence, \
         got {actual:?}",
        actual = read.message()
    );
    let put = emulator
        .put_table_bucket_metrics_configuration(region, &arn)
        .await;
    assert_empty_204(&put, "the metrics put after the delete");
    let fresh = reported_id(&emulator, region, &arn, "the metrics put after the delete").await;
    assert!(
        !fresh.is_empty(),
        "case \"the metrics put after the delete\": expected a fresh id, got {fresh:?}"
    );
}
