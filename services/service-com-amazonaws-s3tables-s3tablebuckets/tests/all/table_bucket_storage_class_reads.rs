// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of `GetTableBucketStorageClass` as a REPORT on one
//! table bucket.
//!
//! The rule under test: the read answers for exactly the table bucket its
//! `tableBucketARN` addresses — the default storage class that bucket's own
//! record holds, else the service's own class for a bucket no caller ever named
//! one for — and it reports it without changing anything a later caller sees.
//! A bucket the store does not hold is refused instead, and that too is decided
//! per bucket.
//!
//! `table_bucket_storage_class.rs` covers the put/read round trip and the
//! inheritance rule one bucket at a time; this suite is about WHICH bucket a
//! read answers for and about the read being a pure report, so its rows are
//! buckets that coexist in one store: configured by their create, configured by
//! a later put, configured by a put that replaced the create's class, never
//! configured at all, and the same bucket NAME in a second region. Every
//! modeled storage class appears as both a create's and a put's class, and the
//! reads are repeated and interleaved so a read that answered from (or wrote
//! to) another bucket's record would be caught.

use serde_json::{json, Value};
use service_com_amazonaws_s3tables_s3tablebuckets as s3tables;

use s3tables::state::{service_state, StorageClass};

use super::harness::{expected_bucket_arn, Emulator};
use super::table_bucket_storage_class::{
    bucket, bucket_storage_class, configuration, table, table_storage_class,
};

/// One row: a table bucket that exists alongside every other row's bucket, how
/// its default storage class was (or was not) named, and what a read of it must
/// report.
#[derive(Debug)]
struct Row {
    label: &'static str,
    region: &'static str,
    /// The bucket's name, which two rows in different regions deliberately
    /// share.
    name: &'static str,
    /// The `storageClassConfiguration` the create carried, when any.
    created_with: Option<&'static str>,
    /// The class a later `PutTableBucketStorageClass` set, when the row puts
    /// one.
    put: Option<&'static str>,
    /// The class a read must report for this bucket.
    expected: &'static str,
    /// What the bucket's own record must hold afterwards: `None` for a bucket no
    /// caller ever named a class for, which is what makes the reported class the
    /// service's own default rather than a stored one.
    stored: Option<&'static str>,
}

/// The rows, spanning where a bucket's default comes from crossed with both
/// modeled classes, plus one name shared across two regions.
fn rows() -> Vec<Row> {
    vec![
        Row {
            label: "no caller ever named a class",
            region: "us-east-1",
            name: "reads-unnamed",
            created_with: None,
            put: None,
            expected: "STANDARD",
            stored: None,
        },
        Row {
            label: "the create named the general-purpose class",
            region: "us-east-1",
            name: "reads-created-standard",
            created_with: Some("STANDARD"),
            put: None,
            expected: "STANDARD",
            stored: Some("STANDARD"),
        },
        Row {
            label: "the create named intelligent tiering",
            region: "us-east-1",
            name: "reads-created-tiering",
            created_with: Some("INTELLIGENT_TIERING"),
            put: None,
            expected: "INTELLIGENT_TIERING",
            stored: Some("INTELLIGENT_TIERING"),
        },
        Row {
            label: "a put named a class the create did not",
            region: "eu-west-1",
            name: "reads-put-tiering",
            created_with: None,
            put: Some("INTELLIGENT_TIERING"),
            expected: "INTELLIGENT_TIERING",
            stored: Some("INTELLIGENT_TIERING"),
        },
        Row {
            label: "a put replaced the class the create named",
            region: "eu-west-1",
            name: "reads-put-replaces",
            created_with: Some("INTELLIGENT_TIERING"),
            put: Some("STANDARD"),
            expected: "STANDARD",
            stored: Some("STANDARD"),
        },
        Row {
            label: "the same bucket name in a second region",
            region: "ap-southeast-2",
            // Deliberately the name row one uses: the read is addressed by ARN,
            // and the two ARNs differ only in their region.
            name: "reads-unnamed",
            created_with: Some("INTELLIGENT_TIERING"),
            put: None,
            expected: "INTELLIGENT_TIERING",
            stored: Some("INTELLIGENT_TIERING"),
        },
    ]
}

/// The storage class the store's own record for `arn` holds, and whether it
/// holds a record for `arn` at all.
fn stored_storage_class(emulator: &Emulator, arn: &str) -> Option<Option<StorageClass>> {
    let state = service_state(&*emulator.engine).expect("the S3 Tables store is reachable");
    let store = state.lock();
    store
        .table_buckets
        .get(arn)
        .map(|bucket| bucket.storage_class)
}

/// Create every row's bucket, apply the put the row names, and answer the ARNs
/// in row order.
async fn create_rows(emulator: &Emulator, rows: &[Row]) -> Vec<String> {
    let mut arns = Vec::new();
    for row in rows {
        let arn = bucket(emulator, row.region, row.name, row.created_with, row.label).await;
        if let Some(storage_class) = row.put {
            let put = emulator
                .put_table_bucket_storage_class(row.region, &arn, &configuration(storage_class))
                .await;
            assert_eq!(
                put.status,
                200,
                "case {label:?}: PutTableBucketStorageClass must succeed, got {status} {body}",
                label = row.label,
                status = put.status,
                body = put.body
            );
        }
        arns.push(arn);
    }
    arns
}

#[tokio::test]
async fn each_read_reports_the_default_of_the_bucket_its_arn_addresses() {
    let emulator = Emulator::new();
    let rows = rows();
    let arns = create_rows(&emulator, &rows).await;

    // Every bucket, read while every other row's bucket is resident.
    for (row, arn) in rows.iter().zip(&arns) {
        let read = emulator
            .get_table_bucket_storage_class(row.region, arn)
            .await;
        assert_eq!(
            read.status,
            200,
            "case {label:?}: GetTableBucketStorageClass must succeed, got {status} {body}",
            label = row.label,
            status = read.status,
            body = read.body
        );

        // The response is the one required output member and nothing else, and
        // the configuration carries only the class it models.
        let members: Vec<&String> = read
            .body
            .as_object()
            .map(|object| object.keys().collect())
            .unwrap_or_default();
        assert_eq!(
            members,
            vec!["storageClassConfiguration"],
            "case {label:?}: the read must carry exactly the modeled output member, got {body}",
            label = row.label,
            body = read.body
        );
        let configuration_members: Vec<&String> = read
            .body
            .get("storageClassConfiguration")
            .and_then(Value::as_object)
            .map(|object| object.keys().collect())
            .unwrap_or_default();
        assert_eq!(
            configuration_members,
            vec!["storageClass"],
            "case {label:?}: the configuration must carry exactly its modeled member, got {body}",
            label = row.label,
            body = read.body
        );

        let reported = read
            .body
            .get("storageClassConfiguration")
            .and_then(|configuration| configuration.get("storageClass"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "case {label:?}: the read must carry storageClassConfiguration.storageClass: \
                     {body}",
                    label = row.label,
                    body = read.body
                )
            });
        assert_eq!(
            reported, row.expected,
            "case {label:?}: expected {expected}, got {reported:?}",
            label = row.label,
            expected = row.expected
        );
    }

    // Read every bucket again, in the opposite order: a read that answered from
    // another bucket's record, or that wrote to one, shows up here.
    for (row, arn) in rows.iter().zip(&arns).rev() {
        let reported = bucket_storage_class(&emulator, row.region, arn, row.label).await;
        assert_eq!(
            reported, row.expected,
            "case {label:?}: a repeated read must report {expected}, got {reported:?}",
            label = row.label,
            expected = row.expected
        );
        assert_eq!(
            stored_storage_class(&emulator, arn),
            Some(row.stored.map(|wire| {
                StorageClass::from_wire(wire).expect("a row names a modeled storage class")
            })),
            "case {label:?}: the reads must leave the bucket's own record as it was",
            label = row.label
        );
    }
}

#[tokio::test]
async fn a_read_reports_the_service_default_without_setting_it() {
    let emulator = Emulator::new();
    let region = "us-east-1";

    // Both modeled classes as the class a put names AFTER the reads, so the
    // assertion does not rest on the put agreeing with what the reads reported.
    for storage_class in StorageClass::ALL {
        let wire = storage_class.as_wire();
        let label = format!("read then put {wire}");
        let name = format!("reads-then-put-{}", wire.to_lowercase().replace('_', "-"));
        let arn = bucket(&emulator, region, &name, None, &label).await;

        // Repeated reads of a bucket no caller ever configured: each reports the
        // service's own class, and none of them names one on the bucket's
        // behalf.
        for attempt in 1..=3 {
            let case = format!("{label}, read {attempt}");
            let reported = bucket_storage_class(&emulator, region, &arn, &case).await;
            assert_eq!(
                reported, "STANDARD",
                "case {case:?}: an unconfigured bucket must report the service's own class, got \
                 {reported:?}"
            );
            assert_eq!(
                stored_storage_class(&emulator, &arn),
                Some(None),
                "case {case:?}: a read must not name a storage class on the bucket's behalf"
            );
        }

        // The put still settles the default, and the read reports it: the reads
        // left nothing behind that fixes the bucket at what they reported.
        let put = emulator
            .put_table_bucket_storage_class(region, &arn, &configuration(wire))
            .await;
        assert_eq!(
            put.status,
            200,
            "case {label:?}: PutTableBucketStorageClass must succeed, got {status} {body}",
            status = put.status,
            body = put.body
        );
        let reported = bucket_storage_class(&emulator, region, &arn, &label).await;
        assert_eq!(
            reported, wire,
            "case {label:?}: expected the put class {wire}, got {reported:?}"
        );

        // And a table created after those reads is created in the put's class,
        // which is what the bucket's default is for.
        table(&emulator, region, &arn, "later", None, &label).await;
        let inherited = table_storage_class(&emulator, region, &arn, "later", &label).await;
        assert_eq!(
            inherited, wire,
            "case {label:?}: a table created after the reads must inherit {wire}, got \
             {inherited:?}"
        );
    }
}

#[tokio::test]
async fn a_read_of_a_bucket_the_store_does_not_hold_is_refused_and_creates_nothing() {
    let emulator = Emulator::new();
    let region = "us-east-1";

    // A bucket nothing ever created, and one that was created and then deleted:
    // both are buckets the store does not hold at the moment of the read.
    let never_created = expected_bucket_arn(region, "reads-never-created");
    let doomed = emulator
        .create_table_bucket(
            region,
            &json!({
                "name": "reads-deleted",
                "storageClassConfiguration": configuration("INTELLIGENT_TIERING"),
            }),
        )
        .await
        .text("arn");
    let resident = bucket(&emulator, region, "reads-resident", None, "resident").await;

    // The doomed bucket answers while it is resident, so the refusal below is
    // the delete's effect and not a bucket that never worked.
    let reported = bucket_storage_class(&emulator, region, &doomed, "deleted, before the delete")
        .await;
    assert_eq!(
        reported, "INTELLIGENT_TIERING",
        "case \"deleted, before the delete\": expected INTELLIGENT_TIERING, got {reported:?}"
    );
    let removed = emulator.delete_table_bucket(region, &doomed).await;
    assert_eq!(
        removed.status, 204,
        "case \"a bucket a delete removed\": the delete must succeed, got {status} {body}",
        status = removed.status,
        body = removed.body
    );

    for (label, arn) in [
        ("a bucket nothing ever created", &never_created),
        ("a bucket a delete removed", &doomed),
    ] {
        let refused = emulator.get_table_bucket_storage_class(region, arn).await;
        assert_eq!(
            refused.status, 404,
            "case {label:?}: expected 404, got {status} {body}",
            status = refused.status,
            body = refused.body
        );
        assert_eq!(
            refused.error_code.as_deref(),
            Some("NotFoundException"),
            "case {label:?}: expected the modeled error code, got {actual:?}",
            actual = refused.error_code
        );
        assert_eq!(
            refused.message(),
            s3tables::state::BUCKET_NOT_FOUND_MESSAGE,
            "case {label:?}: the refusal must state the bucket class sentence"
        );
        // The refused read created nothing: neither a record in the store nor a
        // row a list reports.
        assert_eq!(
            stored_storage_class(&emulator, arn),
            None,
            "case {label:?}: a refused read must not create a bucket record"
        );
        let listed = emulator.list_table_buckets(region, &[]).await;
        let arns: Vec<String> = listed
            .list("tableBuckets")
            .iter()
            .filter_map(|row| row.get("arn").and_then(Value::as_str).map(str::to_string))
            .collect();
        assert!(
            !arns.contains(arn),
            "case {label:?}: a refused read must not add the bucket to the list, got {arns:?}"
        );
    }

    // The bucket that IS resident still reports its own default: a refused read
    // of another ARN changed nothing for it.
    let reported = bucket_storage_class(&emulator, region, &resident, "resident, after the refusals")
        .await;
    assert_eq!(
        reported, "STANDARD",
        "case \"resident, after the refusals\": expected STANDARD, got {reported:?}"
    );
}
