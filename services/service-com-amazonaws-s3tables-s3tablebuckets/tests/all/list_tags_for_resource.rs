// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of `ListTagsForResource`: the tags an S3 Tables resource
//! carries, read by the ARN that resource is addressed with.
//!
//! The rule under test: **the read answers the tag set the ADDRESSED resource's own
//! record carries and nothing else — "the tagged resource can be a table bucket or a
//! table", so a bucket ARN answers that bucket's tags and a table ARN that table's —
//! a resource nothing ever tagged has an empty set rather than no answer, an ARN the
//! store holds no resource at is refused with the modelled not-found, and the read
//! changes nothing, so a second read answers the same.**
//!
//! The table spans what the rule generalises over: how many tags the resource was
//! created with (none, one, several), the `@length` bounds `TagKey` (1..128) and
//! `TagValue` (0..256) publish for a key and a value, which KIND of resource the ARN
//! names, which resource of several is addressed, and the region.

use serde_json::{json, Map, Value};

use super::harness::{encode, expected_bucket_arn, Emulator, Reply};

/// The fixed sentences this service states an absent resource with, one per class of
/// resource an ARN here can name.
const NO_BUCKET: &str = "The specified bucket does not exist.";
const NO_TABLE: &str = "The specified table does not exist.";

/// The modelled 404 of this operation.
const NOT_FOUND: &str = "NotFoundException";

/// The bounds `Tags` publishes for one entry: `TagKey` is `@length(min: 1, max: 128)`
/// and `TagValue` is `@length(min: 0, max: 256)`, so a key at 128 characters and a
/// value at 256 — and the empty value the minimum admits — are all inside the set a
/// resource may carry.
const LONGEST_KEY_LENGTH: usize = 128;
const LONGEST_VALUE_LENGTH: usize = 256;

/// The tags the read reported, in key order so a case compares a set rather than an
/// arrival order.
fn reported(reply: &Reply, case: &str) -> Vec<(String, String)> {
    assert_eq!(
        reply.status, 200,
        "case {case:?}: the read must succeed, got {status} {body}",
        status = reply.status,
        body = reply.body
    );
    let tags = reply
        .body
        .get("tags")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: the read has no tags map: {body}",
                body = reply.body
            )
        });
    let mut rows: Vec<(String, String)> = tags
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value.as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    rows.sort();
    rows
}

/// The tag map a create carries, as the wire takes it.
fn tag_map(tags: &[(String, String)]) -> Value {
    let mut map = Map::new();
    for (key, value) in tags {
        map.insert(key.clone(), json!(value));
    }
    Value::Object(map)
}

/// The tags a row's resource is created with, as the set the read must then report.
fn sorted(tags: &[(String, String)]) -> Vec<(String, String)> {
    let mut rows = tags.to_vec();
    rows.sort();
    rows
}

/// One row: a table bucket created with `bucket_tags`, holding a table created with
/// `table_tags`, and which of the two the row reads.
struct Row {
    case: &'static str,
    region: &'static str,
    bucket: &'static str,
    bucket_tags: Vec<(String, String)>,
    /// The table the row's bucket holds, where the row declares one: the tags it is
    /// created with, and whether the row reads the TABLE rather than the bucket.
    table_tags: Option<Vec<(String, String)>>,
    reads_the_table: bool,
}

/// A key and a value of the longest form `Tags` admits, built here so the row and the
/// assertion cannot disagree about their length.
fn longest_key() -> String {
    "k".repeat(LONGEST_KEY_LENGTH)
}

fn longest_value() -> String {
    "v".repeat(LONGEST_VALUE_LENGTH)
}

fn owned(tags: &[(&str, &str)]) -> Vec<(String, String)> {
    tags.iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "a table bucket created with several tags",
            region: "us-east-1",
            bucket: "tagged-bucket",
            bucket_tags: owned(&[
                ("Owner", "analytics"),
                ("Tier", "prod"),
                ("aws:cloudformation:logical-id", "Bucket"),
            ]),
            table_tags: None,
            reads_the_table: false,
        },
        Row {
            case: "a table bucket nothing ever tagged",
            region: "eu-west-1",
            bucket: "untagged-bucket",
            bucket_tags: Vec::new(),
            table_tags: None,
            reads_the_table: false,
        },
        Row {
            case: "one tag whose value is the empty string the minimum admits",
            region: "us-west-2",
            bucket: "empty-value-bucket",
            bucket_tags: owned(&[("Marker", "")]),
            table_tags: None,
            reads_the_table: false,
        },
        Row {
            case: "a key and a value at the longest published length",
            region: "ap-south-1",
            bucket: "longest-entry-bucket",
            bucket_tags: vec![(longest_key(), longest_value())],
            table_tags: None,
            reads_the_table: false,
        },
        Row {
            // The bucket and the table it holds carry DIFFERENT sets, and the row
            // reads the table: a read addressed at one resource cannot answer with
            // the other's.
            case: "a table of the bucket, addressed by its own ARN",
            region: "us-east-2",
            bucket: "bucket-with-a-table",
            bucket_tags: owned(&[("Owner", "the-bucket")]),
            table_tags: Some(owned(&[("Owner", "the-table"), ("Dataset", "events")])),
            reads_the_table: true,
        },
        Row {
            // The same pair, read from the BUCKET end.
            case: "the bucket of that table, addressed by its own ARN",
            region: "eu-central-1",
            bucket: "bucket-read-not-table",
            bucket_tags: owned(&[("Owner", "the-bucket"), ("Tier", "staging")]),
            table_tags: Some(owned(&[("Owner", "the-table")])),
            reads_the_table: false,
        },
        Row {
            case: "a table nothing ever tagged, in a tagged bucket",
            region: "ap-northeast-1",
            bucket: "untagged-table-bucket",
            bucket_tags: owned(&[("Owner", "the-bucket")]),
            table_tags: Some(Vec::new()),
            reads_the_table: true,
        },
    ]
}

/// The namespace and table name the rows that declare a table use.
const NAMESPACE: &str = "sales";
const TABLE: &str = "orders";

/// Every row: the read answers the addressed resource's own tag set, and answers the
/// same set when it is asked again.
#[tokio::test]
async fn the_read_reports_the_addressed_resources_own_tags() {
    let emulator = Emulator::new();

    for row in rows() {
        let case = row.case;
        let mut request = Map::new();
        request.insert("name".to_string(), json!(row.bucket));
        if !row.bucket_tags.is_empty() {
            request.insert("tags".to_string(), tag_map(&row.bucket_tags));
        }
        let created = emulator
            .create_table_bucket(row.region, &Value::Object(request))
            .await;
        assert_eq!(
            created.status, 200,
            "case {case:?}: creating the bucket must succeed, got {status} {body}",
            status = created.status,
            body = created.body
        );
        let bucket_arn = created.text("arn");
        assert_eq!(
            bucket_arn,
            expected_bucket_arn(row.region, row.bucket),
            "case {case:?}: the create must mint the bucket's own ARN, got {bucket_arn:?}"
        );

        let mut table_arn = None;
        if let Some(table_tags) = &row.table_tags {
            let namespaced = emulator
                .create_namespace(
                    row.region,
                    &bucket_arn,
                    &json!({ "namespace": [NAMESPACE] }),
                )
                .await;
            assert_eq!(
                namespaced.status, 200,
                "case {case:?}: creating the namespace must succeed, got {status} {body}",
                status = namespaced.status,
                body = namespaced.body
            );
            let mut request = Map::new();
            request.insert("name".to_string(), json!(TABLE));
            request.insert("format".to_string(), json!("ICEBERG"));
            if !table_tags.is_empty() {
                request.insert("tags".to_string(), tag_map(table_tags));
            }
            let table = emulator
                .create_table(
                    row.region,
                    &bucket_arn,
                    NAMESPACE,
                    &Value::Object(request),
                )
                .await;
            assert_eq!(
                table.status, 200,
                "case {case:?}: creating the table must succeed, got {status} {body}",
                status = table.status,
                body = table.body
            );
            table_arn = Some(table.text("tableARN"));
        }

        let (addressed, expected) = if row.reads_the_table {
            (
                table_arn.clone().expect("a row that reads a table made one"),
                sorted(row.table_tags.as_deref().unwrap_or_default()),
            )
        } else {
            (bucket_arn.clone(), sorted(&row.bucket_tags))
        };

        let read = emulator.list_tags_for_resource(row.region, &addressed).await;
        let answered = reported(&read, case);
        assert_eq!(
            answered, expected,
            "case {case:?}: expected the tags {expected:?} of {addressed}, got {answered:?}"
        );

        // The read changed nothing: asked again, it answers the same set.
        let again = emulator.list_tags_for_resource(row.region, &addressed).await;
        let answered_again = reported(&again, case);
        assert_eq!(
            answered_again, expected,
            "case {case:?}: a read must change nothing, expected {expected:?} again, got \
             {answered_again:?}"
        );
    }
}

/// An ARN the store holds no resource at is refused with the modelled not-found, stated
/// as the class of resource that ARN names.
#[tokio::test]
async fn an_arn_no_resource_is_held_at_is_refused() {
    let emulator = Emulator::new();
    let region = "us-east-1";
    let held = "present-bucket";
    let created = emulator
        .create_table_bucket(region, &json!({ "name": held }))
        .await;
    assert_eq!(
        created.status, 200,
        "creating the bucket must succeed, got {status} {body}",
        status = created.status,
        body = created.body
    );
    let bucket_arn = created.text("arn");

    for (case, addressed, message) in [
        (
            "a table bucket ARN nothing was created under",
            expected_bucket_arn(region, "absent-bucket"),
            NO_BUCKET,
        ),
        (
            "a table ARN under a bucket that exists",
            format!("{bucket_arn}/table/{}", "0123456789abcdef"),
            NO_TABLE,
        ),
        (
            "a table ARN under a bucket that does not",
            format!(
                "{}/table/{}",
                expected_bucket_arn(region, "absent-bucket"),
                "0123456789abcdef"
            ),
            NO_TABLE,
        ),
    ] {
        let refused = emulator.list_tags_for_resource(region, &addressed).await;
        assert_eq!(
            refused.status, 404,
            "case {case:?}: expected HTTP 404 for {addressed}, got {status} {body}",
            status = refused.status,
            body = refused.body
        );
        assert_eq!(
            refused.error_code.as_deref(),
            Some(NOT_FOUND),
            "case {case:?}: expected the modelled {NOT_FOUND}, got {:?}",
            refused.error_code
        );
        assert_eq!(
            refused.message(),
            message,
            "case {case:?}: expected the fixed sentence {message:?}, got {:?}",
            refused.message()
        );
    }

    // ...and the ARN that IS held still answers, so the refusals above are about the
    // resource and not about the route.
    let read = emulator.list_tags_for_resource(region, &bucket_arn).await;
    assert_eq!(
        read.status, 200,
        "expected the held bucket {bucket_arn} to answer, got {status} {body}",
        status = read.status,
        body = read.body
    );
    assert!(
        encode(&bucket_arn).contains("%3A"),
        "the ARN travels as one path label, so its separators are encoded: {bucket_arn}"
    );
}
