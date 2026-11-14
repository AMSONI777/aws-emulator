// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of tagging an S3 Tables resource.
//!
//! The rules under test:
//!
//! * A tag key reserved for system use — one beginning with `aws:`, in any case
//!   — is refused to a CALLER of `TagResource` with the modelled
//!   `BadRequestException` (HTTP 400), and so is a key carrying a character
//!   outside letters, digits, separators and `_.:/=+@-` (that one on every
//!   operation that takes tags, whoever asked). The refusal is stated BEFORE
//!   anything is written, so none of the request's tags lands on the resource.
//! * That reserved namespace is the one this service's own control plane writes
//!   in, so a `TagResource` arriving on the in-process callback another emulated
//!   service reaches this one through DOES carry such a key, and every later read
//!   reports it beside the caller's own tags.
//! * A `resourceArn` is resolved against the store: the ARN of a table bucket or
//!   a table the store does not hold — a deleted one included, since its ARN
//!   stays well formed — is the modelled `NotFoundException` (HTTP 404), and a
//!   value that addresses no taggable resource at all is a `BadRequestException`.
//! * What a tag write leaves behind is what `ListTagsForResource` reports, for a
//!   table bucket and for a table alike, including the tags a create applied.
//!
//! Each table spans what the rule generalises over rather than one recorded
//! request: which resource form the ARN names, which character class the key is
//! made of, which case the reserved prefix is spelled in, which path the request
//! arrived on, how the resource came to be absent, and how many tags the
//! resource holds. The character classes and the punctuation set come from the
//! sentence the service states a refused key with, and the length bounds from
//! `TagKey` (`@length(1, 128)`) and `TagValue` (`@length(0, 256)`)
//! (`smithy_query(query="shape", shape="Tags,TagKey,TagValue")`).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::harness::{expected_bucket_arn, Emulator, Reply};

const REGION: &str = "us-east-1";

/// The sentences this service states each tagging refusal class with. No
/// variable part: that is exactly what is asserted below.
const RESERVED_KEY: &str = "Tags beginning with 'aws:' are reserved for system use.";
const INVALID_KEY: &str = "The provided tags are invalid. Tag key can only contain alphanumeric \
                           characters, spaces, and _.:/=+@-";
const NO_TABLE: &str = "The specified table does not exist.";
const NO_BUCKET: &str = "The specified bucket does not exist.";
const INVALID_RESOURCE_ARN: &str = "The specified resourceArn is not valid.";

/// The bound `TagResource` publishes: "You can add up to 50 tags for each S3
/// resource."
const MAX_TAGS_PER_RESOURCE: usize = 50;

/// One live resource of each taggable form, in one table bucket.
struct Resources {
    bucket_arn: String,
    table_arn: String,
    /// A second table, so a refusal aimed at one resource can be shown to leave
    /// another alone.
    sibling_table_arn: String,
}

/// Create a table bucket, a namespace and two tables in it.
async fn resources(emulator: &Emulator, bucket: &str) -> Resources {
    let bucket_arn = created(
        emulator.create_table_bucket(REGION, &json!({ "name": bucket })).await,
        bucket,
    )
    .text("arn");
    created(
        emulator
            .create_namespace(REGION, &bucket_arn, &json!({ "namespace": ["ns"] }))
            .await,
        bucket,
    );
    let table_arn = created(
        emulator
            .create_table(
                REGION,
                &bucket_arn,
                "ns",
                &json!({ "name": "first_table", "format": "ICEBERG" }),
            )
            .await,
        bucket,
    )
    .text("tableARN");
    let sibling_table_arn = created(
        emulator
            .create_table(
                REGION,
                &bucket_arn,
                "ns",
                &json!({ "name": "second_table", "format": "ICEBERG" }),
            )
            .await,
        bucket,
    )
    .text("tableARN");
    Resources {
        bucket_arn,
        table_arn,
        sibling_table_arn,
    }
}

/// Assert a setup call was served, and hand the reply on.
fn created(reply: Reply, case: &str) -> Reply {
    assert_eq!(
        reply.status, 200,
        "case {case:?}: the setup call must be served, got {status} {body}",
        status = reply.status,
        body = reply.body
    );
    reply
}

/// Assert `reply` is the refusal `expected_message` states, carrying `status`
/// and `code`.
fn assert_refusal(reply: &Reply, status: u16, code: &str, expected_message: &str, case: &str) {
    assert_eq!(
        reply.status, status,
        "case {case:?}: expected status {status}, got {actual} {body}",
        actual = reply.status,
        body = reply.body
    );
    assert_eq!(
        reply.error_code.as_deref(),
        Some(code),
        "case {case:?}: expected the modelled {code}, got {actual:?}",
        actual = reply.error_code
    );
    assert_eq!(
        reply.message(),
        expected_message,
        "case {case:?}: expected the service's fixed sentence {expected_message:?}, got \
         {actual:?}",
        actual = reply.message()
    );
}

/// The tags `ListTagsForResource` reports for `resource_arn`.
async fn listed_tags(
    emulator: &Emulator,
    resource_arn: &str,
    case: &str,
) -> BTreeMap<String, String> {
    let reply = emulator.list_tags_for_resource(REGION, resource_arn).await;
    assert_eq!(
        reply.status, 200,
        "case {case:?}: listing the tags of a live resource must be served, got {status} {body}",
        status = reply.status,
        body = reply.body
    );
    match reply.body.get("tags") {
        Some(Value::Object(map)) => map
            .iter()
            .map(|(key, value)| {
                let text = value.as_str().unwrap_or_else(|| {
                    panic!("case {case:?}: tag {key:?} must be a string, got {value:?}")
                });
                (key.clone(), text.to_string())
            })
            .collect(),
        actual => panic!("case {case:?}: expected a `tags` map, got {actual:?}"),
    }
}

/// A map of one tag, as the body of a `TagResource` carries it.
fn one_tag(key: &str, value: &str) -> Value {
    json!({ key: value })
}

#[tokio::test]
async fn a_reserved_tag_key_is_refused_and_nothing_it_travelled_with_is_stored() {
    let emulator = Emulator::new();
    let live = resources(&emulator, "reserved-prefix-bucket").await;

    // The forms a reserved key takes: the prefix alone, the prefix with the
    // punctuation and the character classes a key may otherwise carry, and the
    // prefix in a key that would be perfectly acceptable without it.
    let reserved = [
        "aws:",
        "aws:reserved-marker",
        "aws:sim2real-reserved",
        "aws:cost/center=1",
        "aws:Name With Spaces",
        "aws:クラスタ",
        // The namespace is the service's however a request spells the prefix.
        "AWS:LOUD",
        "aWs:mixed",
    ];
    // A key that merely CONTAINS the prefix is not reserved: the rule is about
    // how a key BEGINS.
    let accepted = ["not-aws:reserved", "team:aws:owner", " aws:leading-space"];

    for resource in [&live.bucket_arn, &live.table_arn] {
        for key in reserved {
            let case = format!("{key:?} on {resource}");
            let refused = emulator
                .tag_resource(REGION, resource, &one_tag(key, "x"))
                .await;
            assert_refusal(&refused, 400, "BadRequestException", RESERVED_KEY, &case);

            // The refused key travelled with an ordinary one; neither landed.
            let together = emulator
                .tag_resource(
                    REGION,
                    resource,
                    &json!({ key: "x", "ordinary_key": "ordinary" }),
                )
                .await;
            assert_refusal(&together, 400, "BadRequestException", RESERVED_KEY, &case);
            let stored = listed_tags(&emulator, resource, &case).await;
            assert!(
                stored.is_empty(),
                "case {case:?}: a refused request must store no tag at all, got {stored:?}"
            );
        }

        for key in accepted {
            let case = format!("{key:?} on {resource}");
            let served = emulator
                .tag_resource(REGION, resource, &one_tag(key, "value"))
                .await;
            assert_eq!(
                served.status, 200,
                "case {case:?}: a key that only contains the reserved prefix must be accepted, \
                 got {status} {body}",
                status = served.status,
                body = served.body
            );
            let stored = listed_tags(&emulator, resource, &case).await;
            assert_eq!(
                stored.get(key).map(String::as_str),
                Some("value"),
                "case {case:?}: the accepted key must be stored, got {stored:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_tag_key_outside_the_accepted_character_set_is_refused() {
    let emulator = Emulator::new();
    let live = resources(&emulator, "charset-bucket").await;

    // One row per character class the service does NOT accept, each carried in a
    // key that is otherwise well formed.
    let refused_keys = [
        "bad key!",
        "project#1",
        "percent%",
        "star*",
        "semi;colon",
        "quote\"key",
        "paren(key)",
        "comma,key",
        "brace{key}",
        "back\\slash",
        // Whitespace that is a CONTROL character, not a separator: the sentence
        // names spaces, and a tab or a line break is neither.
        "tab\tkey",
        "line\nbreak",
    ];
    // One row per class the service DOES accept: every punctuation mark the
    // sentence names, spaces, digits, letters of another script, and the longest
    // key `TagKey`'s @length(1, 128) publishes.
    let accepted_keys = [
        "_.:/=+@-".to_string(),
        "key with spaces".to_string(),
        "0123456789".to_string(),
        "Mixed_Case".to_string(),
        "クラスタ名".to_string(),
        "k".repeat(128),
        "k".to_string(),
    ];

    for resource in [&live.bucket_arn, &live.table_arn] {
        for key in refused_keys {
            let case = format!("{key:?} on {resource}");
            let refused = emulator
                .tag_resource(REGION, resource, &one_tag(key, "value"))
                .await;
            assert_refusal(&refused, 400, "BadRequestException", INVALID_KEY, &case);
            let stored = listed_tags(&emulator, resource, &case).await;
            assert!(
                !stored.contains_key(key),
                "case {case:?}: a refused key must not land on the resource, got {stored:?}"
            );
        }

        // A well-formed key is still accepted after every refusal above, and
        // the values a tag carries span `TagValue`'s @length(0, 256).
        for (index, key) in accepted_keys.iter().enumerate() {
            let case = format!("{key:?} on {resource}");
            let value = match index {
                0 => String::new(),
                1 => "v".repeat(256),
                _ => format!("value {index}"),
            };
            let served = emulator
                .tag_resource(REGION, resource, &one_tag(key, &value))
                .await;
            assert_eq!(
                served.status, 200,
                "case {case:?}: a well-formed key must be accepted, got {status} {body}",
                status = served.status,
                body = served.body
            );
            let stored = listed_tags(&emulator, resource, &case).await;
            assert_eq!(
                stored.get(key.as_str()),
                Some(&value),
                "case {case:?}: the accepted tag must be stored, got {stored:?}"
            );
        }
    }
}

#[tokio::test]
async fn tagging_a_resource_the_store_does_not_hold_is_refused_as_missing() {
    let emulator = Emulator::new();
    let live = resources(&emulator, "stale-arn-bucket").await;

    // The table is deleted, so its ARN is well formed and names nothing.
    assert_eq!(
        emulator
            .delete_table(REGION, &live.bucket_arn, "ns", "first_table", &[])
            .await
            .status,
        204,
        "the table must be deleted"
    );

    // How the resource came to be absent is what varies: deleted, or never
    // created at all — and each ARN form states its own class.
    let absent = [
        ("a deleted table", live.table_arn.clone(), NO_TABLE),
        (
            "a table that was never created",
            format!("{bucket}/table/11111111-2222-3333-4444-555555555555", bucket = live.bucket_arn),
            NO_TABLE,
        ),
        (
            "a bucket that was never created",
            expected_bucket_arn(REGION, "absent-bucket"),
            NO_BUCKET,
        ),
        (
            "a table under a bucket that was never created",
            format!(
                "{bucket}/table/66666666-7777-8888-9999-aaaaaaaaaaaa",
                bucket = expected_bucket_arn(REGION, "absent-bucket")
            ),
            NO_TABLE,
        ),
    ];

    for (case, resource_arn, expected) in &absent {
        let refused = emulator
            .tag_resource(REGION, resource_arn, &one_tag("stale", "should-not-attach"))
            .await;
        assert_refusal(&refused, 404, "NotFoundException", expected, case);

        // The read states the same class for the same ARN.
        let listed = emulator.list_tags_for_resource(REGION, resource_arn).await;
        assert_refusal(&listed, 404, "NotFoundException", expected, case);
    }

    // A live sibling in the same bucket is still taggable, and so is the bucket.
    for resource in [&live.sibling_table_arn, &live.bucket_arn] {
        let case = format!("the live {resource}");
        let served = emulator
            .tag_resource(REGION, resource, &one_tag("owner", "team"))
            .await;
        assert_eq!(
            served.status, 200,
            "case {case:?}: a live resource must still be taggable, got {status} {body}",
            status = served.status,
            body = served.body
        );
        let stored = listed_tags(&emulator, resource, &case).await;
        assert_eq!(
            stored.get("owner").map(String::as_str),
            Some("team"),
            "case {case:?}: the tag must be stored, got {stored:?}"
        );
    }

    // A deleted bucket's ARN answers as missing too, whatever it held before.
    let doomed = created(
        emulator
            .create_table_bucket(REGION, &json!({ "name": "doomed-bucket" }))
            .await,
        "a deleted bucket",
    )
    .text("arn");
    assert_eq!(
        emulator.delete_table_bucket(REGION, &doomed).await.status,
        204,
        "the empty bucket must be deleted"
    );
    let refused = emulator
        .tag_resource(REGION, &doomed, &one_tag("stale", "x"))
        .await;
    assert_refusal(
        &refused,
        404,
        "NotFoundException",
        NO_BUCKET,
        "a deleted bucket",
    );
}

#[tokio::test]
async fn an_arn_that_addresses_no_taggable_resource_is_refused_as_invalid() {
    let emulator = Emulator::new();
    let live = resources(&emulator, "arn-form-bucket").await;

    // Values the modelled pattern accepts that still address neither of the two
    // forms the operation documents — a table bucket and a table.
    let not_taggable = [
        format!("{bucket}/unknown-child", bucket = live.bucket_arn),
        format!("{table}/extra", table = live.table_arn),
        format!("{bucket}/table/an-id/deeper", bucket = live.bucket_arn),
        format!("{bucket}/table/", bucket = live.bucket_arn),
    ];

    for resource_arn in &not_taggable {
        let refused = emulator
            .tag_resource(REGION, resource_arn, &one_tag("key", "value"))
            .await;
        assert_refusal(
            &refused,
            400,
            "BadRequestException",
            INVALID_RESOURCE_ARN,
            resource_arn,
        );
        let listed = emulator.list_tags_for_resource(REGION, resource_arn).await;
        assert_refusal(
            &listed,
            400,
            "BadRequestException",
            INVALID_RESOURCE_ARN,
            resource_arn,
        );
    }
}

#[tokio::test]
async fn tags_round_trip_through_the_store_for_every_taggable_form() {
    let emulator = Emulator::new();

    // The create carries the tags for one row and `TagResource` applies them for
    // the other, so both writes are read back through the same reader.
    let bucket_arn = created(
        emulator
            .create_table_bucket(
                REGION,
                &json!({
                    "name": "round-trip-bucket",
                    "tags": { "created_with": "bucket", "owner": "first" },
                }),
            )
            .await,
        "a bucket created with tags",
    )
    .text("arn");
    created(
        emulator
            .create_namespace(REGION, &bucket_arn, &json!({ "namespace": ["ns"] }))
            .await,
        "the namespace",
    );
    let table_arn = created(
        emulator
            .create_table(
                REGION,
                &bucket_arn,
                "ns",
                &json!({
                    "name": "tagged_table",
                    "format": "ICEBERG",
                    "tags": { "created_with": "table" },
                }),
            )
            .await,
        "a table created with tags",
    )
    .text("tableARN");

    assert_eq!(
        listed_tags(&emulator, &bucket_arn, "a bucket created with tags").await,
        BTreeMap::from([
            ("created_with".to_string(), "bucket".to_string()),
            ("owner".to_string(), "first".to_string()),
        ]),
        "a create's tags must be the ones the reader reports"
    );
    assert_eq!(
        listed_tags(&emulator, &table_arn, "a table created with tags").await,
        BTreeMap::from([("created_with".to_string(), "table".to_string())]),
        "a create's tags must be the ones the reader reports"
    );

    // A tag write ADDS the keys the resource did not carry and REPLACES the
    // value of one it did; it removes nothing.
    for resource in [&bucket_arn, &table_arn] {
        let case = format!("updating {resource}");
        let served = emulator
            .tag_resource(
                REGION,
                resource,
                &json!({ "created_with": "replaced", "added": "second" }),
            )
            .await;
        assert_eq!(
            served.status, 200,
            "case {case:?}: the write must be served, got {status} {body}",
            status = served.status,
            body = served.body
        );
        let stored = listed_tags(&emulator, resource, &case).await;
        assert_eq!(
            stored.get("created_with").map(String::as_str),
            Some("replaced"),
            "case {case:?}: a key the resource already carried must be replaced, got {stored:?}"
        );
        assert_eq!(
            stored.get("added").map(String::as_str),
            Some("second"),
            "case {case:?}: a key the resource did not carry must be added, got {stored:?}"
        );
    }

    // One resource's tags are its own: the bucket kept the key the table never
    // had.
    let bucket_tags = listed_tags(&emulator, &bucket_arn, "the bucket's own tags").await;
    let table_tags = listed_tags(&emulator, &table_arn, "the table's own tags").await;
    assert!(
        bucket_tags.contains_key("owner") && !table_tags.contains_key("owner"),
        "tags belong to one resource: bucket {bucket_tags:?}, table {table_tags:?}"
    );

    // A resource nothing was ever tagged with answers with an empty map rather
    // than a refusal.
    let untagged = created(
        emulator
            .create_table(
                REGION,
                &bucket_arn,
                "ns",
                &json!({ "name": "untagged_table", "format": "ICEBERG" }),
            )
            .await,
        "an untagged table",
    )
    .text("tableARN");
    assert!(
        listed_tags(&emulator, &untagged, "an untagged table")
            .await
            .is_empty(),
        "a resource that carries no tags must report an empty map"
    );
}

#[tokio::test]
async fn a_resource_holds_at_most_the_published_number_of_tags() {
    let emulator = Emulator::new();
    let live = resources(&emulator, "tag-bound-bucket").await;

    for resource in [&live.bucket_arn, &live.table_arn] {
        // Every tag the bound allows, applied in one request.
        let full: serde_json::Map<String, Value> = (0..MAX_TAGS_PER_RESOURCE)
            .map(|index| (format!("key_{index:02}"), Value::String(index.to_string())))
            .collect();
        let served = emulator
            .tag_resource(REGION, resource, &Value::Object(full))
            .await;
        assert_eq!(
            served.status, 200,
            "the published number of tags must be accepted on {resource}, got {status} {body}",
            status = served.status,
            body = served.body
        );
        let stored = listed_tags(&emulator, resource, resource).await;
        assert_eq!(
            stored.len(),
            MAX_TAGS_PER_RESOURCE,
            "the resource must hold every applied tag, got {stored:?}"
        );

        // One more KEY is refused, and the request stores nothing.
        let refused = emulator
            .tag_resource(REGION, resource, &one_tag("one_too_many", "x"))
            .await;
        assert_refusal(
            &refused,
            400,
            "BadRequestException",
            "You can add up to 50 tags for each S3 resource.",
            resource,
        );
        let after = listed_tags(&emulator, resource, resource).await;
        assert_eq!(
            after, stored,
            "a refused write must leave the resource's tags as they were, got {after:?}"
        );

        // Replacing the value of a key the resource already carries adds no
        // key, so it is served at the bound.
        let served = emulator
            .tag_resource(REGION, resource, &one_tag("key_00", "replaced"))
            .await;
        assert_eq!(
            served.status, 200,
            "a replacement at the bound must be served on {resource}, got {status} {body}",
            status = served.status,
            body = served.body
        );
        let after = listed_tags(&emulator, resource, resource).await;
        assert_eq!(
            after.get("key_00").map(String::as_str),
            Some("replaced"),
            "the replacement must be stored, got {after:?}"
        );
        assert_eq!(
            after.len(),
            MAX_TAGS_PER_RESOURCE,
            "a replacement must add no key, got {after:?}"
        );
    }
}

/// The three keys CloudFormation records on every resource it provisions, which
/// is the live example of the reserved namespace this service's own control
/// plane writes in (this emulator's
/// `service-com-amazonaws-cloudformation-cloudformation`
/// `state::provisioning::{STACK_NAME_TAG, STACK_ID_TAG, LOGICAL_ID_TAG}`), plus
/// one key of another service's own namespace and one spelled in another case.
const SYSTEM_KEYS: &[(&str, &str)] = &[
    ("the stack a resource belongs to", "aws:cloudformation:stack-name"),
    ("that stack's id", "aws:cloudformation:stack-id"),
    (
        "the resource's logical id in the template",
        "aws:cloudformation:logical-id",
    ),
    (
        "another service's own namespace",
        "aws:servicecatalog:provisioningPrincipalArn",
    ),
    ("the prefix in another case", "AWS:CloudFormation:Stack-Name"),
];

#[tokio::test]
async fn a_tagging_call_takes_a_reserved_tag_key_only_on_the_in_process_path() {
    for (case, key) in SYSTEM_KEYS {
        // A fresh emulator per row, so what one row stored cannot answer for
        // another.
        let emulator = Emulator::new();

        // A create records the tag set it is given, whichever path it arrived
        // on: the create is how a provisioning service asks for a resource that
        // already carries the service's own keys, and the set it carried is read
        // back whole.
        let bucket_arn = created(
            emulator
                .create_table_bucket(
                    REGION,
                    &json!({
                        "name": "system-tag-bucket",
                        "tags": { *key: "set-by-the-service", "owner": "caller" },
                    }),
                )
                .await,
            case,
        )
        .text("arn");
        created(
            emulator
                .create_namespace(REGION, &bucket_arn, &json!({ "namespace": ["ns"] }))
                .await,
            case,
        );
        let table_arn = created(
            emulator
                .create_table_in_process(
                    REGION,
                    &bucket_arn,
                    "ns",
                    &json!({
                        "name": "system_tagged_table",
                        "format": "ICEBERG",
                        "tags": { *key: "set-by-the-service" },
                    }),
                )
                .await,
            case,
        )
        .text("tableARN");

        // Every later read reports the service's key beside the caller's own.
        let stored = listed_tags(&emulator, &bucket_arn, case).await;
        assert_eq!(
            stored.get(*key).map(String::as_str),
            Some("set-by-the-service"),
            "case {case:?}: the create's reserved key must be stored, got {stored:?}"
        );
        assert_eq!(
            stored.get("owner").map(String::as_str),
            Some("caller"),
            "case {case:?}: the caller's own key must be stored beside it, got {stored:?}"
        );
        let stored = listed_tags(&emulator, &table_arn, case).await;
        assert_eq!(
            stored.get(*key).map(String::as_str),
            Some("set-by-the-service"),
            "case {case:?}: the create's reserved key must be stored, got {stored:?}"
        );

        // `TagResource` is the tagging call, and there the namespace is the
        // service's: a CALLER may not write in it, and the in-process
        // provisioning path may.
        for resource in [&bucket_arn, &table_arn] {
            let refused = emulator
                .tag_resource(REGION, resource, &one_tag(key, "by-a-caller"))
                .await;
            assert_refusal(&refused, 400, "BadRequestException", RESERVED_KEY, case);
            let stored = listed_tags(&emulator, resource, case).await;
            assert_eq!(
                stored.get(*key).map(String::as_str),
                Some("set-by-the-service"),
                "case {case:?}: a caller's refused write must not touch the service's own tag, \
                 got {stored:?}"
            );

            let served = emulator
                .tag_resource_in_process(REGION, resource, &one_tag(key, "reset-by-the-service"))
                .await;
            assert_eq!(
                served.status, 200,
                "case {case:?}: the in-process path must take the reserved key, got {status} \
                 {body}",
                status = served.status,
                body = served.body
            );
            let stored = listed_tags(&emulator, resource, case).await;
            assert_eq!(
                stored.get(*key).map(String::as_str),
                Some("reset-by-the-service"),
                "case {case:?}: the in-process write must land, got {stored:?}"
            );
        }

        // The character-set rule is not about who asked: a malformed key is
        // refused on either path, and on a create as much as on `TagResource`.
        let refused = emulator
            .tag_resource_in_process(REGION, &bucket_arn, &one_tag("bad key!", "x"))
            .await;
        assert_refusal(&refused, 400, "BadRequestException", INVALID_KEY, case);
        let refused = emulator
            .create_table_bucket(
                REGION,
                &json!({ "name": "malformed-tag-bucket", "tags": { "bad key!": "x" } }),
            )
            .await;
        assert_refusal(&refused, 400, "BadRequestException", INVALID_KEY, case);
    }
}
