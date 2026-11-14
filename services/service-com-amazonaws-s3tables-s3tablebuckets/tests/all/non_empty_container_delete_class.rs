// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of WHICH failure a delete of a container that still
//! holds records is.
//!
//! The rule under test: a delete this service refuses because the container it
//! addresses still holds records is the CALLER's request error — the modelled
//! `BadRequestException`, HTTP 400, carrying the one fixed sentence for that
//! class — at every container level this service has. It is not the modelled
//! `ConflictException`, which the model documents as "a conflict with a previous
//! write. You can retry the request" (`smithy_query(query="shape",
//! shape="ConflictException")`): emptying the container, not retrying the same
//! request, is what makes the delete possible, so a client that retries a
//! refused delete can never be served.
//!
//! The retryable class is pinned beside it, so the two cannot collapse into one:
//! a name already taken and a version token that is not the addressed table's
//! own ARE conflicts with a previous write, and stay HTTP 409
//! `ConflictException`.
//!
//! The table spans what the rule generalises over — which container level is
//! addressed, how many records it holds, and whether a SIBLING container is
//! empty — rather than one recorded request, and each case reads the whole
//! sentence, checks the refused delete persisted nothing, and then empties the
//! container to prove the refusal was about the state and not about the call.

use serde_json::json;

use crate::harness::{Emulator, Reply};

const REGION: &str = "us-east-1";

/// The sentences this service states each refusal class with. Fixed text: that
/// the same sentence answers every resource of the class is asserted below by
/// comparing the refusals of differently named resources.
const BUCKET_NOT_EMPTY: &str = "The bucket that you tried to delete is not empty.";
const NAMESPACE_NOT_EMPTY: &str = "The namespace that you tried to delete is not empty.";
const BUCKET_EXISTS: &str = "The bucket that you tried to create already exists, and you own it.";
const NAMESPACE_EXISTS: &str = "A namespace with an identical name already exists in the bucket.";
const TABLE_EXISTS: &str = "A table with an identical name already exists in the namespace.";
const STALE_TABLE_VERSION_TOKEN: &str =
    "Provided version token does not match the table version token.";

/// One shape of a filled table bucket: how many namespaces it holds and how
/// many tables the namespace the delete addresses holds.
struct Filled {
    label: &'static str,
    /// The bucket's name. `TableBucketName`: `@length(3, 63)`,
    /// `@pattern(^[0-9a-z-]*$)`.
    bucket: &'static str,
    /// How many namespaces the bucket holds, the first of which is the one the
    /// refused `DeleteNamespace` addresses.
    namespaces: usize,
    /// How many tables that first namespace holds.
    tables: usize,
}

/// The rows every refusal below is asserted over: the fewest records that fill a
/// container (one), several records in the addressed container, several sibling
/// containers beside it, and both at once.
fn filled() -> Vec<Filled> {
    vec![
        Filled {
            label: "one namespace holding one table",
            bucket: "delete-class-one-one",
            namespaces: 1,
            tables: 1,
        },
        Filled {
            label: "one namespace holding three tables",
            bucket: "delete-class-one-three",
            namespaces: 1,
            tables: 3,
        },
        Filled {
            label: "three namespaces, the addressed one holding one table",
            bucket: "delete-class-three-one",
            namespaces: 3,
            tables: 1,
        },
        Filled {
            label: "two namespaces, the addressed one holding two tables",
            bucket: "delete-class-two-two",
            namespaces: 2,
            tables: 2,
        },
    ]
}

/// The name of the namespace at `index`. `NamespaceName`: `@length(1, 255)`,
/// `@pattern(^[0-9a-z_]*$)`.
fn namespace_name(index: usize) -> String {
    format!("held_namespace_{index}")
}

/// The name of the table at `index`. `TableName` takes the same bounds and
/// character set as `NamespaceName`.
fn table_name(index: usize) -> String {
    format!("held_table_{index}")
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
        "case {case:?}: expected the fixed sentence {expected_message:?}, got {actual:?}",
        actual = reply.message()
    );
}

/// Create the bucket `filled` describes, with its namespaces and the tables of
/// the addressed one, and answer the bucket's ARN.
async fn create_filled(emulator: &Emulator, filled: &Filled) -> String {
    let case = filled.label;
    let created = emulator
        .create_table_bucket(REGION, &json!({ "name": filled.bucket }))
        .await;
    assert_eq!(
        created.status, 200,
        "case {case:?}: the bucket must be created, got {status} {body}",
        status = created.status,
        body = created.body
    );
    let arn = created.text("arn");

    for index in 0..filled.namespaces {
        let made = emulator
            .create_namespace(REGION, &arn, &json!({ "namespace": [namespace_name(index)] }))
            .await;
        assert_eq!(
            made.status, 200,
            "case {case:?}: namespace {index} must be created, got {status} {body}",
            status = made.status,
            body = made.body
        );
    }
    for index in 0..filled.tables {
        let made = emulator
            .create_table(
                REGION,
                &arn,
                &namespace_name(0),
                &json!({ "name": table_name(index), "format": "ICEBERG" }),
            )
            .await;
        assert_eq!(
            made.status, 200,
            "case {case:?}: table {index} must be created, got {status} {body}",
            status = made.status,
            body = made.body
        );
    }
    arn
}

#[tokio::test]
async fn a_delete_of_a_container_that_still_holds_records_is_the_callers_request_error() {
    let emulator = Emulator::new();
    // The refusal of the FIRST row, which every later row's refusal must read
    // identically: the sentence states the class, so two differently named
    // resources are refused with the same body.
    let mut first_namespace_refusal: Option<serde_json::Value> = None;
    let mut first_bucket_refusal: Option<serde_json::Value> = None;

    for row in filled() {
        let case = row.label;
        let arn = create_filled(&emulator, &row).await;

        // The addressed namespace still holds tables.
        let namespace_refused = emulator
            .delete_namespace(REGION, &arn, &namespace_name(0))
            .await;
        assert_refusal(
            &namespace_refused,
            400,
            "BadRequestException",
            NAMESPACE_NOT_EMPTY,
            case,
        );
        // The bucket still holds namespaces.
        let bucket_refused = emulator.delete_table_bucket(REGION, &arn).await;
        assert_refusal(
            &bucket_refused,
            400,
            "BadRequestException",
            BUCKET_NOT_EMPTY,
            case,
        );

        // The refusal of one resource reads exactly as the refusal of another:
        // nothing of the request or the store is in it.
        for (level, actual, first) in [
            (
                "namespace",
                &namespace_refused.body,
                &mut first_namespace_refusal,
            ),
            ("bucket", &bucket_refused.body, &mut first_bucket_refusal),
        ] {
            match first {
                Some(expected) => assert_eq!(
                    actual, expected,
                    "case {case:?}: the {level} refusal must read as the first row's \
                     {expected:?}, got {actual:?}"
                ),
                None => *first = Some(actual.clone()),
            }
        }

        // A refused delete persists nothing: every record is still there.
        let namespaces = emulator.list_namespaces(REGION, &arn, &[]).await;
        assert_eq!(
            namespaces.list("namespaces").len(),
            row.namespaces,
            "case {case:?}: a refused delete must leave every namespace in place, got {body}",
            body = namespaces.body
        );
        let tables = emulator
            .list_tables(REGION, &arn, &[("namespace", namespace_name(0))])
            .await;
        assert_eq!(
            tables.list("tables").len(),
            row.tables,
            "case {case:?}: a refused delete must leave every table in place, got {body}",
            body = tables.body
        );
        assert_eq!(
            emulator.get_table_bucket(REGION, &arn).await.status,
            200,
            "case {case:?}: a refused delete must leave the bucket in place"
        );

        // A SIBLING namespace holds nothing, so its own delete is served while
        // the addressed one is still refused: the refusal is about the records
        // the addressed container holds, not about the bucket it lives in.
        for index in 1..row.namespaces {
            let name = namespace_name(index);
            assert_eq!(
                emulator.delete_namespace(REGION, &arn, &name).await.status,
                204,
                "case {case:?}: the empty namespace {name:?} must be deleted"
            );
        }

        // Emptying each container is what makes its delete possible, bottom up.
        for index in 0..row.tables {
            let name = table_name(index);
            assert_eq!(
                emulator
                    .delete_table(REGION, &arn, &namespace_name(0), &name, &[])
                    .await
                    .status,
                204,
                "case {case:?}: the table {name:?} must be deleted"
            );
        }
        assert_eq!(
            emulator
                .delete_namespace(REGION, &arn, &namespace_name(0))
                .await
                .status,
            204,
            "case {case:?}: the emptied namespace must be deleted"
        );
        assert_eq!(
            emulator.delete_table_bucket(REGION, &arn).await.status,
            204,
            "case {case:?}: the emptied bucket must be deleted"
        );
    }
}

#[tokio::test]
async fn a_conflict_with_a_previous_write_stays_the_retryable_modelled_conflict() {
    let emulator = Emulator::new();
    let bucket = "delete-class-conflicts";
    let namespace = "conflict_namespace";
    let table = "conflict_table";

    let arn = emulator
        .create_table_bucket(REGION, &json!({ "name": bucket }))
        .await
        .text("arn");
    emulator
        .create_namespace(REGION, &arn, &json!({ "namespace": [namespace] }))
        .await;
    let created = emulator
        .create_table(
            REGION,
            &arn,
            namespace,
            &json!({ "name": table, "format": "ICEBERG" }),
        )
        .await;
    let token = created.text("versionToken");

    // The classes that ARE a conflict with a previous write: a name another
    // write already took, at each level this service names one, and a version
    // token that is not the addressed table's own.
    let conflicts = vec![
        (
            "a table bucket name already taken",
            emulator
                .create_table_bucket(REGION, &json!({ "name": bucket }))
                .await,
            BUCKET_EXISTS,
        ),
        (
            "a namespace name already taken",
            emulator
                .create_namespace(REGION, &arn, &json!({ "namespace": [namespace] }))
                .await,
            NAMESPACE_EXISTS,
        ),
        (
            "a table name already taken",
            emulator
                .create_table(
                    REGION,
                    &arn,
                    namespace,
                    &json!({ "name": table, "format": "ICEBERG" }),
                )
                .await,
            TABLE_EXISTS,
        ),
        (
            "a version token that is not the table's own",
            emulator
                .delete_table(
                    REGION,
                    &arn,
                    namespace,
                    table,
                    &[("versionToken", format!("{token}0"))],
                )
                .await,
            STALE_TABLE_VERSION_TOKEN,
        ),
    ];
    for (case, reply, expected_message) in &conflicts {
        assert_refusal(reply, 409, "ConflictException", expected_message, case);
    }
}
