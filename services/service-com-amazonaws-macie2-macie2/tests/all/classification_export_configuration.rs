// SPDX-License-Identifier: CC0-1.0

//! The repository data classification results are stored in, end to end over
//! the wire.
//!
//! Each case drives the production `MultiServiceRouter` through the harness
//! `macie_session_and_custom_data_identifiers` builds, so what is pinned is the
//! HTTP behaviour and the response BODIES rather than a handler called
//! directly.
//!
//! The rules under test, each asserted over a SET of inputs rather than one
//! request:
//!
//! * `PutClassificationExportConfiguration` PERSISTS the `configuration` it is
//!   given, so both it and `GetClassificationExportConfiguration` report
//!   exactly the `s3Destination` members that were stored — every combination
//!   of the two optional members, not one row;
//! * the write is absolute: a call naming no `s3Destination` leaves the account
//!   storing results nowhere, which a read reports as a configuration carrying
//!   no destination, and a read materialises nothing;
//! * the configuration belongs to the region the request signed for and to that
//!   region's Macie session: both operations are refused 403 until Macie is
//!   enabled there, and `DisableMacie` deletes the configuration with the rest
//!   of the account's settings.

use smithy_server_runtime::MultiServiceRouter;

use super::macie_session_and_custom_data_identifiers::{call_in, emulator, enable_in, error_code};

/// The region most cases sign for.
const REGION: &str = "us-west-2";

/// A second region, for the cases that pin the per-region scope of this
/// configuration.
const OTHER_REGION: &str = "eu-west-1";

/// The configuration's URI, from the operations' `@http` bindings (`PUT` for the
/// write, `GET` for the read).
const CONFIGURATION_URI: &str = "/classification-export-configuration";

/// Write the configuration, requiring the modelled 200, and hand back the
/// `configuration` the write reports.
async fn put(
    router: &MultiServiceRouter,
    region: &str,
    body: &serde_json::Value,
    case: &str,
) -> serde_json::Value {
    let (status, reply) = call_in(router, region, "PUT", CONFIGURATION_URI, &body.to_string()).await;
    assert_eq!(
        status, 200,
        "case {case:?}: PutClassificationExportConfiguration must answer 200, \
         got {status} with {reply:?}"
    );
    configuration(case, &reply)
}

/// Read the configuration back, requiring the modelled 200, and hand back the
/// `configuration` the read reports.
async fn read(router: &MultiServiceRouter, region: &str, case: &str) -> serde_json::Value {
    let (status, reply) = call_in(router, region, "GET", CONFIGURATION_URI, "").await;
    assert_eq!(
        status, 200,
        "case {case:?}: GetClassificationExportConfiguration must answer 200, \
         got {status} with {reply:?}"
    );
    configuration(case, &reply)
}

/// The `configuration` member of either response, required to be present and an
/// object: the response states where this account's results are stored, and an
/// account storing them nowhere is an object carrying no `s3Destination`.
fn configuration(case: &str, body: &serde_json::Value) -> serde_json::Value {
    let configuration = &body["configuration"];
    assert!(
        configuration.is_object(),
        "case {case:?}: the response must carry a configuration object, got {body:?}"
    );
    configuration.clone()
}

/// A destination naming only the two members an `S3Destination` requires,
/// per the model (`bucketName` and `kmsKeyArn` are `required`).
fn destination(bucket: &str, key: &str) -> serde_json::Value {
    serde_json::json!({ "bucketName": bucket, "kmsKeyArn": key })
}

/// A KMS key ARN of the shape the `kmsKeyArn` member documents ("the ARN of an
/// existing, symmetric encryption KMS key"), built for `region`.
fn kms_key_arn(region: &str, key_id: &str) -> String {
    format!("arn:aws:kms:{region}:111122223333:key/{key_id}")
}

/// The rows of the write/read table: the `s3Destination` a write names (`None`
/// when it names none), spanning the two optional members of the modelled
/// `S3Destination` — absent, each one alone, and both.
fn rows() -> Vec<(&'static str, Option<serde_json::Value>)> {
    let bucket = "macie-results-bucket";
    let key = kms_key_arn(REGION, "1234abcd-12ab-34cd-56ef-1234567890ab");
    let mut rows: Vec<(&'static str, Option<serde_json::Value>)> = Vec::new();

    rows.push(("required members only", Some(destination(bucket, &key))));

    let mut with_prefix = destination(bucket, &key);
    with_prefix["keyPrefix"] = serde_json::json!("macie/results/");
    rows.push(("a key prefix", Some(with_prefix)));

    let mut with_owner = destination(bucket, &key);
    with_owner["expectedBucketOwner"] = serde_json::json!("111122223333");
    rows.push(("an expected bucket owner", Some(with_owner)));

    let mut with_both = destination("another-results-bucket", &kms_key_arn(REGION, "0000ffff"));
    with_both["keyPrefix"] = serde_json::json!("");
    with_both["expectedBucketOwner"] = serde_json::json!("444455556666");
    rows.push(("both optional members", Some(with_both)));

    // The configuration naming no destination is a row of its own: the write is
    // absolute, so it leaves the account storing results nowhere.
    rows.push(("no destination", None));

    rows
}

/// A region nothing has configured stores results nowhere: the read reports a
/// configuration carrying no `s3Destination`, and reading it twice reports the
/// same thing — a read materialises nothing.
#[tokio::test]
async fn an_unconfigured_account_reports_no_destination() {
    let router = emulator();
    enable_in(&router, REGION, "{}").await;

    let first = read(&router, REGION, "unconfigured").await;
    assert_eq!(
        first,
        serde_json::json!({}),
        "case \"unconfigured\": no repository is configured, so no s3Destination is \
         reported, got {first:?}"
    );

    let again = read(&router, REGION, "unconfigured twice").await;
    assert_eq!(
        again, first,
        "case \"unconfigured twice\": a read must not change what the next reader sees, \
         got {again:?}"
    );
}

/// A write persists exactly the destination it names, and both the write and
/// the read report it back. Each row is written on top of the previous one, so
/// the read also pins that a later write REPLACES what the earlier one stored —
/// including the row that names no destination, which leaves the account
/// storing results nowhere.
#[tokio::test]
async fn a_write_persists_the_destination_a_read_reports() {
    let router = emulator();
    enable_in(&router, REGION, "{}").await;

    for (case, requested) in rows() {
        let body = match requested.clone() {
            Some(destination) => serde_json::json!({
                "configuration": { "s3Destination": destination }
            }),
            None => serde_json::json!({ "configuration": {} }),
        };
        let expected = match requested {
            Some(destination) => serde_json::json!({ "s3Destination": destination }),
            None => serde_json::json!({}),
        };

        let written = put(&router, REGION, &body, case).await;
        assert_eq!(
            written, expected,
            "case {case:?}: the write must report the configuration it stored, \
             got {written:?}"
        );

        let back = read(&router, REGION, case).await;
        assert_eq!(
            back, expected,
            "case {case:?}: the stored configuration must be reported, got {back:?}"
        );
    }
}

/// A repeated write of the same configuration leaves exactly what the first
/// call stored: the write states the repository the account is to have, so
/// repeating it changes nothing. Every row of the table is exercised.
#[tokio::test]
async fn a_repeated_write_leaves_the_configuration_it_wrote() {
    let router = emulator();
    enable_in(&router, REGION, "{}").await;

    for (case, requested) in rows() {
        let body = match requested {
            Some(destination) => serde_json::json!({
                "configuration": { "s3Destination": destination }
            }),
            None => serde_json::json!({ "configuration": {} }),
        };

        put(&router, REGION, &body, case).await;
        let written = read(&router, REGION, case).await;

        put(&router, REGION, &body, case).await;
        let repeated = read(&router, REGION, case).await;
        assert_eq!(
            repeated, written,
            "case {case:?}: repeating the write must leave the configuration the first \
             call stored, got {repeated:?}"
        );
    }
}

/// The configuration belongs to the region the request signed for: writing it
/// in one region leaves another region storing results nowhere, and both
/// operations are refused 403 `AccessDeniedException` in a region where nothing
/// has enabled Macie. The rows are the two operations.
#[tokio::test]
async fn the_configuration_is_scoped_to_the_region_and_needs_a_session() {
    let router = emulator();
    let key = kms_key_arn(REGION, "11112222-3333-4444-5555-666677778888");

    for (case, method, body) in [
        (
            "GetClassificationExportConfiguration",
            "GET",
            String::new(),
        ),
        (
            "PutClassificationExportConfiguration",
            "PUT",
            serde_json::json!({
                "configuration": { "s3Destination": destination("macie-results-bucket", &key) }
            })
            .to_string(),
        ),
    ] {
        let (status, reply) = call_in(&router, REGION, method, CONFIGURATION_URI, &body).await;
        assert_eq!(
            status, 403,
            "case {case:?}: Macie is not enabled here, so the call is refused, \
             got {status} with {reply:?}"
        );
        assert_eq!(
            error_code(&reply),
            "AccessDeniedException",
            "case {case:?}: the refusal must be the modelled AccessDeniedException, \
             got {reply:?}"
        );
    }

    enable_in(&router, REGION, "{}").await;
    enable_in(&router, OTHER_REGION, "{}").await;
    let requested = destination("macie-results-bucket", &key);
    put(
        &router,
        REGION,
        &serde_json::json!({ "configuration": { "s3Destination": requested.clone() } }),
        "configure one region",
    )
    .await;

    let here = read(&router, REGION, "configure one region").await;
    assert_eq!(
        here,
        serde_json::json!({ "s3Destination": requested }),
        "case \"configure one region\": the region written reports its own destination, \
         got {here:?}"
    );
    let elsewhere = read(&router, OTHER_REGION, "another region").await;
    assert_eq!(
        elsewhere,
        serde_json::json!({}),
        "case \"another region\": configuring one region must not configure another, \
         got {elsewhere:?}"
    );
}

/// `DisableMacie` "deletes all settings and resources for a Macie account", so
/// the results repository goes with the session: a region enabled again stores
/// results nowhere rather than keeping the deleted configuration's destination.
#[tokio::test]
async fn disabling_macie_deletes_the_configuration() {
    let router = emulator();
    enable_in(&router, REGION, "{}").await;
    let configured = put(
        &router,
        REGION,
        &serde_json::json!({
            "configuration": {
                "s3Destination": destination(
                    "macie-results-bucket",
                    &kms_key_arn(REGION, "99998888-7777-6666-5555-444433332222"),
                )
            }
        }),
        "configure before disabling",
    )
    .await;

    let (status, reply) = call_in(&router, REGION, "DELETE", "/macie", "").await;
    assert_eq!(
        status, 200,
        "case \"disable Macie\": DisableMacie must answer 200, got {status} with {reply:?}"
    );

    enable_in(&router, REGION, "{}").await;
    let after = read(&router, REGION, "after re-enabling Macie").await;
    assert_eq!(
        after,
        serde_json::json!({}),
        "case \"after re-enabling Macie\": the configuration was deleted with the \
         session, got {after:?} after {configured:?}"
    );
}
