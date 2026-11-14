// SPDX-License-Identifier: CC0-1.0

//! The version-token precondition of `PutTableBucketReplication`.
//!
//! The rule under test: the `versionToken` a write hands back identifies ONE
//! bucket's replication configuration as of THAT write, so a put is accepted
//! only when it presents no token at all or the token of the configuration the
//! named bucket currently holds. Every other token — one a later write
//! superseded, one minted for another bucket's configuration, or one whose
//! configuration has since been deleted — is refused and changes nothing: the
//! modelled `ConflictException` (HTTP 409) while the bucket still holds a
//! configuration the token could have named, and the modelled
//! `NotFoundException` (HTTP 404) once it holds none, because then there is no
//! configuration to precondition.
//!
//! The model is what bounds the shapes the table spans
//! (`smithy_query(query="closure", operation="PutTableBucketReplication")`):
//! `versionToken` is an optional `@length(1, 2048)` query member on the input
//! and a `@required` member of the output, `TableBucketReplicationRules` is
//! `@length(1, 1)` and a rule's `destinations` `@length(1, 5)`. So the rows
//! differ in the region the bucket lives in, how many destinations its rule
//! names and how many successive writes it takes — none of which the
//! precondition may depend on.

use serde_json::{json, Value};

use crate::harness::{Emulator, Reply, ACCOUNT};

/// The fixed sentence a presented token that is not the configuration's is
/// refused with.
const STALE_VERSION_TOKEN: &str = "The specified version token does not match the configuration.";

/// The fixed sentence a bucket that holds no replication configuration is
/// stated with.
const NO_REPLICATION_CONFIGURATION: &str = "The specified replication configuration does not exist.";

/// One row: a source table bucket written `writes` times, whose one rule names
/// `destinations` destination buckets.
#[derive(Debug)]
struct Case {
    label: &'static str,
    region: &'static str,
    name: &'static str,
    /// How many destination buckets the row's one rule carries; the modelled
    /// `ReplicationDestinations` bound is 1..=5.
    destinations: usize,
    /// How many accepted writes the row performs before the preconditions are
    /// probed, so a superseded token is one write old in some rows and several
    /// in others.
    writes: usize,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            label: "one destination, a single write",
            region: "us-east-1",
            name: "token-precondition-single",
            destinations: 1,
            writes: 1,
        },
        Case {
            label: "two destinations, three writes",
            region: "eu-west-1",
            name: "token-precondition-triple",
            destinations: 2,
            writes: 3,
        },
        Case {
            label: "five destinations, the modelled maximum, two writes",
            region: "ap-southeast-2",
            name: "token-precondition-five",
            destinations: 5,
            writes: 2,
        },
    ]
}

/// A configuration whose one rule — the rule list is `@length(1, 1)` —
/// replicates to `destinations`.
fn configuration(destinations: &[String]) -> Value {
    json!({
        "role": format!("arn:aws:iam::{ACCOUNT}:role/s3tables-token-precondition"),
        "rules": [{
            "destinations": destinations
                .iter()
                .map(|arn| json!({ "destinationTableBucketARN": arn }))
                .collect::<Vec<Value>>(),
        }],
    })
}

/// Create a table bucket and answer its ARN.
async fn bucket(emulator: &Emulator, region: &str, name: &str, case: &str) -> String {
    let created = emulator
        .create_table_bucket(region, &json!({ "name": name }))
        .await;
    assert_eq!(
        created.status,
        200,
        "case {case:?}: creating {name:?} must succeed, got {status} {body}",
        status = created.status,
        body = created.body
    );
    created.text("arn")
}

/// The version token an accepted write reported.
fn accepted_token(reply: &Reply, case: &str) -> String {
    assert_eq!(
        reply.status, 200,
        "case {case:?}: the put must be accepted, got {status} {body}",
        status = reply.status,
        body = reply.body
    );
    let token = reply.text("versionToken");
    assert!(
        (1..=2048).contains(&token.chars().count()),
        "case {case:?}: the token must be of the modelled length, got {token:?}"
    );
    token
}

/// The version token the read reports for `arn`.
async fn reported_token(emulator: &Emulator, region: &str, arn: &str, case: &str) -> String {
    let read = emulator.get_table_bucket_replication(region, arn).await;
    assert_eq!(
        read.status, 200,
        "case {case:?}: the read must be served, got {status} {body}",
        status = read.status,
        body = read.body
    );
    read.text("versionToken")
}

/// Assert `reply` is the modelled refusal `status`/`code`/`message` names.
fn assert_refused(reply: &Reply, status: u16, code: &str, message: &str, case: &str) {
    assert_eq!(
        reply.status, status,
        "case {case:?}: expected status {status}, got {actual} {body}",
        actual = reply.status,
        body = reply.body
    );
    assert_eq!(
        reply.error_code.as_deref(),
        Some(code),
        "case {case:?}: expected {code}, got {actual:?}",
        actual = reply.error_code
    );
    assert_eq!(
        reply.message(),
        message,
        "case {case:?}: expected the fixed sentence {message:?}, got {actual:?}",
        actual = reply.message()
    );
    assert!(
        reply.optional_text("versionToken").is_none(),
        "case {case:?}: a refused put mints no token, got {body}",
        body = reply.body
    );
}

/// What one row of the table left behind: the source bucket, the configuration
/// its writes applied, the token of the write that is current and every token
/// an earlier write handed back.
struct Written {
    label: &'static str,
    region: &'static str,
    arn: String,
    configuration: Value,
    current: String,
    superseded: Vec<String>,
}

/// Apply each row's writes, chaining the token the previous write reported into
/// the next one, which is the precondition form of the same call.
async fn write_rows(emulator: &Emulator) -> Vec<Written> {
    let mut written = Vec::new();
    for case in cases() {
        let source = bucket(emulator, case.region, case.name, case.label).await;
        let mut destinations = Vec::new();
        for index in 0..case.destinations {
            destinations.push(
                bucket(
                    emulator,
                    case.region,
                    &format!("{name}-dest-{index}", name = case.name),
                    case.label,
                )
                .await,
            );
        }
        let settings = configuration(&destinations);

        let mut tokens: Vec<String> = Vec::new();
        for write in 0..case.writes {
            let query = match tokens.last() {
                Some(held) => vec![
                    ("tableBucketARN", source.clone()),
                    ("versionToken", held.clone()),
                ],
                None => vec![("tableBucketARN", source.clone())],
            };
            let label = format!("{label} (write {write})", label = case.label);
            let put = emulator
                .put_table_bucket_replication(case.region, &query, &settings)
                .await;
            let token = accepted_token(&put, &label);
            assert_eq!(
                reported_token(emulator, case.region, &source, &label).await,
                token,
                "case {label:?}: the read must report the token the write handed back"
            );
            tokens.push(token);
        }

        let current = tokens.pop().expect("every row performs at least one write");
        written.push(Written {
            label: case.label,
            region: case.region,
            arn: source,
            configuration: settings,
            current,
            superseded: tokens,
        });
    }
    written
}

#[tokio::test]
async fn every_write_mints_a_token_no_other_write_carries() {
    let emulator = Emulator::new();
    let written = write_rows(&emulator).await;

    let mut seen: Vec<(&str, String)> = Vec::new();
    for row in &written {
        for token in row.superseded.iter().chain(std::iter::once(&row.current)) {
            if let Some((owner, _)) = seen.iter().find(|(_, held)| held == token) {
                panic!(
                    "case {label:?}: the token {token:?} was already handed back to case \
                     {owner:?}; every write mints a fresh one",
                    label = row.label
                );
            }
            seen.push((row.label, token.clone()));
        }
    }
    assert_eq!(
        seen.len(),
        cases().iter().map(|case| case.writes).sum::<usize>(),
        "every accepted write must contribute exactly one token, got {seen:?}"
    );
}

#[tokio::test]
async fn a_superseded_token_is_the_modelled_conflict_and_writes_nothing() {
    let emulator = Emulator::new();
    let written = write_rows(&emulator).await;

    for row in &written {
        for (index, stale) in row.superseded.iter().enumerate() {
            let label = format!(
                "{label} (the token of write {index})",
                label = row.label
            );
            let refused = emulator
                .put_table_bucket_replication(
                    row.region,
                    &[
                        ("tableBucketARN", row.arn.clone()),
                        ("versionToken", stale.clone()),
                    ],
                    &row.configuration,
                )
                .await;
            assert_refused(&refused, 409, "ConflictException", STALE_VERSION_TOKEN, &label);
            assert_eq!(
                reported_token(&emulator, row.region, &row.arn, &label).await,
                row.current,
                "case {label:?}: the refused put must leave the configuration's token as it was"
            );
        }

        // A token the service never minted is refused the same way: what the
        // precondition names is the stored configuration, not a token's form.
        let label = format!("{label} (a token nothing minted)", label = row.label);
        let refused = emulator
            .put_table_bucket_replication(
                row.region,
                &[
                    ("tableBucketARN", row.arn.clone()),
                    ("versionToken", format!("{current}-x", current = row.current)),
                ],
                &row.configuration,
            )
            .await;
        assert_refused(&refused, 409, "ConflictException", STALE_VERSION_TOKEN, &label);
        assert_eq!(
            reported_token(&emulator, row.region, &row.arn, &label).await,
            row.current,
            "case {label:?}: the refused put must leave the configuration's token as it was"
        );
    }
}

#[tokio::test]
async fn a_token_belongs_to_one_buckets_configuration_only() {
    let emulator = Emulator::new();
    let written = write_rows(&emulator).await;

    for row in &written {
        for other in &written {
            if other.arn == row.arn {
                continue;
            }
            let label = format!(
                "{label} preconditioned on {other}'s token",
                label = row.label,
                other = other.label
            );
            let refused = emulator
                .put_table_bucket_replication(
                    row.region,
                    &[
                        ("tableBucketARN", row.arn.clone()),
                        ("versionToken", other.current.clone()),
                    ],
                    &row.configuration,
                )
                .await;
            assert_refused(&refused, 409, "ConflictException", STALE_VERSION_TOKEN, &label);
            assert_eq!(
                reported_token(&emulator, row.region, &row.arn, &label).await,
                row.current,
                "case {label:?}: the refused put must leave this bucket's token as it was"
            );
            assert_eq!(
                reported_token(&emulator, other.region, &other.arn, &label).await,
                other.current,
                "case {label:?}: the refused put must leave the other bucket's token as it was"
            );
        }
    }
}

#[tokio::test]
async fn the_current_token_is_accepted_and_advances_the_configuration() {
    let emulator = Emulator::new();
    let written = write_rows(&emulator).await;

    for row in &written {
        let label = format!("{label} (the current token)", label = row.label);
        let accepted = emulator
            .put_table_bucket_replication(
                row.region,
                &[
                    ("tableBucketARN", row.arn.clone()),
                    ("versionToken", row.current.clone()),
                ],
                &row.configuration,
            )
            .await;
        let advanced = accepted_token(&accepted, &label);
        assert_ne!(
            advanced, row.current,
            "case {label:?}: an accepted write must advance the token"
        );
        assert_eq!(
            reported_token(&emulator, row.region, &row.arn, &label).await,
            advanced,
            "case {label:?}: the read must report the token of the last write"
        );

        // And the token just superseded is now refused, which is what makes the
        // precondition a precondition.
        let refused = emulator
            .put_table_bucket_replication(
                row.region,
                &[
                    ("tableBucketARN", row.arn.clone()),
                    ("versionToken", row.current.clone()),
                ],
                &row.configuration,
            )
            .await;
        assert_refused(&refused, 409, "ConflictException", STALE_VERSION_TOKEN, &label);
    }
}

#[tokio::test]
async fn once_the_configuration_is_gone_there_is_nothing_to_precondition() {
    let emulator = Emulator::new();
    let written = write_rows(&emulator).await;

    for row in &written {
        let label = format!("{label} (after the delete)", label = row.label);
        let deleted = emulator
            .delete_table_bucket_replication(
                row.region,
                &[("tableBucketARN", row.arn.clone())],
            )
            .await;
        assert_eq!(
            deleted.status, 204,
            "case {label:?}: the delete must answer the modelled 204, got {status} {body}",
            status = deleted.status,
            body = deleted.body
        );

        // The token the deleted configuration carried names nothing now, so the
        // put is the not-found of a configuration that is not there and creates
        // no configuration.
        let refused = emulator
            .put_table_bucket_replication(
                row.region,
                &[
                    ("tableBucketARN", row.arn.clone()),
                    ("versionToken", row.current.clone()),
                ],
                &row.configuration,
            )
            .await;
        assert_refused(
            &refused,
            404,
            "NotFoundException",
            NO_REPLICATION_CONFIGURATION,
            &label,
        );
        let read = emulator
            .get_table_bucket_replication(row.region, &row.arn)
            .await;
        assert_eq!(
            read.status, 404,
            "case {label:?}: the refused put must create no configuration, got {status} {body}",
            status = read.status,
            body = read.body
        );

        // A put that presents no token at all is accepted, and the token it
        // mints is not the one the deleted configuration carried.
        let recreated = emulator
            .put_table_bucket_replication(
                row.region,
                &[("tableBucketARN", row.arn.clone())],
                &row.configuration,
            )
            .await;
        let token = accepted_token(&recreated, &label);
        assert_ne!(
            token, row.current,
            "case {label:?}: the recreated configuration must carry a fresh token"
        );
        assert_eq!(
            reported_token(&emulator, row.region, &row.arn, &label).await,
            token,
            "case {label:?}: the read must report the recreated configuration's token"
        );
    }
}
