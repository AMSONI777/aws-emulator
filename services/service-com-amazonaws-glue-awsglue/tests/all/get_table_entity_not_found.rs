// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the refusal `GetTable` answers when it cannot resolve the table
//! the request addresses — because the database does not hold it, or because the catalog
//! holds no such database at all.
//!
//! The rule under test: that refusal's `Message` is a FIXED CONSTANT — one string the
//! service answers for every such read, carrying no member of the request, and the same
//! string whichever step of the address resolved to nothing. So the body is
//! byte-identical however the request is spelled (whichever database and table it
//! names, in whatever casing, character set or length, with or without `CatalogId` and
//! `AttributesToGet`), and it discloses neither the table, the database nor the catalog
//! the read resolved. The operations that address a DATABASE itself keep their own
//! templated sentence, which is the boundary the second suite here pins.
//!
//! `error_messages.rs` pins that constant's wording against the recorded wire case and
//! pins it apart from the wording the table WRITES answer, and this suite reuses its
//! `assert_refusal`/`assert_withholds` helpers rather than restating them. What it adds
//! is the invariance: the same answer across a cross product of request shapes, which is
//! what distinguishes a constant from a template that merely happens to match on one
//! input. Its rows pair a database name WITH a table name, because the template this
//! pins out interpolated both members, so the two have to vary independently; and each
//! row also reads back a table that IS present, so a constant refusal cannot be passing
//! by refusing everything, and re-reads the database's table list afterwards, so the
//! misses are proven not to change what a later caller sees.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::error_messages::{assert_refusal, assert_withholds};
use crate::wire::{call, emulator, error_code, error_message, ok, table_names, ACCOUNT_ID};

/// The wording the read's miss answers, written out here as a literal so this suite pins
/// it rather than restating the service's own constant.
const ENTITY_NOT_FOUND: &str = "Entity Not Found";

/// The table every row creates in its database: the control that proves the lookup is
/// answered from the store and not refused unconditionally.
const PRESENT_TABLE: &str = "present_tbl";

/// `(row, database, absent table)` triples spanning the axes the rule generalises over:
/// the two names' values, length, casing, character set and punctuation. The first row
/// is the shape of the recorded behavioural case; the last sits at the documented
/// ceiling of `NameString` (length 1..255, from `smithy_query` on `GetTable`'s
/// `DatabaseName`/`Name`).
fn absent_pairs() -> Vec<(&'static str, String, String)> {
    vec![
        (
            "recorded behavioural shape",
            "sim2real_deny_db_3fd80938d8ed".to_string(),
            "sim2real_facts_c586e4884d78".to_string(),
        ),
        (
            "single character names",
            "d".to_string(),
            "t".to_string(),
        ),
        (
            "mixed case names",
            "Warehouse_DB".to_string(),
            "Sales_By_Day".to_string(),
        ),
        (
            "punctuation and digits",
            "team.data_lake-2026".to_string(),
            "raw.events-2026_01".to_string(),
        ),
        (
            "non-ascii character set",
            "donnees_brutes_\u{e9}t\u{e9}".to_string(),
            "ventes_\u{e9}t\u{e9}".to_string(),
        ),
        (
            "names at the 255 ceiling",
            "d".repeat(255),
            "t".repeat(255),
        ),
    ]
}

/// `(shape, CatalogId, AttributesToGet)` variants: the other input members a template
/// could have reached for. `CatalogId` is the account id the model documents as the
/// default ("If none is provided, the Amazon Web Services account ID is used by
/// default"), and `DEFAULT` is the `AttributesToGet` value that selects the Hive-style
/// definition this read serves (both from `smithy_query` on `GetTable`).
fn request_shapes() -> Vec<RequestShape> {
    vec![
        RequestShape {
            label: "no optional members",
            catalog_id: None,
            attributes: None,
        },
        RequestShape {
            label: "explicit default CatalogId",
            catalog_id: Some(ACCOUNT_ID),
            attributes: None,
        },
        RequestShape {
            label: "AttributesToGet DEFAULT",
            catalog_id: None,
            attributes: Some(&["DEFAULT"]),
        },
        RequestShape {
            label: "CatalogId and AttributesToGet",
            catalog_id: Some(ACCOUNT_ID),
            attributes: Some(&["DEFAULT"]),
        },
    ]
}

/// The optional input members one `GetTable` miss is asked with.
struct RequestShape {
    label: &'static str,
    catalog_id: Option<&'static str>,
    attributes: Option<&'static [&'static str]>,
}

/// One `GetTable` body for a row and a request shape.
fn get_table_request(database: &str, name: &str, shape: &RequestShape) -> Value {
    let mut request = json!({ "DatabaseName": database, "Name": name });
    if let Some(catalog_id) = shape.catalog_id {
        request["CatalogId"] = json!(catalog_id);
    }
    if let Some(attributes) = shape.attributes {
        request["AttributesToGet"] = json!(attributes);
    }
    request
}

/// Read the table that IS present back through `GetTable`, so a row cannot be satisfied
/// by a handler that refuses every read.
async fn assert_present_table_is_served(router: &MultiServiceRouter, case: &str, database: &str) {
    let served = ok(
        router,
        "GetTable",
        &json!({ "DatabaseName": database, "Name": PRESENT_TABLE }),
    )
    .await;
    assert_eq!(
        served["Table"]["Name"].as_str(),
        Some(PRESENT_TABLE),
        "case {case}: the table that exists must still be served, got {served}"
    );
}

/// `GetTable` for a table its database does not hold is refused with HTTP 400,
/// `EntityNotFoundException` and one constant `Message` that is the same for every
/// request — it carries neither name the caller sent nor the catalog the read resolved.
#[tokio::test]
async fn the_get_table_miss_answers_one_constant_for_every_request() {
    let router = emulator();
    let mut answered: Vec<(String, String)> = Vec::new();

    for (row, database, absent) in &absent_pairs() {
        ok(
            &router,
            "CreateDatabase",
            &json!({ "DatabaseInput": { "Name": database } }),
        )
        .await;
        ok(
            &router,
            "CreateTable",
            &json!({ "DatabaseName": database, "TableInput": { "Name": PRESENT_TABLE } }),
        )
        .await;
        assert_present_table_is_served(&router, row, database).await;

        for shape in &request_shapes() {
            let case = format!("{row} / {label}", label = shape.label);
            let request = get_table_request(database, absent, shape);
            // The status, code and wording assertions are the shared ones this crate's
            // refusal suites already use (`error_messages::assert_refusal`).
            let body = assert_refusal(
                &router,
                &case,
                "GetTable",
                &request,
                "EntityNotFoundException",
                ENTITY_NOT_FOUND,
            )
            .await;
            let message = error_message(&body);
            // The constant names neither entity the request addressed, nor the catalog
            // the emulator resolved on the caller's behalf.
            assert_withholds(&case, &message, absent);
            assert_withholds(&case, &message, database);
            assert_withholds(&case, &message, ACCOUNT_ID);
            answered.push((case, message));
        }

        // A refused read is still a read: it leaves the database holding exactly the one
        // table that was created, so the next caller sees what the first one did.
        let listed = ok(&router, "GetTables", &json!({ "DatabaseName": database })).await;
        assert_eq!(
            table_names(&listed),
            vec![PRESENT_TABLE.to_string()],
            "case {row}: a refused read must not change the catalog, got {listed}"
        );
        assert_present_table_is_served(&router, row, database).await;
    }

    // The invariance itself: every request shape above answered the SAME bytes, which a
    // message interpolated from the request could not.
    let (first_case, first) = answered
        .first()
        .cloned()
        .expect("the table above contributes at least one case");
    for (case, message) in &answered {
        assert_eq!(
            message, &first,
            "case {case}: the refusal must not vary with the request; {first_case} answered \
             {first:?} and this one answered {message:?}"
        );
    }
    assert_eq!(
        answered.len(),
        absent_pairs().len() * request_shapes().len(),
        "every row and request shape must have been exercised, got {} cases",
        answered.len()
    );
}

// ---------------------------------------------------------------------------
// The database step of the address
// ---------------------------------------------------------------------------

/// The database holding the control table every row below reads back.
const PRESENT_DATABASE: &str = "present_db";

/// A table name no database in these rows ever held.
const UNKNOWN_TABLE: &str = "never_created_tbl";

/// The table a released database held while it existed: the address stays spelled the
/// same after the database is gone, so the read's two steps both miss on it.
const RELEASED_TABLE: &str = "released_tbl";

/// How a `DatabaseName` comes to resolve to nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Absence {
    /// A name the catalog never held a database under.
    NeverCreated,
    /// A name whose database (and the table in it) the catalog held and then released.
    Released,
}

/// `(row, database, how it is absent)` rows spanning both axes the rule generalises
/// over: how the database came to be unresolvable, and how its name is spelled — value,
/// length, casing, character set and punctuation. The first row is the shape of the
/// recorded behavioural case; the `Released` rows are the teardown shape (the catalog
/// held the entry and released it); the last sits at the documented ceiling of
/// `NameString` (length 1..255, from `smithy_query` on `GetTable`'s `DatabaseName`).
fn absent_databases() -> Vec<(&'static str, String, Absence)> {
    vec![
        (
            "recorded behavioural shape, never created",
            "sim2real_athorigin_b13fe7a5fa41_db".to_string(),
            Absence::NeverCreated,
        ),
        (
            "single character, never created",
            "d".to_string(),
            Absence::NeverCreated,
        ),
        (
            "mixed case, never created",
            "Warehouse_DB".to_string(),
            Absence::NeverCreated,
        ),
        (
            "punctuation and digits, never created",
            "team.data_lake-2026".to_string(),
            Absence::NeverCreated,
        ),
        (
            "non-ascii character set, never created",
            "donnees_brutes_\u{e9}t\u{e9}".to_string(),
            Absence::NeverCreated,
        ),
        (
            "at the 255 ceiling, never created",
            "d".repeat(255),
            Absence::NeverCreated,
        ),
        (
            "released after holding the table",
            "released_db".to_string(),
            Absence::Released,
        ),
        (
            "released, mixed case name",
            "Released_DB_Two".to_string(),
            Absence::Released,
        ),
    ]
}

/// `GetTable` whose `DatabaseName` resolves to no database answers the SAME constant the
/// table step's miss answers: one `EntityNotFoundException` wording for the whole
/// address, carrying neither name the request sent.
///
/// Each row also drives the control the rule is bounded by — the operation that
/// addresses the database ITSELF still answers its own templated sentence — so the two
/// refusals stay distinguishable on the wire.
#[tokio::test]
async fn the_get_table_miss_is_one_constant_whichever_step_of_the_address_missed() {
    let router = emulator();
    // A database that exists, holding a table that exists: the table step's miss is read
    // from here, and is what every database-step miss below must answer identically.
    ok(
        &router,
        "CreateDatabase",
        &json!({ "DatabaseInput": { "Name": PRESENT_DATABASE } }),
    )
    .await;
    ok(
        &router,
        "CreateTable",
        &json!({ "DatabaseName": PRESENT_DATABASE, "TableInput": { "Name": PRESENT_TABLE } }),
    )
    .await;
    let table_step_miss = error_message(
        &assert_refusal(
            &router,
            "table step of the address",
            "GetTable",
            &json!({ "DatabaseName": PRESENT_DATABASE, "Name": UNKNOWN_TABLE }),
            "EntityNotFoundException",
            ENTITY_NOT_FOUND,
        )
        .await,
    );

    let mut cases_run = 0usize;
    for (row, database, absence) in &absent_databases() {
        if *absence == Absence::Released {
            ok(
                &router,
                "CreateDatabase",
                &json!({ "DatabaseInput": { "Name": database } }),
            )
            .await;
            ok(
                &router,
                "CreateTable",
                &json!({ "DatabaseName": database, "TableInput": { "Name": RELEASED_TABLE } }),
            )
            .await;
            // The address resolved while the database was there, so the refusal below is
            // about the release and not about a request the read never served.
            let served = ok(
                &router,
                "GetTable",
                &json!({ "DatabaseName": database, "Name": RELEASED_TABLE }),
            )
            .await;
            assert_eq!(
                served["Table"]["Name"].as_str(),
                Some(RELEASED_TABLE),
                "case {row}: the table must be served while its database exists, got {served}"
            );
            ok(&router, "DeleteDatabase", &json!({ "Name": database })).await;
        }

        for table in [RELEASED_TABLE, UNKNOWN_TABLE] {
            for shape in &request_shapes() {
                let case = format!("{row} / table {table} / {label}", label = shape.label);
                let body = assert_refusal(
                    &router,
                    &case,
                    "GetTable",
                    &get_table_request(database, table, shape),
                    "EntityNotFoundException",
                    ENTITY_NOT_FOUND,
                )
                .await;
                let message = error_message(&body);
                // One wording for the whole address: the database step's miss is the
                // table step's miss, byte for byte.
                assert_eq!(
                    message, table_step_miss,
                    "case {case}: the database step must answer the table step's constant \
                     {table_step_miss:?}, got {message:?}"
                );
                assert_withholds(&case, &message, database);
                assert_withholds(&case, &message, table);
                assert_withholds(&case, &message, ACCOUNT_ID);
                cases_run += 1;
            }
        }

        // The boundary: the read that addresses the DATABASE itself answers its own
        // templated sentence, so the two refusals are still tellable apart. Only the
        // template's shape is asserted here — its name rendering is pinned by
        // `error_messages.rs`.
        let (status, body) = call(&router, "GetDatabase", &json!({ "Name": database })).await;
        assert_eq!(
            status, 400,
            "case {row}: GetDatabase for an absent database must answer 400, got {status} \
             with {body}"
        );
        assert!(
            error_code(&body).contains("EntityNotFoundException"),
            "case {row}: expected EntityNotFoundException from GetDatabase, got {body}"
        );
        let database_message = error_message(&body);
        assert!(
            database_message != ENTITY_NOT_FOUND
                && database_message.starts_with("Database ")
                && database_message.ends_with(" not found."),
            "case {row}: GetDatabase must keep its own templated sentence, got \
             {database_message:?}"
        );

        // A refused read changes nothing a later caller sees: the database that exists
        // still serves the table it holds.
        assert_present_table_is_served(&router, row, PRESENT_DATABASE).await;
    }

    assert_eq!(
        cases_run,
        absent_databases().len() * 2 * request_shapes().len(),
        "every row, table name and request shape must have been exercised, got {cases_run} cases"
    );
}
