// SPDX-License-Identifier: CC0-1.0

//! What ONE `Get` of a transactional read REPORTS, and how its substitution table is held
//! to its projection, driven end to end.
//!
//! RULE under test: every element of a transactional read states what it reports through
//! its own `ProjectionExpression`, resolved through its own `ExpressionAttributeNames`
//! aliases — so the call is SERVED, with each `Responses[i]` carrying the item behind that
//! element's key narrowed to the locations that element projected, in request order — and
//! an `ExpressionAttributeNames` entry whose key that element's projection never
//! references refuses the WHOLE call as the element's own unused-entry sentence at HTTP
//! 400 `ValidationException`, with no cancellation reasons: it is a refusal of the input,
//! decided before any item is read, and not a cancelled transaction.
//!
//! The served rows span what the rule generalises over: the form of the projection (no
//! projection at all, a whole attribute, an attribute reached through an alias, several
//! attributes, a path into a map, a path whose every step is aliased, a path into a list,
//! an alias standing for a reserved word, a location the item holds nothing at), and then
//! the element axis — several elements each narrowed by its OWN projection, one of them
//! projecting nothing and one addressing a key that holds no item.
//!
//! The refusal rows span how many entries are unused (one, two, three), whether the
//! projection references any entry at all, which order the request wrote them in, the form
//! of the projection the entries were offered to, and where the faulty element sits among
//! its siblings (first, second).
//!
//! The unused-entry sentence is the one this crate states once, in
//! `undefined_expression_tokens`, so no suite spells it twice;
//! `element_expression_envelopes` takes the ENVELOPE axis of the same sentence and
//! `index_and_projection_reads` the read-path axis of the projection itself.

use serde_json::{json, Value};

use crate::emulator::{call, emulator, error_code, message, ok};
use crate::table_items::create_active_table;
use crate::undefined_expression_tokens::unused_entries_in_element;

/// The table every row below drives: one string partition key.
const TABLE: &str = "TransactProjectedReads";

/// The item most rows project out of.
fn seed_key() -> Value {
    json!({"pk": {"S": "seed"}})
}

/// A second stored item, so a row can narrow two elements differently in one call.
fn other_key() -> Value {
    json!({"pk": {"S": "other"}})
}

/// A third stored item, so a row can put an element that projects NOTHING beside ones
/// that do.
fn third_key() -> Value {
    json!({"pk": {"S": "third"}})
}

/// A key nothing stores, so a row can show what an element that finds no item reports.
fn absent_key() -> Value {
    json!({"pk": {"S": "absent"}})
}

/// The items every row reads. `status` is a reserved word, so a projection can only reach
/// it through an alias; `doc` and `parts` are the containers the path rows step into.
fn stored_items() -> Vec<Value> {
    vec![
        json!({"pk": {"S": "seed"}, "color": {"S": "red"}, "note": {"S": "first"},
               "status": {"S": "active"},
               "doc": {"M": {"leaf": {"S": "deep"}, "branch": {"N": "7"}}},
               "parts": {"L": [{"S": "zero"}, {"S": "one"}, {"S": "two"}]}}),
        json!({"pk": {"S": "other"}, "color": {"S": "blue"}, "note": {"S": "second"}}),
        json!({"pk": {"S": "third"}, "color": {"S": "green"}}),
    ]
}

/// The table and the items every row is driven against.
async fn seeded() -> smithy_server_runtime::MultiServiceRouter {
    let router = emulator();
    create_active_table(&router, TABLE, &[("pk", "HASH", "S")]).await;
    for item in stored_items() {
        ok(&router, "PutItem", json!({"TableName": TABLE, "Item": item})).await;
    }
    router
}

/// One `Get` element: the table, the key, and whichever of the two projection members the
/// element carries.
fn get(key: Value, expression: Option<&str>, names: &Value) -> Value {
    let mut element = json!({"TableName": TABLE, "Key": key});
    if let Some(expression) = expression {
        element["ProjectionExpression"] = json!(expression);
    }
    if !names.is_null() {
        element["ExpressionAttributeNames"] = names.clone();
    }
    json!({"Get": element})
}

/// What the element at `at` reported of the item it addressed: its `Item`, or the empty
/// map where it reported no attributes at all — "if the requested item has no projected
/// attributes, the corresponding ItemResponse object is an empty Map"
/// (`TransactGetItems$Responses`).
fn reported(response: &Value, at: usize) -> Value {
    response["Responses"][at]
        .get("Item")
        .cloned()
        .unwrap_or(json!({}))
}

/// The whole item `key` stores, read back through `GetItem` — the reader the transactional
/// read is held to, so a row compares what a projection narrowed against what the store
/// holds.
async fn whole_item(router: &smithy_server_runtime::MultiServiceRouter, key: Value) -> Value {
    let read = ok(router, "GetItem", json!({"TableName": TABLE, "Key": key})).await;
    read.get("Item").cloned().unwrap_or(json!({}))
}

/// One served row: the case, the projection the element carries, its aliases, and the item
/// the transaction must report for the seeded item.
struct ProjectionRow {
    case: &'static str,
    expression: Option<&'static str>,
    names: Value,
    expected: Value,
}

/// The forms an element's projection takes. "These attributes can include scalars, sets,
/// or elements of a JSON document" and "If no attribute names are specified, then all
/// attributes of the specified item are returned" (`Get$ProjectionExpression`).
fn projection_rows() -> Vec<ProjectionRow> {
    vec![
        ProjectionRow {
            case: "no projection at all reports the whole item",
            expression: None,
            names: Value::Null,
            expected: stored_items()[0].clone(),
        },
        ProjectionRow {
            case: "one whole attribute",
            expression: Some("color"),
            names: Value::Null,
            expected: json!({"color": {"S": "red"}}),
        },
        ProjectionRow {
            case: "an attribute reached through an alias",
            expression: Some("#n"),
            names: json!({"#n": "color"}),
            expected: json!({"color": {"S": "red"}}),
        },
        ProjectionRow {
            case: "the key attribute alone",
            expression: Some("pk"),
            names: Value::Null,
            expected: json!({"pk": {"S": "seed"}}),
        },
        ProjectionRow {
            case: "two attributes, one of them aliased",
            expression: Some("#n, note"),
            names: json!({"#n": "color"}),
            expected: json!({"color": {"S": "red"}, "note": {"S": "first"}}),
        },
        ProjectionRow {
            case: "an alias standing for a reserved word",
            expression: Some("#s"),
            names: json!({"#s": "status"}),
            expected: json!({"status": {"S": "active"}}),
        },
        ProjectionRow {
            case: "a path into a map, which reports the container it steps through",
            expression: Some("doc.leaf"),
            names: Value::Null,
            expected: json!({"doc": {"M": {"leaf": {"S": "deep"}}}}),
        },
        ProjectionRow {
            case: "a path into a map with every step aliased",
            expression: Some("#d.#b"),
            names: json!({"#d": "doc", "#b": "branch"}),
            expected: json!({"doc": {"M": {"branch": {"N": "7"}}}}),
        },
        ProjectionRow {
            case: "a path into a list, which reports a one-element list",
            expression: Some("parts[1]"),
            names: Value::Null,
            expected: json!({"parts": {"L": [{"S": "one"}]}}),
        },
        ProjectionRow {
            case: "a location the item holds nothing at, which reports no attributes",
            expression: Some("#missing"),
            names: json!({"#missing": "absent"}),
            expected: json!({}),
        },
    ]
}

#[tokio::test]
async fn an_element_of_a_transactional_read_reports_what_its_projection_names() {
    let router = seeded().await;
    let whole = whole_item(&router, seed_key()).await;

    for row in projection_rows() {
        let request = json!({"TransactItems": [get(seed_key(), row.expression, &row.names)]});
        let served = ok(&router, "TransactGetItems", request.clone()).await;
        assert_eq!(
            served["Responses"].as_array().map(Vec::len),
            Some(1),
            "case {:?}: one ItemResponse per element, got {served}",
            row.case
        );
        let item = reported(&served, 0);
        assert_eq!(
            item, row.expected,
            "case {:?}: expected {}, got {item}",
            row.case, row.expected
        );
    }

    // A read reports a projection; it never narrows what the store holds, so the item is
    // still whole for the next caller.
    let after = whole_item(&router, seed_key()).await;
    assert_eq!(
        after, whole,
        "the projected reads must leave the stored item whole: expected {whole}, got {after}"
    );
}

#[tokio::test]
async fn every_element_is_narrowed_by_its_own_projection_in_request_order() {
    let router = seeded().await;

    let served = ok(
        &router,
        "TransactGetItems",
        json!({"TransactItems": [
            get(seed_key(), Some("#n"), &json!({"#n": "color"})),
            get(other_key(), Some("note"), &Value::Null),
            get(absent_key(), Some("color"), &Value::Null),
            get(third_key(), None, &Value::Null),
        ]}),
    )
    .await;
    assert_eq!(
        served["Responses"].as_array().map(Vec::len),
        Some(4),
        "one ItemResponse per element, in request order, got {served}"
    );
    let expected = [
        ("the first element's alias", json!({"color": {"S": "red"}})),
        ("the second element's attribute", json!({"note": {"S": "second"}})),
        ("an element whose key stores no item", json!({})),
        ("an element that projects nothing", stored_items()[2].clone()),
    ];
    for (at, (case, want)) in expected.iter().enumerate() {
        let item = reported(&served, at);
        assert_eq!(
            &item, want,
            "case {case:?} (element {at}): expected {want}, got {served}"
        );
    }
}

/// One refusal row: the case, the elements the call carries, and the keys the unused-entry
/// sentence must list, in the order it lists them.
struct UnusedRow {
    case: &'static str,
    items: Value,
    keys: &'static [&'static str],
}

/// Every way an element of a transactional read can define an `ExpressionAttributeNames`
/// entry its own projection never references: "One or more substitution tokens for
/// attribute names in the ProjectionExpression parameter" (`Get$ExpressionAttributeNames`)
/// — an entry no projection substitutes stands for nothing.
fn unused_rows() -> Vec<UnusedRow> {
    vec![
        UnusedRow {
            case: "an entry offered to a projection that references none of it",
            items: json!([get(seed_key(), Some("pk"), &json!({"#n": "color"}))]),
            keys: &["#n"],
        },
        UnusedRow {
            case: "one entry unused beside one the projection references",
            items: json!([get(
                seed_key(),
                Some("#n"),
                &json!({"#n": "color", "#m": "note"})
            )]),
            keys: &["#m"],
        },
        UnusedRow {
            case: "two entries unused",
            items: json!([get(
                seed_key(),
                Some("#n"),
                &json!({"#n": "color", "#a": "note", "#b": "doc"})
            )]),
            keys: &["#a", "#b"],
        },
        UnusedRow {
            case: "three entries unused",
            items: json!([get(
                seed_key(),
                Some("#n"),
                &json!({"#n": "color", "#a": "note", "#b": "doc", "#c": "parts"})
            )]),
            keys: &["#a", "#b", "#c"],
        },
        UnusedRow {
            // The entries are listed in one stable order whatever order the request wrote
            // them in, so the same request earns the same sentence every time.
            case: "two entries the request wrote in the reverse of the listed order",
            items: json!([get(
                seed_key(),
                Some("pk"),
                &json!({"#z": "note", "#a": "color"})
            )]),
            keys: &["#a", "#z"],
        },
        UnusedRow {
            case: "an entry offered to a projection whose every step is aliased",
            items: json!([get(
                seed_key(),
                Some("#d.#l"),
                &json!({"#d": "doc", "#l": "leaf", "#x": "note"})
            )]),
            keys: &["#x"],
        },
        UnusedRow {
            case: "an entry on the SECOND element, behind a sound projected one",
            items: json!([
                get(seed_key(), Some("#n"), &json!({"#n": "color"})),
                get(other_key(), Some("note"), &json!({"#u": "color"})),
            ]),
            keys: &["#u"],
        },
        UnusedRow {
            case: "an entry on the second element of an otherwise unprojected call",
            items: json!([
                get(seed_key(), None, &Value::Null),
                get(
                    other_key(),
                    Some("#n"),
                    &json!({"#n": "note", "#spare": "color"})
                ),
            ]),
            keys: &["#spare"],
        },
    ]
}

#[tokio::test]
async fn an_element_entry_its_projection_never_references_refuses_the_call() {
    let router = seeded().await;
    let before = whole_item(&router, seed_key()).await;

    for row in unused_rows() {
        let expected = unused_entries_in_element("ExpressionAttributeNames", row.keys);
        let (status, body) = call(
            &router,
            "TransactGetItems",
            json!({"TransactItems": row.items.clone()}),
        )
        .await;
        assert_eq!(
            (status, error_code(&body).as_str()),
            (400, "ValidationException"),
            "case {:?}: expected 400 ValidationException, got {status} with {body}",
            row.case
        );
        let said = message(&body);
        assert_eq!(
            said, expected,
            "case {:?}: expected {expected:?}, got {said:?}",
            row.case
        );
        // The input itself is refused, before any item is read, so there is no cancelled
        // transaction to report reasons for.
        assert_eq!(
            body.get("CancellationReasons"),
            None,
            "case {:?}: a refused input reports no cancellation reasons, got {body}",
            row.case
        );
    }

    // Every refusal above served nothing, so the items stand exactly as they were written.
    let after = whole_item(&router, seed_key()).await;
    assert_eq!(
        after, before,
        "the refused calls must leave the store where it was: expected {before}, got {after}"
    );
}
