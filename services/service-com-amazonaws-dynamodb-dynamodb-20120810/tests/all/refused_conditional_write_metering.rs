// SPDX-License-Identifier: CC0-1.0

//! What a write REFUSED because its condition was not met costs the table it addressed.
//!
//! The rule under test: a conditional write the service turns down stores nothing and reports
//! no capacity in band, and is METERED all the same — the units the item the key holds costs,
//! one unit for a key that holds nothing — into that table's `AWS/DynamoDB`
//! `ConsumedWriteCapacityUnits` series under the `TableName` dimension. So a table whose
//! writers keep LOSING an optimistic-concurrency race carries the same consumption as a twin
//! whose identical writes all won, and neither reads as idle.
//!
//! The catalog spans what the rule generalises over: which surface refused the write (the
//! item API's three write verbs, the statement surface, the batched statement surface and the
//! two transactional surfaces), how large the item the refusal is weighed on is, how many
//! writes were refused, and the capacity mode the table is in — rather than one operation
//! against one table.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use super::emulator::{
    call, describe_when_active, emulator_with_cloudwatch, error_code, ok, ok_cloudwatch,
};

/// The namespace Amazon DynamoDB publishes a table's own metrics under.
const NAMESPACE: &str = "AWS/DynamoDB";

/// The metric that counts write capacity units.
const CONSUMED_WRITE: &str = "ConsumedWriteCapacityUnits";

/// The partition key value every row addresses.
const KEY: &str = "race";

/// The version the seeded item carries, which a winning write states and a losing one does
/// not.
const LIVE_VERSION: i64 = 0;

/// The version a LOSING writer believes the item carries: one no stored item ever holds here,
/// so every write guarded by it is refused.
const STALE_VERSION: i64 = 99;

/// The largest difference two capacity figures may show and still be the same figure: both
/// sides are sums of whole units, so anything above rounding is a real divergence.
const TOLERANCE: f64 = 1e-9;

/// How a surface reports the refusal of a write whose condition was not met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// A modelled `ConditionalCheckFailedException`, HTTP 400.
    Modelled,
    /// A `TransactionCanceledException` whose reasons name the element that failed.
    Cancelled,
    /// A served batch whose SLOT carries the failure code.
    Slot,
}

/// One row of the catalog: the surface a write is refused on, and the same write applied.
struct RefusalRow {
    case: &'static str,
    /// The operation both the refused and the applied write are made with.
    operation: &'static str,
    /// The table's billing mode: the units a refused write consumes are counted either way.
    billing_mode: &'static str,
    /// Bytes of payload the addressed item carries, which decides what one write of it costs.
    payload_bytes: usize,
    /// How many writes are refused on the subject table — and applied on its twin.
    writes: usize,
    /// The least units ONE refused write of this row can cost: one unit per kilobyte of the
    /// item it is weighed on, never less than one, doubled for a transactional write.
    least_units_each: f64,
    /// How this surface reports the refusal.
    refusal: Refusal,
    /// The request the SUBJECT table refuses: the write guarded by a stale version.
    refused: fn(&str, usize) -> Value,
    /// The SAME write on the TWIN table, stating the version the item really carries, so it
    /// applies.
    applied: fn(&str, usize) -> Value,
}

/// The catalog.
const REFUSAL_ROWS: &[RefusalRow] = &[
    RefusalRow {
        case: "ten PutItems that lose the race, against ten identical ones that win",
        operation: "PutItem",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 0,
        writes: 10,
        least_units_each: 1.0,
        refusal: Refusal::Modelled,
        refused: |table, padding| put(table, padding, STALE_VERSION),
        applied: |table, padding| put(table, padding, LIVE_VERSION),
    },
    RefusalRow {
        case: "a refused PutItem of a multi-kilobyte item",
        operation: "PutItem",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 3_000,
        writes: 2,
        least_units_each: 3.0,
        refusal: Refusal::Modelled,
        refused: |table, padding| put(table, padding, STALE_VERSION),
        applied: |table, padding| put(table, padding, LIVE_VERSION),
    },
    RefusalRow {
        case: "refused PutItems against a provisioned table",
        operation: "PutItem",
        billing_mode: "PROVISIONED",
        payload_bytes: 0,
        writes: 3,
        least_units_each: 1.0,
        refusal: Refusal::Modelled,
        refused: |table, padding| put(table, padding, STALE_VERSION),
        applied: |table, padding| put(table, padding, LIVE_VERSION),
    },
    RefusalRow {
        case: "a refused UpdateItem",
        operation: "UpdateItem",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 900,
        writes: 3,
        least_units_each: 1.0,
        refusal: Refusal::Modelled,
        refused: |table, _| update(table, STALE_VERSION),
        applied: |table, _| update(table, LIVE_VERSION),
    },
    RefusalRow {
        case: "a refused DeleteItem",
        operation: "DeleteItem",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 2_500,
        writes: 1,
        least_units_each: 3.0,
        refusal: Refusal::Modelled,
        refused: |table, _| delete(table, STALE_VERSION),
        applied: |table, _| delete(table, LIVE_VERSION),
    },
    RefusalRow {
        case: "a refused statement-surface UPDATE",
        operation: "ExecuteStatement",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 0,
        writes: 2,
        least_units_each: 1.0,
        refusal: Refusal::Modelled,
        refused: |table, _| json!({"Statement": statement(table, STALE_VERSION)}),
        applied: |table, _| json!({"Statement": statement(table, LIVE_VERSION)}),
    },
    RefusalRow {
        case: "a refused slot of a batched statement",
        operation: "BatchExecuteStatement",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 0,
        writes: 2,
        least_units_each: 1.0,
        refusal: Refusal::Slot,
        refused: |table, _| json!({"Statements": [{"Statement": statement(table, STALE_VERSION)}]}),
        applied: |table, _| json!({"Statements": [{"Statement": statement(table, LIVE_VERSION)}]}),
    },
    RefusalRow {
        case: "a transaction cancelled by one element's unmet condition",
        operation: "TransactWriteItems",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 0,
        writes: 2,
        // "If the conditional write were part of a transaction, it would consume two write
        // capacity units."
        least_units_each: 2.0,
        refusal: Refusal::Cancelled,
        refused: |table, padding| transaction(table, padding, STALE_VERSION),
        applied: |table, padding| transaction(table, padding, LIVE_VERSION),
    },
    RefusalRow {
        case: "a statement transaction cancelled by an unmet predicate",
        operation: "ExecuteTransaction",
        billing_mode: "PAY_PER_REQUEST",
        payload_bytes: 0,
        writes: 1,
        least_units_each: 2.0,
        refusal: Refusal::Cancelled,
        refused: |table, _| {
            json!({"TransactStatements": [{"Statement": statement(table, STALE_VERSION)}]})
        },
        applied: |table, _| {
            json!({"TransactStatements": [{"Statement": statement(table, LIVE_VERSION)}]})
        },
    },
];

#[tokio::test]
async fn a_refused_conditional_write_is_metered_like_the_write_that_would_have_applied() {
    for row in REFUSAL_ROWS {
        let case = row.case;
        let router = emulator_with_cloudwatch();
        // Twin tables, identically created and identically seeded, so the only difference
        // between their series is what the writes under test did. Both creates are issued
        // before either is waited on, so the two tables become ACTIVE over one span.
        let subject = "loser";
        let twin = "winner";
        for table in [subject, twin] {
            create_table(&router, table, row.billing_mode).await;
        }
        for table in [subject, twin] {
            // A table is served once it is ACTIVE: the waiter loop a client runs after a
            // create.
            describe_when_active(&router, case, table).await;
            seed_item(&router, table, row.payload_bytes).await;
        }
        let seeded = series_sum(&router, subject, CONSUMED_WRITE).await;

        for attempt in 0..row.writes {
            let body = (row.refused)(subject, row.payload_bytes);
            let (status, answered) = call(&router, row.operation, body.clone()).await;
            assert_refused(case, attempt, row, status, &answered);
            let applied = (row.applied)(twin, row.payload_bytes);
            let (status, answered) = call(&router, row.operation, applied.clone()).await;
            assert_applied(case, attempt, row, status, &answered);
        }

        // The refused writes left the subject's item exactly as it was seeded.
        let held = stored_item(&router, subject).await;
        assert_eq!(
            held,
            Some(json!({"N": LIVE_VERSION.to_string()})),
            "case {case:?}: expected the refused writes to leave the seeded version in place, \
             got {held:?}"
        );

        let refused_units = series_sum(&router, subject, CONSUMED_WRITE).await - seeded;
        let applied_units = series_sum(&router, twin, CONSUMED_WRITE).await - seeded;
        let least = row.least_units_each * row.writes as f64;
        assert!(
            refused_units >= least - TOLERANCE,
            "case {case:?}: expected the {} refused writes to count at least {least} units into \
             the {CONSUMED_WRITE} series of {subject:?}, got {refused_units}",
            row.writes
        );
        assert!(
            (refused_units - applied_units).abs() < TOLERANCE,
            "case {case:?}: expected the refused writes to cost what the same writes applied \
             cost — {applied_units} units on {twin:?} — got {refused_units} on {subject:?}"
        );
    }
}

/// A refused write on a key that holds NO item costs the one-unit minimum, and the series
/// carries exactly that: there is no stored item to weigh it on, and nothing else has been
/// written to this table.
#[tokio::test]
async fn a_refusal_on_a_key_that_holds_no_item_counts_the_one_unit_minimum() {
    let router = emulator_with_cloudwatch();
    let table = "absent";
    let case = "a guarded write of a key that holds no item";
    create_table(&router, table, "PAY_PER_REQUEST").await;
    describe_when_active(&router, case, table).await;

    let (status, answered) = call(
        &router,
        "PutItem",
        json!({
            "TableName": table,
            "Item": {"pk": {"S": KEY}, "version": {"N": "1"}},
            "ConditionExpression": "attribute_exists(version)",
            "ReturnConsumedCapacity": "TOTAL",
        }),
    )
    .await;
    assert_eq!(
        (status, error_code(&answered)),
        (400, "ConditionalCheckFailedException".to_string()),
        "case {case:?}: expected the guarded put to be refused, got {status} {answered:?}"
    );
    assert!(
        answered.get("ConsumedCapacity").is_none(),
        "case {case:?}: a refusal reports no ConsumedCapacity in band, got {answered:?}"
    );
    let counted = series_sum(&router, table, CONSUMED_WRITE).await;
    assert!(
        (counted - 1.0).abs() < TOLERANCE,
        "case {case:?}: expected the {CONSUMED_WRITE} series of {table:?} to carry the one-unit \
         minimum, got {counted}"
    );
    // And the refusal stored nothing.
    let held = stored_item(&router, table).await;
    assert!(
        held.is_none(),
        "case {case:?}: expected the refused put to store nothing, got {held:?}"
    );
}

/// Every refused write of a row is reported the way its surface reports an unmet condition,
/// and reports no capacity in band whichever surface it came in through.
fn assert_refused(case: &str, attempt: usize, row: &RefusalRow, status: u16, answered: &Value) {
    match row.refusal {
        Refusal::Modelled => {
            assert_eq!(
                (status, error_code(answered)),
                (400, "ConditionalCheckFailedException".to_string()),
                "case {case:?}, attempt {attempt}: expected the modelled refusal, got {status} \
                 {answered:?}"
            );
        }
        Refusal::Cancelled => {
            assert_eq!(
                (status, error_code(answered)),
                (400, "TransactionCanceledException".to_string()),
                "case {case:?}, attempt {attempt}: expected the cancellation, got {status} \
                 {answered:?}"
            );
            let reasons = answered["CancellationReasons"].to_string();
            assert!(
                reasons.contains("ConditionalCheckFailed"),
                "case {case:?}, attempt {attempt}: expected a reason naming the unmet \
                 condition, got {reasons}"
            );
        }
        Refusal::Slot => {
            assert_eq!(
                status, 200,
                "case {case:?}, attempt {attempt}: a batch serves its slots, got {status} \
                 {answered:?}"
            );
            let slots = answered["Responses"].to_string();
            assert!(
                slots.contains("ConditionalCheckFailed"),
                "case {case:?}, attempt {attempt}: expected the slot to carry the failure, got \
                 {slots}"
            );
        }
    }
    // A refusal the whole request is answered with names no capacity at all: the refused call
    // reports no `ConsumedCapacity` member in band, however much it consumed out of band.
    if row.refusal != Refusal::Slot {
        assert!(
            !mentions_capacity(answered),
            "case {case:?}, attempt {attempt}: expected the refusal to report no \
             ConsumedCapacity, got {answered:?}"
        );
    }
}

/// The twin's write applies, whichever surface it came in through.
fn assert_applied(case: &str, attempt: usize, row: &RefusalRow, status: u16, answered: &Value) {
    assert_eq!(
        status, 200,
        "case {case:?}, attempt {attempt}: expected the winning {} to apply, got {status} \
         {answered:?}",
        row.operation
    );
    if row.refusal == Refusal::Slot {
        let slots = answered["Responses"].to_string();
        assert!(
            !slots.contains("Error"),
            "case {case:?}, attempt {attempt}: expected every slot of the winning batch to \
             apply, got {slots}"
        );
    }
}

/// Whether a response mentions a consumed-capacity member anywhere in it.
fn mentions_capacity(answered: &Value) -> bool {
    match answered {
        Value::Object(members) => members
            .iter()
            .any(|(name, value)| name == "ConsumedCapacity" || mentions_capacity(value)),
        Value::Array(entries) => entries.iter().any(mentions_capacity),
        _ => false,
    }
}

/// The item the seeded key holds, padded to `padding` bytes beside the key and the version.
fn seeded(padding: usize) -> Value {
    let mut item = json!({"pk": {"S": KEY}, "version": {"N": LIVE_VERSION.to_string()}});
    if padding > 0 {
        item["payload"] = json!({"S": "x".repeat(padding)});
    }
    item
}

/// A put of the seeded item, unchanged in shape and size and guarded on the version
/// `expected`, so what it costs applied is what the stored item costs — the same figure a
/// refusal of it is weighed on. A losing writer states a version no stored item holds; a
/// winning one states the version it really carries.
fn put(table: &str, padding: usize, expected: i64) -> Value {
    json!({
        "TableName": table,
        "Item": seeded(padding),
        "ConditionExpression": "version = :expected",
        "ExpressionAttributeValues": {":expected": {"N": expected.to_string()}},
        "ReturnConsumedCapacity": "TOTAL",
    })
}

/// A guarded update that rewrites the version it already carries, so repeating it is
/// idempotent.
fn update(table: &str, expected: i64) -> Value {
    json!({
        "TableName": table,
        "Key": {"pk": {"S": KEY}},
        "UpdateExpression": "SET version = :live",
        "ConditionExpression": "version = :expected",
        "ExpressionAttributeValues": {
            ":expected": {"N": expected.to_string()},
            ":live": {"N": LIVE_VERSION.to_string()},
        },
        "ReturnConsumedCapacity": "TOTAL",
    })
}

/// A guarded delete of the seeded item.
fn delete(table: &str, expected: i64) -> Value {
    json!({
        "TableName": table,
        "Key": {"pk": {"S": KEY}},
        "ConditionExpression": "version = :expected",
        "ExpressionAttributeValues": {":expected": {"N": expected.to_string()}},
        "ReturnConsumedCapacity": "TOTAL",
    })
}

/// A guarded transactional put of the seeded item, as `TransactWriteItems` states it.
fn transaction(table: &str, padding: usize, expected: i64) -> Value {
    json!({
        "TransactItems": [{
            "Put": {
                "TableName": table,
                "Item": seeded(padding),
                "ConditionExpression": "version = :expected",
                "ExpressionAttributeValues": {":expected": {"N": expected.to_string()}},
            },
        }],
        "ReturnConsumedCapacity": "TOTAL",
    })
}

/// The statement surfaces' guarded write: the `WHERE` clause pins the key and states the
/// version the writer believes it holds, and sets that same version back, so a winning
/// statement is idempotent.
fn statement(table: &str, expected: i64) -> String {
    format!(
        "UPDATE \"{table}\" SET version = {LIVE_VERSION} WHERE pk = '{KEY}' AND version = \
         {expected}"
    )
}

/// Create one table in `billing_mode`. The caller waits for it to serve, so a suite that
/// creates several tables can have them become ACTIVE over one span rather than one each.
async fn create_table(router: &MultiServiceRouter, name: &str, billing_mode: &str) {
    let mut request = json!({
        "TableName": name,
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "BillingMode": billing_mode,
    });
    if billing_mode == "PROVISIONED" {
        // Provisioned far above what these rows ask for, so nothing here is throttled and
        // what the series carries is what the writes consumed.
        request["ProvisionedThroughput"] =
            json!({"ReadCapacityUnits": 1_000, "WriteCapacityUnits": 1_000});
    }
    ok(router, "CreateTable", request).await;
}

/// Write the item every row addresses. It lands BEFORE the sums a row asserts are read, and
/// both tables are seeded the same way, so what it consumed is outside the delta under test.
async fn seed_item(router: &MultiServiceRouter, table: &str, padding: usize) {
    ok(
        router,
        "PutItem",
        json!({"TableName": table, "Item": seeded(padding)}),
    )
    .await;
}

/// The `version` attribute the addressed key holds, read consistently, or `None` when the key
/// holds no item.
async fn stored_item(router: &MultiServiceRouter, table: &str) -> Option<Value> {
    let read = ok(
        router,
        "GetItem",
        json!({"TableName": table, "Key": {"pk": {"S": KEY}}, "ConsistentRead": true}),
    )
    .await;
    read.get("Item")
        .and_then(|item| item.get("version"))
        .cloned()
}

/// The `Sum` CloudWatch reports for a table's write-consumption series, over a window wide
/// enough to hold everything this suite published.
async fn series_sum(router: &MultiServiceRouter, table: &str, metric: &str) -> f64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("an instant after the epoch")
        .as_secs_f64();
    let answered = ok_cloudwatch(
        router,
        "GetMetricStatistics",
        json!({
            "Namespace": NAMESPACE,
            "MetricName": metric,
            "Dimensions": [{"Name": "TableName", "Value": table}],
            "StartTime": now - 3600.0,
            "EndTime": now + 3600.0,
            "Period": 60,
            "Statistics": ["Sum"],
        }),
    )
    .await;
    answered["Datapoints"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|point| point["Sum"].as_f64())
        .sum()
}
