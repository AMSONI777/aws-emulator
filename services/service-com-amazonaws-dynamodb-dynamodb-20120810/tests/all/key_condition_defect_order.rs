// SPDX-License-Identifier: CC0-1.0

//! WHICH defect a `KeyConditionExpression` carrying TWO of them is refused for, driven end
//! to end.
//!
//! THE RULE: the defects a key condition's OPERANDS carry — a `:placeholder` the request
//! never defined, and a value of a type the operator or function it was written with does
//! not compare — are read in the order the expression WROTE the operands, and the request is
//! refused for the first of them. Both are settled by the request alone, so both are
//! answered as a 400 `ValidationException` whether or not the addressed table exists; only
//! the rules about how the condition BINDS to a key schema wait for the table
//! (`crate::absent_table_before_key_binding` states that half).
//!
//! The rows span what the rule generalises over: which defect the expression states first,
//! which operator or function the defective operand was written with (`=`, `<`, `>=`,
//! `BETWEEN`, `begins_with`), which side of the comparison carried it, which
//! `AttributeValue` type it had (`N` where a prefix is needed, `BOOL`, `NULL`, `L`, `M`,
//! `SS`), how many clauses the condition states, and whether the table is there at all.
//!
//! The wording helpers are this crate's own statements of the two sentences
//! (`crate::key_condition_operands_and_legacy_conditions` and
//! `crate::undefined_expression_tokens`), so the expectations here cannot drift from them.

use serde_json::{json, Value};

use crate::emulator::{call, describe_when_active, emulator, error_code, message, ok};

/// The table the rows read: a composite primary key whose sort key is a String.
const TABLE: &str = "KeyConditionDefectOrder";

/// A table name nothing here creates, which is what makes the "whatever table was
/// addressed" half of the rule visible.
const ABSENT: &str = "NoSuchTableForDefectOrder";

/// The placeholder no row defines, so every row that writes it carries the undefined-token
/// defect.
const UNDEFINED: &str = ":undef";

/// AWS's sentence for an operand whose type the operator or function does not compare, with
/// the operator as the expression WROTE it and the operand's `AttributeValue` type.
fn incorrect_operand(operator: &str, datatype: &str) -> String {
    format!(
        "Invalid KeyConditionExpression: Incorrect operand type for operator or function; \
         operator or function: {operator}, operand type: {datatype}"
    )
}

/// AWS's sentence for a `:placeholder` `ExpressionAttributeValues` does not define.
fn undefined_value() -> String {
    format!(
        "Invalid KeyConditionExpression: An expression attribute value used in expression is \
         not defined; attribute value: {UNDEFINED}"
    )
}

/// Create [`TABLE`] and wait out the documented `CREATING` -> `ACTIVE` transition.
async fn seeded() -> smithy_server_runtime::MultiServiceRouter {
    let router = emulator();
    ok(
        &router,
        "CreateTable",
        json!({
            "TableName": TABLE,
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            "BillingMode": "PAY_PER_REQUEST",
        }),
    )
    .await;
    describe_when_active(&router, "seed the defect-order table", TABLE).await;
    router
}

/// One row: the condition, the values it defines, and the message the rule requires.
struct Row {
    case: &'static str,
    condition: &'static str,
    values: Value,
    expected: String,
}

/// The rows: each condition carries BOTH defects, and the message is the one its text states
/// first.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "the undefined placeholder is written first, before a bad prefix operand",
            condition: "pk = :undef AND begins_with(sk, :n)",
            values: json!({":n": {"N": "1"}}),
            expected: undefined_value(),
        },
        Row {
            case: "the bad prefix operand is written first, before the undefined placeholder",
            condition: "begins_with(sk, :n) AND pk = :undef",
            values: json!({":n": {"N": "1"}}),
            expected: incorrect_operand("begins_with", "N"),
        },
        Row {
            case: "a list operand written first, before the undefined placeholder",
            condition: "sk >= :l AND pk = :undef",
            values: json!({":l": {"L": [{"S": "a"}]}}),
            expected: incorrect_operand(">=", "L"),
        },
        Row {
            case: "a map operand on the partition key, before the undefined placeholder",
            condition: "pk = :m AND sk = :undef",
            values: json!({":m": {"M": {"a": {"S": "a"}}}}),
            expected: incorrect_operand("=", "M"),
        },
        Row {
            case: "a string-set operand written OPERAND first, before the undefined one",
            condition: ":ss < sk AND pk = :undef",
            values: json!({":ss": {"SS": ["a", "b"]}}),
            expected: incorrect_operand("<", "SS"),
        },
        Row {
            case: "the undefined placeholder as the low bound of a BETWEEN",
            condition: "sk BETWEEN :undef AND :b",
            values: json!({":b": {"BOOL": true}}),
            expected: undefined_value(),
        },
        Row {
            case: "a bad low bound of a BETWEEN, before the undefined high bound",
            condition: "sk BETWEEN :b AND :undef",
            values: json!({":b": {"BOOL": false}}),
            expected: incorrect_operand("BETWEEN", "BOOL"),
        },
        Row {
            case: "three clauses, the bad operand in the middle one",
            condition: "pk = :p AND begins_with(sk, :n) AND other = :undef",
            values: json!({":p": {"S": "p"}, ":n": {"N": "7"}}),
            expected: incorrect_operand("begins_with", "N"),
        },
        Row {
            case: "three clauses, the undefined placeholder in the first one",
            condition: "pk = :undef AND sk = :nul AND other = :o",
            values: json!({":nul": {"NULL": true}, ":o": {"S": "o"}}),
            expected: undefined_value(),
        },
        Row {
            case: "a parenthesised group whose operand is the first defect",
            condition: "(sk > :nul) AND pk = :undef",
            values: json!({":nul": {"NULL": true}}),
            expected: incorrect_operand(">", "NULL"),
        },
    ]
}

/// The `Query` a row sends against `table`. A row defines only the tokens its own condition
/// writes: an unused definition is its own refusal.
fn request_for(row: &Row, table: &str) -> Value {
    json!({
        "TableName": table,
        "KeyConditionExpression": row.condition,
        "ExpressionAttributeValues": row.values,
    })
}

/// RULE: against a table that is there, the refusal is the defect the expression's text
/// states first.
#[tokio::test]
async fn the_operand_defect_the_expression_states_first_is_the_one_answered() {
    let router = seeded().await;
    for row in rows() {
        let (status, body) = call(&router, "Query", request_for(&row, TABLE)).await;
        assert_eq!(
            (status, error_code(&body).as_str()),
            (400, "ValidationException"),
            "case {:?}: expected a 400 ValidationException, got {status} with {body}",
            row.case
        );
        assert_eq!(
            message(&body),
            row.expected,
            "case {:?}: expected the message {:?}, got {:?}",
            row.case,
            row.expected,
            message(&body)
        );
    }
}

/// RULE, the other half: both defects are settled by the REQUEST, so the same row earns the
/// same sentence when the table it addresses does not exist at all.
#[tokio::test]
async fn the_same_defect_is_answered_for_a_table_this_account_does_not_hold() {
    let router = emulator();
    for row in rows() {
        let (status, body) = call(&router, "Query", request_for(&row, ABSENT)).await;
        assert_eq!(
            (status, error_code(&body).as_str()),
            (400, "ValidationException"),
            "case {:?}: a defect the request alone settles is answered before the table is \
             resolved, got {status} with {body}",
            row.case
        );
        assert_eq!(
            message(&body),
            row.expected,
            "case {:?}: expected the message {:?} for an absent table, got {:?}",
            row.case,
            row.expected,
            message(&body)
        );
    }
}

/// RULE: with neither defect the same shapes of condition are SERVED, so no row above
/// passes because key conditions are refused in general.
#[tokio::test]
async fn the_same_conditions_with_well_typed_defined_operands_are_served() {
    let router = seeded().await;
    ok(
        &router,
        "PutItem",
        json!({
            "TableName": TABLE,
            "Item": {"pk": {"S": "p"}, "sk": {"S": "alpha"}},
        }),
    )
    .await;

    // Each row: the same shape of condition as a refused row above, with every operand
    // defined and of a type its operator compares.
    let served: [(&str, &str, Value); 4] = [
        (
            "a prefix on the sort key",
            "pk = :p AND begins_with(sk, :n)",
            json!({":p": {"S": "p"}, ":n": {"S": "al"}}),
        ),
        (
            "an ordering comparison on the sort key",
            "sk >= :l AND pk = :p",
            json!({":p": {"S": "p"}, ":l": {"S": "a"}}),
        ),
        (
            "an operand written before its operator",
            ":lo < sk AND pk = :p",
            json!({":p": {"S": "p"}, ":lo": {"S": "a"}}),
        ),
        (
            "a BETWEEN over the sort key",
            "pk = :p AND sk BETWEEN :b AND :c",
            json!({":p": {"S": "p"}, ":b": {"S": "a"}, ":c": {"S": "z"}}),
        ),
    ];
    for (case, condition, values) in served {
        let (status, body) = call(
            &router,
            "Query",
            json!({
                "TableName": TABLE,
                "KeyConditionExpression": condition,
                "ExpressionAttributeValues": values,
            }),
        )
        .await;
        assert_eq!(
            (status, body["Count"].clone()),
            (200, json!(1)),
            "case {case:?}: expected the seeded item, got {status} with {body}"
        );
        assert_eq!(
            body["Items"][0]["sk"],
            json!({"S": "alpha"}),
            "case {case:?}: expected the seeded item's sort key, got {:?}",
            body["Items"][0]
        );
    }
}
