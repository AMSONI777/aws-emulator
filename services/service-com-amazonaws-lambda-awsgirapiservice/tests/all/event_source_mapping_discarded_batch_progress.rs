// SPDX-License-Identifier: CC0-1.0

//! What a mapping on an Amazon DynamoDB table's STREAM does with the records BEHIND a batch
//! it gave up on, end to end over the wire with DynamoDB, DynamoDB Streams, Amazon SQS and
//! IAM mounted beside Lambda on ONE engine — so the items are written where a client writes
//! them, the shard is read as the function's own execution role, and every effect this suite
//! asserts is read back where a client reads it.
//!
//! The RULE asserted over the table below: once a mapping has spent on one batch every
//! attempt its `MaximumRetryAttempts` allows — "Discard records after the specified number of
//! retries. The default value is infinite (-1)" — that batch is DISCARDED and the shard is
//! read on from past it, so the records behind it are delivered and processed while the
//! discarded records' own effects never happen; and where the mapping's
//! `DestinationConfig$OnFailure` names a destination ("The destination configuration for
//! failed invocations"), exactly one record describing each discarded batch is written there,
//! while a mapping naming none records the batch nowhere at all. Whether a destination is
//! named decides only where the batch is recorded, never whether the shard advances.
//!
//! Every verdict is a consequence of the handler having been invoked with the batch: the
//! function's package RUNS, it decides out of each record's own image whether to refuse it,
//! and the item a row reads back out of the results table was written by the handler through
//! the AWS SDK its runtime supplies — a mapping that stalls on the refused record leaves that
//! table short and the row fails.
//!
//! The rows differ along what the rule generalises over: how many retries the mapping allows
//! (none, one), where in the stream the refused records sit (first, in the middle, two in a
//! row), how many records there are, and whether the mapping names a failure destination.
//!
//! Nothing here waits a span of its own: every wait looks again until what it waits for is
//! there or a generous deadline passes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::event_source_mapping_role_access::{allow, given_role, logs_only, DYNAMODB_READS};
use crate::synchronous_invoke_run::package;

/// The Region every call below signs for, and the Region every ARN carries.
const REGION: &str = "us-east-1";

/// Where `CreateFunction` is bound, and where `CreateEventSourceMapping` is.
const FUNCTIONS_URI: &str = "/2015-03-31/functions";
/// See [`FUNCTIONS_URI`].
const MAPPINGS_URI: &str = "/2015-03-31/event-source-mappings";

/// The `X-Amz-Target` prefixes of the services this suite drives (each service's own
/// `OPERATIONS.md`, "Wire protocol").
const DYNAMODB_TARGET_PREFIX: &str = "DynamoDB_20120810";
/// See [`DYNAMODB_TARGET_PREFIX`].
const SQS_TARGET_PREFIX: &str = "AmazonSQS";

/// The runtime every function below is created with, and the handler its package exposes.
const RUNTIME: &str = "python3.12";
/// See [`RUNTIME`].
const HANDLER: &str = "lambda_function.lambda_handler";

/// How long one invocation of this handler is given, as the function's own `Timeout`: well
/// past what an interpreted run needs, because what is under test is the delivery.
const FUNCTION_TIMEOUT: u64 = 30;

/// The `StartingPosition` that reads the records already sitting in the stream: "Required for
/// Amazon Kinesis and Amazon DynamoDB Stream event sources"
/// (`CreateEventSourceMappingInput$StartingPosition`).
const TRIM_HORIZON: &str = "TRIM_HORIZON";

/// What the stream of every table below captures for each change
/// (`smithy_query(query="shape", shape="StreamViewType")`, DynamoDB), which is the view a
/// handler reading the new image of a change needs.
const NEW_AND_OLD_IMAGES: &str = "NEW_AND_OLD_IMAGES";

/// The attribute every table below is keyed on, and the attribute the handler reads a
/// record's verdict out of. Neither is read by this emulator: both are the handler's own.
const KEY: &str = "pk";
/// See [`KEY`].
const VERDICT: &str = "fail";

/// The member the batch of an Amazon DynamoDB table's stream is described under in the record
/// of a discarded batch, and the condition that record reports for a batch whose attempts ran
/// out. Written out here rather than imported from the emulator so a change to either side of
/// them fails a row.
///
/// Source: AWS's published on-failure record for a DynamoDB Streams event source.
const DYNAMODB_STREAM_BATCH_INFO: &str = "DDBStreamBatchInfo";
/// See [`DYNAMODB_STREAM_BATCH_INFO`].
const CONDITION_RETRY_ATTEMPTS_EXHAUSTED: &str = "RetryAttemptsExhausted";

/// How long a row waits for work the clock owes — a table settling, a mapping settling, a
/// batch being read, the attempts being spent and a record reaching a destination.
///
/// A ceiling on PATIENCE, never a span anything counts on: every wait looks again until what
/// it waits for is there or this deadline passes.
const BUDGET: Duration = Duration::from_secs(120);

/// How long between two looks while waiting.
const LOOK_AGAIN: Duration = Duration::from_millis(50);

/// One row: how many retries the mapping allows, which records are written to the table it
/// reads and which of them the handler refuses, and whether the mapping names a destination
/// for the batches it gives up on.
struct Row {
    case: &'static str,
    /// A name no other row uses, short enough for `FunctionName` and `RoleName`.
    name: &'static str,
    /// The `MaximumRetryAttempts` the mapping states.
    retries: i64,
    /// The items written to the source table, in order: the key each is written under, and
    /// whether the handler refuses the record of that write.
    records: &'static [(&'static str, bool)],
    /// Whether the mapping's `DestinationConfig$OnFailure` names the row's queue.
    records_failures: bool,
}

impl Row {
    /// The keys whose records the handler refuses, so their batches are discarded.
    fn refused(&self) -> Vec<&'static str> {
        self.records
            .iter()
            .filter(|(_, refused)| *refused)
            .map(|(key, _)| *key)
            .collect()
    }

    /// The keys whose records the handler processes, so their effect lands.
    fn processed(&self) -> Vec<&'static str> {
        self.records
            .iter()
            .filter(|(_, refused)| !*refused)
            .map(|(key, _)| *key)
            .collect()
    }

    /// How many attempts each batch gets: the first one plus the retries the mapping states.
    fn attempts(&self) -> i64 {
        self.retries + 1
    }
}

/// The rows: both retry counts, the refused record at the head of the stream as well as
/// between two processed ones and twice in a row, and a mapping that names a failure
/// destination as well as one that names none.
fn rows() -> Vec<Row> {
    vec![
        // The shape a client wires up to keep a poison record from stalling a shard, with
        // nowhere to retain it: the refused record is dropped and the one behind it lands.
        Row {
            case: "no destination, no retry, the refused record at the head of the stream",
            name: "drop-head",
            retries: 0,
            records: &[("neg-a", true), ("neg-b", false)],
            records_failures: false,
        },
        Row {
            case: "no destination, one retry, the refused record between two processed ones",
            name: "drop-mid",
            retries: 1,
            records: &[("mid-a", false), ("mid-b", true), ("mid-c", false)],
            records_failures: false,
        },
        // The same progress, with the batch retained: the record of it is written to the
        // queue the mapping names.
        Row {
            case: "a queue destination, no retry, the refused record at the head of the stream",
            name: "keep-head",
            retries: 0,
            records: &[("pos-a", true), ("pos-b", false)],
            records_failures: true,
        },
        Row {
            case: "a queue destination, one retry, two refused records in a row",
            name: "keep-two",
            retries: 1,
            records: &[("two-a", true), ("two-b", true), ("two-c", false)],
            records_failures: true,
        },
    ]
}

/// The handler every function below runs: for each record of the batch it was handed it reads
/// that record's OWN new image, RAISES for a record whose verdict attribute says to, and
/// otherwise writes one item keyed by the record's key into the results table through the SDK
/// the runtime supplies.
///
/// So an item in the results table is evidence that the record reached the handler and was
/// processed, and the absence of one is evidence that it was not.
fn handler_source() -> String {
    format!(
        r#"
import os

import boto3

RESULTS = os.environ["RESULTS_TABLE"]
CLIENT = boto3.client("dynamodb")


def lambda_handler(event, context):
    processed = []
    for record in event["Records"]:
        if record["eventSource"] != "aws:dynamodb":
            raise ValueError("eventSource is " + repr(record["eventSource"]))
        image = record["dynamodb"]["NewImage"]
        key = image["{KEY}"]["S"]
        if image.get("{VERDICT}", {{}}).get("S") == "true":
            raise ValueError("the handler refuses " + key)
        CLIENT.put_item(
            TableName=RESULTS,
            Item={{
                "{KEY}": {{"S": key}},
                "eventName": {{"S": record["eventName"]}},
                "streamArn": {{"S": record["eventSourceARN"]}},
            }},
        )
        processed.append(key)
    return {{"processed": processed}}
"#
    )
}

/// Lambda, DynamoDB, DynamoDB Streams, Amazon SQS and IAM on ONE engine: the mapping's event
/// source is a table's stream of this emulator, the role it reads that stream as is the one
/// IAM holds, the destination it records a discarded batch at is a queue of this emulator and
/// the handler's own SDK call is dispatched back into this same router — the shape
/// `core/router/src/lib.rs` mounts them in.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_lambda_awsgirapiservice::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_dynamodb_dynamodb_20120810::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_dynamodbstreams_dynamodbstreams_20120810::EmulatedService::new(
            Arc::clone(&engine),
        ),
    );
    router.register_service(service_com_amazonaws_sqs_amazonsqs::EmulatedService::new(
        Arc::clone(&engine),
    ));
    router.register_service(
        service_com_amazonaws_iam_awsidentitymanagementv20100508::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router
}

/// A SigV4 credential scope naming `signing_name` in [`REGION`]. Nothing in it is verified:
/// the harness turns request authentication off.
fn authorization(signing_name: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=emulator-test-key/20260101/{REGION}/{signing_name}/\
         aws4_request, SignedHeaders=host, Signature=not-verified"
    )
}

/// One Lambda call, over its own restJson1 routes.
async fn lambda(
    router: &MultiServiceRouter,
    method: &str,
    uri: &str,
    body: &Value,
) -> (u16, Value) {
    let payload = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body).expect("the test request body must serialize")
    };
    let request = http::Request::builder()
        .method(method)
        .uri(format!("http://lambda.{REGION}.amazonaws.com{uri}"))
        .header("host", format!("lambda.{REGION}.amazonaws.com"))
        .header("authorization", authorization("lambda"))
        .header("content-type", "application/json")
        .body(bytes::Bytes::from(payload))
        .expect("the test request must build");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let body = response.into_body();
    let parsed = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// One AWS JSON call against the service whose signing name is `signing_name`.
async fn rpc(
    router: &MultiServiceRouter,
    signing_name: &str,
    target_prefix: &str,
    content_type: &str,
    operation: &str,
    body: &Value,
) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("{signing_name}.{REGION}.amazonaws.com"))
        .header("content-type", content_type)
        .header("x-amz-target", format!("{target_prefix}.{operation}"))
        .header("authorization", authorization(signing_name))
        .body(bytes::Bytes::from(body.to_string()))
        .expect("the test request must build");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload = response.into_body();
    let parsed = if payload.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&payload).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// One DynamoDB call.
async fn dynamodb(router: &MultiServiceRouter, operation: &str, body: &Value) -> (u16, Value) {
    rpc(
        router,
        "dynamodb",
        DYNAMODB_TARGET_PREFIX,
        "application/x-amz-json-1.0",
        operation,
        body,
    )
    .await
}

/// One Amazon SQS call.
async fn sqs(router: &MultiServiceRouter, operation: &str, body: &Value) -> (u16, Value) {
    rpc(
        router,
        "sqs",
        SQS_TARGET_PREFIX,
        "application/x-amz-json-1.0",
        operation,
        body,
    )
    .await
}

/// A table keyed on [`KEY`], with a stream capturing every change when `streamed`, waited out
/// to `ACTIVE` — "you can perform read and write operations only on an ACTIVE table". Answers
/// the table's ARN and, for a streamed table, its `LatestStreamArn`.
async fn given_table(
    router: &MultiServiceRouter,
    case: &str,
    name: &str,
    streamed: bool,
) -> (String, String) {
    let mut request = json!({
        "TableName": name,
        "AttributeDefinitions": [{ "AttributeName": KEY, "AttributeType": "S" }],
        "KeySchema": [{ "AttributeName": KEY, "KeyType": "HASH" }],
        "BillingMode": "PAY_PER_REQUEST",
    });
    if streamed {
        request["StreamSpecification"] = json!({
            "StreamEnabled": true,
            "StreamViewType": NEW_AND_OLD_IMAGES,
        });
    }
    let (status, created) = dynamodb(router, "CreateTable", &request).await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateTable {name:?} answered {status} {created}"
    );
    let deadline = Instant::now() + BUDGET;
    loop {
        let (status, read) = dynamodb(router, "DescribeTable", &json!({ "TableName": name })).await;
        assert_eq!(
            status, 200,
            "case {case:?}: DescribeTable {name:?} answered {status} {read}"
        );
        let description = &read["Table"];
        if description["TableStatus"] == json!("ACTIVE") {
            let arn = description["TableArn"]
                .as_str()
                .unwrap_or_else(|| panic!("case {case:?}: no TableArn in {read}"))
                .to_string();
            let stream_arn = description["LatestStreamArn"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert_eq!(
                stream_arn.is_empty(),
                !streamed,
                "case {case:?}: a streamed table reports its stream and a plain one does not, \
                 got {read}"
            );
            return (arn, stream_arn);
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the table {name:?} never became ACTIVE: {read}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// A queue of this account: its url and its ARN, both as the queue itself reports them.
async fn given_queue(router: &MultiServiceRouter, case: &str, name: &str) -> (String, String) {
    let (status, created) = sqs(router, "CreateQueue", &json!({ "QueueName": name })).await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateQueue {name:?} answered {status} {created}"
    );
    let url = created["QueueUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: no QueueUrl in {created}"))
        .to_string();
    let (status, attributes) = sqs(
        router,
        "GetQueueAttributes",
        &json!({ "QueueUrl": url, "AttributeNames": ["QueueArn"] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: GetQueueAttributes answered {status} {attributes}"
    );
    let arn = attributes["Attributes"]["QueueArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: no QueueArn in {attributes}"))
        .to_string();
    (url, arn)
}

/// A function whose package RUNS [`handler_source`], running as `role_arn` and told through
/// its environment which table to write, waited out to `Active`.
async fn given_function(
    router: &MultiServiceRouter,
    case: &str,
    name: &str,
    role_arn: &str,
    results_table: &str,
) {
    let (status, created) = lambda(
        router,
        "POST",
        FUNCTIONS_URI,
        &json!({
            "FunctionName": name,
            "Role": role_arn,
            "Runtime": RUNTIME,
            "Handler": HANDLER,
            "Timeout": FUNCTION_TIMEOUT,
            "Environment": { "Variables": { "RESULTS_TABLE": results_table } },
            "Code": {
                "ZipFile": base64::engine::general_purpose::STANDARD
                    .encode(package(&handler_source())),
            },
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "case {case:?}: CreateFunction answered {status} {created}"
    );
    let deadline = Instant::now() + BUDGET;
    loop {
        let (status, read) = lambda(
            router,
            "GET",
            &format!("{FUNCTIONS_URI}/{name}/configuration"),
            &Value::Null,
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: GetFunctionConfiguration answered {status} {read}"
        );
        if read["State"] == json!("Active") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the function never became Active: {read}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// The mapping between `function` and `stream_arn`, reading ONE record per batch so each
/// record is a batch of its own, allowing `retries` retries per batch and recording a batch it
/// gives up on at `destination` when the row names one. Answers its UUID.
async fn given_mapping(
    router: &MultiServiceRouter,
    case: &str,
    function: &str,
    stream_arn: &str,
    retries: i64,
    destination: Option<&str>,
) -> String {
    let mut request = json!({
        "FunctionName": function,
        "EventSourceArn": stream_arn,
        "StartingPosition": TRIM_HORIZON,
        "BatchSize": 1,
        "Enabled": true,
        "MaximumRetryAttempts": retries,
    });
    if let Some(destination) = destination {
        request["DestinationConfig"] = json!({ "OnFailure": { "Destination": destination } });
    }
    let (status, created) = lambda(router, "POST", MAPPINGS_URI, &request).await;
    assert_eq!(
        status, 202,
        "case {case:?}: CreateEventSourceMapping answered {status} {created}"
    );
    created["UUID"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: no UUID in {created}"))
        .to_string()
}

/// Write one item keyed by `key` into `table`, marked as a record the handler refuses when
/// `refused`.
async fn put_item(router: &MultiServiceRouter, case: &str, table: &str, key: &str, refused: bool) {
    let (status, written) = dynamodb(
        router,
        "PutItem",
        &json!({
            "TableName": table,
            "Item": {
                KEY: { "S": key },
                VERDICT: { "S": if refused { "true" } else { "false" } },
            },
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: PutItem {key:?} answered {status} {written}"
    );
}

/// Every key the results table holds an item under, read through DynamoDB's own `Scan` the way
/// a client that polls for the effect reads it.
async fn results(router: &MultiServiceRouter, case: &str, table: &str) -> Vec<String> {
    let (status, scanned) = dynamodb(
        router,
        "Scan",
        &json!({ "TableName": table, "ConsistentRead": true }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: Scan answered {status} {scanned}"
    );
    let mut keys: Vec<String> = scanned["Items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|item| item[KEY]["S"].as_str().map(str::to_string))
        .collect();
    keys.sort();
    keys
}

/// Wait until the results table holds an item under every key of `expected`.
async fn await_results(router: &MultiServiceRouter, case: &str, table: &str, expected: &[&str]) {
    let deadline = Instant::now() + BUDGET;
    loop {
        let held = results(router, case, table).await;
        if expected.iter().all(|key| held.iter().any(|got| got == key)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the mapping must read on past the batch it gave up on and process \
             the records behind it, so the results table must hold {expected:?}, got {held:?}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// Every message visible on the queue `url` addresses right now, removed from it so a later
/// look sees only what arrived after this one.
async fn drained(router: &MultiServiceRouter, case: &str, url: &str) -> Vec<Value> {
    let (status, received) = sqs(
        router,
        "ReceiveMessage",
        &json!({ "QueueUrl": url, "MaxNumberOfMessages": 10 }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: ReceiveMessage answered {status} {received}"
    );
    let messages = received["Messages"].as_array().cloned().unwrap_or_default();
    for message in &messages {
        let handle = message["ReceiptHandle"].as_str().unwrap_or_default();
        let (status, deleted) = sqs(
            router,
            "DeleteMessage",
            &json!({ "QueueUrl": url, "ReceiptHandle": handle }),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: DeleteMessage answered {status} {deleted}"
        );
    }
    messages
}

/// Wait until `wanted` messages have arrived on the queue `url` addresses, answering
/// everything that was on it — more than `wanted` when more arrived, which is what makes
/// "exactly one per discarded batch" assertable.
async fn awaited_messages(
    router: &MultiServiceRouter,
    case: &str,
    url: &str,
    wanted: usize,
) -> Vec<Value> {
    let deadline = Instant::now() + BUDGET;
    let mut held: Vec<Value> = Vec::new();
    loop {
        held.extend(drained(router, case, url).await);
        if held.len() >= wanted {
            return held;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected {wanted} record(s) of discarded batches on {url}, got \
             {held:?}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// What one row stood up: the names and addresses everything below is asserted against.
struct Wired {
    source_table: String,
    results_table: String,
    stream_arn: String,
    queue_url: String,
}

/// Stand `row` up: its streamed source table, its results table, its queue, the execution
/// role carrying exactly the grants this pipeline needs, the function and the mapping.
async fn wire(router: &MultiServiceRouter, row: &Row) -> Wired {
    let case = row.case;
    let source_table = format!("src-{}", row.name);
    let results_table = format!("res-{}", row.name);
    let function = format!("fn-{}", row.name);
    let (_, stream_arn) = given_table(router, case, &source_table, true).await;
    let (results_arn, _) = given_table(router, case, &results_table, false).await;
    let (queue_url, queue_arn) = given_queue(router, case, &format!("q-{}", row.name)).await;
    // Lambda reads the stream acting as the function's execution role, and the handler writes
    // the results table as itself: the role carries both grants, as a client that wires this
    // pipeline together gives it.
    let role = given_role(
        router,
        case,
        &format!("role-{}", row.name),
        Some(json!([
            logs_only(),
            allow("dynamodb", &DYNAMODB_READS, &stream_arn),
            allow("dynamodb", &["PutItem"], &results_arn),
            allow("sqs", &["SendMessage"], &queue_arn),
        ])),
    )
    .await;
    given_function(router, case, &function, &role, &results_table).await;
    given_mapping(
        router,
        case,
        &function,
        &stream_arn,
        row.retries,
        row.records_failures.then_some(queue_arn.as_str()),
    )
    .await;
    Wired {
        source_table,
        results_table,
        stream_arn,
        queue_url,
    }
}

/// RULE: a mapping that has spent on one batch every attempt its `MaximumRetryAttempts` allows
/// DISCARDS that batch and reads the shard on from past it, so the records behind it are
/// delivered and processed while the discarded records' own effects never happen — and where
/// its `DestinationConfig$OnFailure` names a destination, exactly one record per discarded
/// batch is written there, describing the BATCH (the stream, the shard, the sequence-number
/// window, the record count) beside the attempts it had and the condition that ended it, while
/// a mapping naming none records the batch nowhere at all.
#[tokio::test]
async fn a_mapping_reads_on_past_the_batch_it_gave_up_on() {
    for row in rows() {
        let case = row.case;
        let router = emulator();
        let wired = wire(&router, &row).await;

        // The only data-plane calls this row makes: the writes a client makes to the table.
        // Nothing below invokes the function.
        for (key, refused) in row.records {
            put_item(&router, case, &wired.source_table, key, *refused).await;
        }

        // The records BEHIND the discarded ones are delivered and processed, which is the
        // shard having advanced past a batch the function never processed.
        let processed = row.processed();
        await_results(&router, case, &wired.results_table, &processed).await;

        // And the discarded records' own effects never happen: the handler raised for each of
        // them, so nothing was ever written for it. The records behind them having landed is
        // what makes this assertable — the shard is read in order, so their batches are done.
        let held = results(&router, case, &wired.results_table).await;
        let mut expected: Vec<String> = processed.iter().map(|key| (*key).to_string()).collect();
        expected.sort();
        assert_eq!(
            held, expected,
            "case {case:?}: expected the results table to hold exactly {expected:?} — the \
             refused records {:?} must leave no effect — got {held:?}",
            row.refused()
        );

        let refused = row.refused();
        if !row.records_failures {
            let written = drained(&router, case, &wired.queue_url).await;
            assert!(
                written.is_empty(),
                "case {case:?}: a mapping naming no failure destination records the batch \
                 nowhere, got {written:?}"
            );
            continue;
        }

        let messages = awaited_messages(&router, case, &wired.queue_url, refused.len()).await;
        assert_eq!(
            messages.len(),
            refused.len(),
            "case {case:?}: exactly one record must be written per discarded batch, and {} \
             batch(es) were discarded, got {messages:?}",
            refused.len()
        );
        for message in &messages {
            let body = message["Body"].as_str().unwrap_or_default().to_string();
            let record: Value = serde_json::from_str(&body).unwrap_or_else(|_| {
                panic!("case {case:?}: the record must be a JSON document: {body}")
            });
            let info = &record[DYNAMODB_STREAM_BATCH_INFO];
            assert_eq!(
                info["streamArn"],
                json!(wired.stream_arn),
                "case {case:?}: the batch must name the stream it was read from, got {record}"
            );
            assert!(
                info["shardId"]
                    .as_str()
                    .is_some_and(|shard| shard.starts_with("shardId-")),
                "case {case:?}: the batch must name the shard it was read from, got {record}"
            );
            assert_eq!(
                info["batchSize"],
                json!(1),
                "case {case:?}: a mapping reading one record per batch discards a batch of one, \
                 got {record}"
            );
            let start = info["startSequenceNumber"].as_str().unwrap_or_default();
            let end = info["endSequenceNumber"].as_str().unwrap_or_default();
            assert!(
                !start.is_empty() && start == end,
                "case {case:?}: a batch of one record starts and ends at that record, got \
                 {record}"
            );
            assert_eq!(
                record["requestContext"]["condition"],
                json!(CONDITION_RETRY_ATTEMPTS_EXHAUSTED),
                "case {case:?}: the record must say the attempts are what ran out, got {record}"
            );
            assert_eq!(
                record["requestContext"]["approximateInvokeCount"],
                json!(row.attempts()),
                "case {case:?}: a mapping allowing {} retries gives the batch {} attempt(s), \
                 got {record}",
                row.retries,
                row.attempts()
            );
            // The record describes the batch and carries none of its payloads, so a key the
            // handler never processed is not in it either.
            for (key, _) in row.records {
                assert!(
                    !body.contains(key),
                    "case {case:?}: the record must describe the batch and carry no record \
                     payload, but it holds {key:?}: {body}"
                );
            }
        }

        // Every batch of this mapping is done — the records behind the discarded ones have
        // been processed — so nothing more is ever written: the record is written per
        // discarded batch and not per pass.
        let again = drained(&router, case, &wired.queue_url).await;
        assert!(
            again.is_empty(),
            "case {case:?}: the destination must hold one record per discarded batch, but \
             another arrived: {again:?}"
        );
    }
}
