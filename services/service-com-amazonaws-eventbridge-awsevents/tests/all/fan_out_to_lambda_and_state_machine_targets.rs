// SPDX-License-Identifier: CC0-1.0

//! ONE rule carrying a Lambda target AND a Step Functions target, and what a single
//! matching event does to each of them — end to end over the wire, with the services the
//! targets live in mounted beside EventBridge on one engine.
//!
//! The RULE pinned here: **a published entry is handed to EVERY target of every ENABLED
//! rule whose `EventPattern` matched it, once per matching entry, and each handover is
//! made and decided ON ITS OWN. A function target is invoked as
//! `events.amazonaws.com` — "for Lambda functions, Amazon SNS topics and Amazon SQS
//! queues, EventBridge relies on resource-based policies" — and a state-machine target is
//! started under the role the target names — "for EC2 instances, Kinesis data streams,
//! Step Functions state machines and API Gateway APIs, EventBridge relies on IAM roles
//! that you specify in the `RoleARN` argument in `PutTargets`" — both carrying the whole
//! event envelope. So a handover the documents in force refuse withholds NOTHING from its
//! siblings: the sibling targets are still invoked, the refused one is written to the queue
//! ITS OWN `DeadLetterConfig` names carrying the condition and the target it was for, and
//! the rule's `Invocations` and `FailedInvocations` count one datapoint per handover rather
//! than one per event.**
//!
//! That per-target independence is the whole point of a fan-out: it is what lets a client
//! tell "this one target is mis-permissioned" from "nothing is ever dispatched".
//!
//! The rows differ along what the rule generalises over: which target kinds the one rule
//! carries and in which ORDER they are written, WHICH of them the documents in force
//! refuse (neither, the function, the state machine, both), HOW the refusal is stated (a
//! function carrying no statement for this service, a target role whose policies withhold
//! the start, a target role whose trust does not admit this service at all) and HOW MANY
//! matching entries are published, so a count is a count rather than a flag.
//!
//! Every observation is one a client makes: the message the function's own handler wrote,
//! the executions Step Functions reports for the machine, the messages on each target's
//! dead-letter queue, and the `AWS/Events` series CloudWatch answers for the rule.

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

/// The Region every request below is signed for, and so the Region every resource here
/// belongs to.
const REGION: &str = "us-west-2";

/// The `Source` and `DetailType` the rule's pattern names, which every entry carries.
const SOURCE: &str = "com.demo.fanout";
const DETAIL_TYPE: &str = "Fan Out Probe";

/// The member of the published detail each entry is told apart by, which the handler and
/// the execution input both carry through.
const MARKER: &str = "marker";

/// The service principal EventBridge makes a target's call as, and the two actions those
/// calls perform.
const EVENTS_PRINCIPAL: &str = "events.amazonaws.com";
const INVOKE_ACTION: &str = "lambda:InvokeFunction";
const START_EXECUTION_ACTION: &str = "states:StartExecution";

/// An action of the same service as [`START_EXECUTION_ACTION`] that is NOT the one a
/// state-machine handover makes, which is how a row's withholding role grants something
/// without granting this.
const DESCRIBE_MACHINE_ACTION: &str = "states:DescribeStateMachine";

/// The principals the two execution roles here are assumed by.
const LAMBDA_PRINCIPAL: &str = "lambda.amazonaws.com";
const STATES_PRINCIPAL: &str = "states.amazonaws.com";

/// A principal this service is NOT, which is how a row's untrusting target role is stated:
/// a trust policy that admits only it does not admit [`EVENTS_PRINCIPAL`].
const ANOTHER_PRINCIPAL: &str = "s3.amazonaws.com";

/// The module and attribute the deployment package carries its handler as.
const HANDLER: &str = "lambda_function.lambda_handler";

/// How long one invocation is given, as the function's own `Timeout`: well past what the
/// handler needs on any host.
const FUNCTION_TIMEOUT: u64 = 60;

/// The environment variable the handler reads the witness queue's name from.
const WITNESS_VARIABLE: &str = "WITNESS_QUEUE";

/// The bus every rule here lives on: the account's own, which a rule written with no
/// `EventBusName` belongs to and which a publication with none is routed on.
const DEFAULT_BUS: &str = "default";

/// The `AWS/Events` series a fan-out is read off, as EventBridge's published metric
/// reference names them — written out here rather than read from the crate, so a counter
/// published under a name no AWS reader would ask for fails this suite.
const METRIC_NAMESPACE: &str = "AWS/Events";
/// See [`METRIC_NAMESPACE`]: "the number of times a target is invoked for a rule in
/// response to an event".
const INVOCATIONS_METRIC: &str = "Invocations";
/// See [`METRIC_NAMESPACE`]: "the number of invocations that failed permanently".
const FAILED_INVOCATIONS_METRIC: &str = "FailedInvocations";
/// See [`METRIC_NAMESPACE`]: the two dimensions a per-rule series is reported under.
const EVENT_BUS_DIMENSION: &str = "EventBusName";
/// See [`METRIC_NAMESPACE`].
const RULE_DIMENSION: &str = "RuleName";

/// The attributes "EventBridge adds to the dead-letter message", which is what tells a
/// consumer of one queue which delivery failed and why.
const RULE_ARN_ATTRIBUTE: &str = "RULE_ARN";
/// See [`RULE_ARN_ATTRIBUTE`].
const TARGET_ARN_ATTRIBUTE: &str = "TARGET_ARN";
/// See [`RULE_ARN_ATTRIBUTE`].
const ERROR_CODE_ATTRIBUTE: &str = "ERROR_CODE";

/// The condition EventBridge reports for a handover refused for want of a permission: the
/// role could be assumed, or the resource's own policy was read, and the call the handover
/// makes is not allowed.
const NO_PERMISSIONS: &str = "NO_PERMISSIONS";

/// The condition it reports for a handover that failed at the assume-role step, before any
/// target call was attempted: the role's trust policy does not admit this service.
const FAILED_TO_ASSUME_ROLE: &str = "FAILED_TO_ASSUME_ROLE";

/// How long each observation of work the clock owes — the function becoming `Active`, an
/// asynchronous invocation running, a dead letter arriving — waits before giving up, and
/// how long between two looks. The deadline is generous: what is under test is that the
/// work happens at all, never how fast this host gets to it.
const BUDGET: Duration = Duration::from_secs(60);
/// See [`BUDGET`].
const LOOK_AGAIN: Duration = Duration::from_millis(50);

/// How long an observation that must stay EMPTY keeps looking before concluding nothing
/// came. Every positive observation of the same row is made first, so by the time this runs
/// the fan-out it belongs to has already happened.
const QUIET_BUDGET: Duration = Duration::from_secs(3);

/// A state machine that terminates on its own, so an execution a handover started is a real
/// execution rather than one waiting on a task.
const DEFINITION: &str = r#"{"StartAt":"Done","States":{"Done":{"Type":"Succeed"}}}"#;

/// The handler every function target here deploys: it writes the envelope it was handed to
/// the witness queue, which is where a client observes that the invocation really ran. The
/// queue is addressed by NAME through Amazon SQS's own `GetQueueUrl`, so the source carries
/// nothing this suite had to compute.
const WITNESS_SOURCE: &str = r#"
import json
import os

import boto3


def lambda_handler(event, context):
    client = boto3.client("sqs")
    url = client.get_queue_url(QueueName=os.environ["WITNESS_QUEUE"])["QueueUrl"]
    client.send_message(QueueUrl=url, MessageBody=json.dumps(event, sort_keys=True))
    return {"handled": event["detail"]["marker"]}
"#;

/// EventBridge, Lambda, Step Functions, IAM, the token service, Amazon SQS and CloudWatch
/// over ONE shared engine, as `core/router/src/lib.rs` mounts them: the handler's own SDK
/// call is dispatched back into this same router, so the queue it writes is the queue this
/// suite reads.
fn emulator() -> (MultiServiceRouter, Arc<engine::InMemoryEngine>) {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    // The suite signs nothing: the `Authorization` header carries only the credential
    // scope, which is where a service reads the Region and the caller's access key id
    // from. The handler's OWN call is signed by the runtime with the credential it was
    // given.
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_eventbridge_awsevents::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_lambda_awsgirapiservice::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_sfn_awsstepfunctions::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_iam_awsidentitymanagementv20100508::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(
        service_com_amazonaws_sts_awssecuritytokenservicev20110615::EmulatedService::new(
            Arc::clone(&engine),
        ),
    );
    router.register_service(service_com_amazonaws_sqs_amazonsqs::EmulatedService::new(
        Arc::clone(&engine),
    ));
    router.register_service(
        service_com_amazonaws_cloudwatch_graniteserviceversion20100801::EmulatedService::new(
            Arc::clone(&engine),
        ),
    );
    (router, engine)
}

/// A SigV4 `Authorization` whose credential scope names `service`, which is what routes the
/// request. The signature is never checked here.
fn authorization(service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/{service}/aws4_request, \
         SignedHeaders=host, Signature=not-verified"
    )
}

/// One `X-Amz-Target` RPC call, as its status and parsed body.
async fn rpc(
    router: &MultiServiceRouter,
    signing_name: &str,
    target_prefix: &str,
    json_version: &str,
    operation: &str,
    body: &Value,
) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("{signing_name}.{REGION}.amazonaws.com"))
        .header("authorization", authorization(signing_name))
        .header(
            "content-type",
            format!("application/x-amz-json-{json_version}"),
        )
        .header("x-amz-target", format!("{target_prefix}.{operation}"))
        .body(bytes::Bytes::from(body.to_string()))
        .expect("the test request is well formed");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let parsed = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// One EventBridge call (`awsJson1_1`, `AWSEvents.<Operation>`) that must answer 200.
async fn events(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    let (status, parsed) = rpc(router, "events", "AWSEvents", "1.1", operation, body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from EventBridge {operation}, got {status} with \
         {parsed}"
    );
    parsed
}

/// One Step Functions call (`awsJson1_0`, `AWSStepFunctions.<Operation>`) that must answer
/// 200.
async fn sfn(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    let (status, parsed) = rpc(
        router,
        "states",
        "AWSStepFunctions",
        "1.0",
        operation,
        body,
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from Step Functions {operation}, got {status} with \
         {parsed}"
    );
    parsed
}

/// One Amazon SQS call (`awsJson1_0`, `AmazonSQS.<Operation>`) that must answer 200.
async fn sqs(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    let (status, parsed) = rpc(router, "sqs", "AmazonSQS", "1.0", operation, body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from Amazon SQS {operation}, got {status} with \
         {parsed}"
    );
    parsed
}

/// One CloudWatch call (`awsJson1_0`, `GraniteServiceVersion20100801.<Operation>`) that
/// must answer 200.
async fn cloudwatch(
    router: &MultiServiceRouter,
    case: &str,
    operation: &str,
    body: &Value,
) -> Value {
    let (status, parsed) = rpc(
        router,
        "monitoring",
        "GraniteServiceVersion20100801",
        "1.0",
        operation,
        body,
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from CloudWatch {operation}, got {status} with \
         {parsed}"
    );
    parsed
}

/// One Lambda `restJson1` call, as its status and parsed body.
async fn lambda(
    router: &MultiServiceRouter,
    method: &str,
    uri: &str,
    body: &Value,
) -> (u16, Value) {
    let payload = if body.is_null() {
        bytes::Bytes::new()
    } else {
        bytes::Bytes::from(body.to_string())
    };
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", format!("lambda.{REGION}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("lambda"))
        .body(payload)
        .expect("the test request is well formed");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let parsed: Value = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// One awsQuery call to IAM, as the account's own credential, which must be served.
async fn iam(router: &MultiServiceRouter, case: &str, action: &str, params: &[(&str, String)]) {
    let mut body = format!("Action={action}&Version=2010-05-08");
    for (name, value) in params {
        body.push('&');
        body.push_str(name);
        body.push('=');
        body.push_str(&form_encode(value));
    }
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", "iam.amazonaws.com")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", authorization("iam"))
        .body(bytes::Bytes::from(body))
        .expect("the test request is well formed");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let answered = String::from_utf8_lossy(response.body()).to_string();
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from IAM {action}, got {status} with {answered}"
    );
}

/// `application/x-www-form-urlencoded` for one awsQuery parameter value.
fn form_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// The account every emulated resource of this suite belongs to, as the engine holds it.
fn account() -> String {
    engine::emulator_account_id().to_string()
}

/// A .zip deployment package holding [`WITNESS_SOURCE`] as `lambda_function.py`, written in
/// memory the way a caller uploads one and base64-encoded as `FunctionCode$ZipFile` carries
/// it.
fn package() -> String {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options: zip::write::FileOptions<'_, '_, ()> = zip::write::FileOptions::default();
        writer
            .start_file("lambda_function.py", options)
            .expect("the entry starts");
        writer
            .write_all(WITNESS_SOURCE.as_bytes())
            .expect("the entry's bytes");
        writer.finish().expect("a finished archive");
    }
    base64::engine::general_purpose::STANDARD.encode(buffer.into_inner())
}

/// A role trusting `principal`, carrying `statements` as its one inline policy when a row
/// names any; answered with the ARN it carries.
async fn role(
    router: &MultiServiceRouter,
    case: &str,
    name: &str,
    principal: &str,
    statements: Option<Value>,
) -> String {
    let trust = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": principal },
            "Action": "sts:AssumeRole",
        }],
    })
    .to_string();
    iam(
        router,
        case,
        "CreateRole",
        &[
            ("RoleName", name.to_string()),
            ("AssumeRolePolicyDocument", trust),
        ],
    )
    .await;
    if let Some(statements) = statements {
        let document = json!({ "Version": "2012-10-17", "Statement": statements }).to_string();
        iam(
            router,
            case,
            "PutRolePolicy",
            &[
                ("RoleName", name.to_string()),
                ("PolicyName", "inline".to_string()),
                ("PolicyDocument", document),
            ],
        )
        .await;
    }
    format!("arn:aws:iam::{}:role/{name}", account())
}

/// One `Allow` statement about `action` on every resource.
fn allow(action: &str) -> Value {
    json!([{ "Effect": "Allow", "Action": action, "Resource": "*" }])
}

/// A queue called `name`, carrying a policy that grants this service `sqs:SendMessage` on
/// it when `grant_events` — which a dead-letter queue needs, since the dead-letter write is
/// the same `sqs:SendMessage` by the same principal a queue target's delivery is. Answered
/// with its url.
async fn queue(router: &MultiServiceRouter, case: &str, name: &str, grant_events: bool) -> String {
    let created = sqs(router, case, "CreateQueue", &json!({ "QueueName": name })).await;
    let url = created["QueueUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a QueueUrl for {name}, got {created}"))
        .to_string();
    if grant_events {
        let arn = format!("arn:aws:sqs:{REGION}:{}:{name}", account());
        let policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "Service": EVENTS_PRINCIPAL },
                "Action": "sqs:SendMessage",
                "Resource": arn,
            }],
        })
        .to_string();
        sqs(
            router,
            case,
            "SetQueueAttributes",
            &json!({ "QueueUrl": url, "Attributes": { "Policy": policy } }),
        )
        .await;
    }
    url
}

/// Every message waiting on the queue at `url`, with its attributes, drained from it.
async fn drain(router: &MultiServiceRouter, case: &str, url: &str) -> Vec<Value> {
    let received = sqs(
        router,
        case,
        "ReceiveMessage",
        &json!({
            "QueueUrl": url,
            "MaxNumberOfMessages": 10,
            "MessageAttributeNames": ["All"],
        }),
    )
    .await;
    received["Messages"].as_array().cloned().unwrap_or_default()
}

/// Everything the queue at `url` holds once it holds `want` messages, so a delivery still
/// in flight is looked for again rather than read as missing; gives up after [`BUDGET`] so a
/// message that never arrives fails an assertion instead of hanging.
async fn messages_until(
    router: &MultiServiceRouter,
    case: &str,
    url: &str,
    want: usize,
) -> Vec<Value> {
    let deadline = Instant::now() + BUDGET;
    let mut held: Vec<Value> = Vec::new();
    loop {
        held.extend(drain(router, case, url).await);
        if held.len() >= want || Instant::now() >= deadline {
            return held;
        }
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// Whether the queue at `url` stays empty for [`QUIET_BUDGET`], answered with whatever it
/// did hold.
async fn stayed_empty(router: &MultiServiceRouter, case: &str, url: &str) -> Vec<Value> {
    let until = Instant::now() + QUIET_BUDGET;
    let mut held: Vec<Value> = Vec::new();
    while Instant::now() < until {
        held.extend(drain(router, case, url).await);
        if !held.is_empty() {
            return held;
        }
        tokio::time::sleep(LOOK_AGAIN).await;
    }
    held
}

/// The `input` of every execution `machine_arn` holds, once it holds `want` of them.
async fn execution_inputs(
    router: &MultiServiceRouter,
    case: &str,
    machine_arn: &str,
    want: usize,
) -> Vec<String> {
    let deadline = Instant::now() + BUDGET;
    loop {
        let listed = sfn(
            router,
            case,
            "ListExecutions",
            &json!({ "stateMachineArn": machine_arn }),
        )
        .await;
        let arns: Vec<String> = listed["executions"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|execution| execution["executionArn"].as_str().map(str::to_string))
            .collect();
        if arns.len() >= want || Instant::now() >= deadline {
            let mut inputs = Vec::new();
            for arn in &arns {
                let described = sfn(
                    router,
                    case,
                    "DescribeExecution",
                    &json!({ "executionArn": arn }),
                )
                .await;
                inputs.push(described["input"].as_str().unwrap_or_default().to_string());
            }
            return inputs;
        }
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// Now, in epoch seconds, which is how CloudWatch's `awsJson` wire form carries an instant.
fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// The `Sum` of the rule's `metric` series over a window around now — the magnitude a
/// client charts or alarms on. A series with no datapoint at all sums to zero, which is what
/// "nothing was counted" reads as.
async fn metric_sum(router: &MultiServiceRouter, case: &str, metric: &str, rule: &str) -> f64 {
    let now = now_secs();
    let read = cloudwatch(
        router,
        case,
        "GetMetricStatistics",
        &json!({
            "Namespace": METRIC_NAMESPACE,
            "MetricName": metric,
            "Dimensions": [
                { "Name": EVENT_BUS_DIMENSION, "Value": DEFAULT_BUS },
                { "Name": RULE_DIMENSION, "Value": rule },
            ],
            "StartTime": now - 600.0,
            "EndTime": now + 600.0,
            "Period": 1200,
            "Statistics": ["Sum"],
        }),
    )
    .await;
    read["Datapoints"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|point| point["Sum"].as_f64())
        .sum()
}

/// The same sum once it has reached `want`, so a handover still being counted is read again
/// rather than read as missing.
async fn metric_sum_until(
    router: &MultiServiceRouter,
    case: &str,
    metric: &str,
    rule: &str,
    want: f64,
) -> f64 {
    let deadline = Instant::now() + BUDGET;
    loop {
        let sum = metric_sum(router, case, metric, rule).await;
        if sum >= want || Instant::now() >= deadline {
            return sum;
        }
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// The kind of target one leg of a row's rule is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A Lambda function, invoked as the service principal and decided against the
    /// FUNCTION's own resource-based policy.
    Function,
    /// A Step Functions state machine, started under the role the target names and decided
    /// against the documents in force on THAT role.
    Machine,
}

/// Whether the documents in force admit a leg's handover, and — when they do not — in which
/// form the refusal is stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admits {
    /// The function carries the statement, or the target role trusts this service and
    /// allows the start.
    Yes,
    /// The function carries no statement at all, or the target role's policies allow
    /// another action of the target's service and not the one the handover makes.
    NoPermission,
    /// The target role's trust policy does not admit this service, so the handover fails
    /// at the assume-role step. Only a role-governed target can be refused this way.
    NoTrust,
}

impl Admits {
    /// The `ERROR_CODE` a dead letter of a refused handover carries, or `None` for one the
    /// documents admit.
    fn condition(self) -> Option<&'static str> {
        match self {
            Self::Yes => None,
            Self::NoPermission => Some(NO_PERMISSIONS),
            Self::NoTrust => Some(FAILED_TO_ASSUME_ROLE),
        }
    }
}

/// One target of a row's rule.
#[derive(Debug, Clone, Copy)]
struct Leg {
    kind: Kind,
    admits: Admits,
}

/// One row: the legs of the ONE rule it writes, in the order they are written, and how many
/// matching entries it publishes.
struct Row {
    case: &'static str,
    /// The prefix every resource of the row is named with, so the rows share no resource.
    slug: &'static str,
    legs: &'static [Leg],
    entries: usize,
}

/// The rows every leg of whose rule the documents in force ADMIT.
fn admitted_rows() -> Vec<Row> {
    vec![
        Row {
            case: "a function and a state machine, both admitted",
            slug: "both",
            legs: &[
                Leg { kind: Kind::Function, admits: Admits::Yes },
                Leg { kind: Kind::Machine, admits: Admits::Yes },
            ],
            entries: 1,
        },
        Row {
            case: "the same two targets written in the opposite order, two matching entries",
            slug: "reversed",
            legs: &[
                Leg { kind: Kind::Machine, admits: Admits::Yes },
                Leg { kind: Kind::Function, admits: Admits::Yes },
            ],
            entries: 2,
        },
    ]
}

/// The rows where the documents in force refuse one leg of the rule, or both.
fn refused_rows() -> Vec<Row> {
    vec![
        Row {
            case: "the state machine target's role withholds the start, the function is \
                   admitted",
            slug: "machine-withheld",
            legs: &[
                Leg { kind: Kind::Function, admits: Admits::Yes },
                Leg { kind: Kind::Machine, admits: Admits::NoPermission },
            ],
            entries: 1,
        },
        Row {
            case: "the function carries no statement, the state machine target is admitted",
            slug: "function-withheld",
            legs: &[
                Leg { kind: Kind::Function, admits: Admits::NoPermission },
                Leg { kind: Kind::Machine, admits: Admits::Yes },
            ],
            entries: 1,
        },
        Row {
            case: "the state machine target's role does not trust this service, the function \
                   is admitted",
            slug: "machine-untrusted",
            legs: &[
                Leg { kind: Kind::Machine, admits: Admits::NoTrust },
                Leg { kind: Kind::Function, admits: Admits::Yes },
            ],
            entries: 2,
        },
        Row {
            case: "neither target is admitted",
            slug: "neither",
            legs: &[
                Leg { kind: Kind::Function, admits: Admits::NoPermission },
                Leg { kind: Kind::Machine, admits: Admits::NoPermission },
            ],
            entries: 1,
        },
    ]
}

/// Every leg of a rule the documents admit is handed each matching entry once, with the
/// whole envelope, and dead-letters nothing.
#[tokio::test]
async fn every_admitted_target_of_one_rule_is_handed_each_matching_entry() {
    for row in admitted_rows() {
        fan_out(&row).await;
    }
}

/// A leg the documents in force refuse withholds nothing from its siblings: they are still
/// handed the event, the refused one is dead-lettered to the queue its own
/// `DeadLetterConfig` names carrying its condition, and the rule's two counters split the
/// handovers between them.
#[tokio::test]
async fn a_refused_target_withholds_nothing_from_its_siblings() {
    for row in refused_rows() {
        fan_out(&row).await;
    }
}

/// One row: wire the rule the row declares, publish its entries, and assert what each leg
/// came to.
async fn fan_out(row: &Row) {
    {
        let case = row.case;
        let slug = row.slug;
        let (router, _engine) = emulator();

        // The witness queue the function's handler writes to, which is where a client
        // observes that the invocation really ran, and one dead-letter queue PER LEG, so a
        // refusal is read against the target it was for rather than against the rule.
        let witness = format!("{slug}-witness");
        let witness_url = queue(&router, case, &witness, false).await;
        let mut dead_letter_urls = Vec::new();
        let mut dead_letter_arns = Vec::new();
        for index in 0..row.legs.len() {
            let name = format!("{slug}-dlq-{index}");
            dead_letter_urls.push(queue(&router, case, &name, true).await);
            dead_letter_arns.push(format!("arn:aws:sqs:{REGION}:{}:{name}", account()));
        }

        // The function, with the execution role its handler's own write is judged against.
        let execution_role = role(
            &router,
            case,
            &format!("{slug}-function-exec"),
            LAMBDA_PRINCIPAL,
            Some(json!([{
                "Effect": "Allow",
                "Action": ["sqs:GetQueueUrl", "sqs:SendMessage"],
                "Resource": "*",
            }])),
        )
        .await;
        let function = format!("{slug}-function");
        let function_arn =
            given_function(&router, case, &function, &execution_role, &witness).await;

        // The state machine, with the role Step Functions runs its executions as.
        let machine_role = role(
            &router,
            case,
            &format!("{slug}-machine-exec"),
            STATES_PRINCIPAL,
            None,
        )
        .await;
        let machine = format!("{slug}-machine");
        let machine_arn = given_machine(&router, case, &machine, &machine_role).await;

        // The role a state-machine target names, in the three forms the rows need.
        let allowing_role = role(
            &router,
            case,
            &format!("{slug}-target-allow"),
            EVENTS_PRINCIPAL,
            Some(allow(START_EXECUTION_ACTION)),
        )
        .await;
        let withholding_role = role(
            &router,
            case,
            &format!("{slug}-target-withhold"),
            EVENTS_PRINCIPAL,
            Some(allow(DESCRIBE_MACHINE_ACTION)),
        )
        .await;
        let untrusting_role = role(
            &router,
            case,
            &format!("{slug}-target-untrusted"),
            ANOTHER_PRINCIPAL,
            Some(allow(START_EXECUTION_ACTION)),
        )
        .await;

        // The ONE rule, and its legs written in the row's own order.
        let rule = format!("{slug}-rule");
        let written = events(
            &router,
            case,
            "PutRule",
            &json!({
                "Name": rule,
                "EventPattern": json!({
                    "source": [SOURCE],
                    "detail-type": [DETAIL_TYPE],
                })
                .to_string(),
                "State": "ENABLED",
            }),
        )
        .await;
        let rule_arn = written["RuleArn"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: expected a RuleArn, got {written}"))
            .to_string();

        let targets: Vec<Value> = row
            .legs
            .iter()
            .enumerate()
            .map(|(index, leg)| {
                let mut target = json!({
                    "Id": format!("t{index}"),
                    "Arn": match leg.kind {
                        Kind::Function => function_arn.clone(),
                        Kind::Machine => machine_arn.clone(),
                    },
                    "DeadLetterConfig": { "Arn": dead_letter_arns[index].clone() },
                    "RetryPolicy": { "MaximumRetryAttempts": 0 },
                });
                if leg.kind == Kind::Machine {
                    target["RoleArn"] = json!(match leg.admits {
                        Admits::Yes => allowing_role.clone(),
                        Admits::NoPermission => withholding_role.clone(),
                        Admits::NoTrust => untrusting_role.clone(),
                    });
                }
                target
            })
            .collect();
        let targeted = events(
            &router,
            case,
            "PutTargets",
            &json!({ "Rule": rule, "Targets": targets }),
        )
        .await;
        assert_eq!(
            targeted["FailedEntryCount"],
            json!(0),
            "case {case:?}: every target must be accepted, got {targeted}"
        );

        // The FUNCTION's own resource-based policy is the whole decision for its leg.
        let function_leg = row.legs.iter().find(|leg| leg.kind == Kind::Function);
        if function_leg.is_some_and(|leg| leg.admits == Admits::Yes) {
            grant_invocation(&router, case, &function, &rule_arn).await;
        }

        // The publication: one entry per marker, each matching the rule's pattern.
        let markers: Vec<String> = (0..row.entries)
            .map(|index| format!("{slug}-{index}"))
            .collect();
        let entries: Vec<Value> = markers
            .iter()
            .map(|marker| {
                json!({
                    "Source": SOURCE,
                    "DetailType": DETAIL_TYPE,
                    "Detail": json!({ MARKER: marker }).to_string(),
                })
            })
            .collect();
        let published = events(
            &router,
            case,
            "PutEvents",
            &json!({ "Entries": entries }),
        )
        .await;
        assert_eq!(
            published["FailedEntryCount"],
            json!(0),
            "case {case:?}: every entry must be accepted, got {published}"
        );
        let event_ids: Vec<String> = published["Entries"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|entry| entry["EventId"].as_str().map(str::to_string))
            .collect();
        assert_eq!(
            event_ids.len(),
            row.entries,
            "case {case:?}: expected one answered EventId per entry, got {published}"
        );

        // Each REFUSED leg's own dead-letter queue carries one copy of every published
        // envelope, naming that leg's target, its rule and its condition.
        for (index, leg) in row.legs.iter().enumerate() {
            let Some(condition) = leg.admits.condition() else {
                continue;
            };
            let url = &dead_letter_urls[index];
            let dead_lettered = messages_until(&router, case, url, row.entries).await;
            assert_eq!(
                dead_lettered.len(),
                row.entries,
                "case {case:?}: expected the refused target t{index} to dead-letter one copy \
                 of each of the {} published event(s), got {dead_lettered:?}",
                row.entries
            );
            let target_arn = match leg.kind {
                Kind::Function => &function_arn,
                Kind::Machine => &machine_arn,
            };
            for message in &dead_lettered {
                let attributes = &message["MessageAttributes"];
                assert_eq!(
                    attributes[ERROR_CODE_ATTRIBUTE]["StringValue"],
                    json!(condition),
                    "case {case:?}: expected the dead letter of t{index} to carry \
                     {ERROR_CODE_ATTRIBUTE} {condition}, got {message}"
                );
                assert_eq!(
                    attributes[TARGET_ARN_ATTRIBUTE]["StringValue"],
                    json!(target_arn),
                    "case {case:?}: expected the dead letter of t{index} to name that target, \
                     got {message}"
                );
                assert_eq!(
                    attributes[RULE_ARN_ATTRIBUTE]["StringValue"],
                    json!(rule_arn),
                    "case {case:?}: expected the dead letter of t{index} to name the invoking \
                     rule, got {message}"
                );
                let envelope: Value =
                    serde_json::from_str(message["Body"].as_str().unwrap_or_default())
                        .unwrap_or_else(|error| {
                            panic!(
                                "case {case:?}: the dead letter carries the event envelope, got \
                                 {message} ({error})"
                            )
                        });
                assert!(
                    markers
                        .iter()
                        .any(|marker| envelope["detail"][MARKER] == json!(marker)),
                    "case {case:?}: expected the dead letter to carry one of the published \
                     envelopes, got {envelope}"
                );
            }
        }

        // The STATE MACHINE leg's own far-end effect: one execution per published entry
        // when its role admits the start, each carrying the whole envelope as its input —
        // and none at all when it does not.
        let machine_leg = row.legs.iter().find(|leg| leg.kind == Kind::Machine);
        let wanted_executions = usize::from(machine_leg.is_some_and(|leg| leg.admits == Admits::Yes))
            * row.entries;
        let inputs = execution_inputs(&router, case, &machine_arn, wanted_executions).await;
        assert_eq!(
            inputs.len(),
            wanted_executions,
            "case {case:?}: expected {wanted_executions} execution(s) of the state machine \
             target, got {inputs:?}"
        );
        for input in &inputs {
            let envelope: Value = serde_json::from_str(input).unwrap_or_else(|error| {
                panic!("case {case:?}: an execution's input is the envelope, got {input} ({error})")
            });
            assert_eq!(
                envelope["source"],
                json!(SOURCE),
                "case {case:?}: the execution's input carries the published source, got \
                 {envelope}"
            );
            assert_eq!(
                envelope["detail-type"],
                json!(DETAIL_TYPE),
                "case {case:?}: the execution's input carries the published detail type, got \
                 {envelope}"
            );
            assert!(
                event_ids
                    .iter()
                    .any(|id| envelope["id"] == json!(id)),
                "case {case:?}: the execution's input carries the id of one published event, \
                 got {envelope}"
            );
        }
        for marker in &markers {
            assert_eq!(
                inputs
                    .iter()
                    .filter(|input| input.contains(marker.as_str()))
                    .count(),
                usize::from(wanted_executions > 0),
                "case {case:?}: expected one execution per matching entry, so {marker:?} \
                 appears in exactly as many inputs, got {inputs:?}"
            );
        }

        // The FUNCTION leg's own far-end effect: its handler ran once per published entry
        // and wrote the envelope it was handed, or nothing ran at all.
        let wanted_runs =
            usize::from(function_leg.is_some_and(|leg| leg.admits == Admits::Yes)) * row.entries;
        let witnessed = if wanted_runs == 0 {
            stayed_empty(&router, case, &witness_url).await
        } else {
            messages_until(&router, case, &witness_url, wanted_runs).await
        };
        assert_eq!(
            witnessed.len(),
            wanted_runs,
            "case {case:?}: expected the function target's handler to run {wanted_runs} \
             time(s), got {witnessed:?}"
        );
        for marker in &markers {
            assert_eq!(
                witnessed
                    .iter()
                    .filter(|message| {
                        message["Body"]
                            .as_str()
                            .is_some_and(|body| body.contains(marker.as_str()))
                    })
                    .count(),
                usize::from(wanted_runs > 0),
                "case {case:?}: expected the handler to be handed each matching entry once, \
                 so {marker:?} appears in exactly as many writes, got {witnessed:?}"
            );
        }

        // Each ADMITTED leg dead-letters nothing: a sibling's refusal is not its failure.
        for (index, leg) in row.legs.iter().enumerate() {
            if leg.admits != Admits::Yes {
                continue;
            }
            let quiet = stayed_empty(&router, case, &dead_letter_urls[index]).await;
            assert!(
                quiet.is_empty(),
                "case {case:?}: expected the admitted target t{index} to dead-letter nothing, \
                 got {quiet:?}"
            );
        }

        // The rule's own counters: ONE datapoint per handover, on the series the handover's
        // outcome decides — never one per event.
        let admitted = row
            .legs
            .iter()
            .filter(|leg| leg.admits == Admits::Yes)
            .count();
        let refused = row.legs.len() - admitted;
        for (metric, handovers) in [
            (INVOCATIONS_METRIC, admitted),
            (FAILED_INVOCATIONS_METRIC, refused),
        ] {
            let want = (handovers * row.entries) as f64;
            let sum = metric_sum_until(&router, case, metric, &rule, want).await;
            assert_eq!(
                sum, want,
                "case {case:?}: expected the rule's {metric} to sum to {want} — one datapoint \
                 per handover of each of the {} published event(s) — got {sum}",
                row.entries
            );
        }
    }
}

/// Create the function the rule targets, wait until Lambda reports it `Active` — "during
/// this time, you can't invoke or modify the function" (`CreateFunction`) — and answer its
/// ARN.
async fn given_function(
    router: &MultiServiceRouter,
    case: &str,
    name: &str,
    role_arn: &str,
    witness: &str,
) -> String {
    let (status, created) = lambda(
        router,
        "POST",
        "/2015-03-31/functions",
        &json!({
            "FunctionName": name,
            "Role": role_arn,
            "Runtime": "python3.12",
            "Handler": HANDLER,
            "Timeout": FUNCTION_TIMEOUT,
            "Environment": { "Variables": { WITNESS_VARIABLE: witness } },
            "Code": { "ZipFile": package() },
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "case {case:?}: expected HTTP 201 from CreateFunction, got {status} with {created}"
    );
    let arn = created["FunctionArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a FunctionArn, got {created}"))
        .to_string();
    let deadline = Instant::now() + BUDGET;
    loop {
        let (_, configuration) = lambda(
            router,
            "GET",
            &format!("/2015-03-31/functions/{name}/configuration"),
            &Value::Null,
        )
        .await;
        if configuration["State"].as_str() == Some("Active") {
            return arn;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: Lambda never reported {name:?} Active, last read {configuration}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// Create the state machine the rule targets, under `role_arn`, and answer its ARN.
async fn given_machine(
    router: &MultiServiceRouter,
    case: &str,
    name: &str,
    role_arn: &str,
) -> String {
    let created = sfn(
        router,
        case,
        "CreateStateMachine",
        &json!({ "name": name, "definition": DEFINITION, "roleArn": role_arn }),
    )
    .await;
    created["stateMachineArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a stateMachineArn, got {created}"))
        .to_string()
}

/// Grant this service the invocation on `function`, scoped by `aws:SourceArn` to the rule
/// that invokes it: "for Lambda functions, Amazon SNS topics and Amazon SQS queues,
/// EventBridge relies on resource-based policies" (`PutTargets`).
async fn grant_invocation(
    router: &MultiServiceRouter,
    case: &str,
    function: &str,
    rule_arn: &str,
) {
    let (status, granted) = lambda(
        router,
        "POST",
        &format!("/2015-03-31/functions/{function}/policy"),
        &json!({
            "StatementId": "AllowEventBridgeInvoke",
            "Action": INVOKE_ACTION,
            "Principal": EVENTS_PRINCIPAL,
            "SourceArn": rule_arn,
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "case {case:?}: expected HTTP 201 from AddPermission, got {status} with {granted}"
    );
}
