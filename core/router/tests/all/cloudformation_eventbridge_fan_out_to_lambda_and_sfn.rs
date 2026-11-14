// SPDX-License-Identifier: CC0-1.0

//! The IaC form of an EventBridge fan-out: ONE CloudFormation stack declaring the rule, its
//! LAMBDA target, its STEP FUNCTIONS target, the role that target is started under, and the
//! statement that admits the function's invocation — deployed end to end over the real
//! `MultiServiceRouter` with CloudFormation, EventBridge, Lambda, Step Functions, IAM, the
//! token service and Amazon SQS mounted on one engine.
//!
//! Two rules are pinned here, and they are about different instants:
//!
//! * **CREATE time belongs to the owning services alone.** Every resource of the stack is
//!   created through the API of the service that owns it, so the stack reaches
//!   `CREATE_COMPLETE` with every one of its resources `CREATE_COMPLETE` — and an
//!   `AWS::IAM::Role` whose `AssumeRolePolicyDocument` does not name `events.amazonaws.com`
//!   is created like any other role, because a trust policy is not a thing IAM, or the
//!   stack, judges against a future caller: nothing at create time knows the role is going
//!   to be named by a rule's target.
//! * **INVOCATION time is where that trust is enforced.** A `PutEvents` entry the deployed
//!   rule matches is handed to each of its targets on its own: the function is invoked as
//!   `events.amazonaws.com` ("for Lambda functions, Amazon SNS topics and Amazon SQS
//!   queues, EventBridge relies on resource-based policies"), and the state machine is
//!   started under the role the target names ("for EC2 instances, Kinesis data streams,
//!   Step Functions state machines and API Gateway APIs, EventBridge relies on IAM roles
//!   that you specify in the `RoleARN` argument in `PutTargets`") — so a target role this
//!   service cannot assume fails THAT handover, which is dead-lettered to the queue the
//!   target's own `DeadLetterConfig` names, while the sibling target is invoked exactly as
//!   it is when both roles are in order.
//!
//! Seven crates have to agree for that to hold, so the suite lives here rather than in any
//! one of them. Every observation is one a client makes: the stack's own resource statuses,
//! the role IAM holds, the message the function's handler wrote, the executions Step
//! Functions reports, and what each target's dead-letter queue received.
//!
//! The rows differ along the one thing the rules above generalise over: whether the trust
//! policy of the role the state-machine target names admits this service at all.
//!
//! `crate::cloudformation_events_rule_lambda_target_permission_boundary` is the suite for
//! which statement admits a deployed rule's LAMBDA target; what this one adds is the
//! heterogeneous fan-out — a function and a state machine on ONE rule — and the role-governed
//! half of it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::query_wire::{element, form_encode, opt_element, outputs_of, pairs_of};

/// The Region every request below is signed for.
const REGION: &str = "us-west-2";

/// The stack status a deployment that created everything it declared reports, and the
/// resource status each of its resources reports.
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";

/// The `source` and `detail-type` the deployed rule's pattern names, which the published
/// entry carries.
const SOURCE: &str = "sim2real.events.iac-fanout";
const DETAIL_TYPE: &str = "Fan Out Probe";

/// The member of the published detail the observations below are keyed by.
const MARKER: &str = "marker";

/// The service principal EventBridge makes a target's call as, and the two actions those
/// calls perform.
const EVENTS_PRINCIPAL: &str = "events.amazonaws.com";
const INVOKE_ACTION: &str = "lambda:InvokeFunction";
const START_EXECUTION_ACTION: &str = "states:StartExecution";

/// The principals the stack's other two roles are assumed by.
const LAMBDA_PRINCIPAL: &str = "lambda.amazonaws.com";
const STATES_PRINCIPAL: &str = "states.amazonaws.com";

/// The condition EventBridge dead-letters a handover under when it could not assume the
/// role the target names at all, and the one it uses when the role could be assumed but its
/// policies withhold the call.
const FAILED_TO_ASSUME_ROLE: &str = "FAILED_TO_ASSUME_ROLE";

/// The attributes "EventBridge adds to the dead-letter message".
const ERROR_CODE_ATTRIBUTE: &str = "ERROR_CODE";
/// See [`ERROR_CODE_ATTRIBUTE`].
const TARGET_ARN_ATTRIBUTE: &str = "TARGET_ARN";

/// The environment variable the handler reads the witness queue's name from.
const WITNESS_VARIABLE: &str = "WITNESS_QUEUE";

/// A state machine that terminates on its own, so an execution a handover started is a real
/// execution rather than one waiting on a task.
const DEFINITION: &str = r#"{"StartAt":"Done","States":{"Done":{"Type":"Succeed"}}}"#;

/// How long each observation of work the clock owes — the stack settling, the function
/// becoming `Active`, an asynchronous invocation running, a dead letter arriving — waits
/// before giving up, and how long between two looks. The deadline is generous: what is
/// under test is that the work happens at all, never how fast this host gets to it.
const BUDGET: Duration = Duration::from_secs(60);
/// See [`BUDGET`].
const LOOK_AGAIN: Duration = Duration::from_millis(50);

/// How long an observation that must stay EMPTY keeps looking before concluding nothing
/// came. Every positive observation of the same row is made first, so by the time this runs
/// the fan-out it belongs to has already happened.
const QUIET_BUDGET: Duration = Duration::from_secs(3);

/// The handler the stack declares inline. It writes the envelope it was handed to the
/// witness queue the same stack declares, which is where a client observes that the
/// invocation really ran; the queue is addressed by NAME through Amazon SQS's own
/// `GetQueueUrl`, so the source carries nothing the deployment had to compute.
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

/// The services this deployment runs through, over ONE shared engine, as
/// `core/router/src/lib.rs` mounts them.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_cloudformation_cloudformation::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(
        service_com_amazonaws_eventbridge_awsevents::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_lambda_awsgirapiservice::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(service_com_amazonaws_sfn_awsstepfunctions::EmulatedService::new(
        Arc::clone(&engine),
    ));
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
    router.register_service(service_com_amazonaws_sqs_amazonsqs::EmulatedService::new(engine));
    router
}

/// A SigV4 `Authorization` whose credential scope names `service`, which is what routes the
/// request. The signature is never checked: this router runs with request authentication
/// off.
fn authorization(service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/{REGION}/{service}/\
         aws4_request, SignedHeaders=host, Signature=0000"
    )
}

/// One awsQuery call against `signing_name`, as its status and body.
async fn query(
    router: &MultiServiceRouter,
    signing_name: &str,
    host: &str,
    version: &str,
    action: &str,
    members: &[(&str, String)],
) -> (u16, String) {
    let mut body = format!("Action={action}&Version={version}");
    for (key, value) in members {
        body.push('&');
        body.push_str(&form_encode(key));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", host)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", authorization(signing_name))
        .body(Bytes::from(body))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(response.body()).to_string())
}

/// One CloudFormation call that must answer 200.
async fn cloudformation(
    router: &MultiServiceRouter,
    case: &str,
    action: &str,
    members: &[(&str, String)],
) -> String {
    let (status, body) = query(
        router,
        "cloudformation",
        &format!("cloudformation.{REGION}.amazonaws.com"),
        "2010-05-15",
        action,
        members,
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from CloudFormation {action}, got {status} with {body}"
    );
    body
}

/// One IAM call, as its status and body — a read of a role the account does not hold is a
/// refusal, so the status is answered rather than asserted here.
async fn iam(
    router: &MultiServiceRouter,
    action: &str,
    members: &[(&str, String)],
) -> (u16, String) {
    query(
        router,
        "iam",
        "iam.amazonaws.com",
        "2010-05-08",
        action,
        members,
    )
    .await
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
        .body(Bytes::from(body.to_string()))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let parsed: Value = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// One EventBridge call (`awsJson1_1`) that must answer 200.
async fn events(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    let (status, parsed) = rpc(router, "events", "AWSEvents", "1.1", operation, body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from EventBridge {operation}, got {status} with \
         {parsed}"
    );
    parsed
}

/// One Step Functions call (`awsJson1_0`) that must answer 200.
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

/// One Amazon SQS call (`awsJson1_0`) that must answer 200.
async fn sqs(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    let (status, parsed) = rpc(router, "sqs", "AmazonSQS", "1.0", operation, body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from Amazon SQS {operation}, got {status} with \
         {parsed}"
    );
    parsed
}

/// One Lambda `restJson1` GET, as its parsed body.
async fn lambda_get(router: &MultiServiceRouter, uri: &str) -> Value {
    let request = http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", format!("lambda.{REGION}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("lambda"))
        .body(Bytes::new())
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    serde_json::from_slice(response.body()).unwrap_or(Value::Null)
}

/// Poll `stack` until it first reports `wanted`, and answer the `DescribeStacks` answer the
/// last status was read from. The wait is on that CONDITION — the stack's own clock-owed
/// span, which no fixed sleep can name.
async fn stack_until(
    router: &MultiServiceRouter,
    case: &str,
    stack: &str,
    wanted: &str,
) -> (String, String) {
    let deadline = Instant::now() + BUDGET;
    loop {
        let described = cloudformation(
            router,
            case,
            "DescribeStacks",
            &[("StackName", stack.to_string())],
        )
        .await;
        let status = opt_element(&described, "StackStatus").unwrap_or_default();
        if status == wanted || Instant::now() >= deadline {
            return (status, described);
        }
        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// Poll `GetFunctionConfiguration` until Lambda first reports `name` `Active` — "during
/// this time, you can't invoke or modify the function" (`CreateFunction`). The span is that
/// service's own, so nothing here sleeps a fixed span on its behalf.
async fn function_active(router: &MultiServiceRouter, case: &str, name: &str) {
    let deadline = Instant::now() + BUDGET;
    loop {
        let reported = lambda_get(
            router,
            &format!("/2015-03-31/functions/{name}/configuration"),
        )
        .await;
        if reported.get("State").and_then(Value::as_str) == Some("Active") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: Lambda never reported {name:?} Active, last read {reported}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
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

/// Everything the queue at `url` holds once it holds `want` messages.
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

/// Whatever the queue at `url` held while it was watched for [`QUIET_BUDGET`].
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

/// A trust policy admitting `principal` for `sts:AssumeRole`, as the template states one.
fn trust(principal: &str) -> Value {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": principal },
            "Action": "sts:AssumeRole",
        }],
    })
}

/// An inline policy list with one `Allow` statement about `actions` on every resource, as
/// `AWS::IAM::Role`'s `Policies` property carries one.
fn policies(name: &str, actions: Value) -> Value {
    json!([{
        "PolicyName": name,
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{ "Effect": "Allow", "Action": actions, "Resource": "*" }],
        },
    }])
}

/// One row: what the trust policy of the role the state-machine target names admits.
struct Row {
    case: &'static str,
    stack: &'static str,
    /// The service principal the target role's `AssumeRolePolicyDocument` names.
    trusts: &'static str,
    /// Whether EventBridge can therefore assume it, and so whether the state-machine
    /// handover is made at all.
    assumable: bool,
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "the target role's trust policy names this service",
            stack: "iac-fanout-trusted",
            trusts: EVENTS_PRINCIPAL,
            assumable: true,
        },
        Row {
            case: "the target role's trust policy names another service instead",
            stack: "iac-fanout-untrusted",
            trusts: "s3.amazonaws.com",
            assumable: false,
        },
    ]
}

/// The template one row deploys: the whole fan-out, in one stack.
fn template(row: &Row) -> String {
    let stack = row.stack;
    let witness = format!("{stack}-witness");
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Witness": {
                "Type": "AWS::SQS::Queue",
                "Properties": { "QueueName": witness },
            },
            "FunctionDlq": {
                "Type": "AWS::SQS::Queue",
                "Properties": { "QueueName": format!("{stack}-dlq-function") },
            },
            "MachineDlq": {
                "Type": "AWS::SQS::Queue",
                "Properties": { "QueueName": format!("{stack}-dlq-machine") },
            },
            // The dead-letter write is the same `sqs:SendMessage` by the same principal a
            // queue target's delivery is, so each dead-letter queue has to admit it.
            "DlqPolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{ "Ref": "FunctionDlq" }, { "Ref": "MachineDlq" }],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": { "Service": EVENTS_PRINCIPAL },
                            "Action": "sqs:SendMessage",
                            "Resource": [
                                { "Fn::GetAtt": ["FunctionDlq", "Arn"] },
                                { "Fn::GetAtt": ["MachineDlq", "Arn"] },
                            ],
                        }],
                    },
                },
            },
            "FunctionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": format!("{stack}-function-exec"),
                    "AssumeRolePolicyDocument": trust(LAMBDA_PRINCIPAL),
                    "Policies": policies(
                        "write-the-witness",
                        json!(["sqs:GetQueueUrl", "sqs:SendMessage"]),
                    ),
                },
            },
            "MachineRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": format!("{stack}-machine-exec"),
                    "AssumeRolePolicyDocument": trust(STATES_PRINCIPAL),
                },
            },
            // The role the rule's state-machine target is started under — the one resource
            // the rows differ in. Its POLICIES allow the start in both rows; only its
            // trust differs.
            "TargetRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": format!("{stack}-target"),
                    "AssumeRolePolicyDocument": trust(row.trusts),
                    "Policies": policies("start-the-machine", json!(START_EXECUTION_ACTION)),
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": format!("{stack}-function"),
                    "Role": { "Fn::GetAtt": ["FunctionRole", "Arn"] },
                    "Runtime": "python3.12",
                    "Handler": "index.lambda_handler",
                    "Timeout": 60,
                    "Environment": { "Variables": { WITNESS_VARIABLE: witness } },
                    "Code": { "ZipFile": WITNESS_SOURCE },
                },
            },
            "Machine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineName": format!("{stack}-machine"),
                    "RoleArn": { "Fn::GetAtt": ["MachineRole", "Arn"] },
                    "DefinitionString": DEFINITION,
                },
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": format!("{stack}-rule"),
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": [SOURCE],
                        "detail-type": [DETAIL_TYPE],
                    },
                    "Targets": [
                        {
                            "Id": "function",
                            "Arn": { "Fn::GetAtt": ["Function", "Arn"] },
                            "RetryPolicy": { "MaximumRetryAttempts": 0 },
                            "DeadLetterConfig": {
                                "Arn": { "Fn::GetAtt": ["FunctionDlq", "Arn"] },
                            },
                        },
                        {
                            "Id": "machine",
                            "Arn": { "Fn::GetAtt": ["Machine", "Arn"] },
                            "RoleArn": { "Fn::GetAtt": ["TargetRole", "Arn"] },
                            "RetryPolicy": { "MaximumRetryAttempts": 0 },
                            "DeadLetterConfig": {
                                "Arn": { "Fn::GetAtt": ["MachineDlq", "Arn"] },
                            },
                        },
                    ],
                },
            },
            "Permission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": { "Fn::GetAtt": ["Function", "Arn"] },
                    "Action": INVOKE_ACTION,
                    "Principal": EVENTS_PRINCIPAL,
                    "SourceArn": { "Fn::GetAtt": ["Rule", "Arn"] },
                },
            },
        },
        "Outputs": {
            "WitnessUrl": { "Value": { "Ref": "Witness" } },
            "FunctionDlqUrl": { "Value": { "Ref": "FunctionDlq" } },
            "MachineDlqUrl": { "Value": { "Ref": "MachineDlq" } },
            "MachineArn": { "Value": { "Fn::GetAtt": ["Machine", "Arn"] } },
            "TargetRoleArn": { "Value": { "Fn::GetAtt": ["TargetRole", "Arn"] } },
        },
    })
    .to_string()
}

/// Both rows: the stack deploys every resource it declares — the target role included,
/// whatever its trust policy says — and the deployed rule then hands the event to each of
/// its targets on its own.
#[tokio::test]
async fn a_stack_deploys_the_fan_out_and_its_rule_reaches_each_target_on_its_own() {
    for row in rows() {
        let case = row.case;
        let stack = row.stack;
        let router = build_router();

        cloudformation(
            &router,
            case,
            "CreateStack",
            &[
                ("StackName", stack.to_string()),
                ("TemplateBody", template(&row)),
                // The template declares IAM resources and NAMES them, which is the
                // capability a client has to acknowledge: "If you have IAM resources with
                // custom names, you must specify CAPABILITY_NAMED_IAM" (`CreateStack`).
                (
                    "Capabilities.member.1",
                    "CAPABILITY_NAMED_IAM".to_string(),
                ),
            ],
        )
        .await;
        let (status, described) = stack_until(&router, case, stack, CREATE_COMPLETE).await;
        assert_eq!(
            status, CREATE_COMPLETE,
            "case {case:?}: expected the stack to deploy the whole fan-out, got {status} with \
             {described}"
        );

        // Every declared resource is one the owning service really created, so the stack
        // reports each of them created rather than only summing to a complete stack.
        let resources = cloudformation(
            &router,
            case,
            "DescribeStackResources",
            &[("StackName", stack.to_string())],
        )
        .await;
        let statuses: BTreeMap<String, String> =
            pairs_of(&resources, "LogicalResourceId", "ResourceStatus");
        let declared = [
            "Witness",
            "FunctionDlq",
            "MachineDlq",
            "DlqPolicy",
            "FunctionRole",
            "MachineRole",
            "TargetRole",
            "Function",
            "Machine",
            "Rule",
            "Permission",
        ];
        for logical_id in declared {
            assert_eq!(
                statuses.get(logical_id).map(String::as_str),
                Some(CREATE_COMPLETE),
                "case {case:?}: expected {logical_id} to report {CREATE_COMPLETE}, got \
                 {resources}"
            );
        }

        let outputs = outputs_of(&described);
        let output = |name: &str| {
            outputs.get(name).cloned().unwrap_or_else(|| {
                panic!("case {case:?}: expected the stack to publish {name}, got {described}")
            })
        };
        let witness_url = output("WitnessUrl");
        let function_dlq_url = output("FunctionDlqUrl");
        let machine_dlq_url = output("MachineDlqUrl");
        let machine_arn = output("MachineArn");
        let target_role_arn = output("TargetRoleArn");

        // CREATE time: the role is IAM's, created with the trust policy the template
        // declared, whichever principal that names — nothing at create time judges it
        // against a caller that does not exist yet.
        let role_name = format!("{stack}-target");
        let (role_status, role) = iam(
            &router,
            "GetRole",
            &[("RoleName", role_name.clone())],
        )
        .await;
        assert_eq!(
            role_status, 200,
            "case {case:?}: expected IAM to hold the role the stack created, got {role_status} \
             with {role}"
        );
        assert_eq!(
            element(&role, "Arn"),
            target_role_arn,
            "case {case:?}: expected IAM's role to be the one the stack published, got {role}"
        );
        assert!(
            element(&role, "AssumeRolePolicyDocument").contains(row.trusts),
            "case {case:?}: expected the role to carry the declared trust policy naming \
             {:?}, got {role}",
            row.trusts
        );

        // The function has to be invocable before the event is published: a handover
        // withheld inside that window would be the lifecycle's refusal and not the
        // documents'.
        function_active(&router, case, &format!("{stack}-function")).await;

        let marker = format!("{stack}-matched");
        let published = events(
            &router,
            case,
            "PutEvents",
            &json!({
                "Entries": [{
                    "Source": SOURCE,
                    "DetailType": DETAIL_TYPE,
                    "Detail": json!({ MARKER: marker }).to_string(),
                }],
            }),
        )
        .await;
        assert_eq!(
            published["FailedEntryCount"],
            json!(0),
            "case {case:?}: expected the entry to be accepted, got {published}"
        );
        let event_id = published["Entries"][0]["EventId"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: expected an EventId, got {published}"))
            .to_string();

        // The LAMBDA leg is the same in both rows: its statement admits the invocation, so
        // its handler runs and writes the envelope it was handed — whatever became of the
        // sibling.
        let witnessed = messages_until(&router, case, &witness_url, 1).await;
        assert_eq!(
            witnessed.len(),
            1,
            "case {case:?}: expected the deployed rule's function target to be invoked once, \
             got {witnessed:?}"
        );
        let handed: Value = serde_json::from_str(witnessed[0]["Body"].as_str().unwrap_or_default())
            .unwrap_or_else(|error| {
                panic!(
                    "case {case:?}: the handler writes the envelope as JSON, got {:?} ({error})",
                    witnessed[0]["Body"]
                )
            });
        assert_eq!(
            handed["detail"][MARKER],
            json!(marker),
            "case {case:?}: expected the handler to be handed the published detail, got {handed}"
        );
        assert_eq!(
            handed["id"],
            json!(event_id),
            "case {case:?}: expected the handler to be handed the envelope of the published \
             event, got {handed}"
        );
        let function_dead_letters = stayed_empty(&router, case, &function_dlq_url).await;
        assert!(
            function_dead_letters.is_empty(),
            "case {case:?}: expected the admitted function target to dead-letter nothing, got \
             {function_dead_letters:?}"
        );

        // The STATE MACHINE leg is the one the rows differ in, and it is decided at
        // INVOCATION time against the role's trust policy.
        if row.assumable {
            let inputs = execution_inputs(&router, case, &machine_arn, 1).await;
            assert_eq!(
                inputs.len(),
                1,
                "case {case:?}: expected the deployed rule's state-machine target to start one \
                 execution, got {inputs:?}"
            );
            let input: Value = serde_json::from_str(&inputs[0]).unwrap_or_else(|error| {
                panic!(
                    "case {case:?}: the execution's input is the envelope, got {:?} ({error})",
                    inputs[0]
                )
            });
            assert_eq!(
                input["detail"][MARKER],
                json!(marker),
                "case {case:?}: expected the execution to carry the published detail, got {input}"
            );
            assert_eq!(
                input["id"],
                json!(event_id),
                "case {case:?}: expected the execution to carry the published event's id, got \
                 {input}"
            );
            let machine_dead_letters = stayed_empty(&router, case, &machine_dlq_url).await;
            assert!(
                machine_dead_letters.is_empty(),
                "case {case:?}: expected the admitted state-machine target to dead-letter \
                 nothing, got {machine_dead_letters:?}"
            );
        } else {
            let dead_lettered = messages_until(&router, case, &machine_dlq_url, 1).await;
            assert_eq!(
                dead_lettered.len(),
                1,
                "case {case:?}: expected the handover under a role this service cannot assume \
                 to be dead-lettered to the queue the target names, got {dead_lettered:?}"
            );
            let attributes = &dead_lettered[0]["MessageAttributes"];
            assert_eq!(
                attributes[ERROR_CODE_ATTRIBUTE]["StringValue"],
                json!(FAILED_TO_ASSUME_ROLE),
                "case {case:?}: expected the dead letter to carry {ERROR_CODE_ATTRIBUTE} \
                 {FAILED_TO_ASSUME_ROLE}, got {:?}",
                dead_lettered[0]
            );
            assert_eq!(
                attributes[TARGET_ARN_ATTRIBUTE]["StringValue"],
                json!(machine_arn),
                "case {case:?}: expected the dead letter to name the state-machine target, got \
                 {:?}",
                dead_lettered[0]
            );
            let inputs = execution_inputs(&router, case, &machine_arn, 0).await;
            assert!(
                inputs.is_empty(),
                "case {case:?}: expected a handover that failed at the assume-role step to \
                 start no execution, got {inputs:?}"
            );
        }
    }
}
