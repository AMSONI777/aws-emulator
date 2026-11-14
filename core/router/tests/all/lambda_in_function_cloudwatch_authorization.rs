// SPDX-License-Identifier: CC0-1.0

//! What a RUNNING function's own Amazon CloudWatch metric call is authorized against: the
//! identity-based policies in force on the function's execution role.
//!
//! RULE: a CloudWatch operation whose IAM action supports no resource types — publishing a
//! datapoint and the metric reads beside it, which the IAM Service Authorization Reference
//! lists with an empty "Resource types" column, so IAM judges each over every resource — is
//! decided against the CALLING PRINCIPAL's identity-based policies before the service reads or
//! writes anything, and the principal of a call an AWS SDK makes from inside a running function
//! is a session of that function's execution role. An explicit `Deny` about the request wins
//! over every `Allow`, an `Allow` about it permits, a principal with neither is refused, and a
//! grant scoped to one resource ARN does not cover an action judged over every resource. A
//! refusal is HTTP 403 under the code a client branches on for this class, worded as the
//! principal, the action and the rule that withheld the grant, and the refused call persists
//! nothing — no datapoint of it lands and no series of it appears in the catalogue. A refusal
//! the handler does not catch is the FUNCTION's own failure: the invocation is still answered
//! HTTP 200, carrying `X-Amz-Function-Error: Unhandled` and the error document of the run.
//!
//! "The execution role grants the function permission to use Amazon Web Services services"
//! (`FunctionConfiguration$Role`), and with neither an identity-based nor a resource-based
//! allow a request is denied (IAM User Guide, *Policy evaluation logic*). CloudWatch's model
//! declares no authorization error for these operations, so the refusal is the AWS-common one
//! every service answers for a request its policies do not permit.
//!
//! Five crates have to agree for that to hold — CloudFormation deploys the roles and the probe
//! functions together, IAM holds each role and its inline document, STS mints the session the
//! function's calls are signed with, Lambda runs the handler and supplies it the SDK, and
//! CloudWatch takes the decision — so the suite lives here: a crate-local suite can only ever
//! see one side of it. What the neighbours pin and this one does not repeat: the CloudWatch
//! crate's own `metric_identity_authorization` drives the decision for a credential a client
//! assumed directly, and `lambda_in_function_sqs_authorization` drives this in-function seam
//! against another service's decision, on actions judged against a named resource.
//!
//! The rows differ along what the rule generalises over: what the execution role's own document
//! allows (nothing of this service, this operation's action, another operation's action, every
//! action of the service, every action plus an explicit deny of one), which resource that
//! statement names (every resource, one alarm's ARN), and WHICH metric operation the handler
//! calls (a publish, a statistics read, a catalogue listing) — several per role, so one
//! document is asked about more than one action — and whether the handler catches the refusal.
//! Each row asserts both halves: what the handler reports of its call, and what the metric
//! store holds afterwards, so a refusal that still published, and a grant that answered
//! without publishing, both fail here.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::cloudformation_firehose_stream_stabilisation::wait_for_stack_status;
use crate::query_wire::{elements, form_encode, physical_ids_of};

/// The Region every request here is signed for, and so the Region the functions belong to.
const REGION: &str = "us-east-1";

/// The account this emulator serves, which every session ARN a refusal names carries.
const ACCOUNT: &str = ::engine::EMULATOR_ACCOUNT_ID;

/// The namespace every datapoint and every read below names: a custom one, so nothing here
/// touches a reserved `AWS/` namespace or the series Lambda itself publishes.
const NAMESPACE: &str = "Emulator/XsvcInFnCloudWatch";

/// The stack the roles and the probe functions are deployed by.
const STACK: &str = "xsvc-in-fn-cloudwatch-probes";

/// The `StackStatus` that stack must reach.
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";

/// The `X-Amz-Target` prefix CloudWatch's model declares
/// (`smithy_query(query="service_info")`: service shape `GraniteServiceVersion20100801`).
const CLOUDWATCH_TARGET: &str = "GraniteServiceVersion20100801";

/// CloudWatch's signing name, which is what routes a request to it.
const CLOUDWATCH_SIGNING_NAME: &str = "monitoring";

/// The code and status CloudWatch refuses a call the policies in force do not permit with.
const ACCESS_DENIED: &str = "AccessDenied";
const ACCESS_DENIED_STATUS: u64 = 403;

/// The signal an invocation whose handler raised carries, and the status such an invocation is
/// still answered on: the run failed, the call did not.
const UNHANDLED: &str = "Unhandled";

/// How long one invocation is given, as the function's own `Timeout`: well past what a run
/// needs on any host, because what is under test is the authorization decision and not how fast
/// an interpreter gets through the handler.
const FUNCTION_TIMEOUT: u64 = 120;

/// The granularity every statistics read below is answered at, in seconds: one minute, the
/// smallest period a standard-resolution metric is read at.
const PERIOD: u64 = 60;

/// How far either side of the clock a read's window reaches, in seconds: an hour, so the
/// datapoint the suite plants is inside it however long the suite takes to get to the read.
const WINDOW: u64 = 3600;

/// The value of the datapoint the suite PLANTS in each row's read series, as the account's own
/// credential — what a served read must report back.
const PLANTED_VALUE: f64 = 7.0;

/// The value of the datapoint a row's handler PUBLISHES — what a served publish must leave in
/// the store, and what a refused one must leave nothing of.
const PUBLISHED_VALUE: f64 = 2.5;

/// How often to look while waiting for work the clock owes — a stack reaching
/// `CREATE_COMPLETE`, a created function reaching `Active`, a published datapoint — and how
/// many looks to take. The spans are those services' own, so no fixed sleep names the instant
/// one ends, and the deadline is generous so a loaded host cannot decide the outcome.
const LOOK: Duration = Duration::from_millis(100);
const LOOKS: usize = 1_800;

/// The handler every row runs. It performs each metric operation the event names with the SDK
/// the runtime supplies, and either reports what CloudWatch answered — the code, the sentence
/// and the HTTP status of a refusal — or leaves it to propagate, which is what makes the
/// invocation report a function error.
const PROBE_HANDLER: &str = r##"
import datetime

import boto3
from botocore.exceptions import ClientError


def call(client, op, event):
    if op == "put":
        client.put_metric_data(
            Namespace=event["namespace"],
            MetricData=[{
                "MetricName": event["published"],
                "Value": event["value"],
                "Unit": "Count",
            }],
        )
        return {"ok": True}
    if op == "get":
        now = datetime.datetime.now(datetime.timezone.utc)
        answered = client.get_metric_statistics(
            Namespace=event["namespace"],
            MetricName=event["planted"],
            StartTime=now - datetime.timedelta(seconds=event["window"]),
            EndTime=now + datetime.timedelta(seconds=event["window"]),
            Period=event["period"],
            Statistics=["Sum"],
        )
        total = 0.0
        for point in answered.get("Datapoints", []):
            total = total + point["Sum"]
        return {"ok": True, "sum": total}
    answered = client.list_metrics(
        Namespace=event["namespace"], MetricName=event["planted"]
    )
    names = []
    for metric in answered.get("Metrics", []):
        names.append(metric["MetricName"])
    return {"ok": True, "names": names}


def handler(event, context):
    client = boto3.client("cloudwatch")
    answers = {}
    for op in event["ops"]:
        if not event["catch"]:
            answers[op] = call(client, op, event)
            continue
        try:
            answers[op] = call(client, op, event)
        except ClientError as refused:
            answers[op] = {
                "ok": False,
                "code": refused.response["Error"]["Code"],
                "message": refused.response["Error"]["Message"],
                "status": refused.response["ResponseMetadata"]["HTTPStatusCode"],
            }
    return answers
"##;

/// The emulator as it is ASSEMBLED, on one engine: a handler's own SDK call is dispatched back
/// into this same router, so the series it publishes into is the series this suite reads.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = aws_emulator_router::build_router(engine);
    // The signature is never checked here, as in every other suite of this crate; the
    // credential scope is what routes a request.
    router.set_request_authentication(false);
    router
}

/// A SigV4 `Authorization` header whose credential scope names `service`, which is what routes
/// the request. Its credential is the long-term key every emulator publishes, so these calls
/// are the account's own and not any row's role's.
fn authorization(service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/{REGION}/{service}/\
         aws4_request, SignedHeaders=host, Signature=0000"
    )
}

/// One awsQuery call of `service`, answered with the HTTP status and the XML body.
async fn query(
    router: &MultiServiceRouter,
    service: &str,
    version: &str,
    action: &str,
    members: &[(&str, &str)],
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
        .header("host", format!("{service}.{REGION}.amazonaws.com"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", authorization(service))
        .body(Bytes::from(body))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(response.body()).to_string())
}

/// One Lambda `restJson1` call, as its status, its headers and its parsed body.
async fn lambda(
    router: &MultiServiceRouter,
    method: &str,
    uri: &str,
    body: &[u8],
) -> (u16, http::HeaderMap, Value) {
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", format!("lambda.{REGION}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("lambda"))
        .body(Bytes::from(body.to_vec()))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let (parts, body) = response.into_parts();
    let parsed = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).to_string()))
    };
    (parts.status.as_u16(), parts.headers, parsed)
}

/// One CloudWatch operation over its `awsJson1_0` wire, made as the ACCOUNT's own credential —
/// the identity no row's grant decides, so what this suite reads of the store is never itself
/// subject to the decision under test.
async fn cloudwatch(router: &MultiServiceRouter, operation: &str, body: &Value) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header(
            "host",
            format!("{CLOUDWATCH_SIGNING_NAME}.{REGION}.amazonaws.com"),
        )
        .header("content-type", "application/x-amz-json-1.0")
        .header("authorization", authorization(CLOUDWATCH_SIGNING_NAME))
        .header("x-amz-target", format!("{CLOUDWATCH_TARGET}.{operation}"))
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

/// WHICH metric operation one probe's handler calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `PutMetricData`: the publish.
    Put,
    /// `GetMetricStatistics`: the statistics read of one series.
    Get,
    /// `ListMetrics`: the catalogue listing.
    List,
}

impl Op {
    /// The word the event names it by, which the handler reads.
    fn event(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Get => "get",
            Self::List => "list",
        }
    }

    /// The IAM action the operation performs, which is the action a statement grants and a
    /// refusal names: CloudWatch's actions are published as `cloudwatch:<OperationName>`.
    fn action(self) -> &'static str {
        match self {
            Self::Put => "cloudwatch:PutMetricData",
            Self::Get => "cloudwatch:GetMetricStatistics",
            Self::List => "cloudwatch:ListMetrics",
        }
    }
}

/// What the policies in force on a row's role make of one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The call is served.
    Served,
    /// Refused because no readable document allows it — IAM's default deny.
    DefaultDeny,
    /// Refused by an explicit `Deny` in one of the role's own documents.
    ExplicitDeny,
}

impl Outcome {
    /// The reason clause the refusal's sentence closes with, as IAM words each.
    fn reason(self, action: &str) -> String {
        match self {
            Self::Served => String::new(),
            Self::DefaultDeny => {
                format!("because no identity-based policy allows the {action} action")
            }
            Self::ExplicitDeny => "with an explicit deny in an identity-based policy".to_string(),
        }
    }
}

/// One row: the statements the execution role carries beyond the log actions, and the probes
/// taken against it in one invocation.
struct Row {
    case: &'static str,
    /// The row's own statements, added to the log actions every execution role carries.
    statements: Vec<Value>,
    /// The operations the handler calls, with what the policies make of each.
    probes: Vec<(Op, Outcome)>,
    /// Whether this row is also driven with a handler that does NOT catch the refusal.
    uncaught: bool,
}

/// The ARN of one alarm of this account, which the resource-scoped row's statement names
/// instead of every resource.
fn alarm_arn() -> String {
    format!("arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:xsvc-in-fn-cloudwatch-probe")
}

/// One identity-based statement.
fn statement(effect: &str, actions: &[&str], resource: &str) -> Value {
    json!({"Effect": effect, "Action": actions, "Resource": resource})
}

/// The rows of the table below.
fn rows() -> Vec<Row> {
    vec![
        // The case the rule is stated about: a least-privilege execution role granting only the
        // log actions a function needs is granted no metric operation at all.
        Row {
            case: "a role granting only the log actions",
            statements: Vec::new(),
            probes: vec![
                (Op::Put, Outcome::DefaultDeny),
                (Op::Get, Outcome::DefaultDeny),
                (Op::List, Outcome::DefaultDeny),
            ],
            uncaught: true,
        },
        Row {
            case: "a role granted the publish",
            statements: vec![statement("Allow", &["cloudwatch:PutMetricData"], "*")],
            probes: vec![
                (Op::Put, Outcome::Served),
                (Op::Get, Outcome::DefaultDeny),
                (Op::List, Outcome::DefaultDeny),
            ],
            uncaught: false,
        },
        Row {
            case: "a role granted the statistics read",
            statements: vec![statement("Allow", &["cloudwatch:GetMetricStatistics"], "*")],
            probes: vec![
                (Op::Get, Outcome::Served),
                (Op::Put, Outcome::DefaultDeny),
            ],
            uncaught: false,
        },
        Row {
            case: "a role granted every action of the service",
            statements: vec![statement("Allow", &["cloudwatch:*"], "*")],
            probes: vec![
                (Op::Put, Outcome::Served),
                (Op::Get, Outcome::Served),
                (Op::List, Outcome::Served),
            ],
            uncaught: false,
        },
        Row {
            case: "a role granted every action of the service and denied the publish",
            statements: vec![
                statement("Allow", &["cloudwatch:*"], "*"),
                statement("Deny", &["cloudwatch:PutMetricData"], "*"),
            ],
            probes: vec![
                (Op::Put, Outcome::ExplicitDeny),
                (Op::Get, Outcome::Served),
            ],
            uncaught: false,
        },
        Row {
            case: "a role granted the publish on one alarm's ARN",
            statements: vec![statement(
                "Allow",
                &["cloudwatch:PutMetricData"],
                &alarm_arn(),
            )],
            probes: vec![(Op::Put, Outcome::DefaultDeny)],
            uncaught: false,
        },
    ]
}

/// The role one row runs as, and the function it runs in — named here because the refusal's own
/// sentence names both: the identity a function's call is signed as is the session
/// `arn:aws:sts::<account>:assumed-role/<role>/<function>`.
fn role_name(index: usize) -> String {
    format!("xsvc-in-fn-cw-role-{index}")
}
fn function_name(index: usize) -> String {
    format!("xsvc-in-fn-cw-probe-{index}")
}

/// The series one row's handler PUBLISHES into, and the series the suite PLANTS a datapoint in
/// for that row's read: one pair per row, so no row can read or write another's.
fn published_metric(index: usize) -> String {
    format!("Published{index}")
}
fn planted_metric(index: usize) -> String {
    format!("Planted{index}")
}

/// The sentence CloudWatch refuses a call the policies in force do not allow with. Written out
/// here rather than built from the service's own helper, so the wording has something to be
/// wrong about.
///
/// Its parts: the principal the request signed as, the action it asked for, the resource that
/// action was judged against, and the rule that withheld the grant. An action IAM judges over
/// every resource is judged against every resource, which is what the sentence names as the
/// resource — this service decides exactly those actions in front of the operation
/// (`services/service-com-amazonaws-cloudwatch-graniteserviceversion20100801/src/service/\
/// authorization.rs`), and the clauses come from the tree's one wording of this refusal
/// (`services/common/src/iam_authorization.rs`), which is also what the CloudWatch crate's own
/// `metric_identity_authorization` suite asserts for a directly assumed session. The behavioural
/// recording behind this rule pins the error CODE and the status of the refusal, not its
/// sentence, so this suite asserts the same sentence those two do rather than a second wording of
/// it: one refusal of one class is worded one way across the tree.
fn refusal_message(index: usize, action: &str, outcome: Outcome) -> String {
    format!(
        "User: arn:aws:sts::{ACCOUNT}:assumed-role/{}/{} is not authorized to perform: {action} \
         on resource: * {}",
        role_name(index),
        function_name(index),
        outcome.reason(action),
    )
}

/// The trust policy a Lambda execution role needs: Lambda has to be able to assume it for the
/// function to be handed it at all.
fn trust_policy() -> Value {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
}

/// The inline document one row's role carries: the log actions every execution role needs, and
/// the row's own statements.
fn role_document(row: &Row) -> Value {
    let mut statements = vec![statement(
        "Allow",
        &[
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "*",
    )];
    statements.extend(row.statements.iter().cloned());
    json!({"Version": "2012-10-17", "Statement": statements})
}

/// The template the suite deploys: one execution role per row carrying that row's document, and
/// one probe function per row running as that role. The inline source is archived into the
/// deployment package by CloudFormation, which is how a function whose handler is written here
/// comes to exist at all.
fn stack_template(rows: &[Row]) -> String {
    let mut resources = serde_json::Map::new();
    for (index, row) in rows.iter().enumerate() {
        let role_logical = format!("Role{index}");
        resources.insert(
            role_logical.clone(),
            json!({
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name(index),
                    "AssumeRolePolicyDocument": trust_policy(),
                    "Policies": [{
                        "PolicyName": "probe-grants",
                        "PolicyDocument": role_document(row),
                    }],
                },
            }),
        );
        resources.insert(
            format!("Probe{index}"),
            json!({
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name(index),
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": [role_logical, "Arn"]},
                    "Timeout": FUNCTION_TIMEOUT,
                    "Code": {"ZipFile": PROBE_HANDLER},
                },
            }),
        );
    }
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": Value::Object(resources),
    })
    .to_string()
}

/// Deploy the stack, wait for `CREATE_COMPLETE` and answer the physical id of each declared
/// resource.
async fn deploy(router: &MultiServiceRouter, rows: &[Row]) -> BTreeMap<String, String> {
    let template = stack_template(rows);
    let (status, answered) = query(
        router,
        "cloudformation",
        "2010-05-15",
        "CreateStack",
        &[
            ("StackName", STACK),
            ("TemplateBody", &template),
            // The template declares named IAM roles, which a create acknowledges before
            // CloudFormation provisions them.
            ("Capabilities.member.1", "CAPABILITY_NAMED_IAM"),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: CreateStack({STACK:?}) must be accepted, got {status} with {answered}"
    );
    // The stack's completion is owed from the instant the owning services report its resources
    // ready, which no fixed sleep can name: this looks until it reports it, on the shared wait
    // whose deadline is generous enough that a loaded host does not decide the outcome.
    let reported = wait_for_stack_status(router, STACK, CREATE_COMPLETE).await;
    let failures = if reported.0 == CREATE_COMPLETE {
        Vec::new()
    } else {
        let (_, events) = query(
            router,
            "cloudformation",
            "2010-05-15",
            "DescribeStackEvents",
            &[("StackName", STACK)],
        )
        .await;
        elements(&events, "ResourceStatusReason")
    };
    assert_eq!(
        reported.0, CREATE_COMPLETE,
        "setup: the stack must reach {CREATE_COMPLETE}, got {} with resource failures {failures:?}",
        reported.1
    );
    let (status, described) = query(
        router,
        "cloudformation",
        "2010-05-15",
        "DescribeStackResources",
        &[("StackName", STACK)],
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: DescribeStackResources({STACK:?}) must succeed, got {status} with {described}"
    );
    physical_ids_of(&described)
}

/// Wait until Lambda reports `name` `Active`, which is the state an invocation needs.
async fn wait_until_active(router: &MultiServiceRouter, name: &str) {
    let mut last = Value::Null;
    for _ in 0..LOOKS {
        let (_, _, configuration) = lambda(
            router,
            "GET",
            &format!("/2015-03-31/functions/{name}/configuration"),
            &[],
        )
        .await;
        if configuration["State"].as_str() == Some("Active") {
            return;
        }
        last = configuration;
        tokio::time::sleep(LOOK).await;
    }
    panic!("setup: Lambda must report {name:?} Active, last reported {last}");
}

/// Publish one datapoint of `value` into `metric` as the ACCOUNT's own credential, which no
/// row's handler can be confused with.
async fn plant(router: &MultiServiceRouter, case: &str, metric: &str, value: f64) {
    let (status, answered) = cloudwatch(
        router,
        "PutMetricData",
        &json!({
            "Namespace": NAMESPACE,
            "MetricData": [{"MetricName": metric, "Value": value, "Unit": "Count"}],
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: planting {metric:?} must succeed, got {status} with {answered}"
    );
}

/// The `Sum` of every datapoint `metric` holds around the clock's instant, read as the account's
/// own credential.
async fn sums(router: &MultiServiceRouter, case: &str, metric: &str) -> Vec<f64> {
    let (status, answered) = cloudwatch(
        router,
        "GetMetricStatistics",
        &json!({
            "Namespace": NAMESPACE,
            "MetricName": metric,
            "StartTime": now_seconds() - WINDOW as f64,
            "EndTime": now_seconds() + WINDOW as f64,
            "Period": PERIOD,
            "Statistics": ["Sum"],
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: reading {metric:?} must succeed, got {status} with {answered}"
    );
    answered["Datapoints"]
        .as_array()
        .map(|listed| {
            listed
                .iter()
                .filter_map(|point| point["Sum"].as_f64())
                .collect()
        })
        .unwrap_or_default()
}

/// The same read, looked at again until it reports `wanted` datapoints or the generous deadline
/// passes — so a host that is slow to make a published datapoint readable cannot decide the
/// outcome, and a caller expecting none takes one look and reports what it found.
async fn awaited_sums(
    router: &MultiServiceRouter,
    case: &str,
    metric: &str,
    wanted: usize,
) -> Vec<f64> {
    let mut held = Vec::new();
    for look in 0..LOOKS {
        held = sums(router, case, metric).await;
        if held.len() >= wanted || look + 1 == LOOKS {
            break;
        }
        tokio::time::sleep(LOOK).await;
    }
    held
}

/// The metric names the catalogue carries for `metric` in this suite's namespace, read as the
/// account's own credential.
async fn catalogued(router: &MultiServiceRouter, case: &str, metric: &str) -> Vec<String> {
    let (status, answered) = cloudwatch(
        router,
        "ListMetrics",
        &json!({"Namespace": NAMESPACE, "MetricName": metric}),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: listing {metric:?} must succeed, got {status} with {answered}"
    );
    answered["Metrics"]
        .as_array()
        .map(|listed| {
            listed
                .iter()
                .filter_map(|held| held["MetricName"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The clock's instant in epoch seconds, as this service's JSON wire carries a timestamp.
fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs_f64()
}

/// The event one row's invocation carries.
fn event(index: usize, ops: &[Op], catch: bool) -> Value {
    json!({
        "namespace": NAMESPACE,
        "published": published_metric(index),
        "planted": planted_metric(index),
        "value": PUBLISHED_VALUE,
        "period": PERIOD,
        "window": WINDOW,
        "ops": ops.iter().map(|op| op.event()).collect::<Vec<_>>(),
        "catch": catch,
    })
}

/// The `X-Amz-Function-Error` an invocation carries, which is set exactly when the run failed.
fn function_error(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("x-amz-function-error")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// Every row: the metric operation a deployed function may perform is the one the identity-based
/// policies in force on its execution role allow, and what the metric store holds afterwards
/// follows that decision.
#[tokio::test]
async fn an_in_function_metric_call_is_decided_against_its_execution_role() {
    let router = build_router();
    let rows = rows();
    let physical = deploy(&router, &rows).await;

    for (index, row) in rows.iter().enumerate() {
        let case = row.case;
        let logical = format!("Probe{index}");
        let function = physical
            .get(&logical)
            .cloned()
            .unwrap_or_else(|| panic!("setup: the stack must report a physical id for {logical}"));
        assert_eq!(
            function,
            function_name(index),
            "setup: the stack must name the function {:?}, got {function:?}",
            function_name(index)
        );
        wait_until_active(&router, &function).await;

        // The series a served read must report back, published by the account rather than by any
        // row, so a read that answered from nothing fails here.
        plant(&router, case, &planted_metric(index), PLANTED_VALUE).await;

        let ops: Vec<Op> = row.probes.iter().map(|(op, _)| *op).collect();
        let (status, headers, payload) = lambda(
            &router,
            "POST",
            &format!("/2015-03-31/functions/{function}/invocations"),
            event(index, &ops, true).to_string().as_bytes(),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the invocation must be served, got {status} with {payload}"
        );
        assert_eq!(
            function_error(&headers),
            None,
            "case {case:?}: a handler that catches every refusal runs to completion, got {:?} \
             with {payload}",
            function_error(&headers)
        );

        for (op, outcome) in &row.probes {
            let reported = &payload[op.event()];
            let expected = match (*outcome, *op) {
                (Outcome::Served, Op::Put) => json!({"ok": true}),
                (Outcome::Served, Op::Get) => json!({"ok": true, "sum": PLANTED_VALUE}),
                (Outcome::Served, Op::List) => {
                    json!({"ok": true, "names": [planted_metric(index)]})
                }
                (refused, op) => json!({
                    "ok": false,
                    "code": ACCESS_DENIED,
                    "message": refusal_message(index, op.action(), refused),
                    "status": ACCESS_DENIED_STATUS,
                }),
            };
            // A served statistics read reports a float the handler summed, which is compared on
            // its value rather than on how JSON spelled it.
            if (*outcome, *op) == (Outcome::Served, Op::Get) {
                assert_eq!(
                    reported["ok"],
                    json!(true),
                    "case {case:?}: expected {} to be served, got {reported}",
                    op.action()
                );
                let read = reported["sum"].as_f64().unwrap_or(f64::NAN);
                assert!(
                    (read - PLANTED_VALUE).abs() < f64::EPSILON,
                    "case {case:?}: expected {} to report the planted {PLANTED_VALUE}, got \
                     {read} ({reported})",
                    op.action()
                );
                continue;
            }
            assert_eq!(
                *reported,
                expected,
                "case {case:?}: expected {} to answer {expected}, got {reported}",
                op.action()
            );
        }

        // And what the STORE holds: a served publish is in it, a refused one published nothing
        // at all — neither a datapoint nor a series in the catalogue.
        let published = published_metric(index);
        let publish_served = row
            .probes
            .iter()
            .any(|(op, outcome)| *op == Op::Put && *outcome == Outcome::Served);
        let held = awaited_sums(&router, case, &published, usize::from(publish_served)).await;
        let listed = catalogued(&router, case, &published).await;
        if publish_served {
            assert_eq!(
                held.len(),
                1,
                "case {case:?}: expected one published datapoint in {published:?}, got {held:?}"
            );
            assert!(
                (held[0] - PUBLISHED_VALUE).abs() < f64::EPSILON,
                "case {case:?}: expected the published datapoint to sum to {PUBLISHED_VALUE}, \
                 got {:?}",
                held[0]
            );
            assert_eq!(
                listed,
                vec![published.clone()],
                "case {case:?}: expected the published series in the catalogue, got {listed:?}"
            );
        } else {
            assert!(
                held.is_empty(),
                "case {case:?}: a refused publish must land no datapoint, got {held:?}"
            );
            assert!(
                listed.is_empty(),
                "case {case:?}: a refused publish must leave no series in the catalogue, got \
                 {listed:?}"
            );
        }

        if row.uncaught {
            assert_an_uncaught_refusal_is_the_functions_own_error(&router, case, index, &function)
                .await;
        }
    }
}

/// The refusal reaches the handler as its own SDK's error, so one the handler does not catch is
/// the FUNCTION's failure — the `Invoke` is still answered HTTP 200, carrying the function-error
/// signal and the run's error document, which quotes what CloudWatch refused the call with.
///
/// Driven on the row whose role is granted no metric operation at all, in the function that row
/// already runs, so the one deployment serves it too.
async fn assert_an_uncaught_refusal_is_the_functions_own_error(
    router: &MultiServiceRouter,
    case: &str,
    index: usize,
    function: &str,
) {
    let (status, headers, payload) = lambda(
        router,
        "POST",
        &format!("/2015-03-31/functions/{function}/invocations"),
        event(index, &[Op::Put], false).to_string().as_bytes(),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: the invocation must be served, got {status} with {payload}"
    );
    assert_eq!(
        function_error(&headers).as_deref(),
        Some(UNHANDLED),
        "case {case:?}: an uncaught refusal must surface as the function's own error, got {:?} \
         with {payload}",
        function_error(&headers)
    );
    let wanted = refusal_message(index, Op::Put.action(), Outcome::DefaultDeny);
    let reported = payload["errorMessage"].as_str().unwrap_or_default();
    assert!(
        reported.contains(&wanted),
        "case {case:?}: the error document must carry what CloudWatch refused the call with \
         ({wanted:?}), got {payload}"
    );
    assert!(
        payload["errorType"]
            .as_str()
            .is_some_and(|kind| !kind.is_empty()),
        "case {case:?}: the error document must name the class that was raised, got {payload}"
    );
    // The refused publish left nothing behind.
    let held = sums(router, case, &published_metric(index)).await;
    assert!(
        held.is_empty(),
        "case {case:?}: a refused publish must land no datapoint, got {held:?}"
    );
}
