// SPDX-License-Identifier: CC0-1.0

//! What a client of a DEPLOYED REST stage is served when the method behind it is an `AWS_PROXY`
//! integration over a function whose own AWS call is decided by IAM.
//!
//! RULE: every request that reaches a deployed stage terminates in an HTTP response — a request
//! the stage's own gate refuses is answered the refusal, and a request it admits to an
//! `AWS_PROXY` integration is answered the MAPPING of the proxy envelope the target function
//! returned: its `statusCode` is the client's status, its `headers` are the client's headers and
//! its `body` is the client's body, whatever the function's own backend calls answered. So a
//! handler that reports its backend's refusal as a `500` envelope is served to the client as a
//! `500` carrying that body, exactly as the handler's `200` envelope is served as a `200`.
//!
//! "With Lambda proxy integration ... API Gateway ... uses the Lambda function's output as the
//! HTTP response body, status code and headers" (API Gateway Developer Guide, *Lambda proxy
//! integration*), and a call an SDK makes from inside a running function is made as a session of
//! the function's execution role, decided afresh against the documents then in force on that
//! role (`FunctionConfiguration$Role`; IAM User Guide, *Policy evaluation logic*).
//!
//! Five crates have to agree for that to hold — IAM holds the roles and the inline document the
//! rows rewrite, STS mints both the caller's session and the one the function's call is signed
//! with, CloudFormation archives the inline handler into a package this emulator can run, Lambda
//! runs it, DynamoDB serves the read and takes the authorization decision, and API Gateway
//! resolves the stage and maps the envelope — so the suite lives here rather than in any one of
//! them. The sibling `apigateway_iam_authorized_invoke` suite pins the GATE's own decision and
//! `apigateway_proxy_lambda_ddb_pipeline` pins the admitted `200`; what only this suite reaches
//! is the whole non-2xx class: a status the handler itself chose, surfaced to the client.
//!
//! The rows differ along what the rule generalises over: the `statusCode` the handler's envelope
//! carries (`200`, `404`, `500`), WHY it carries it (the item is there, the item is gone, the
//! role's table-read grant is gone), and whether the gate admitted the request at all (a caller
//! granted `execute-api:Invoke` on the method, and one granted nothing). Every row asserts the
//! status, the mapped headers and the body — so a stage that answers nothing, answers a status
//! of its own, or drops the handler's body fails here.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::cloudformation_firehose_stream_stabilisation::wait_for_stack_status;
use crate::query_wire::{form_encode, opt_element};

/// The Region every request here is signed for, and so the Region of the table, the function and
/// the api's own invoke host.
const REGION: &str = "us-east-1";

/// The account this emulator serves, which the table's ARN and every session's ARN carry.
const ACCOUNT: &str = ::engine::EMULATOR_ACCOUNT_ID;

/// The table the handler reads, the key it reads, and the body that key holds.
const TABLE: &str = "xsvc-proxy-envelope-items";
const ITEM_KEY: &str = "the-one-item";
const ITEM_DATA: &str = "the body the handler answers with";

/// The function the stage's integration invokes, and the role it runs as.
const FUNCTION: &str = "xsvc-proxy-envelope-reader";
const EXECUTION_ROLE: &str = "xsvc-proxy-envelope-reader-role";

/// The two inline documents the execution role carries: the log grants every execution role
/// needs, which stay in force throughout, and the table-read grant the rows withdraw and restore.
const LOGGING_POLICY: &str = "logging";
const TABLE_READ_POLICY: &str = "table-read";

/// The stack that archives the inline handler into a deployment package, and the status it must
/// reach.
const STACK: &str = "xsvc-proxy-envelope-stack";
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";

/// The stage the api is deployed to, and the resource path of its one method.
const STAGE: &str = "prod";
const RESOURCE_PATH: &str = "item";

/// The IAM action an invoke of a deployed method asks for, and the one the handler's read
/// performs.
const INVOKE_ACTION: &str = "execute-api:Invoke";
const READ_ACTION: &str = "dynamodb:GetItem";

/// The code DynamoDB refuses an unauthorized item operation with, which the handler reports.
const ACCESS_DENIED: &str = "AccessDeniedException";

/// The clause an API Gateway authorization refusal carries.
const NOT_AUTHORIZED_CLAUSE: &str = "is not authorized to perform: execute-api:Invoke";

/// The response header the handler's envelope carries, which is how a row observes that the
/// headers the client was served are the handler's own and that the integration ran at all.
const PROBE_HEADER: &str = "x-probe";

/// How long one invocation is given, as the function's own `Timeout`: well past what a run needs
/// on any host, because what is under test is the mapping and not how fast an interpreter gets
/// through the handler.
const FUNCTION_TIMEOUT: u64 = 120;

/// How often to look while waiting for work the clock owes — a created table reaching `ACTIVE`, a
/// created function reaching `Active` — and how many looks to take. The spans are those services'
/// own, so no fixed sleep names the instant one ends, and the deadline is generous so a loaded
/// host cannot decide the outcome.
const LOOK: Duration = Duration::from_millis(100);
const LOOKS: usize = 1_800;

/// The handler the stage's integration invokes: it reads the one item with the SDK the runtime
/// supplies and answers a proxy envelope of its own — the item, its absence, or the refusal
/// DynamoDB answered its read with, rendered the way an SDK renders one.
///
/// `TABLE_NAME` and `ITEM_KEY` are substituted before the stack is deployed.
const READER_HANDLER: &str = r##"
import json

import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    client = boto3.client("dynamodb")
    try:
        read = client.get_item(
            TableName="TABLE_NAME",
            Key={"id": {"S": "ITEM_KEY"}},
            ConsistentRead=True,
        )
    except ClientError as refused:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "x-probe": "refused"},
            "body": json.dumps({"error": str(refused)}),
        }
    item = read.get("Item")
    if item is None:
        return {
            "statusCode": 404,
            "headers": {"Content-Type": "application/json", "x-probe": "absent"},
            "body": json.dumps({"error": "no item under that key"}),
        }
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", "x-probe": "served"},
        "body": json.dumps({"id": item["id"]["S"], "data": item["data"]["S"]}),
    }
"##;

/// The handler source as it is deployed: the table and key it reads named in it.
fn handler_source() -> String {
    READER_HANDLER
        .replace("TABLE_NAME", TABLE)
        .replace("ITEM_KEY", ITEM_KEY)
}

/// One answered request: its status, its headers and its body verbatim.
struct Answered {
    status: u16,
    headers: http::HeaderMap,
    body: Bytes,
}

impl Answered {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    /// The `Message` or `message` member a gateway response carries, or the whole body.
    fn message(&self) -> String {
        let body = self.json();
        for name in ["Message", "message"] {
            if let Some(message) = body.get(name).and_then(Value::as_str) {
                return message.to_string();
            }
        }
        self.text()
    }

    fn summary(&self) -> String {
        format!("{} {}", self.status, self.text())
    }
}

/// The emulator as it is ASSEMBLED, on one engine: the handler's own SDK call is dispatched back
/// into this same router, so the table it reads is the table this suite writes.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = aws_emulator_router::build_router(engine);
    // The signature is never checked here, as in every other suite of this crate: the credential
    // scope is what routes a request, and its access key id is what the invoke's authorization
    // resolves its principal from.
    router.set_request_authentication(false);
    router
}

/// The access key id this emulator publishes, which resolves to no session and so speaks for the
/// account's own identity.
const ACCOUNT_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";

/// A SigV4 `Authorization` whose credential scope names `signing_name` and whose credential is
/// `access_key_id`.
fn authorization(access_key_id: &str, signing_name: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/20260101/{REGION}/{signing_name}/\
         aws4_request, SignedHeaders=host, Signature=0000"
    )
}

/// Dispatch one request as it arrives on the wire.
async fn dispatch(
    router: &MultiServiceRouter,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> Answered {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("host", host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = router
        .dispatch(builder.body(body).expect("a well-formed request"))
        .await;
    let (parts, body) = response.into_parts();
    Answered {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    }
}

/// One awsQuery call of `service`, made as the account's own credential.
async fn query(
    router: &MultiServiceRouter,
    service: &str,
    version: &str,
    action: &str,
    members: &[(&str, &str)],
) -> Answered {
    let mut body = format!("Action={action}&Version={version}");
    for (key, value) in members {
        body.push('&');
        body.push_str(&form_encode(key));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    dispatch(
        router,
        "POST",
        &format!("{service}.{REGION}.amazonaws.com"),
        "/",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", &authorization(ACCOUNT_KEY_ID, service)),
        ],
        Bytes::from(body),
    )
    .await
}

/// One awsQuery call that has to be accepted, answered with its XML body.
async fn accepted_query(
    router: &MultiServiceRouter,
    service: &str,
    version: &str,
    action: &str,
    members: &[(&str, &str)],
) -> String {
    let answered = query(router, service, version, action, members).await;
    assert_eq!(
        answered.status,
        200,
        "setup: {service} {action} must answer 200, got {}",
        answered.summary()
    );
    answered.text()
}

/// One Amazon DynamoDB call over its `awsJson1_0` wire, made as the account's own credential.
async fn dynamodb(router: &MultiServiceRouter, operation: &str, body: &Value) -> Answered {
    dispatch(
        router,
        "POST",
        &format!("dynamodb.{REGION}.amazonaws.com"),
        "/",
        &[
            ("content-type", "application/x-amz-json-1.0"),
            ("authorization", &authorization(ACCOUNT_KEY_ID, "dynamodb")),
            ("x-amz-target", &format!("DynamoDB_20120810.{operation}")),
        ],
        Bytes::from(body.to_string()),
    )
    .await
}

/// One AWS Lambda call over its `restJson1` wire.
async fn lambda(
    router: &MultiServiceRouter,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Answered {
    let payload = body.map(|value| value.to_string()).unwrap_or_default();
    dispatch(
        router,
        method,
        &format!("lambda.{REGION}.amazonaws.com"),
        path,
        &[
            ("content-type", "application/json"),
            ("authorization", &authorization(ACCOUNT_KEY_ID, "lambda")),
        ],
        Bytes::from(payload),
    )
    .await
}

/// One API Gateway control-plane call that has to answer `expected`.
async fn apigw(
    router: &MultiServiceRouter,
    what: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
    expected: u16,
) -> Value {
    let payload = body.map(|value| value.to_string()).unwrap_or_default();
    let answered = dispatch(
        router,
        method,
        &format!("apigateway.{REGION}.amazonaws.com"),
        path,
        &[
            ("content-type", "application/json"),
            ("authorization", &authorization(ACCOUNT_KEY_ID, "apigateway")),
        ],
        Bytes::from(payload),
    )
    .await;
    assert_eq!(
        answered.status,
        expected,
        "setup {what:?}: must answer HTTP {expected}, got {}",
        answered.summary()
    );
    answered.json()
}

/// A required string member of a response body.
fn as_str(what: &str, body: &Value, member: &str) -> String {
    body.get(member)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("setup {what:?}: must carry a non-empty {member:?}, got {body}"))
}

/// The ARN of the table the handler reads, which the grant names and the refusal blames.
fn table_arn() -> String {
    format!("arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}")
}

/// A trust policy naming one AWS service as the principal that may assume the role.
fn service_trust_policy(service_principal: &str) -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": service_principal},
            "Action": "sts:AssumeRole",
        }],
    })
    .to_string()
}

/// A trust policy letting this account's own principals assume the role, which is what a caller
/// of the api assumes a role of its own account with.
fn account_trust_policy() -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": format!("arn:aws:iam::{ACCOUNT}:root")},
            "Action": "sts:AssumeRole",
        }],
    })
    .to_string()
}

/// One identity-based document stating `effect` about `action` on `resource`.
fn policy_document(effect: &str, action: &str, resource: &str) -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": effect, "Action": action, "Resource": resource}],
    })
    .to_string()
}

/// The document every execution role needs: the log actions a run writes with.
fn logging_document() -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }],
    })
    .to_string()
}

/// Create a role with `trust_policy` and answer the ARN IAM minted for it.
async fn create_role(router: &MultiServiceRouter, name: &str, trust_policy: &str) -> String {
    let created = accepted_query(
        router,
        "iam",
        "2010-05-08",
        "CreateRole",
        &[
            ("RoleName", name),
            ("AssumeRolePolicyDocument", trust_policy),
        ],
    )
    .await;
    opt_element(&created, "Arn")
        .unwrap_or_else(|| panic!("setup: CreateRole({name:?}) must answer the role's ARN"))
}

/// Embed one inline document in a role.
async fn put_role_policy(
    router: &MultiServiceRouter,
    role: &str,
    policy: &str,
    document: &str,
) {
    accepted_query(
        router,
        "iam",
        "2010-05-08",
        "PutRolePolicy",
        &[
            ("RoleName", role),
            ("PolicyName", policy),
            ("PolicyDocument", document),
        ],
    )
    .await;
}

/// Withdraw one inline document from a role.
async fn delete_role_policy(router: &MultiServiceRouter, role: &str, policy: &str) {
    accepted_query(
        router,
        "iam",
        "2010-05-08",
        "DeleteRolePolicy",
        &[("RoleName", role), ("PolicyName", policy)],
    )
    .await;
}

/// Assume `role_arn` and answer the access key id of the session STS minted.
async fn assume_role(router: &MultiServiceRouter, role_arn: &str, session: &str) -> String {
    let assumed = accepted_query(
        router,
        "sts",
        "2011-06-15",
        "AssumeRole",
        &[("RoleArn", role_arn), ("RoleSessionName", session)],
    )
    .await;
    opt_element(&assumed, "AccessKeyId")
        .unwrap_or_else(|| panic!("setup: AssumeRole({role_arn:?}) must answer an access key id"))
}

/// Create the table the handler reads and wait until DynamoDB reports it `ACTIVE` — "you can
/// perform read and write operations only on an ACTIVE table".
async fn create_table(router: &MultiServiceRouter) {
    let created = dynamodb(
        router,
        "CreateTable",
        &json!({
            "TableName": TABLE,
            "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
        }),
    )
    .await;
    assert_eq!(
        created.status,
        200,
        "setup: CreateTable({TABLE:?}) must succeed, got {}",
        created.summary()
    );
    let mut described = Value::Null;
    for _ in 0..LOOKS {
        described = dynamodb(router, "DescribeTable", &json!({"TableName": TABLE}))
            .await
            .json();
        if described["Table"]["TableStatus"].as_str() == Some("ACTIVE") {
            break;
        }
        tokio::time::sleep(LOOK).await;
    }
    assert_eq!(
        described["Table"]["TableStatus"].as_str(),
        Some("ACTIVE"),
        "setup: DynamoDB must report {TABLE:?} ACTIVE, got {described}"
    );
    assert_eq!(
        described["Table"]["TableArn"].as_str(),
        Some(table_arn().as_str()),
        "setup: the table's ARN is what the grant and the refusal name, got {described}"
    );
}

/// Write the one item the handler reads.
async fn put_item(router: &MultiServiceRouter) {
    let written = dynamodb(
        router,
        "PutItem",
        &json!({
            "TableName": TABLE,
            "Item": {"id": {"S": ITEM_KEY}, "data": {"S": ITEM_DATA}},
        }),
    )
    .await;
    assert_eq!(
        written.status,
        200,
        "setup: PutItem({ITEM_KEY:?}) must succeed, got {}",
        written.summary()
    );
}

/// Remove it again.
async fn delete_item(router: &MultiServiceRouter) {
    let removed = dynamodb(
        router,
        "DeleteItem",
        &json!({"TableName": TABLE, "Key": {"id": {"S": ITEM_KEY}}}),
    )
    .await;
    assert_eq!(
        removed.status,
        200,
        "setup: DeleteItem({ITEM_KEY:?}) must succeed, got {}",
        removed.summary()
    );
}

/// Deploy the stack declaring the function: the inline source is archived into the deployment
/// package by CloudFormation, which is how a function whose handler is written here comes to
/// exist at all. Answers the ARN Lambda reports for it, once it reports it `Active`.
async fn deploy_function(router: &MultiServiceRouter, role_arn: &str) -> String {
    let template = json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Reader": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": FUNCTION,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": role_arn,
                    "Timeout": FUNCTION_TIMEOUT,
                    "Code": {"ZipFile": handler_source()},
                },
            },
        },
    })
    .to_string();
    accepted_query(
        router,
        "cloudformation",
        "2010-05-15",
        "CreateStack",
        &[("StackName", STACK), ("TemplateBody", &template)],
    )
    .await;
    let (reached, described) = wait_for_stack_status(router, STACK, CREATE_COMPLETE).await;
    assert_eq!(
        reached, CREATE_COMPLETE,
        "setup: the stack must reach {CREATE_COMPLETE}, got {described}"
    );

    // The invoke the integration makes needs the function RUNNABLE, which is a transition its own
    // service owes: look until it reports it rather than sleeping a span on its behalf.
    let mut configuration = Value::Null;
    for _ in 0..LOOKS {
        configuration = lambda(
            router,
            "GET",
            &format!("/2015-03-31/functions/{FUNCTION}/configuration"),
            None,
        )
        .await
        .json();
        if configuration.get("State").and_then(Value::as_str) == Some("Active") {
            break;
        }
        tokio::time::sleep(LOOK).await;
    }
    assert_eq!(
        configuration.get("State").and_then(Value::as_str),
        Some("Active"),
        "setup: Lambda must report {FUNCTION:?} Active, got {configuration}"
    );
    as_str("GetFunctionConfiguration", &configuration, "FunctionArn")
}

/// The sentence DynamoDB refuses the handler's read with when nothing in force allows it, as the
/// SDK renders a refusal to the handler: "An error occurred (<Code>) when calling the <Operation>
/// operation: <Message>". Written out here rather than built from either service's own helper, so
/// the wording has something to be wrong about.
fn refusal_reported() -> String {
    format!(
        "An error occurred ({ACCESS_DENIED}) when calling the GetItem operation: User: \
         arn:aws:sts::{ACCOUNT}:assumed-role/{EXECUTION_ROLE}/{FUNCTION} is not authorized to \
         perform: {READ_ACTION} on resource: {} because no identity-based policy allows the \
         {READ_ACTION} action",
        table_arn()
    )
}

/// What this suite does to the state the handler reads BEFORE a row's request.
#[derive(Debug, Clone, Copy)]
enum Before {
    /// Nothing: the item is there and the role's table-read grant is in force.
    Nothing,
    /// The item is removed, the grant left in force.
    RemoveItem,
    /// The item is written back and the role's table-read grant withdrawn.
    RestoreItemAndWithdrawGrant,
    /// The grant is put back.
    RestoreGrant,
}

/// WHICH caller signs a row's request.
#[derive(Debug, Clone, Copy)]
enum Caller {
    /// A session of a role granted `execute-api:Invoke` on this stage's `GET` methods.
    Granted,
    /// A session of a role granted nothing at all.
    Ungranted,
}

/// What the client is owed.
#[derive(Debug, Clone, Copy)]
enum Owed {
    /// The gate admitted the request and the integration answered: the handler's own envelope,
    /// mapped — this status, this `x-probe` header, and this body.
    Envelope {
        status: u16,
        probe: &'static str,
    },
    /// The gate refused it: `403` with the IAM authorization sentence, and the integration was
    /// not reached.
    NotAuthorized,
}

/// One request to the deployed stage.
struct Row {
    case: &'static str,
    before: Before,
    caller: Caller,
    owed: Owed,
}

const ROWS: &[Row] = &[
    Row {
        case: "the item is there and the role may read it",
        before: Before::Nothing,
        caller: Caller::Granted,
        owed: Owed::Envelope {
            status: 200,
            probe: "served",
        },
    },
    Row {
        case: "the item is gone, so the handler's own 404 envelope is what is served",
        before: Before::RemoveItem,
        caller: Caller::Granted,
        owed: Owed::Envelope {
            status: 404,
            probe: "absent",
        },
    },
    Row {
        case: "the role's table-read grant is withdrawn, so the handler's 500 envelope carries \
               the refusal its read earned",
        before: Before::RestoreItemAndWithdrawGrant,
        caller: Caller::Granted,
        owed: Owed::Envelope {
            status: 500,
            probe: "refused",
        },
    },
    Row {
        case: "the grant is put back and the identical request is served again",
        before: Before::RestoreGrant,
        caller: Caller::Granted,
        owed: Owed::Envelope {
            status: 200,
            probe: "served",
        },
    },
    Row {
        case: "a caller granted nothing is refused by the stage's own gate",
        before: Before::Nothing,
        caller: Caller::Ungranted,
        owed: Owed::NotAuthorized,
    },
];

/// The body the handler's envelope carries for each status it answers, which is the body the
/// client is served.
fn expected_body(status: u16) -> Value {
    match status {
        200 => json!({"id": ITEM_KEY, "data": ITEM_DATA}),
        404 => json!({"error": "no item under that key"}),
        _ => json!({"error": refusal_reported()}),
    }
}

#[tokio::test]
async fn a_deployed_proxy_stage_serves_the_status_headers_and_body_its_handler_returned() {
    let router = emulator();

    // 1. The table the handler reads, holding the one item.
    create_table(&router).await;
    put_item(&router).await;

    // 2. The function, running as a role that may read exactly that table.
    let execution_role = create_role(
        &router,
        EXECUTION_ROLE,
        &service_trust_policy("lambda.amazonaws.com"),
    )
    .await;
    put_role_policy(
        &router,
        EXECUTION_ROLE,
        LOGGING_POLICY,
        &logging_document(),
    )
    .await;
    put_role_policy(
        &router,
        EXECUTION_ROLE,
        TABLE_READ_POLICY,
        &policy_document("Allow", READ_ACTION, &table_arn()),
    )
    .await;
    let function_arn = deploy_function(&router, &execution_role).await;

    // The grant that admits an invocation from API Gateway.
    let granted = lambda(
        &router,
        "POST",
        &format!("/2015-03-31/functions/{FUNCTION}/policy"),
        Some(json!({
            "StatementId": "apigw-invoke",
            "Action": "lambda:InvokeFunction",
            "Principal": "apigateway.amazonaws.com",
        })),
    )
    .await;
    assert_eq!(
        granted.status,
        201,
        "setup: AddPermission must answer 201, got {}",
        granted.summary()
    );

    // 3. The api: one AWS_IAM method behind an AWS_PROXY integration on that function, deployed.
    let api_record = apigw(
        &router,
        "CreateRestApi",
        "POST",
        "/restapis",
        Some(json!({"name": "proxy-envelope-api"})),
        201,
    )
    .await;
    let api = as_str("CreateRestApi", &api_record, "id");
    let root = as_str("CreateRestApi", &api_record, "rootResourceId");
    let resource = apigw(
        &router,
        "CreateResource",
        "POST",
        &format!("/restapis/{api}/resources/{root}"),
        Some(json!({"pathPart": RESOURCE_PATH})),
        201,
    )
    .await;
    let resource_id = as_str("CreateResource", &resource, "id");
    let method = format!("/restapis/{api}/resources/{resource_id}/methods/GET");
    apigw(
        &router,
        "PutMethod",
        "PUT",
        &method,
        Some(json!({"authorizationType": "AWS_IAM"})),
        201,
    )
    .await;
    apigw(
        &router,
        "PutIntegration",
        "PUT",
        &format!("{method}/integration"),
        Some(json!({
            "type": "AWS_PROXY",
            // `integrationHttpMethod` travels under its `jsonName`, which is what
            // `smithy_query(query="operation",operation="PutIntegration")` reports.
            "httpMethod": "POST",
            "uri": format!(
                "arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function_arn}/\
                 invocations"
            ),
        })),
        201,
    )
    .await;
    apigw(
        &router,
        "CreateDeployment",
        "POST",
        &format!("/restapis/{api}/deployments"),
        Some(json!({"stageName": STAGE})),
        201,
    )
    .await;

    // 4. The two callers: one granted the invoke of this stage's GET methods, one granted
    //    nothing. The ACCOUNT field of the method ARN is written as the wildcard IAM admits, so
    //    the document names this method without this suite restating the account contract.
    let invoker_role = create_role(&router, "xsvc-proxy-envelope-caller", &account_trust_policy())
        .await;
    put_role_policy(
        &router,
        "xsvc-proxy-envelope-caller",
        "invoke",
        &policy_document(
            "Allow",
            INVOKE_ACTION,
            &format!("arn:aws:execute-api:{REGION}:*:{api}/{STAGE}/GET/*"),
        ),
    )
    .await;
    let granted_key = assume_role(&router, &invoker_role, "granted").await;
    let ungranted_role = create_role(
        &router,
        "xsvc-proxy-envelope-stranger",
        &account_trust_policy(),
    )
    .await;
    let ungranted_key = assume_role(&router, &ungranted_role, "stranger").await;

    // 5. The rows, in order: each one's own request to the deployed stage's invoke URL.
    let invoke_host = format!("{api}.execute-api.{REGION}.amazonaws.com");
    for row in ROWS {
        let case = row.case;
        match row.before {
            Before::Nothing => {}
            Before::RemoveItem => delete_item(&router).await,
            Before::RestoreItemAndWithdrawGrant => {
                put_item(&router).await;
                delete_role_policy(&router, EXECUTION_ROLE, TABLE_READ_POLICY).await;
            }
            Before::RestoreGrant => {
                put_role_policy(
                    &router,
                    EXECUTION_ROLE,
                    TABLE_READ_POLICY,
                    &policy_document("Allow", READ_ACTION, &table_arn()),
                )
                .await;
            }
        }

        let key_id = match row.caller {
            Caller::Granted => &granted_key,
            Caller::Ungranted => &ungranted_key,
        };
        let answered = dispatch(
            &router,
            "GET",
            &invoke_host,
            &format!("/{STAGE}/{RESOURCE_PATH}"),
            &[("authorization", &authorization(key_id, "execute-api"))],
            Bytes::new(),
        )
        .await;

        match row.owed {
            Owed::Envelope { status, probe } => {
                assert_eq!(
                    answered.status,
                    status,
                    "case {case:?}: expected the handler's own statusCode {status}, got {}",
                    answered.summary()
                );
                assert_eq!(
                    answered.header(PROBE_HEADER).as_deref(),
                    Some(probe),
                    "case {case:?}: expected the handler's {PROBE_HEADER:?} header {probe:?}, \
                     got {:?} with {}",
                    answered.header(PROBE_HEADER),
                    answered.summary()
                );
                assert_eq!(
                    answered.json(),
                    expected_body(status),
                    "case {case:?}: expected the handler's own body, got {}",
                    answered.summary()
                );
            }
            Owed::NotAuthorized => {
                assert_eq!(
                    answered.status,
                    403,
                    "case {case:?}: expected the gate's 403, got {}",
                    answered.summary()
                );
                let message = answered.message();
                assert!(
                    message.contains(NOT_AUTHORIZED_CLAUSE),
                    "case {case:?}: expected the refusal to name the {INVOKE_ACTION} action, got \
                     {message:?}"
                );
                assert_eq!(
                    answered.header(PROBE_HEADER),
                    None,
                    "case {case:?}: a refused request must not reach the integration, got {}",
                    answered.summary()
                );
            }
        }
    }
}
