// SPDX-License-Identifier: CC0-1.0

//! What a `COGNITO_USER_POOLS`-gated method whose integration is an `AWS_PROXY` Lambda
//! function answers a value that is NOT a verifiable user-pool token, and whether that
//! function ran.
//!
//! THE RULE UNDER TEST, one level above the recorded case:
//!
//! > A deployed method whose `authorizationType` is `COGNITO_USER_POOLS` is decided BEFORE its
//! > integration is performed. A value at the authorizer's `identitySource` that cannot be
//! > verified as a token of one of the authorizer's `providerARNs` pools — nothing presented at
//! > all, an empty value, a value that is not a compact JWS, one presented under the RFC 6750
//! > bearer scheme, one whose `iss` names no pool the authorizer lists — authorized nobody, so
//! > the request is answered through the api's own `UNAUTHORIZED` gateway response: `401` with
//! > the fixed body `{"message":"Unauthorized"}`, whose message has no variable part. The
//! > method's integration is never performed on that path, so nothing of the backend runs and
//! > it leaves no side effect; and such a request is NEVER answered `5xx`, which is the class of
//! > an authorizer whose decision could not be obtained rather than of a credential question.
//! > A token one of those pools minted and signed is admitted, reaches the function, and the
//! > caller is served the envelope the function returned.
//!
//! The rows span what the rule generalises over: WHAT was presented (nothing, an empty value,
//! the recorded unverifiable string, a two-segment value, three segments that are not
//! base64url JSON, a well-formed compact JWS claiming an issuer that is no pool, a token a
//! DIFFERENT pool minted, and the authorizer's own pool's token), HOW it was presented (bare
//! and under the bearer scheme) and HOW the stage was addressed (the api's own `execute-api`
//! host, and the path-style addressing a client that cannot resolve that host reaches this
//! emulator by) — every row is driven both ways, because the gate is the method's, not the
//! addressing's.
//!
//! What makes "the backend never ran" observable: the handler WRITES an item keyed by the
//! nonce the request carries before it returns anything, so a request that reached it leaves
//! that item and one the gate refused leaves nothing. The write happens inside the invocation
//! the gateway waits on, so by the time the client has been answered the item either exists or
//! never will; the admitted rows are what prove that side channel is live.
//!
//! Only a cross-service suite can pin this: the pool that mints and signs the token and
//! publishes the key set it is checked against is Amazon Cognito's, the function behind the
//! method and the grant that admits its invocation are AWS Lambda's, the item the handler
//! writes is Amazon DynamoDB's, and the api, the authorizer and the stage are API Gateway's —
//! all on ONE engine, as `core/router/src/lib.rs` mounts them.

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_cognitoidentityprovider_awscognitoidentityproviderservice as cognito_idp;

/// The Region every request below is signed for and every ARN names.
const REGION: &str = "us-east-1";

/// The stage the api is deployed to, and the resource path of its one gated method.
const STAGE: &str = "prod";
const RESOURCE_PATH: &str = "secure";

/// The function the gated method's `AWS_PROXY` integration names.
const FUNCTION: &str = "cognito-gated-backend";

/// The table the handler writes its marker item into.
const TABLE: &str = "cognito-gate-marks";

/// The role a created function names. No IAM store is mounted here, so it is a value the
/// create carries rather than a record this suite relies on.
const ROLE: &str = "arn:aws:iam::000000000000:role/lambda-exec";

/// The handler the deployment package declares.
const HANDLER: &str = "lambda_function.lambda_handler";

/// The header the authorizer declares as its identity source.
const TOKEN_HEADER: &str = "Authorization";

/// The permanent password this suite's fixture users sign in with — a value written for this
/// test and used nowhere else. It satisfies a pool's default password policy.
const GOOD_PASSWORD: &str = "Str0ng-Passw0rd!";

/// The status and the body an uncustomized `UNAUTHORIZED` gateway response carries: fixed text
/// for the class, with no api id, token, pool id or request id interpolated into it.
const UNAUTHORIZED: u16 = 401;
const UNAUTHORIZED_MESSAGE: &str = "Unauthorized";

/// The sentence the `API_CONFIGURATION_ERROR` / `AUTHORIZER_CONFIGURATION_ERROR` gateway
/// responses carry — the `500` that must never answer a question about a presented token.
const CONFIGURATION_ERROR: &str = "Internal server error";

/// How long this suite waits for another service's own clock-owed transition (a created
/// function becoming `Active`, a created table becoming `ACTIVE`), and how often it looks.
/// Generous: the wait is on the CONDITION, and nothing here is graded on how fast the host
/// runs.
const WAIT: Duration = Duration::from_secs(30);
const LOOK: Duration = Duration::from_millis(50);

/// The handler behind the gated method: it marks the invocation it is making, keyed by the
/// nonce the request carries, and answers the proxy envelope the client is served. The claim
/// it records is the one the authorizer published for the admitted token.
const HANDLER_SOURCE: &str = r#"
import json
import os

import boto3


def lambda_handler(event, context):
    nonce = (event.get("queryStringParameters") or {}).get("nonce", "NONE")
    claims = ((event.get("requestContext") or {}).get("authorizer") or {}).get("claims") or {}
    subject = claims.get("sub", "NONE")
    boto3.client("dynamodb").put_item(
        TableName=os.environ["TABLE"],
        Item={"pk": {"S": nonce}, "sub": {"S": subject}},
    )
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"served": nonce, "sub": subject}),
    }
"#;

/// One dispatched request, and what came back.
struct Answer {
    status: u16,
    body: Value,
    text: String,
}

impl Answer {
    /// One string member of a data-plane body, or `"<no message>"`.
    fn message(&self) -> String {
        self.body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("<no message>")
            .to_string()
    }

    fn summary(&self) -> String {
        format!("{} {}", self.status, self.text)
    }
}

/// The four services this rule spans, over ONE engine, as `core/router/src/lib.rs` mounts
/// them.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    // The suite exercises the services, not SigV4: the control-plane calls carry a credential
    // scope so the router can name the target service, and the invokes carry no credential at
    // all, as a client of a published invoke URL sends none.
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_apigateway_backplanecontrolservice::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(cognito_idp::EmulatedService::new(Arc::clone(&engine)));
    router.register_service(
        service_com_amazonaws_lambda_awsgirapiservice::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_dynamodb_dynamodb_20120810::EmulatedService::new(engine),
    );
    router
}

/// A SigV4 `Authorization` whose credential scope names `signing_name`, which is what routes
/// the request. The signature itself is never checked here.
fn authorization(signing_name: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/{REGION}/{signing_name}/\
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
) -> Answer {
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
    let status = response.status().as_u16();
    let bytes = response.into_body();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Answer { status, body, text }
}

/// One API Gateway control-plane call that has to be accepted with `expected`.
async fn apigw(
    router: &MultiServiceRouter,
    case: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
    expected: u16,
) -> Value {
    let payload = body.map(|value| value.to_string()).unwrap_or_default();
    let answer = dispatch(
        router,
        method,
        &format!("apigateway.{REGION}.amazonaws.com"),
        path,
        &[
            ("content-type", "application/json"),
            ("authorization", &authorization("apigateway")),
        ],
        Bytes::from(payload),
    )
    .await;
    assert_eq!(
        answer.status,
        expected,
        "setup {case:?}: expected HTTP {expected} from {method} {path}, got {}",
        answer.summary()
    );
    answer.body
}

/// One awsJson1_1 call to the user pools service, which must succeed.
async fn cognito(router: &MultiServiceRouter, operation: &str, body: &Value) -> Value {
    let answer = dispatch(
        router,
        "POST",
        &format!("cognito-idp.{REGION}.amazonaws.com"),
        "/",
        &[
            ("content-type", "application/x-amz-json-1.1"),
            ("authorization", &authorization("cognito-idp")),
            (
                "x-amz-target",
                &format!("AWSCognitoIdentityProviderService.{operation}"),
            ),
        ],
        Bytes::from(body.to_string()),
    )
    .await;
    assert_eq!(
        answer.status,
        200,
        "setup {operation}: expected HTTP 200, got {}",
        answer.summary()
    );
    answer.body
}

/// One AWS Lambda call over its `restJson1` wire, answering its status and parsed body.
async fn lambda(
    router: &MultiServiceRouter,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let payload = body.map(|value| value.to_string()).unwrap_or_default();
    let answer = dispatch(
        router,
        method,
        &format!("lambda.{REGION}.amazonaws.com"),
        path,
        &[
            ("content-type", "application/json"),
            ("authorization", &authorization("lambda")),
        ],
        Bytes::from(payload),
    )
    .await;
    (answer.status, answer.body)
}

/// One Amazon DynamoDB call over its `awsJson1_0` wire, answering its status and parsed body.
async fn dynamodb(router: &MultiServiceRouter, operation: &str, body: Value) -> (u16, Value) {
    let answer = dispatch(
        router,
        "POST",
        &format!("dynamodb.{REGION}.amazonaws.com"),
        "/",
        &[
            ("content-type", "application/x-amz-json-1.0"),
            ("authorization", &authorization("dynamodb")),
            ("x-amz-target", &format!("DynamoDB_20120810.{operation}")),
        ],
        Bytes::from(body.to_string()),
    )
    .await;
    (answer.status, answer.body)
}

/// A required non-empty string member of a response body.
fn member(case: &str, body: &Value, name: &str) -> String {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("setup {case:?}: no {name:?} in {body}"))
        .to_string()
}

/// `bytes` as one base64url segment of a compact JWS: "base64url without padding"
/// (RFC 7515 §2).
fn segment(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A well-formed compact JWS over `claims` that NO pool signed — its signature segment is a
/// value written here — which is what a row presenting a token of an issuer this authorizer
/// does not list needs.
fn unsigned_jws(claims: &Value) -> String {
    format!(
        "{}.{}.{}",
        segment(br#"{"alg":"RS256","kid":"k"}"#),
        segment(claims.to_string().as_bytes()),
        segment(b"this-is-no-signature")
    )
}

/// Seconds since the epoch, which is what a token's `exp` is (RFC 7519 §2 NumericDate).
fn now_seconds() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs(),
    )
    .expect("an epoch second within i64")
}

/// A .zip deployment package holding `source` as the module the handler names, written in
/// memory the way a caller uploads one.
fn package(source: &str) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options: zip::write::FileOptions<'_, '_, ()> = zip::write::FileOptions::default();
        writer
            .start_file("lambda_function.py", options)
            .expect("the entry starts");
        writer
            .write_all(source.as_bytes())
            .expect("the entry's bytes");
        writer.finish().expect("a finished archive");
    }
    buffer.into_inner()
}

/// What one fixture pool answers with: its id, its ARN, and the identity token a sign-in of
/// its one user produced.
struct Pool {
    arn: String,
    id_token: String,
    subject: String,
}

/// Mint one pool, one app client and one confirmed user, and sign that user in.
async fn pool_with_signed_in_user(
    router: &MultiServiceRouter,
    pool_name: &str,
    username: &str,
) -> Pool {
    let created = cognito(router, "CreateUserPool", &json!({ "PoolName": pool_name })).await;
    let id = member("CreateUserPool", &created["UserPool"], "Id");
    let arn = member("CreateUserPool", &created["UserPool"], "Arn");
    let client = cognito(
        router,
        "CreateUserPoolClient",
        &json!({
            "UserPoolId": id,
            "ClientName": format!("{pool_name}-client"),
            // The flow the sign-in below uses, plus the refresh flow AWS requires beside any
            // other `ALLOW_` flow.
            "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        }),
    )
    .await;
    let client_id = member("CreateUserPoolClient", &client["UserPoolClient"], "ClientId");
    cognito(
        router,
        "AdminCreateUser",
        &json!({ "UserPoolId": id, "Username": username }),
    )
    .await;
    cognito(
        router,
        "AdminSetUserPassword",
        &json!({
            "UserPoolId": id,
            "Username": username,
            "Password": GOOD_PASSWORD,
            "Permanent": true,
        }),
    )
    .await;
    let signed_in = cognito(
        router,
        "AdminInitiateAuth",
        &json!({
            "UserPoolId": id,
            "ClientId": client_id,
            "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
            "AuthParameters": { "USERNAME": username, "PASSWORD": GOOD_PASSWORD },
        }),
    )
    .await;
    let id_token = member(
        "AdminInitiateAuth",
        &signed_in["AuthenticationResult"],
        "IdToken",
    );
    let user = cognito(
        router,
        "AdminGetUser",
        &json!({ "UserPoolId": id, "Username": username }),
    )
    .await;
    let subject = user["UserAttributes"]
        .as_array()
        .and_then(|attributes| {
            attributes
                .iter()
                .find(|attribute| attribute.get("Name").and_then(Value::as_str) == Some("sub"))
        })
        .map(|attribute| member("AdminGetUser", attribute, "Value"))
        .expect("the created user's own subject attribute");
    Pool {
        arn,
        id_token,
        subject,
    }
}

/// Poll `GetFunctionConfiguration` until Lambda first reports the function `Active`, which is
/// that service's own clock-owed transition.
async fn wait_until_active(router: &MultiServiceRouter) {
    let deadline = Instant::now() + WAIT;
    loop {
        let (_, configuration) = lambda(
            router,
            "GET",
            &format!("/2015-03-31/functions/{FUNCTION}/configuration"),
            None,
        )
        .await;
        if configuration.get("State").and_then(Value::as_str) == Some("Active") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "setup CreateFunction: the function never became Active, last read {configuration}"
        );
        tokio::time::sleep(LOOK).await;
    }
}

/// Poll `DescribeTable` until DynamoDB first reports the table `ACTIVE`, which is when it
/// serves the writes the handler makes.
async fn wait_until_table_active(router: &MultiServiceRouter) {
    let deadline = Instant::now() + WAIT;
    loop {
        let (_, described) = dynamodb(router, "DescribeTable", json!({ "TableName": TABLE })).await;
        if described.pointer("/Table/TableStatus").and_then(Value::as_str) == Some("ACTIVE") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "setup CreateTable: the table never became ACTIVE, last read {described}"
        );
        tokio::time::sleep(LOOK).await;
    }
}

/// The marker item the handler wrote for `nonce`, or `None` when nothing is stored under it —
/// which is what an invocation that never happened leaves behind. Read strongly consistently,
/// so what it answers is every write made before it.
async fn marker(router: &MultiServiceRouter, case: &str, nonce: &str) -> Option<Value> {
    let (status, read) = dynamodb(
        router,
        "GetItem",
        json!({
            "TableName": TABLE,
            "Key": { "pk": { "S": nonce } },
            "ConsistentRead": true,
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from GetItem for {nonce:?}, got {status} with {read}"
    );
    read.get("Item").cloned()
}

/// The whole wiring: the table, the function and its grant, the two pools, and the api whose
/// one `COGNITO_USER_POOLS`-gated `GET` is integrated with that function. Answers the api id.
async fn deployed(router: &MultiServiceRouter, pool_arn: &str) -> String {
    let (status, created) = dynamodb(
        router,
        "CreateTable",
        json!({
            "TableName": TABLE,
            "AttributeDefinitions": [{ "AttributeName": "pk", "AttributeType": "S" }],
            "KeySchema": [{ "AttributeName": "pk", "KeyType": "HASH" }],
            "BillingMode": "PAY_PER_REQUEST",
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "setup CreateTable: expected HTTP 200, got {status} with {created}"
    );

    let (status, function) = lambda(
        router,
        "POST",
        "/2015-03-31/functions",
        Some(json!({
            "FunctionName": FUNCTION,
            "Role": ROLE,
            "Runtime": "python3.12",
            "Handler": HANDLER,
            "Environment": { "Variables": { "TABLE": TABLE } },
            "Code": {
                "ZipFile": base64::engine::general_purpose::STANDARD
                    .encode(package(HANDLER_SOURCE)),
            },
        })),
    )
    .await;
    assert_eq!(
        status, 201,
        "setup CreateFunction: expected HTTP 201, got {status} with {function}"
    );
    let function_arn = member("CreateFunction", &function, "FunctionArn");

    let api = apigw(
        router,
        "CreateRestApi",
        "POST",
        "/restapis",
        Some(json!({ "name": "cognito-gate-spares-its-backend" })),
        201,
    )
    .await;
    let api = member("CreateRestApi", &api, "id");
    let resources = apigw(
        router,
        "GetResources",
        "GET",
        &format!("/restapis/{api}/resources"),
        None,
        200,
    )
    .await;
    let root = resources
        .get("item")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .map(|item| member("GetResources", item, "id"))
        .expect("the api's root resource");

    let authorizer = apigw(
        router,
        "CreateAuthorizer",
        "POST",
        &format!("/restapis/{api}/authorizers"),
        Some(json!({
            "name": "pool-authorizer",
            "type": "COGNITO_USER_POOLS",
            // "A list of the Amazon Cognito user pool ARNs for the COGNITO_USER_POOLS
            // authorizer" (`Authorizer$providerARNs`): the one pool whose tokens this gate
            // accepts.
            "providerARNs": [pool_arn],
            "identitySource": format!("method.request.header.{TOKEN_HEADER}"),
            // "If it equals 0, authorization caching is disabled": every row's own value is
            // evaluated, so one row cannot be decided by another's held result.
            "authorizerResultTtlInSeconds": 0,
        })),
        201,
    )
    .await;
    let authorizer = member("CreateAuthorizer", &authorizer, "id");

    let resource = apigw(
        router,
        "CreateResource",
        "POST",
        &format!("/restapis/{api}/resources/{root}"),
        Some(json!({ "pathPart": RESOURCE_PATH })),
        201,
    )
    .await;
    let resource = member("CreateResource", &resource, "id");
    apigw(
        router,
        "PutMethod",
        "PUT",
        &format!("/restapis/{api}/resources/{resource}/methods/GET"),
        Some(json!({
            "authorizationType": "COGNITO_USER_POOLS",
            "authorizerId": authorizer,
        })),
        201,
    )
    .await;
    apigw(
        router,
        "PutIntegration",
        "PUT",
        &format!("/restapis/{api}/resources/{resource}/methods/GET/integration"),
        Some(json!({
            "type": "AWS_PROXY",
            "httpMethod": "POST",
            "uri": format!(
                "arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/\
                 {function_arn}/invocations"
            ),
        })),
        201,
    )
    .await;

    // "Grants a principal permission to use a function" (`AddPermission`), scoped to the
    // methods of this api, as a client scripts it after wiring the integration.
    let (status, granted) = lambda(
        router,
        "POST",
        &format!("/2015-03-31/functions/{FUNCTION}/policy"),
        Some(json!({
            "StatementId": "apigateway-invoke-backend",
            "Action": "lambda:InvokeFunction",
            "Principal": "apigateway.amazonaws.com",
            "SourceArn": format!(
                "arn:aws:execute-api:{REGION}:{account}:{api}/*/*",
                account = engine::emulator_account_id(),
            ),
        })),
    )
    .await;
    assert_eq!(
        status, 201,
        "setup AddPermission: expected HTTP 201, got {status} with {granted}"
    );

    let deployment = apigw(
        router,
        "CreateDeployment",
        "POST",
        &format!("/restapis/{api}/deployments"),
        Some(json!({ "stageName": STAGE })),
        201,
    )
    .await;
    member("CreateDeployment", &deployment, "id");

    wait_until_active(router).await;
    wait_until_table_active(router).await;
    api
}

/// What the gate owes one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// The authorizer admitted the request, so the function behind the method ran and the
    /// caller was served the envelope it returned.
    Served,
    /// The authorizer does not admit what the request presented, so it authorized nobody: the
    /// api's `UNAUTHORIZED` gateway response, and nothing of the backend run.
    Unauthorized,
}

/// How a row addresses the deployed stage: the two addressings this emulator serves one stage
/// at, which the gate's decision cannot depend on.
#[derive(Debug, Clone, Copy)]
enum Addressed {
    /// The api's own `execute-api` host, which is the endpoint
    /// `RestApi$disableExecuteApiEndpoint` documents.
    ExecuteApiHost,
    /// The data plane named in the PATH, ahead of the api id and the stage — how a client that
    /// cannot resolve that host reaches this emulator.
    PathStyle,
}

impl Addressed {
    fn label(self) -> &'static str {
        match self {
            Self::ExecuteApiHost => "the api's execute-api host",
            Self::PathStyle => "the path-style data-plane address",
        }
    }

    /// The part of a row's nonce that tells the two addressings of one row apart.
    fn slug(self) -> &'static str {
        match self {
            Self::ExecuteApiHost => "host",
            Self::PathStyle => "path",
        }
    }
}

/// One row: the value presented at the authorizer's identity source, and what the gate owes
/// the request.
struct Row {
    case: String,
    /// The value the `Authorization` header carries, or `None` to present nothing at all.
    presented: Option<String>,
    expected: Expected,
}

#[tokio::test]
async fn a_cognito_gate_refuses_an_unverifiable_token_without_running_its_backend() {
    let router = emulator();

    // The pool the api's authorizer lists, and a second pool it does not: a token the second
    // minted is a verifiable token of an issuer this gate does not accept.
    let home = pool_with_signed_in_user(&router, "home-pool", "alice").await;
    let foreign = pool_with_signed_in_user(&router, "foreign-pool", "bob").await;
    let api = deployed(&router, &home.arn).await;

    // A compact JWS nothing signed whose `iss` names a pool id no pool of this emulator holds,
    // in the issuer form a pool publishes.
    let stranger = unsigned_jws(&json!({
        "iss": format!("https://cognito-idp.{REGION}.amazonaws.com/{REGION}_nosuchpool"),
        "token_use": "id",
        "sub": "someone",
        "exp": now_seconds() + 3_600,
    }));

    let rows: Vec<Row> = vec![
        Row {
            case: "the pool's own identity token".to_string(),
            presented: Some(home.id_token.clone()),
            expected: Expected::Served,
        },
        Row {
            case: "the same token under the RFC 6750 bearer scheme".to_string(),
            presented: Some(format!("Bearer {}", home.id_token)),
            expected: Expected::Served,
        },
        Row {
            case: "nothing at the identity source".to_string(),
            presented: None,
            expected: Expected::Unauthorized,
        },
        Row {
            case: "an empty value at the identity source".to_string(),
            presented: Some(String::new()),
            expected: Expected::Unauthorized,
        },
        Row {
            case: "a value that is not a token at all".to_string(),
            presented: Some("not-a-real-cognito-token".to_string()),
            expected: Expected::Unauthorized,
        },
        Row {
            case: "that same value under the bearer scheme".to_string(),
            presented: Some("Bearer not-a-real-cognito-token".to_string()),
            expected: Expected::Unauthorized,
        },
        Row {
            case: "two segments, which is no compact JWS".to_string(),
            presented: Some("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0".to_string()),
            expected: Expected::Unauthorized,
        },
        Row {
            case: "three segments that are not base64url JSON".to_string(),
            presented: Some("aaa.bbb.ccc".to_string()),
            expected: Expected::Unauthorized,
        },
        Row {
            case: "a compact JWS claiming an issuer that is no pool".to_string(),
            presented: Some(stranger),
            expected: Expected::Unauthorized,
        },
        Row {
            case: "another pool's token, which this authorizer does not list".to_string(),
            presented: Some(foreign.id_token.clone()),
            expected: Expected::Unauthorized,
        },
    ];

    for (index, row) in rows.iter().enumerate() {
        for addressed in [Addressed::ExecuteApiHost, Addressed::PathStyle] {
            // The nonce the request carries is what the handler keys its marker item by, so
            // each row and addressing observes its OWN invocation rather than another's.
            let nonce = format!("row-{index}-{}", addressed.slug());
            let case = format!("{} at {}", row.case, addressed.label());
            let mut headers: Vec<(&str, &str)> = Vec::new();
            if let Some(presented) = &row.presented {
                headers.push((TOKEN_HEADER, presented.as_str()));
            }
            let (host, path) = match addressed {
                Addressed::ExecuteApiHost => (
                    format!("{api}.execute-api.{REGION}.amazonaws.com"),
                    format!("/{STAGE}/{RESOURCE_PATH}?nonce={nonce}"),
                ),
                Addressed::PathStyle => (
                    format!("apigateway.{REGION}.amazonaws.com"),
                    format!("/_aws/execute-api/{api}/{STAGE}/{RESOURCE_PATH}?nonce={nonce}"),
                ),
            };
            let answer = dispatch(&router, "GET", &host, &path, &headers, Bytes::new()).await;

            // Whatever the gate decided, the question about a presented value is never
            // answered as a fault of the gate itself.
            assert!(
                !(500..600).contains(&answer.status),
                "case {case:?}: expected a decision about the presented value, got {}",
                answer.summary()
            );
            assert_ne!(
                answer.message(),
                CONFIGURATION_ERROR,
                "case {case:?}: expected no configuration-error sentence, got {}",
                answer.summary()
            );

            let marked = marker(&router, &case, &nonce).await;
            match row.expected {
                Expected::Served => {
                    assert_eq!(
                        answer.status, 200,
                        "case {case:?}: expected HTTP 200 from the admitted invocation, got {}",
                        answer.summary()
                    );
                    assert_eq!(
                        answer.body,
                        json!({ "served": nonce, "sub": home.subject }),
                        "case {case:?}: expected the function's own envelope body, got {}",
                        answer.summary()
                    );
                    let marked = marked.unwrap_or(Value::Null);
                    assert_eq!(
                        marked,
                        json!({
                            "pk": { "S": nonce },
                            "sub": { "S": home.subject },
                        }),
                        "case {case:?}: expected the marker item the invocation wrote, got \
                         {marked}"
                    );
                }
                Expected::Unauthorized => {
                    assert_eq!(
                        answer.status, UNAUTHORIZED,
                        "case {case:?}: expected HTTP {UNAUTHORIZED}, got {}",
                        answer.summary()
                    );
                    assert_eq!(
                        answer.body,
                        json!({ "message": UNAUTHORIZED_MESSAGE }),
                        "case {case:?}: expected the UNAUTHORIZED gateway response body, got {}",
                        answer.summary()
                    );
                    assert_eq!(
                        marked, None,
                        "case {case:?}: expected the integration never to have run, got the \
                         marker {marked:?}"
                    );
                }
            }
        }
    }
}
