// SPDX-License-Identifier: CC0-1.0

//! Every object event class a bucket's notification configuration names really runs the
//! function it names, and what the handler's own signed data-plane calls did is read back
//! where a client reads it.
//!
//! The rules under test:
//!
//! 1. **A bucket's notification configuration publishes an object event to the Lambda function
//!    it names for EVERY event class it lists — a removal exactly as a creation — carrying the
//!    class of the event that happened, and only for a key every rule of that configuration's
//!    key-name `Filter` admits**, so the document a creation indexed is gone after the removal
//!    of the object that produced it, a re-write of the same key leaves the document the
//!    re-write carried, and a key the filter excludes changes nothing.
//! 2. **A signed request to the address a domain publishes is authorized by IAM's two sides
//!    TOGETHER — the domain's own access policy and the signing principal's identity-based
//!    policies — so a principal the access policy does not name is served when its identity
//!    policies allow the action, and refused, with the sentence IAM words for a request no
//!    policy allows, when neither side does.** The handler here is that principal: the
//!    domain's access policy names a separate control role and nothing else, so every write
//!    the handler makes is decided on the identity side alone.
//!
//! Five crates have to agree for either to hold (CloudFormation deploys the estate, S3
//! evaluates the configuration and makes the invocation, Lambda runs the handler, IAM and STS
//! answer for the execution role the handler's own calls are signed as, and Amazon OpenSearch
//! Service decides and serves the signed request), so the suite lives here: no single service
//! crate's test target can write the object and then read what the handler did.
//!
//! The rows differ along what the rules generalise over: for the first, the event class the
//! client produces (a creation, a re-write of the same key, a removal, and a write of a key the
//! filter excludes) and which key it names, with a row that writes nothing at all to pin that a
//! removal is scoped to the key it named; for the second, whether the handler's identity side
//! grants this service's data-plane actions, over the two methods the pipeline signs (the index
//! write and the delete), so neither the verdict nor the action the refusal names is a fixed
//! answer.
//!
//! Every request below is dispatched through a BOXED future ([`Box::pin`]), on a thread sized
//! for the chain it drives, for the reason the sibling
//! [`super::s3_notification_invokes_its_lambda_target`] suite records: the assembled router's
//! dispatch future carries the whole emulator's handler state inline, and this suite nests
//! CloudFormation into S3, S3's delivery into Lambda, and the handler's own calls back into
//! both.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::cloudformation_firehose_stream_stabilisation::stack_status;
use crate::query_wire::{form_encode, outputs_of};

/// The Region every request here is signed for — the one the shared stack reader
/// ([`stack_status`]) signs for, so the stack this suite creates is the stack it reports.
const REGION: &str = "us-east-1";

/// The `StackStatus` a deployed stack must reach.
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";

/// The engine release every deployed domain runs.
const ENGINE_VERSION: &str = "OpenSearch_2.11";

/// The index every handler writes into, and the suffix both of a configuration's two
/// destination configurations filter on — which is also what keeps the `.err` object the
/// handler writes back from producing an event of its own.
const INDEX: &str = "documents";
const SUFFIX: &str = ".json";

/// How long this suite waits for work the clock owes — a stack's resources coming up, and the
/// asynchronous delivery of an object event — and how often it looks while waiting.
const WAIT: Duration = Duration::from_secs(90);
const LOOK_INTERVAL: Duration = Duration::from_millis(200);

/// How long a row that must see a document STAY absent keeps looking before concluding nothing
/// came: well past the span a delivered row takes to reach the domain.
const QUIET_WINDOW: Duration = Duration::from_secs(8);

/// The stack the emulator's own boot path gives the thread that assembles the router
/// (`core/router/src/main.rs`). Assembling every service and then dispatching a CHAIN of
/// in-process calls through it — CloudFormation into S3, S3's delivery into Lambda, the
/// handler's own calls back into S3 and into the search domain — nests more future than the
/// default stack of a test thread holds.
const BOOT_STACK_SIZE: usize = 64 * 1024 * 1024;

/// Run `body` to completion on a thread with [`BOOT_STACK_SIZE`], on the current-thread runtime
/// this suite's deliveries are made on: a notification delivery is a task of its own, so it runs
/// on this same thread and needs the same depth.
fn driven<Body>(name: &'static str, body: Body)
where
    Body: FnOnce() -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = ()>>> + Send + 'static,
{
    ::std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(BOOT_STACK_SIZE)
        .spawn(move || {
            let runtime = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build a current-thread runtime");
            runtime.block_on(body());
        })
        .expect("spawn the sized thread")
        .join()
        .expect("the suite thread runs to completion");
}

/// The handler every stack here deploys: for each record it is handed it SIGNS a request of its
/// own against the domain endpoint its configuration carries — the document written for a
/// creation, the document deleted for a removal — and, where the domain refuses that request,
/// writes the refusal back beside the object as a `<key>.err` object, which is how a caller of
/// an asynchronous invocation sees what the handler was told.
const INDEXING_HANDLER: &str = r#"
import json
import os
import urllib.error
import urllib.request

import boto3
import botocore.session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

REMOVAL = "ObjectRemoved:"


def _signed(method, url, body):
    request = AWSRequest(
        method=method, url=url, data=body, headers={"Content-Type": "application/json"}
    )
    SigV4Auth(
        botocore.session.get_session().get_credentials(),
        "es",
        os.environ["AWS_REGION"],
    ).add_auth(request)
    sending = urllib.request.Request(request.url, data=body, method=request.method)
    for name, value in request.headers.items():
        sending.add_header(name, value)
    with urllib.request.urlopen(sending) as answer:
        return answer.status


def _document(document_id):
    return (
        "https://"
        + os.environ["SEARCH_ENDPOINT"]
        + "/"
        + os.environ["SEARCH_INDEX"]
        + "/_doc/"
        + document_id
    )


def handler(event, context):
    s3 = boto3.client("s3")
    done = []
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        name = record["eventName"]
        url = _document(key.replace("/", "_"))
        try:
            if name.startswith(REMOVAL):
                status = _signed("DELETE", url, None)
            else:
                body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                status = _signed("PUT", url, body)
        except urllib.error.HTTPError as refused:
            s3.put_object(
                Bucket=bucket,
                Key=key + ".err",
                Body=json.dumps(
                    {
                        "eventName": name,
                        "key": key,
                        "status": refused.code,
                        "detail": refused.read().decode("utf-8"),
                    }
                ).encode("utf-8"),
            )
            continue
        done.append({"eventName": name, "key": key, "status": status})
    return {"done": done}
"#;

/// The emulator as it is ASSEMBLED, on one engine: the handler's own calls are dispatched back
/// into this same router, so the domain it writes to is the domain this suite reads.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = aws_emulator_router::build_router(engine);
    router.set_request_authentication(false);
    router
}

/// A SigV4 `Authorization` header whose credential scope names `service`, which is what routes
/// the request. The signature is never checked: request authentication is off.
fn authorization(service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDTEST/20260101/{REGION}/{service}/aws4_request, \
         SignedHeaders=host, Signature=not-verified"
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
    let response = Box::pin(router.dispatch(request)).await;
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(response.body()).to_string())
}

/// Dispatch one request against S3's REST surface, path-style: the status and the body as text.
async fn s3(router: &MultiServiceRouter, method: &str, path: &str, body: &str) -> (u16, String) {
    let host = format!("s3.{REGION}.amazonaws.com");
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("host", host)
        .header("authorization", authorization("s3"))
        .header("content-type", "application/octet-stream")
        .body(Bytes::from(body.to_owned()))
        .expect("a well-formed request");
    let response = Box::pin(router.dispatch(request)).await;
    (
        response.status().as_u16(),
        String::from_utf8_lossy(response.body()).into_owned(),
    )
}

/// `PUT /<bucket>/<key>` — `PutObject`.
async fn put_object(router: &MultiServiceRouter, case: &str, bucket: &str, key: &str, body: &str) {
    let (status, answered) = s3(router, "PUT", &format!("/{bucket}/{key}"), body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: PutObject({bucket:?}, {key:?}) must succeed, got {status} with {answered}"
    );
}

/// `DELETE /<bucket>/<key>` — `DeleteObject`.
async fn delete_object(router: &MultiServiceRouter, case: &str, bucket: &str, key: &str) {
    let (status, answered) = s3(router, "DELETE", &format!("/{bucket}/{key}"), "").await;
    assert_eq!(
        status, 204,
        "case {case:?}: DeleteObject({bucket:?}, {key:?}) must succeed, got {status} with \
         {answered}"
    );
}

/// One GET of the address the domain PUBLISHES, dialled the way a client dials it: the status
/// and the parsed body.
///
/// It is signed with the account's own published credential, which the deployed access policy
/// does not name — the other half of the second rule: the two sides of IAM decide together, so
/// a caller no access policy names is not refused for that reason alone.
async fn at_address(
    router: &MultiServiceRouter,
    address: &str,
    method: &str,
    path: &str,
) -> (u16, Value) {
    let (host, prefix) = match address.split_once('/') {
        Some((host, under)) => (host.to_string(), format!("/{under}")),
        None => (address.to_string(), String::new()),
    };
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{prefix}{path}"))
        .header("host", host)
        .header("authorization", authorization("es"))
        .header("content-type", "application/json")
        .body(Bytes::new())
        .expect("a well-formed request");
    let response = Box::pin(router.dispatch(request)).await;
    let status = response.status().as_u16();
    let body: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, body)
}

/// The document id the handler derives from an object key.
fn document_id(key: &str) -> String {
    key.replace('/', "_")
}

/// The trust policy both execution roles carry, with `grants_search` deciding whether the
/// IDENTITY side of IAM grants this service's data-plane actions — the one axis the second
/// rule's rows differ along.
fn role_resource(grants_search: bool) -> Value {
    // The handler reads the object the event named and writes its own `.err` object, so those
    // two are granted whatever the row decides about the search domain.
    let mut actions = vec!["s3:GetObject", "s3:PutObject", "logs:*"];
    if grants_search {
        actions.push("es:ESHttp*");
    }
    json!({
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": { "Service": "lambda.amazonaws.com" },
                    "Action": "sts:AssumeRole",
                }],
            },
            "Policies": [{
                "PolicyName": "handle-the-object-event",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": "*",
                    }],
                },
            }],
        },
    })
}

/// One `LambdaConfigurations` entry: the function notified of `event`, for keys the suffix
/// filter admits.
fn lambda_configuration(event: &str) -> Value {
    json!({
        "Event": event,
        "Function": { "Fn::GetAtt": ["Indexer", "Arn"] },
        "Filter": { "S3Key": { "Rules": [{ "Name": "suffix", "Value": SUFFIX }] } },
    })
}

/// The whole pipeline as ONE stack: the search domain whose access policy names a separate
/// control role and nothing else, the handler configured with the address that domain
/// publishes, the grant S3 needs to invoke it, and the landing bucket whose notification
/// configuration names it for BOTH the creation and the removal class.
fn pipeline_stack(bucket: &str, grants_search: bool) -> Value {
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "IndexerRole": role_resource(grants_search),
            // The ONE principal the domain's access policy names, so nothing on the resource
            // side of IAM says anything about the handler or about this suite's own reader.
            "ControlRole": role_resource(true),
            "SearchDomain": {
                "Type": "AWS::OpenSearchService::Domain",
                "Properties": {
                    "EngineVersion": ENGINE_VERSION,
                    "ClusterConfig": { "InstanceType": "t3.small.search", "InstanceCount": 1 },
                    "EBSOptions": { "EBSEnabled": true, "VolumeType": "gp3", "VolumeSize": 10 },
                    "AccessPolicies": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": { "AWS": { "Fn::GetAtt": ["ControlRole", "Arn"] } },
                            "Action": "es:ESHttp*",
                            "Resource": "*",
                        }],
                    },
                },
            },
            "Indexer": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": { "Fn::GetAtt": ["IndexerRole", "Arn"] },
                    "Timeout": 30,
                    "Environment": {
                        "Variables": {
                            "SEARCH_ENDPOINT": { "Fn::GetAtt": ["SearchDomain", "DomainEndpoint"] },
                            "SEARCH_INDEX": INDEX,
                        },
                    },
                    "Code": { "ZipFile": INDEXING_HANDLER },
                },
            },
            "InvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": { "Fn::GetAtt": ["Indexer", "Arn"] },
                    "Action": "lambda:InvokeFunction",
                    "Principal": "s3.amazonaws.com",
                    "SourceArn": format!("arn:aws:s3:::{bucket}"),
                },
            },
            "LandingBucket": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": "InvokePermission",
                "Properties": {
                    "BucketName": bucket,
                    "NotificationConfiguration": {
                        "LambdaConfigurations": [
                            lambda_configuration("s3:ObjectCreated:*"),
                            lambda_configuration("s3:ObjectRemoved:*"),
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "DomainEndpoint": { "Value": { "Fn::GetAtt": ["SearchDomain", "DomainEndpoint"] } },
            "RoleName": { "Value": { "Ref": "IndexerRole" } },
        },
    })
}

/// Create `stack` from `template`, wait for `CREATE_COMPLETE` and answer its outputs.
async fn deployed(
    router: &MultiServiceRouter,
    case: &str,
    stack: &str,
    template: &str,
) -> BTreeMap<String, String> {
    let (status, body) = query(
        router,
        "cloudformation",
        "2010-05-15",
        "CreateStack",
        &[
            ("StackName", stack),
            ("TemplateBody", template),
            ("Capabilities.member.1", "CAPABILITY_IAM"),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateStack({stack:?}) must be accepted, got {status} with {body}"
    );
    let looks = WAIT.as_millis() / LOOK_INTERVAL.as_millis();
    let mut reported = stack_status(router, stack).await;
    for _ in 0..looks {
        if reported.0 == CREATE_COMPLETE {
            break;
        }
        tokio::time::sleep(LOOK_INTERVAL).await;
        reported = stack_status(router, stack).await;
    }
    assert_eq!(
        reported.0, CREATE_COMPLETE,
        "case {case:?}: the stack must reach {CREATE_COMPLETE}, got {:?} with {}",
        reported.0, reported.1
    );
    outputs_of(&reported.1)
}

/// The deployed pipeline: the address its domain published, and the name of the role its
/// handler's own calls are signed as.
async fn deployed_pipeline(
    router: &MultiServiceRouter,
    case: &str,
    stack: &str,
    bucket: &str,
    grants_search: bool,
) -> (String, String) {
    let outputs = deployed(
        router,
        case,
        stack,
        &pipeline_stack(bucket, grants_search).to_string(),
    )
    .await;
    let address = outputs
        .get("DomainEndpoint")
        .cloned()
        .unwrap_or_else(|| panic!("case {case:?}: the stack must output its domain's address"));
    assert!(
        !address.is_empty(),
        "case {case:?}: the domain must publish an address once it is up, got {address:?}"
    );
    let role = outputs
        .get("RoleName")
        .cloned()
        .unwrap_or_else(|| panic!("case {case:?}: the stack must output its role's name"));
    (address, role)
}

/// Look at the signed read of one document until `settled` holds of the answer, or [`WAIT`]
/// passes, and answer the last answer it gave.
async fn awaited_document(
    router: &MultiServiceRouter,
    address: &str,
    key: &str,
    settled: impl Fn(u16, &Value) -> bool,
) -> (u16, Value) {
    let path = format!("/{INDEX}/_doc/{}", document_id(key));
    let looks = WAIT.as_millis() / LOOK_INTERVAL.as_millis();
    let mut answer = at_address(router, address, "GET", &path).await;
    for _ in 0..looks {
        if settled(answer.0, &answer.1) {
            break;
        }
        tokio::time::sleep(LOOK_INTERVAL).await;
        answer = at_address(router, address, "GET", &path).await;
    }
    answer
}

/// What the client does to the object of one row.
#[derive(Debug, Clone, Copy)]
enum Wrote {
    /// `PutObject` carrying this body.
    Body(&'static str),
    /// `DeleteObject`.
    Removal,
    /// Nothing at all: the row only reads, which is what pins a removal to the key it named.
    Nothing,
}

/// One row: what the client does, to which key, and what the signed read of the document that
/// key derives must then answer.
struct Row {
    case: &'static str,
    key: &'static str,
    wrote: Wrote,
    /// The `_source` the document must carry, or `None` when no document may be there.
    indexed: Option<&'static str>,
}

/// The table, over the event classes the configuration names and the keys its filter decides.
const ROWS: &[Row] = &[
    Row {
        case: "a created object is indexed under the id its key derives",
        key: "items/alpha.json",
        wrote: Wrote::Body(r#"{"id":"alpha","qty":7}"#),
        indexed: Some(r#"{"id":"alpha","qty":7}"#),
    },
    Row {
        case: "a second created object of the same prefix",
        key: "items/beta.json",
        wrote: Wrote::Body(r#"{"id":"beta","qty":0}"#),
        indexed: Some(r#"{"id":"beta","qty":0}"#),
    },
    Row {
        case: "a re-write of the same key leaves the document that write carried",
        key: "items/alpha.json",
        wrote: Wrote::Body(r#"{"id":"alpha","qty":11,"note":"re-written"}"#),
        indexed: Some(r#"{"id":"alpha","qty":11,"note":"re-written"}"#),
    },
    Row {
        case: "a key the configuration's suffix filter excludes reaches no function",
        key: "items/gamma.csv",
        wrote: Wrote::Body("id,qty\ngamma,3\n"),
        indexed: None,
    },
    Row {
        case: "the removal of an object removes the document its creation indexed",
        key: "items/alpha.json",
        wrote: Wrote::Removal,
        indexed: None,
    },
    Row {
        case: "the document of a key the removal did not name is left alone",
        key: "items/beta.json",
        wrote: Wrote::Nothing,
        indexed: Some(r#"{"id":"beta","qty":0}"#),
    },
    Row {
        case: "the removal of the second object removes its document too",
        key: "items/beta.json",
        wrote: Wrote::Removal,
        indexed: None,
    },
];

/// RULE 1 (with the serving half of rule 2): every event class the configuration names runs the
/// function, so the document follows the object — written by a creation, replaced by a
/// re-write, gone after a removal and untouched for a key the filter excludes — and the account's
/// own credential, which the domain's access policy does not name, reads it all back at the
/// address the domain published.
///
/// Driven on a sized thread; see [`driven`].
#[test]
fn the_document_follows_the_object_the_bucket_notifies_about() {
    driven("s3-object-events-update-their-search-index", || {
        Box::pin(the_document_follows_the_object_the_bucket_notifies_about_body())
    });
}

async fn the_document_follows_the_object_the_bucket_notifies_about_body() {
    let router = build_router();
    let bucket = "search-index-landing";
    let (address, _) = deployed_pipeline(
        &router,
        "the deployed pipeline",
        "search-index-stack",
        bucket,
        true,
    )
    .await;

    for row in ROWS {
        let case = row.case;
        match row.wrote {
            Wrote::Body(body) => put_object(&router, case, bucket, row.key, body).await,
            Wrote::Removal => delete_object(&router, case, bucket, row.key).await,
            Wrote::Nothing => {}
        }
        match row.indexed {
            Some(expected) => {
                let expected: Value = serde_json::from_str(expected).unwrap_or_else(|error| {
                    panic!("case {case:?}: the row's document must be JSON: {error}")
                });
                let (status, answered) =
                    awaited_document(&router, &address, row.key, |status, body| {
                        status == 200 && body["_source"] == expected
                    })
                    .await;
                assert_eq!(
                    status, 200,
                    "case {case:?}: the document for {:?} must be readable at {address:?}, got \
                     {status} with {answered}",
                    row.key
                );
                assert_eq!(
                    answered["_source"], expected,
                    "case {case:?}: expected the written object as the indexed _source, got \
                     {answered}"
                );
                assert_eq!(
                    answered["found"],
                    Value::Bool(true),
                    "case {case:?}: a document the read answers 200 for is found, got {answered}"
                );
            }
            None => {
                let (status, answered) =
                    awaited_document(&router, &address, row.key, |status, _| status == 404).await;
                assert_eq!(
                    status, 404,
                    "case {case:?}: no document may be there for {:?}, got {status} with \
                     {answered}",
                    row.key
                );
                assert_eq!(
                    answered["found"],
                    Value::Bool(false),
                    "case {case:?}: the read of an absent document of an index the domain holds \
                     reports it as not found, got {answered}"
                );
                // Nothing may arrive late either: a delivery that re-indexed the document after
                // the removal would be as wrong as one that never came.
                let looks = QUIET_WINDOW.as_millis() / LOOK_INTERVAL.as_millis();
                for _ in 0..looks {
                    tokio::time::sleep(LOOK_INTERVAL).await;
                    let (status, answered) = at_address(
                        &router,
                        &address,
                        "GET",
                        &format!("/{INDEX}/_doc/{}", document_id(row.key)),
                    )
                    .await;
                    assert_eq!(
                        status, 404,
                        "case {case:?}: the document for {:?} must STAY absent, got {status} with \
                         {answered}",
                        row.key
                    );
                }
            }
        }
    }
}

/// One row of the refusal table: the method the pipeline signs for the event the client
/// produces, and the `es:ESHttp*` action that method asks for, which the refusal names.
struct Refused {
    case: &'static str,
    /// Whether the client's call is the creation (a write) or the removal (a delete).
    removal: bool,
    /// The `eventName` the record carries, which the marker reports.
    event_name: &'static str,
    action: &'static str,
}

/// The rows: the two methods one pipeline signs against the domain, each refused on the same
/// grounds, so the action the sentence names is not a fixed answer.
const REFUSALS: &[Refused] = &[
    Refused {
        case: "the index write a creation makes",
        removal: false,
        event_name: "ObjectCreated:Put",
        action: "es:ESHttpPut",
    },
    Refused {
        case: "the delete a removal makes",
        removal: true,
        event_name: "ObjectRemoved:Delete",
        action: "es:ESHttpDelete",
    },
];

/// The `<key>.err` object the handler wrote, parsed, once it reports `event_name` — the marker
/// of the event the row produced rather than the one before it.
async fn awaited_marker(
    router: &MultiServiceRouter,
    case: &str,
    bucket: &str,
    key: &str,
    event_name: &str,
) -> Value {
    let path = format!("/{bucket}/{key}.err");
    let looks = WAIT.as_millis() / LOOK_INTERVAL.as_millis();
    let mut answered = (0_u16, String::new());
    for _ in 0..looks {
        answered = s3(router, "GET", &path, "").await;
        if answered.0 == 200 {
            if let Ok(marker) = serde_json::from_str::<Value>(&answered.1) {
                if marker["eventName"] == Value::String(event_name.to_string()) {
                    return marker;
                }
            }
        }
        tokio::time::sleep(LOOK_INTERVAL).await;
    }
    panic!(
        "case {case:?}: the handler must write {key}.err reporting {event_name:?}, last read {} \
         with {}",
        answered.0, answered.1
    );
}

/// RULE 2 (the refusing half): with neither side of IAM allowing the action — the domain's
/// access policy names another role and the handler's identity policies grant nothing of this
/// service — the signed request is refused with the sentence IAM words for a request no policy
/// allows, naming the principal that signed and the action its METHOD asks for, and nothing is
/// indexed.
///
/// Driven on a sized thread; see [`driven`].
#[test]
fn a_handler_no_side_of_iam_allows_is_told_so_and_indexes_nothing() {
    driven("s3-object-events-refused-search-index", || {
        Box::pin(a_handler_no_side_of_iam_allows_is_told_so_and_indexes_nothing_body())
    });
}

async fn a_handler_no_side_of_iam_allows_is_told_so_and_indexes_nothing_body() {
    let router = build_router();
    let bucket = "search-refused-landing";
    let key = "items/denied.json";
    let (address, role) = deployed_pipeline(
        &router,
        "the deployed pipeline whose handler is granted nothing of the search domain",
        "search-refused-stack",
        bucket,
        false,
    )
    .await;

    for row in REFUSALS {
        let case = row.case;
        if row.removal {
            delete_object(&router, case, bucket, key).await;
        } else {
            put_object(&router, case, bucket, key, r#"{"id":"denied"}"#).await;
        }
        let marker = awaited_marker(&router, case, bucket, key, row.event_name).await;
        assert_eq!(
            marker["key"],
            Value::String(key.to_string()),
            "case {case:?}: the marker must name the key its record named, got {marker}"
        );
        assert_eq!(
            marker["status"],
            Value::from(403),
            "case {case:?}: a request no policy allows is refused with 403, got {marker}"
        );
        let detail: Value = serde_json::from_str(marker["detail"].as_str().unwrap_or_default())
            .unwrap_or_else(|error| {
                panic!("case {case:?}: the refusal the handler read must be JSON ({error}): {marker}")
            });
        let message = detail["Message"].as_str().unwrap_or_default();
        // The sentence is IAM's own. Its principal and the policy that refused come from the
        // request and from what the stack deployed, so only the clause and the action are
        // stated here — and the action is the one this row's METHOD asks for.
        let expected = format!(
            "is not authorized to perform: {} because no resource-based policy allows the {} \
             action",
            row.action, row.action
        );
        assert!(
            message.starts_with("User: ") && message.ends_with(&expected),
            "case {case:?}: expected IAM's refusal of {} ending {expected:?}, got {message:?}",
            row.action
        );
        assert!(
            message.contains(&role),
            "case {case:?}: the refusal must name the principal the handler signed as, a session \
             of {role:?}, got {message:?}"
        );
    }

    // And nothing was indexed by either leg: a refused write is a write that did not happen.
    let (status, answered) = at_address(
        &router,
        &address,
        "GET",
        &format!("/{INDEX}/_doc/{}", document_id(key)),
    )
    .await;
    assert_ne!(
        status, 200,
        "a handler no side of IAM allows may index nothing, got {status} with {answered}"
    );
}
