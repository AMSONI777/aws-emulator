// SPDX-License-Identifier: CC0-1.0

//! A CloudFormation stack that puts a REST API's deployed stage behind a CloudFront custom
//! origin serves the api's own answer on BOTH hops: at the stage's invoke URL and at the
//! distribution's edge domain.
//!
//! The rule under test: **a deployed REST stage answers a request to its invoke URL from the
//! method's integration — a `MOCK` integration's answer being the integration response its
//! rendered request template selects, with that response's mapped status and its response
//! template as the body — and a CloudFront distribution that names that stage as a custom
//! origin relays the origin's own status and body to the viewer once the distribution is
//! `Deployed`.** Nothing about the hop is specific to how the api was built, so a stack that
//! declares the whole topology by template is served exactly as one assembled call by call.
//!
//! Three crates have to agree for that to hold — CloudFormation makes the creates, API Gateway
//! holds the api and serves the invoke, CloudFront holds the distribution and performs the
//! origin fetch — so the suite lives here and drives the emulator as it is ASSEMBLED.
//!
//! The rows differ along what the rule generalises over: whether the method sits on the api's
//! ROOT resource or on a resource under it, the stage's name, whether the origin names the
//! stage in its `OriginPath` (so the viewer asks for the bare resource path) or leaves it off
//! (so the viewer's own path carries the stage), the status the integration response maps to,
//! and the document the response template renders.
//!
//! Every expected value is computed here from what the row declares, and the api id, the
//! invoke URL, the distribution id and its domain name come out of the stack's own OUTPUTS —
//! what a client deploying the stack reads — never out of the answer being checked.

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;
use std::sync::Arc;

use crate::cloudformation_firehose_stream_stabilisation::wait_for_stack_status;
use crate::cloudfront_apigateway_origin_edge::{view, wait_until_deployed};
use crate::query_wire::{elements, form_encode, outputs_of};

/// The Region every request here is signed for, and so the Region the stack's resources
/// belong to and the one the api's invoke host names.
const REGION: &str = "us-east-1";

/// The `StackStatus` the rule is stated about.
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";

/// The logical id of the origin the distribution's one behaviour targets.
const ORIGIN_ID: &str = "api-origin";

/// The emulator as it is ASSEMBLED, on one engine: the api CloudFormation creates is the api
/// the invoke reaches, and the distribution it creates is the one the viewer dials.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = aws_emulator_router::build_router(engine);
    // The signature is never checked here, as in every other suite of this crate; the
    // credential scope is what routes a request.
    router.set_request_authentication(false);
    router
}

/// A SigV4 `Authorization` header whose credential scope names `service`, which is what routes
/// the request and what each handler reads its Region from.
fn authorization(service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/{REGION}/{service}/aws4_request, \
         SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
    )
}

/// Call one CloudFormation operation over its awsQuery wire.
async fn cloudformation(
    router: &MultiServiceRouter,
    action: &str,
    members: &[(&str, &str)],
) -> (u16, String) {
    let mut body = format!("Action={action}&Version=2010-05-15");
    for (key, value) in members {
        body.push('&');
        body.push_str(&form_encode(key));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("cloudformation.{REGION}.amazonaws.com"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", authorization("cloudformation"))
        .body(Bytes::from(body))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(response.body()).to_string())
}

/// Read one API Gateway control-plane resource over its restJson1 wire.
async fn apigateway(router: &MultiServiceRouter, uri: &str) -> (u16, Value) {
    let request = http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", format!("apigateway.{REGION}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("apigateway"))
        .body(Bytes::new())
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let answered: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, answered)
}

/// Invoke a deployed stage at the invoke URL the stack published, exactly as a client reaches
/// AWS: the request's host is the api's own `{rest-api-id}.execute-api.{region}.amazonaws.com`
/// endpoint and its path is the stage and the resource path. The URL is taken APART rather
/// than rebuilt, so what is driven is the value the stack told the caller to use.
///
/// A viewer of the distribution carries no credential, and neither does this invoke: the
/// method the rows declare is `AuthorizationType: NONE`.
async fn invoke(router: &MultiServiceRouter, invoke_url: &str) -> (u16, String) {
    let without_scheme = invoke_url
        .strip_prefix("https://")
        .or_else(|| invoke_url.strip_prefix("http://"))
        .unwrap_or(invoke_url);
    let (host, path) = match without_scheme.split_once('/') {
        Some((host, path)) => (host.to_string(), format!("/{path}")),
        None => (without_scheme.to_string(), "/".to_string()),
    };
    let request = http::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host)
        .body(Bytes::new())
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(response.body()).to_string())
}

/// One row of the table: the topology the template declares and what both hops must answer.
struct Row {
    case: &'static str,
    /// The stage the deployment is served under, and the stage the invoke URL names.
    stage: &'static str,
    /// The path part of the resource the method sits on, or `None` for the api's ROOT
    /// resource — the two places a method can be put.
    path_part: Option<&'static str>,
    /// Whether the origin names the stage in its `OriginPath`. When it does, the viewer asks
    /// for the bare resource path; when it does not, the viewer's own path carries the stage.
    origin_path: bool,
    /// The status the integration response maps to, which is the status both hops answer.
    status: u16,
    /// The document the integration response's `application/json` response template renders,
    /// which is the body both hops answer.
    body: &'static str,
}

/// The stage-relative path of the row's method: `/` for a method on the root resource.
fn method_path(row: &Row) -> String {
    row.path_part.map_or_else(|| "/".to_string(), |part| format!("/{part}"))
}

/// The path the VIEWER asks the distribution for: the method's own path when the origin names
/// the stage, and the stage followed by it when the origin does not.
fn viewer_path(row: &Row) -> String {
    if row.origin_path {
        method_path(row)
    } else {
        format!("/{}{}", row.stage, method_path(row))
    }
}

/// The template the row deploys: the api, the resource its method may sit under, the method
/// with a `MOCK` integration and the response either side of it, the deployment of them, the
/// stage serving that deployment, and a distribution whose only origin is that stage.
fn template(row: &Row, stack: &str) -> String {
    let status = row.status.to_string();
    let (resource_id, mut resources) = match row.path_part {
        Some(part) => (
            json!({ "Ref": "Resource" }),
            json!({
                "Resource": {
                    "Type": "AWS::ApiGateway::Resource",
                    "Properties": {
                        "RestApiId": { "Ref": "Api" },
                        "ParentId": { "Fn::GetAtt": ["Api", "RootResourceId"] },
                        "PathPart": part
                    }
                }
            }),
        ),
        None => (
            json!({ "Fn::GetAtt": ["Api", "RootResourceId"] }),
            json!({}),
        ),
    };

    let mut origin = json!({
        "Id": ORIGIN_ID,
        "DomainName": {
            "Fn::Sub": "${Api}.execute-api.${AWS::Region}.amazonaws.com"
        },
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            // Every AWS endpoint of this emulator is served over TLS alone, which is the
            // scheme the origin fetch has to use.
            "OriginProtocolPolicy": "https-only"
        }
    });
    if row.origin_path {
        origin["OriginPath"] = json!(format!("/{}", row.stage));
    }

    let declared = resources.as_object_mut().expect("an object");
    declared.insert(
        "Api".to_string(),
        json!({
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {
                "Name": format!("{stack}-api"),
                "EndpointConfiguration": { "Types": ["REGIONAL"] }
            }
        }),
    );
    declared.insert(
        "Method".to_string(),
        json!({
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": { "Ref": "Api" },
                "ResourceId": resource_id,
                "HttpMethod": "GET",
                "AuthorizationType": "NONE",
                "MethodResponses": [{ "StatusCode": status }],
                "Integration": {
                    "Type": "MOCK",
                    // A MOCK has no backend: the `statusCode` its rendered request template
                    // names is the integration response the call maps to.
                    "RequestTemplates": {
                        "application/json": format!(r#"{{"statusCode":{status}}}"#)
                    },
                    "IntegrationResponses": [{
                        "StatusCode": status,
                        "ResponseTemplates": { "application/json": row.body }
                    }]
                }
            }
        }),
    );
    declared.insert(
        "Deployment".to_string(),
        json!({
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": ["Method"],
            "Properties": { "RestApiId": { "Ref": "Api" } }
        }),
    );
    declared.insert(
        "Stage".to_string(),
        json!({
            "Type": "AWS::ApiGateway::Stage",
            "Properties": {
                "RestApiId": { "Ref": "Api" },
                "DeploymentId": { "Ref": "Deployment" },
                "StageName": row.stage
            }
        }),
    );
    declared.insert(
        "Distribution".to_string(),
        json!({
            "Type": "AWS::CloudFront::Distribution",
            "DependsOn": ["Stage"],
            "Properties": {
                "DistributionConfig": {
                    "Enabled": true,
                    "Comment": "the stage as a custom origin",
                    "Origins": [origin],
                    "DefaultCacheBehavior": {
                        "TargetOriginId": ORIGIN_ID,
                        "ViewerProtocolPolicy": "allow-all",
                        // A behaviour that names no cache policy keys on its own legacy
                        // ForwardedValues, and a zero MinTTL sends every viewer request on to
                        // the origin.
                        "ForwardedValues": {
                            "QueryString": false,
                            "Cookies": { "Forward": "none" }
                        },
                        "MinTTL": 0
                    }
                }
            }
        }),
    );

    json!({
        "Resources": resources,
        "Outputs": {
            "ApiId": { "Value": { "Ref": "Api" } },
            "InvokeUrl": {
                "Value": {
                    "Fn::Sub": format!(
                        "https://${{Api}}.execute-api.${{AWS::Region}}.amazonaws.com/{}{}",
                        row.stage,
                        // A method on the root resource is invoked at the stage itself.
                        row.path_part.map_or(String::new(), |part| format!("/{part}"))
                    )
                }
            },
            "DistributionId": { "Value": { "Fn::GetAtt": ["Distribution", "Id"] } },
            "DistributionDomainName": {
                "Value": { "Fn::GetAtt": ["Distribution", "DomainName"] }
            }
        }
    })
    .to_string()
}

const ROWS: &[Row] = &[
    Row {
        case: "a method on the api's ROOT resource, the stage in the origin's OriginPath",
        stage: "prod",
        path_part: None,
        origin_path: true,
        status: 200,
        body: r#"{"message":"served-by-the-mock"}"#,
    },
    Row {
        case: "a method on a resource under the root, mapped to 201",
        stage: "live",
        path_part: Some("status"),
        origin_path: true,
        status: 201,
        body: r#"{"state":"ready","depth":1}"#,
    },
    Row {
        case: "an origin with NO OriginPath, so the viewer's own path carries the stage",
        stage: "v1",
        path_part: Some("items"),
        origin_path: false,
        status: 200,
        body: r#"{"items":[1,2,3]}"#,
    },
];

#[tokio::test]
async fn a_stack_s_cloudfront_fronted_rest_stage_serves_on_both_hops() {
    let router = build_router();
    for (index, row) in ROWS.iter().enumerate() {
        let case = row.case;
        let stack = format!("cloudfront-fronted-api-{index}");
        let body = template(row, &stack);

        let (status, answered) = cloudformation(
            &router,
            "CreateStack",
            &[("StackName", &stack), ("TemplateBody", &body)],
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from CreateStack, got {status} with body {answered}"
        );

        let (reported, described) = wait_for_stack_status(&router, &stack, CREATE_COMPLETE).await;
        let failures = if reported == CREATE_COMPLETE {
            Vec::new()
        } else {
            let (_, events) =
                cloudformation(&router, "DescribeStackEvents", &[("StackName", &stack)]).await;
            elements(&events, "ResourceStatusReason")
        };
        assert_eq!(
            reported, CREATE_COMPLETE,
            "case {case:?}: expected the stack to reach {CREATE_COMPLETE}, got {described} with \
             resource failures {failures:?}"
        );

        let outputs = outputs_of(&described);
        let api_id = outputs.get("ApiId").cloned().unwrap_or_else(|| {
            panic!("case {case:?}: the stack published no ApiId output in {described}")
        });
        let invoke_url = outputs.get("InvokeUrl").cloned().unwrap_or_else(|| {
            panic!("case {case:?}: the stack published no InvokeUrl output in {described}")
        });
        let distribution_id = outputs.get("DistributionId").cloned().unwrap_or_else(|| {
            panic!("case {case:?}: the stack published no DistributionId output in {described}")
        });
        let domain = outputs
            .get("DistributionDomainName")
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "case {case:?}: the stack published no DistributionDomainName output in \
                     {described}"
                )
            });

        // The stage the stack deployed is one API Gateway HOLDS: the stack's own records are
        // not evidence of anything, the owning service's read is.
        let (status, stage) =
            apigateway(&router, &format!("/restapis/{api_id}/stages/{}", row.stage)).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetStage for {}, got {status} with body \
             {stage}",
            row.stage
        );

        // Hop one: the stage's own invoke URL answers the integration response the MOCK
        // selected — its mapped status and its rendered response template.
        let (status, served) = invoke(&router, &invoke_url).await;
        assert_eq!(
            status, row.status,
            "case {case:?}: expected the deployed stage at {invoke_url} to answer HTTP {}, got \
             {status} with body {served:?}",
            row.status
        );
        let expected: Value = serde_json::from_str(row.body).expect("the row's own document");
        let direct: Value = serde_json::from_str(&served).unwrap_or(Value::Null);
        assert_eq!(
            direct, expected,
            "case {case:?}: expected the stage to answer the integration response's template \
             {expected}, got {served:?}"
        );

        // Hop two: the same answer through the edge, once CloudFront first reports the
        // distribution Deployed — the state a viewer request is served in.
        wait_until_deployed(&router, case, &distribution_id).await;
        let path = viewer_path(row);
        let viewed = view(&router, "https", &domain, &path, &[]).await;
        assert_eq!(
            viewed.status, row.status,
            "case {case:?}: expected the distribution at https://{domain}{path} to relay HTTP \
             {}, got {} with body {:?}",
            row.status,
            viewed.status,
            viewed.text()
        );
        assert_eq!(
            viewed.json(),
            expected,
            "case {case:?}: expected the edge to relay the origin's body {expected}, got {:?}",
            viewed.text()
        );
        assert_eq!(
            viewed.text(),
            served,
            "case {case:?}: expected the edge to relay the origin's answer unchanged, got {:?} \
             against the origin's {served:?}",
            viewed.text()
        );
    }
}
