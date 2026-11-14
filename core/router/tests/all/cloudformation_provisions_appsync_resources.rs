// SPDX-License-Identifier: CC0-1.0

//! A CloudFormation stack that declares an `AWS::AppSync::*` estate really creates it in AWS
//! AppSync, and the values the stack publishes for it are the ones that service answered.
//!
//! The rule under test: **a resource of a type this emulator provisions is created in the
//! service that OWNS it, through that service's own public API, and the identifiers and
//! endpoints the stack publishes for it are the ones that service answered — so an
//! `Fn::GetAtt` on a GraphQL API's `ApiId`, `Arn`, `GraphQLUrl` or `RealtimeUrl` resolves to
//! what `appsync GetGraphqlApi` reports for that API, and every child the template declares
//! (its schema, its data sources, its resolvers, its pipeline functions, its API keys) is read
//! back through AppSync's own reads.** Several crates have to agree for that to hold
//! (CloudFormation makes the calls; AppSync, Amazon Cognito, Amazon DynamoDB and IAM serve
//! them), so the suite lives here rather than in any one crate.
//!
//! The rows differ along what the rule generalises over: which of the six AppSync types the
//! template declares, how the API authenticates (an API key, or a Cognito user pool the same
//! template declares and names with a `Ref`), which kind of data source it reads through
//! (`NONE`, `AMAZON_DYNAMODB` with a service role reached by `Fn::GetAtt`, `HTTP`), whether a
//! resolver and a pipeline function hang off it, the language the template is written in (JSON
//! or YAML), the Region it deploys in, and which intrinsic each output reads the API with
//! (`Ref`, `Fn::GetAtt`, `Fn::Sub`).
//!
//! No expected value is read out of the answer being checked: each is either what the row's
//! own template declares, or what the OWNING service reports for the resource — which is the
//! whole point of the rule.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::Value;
use smithy_server_runtime::MultiServiceRouter;

// The awsQuery form encoder and the XML readers this crate writes ONCE
// (`tests/all/query_wire.rs`): "Nothing new should write another one — call this module."
use super::query_wire::{form_encode, opt_element, outputs_of, physical_ids_of};

/// How long one `DescribeStacks` poll waits before the next, and how many are made.
///
/// A stack's own status transitions, and the schema creation AppSync carries out
/// asynchronously, are owed on their clocks, so the suite waits for the STATUS rather than for
/// a span, with a deadline generous enough for a loaded host.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// See [`POLL_INTERVAL`].
const POLLS: usize = 600;

/// The emulator with the services this suite exercises, mounted on ONE engine exactly as
/// `core/router/src/lib.rs` mounts them. Request authentication is off, as in every other
/// suite here; the in-process callback CloudFormation makes signs its request either way (the
/// credential scope is what routes it).
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
        service_com_amazonaws_appsync_awsdeepdishcontrolplaneservice::EmulatedService::new(
            Arc::clone(&engine),
        ),
    );
    router.register_service(
        service_com_amazonaws_cognitoidentityprovider_awscognitoidentityproviderservice::
            EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_dynamodb_dynamodb_20120810::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_iam_awsidentitymanagementv20100508::EmulatedService::new(engine),
    );
    router
}

/// A SigV4 `Authorization` header whose credential scope names `service` in `region`, which is
/// what routes the request and what each handler reads its Region from. The signature is never
/// checked: this router runs with request authentication off.
fn authorization(service: &str, region: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/{region}/{service}/aws4_request, \
         SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
    )
}

/// Call one CloudFormation operation over its awsQuery wire, signed for `region`.
async fn cloudformation(
    router: &MultiServiceRouter,
    region: &str,
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
        .header("host", format!("cloudformation.{region}.amazonaws.com"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", authorization("cloudformation", region))
        .body(Bytes::from(body))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload = String::from_utf8_lossy(response.body()).to_string();
    (status, payload)
}

/// Call one AWS AppSync operation over the `restJson1` wire its model declares, on the URI
/// that operation's own `@http` binding states, signed for `region`.
async fn appsync(
    router: &MultiServiceRouter,
    region: &str,
    method: &str,
    path: &str,
) -> (u16, Value) {
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://appsync.{region}.amazonaws.com{path}"))
        .header("host", format!("appsync.{region}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("appsync", region))
        .body(Bytes::new())
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, payload)
}

/// Wait for `stack` to report `wanted`, looking again until it does or the deadline passes. A
/// stack that reaches another TERMINAL status fails the suite at once, quoting the answer: the
/// reason a resource failed is in it.
async fn wait_for_stack_status(
    router: &MultiServiceRouter,
    region: &str,
    stack: &str,
    wanted: &str,
) -> String {
    let mut body = String::new();
    for _ in 0..POLLS {
        let (status, reported) =
            cloudformation(router, region, "DescribeStacks", &[("StackName", stack)]).await;
        assert_eq!(
            status, 200,
            "DescribeStacks {stack:?}: expected HTTP 200, got {status} with body {reported}"
        );
        body = reported;
        let reported_status = opt_element(&body, "StackStatus").unwrap_or_default();
        if reported_status == wanted {
            return body;
        }
        assert!(
            !reported_status.ends_with("_FAILED") && !reported_status.starts_with("ROLLBACK"),
            "stack {stack:?}: expected {wanted:?}, got {reported_status:?} with answer {body}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!("stack {stack:?} never reached {wanted:?}; last answer was {body}");
}

/// One output of a `DescribeStacks` answer, or a panic naming the case and what was there.
fn output(outputs: &BTreeMap<String, String>, key: &str, case: &str) -> String {
    outputs
        .get(key)
        .cloned()
        .unwrap_or_else(|| panic!("case {case:?}: expected an output {key:?}, got {outputs:?}"))
}

/// A VTL request mapping template a UNIT resolver and a pipeline function carry.
const REQUEST_TEMPLATE: &str = "{\"version\":\"2017-02-28\",\"operation\":\"PutItem\"}";

/// Its response mapping template.
const RESPONSE_TEMPLATE: &str = "$util.toJson($ctx.result)";

/// One row of the table: a template, and what the rule says the estate it declares must then
/// be in AWS AppSync.
struct Row {
    case: &'static str,
    /// The Region the row deploys in, which is the Region its API and every child live in.
    region: &'static str,
    /// The stack name the row deploys under.
    stack: &'static str,
    /// The template body, in the language the row writes it in.
    template: &'static str,
    /// The `Name` the API's declaration states, which `GetGraphqlApi` must report.
    api_name: &'static str,
    /// The `AuthenticationType` it states, which that same read must report.
    authentication_type: &'static str,
    /// The data source the template declares, as `(name, type)`, or `None` for a row that
    /// declares none.
    data_source: Option<(&'static str, &'static str)>,
    /// The resolver it declares, as `(type name, field name, data source name)`.
    resolver: Option<(&'static str, &'static str, &'static str)>,
    /// The pipeline function it declares, as `(name, data source name)`.
    function: Option<(&'static str, &'static str)>,
    /// Whether it declares an `AWS::AppSync::ApiKey`, whose key the stack publishes.
    api_key: bool,
    /// Whether it declares the Cognito user pool the API authenticates against, whose id the
    /// API's `UserPoolConfig` names with a `Ref` and the stack publishes.
    user_pool: bool,
    /// The capabilities the row's `CreateStack` acknowledges: a template declaring an IAM
    /// resource is refused without `CAPABILITY_IAM` ("Requires capabilities"), which is the
    /// client's acknowledgement rather than anything about the AppSync estate.
    capabilities: &'static [&'static str],
}

const ROWS: &[Row] = &[
    Row {
        case: "an API-key API with a schema and a NONE data source, in YAML",
        region: "us-east-1",
        stack: "appsync-minimal",
        template: concat!(
            "Resources:\n",
            "  Api:\n",
            "    Type: AWS::AppSync::GraphQLApi\n",
            "    Properties:\n",
            "      Name: notes-api\n",
            "      AuthenticationType: API_KEY\n",
            "      XrayEnabled: true\n",
            "      QueryDepthLimit: 4\n",
            "  Schema:\n",
            "    Type: AWS::AppSync::GraphQLSchema\n",
            "    Properties:\n",
            "      ApiId: !GetAtt Api.ApiId\n",
            "      Definition: \"type Note { id: ID!, body: String } type Mutation { addNote(body: String!): Note } type Query { note(id: ID!): Note } schema { query: Query, mutation: Mutation }\"\n",
            "  Local:\n",
            "    Type: AWS::AppSync::DataSource\n",
            "    Properties:\n",
            "      ApiId: !GetAtt Api.ApiId\n",
            "      Name: LocalSource\n",
            "      Type: NONE\n",
            "Outputs:\n",
            "  ApiUrl:\n",
            "    Value: !GetAtt Api.GraphQLUrl\n",
            "  RealtimeUrl:\n",
            "    Value: !GetAtt Api.RealtimeUrl\n",
            "  ApiRef:\n",
            "    Value: !Ref Api\n",
            "  ApiIdOut:\n",
            "    Value: !GetAtt Api.ApiId\n",
        ),
        api_name: "notes-api",
        authentication_type: "API_KEY",
        data_source: Some(("LocalSource", "NONE")),
        resolver: None,
        function: None,
        api_key: false,
        user_pool: false,
        capabilities: &[],
    },
    Row {
        case: "a Cognito-authenticated API over a DynamoDB table, with a resolver, in JSON",
        region: "us-west-2",
        stack: "appsync-cognito-dynamodb",
        template: concat!(
            r#"{"Resources":{"#,
            r#""Notes":{"Type":"AWS::DynamoDB::Table","Properties":{"#,
            r#""BillingMode":"PAY_PER_REQUEST","#,
            r#""KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"#,
            r#""AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}]}},"#,
            r#""Role":{"Type":"AWS::IAM::Role","Properties":{"#,
            r#""AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{"#,
            r#""Effect":"Allow","Principal":{"Service":"appsync.amazonaws.com"},"#,
            r#""Action":"sts:AssumeRole"}]}}},"#,
            r#""Pool":{"Type":"AWS::Cognito::UserPool","Properties":{"UserPoolName":"notes-pool"}},"#,
            r#""Client":{"Type":"AWS::Cognito::UserPoolClient","Properties":{"#,
            r#""UserPoolId":{"Ref":"Pool"},"ClientName":"notes-client","#,
            r#""ExplicitAuthFlows":["ALLOW_USER_PASSWORD_AUTH","ALLOW_REFRESH_TOKEN_AUTH"]}},"#,
            r#""Api":{"Type":"AWS::AppSync::GraphQLApi","Properties":{"#,
            r#""Name":"notes-cognito-api","AuthenticationType":"AMAZON_COGNITO_USER_POOLS","#,
            r#""UserPoolConfig":{"UserPoolId":{"Ref":"Pool"},"AwsRegion":"us-west-2","#,
            r#""DefaultAction":"DENY"}}},"#,
            r#""Schema":{"Type":"AWS::AppSync::GraphQLSchema","Properties":{"#,
            r#""ApiId":{"Fn::GetAtt":["Api","ApiId"]},"#,
            r#""Definition":"type Note { id: ID!, body: String } type Mutation { addNote(body: String!): Note } type Query { note(id: ID!): Note } schema { query: Query, mutation: Mutation }"}},"#,
            r#""Table":{"Type":"AWS::AppSync::DataSource","Properties":{"#,
            r#""ApiId":{"Fn::GetAtt":["Api","ApiId"]},"Name":"NotesTable","#,
            r#""Type":"AMAZON_DYNAMODB","ServiceRoleArn":{"Fn::GetAtt":["Role","Arn"]},"#,
            r#""DynamoDBConfig":{"TableName":{"Ref":"Notes"},"AwsRegion":"us-west-2"}}},"#,
            r#""AddNote":{"Type":"AWS::AppSync::Resolver","DependsOn":["Schema","Table"],"#,
            r#""Properties":{"ApiId":{"Fn::GetAtt":["Api","ApiId"]},"#,
            r#""TypeName":"Mutation","FieldName":"addNote","#,
            r#""DataSourceName":{"Fn::GetAtt":["Table","Name"]},"#,
            r#""RequestMappingTemplate":"{\"version\":\"2017-02-28\",\"operation\":\"PutItem\"}","#,
            r#""ResponseMappingTemplate":"$util.toJson($ctx.result)"}}},"#,
            r#""Outputs":{"#,
            r#""ApiUrl":{"Value":{"Fn::GetAtt":["Api","GraphQLUrl"]}},"#,
            r#""RealtimeUrl":{"Value":{"Fn::GetAtt":["Api","RealtimeUrl"]}},"#,
            r#""ApiRef":{"Value":{"Ref":"Api"}},"#,
            r#""ApiIdOut":{"Value":{"Fn::Sub":["${Id}",{"Id":{"Fn::GetAtt":["Api","ApiId"]}}]}},"#,
            r#""UserPoolId":{"Value":{"Ref":"Pool"}},"#,
            r#""UserPoolClientId":{"Value":{"Ref":"Client"}}}}"#,
        ),
        api_name: "notes-cognito-api",
        authentication_type: "AMAZON_COGNITO_USER_POOLS",
        data_source: Some(("NotesTable", "AMAZON_DYNAMODB")),
        resolver: Some(("Mutation", "addNote", "NotesTable")),
        function: None,
        api_key: false,
        user_pool: true,
        capabilities: &["CAPABILITY_IAM"],
    },
    Row {
        case: "an API with an HTTP data source, a pipeline function and an API key, in JSON",
        region: "eu-west-1",
        stack: "appsync-pipeline",
        template: concat!(
            r#"{"Resources":{"#,
            r#""Api":{"Type":"AWS::AppSync::GraphQLApi","Properties":{"#,
            r#""Name":"pipeline-api","AuthenticationType":"API_KEY","#,
            r#""Tags":[{"Key":"team","Value":"notes"}]}},"#,
            r#""Schema":{"Type":"AWS::AppSync::GraphQLSchema","Properties":{"#,
            r#""ApiId":{"Fn::GetAtt":["Api","ApiId"]},"#,
            r#""Definition":"type Note { id: ID!, body: String } type Mutation { addNote(body: String!): Note } type Query { note(id: ID!): Note } schema { query: Query, mutation: Mutation }"}},"#,
            r#""Remote":{"Type":"AWS::AppSync::DataSource","Properties":{"#,
            r#""ApiId":{"Fn::GetAtt":["Api","ApiId"]},"Name":"RemoteSource","Type":"HTTP","#,
            r#""HttpConfig":{"Endpoint":"https://notes.example.com"}}},"#,
            r#""Enrich":{"Type":"AWS::AppSync::FunctionConfiguration","DependsOn":["Schema","Remote"],"#,
            r#""Properties":{"ApiId":{"Fn::GetAtt":["Api","ApiId"]},"Name":"Enrich","#,
            r#""DataSourceName":{"Fn::GetAtt":["Remote","Name"]},"FunctionVersion":"2018-05-29","#,
            r#""RequestMappingTemplate":"{\"version\":\"2017-02-28\",\"operation\":\"PutItem\"}","#,
            r#""ResponseMappingTemplate":"$util.toJson($ctx.result)"}},"#,
            r#""Key":{"Type":"AWS::AppSync::ApiKey","Properties":{"#,
            r#""ApiId":{"Fn::GetAtt":["Api","ApiId"]},"Description":"the suite's key"}}},"#,
            r#""Outputs":{"#,
            r#""ApiUrl":{"Value":{"Fn::GetAtt":["Api","GraphQLUrl"]}},"#,
            r#""RealtimeUrl":{"Value":{"Fn::GetAtt":["Api","RealtimeUrl"]}},"#,
            r#""ApiRef":{"Value":{"Ref":"Api"}},"#,
            r#""ApiIdOut":{"Value":{"Fn::GetAtt":["Api","ApiId"]}},"#,
            r#""ApiKeyOut":{"Value":{"Fn::GetAtt":["Key","ApiKey"]}}}}"#,
        ),
        api_name: "pipeline-api",
        authentication_type: "API_KEY",
        data_source: Some(("RemoteSource", "HTTP")),
        resolver: None,
        function: Some(("Enrich", "RemoteSource")),
        api_key: true,
        user_pool: false,
        capabilities: &[],
    },
];

/// Every row: the stack reaches `CREATE_COMPLETE`, the values it publishes for its AppSync
/// resources are the ones AppSync answered, and every resource the template declared is read
/// back through that service's own reads.
#[tokio::test]
async fn a_stack_provisions_the_appsync_estate_its_template_declares() {
    let router = build_router();

    for row in ROWS {
        let case = row.case;
        let region = row.region;
        // The `Capabilities.member.<n>` the row acknowledges, beside the template itself.
        let acknowledged: Vec<(String, &str)> = row
            .capabilities
            .iter()
            .enumerate()
            .map(|(position, capability)| {
                (
                    format!("Capabilities.member.{}", position + 1),
                    *capability,
                )
            })
            .collect();
        let mut members: Vec<(&str, &str)> =
            vec![("StackName", row.stack), ("TemplateBody", row.template)];
        for (name, capability) in &acknowledged {
            members.push((name.as_str(), capability));
        }
        let (status, body) = cloudformation(&router, region, "CreateStack", &members).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from CreateStack, got {status} with body {body}"
        );

        let described = wait_for_stack_status(&router, region, row.stack, "CREATE_COMPLETE").await;
        let outputs = outputs_of(&described);

        // What AppSync itself reports for the API the stack created, addressed by the id the
        // stack published for it.
        let api_id = output(&outputs, "ApiIdOut", case);
        let (status, read) = appsync(&router, region, "GET", &format!("/v1/apis/{api_id}")).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetGraphqlApi on the id the stack published \
             ({api_id:?}), got {status} with body {read}"
        );
        let api = read.get("graphqlApi").cloned().unwrap_or(Value::Null);
        assert_eq!(
            api.get("name").and_then(Value::as_str),
            Some(row.api_name),
            "case {case:?}: expected the API to report the declared name, got {api}"
        );
        assert_eq!(
            api.get("authenticationType").and_then(Value::as_str),
            Some(row.authentication_type),
            "case {case:?}: expected the declared authentication type, got {api}"
        );
        assert_eq!(
            api.get("apiId").and_then(Value::as_str),
            Some(api_id.as_str()),
            "case {case:?}: expected the API to answer to the published id, got {api}"
        );

        // `Ref` returns the API's ARN, and each endpoint output is the address AppSync serves
        // that endpoint at — never a value CloudFormation invented.
        assert_eq!(
            output(&outputs, "ApiRef", case),
            api.get("arn").and_then(Value::as_str).unwrap_or_default(),
            "case {case:?}: expected the Ref output to be the ARN AppSync built, got {api}"
        );
        for (key, endpoint) in [("ApiUrl", "GRAPHQL"), ("RealtimeUrl", "REALTIME")] {
            let published = output(&outputs, key, case);
            let served = api
                .get("uris")
                .and_then(|uris| uris.get(endpoint))
                .and_then(Value::as_str)
                .unwrap_or_default();
            assert_eq!(
                published, served,
                "case {case:?}: expected output {key:?} to be the {endpoint} endpoint AppSync \
                 serves ({served:?}), got {published:?}"
            );
            assert!(
                !published.is_empty() && published.contains("/graphql"),
                "case {case:?}: expected output {key:?} to be an endpoint a client can dial, got \
                 {published:?}"
            );
        }

        // The resource records name the same resources: the API's physical id is the ARN its
        // own create answered.
        let (status, resources) = cloudformation(
            &router,
            region,
            "DescribeStackResources",
            &[("StackName", row.stack)],
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from DescribeStackResources, got {status} with body \
             {resources}"
        );
        let physical = physical_ids_of(&resources);
        assert_eq!(
            physical.get("Api").map(String::as_str),
            api.get("arn").and_then(Value::as_str),
            "case {case:?}: expected the API's physical id to be the ARN AppSync built, got \
             {physical:?}"
        );

        // The schema the template declared was really installed: AppSync reports the creation
        // it started as finished.
        let (status, schema) = appsync(
            &router,
            region,
            "GET",
            &format!("/v1/apis/{api_id}/schemacreation"),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetSchemaCreationStatus, got {status} with body \
             {schema}"
        );
        assert_eq!(
            schema.get("status").and_then(Value::as_str),
            Some("SUCCESS"),
            "case {case:?}: expected the schema creation to have succeeded, got {schema}"
        );

        // ...and so was each child the row declares.
        if let Some((name, kind)) = row.data_source {
            let (status, read) = appsync(
                &router,
                region,
                "GET",
                &format!("/v1/apis/{api_id}/datasources/{name}"),
            )
            .await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected HTTP 200 from GetDataSource {name:?}, got {status} with \
                 body {read}"
            );
            let data_source = read.get("dataSource").cloned().unwrap_or(Value::Null);
            assert_eq!(
                data_source.get("type").and_then(Value::as_str),
                Some(kind),
                "case {case:?}: expected the data source to report the declared type, got \
                 {data_source}"
            );
            assert_eq!(
                data_source.get("name").and_then(Value::as_str),
                Some(name),
                "case {case:?}: expected the data source to report the declared name, got \
                 {data_source}"
            );
            // A DynamoDB data source names the table the template declared and the role it
            // assumes, both of which reached AppSync as values other resources of the stack
            // answered.
            if kind == "AMAZON_DYNAMODB" {
                let table = data_source
                    .get("dynamodbConfig")
                    .and_then(|config| config.get("tableName"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                assert_eq!(
                    physical.get("Notes").map(String::as_str),
                    Some(table.as_str()),
                    "case {case:?}: expected the data source's table to be the one the stack \
                     created, got {data_source}"
                );
                let role_name = physical
                    .get("Role")
                    .cloned()
                    .unwrap_or_else(|| panic!("case {case:?}: no Role resource in {physical:?}"));
                let role = data_source
                    .get("serviceRoleArn")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                assert!(
                    role.ends_with(&format!(":role/{role_name}")),
                    "case {case:?}: expected the data source to assume the role the stack created \
                     ({role_name:?}), got {data_source}"
                );
            }
        }
        if let Some((type_name, field_name, data_source_name)) = row.resolver {
            let (status, read) = appsync(
                &router,
                region,
                "GET",
                &format!("/v1/apis/{api_id}/types/{type_name}/resolvers/{field_name}"),
            )
            .await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected HTTP 200 from GetResolver {field_name:?}, got {status} \
                 with body {read}"
            );
            let resolver = read.get("resolver").cloned().unwrap_or(Value::Null);
            assert_eq!(
                resolver.get("dataSourceName").and_then(Value::as_str),
                Some(data_source_name),
                "case {case:?}: expected the resolver to run against the declared data source, \
                 got {resolver}"
            );
            assert_eq!(
                resolver.get("requestMappingTemplate").and_then(Value::as_str),
                Some(REQUEST_TEMPLATE),
                "case {case:?}: expected the declared request mapping template, got {resolver}"
            );
            assert_eq!(
                resolver
                    .get("responseMappingTemplate")
                    .and_then(Value::as_str),
                Some(RESPONSE_TEMPLATE),
                "case {case:?}: expected the declared response mapping template, got {resolver}"
            );
        }
        if let Some((name, data_source_name)) = row.function {
            // A function is addressed by the id AppSync minted, which the stack recorded as
            // the resource's `FunctionId` attribute and publishes as its physical id's ARN.
            let (status, listed) =
                appsync(&router, region, "GET", &format!("/v1/apis/{api_id}/functions")).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected HTTP 200 from ListFunctions, got {status} with body \
                 {listed}"
            );
            let function = listed
                .get("functions")
                .and_then(Value::as_array)
                .and_then(|functions| {
                    functions
                        .iter()
                        .find(|function| function.get("name").and_then(Value::as_str) == Some(name))
                })
                .cloned()
                .unwrap_or(Value::Null);
            assert_eq!(
                function.get("dataSourceName").and_then(Value::as_str),
                Some(data_source_name),
                "case {case:?}: expected the function to run against the declared data source, \
                 got {listed}"
            );
            assert_eq!(
                physical.get("Enrich").map(String::as_str),
                function.get("functionArn").and_then(Value::as_str),
                "case {case:?}: expected the function's physical id to be the ARN AppSync built, \
                 got {listed}"
            );
        }
        if row.api_key {
            // The key the stack published is one AppSync holds for the API.
            let published = output(&outputs, "ApiKeyOut", case);
            let (status, listed) =
                appsync(&router, region, "GET", &format!("/v1/apis/{api_id}/apikeys")).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected HTTP 200 from ListApiKeys, got {status} with body {listed}"
            );
            let held: Vec<String> = listed
                .get("apiKeys")
                .and_then(Value::as_array)
                .map(|keys| {
                    keys.iter()
                        .filter_map(|key| key.get("id").and_then(Value::as_str))
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            assert!(
                held.contains(&published),
                "case {case:?}: expected the published key {published:?} to be one AppSync holds, \
                 got {held:?}"
            );
        }
        if row.user_pool {
            // The pool the API authenticates against is the one the same template declared,
            // which Amazon Cognito holds under the id the stack published.
            let pool = output(&outputs, "UserPoolId", case);
            assert_eq!(
                api.get("userPoolConfig")
                    .and_then(|config| config.get("userPoolId"))
                    .and_then(Value::as_str),
                Some(pool.as_str()),
                "case {case:?}: expected the API to name the pool the stack created, got {api}"
            );
            assert_eq!(
                physical.get("Pool").map(String::as_str),
                Some(pool.as_str()),
                "case {case:?}: expected the pool's physical id to be the published id, got \
                 {physical:?}"
            );
            let client = output(&outputs, "UserPoolClientId", case);
            assert_eq!(
                physical.get("Client").map(String::as_str),
                Some(client.as_str()),
                "case {case:?}: expected the app client's physical id to be the published id, got \
                 {physical:?}"
            );
        }

        // Deleting the stack deletes the API AppSync holds for it, and with it everything the
        // API owned.
        let (status, body) =
            cloudformation(&router, region, "DeleteStack", &[("StackName", row.stack)]).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from DeleteStack, got {status} with body {body}"
        );
        let mut gone = Value::Null;
        let mut answered = 0;
        for _ in 0..POLLS {
            let (status, read) =
                appsync(&router, region, "GET", &format!("/v1/apis/{api_id}")).await;
            answered = status;
            gone = read;
            if status == 404 {
                break;
            }
            // A reporting call is what advances a deletion the stack still owes, so the wait
            // looks at the stack again rather than only sleeping.
            let _ = cloudformation(&router, region, "DescribeStacks", &[("StackName", row.stack)])
                .await;
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        assert_eq!(
            answered, 404,
            "case {case:?}: expected HTTP 404 from GetGraphqlApi once the stack deleted the API, \
             got {answered} with body {gone}"
        );
    }
}

/// A declaration this emulator cannot carry out is REFUSED rather than reported as created:
/// the schema document of an `AWS::AppSync::GraphQLSchema` held in Amazon S3 is a document
/// nothing here fetches, so the stack fails naming that property instead of publishing an API
/// serving a schema nobody installed.
#[tokio::test]
async fn a_schema_this_emulator_cannot_fetch_fails_the_stack() {
    let router = build_router();
    let region = "ap-northeast-1";
    let stack = "appsync-unfetchable-schema";
    let case = "a schema definition held in Amazon S3";
    let template = concat!(
        r#"{"Resources":{"#,
        r#""Api":{"Type":"AWS::AppSync::GraphQLApi","Properties":{"#,
        r#""Name":"unfetchable","AuthenticationType":"API_KEY"}},"#,
        r#""Schema":{"Type":"AWS::AppSync::GraphQLSchema","Properties":{"#,
        r#""ApiId":{"Fn::GetAtt":["Api","ApiId"]},"#,
        r#""DefinitionS3Location":"s3://a-bucket/schema.graphql"}}}}"#,
    );
    let (status, body) = cloudformation(
        &router,
        region,
        "CreateStack",
        &[("StackName", stack), ("TemplateBody", template)],
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from CreateStack, got {status} with body {body}"
    );

    // The stack's own creation fails, and the event for the schema resource names the property
    // the refusal was about.
    let mut reason = String::new();
    for _ in 0..POLLS {
        let (status, described) =
            cloudformation(&router, region, "DescribeStacks", &[("StackName", stack)]).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from DescribeStacks, got {status} with body \
             {described}"
        );
        let reported = opt_element(&described, "StackStatus").unwrap_or_default();
        if reported.ends_with("_FAILED") || reported.starts_with("ROLLBACK") {
            reason = described;
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert!(
        !reason.is_empty(),
        "case {case:?}: expected the stack's creation to fail, and it never did"
    );
    let (status, events) = cloudformation(
        &router,
        region,
        "DescribeStackEvents",
        &[("StackName", stack)],
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from DescribeStackEvents, got {status} with body {events}"
    );
    assert!(
        events.contains("DefinitionS3Location"),
        "case {case:?}: expected an event naming the property the refusal was about, got {events}"
    );
}
