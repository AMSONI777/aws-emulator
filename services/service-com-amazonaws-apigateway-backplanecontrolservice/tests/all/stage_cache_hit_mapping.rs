// SPDX-License-Identifier: CC0-1.0

//! What a request answered from a stage's cache cluster READS: the entry holds the
//! INTEGRATION response, and the integration response's own mapping is applied to it for
//! every request the entry answers.
//!
//! THE RULE UNDER TEST: a stage's response cache holds what the integration ANSWERED — its
//! status, media type and payload — and the integration response that maps that answer is
//! applied afresh to each request served from the entry, so every value the mapping derives
//! from the request being served (its `$context`, its own parameters) renders THAT request's
//! values, while the payload the integration answered is served unchanged until the entry
//! stops being one the cluster holds. The observable invariant a client can check without
//! knowing anything about the store: the request id a response's body renders is the id of
//! the request that response answers, which is the id its own `x-amzn-RequestId` header
//! carries — on a cache hit exactly as on a miss.
//!
//! Every case drives the real wire path — an HTTP request through the multi-service router on
//! the api's own `{rest-api-id}.execute-api.{region}.amazonaws.com` host — so what is
//! asserted is what a client of the published invoke URL sees.
//!
//! The rows span what the rule generalises over:
//!
//! * the integration whose answer is held: a `MOCK`, whose answer is its own rendered
//!   integration request, and an `AWS` integration, whose answer is what the AWS service it
//!   names answered — the two ways the mapping selects the integration response that maps an
//!   answer (the status a `MOCK`'s rendering names, and `selectionPattern` against the status
//!   a backend answered);
//! * what the mapping derives from the current request: `$context.requestId`, and a request
//!   parameter the integration declares no cache key parameter for — so requests differing in
//!   it are ONE entry, and each still renders its own value;
//! * and what it does NOT re-derive: the payload, which stays the entry's across every hit
//!   although the integration now answers something else, until `FlushStageCache` evicts it.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{json, Value};

use crate::dynamodb_service_integration::{dynamodb, given_role};
use crate::execute_api_data_plane::{
    deploy, integration_response, invoke, method_response, put_integration, put_method, Invoked,
};
use crate::flush_stage_cache::flush_cache;
use crate::rest_api_lifecycle::{
    create_api, gateway_with_dynamodb_and_iam, resource_under, Gateway,
};
use crate::stage_response_cache::settled_cluster;

/// The region the control plane is called in, and the endpoint an integration ARN naming no
/// Region of its own is called at.
const REGION: &str = "us-east-1";

/// The stage every case deploys to.
const STAGE: &str = "cached";

/// The header API Gateway names the request a response answers in; HTTP header names are
/// case-insensitive and the wire carries this one lowercased.
const REQUEST_ID_HEADER: &str = "x-amzn-requestid";

/// How long a poll for a transition the clock owes keeps looking, and how often it looks.
/// Generous: nothing here is timed.
const WAIT: Duration = Duration::from_secs(30);
const LOOK_AGAIN: Duration = Duration::from_millis(25);

/// The `patchOperations` that turn caching on for `method_path` with a TTL long enough that
/// no case can outlive it.
fn caching_on(method_path: &str) -> Value {
    json!([
        {
            "op": "replace",
            "path": format!("{method_path}/caching/enabled"),
            "value": "true"
        },
        {
            "op": "replace",
            "path": format!("{method_path}/caching/ttlInSeconds"),
            "value": "300"
        }
    ])
}

/// `UpdateStage` with `operations`, asserting the modelled 200.
async fn update_stage(gateway: &Gateway, api: &str, case: &str, operations: Value) {
    let updated = gateway
        .call(
            "PATCH",
            &format!("/restapis/{api}/stages/{STAGE}"),
            Some(json!({ "patchOperations": operations })),
        )
        .await;
    assert_eq!(
        updated.status, 200,
        "case {case}: expected 200 from UpdateStage, got {} with {:?}",
        updated.status, updated.body
    );
}

/// `CreateDeployment` of `api` to a [`STAGE`] with a cache cluster, waited out until the
/// cluster is up — "a cache cluster must be enabled on the stage for responses to be cached"
/// (`MethodSetting$cachingEnabled`).
async fn deploy_with_cluster(gateway: &Gateway, api: &str, case: &str) {
    let deployed = gateway
        .call(
            "POST",
            &format!("/restapis/{api}/deployments"),
            Some(json!({
                "stageName": STAGE,
                "cacheClusterEnabled": true,
                "cacheClusterSize": "0.5"
            })),
        )
        .await;
    assert_eq!(
        deployed.status, 201,
        "case {case}: expected 201 from CreateDeployment, got {} with {:?}",
        deployed.status, deployed.body
    );
    settled_cluster(gateway, api, STAGE, case).await;
}

/// The member `member` of a response body read as JSON, named for the case.
fn member(answered: &Invoked, member: &str, case: &str) -> String {
    let parsed: Value = serde_json::from_str(&answered.body)
        .unwrap_or_else(|_| panic!("case {case}: expected a JSON body, got {:?}", answered.body));
    parsed
        .get(member)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            panic!(
                "case {case}: expected a {member} member, got {:?}",
                answered.body
            )
        })
}

/// Assert THE invariant on one answered request: the request id its body renders is the one
/// its own response header carries, so a client correlating the two follows one request.
///
/// Answers that id, so a caller can also check that no two requests rendered the same one.
fn renders_its_own_request_id(answered: &Invoked, case: &str) -> String {
    let rendered = member(answered, "rid", case);
    let reported = answered
        .header(REQUEST_ID_HEADER)
        .unwrap_or_else(|| panic!("case {case}: expected a {REQUEST_ID_HEADER} header"));
    assert_eq!(
        rendered, reported,
        "case {case}: expected the body's rendered request id to be this response's \
         {REQUEST_ID_HEADER}, got {rendered} against {reported}"
    );
    rendered
}

/// The response template every method of this suite carries: one value the mapping derives
/// from the CURRENT request (`$context.requestId`), one it reads off a request parameter, and
/// one it reads off the payload the INTEGRATION answered.
const MOCK_RESPONSE_TEMPLATE: &str = "{\"rid\":\"$context.requestId\",\
     \"q\":\"$input.params('q')\",\"serial\":\"$input.path('$.serial')\"}";

/// The `requestTemplates` of a `MOCK` whose answer carries `serial`: a `MOCK` sends nothing to
/// a backend, so its rendered integration REQUEST is what it answers — the unit the cluster
/// holds — and the `statusCode` that rendering names selects the integration response that
/// maps it.
fn mock_answers(serial: &str) -> Value {
    json!({ "application/json": format!("{{\"statusCode\":200,\"serial\":\"{serial}\"}}") })
}

/// The resource the `MOCK` case invokes.
const MOCK_RESOURCE: &str = "mocked";

/// The serial the `MOCK`'s integration answers while the entry is filled, and the one it
/// answers afterwards — which no request served from the entry may read.
const FILLED_SERIAL: &str = "filled";
const REWRITTEN_SERIAL: &str = "rewritten";

/// One request of the table: the query string it carries, and the value its `q` parameter
/// renders to.
struct Row {
    case: &'static str,
    query: &'static str,
    expected_q: &'static str,
}

/// Rows differ along a request parameter the integration declares NO cache key parameter for,
/// so every row addresses the SAME entry — and each must still read its own value.
const ROWS: &[Row] = &[
    Row {
        case: "a request carrying no q parameter",
        query: "",
        expected_q: "",
    },
    Row {
        case: "a request carrying one q parameter",
        query: "?q=alpha",
        expected_q: "alpha",
    },
    Row {
        case: "a request carrying another q value",
        query: "?q=beta",
        expected_q: "beta",
    },
    Row {
        case: "a request carrying a longer q value",
        query: "?q=a-value-0123456789",
        expected_q: "a-value-0123456789",
    },
];

#[tokio::test]
async fn every_request_a_held_mock_entry_answers_maps_that_entry_for_itself() {
    let gateway = Gateway::new();
    let case = "a cached MOCK method";
    let (api, root) = create_api(&gateway, "cache-hit-mapping-mock").await;
    let resource = resource_under(&gateway, &api, &root, MOCK_RESOURCE).await;
    put_method(
        &gateway,
        &api,
        &resource,
        "GET",
        json!({ "authorizationType": "NONE" }),
    )
    .await;
    put_integration(
        &gateway,
        &api,
        &resource,
        "GET",
        json!({ "type": "MOCK", "requestTemplates": mock_answers(FILLED_SERIAL) }),
    )
    .await;
    method_response(&gateway, &api, &resource, "GET", "200", json!({})).await;
    integration_response(
        &gateway,
        &api,
        &resource,
        "GET",
        "200",
        json!({ "responseTemplates": { "application/json": MOCK_RESPONSE_TEMPLATE } }),
    )
    .await;
    deploy_with_cluster(&gateway, &api, case).await;
    update_stage(
        &gateway,
        &api,
        case,
        caching_on(&format!("/~1{MOCK_RESOURCE}/GET")),
    )
    .await;

    let path = |query: &str| format!("/{STAGE}/{MOCK_RESOURCE}{query}");

    // The first request is a MISS: the integration answers it, and what it answered is what
    // the cluster now holds.
    let filled = invoke(&gateway, &api, "GET", &path("?q=first"), &[]).await;
    assert_eq!(
        filled.status, 200,
        "case {case}: expected 200 from the first invoke, got {} with {:?}",
        filled.status, filled.body
    );
    let mut rendered_ids = BTreeSet::new();
    rendered_ids.insert(renders_its_own_request_id(&filled, case));
    assert_eq!(
        member(&filled, "serial", case),
        FILLED_SERIAL,
        "case {case}: expected the integration's own answer on a miss, got {:?}",
        filled.body
    );

    // What the integration ANSWERS now differs, so a request the cluster answers is visible:
    // it reads the payload the entry holds and not this one.
    let patched = gateway
        .call(
            "PATCH",
            &format!("/restapis/{api}/resources/{resource}/methods/GET/integration"),
            Some(json!({
                "patchOperations": [{
                    "op": "replace",
                    "path": "/requestTemplates/application~1json",
                    "value": mock_answers(REWRITTEN_SERIAL)["application/json"]
                }]
            })),
        )
        .await;
    assert_eq!(
        patched.status, 200,
        "case {case}: expected 200 from UpdateIntegration, got {} with {:?}",
        patched.status, patched.body
    );
    deploy(&gateway, &api, STAGE).await;

    for row in ROWS {
        let case = row.case;
        let answered = invoke(&gateway, &api, "GET", &path(row.query), &[]).await;
        assert_eq!(
            answered.status, 200,
            "case {case}: expected 200, got {} with {:?}",
            answered.status, answered.body
        );
        // The entry is what answered: its payload is the one the first request's integration
        // produced, although the integration now produces another.
        assert_eq!(
            member(&answered, "serial", case),
            FILLED_SERIAL,
            "case {case}: expected the held entry's own payload, got {:?}",
            answered.body
        );
        // And the mapping was applied for THIS request: the id it renders is this response's
        // own, and the parameter it renders is the one this request carried.
        let rendered = renders_its_own_request_id(&answered, case);
        assert!(
            rendered_ids.insert(rendered.clone()),
            "case {case}: expected a request id of its own, but {rendered} was rendered for an \
             earlier request too"
        );
        assert_eq!(
            member(&answered, "q", case),
            row.expected_q,
            "case {case}: expected the q parameter this request carried, got {:?}",
            answered.body
        );
    }

    // Once the entry is gone the integration answers again — and the invariant holds there
    // too, which is what makes it an invariant rather than a property of the hit path.
    let flushed = flush_cache(&gateway, &api, STAGE).await;
    assert_eq!(
        flushed.status, 202,
        "case {case}: expected 202 from FlushStageCache, got {} with {:?}",
        flushed.status, flushed.body
    );
    settled_cluster(&gateway, &api, STAGE, case).await;
    let after = invoke(&gateway, &api, "GET", &path("?q=after"), &[]).await;
    let rendered = renders_its_own_request_id(&after, "the invoke after the flush");
    assert!(
        rendered_ids.insert(rendered.clone()),
        "case the invoke after the flush: expected a request id of its own, got {rendered}"
    );
    assert_eq!(
        member(&after, "serial", "the invoke after the flush"),
        REWRITTEN_SERIAL,
        "case the invoke after the flush: expected the integration's own answer once the \
         entry was evicted, got {:?}",
        after.body
    );
}

/// The table the `AWS` integration reads, the item it reads, and the counts that item carries
/// before and after the out-of-band write.
const TABLE: &str = "readings";
const ITEM_KEY: &str = "sensor-1";
const FILLED_COUNT: i64 = 1;
const WRITTEN_COUNT: i64 = 7;

/// The resource the `AWS` case invokes, and the role its integration is made under.
const AWS_RESOURCE: &str = "readings";
const ROLE: &str = "apigateway-cache-readings";

/// The response template of the `AWS` case: the request id the CURRENT request renders, and
/// the count read off what the table answered.
const AWS_RESPONSE_TEMPLATE: &str =
    "{\"rid\":\"$context.requestId\",\"count\":\"$input.path('$.Item.count.N')\"}";

#[tokio::test]
async fn every_request_a_held_aws_integration_entry_answers_maps_that_entry_for_itself() {
    let gateway = gateway_with_dynamodb_and_iam();
    let case = "a cached AWS integration";

    // The table and the item it holds, created through the owning service's own API.
    let (status, created) = dynamodb(
        &gateway,
        "CreateTable",
        json!({
            "TableName": TABLE,
            "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "setup CreateTable: expected 200, got {status} {created:?}"
    );
    // A table is writable once the owning service has made it ACTIVE, which its own clock
    // owes: polled for the condition rather than waited out for a fixed span.
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let (_, described) = dynamodb(&gateway, "DescribeTable", json!({"TableName": TABLE})).await;
        if described["Table"]["TableStatus"] == json!("ACTIVE") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "setup: expected the table to become ACTIVE, last saw {described:?}"
        );
        tokio::time::sleep(LOOK_AGAIN).await;
    }
    let written = put_count(&gateway, FILLED_COUNT).await;
    assert_eq!(
        written, 200,
        "setup PutItem: expected 200 from the first write, got {written}"
    );

    let role = given_role(
        &gateway,
        ROLE,
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "dynamodb:GetItem",
                "Resource": format!("arn:aws:dynamodb:{REGION}:000000000000:table/{TABLE}"),
            }],
        }),
    )
    .await;

    let (api, root) = create_api(&gateway, "cache-hit-mapping-aws").await;
    let resource = resource_under(&gateway, &api, &root, AWS_RESOURCE).await;
    put_method(
        &gateway,
        &api,
        &resource,
        "GET",
        json!({ "authorizationType": "NONE" }),
    )
    .await;
    put_integration(
        &gateway,
        &api,
        &resource,
        "GET",
        json!({
            "type": "AWS",
            "httpMethod": "POST",
            "uri": format!("arn:aws:apigateway:{REGION}:dynamodb:action/GetItem"),
            "credentials": role,
            "requestTemplates": {
                "application/json": format!(
                    "{{\"TableName\":\"{TABLE}\",\"Key\":{{\"id\":{{\"S\":\"{ITEM_KEY}\"}}}}}}"
                )
            },
        }),
    )
    .await;
    method_response(&gateway, &api, &resource, "GET", "200", json!({})).await;
    integration_response(
        &gateway,
        &api,
        &resource,
        "GET",
        "200",
        json!({ "responseTemplates": { "application/json": AWS_RESPONSE_TEMPLATE } }),
    )
    .await;
    deploy_with_cluster(&gateway, &api, case).await;
    update_stage(
        &gateway,
        &api,
        case,
        caching_on(&format!("/~1{AWS_RESOURCE}/GET")),
    )
    .await;

    let path = format!("/{STAGE}/{AWS_RESOURCE}");
    let filled = invoke(&gateway, &api, "GET", &path, &[]).await;
    assert_eq!(
        filled.status, 200,
        "case {case}: expected 200 from the first invoke, got {} with {:?}",
        filled.status, filled.body
    );
    let mut rendered_ids = BTreeSet::new();
    rendered_ids.insert(renders_its_own_request_id(&filled, case));
    assert_eq!(
        member(&filled, "count", case),
        FILLED_COUNT.to_string(),
        "case {case}: expected the count the table holds on a miss, got {:?}",
        filled.body
    );

    // The TABLE now holds another count, written out of band through the service that owns
    // it: a request the cluster answers must not see it, because the integration is not
    // performed again.
    let written = put_count(&gateway, WRITTEN_COUNT).await;
    assert_eq!(
        written, 200,
        "setup PutItem: expected 200 from the out-of-band write, got {written}"
    );
    let (status, read) = dynamodb(
        &gateway,
        "GetItem",
        json!({"TableName": TABLE, "Key": {"id": {"S": ITEM_KEY}}}),
    )
    .await;
    assert_eq!(
        (status, &read["Item"]["count"]["N"]),
        (200, &json!(WRITTEN_COUNT.to_string())),
        "setup: expected the table to report the count that was written, got {status} {read:?}"
    );

    for round in ["the first request the entry answers", "the second one"] {
        let answered = invoke(&gateway, &api, "GET", &path, &[]).await;
        assert_eq!(
            answered.status, 200,
            "case {round}: expected 200, got {} with {:?}",
            answered.status, answered.body
        );
        // The backend was NOT called again: what the entry holds is what the table answered
        // when it was filled, and the table has moved on since.
        assert_eq!(
            member(&answered, "count", round),
            FILLED_COUNT.to_string(),
            "case {round}: expected the held entry's own payload, got {:?}",
            answered.body
        );
        let rendered = renders_its_own_request_id(&answered, round);
        assert!(
            rendered_ids.insert(rendered.clone()),
            "case {round}: expected a request id of its own, but {rendered} was rendered for \
             an earlier request too"
        );
    }

    // Evicted, the integration is performed again — and reads the count the table now holds.
    let flushed = flush_cache(&gateway, &api, STAGE).await;
    assert_eq!(
        flushed.status, 202,
        "case {case}: expected 202 from FlushStageCache, got {} with {:?}",
        flushed.status, flushed.body
    );
    settled_cluster(&gateway, &api, STAGE, case).await;
    let after = invoke(&gateway, &api, "GET", &path, &[]).await;
    let rendered = renders_its_own_request_id(&after, "the invoke after the flush");
    assert!(
        rendered_ids.insert(rendered.clone()),
        "case the invoke after the flush: expected a request id of its own, got {rendered}"
    );
    assert_eq!(
        member(&after, "count", "the invoke after the flush"),
        WRITTEN_COUNT.to_string(),
        "case the invoke after the flush: expected the count the table holds once the entry \
         was evicted, got {:?}",
        after.body
    );
}

/// Write `count` onto the item the `AWS` integration reads, through the service that owns the
/// table.
async fn put_count(gateway: &Gateway, count: i64) -> u16 {
    let (status, _answered) = dynamodb(
        gateway,
        "PutItem",
        json!({
            "TableName": TABLE,
            "Item": {"id": {"S": ITEM_KEY}, "count": {"N": count.to_string()}},
        }),
    )
    .await;
    status
}
