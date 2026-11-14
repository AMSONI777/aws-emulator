// SPDX-License-Identifier: CC0-1.0

//! What a deployed method whose `AWS` integration names an AMAZON DYNAMODB WRITE performs: the
//! item its REQUEST TEMPLATE renders, stored by the service that owns the table and observable
//! there afterwards.
//!
//! RULE: an `AWS` integration "integrat[es] the API method request with an AWS service action"
//! (`IntegrationType`) named by its `uri`
//! (`arn:aws:apigateway:{region}:{subdomain}:action/{service_api}`, `Integration$uri`), and the
//! document that action is called with is the `requestTemplates` entry keying the call RENDERED
//! against that call ("a map of Velocity templates that are applied on the request payload",
//! `Integration$requestTemplates`) — so a deployed stage SERVES such a method by making that
//! call against the service that owns the resource, and the method response is what that
//! service answered, mapped by the integration response whose `selectionPattern` matches the
//! status it answered with. Nothing of the answer is invented: what the owning service stored
//! is what it reports afterwards, and a call that service refuses stores nothing and is
//! answered with the refusal the service itself gave.
//!
//! The rows differ along what the rule generalises over — which reference form the template
//! renders the input document from (`$input.path` of the sent body's members, `$input.json` of
//! a whole node of it, `$input.body` as the document itself, `$input.params` of a parameter
//! outside the body), which attribute types the rendered item carries (`S`, `N`, `BOOL`), and
//! whether the call is one the owning service serves or one it refuses. Every row is observed
//! twice: through that service's OWN `GetItem`, and through a second method of the same api
//! whose integration names that read — so a write the stage reports is a write the table holds.

use bytes::Bytes;
use serde_json::{json, Value};

use crate::dynamodb_service_integration::{dynamodb, given_role, given_table};
use crate::execute_api_data_plane::{
    deploy, integration_response, method_response, put_integration, put_method,
};
use crate::rest_api_lifecycle::{
    create_api, create_resource, gateway_with_dynamodb_and_iam, string_member, Gateway,
};
use crate::stage_edge_admission::invoke_bytes;

/// The region every request of this suite is addressed in.
const REGION: &str = "us-east-1";

/// The stage the api is deployed to.
const STAGE: &str = "live";

/// The table the integrations write to and read back. The row documents below spell it too —
/// a mapping template is stored TEXT, so each row names the table it addresses
/// ([`Row::table`]) and the test checks the two agree.
const TABLE: &str = "ledger";

/// A table no row creates, which is what the refused row's document names; see [`TABLE`].
const ABSENT_TABLE: &str = "no-such-ledger";

/// The role the integrations name as their `credentials`, which API Gateway may assume.
const ROLE: &str = "apigateway-ledger";

/// The resource whose method reads one item back through the api.
const READ_PATH: &str = "read";

/// The body a served write earns its caller: the integration response's own template, so a row
/// that reaches this body reached the success branch of the mapping.
const WRITE_ANSWER: &str = r#"{"stored":true}"#;

/// One write method of the api: the template that renders the `PutItem` document, what the
/// caller sends it, and what the row expects of the api and of the table afterwards.
struct Row {
    case: &'static str,
    path_part: &'static str,
    /// The `requestTemplates` entry that renders the action's input document.
    request_template: &'static str,
    /// The body the invoke sends.
    sent: &'static str,
    /// The query string the invoke carries, empty for a row that carries none.
    query: &'static str,
    /// The headers the invoke carries.
    headers: &'static [(&'static str, &'static str)],
    /// The table the row's document addresses, which either that template or the sent payload
    /// spells; see [`TABLE`].
    table: &'static str,
    /// The key the row addresses, which both read-backs look up.
    item_id: &'static str,
    /// The status the caller is answered with.
    expected_status: u16,
    /// A fragment the answered body carries.
    expected_body: &'static str,
    /// The item the table must hold under `item_id` afterwards, as JSON; empty for a row that
    /// must store nothing at all.
    expected_item: &'static str,
    /// What the api's own read method answers for `item_id`, rendered by its response template
    /// off what the table service reported.
    expected_read_back: &'static str,
}

const ROWS: &[Row] = &[
    Row {
        case: "attributes rendered from the members of the sent body",
        path_part: "write-path",
        request_template: r#"{"TableName":"ledger","Item":{"id":{"S":"$input.path('$.id')"},"amount":{"N":"$input.path('$.amount')"}}}"#,
        sent: r#"{"id":"path-row","amount":42}"#,
        headers: &[("content-type", "application/json")],
        query: "",
        table: TABLE,
        item_id: "path-row",
        expected_status: 200,
        expected_body: WRITE_ANSWER,
        expected_item: r#"{"id":{"S":"path-row"},"amount":{"N":"42"}}"#,
        expected_read_back: r#"{"id":"path-row","amount":"42"}"#,
    },
    Row {
        case: "the whole item taken as the JSON node the request sent",
        path_part: "write-json",
        request_template: r#"{"TableName":"ledger","Item":$input.json('$.item')}"#,
        sent: r#"{"item":{"id":{"S":"json-row"},"amount":{"N":"7"},"active":{"BOOL":true}}}"#,
        headers: &[("content-type", "application/json")],
        query: "",
        table: TABLE,
        item_id: "json-row",
        expected_status: 200,
        expected_body: WRITE_ANSWER,
        expected_item: r#"{"id":{"S":"json-row"},"amount":{"N":"7"},"active":{"BOOL":true}}"#,
        expected_read_back: r#"{"id":"json-row","amount":"7"}"#,
    },
    Row {
        case: "the sent payload itself as the whole input document",
        path_part: "write-body",
        request_template: r#"$input.body"#,
        sent: r#"{"TableName":"ledger","Item":{"id":{"S":"body-row"},"amount":{"N":"11"}}}"#,
        headers: &[("content-type", "application/json")],
        query: "",
        table: TABLE,
        item_id: "body-row",
        expected_status: 200,
        expected_body: WRITE_ANSWER,
        expected_item: r#"{"id":{"S":"body-row"},"amount":{"N":"11"}}"#,
        expected_read_back: r#"{"id":"body-row","amount":"11"}"#,
    },
    Row {
        case: "attributes rendered from parameters outside the body, which the row sends none of",
        path_part: "write-params",
        request_template: r#"{"TableName":"ledger","Item":{"id":{"S":"$input.params('id')"},"tier":{"S":"$input.params('x-tier')"}}}"#,
        sent: "",
        headers: &[("x-tier", "gold")],
        query: "?id=params-row",
        table: TABLE,
        item_id: "params-row",
        expected_status: 200,
        expected_body: WRITE_ANSWER,
        expected_item: r#"{"id":{"S":"params-row"},"tier":{"S":"gold"}}"#,
        // The read's own template names an attribute this item has none of, and a path that
        // selects nothing renders nothing.
        expected_read_back: r#"{"id":"params-row","amount":""}"#,
    },
    Row {
        case: "a write the owning service itself refuses, which stores nothing",
        path_part: "write-refused",
        request_template: r#"{"TableName":"no-such-ledger","Item":{"id":{"S":"refused-row"},"amount":{"N":"3"}}}"#,
        sent: r#"{"id":"refused-row"}"#,
        headers: &[("content-type", "application/json")],
        query: "",
        table: ABSENT_TABLE,
        item_id: "refused-row",
        expected_status: 400,
        // The class that service names a call against a table it does not hold by, carried
        // through to the caller by the 4xx branch of the mapping.
        expected_body: "ResourceNotFoundException",
        expected_item: "",
        expected_read_back: r#"{"id":"","amount":""}"#,
    },
];

/// Stand one row's write method up: the method, its `AWS` integration naming `PutItem`, and the
/// two integration responses that map what the service answers — the success branch, which
/// renders this api's own document, and the 4xx branch, which carries the service's refusal.
async fn given_write_method(gateway: &Gateway, api: &str, root: &str, row: &Row, role: &str) {
    let resource = string_member(
        &create_resource(gateway, api, root, row.path_part).await,
        "id",
        row.case,
    );
    put_method(
        gateway,
        api,
        &resource,
        "POST",
        json!({"authorizationType": "NONE"}),
    )
    .await;
    put_integration(
        gateway,
        api,
        &resource,
        "POST",
        json!({
            "type": "AWS",
            "httpMethod": "POST",
            "uri": format!("arn:aws:apigateway:{REGION}:dynamodb:action/PutItem"),
            "credentials": role,
            "requestTemplates": {"application/json": row.request_template},
        }),
    )
    .await;
    for (status, pattern, template) in [
        ("200", None, WRITE_ANSWER),
        ("400", Some(r"4\d{2}"), r#"$input.body"#),
    ] {
        method_response(gateway, api, &resource, "POST", status, json!({})).await;
        let mut response = json!({"responseTemplates": {"application/json": template}});
        if let Some(pattern) = pattern {
            response["selectionPattern"] = json!(pattern);
        }
        integration_response(gateway, api, &resource, "POST", status, response).await;
    }
}

/// Stand the api's READ method up: one `GET` whose `AWS` integration names `GetItem` for the
/// key the request's `id` parameter names, and whose response template publishes what the table
/// service reported.
async fn given_read_method(gateway: &Gateway, api: &str, root: &str, role: &str) {
    let resource = string_member(
        &create_resource(gateway, api, root, READ_PATH).await,
        "id",
        "the read method",
    );
    put_method(
        gateway,
        api,
        &resource,
        "GET",
        json!({"authorizationType": "NONE"}),
    )
    .await;
    put_integration(
        gateway,
        api,
        &resource,
        "GET",
        json!({
            "type": "AWS",
            "httpMethod": "POST",
            "uri": format!("arn:aws:apigateway:{REGION}:dynamodb:action/GetItem"),
            "credentials": role,
            "requestTemplates": {
                "application/json":
                    format!(
                        r#"{{"TableName":"{TABLE}","Key":{{"id":{{"S":"$input.params('id')"}}}}}}"#
                    ),
            },
        }),
    )
    .await;
    method_response(gateway, api, &resource, "GET", "200", json!({})).await;
    integration_response(
        gateway,
        api,
        &resource,
        "GET",
        "200",
        json!({"responseTemplates": {
            "application/json":
                r#"{"id":"$input.path('$.Item.id.S')","amount":"$input.path('$.Item.amount.N')"}"#,
        }}),
    )
    .await;
}

#[tokio::test]
async fn a_template_driven_table_write_is_performed_by_the_service_that_owns_the_table() {
    let gateway = gateway_with_dynamodb_and_iam();
    given_table(&gateway, TABLE).await;

    let role = given_role(
        &gateway,
        ROLE,
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                // Both the table the rows write and the one the refused row names, so what
                // that row is answered is the SERVICE's refusal rather than the role's.
                "Resource": [
                    format!("arn:aws:dynamodb:{REGION}:000000000000:table/{TABLE}"),
                    format!("arn:aws:dynamodb:{REGION}:000000000000:table/{ABSENT_TABLE}"),
                ],
            }],
        }),
    )
    .await;

    let (api, root) = create_api(&gateway, "dynamodb-template-writes").await;
    for row in ROWS {
        given_write_method(&gateway, &api, &root, row, &role).await;
    }
    given_read_method(&gateway, &api, &root, &role).await;
    deploy(&gateway, &api, STAGE).await;

    for row in ROWS {
        let case = row.case;
        // The document this row sends the action is the stored template, or — for the row
        // whose template is the payload itself — what the caller sent; either way it is the
        // table named above that the row addresses.
        assert!(
            row.request_template.contains(row.table) || row.sent.contains(row.table),
            "case {case:?}: expected the row's document to address {:?}, got {:?} over {:?}",
            row.table,
            row.request_template,
            row.sent
        );

        let answered = invoke_bytes(
            &gateway,
            &api,
            "POST",
            &format!("/{STAGE}/{}{}", row.path_part, row.query),
            row.headers,
            Bytes::from(row.sent.to_string()),
        )
        .await;
        let body = answered.text();
        assert_eq!(
            answered.status, row.expected_status,
            "case {case:?}: expected HTTP {}, got {} with {body:?}",
            row.expected_status, answered.status
        );
        assert!(
            body.contains(row.expected_body),
            "case {case:?}: expected a body carrying {:?}, got {body:?}",
            row.expected_body
        );

        // The write reached the TABLE: the owning service's own read reports exactly the item
        // the template rendered, and reports none at all for the call it refused.
        let (status, read) = dynamodb(
            &gateway,
            "GetItem",
            json!({"TableName": TABLE, "Key": {"id": {"S": row.item_id}}}),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected the owning service's GetItem to answer 200, got {status} \
             with {read:?}"
        );
        let expected_item: Option<Value> = match row.expected_item.is_empty() {
            true => None,
            false => Some(
                serde_json::from_str(row.expected_item).expect("the row's item is a JSON object"),
            ),
        };
        assert_eq!(
            read.get("Item"),
            expected_item.as_ref(),
            "case {case:?}: expected the table to hold {:?} under {:?}, got {read:?}",
            row.expected_item,
            row.item_id
        );

        // And the same item read back through the api's OWN read method, whose response
        // template publishes what that service reported.
        let published = invoke_bytes(
            &gateway,
            &api,
            "GET",
            &format!("/{STAGE}/{READ_PATH}?id={}", row.item_id),
            &[],
            Bytes::new(),
        )
        .await;
        let document = published.text();
        assert_eq!(
            published.status, 200,
            "case {case:?}: expected the read method to answer 200, got {} with {document:?}",
            published.status
        );
        assert_eq!(
            document, row.expected_read_back,
            "case {case:?}: expected the read method to publish {:?}, got {document:?}",
            row.expected_read_back
        );
    }
}
