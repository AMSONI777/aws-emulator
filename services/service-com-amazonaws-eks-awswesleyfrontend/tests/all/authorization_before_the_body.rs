// SPDX-License-Identifier: CC0-1.0

//! WHAT this service answers a request whose body it cannot bind to the operation's input
//! shapes, driven end to end over the real wire path (a restJson1 request through the
//! multi-service router into the mounted service), so what is asserted is what a client
//! holding those credentials sees.
//!
//! THE RULE UNDER TEST: the authorization decision is taken on the request alone, BEFORE
//! its body is bound to the operation's input shapes. A list, map or structure member is
//! read from the JSON array or object the model declares for it and from nothing else, so a
//! body carrying something else where one of those stands leaves everything inside it
//! unread: an operation that names the resource IAM judges it on in that body —
//! `CreateCluster` and `RegisterCluster`, whose `name` carries no `@httpLabel` — reaches
//! the decision with no resource at all. Nothing can allow an action on a resource the
//! request never named, so the call is refused HTTP 403 `AccessDeniedException` naming the
//! caller's principal and the action and nothing else, whoever the caller is and whatever
//! its policies allow. The codec's own diagnostic is never answered as a fault of this API,
//! and the refused call writes nothing.
//!
//! A body the walk CAN enter is untouched by this: a value that was read and then broke a
//! rule this API states earns that parameter's own refusal, a scalar that states nothing of
//! its modelled type is still the 400 that value earns, and a request this API accepts is
//! served.
//!
//! The tables span what the rule generalises over: the operation (both that name their
//! resource in the body), the member whose container the body does not carry (a list given
//! a string, a structure given a string, a list given an object, a map given a list), and
//! the caller (the account's own published credential, which the authorization gate does
//! not bound, and an IAM user whose inline policy allows every action of this service on
//! every resource).
//!
//! The wire harness (`Answer`, `call_as`, `emulator_with_identity`, `error_code`, `query`,
//! `xml_element`) is the shared one in `tests/all/wire.rs`, and the accepted `CreateCluster`
//! body is `cluster_lifecycle`'s.

use serde_json::json;
use smithy_server_runtime::MultiServiceRouter;

use crate::cluster_lifecycle::minimal_request;
use crate::wire::{
    call_as, emulator_with_identity, error_code, query, xml_element, Answer, DEFAULT_ACCESS_KEY_ID,
};

/// The Region every request in this suite is signed for.
const REGION: &str = "us-west-2";

/// The error code and status an authorization refusal carries (`AccessDeniedException`,
/// `@httpError 403`).
const ACCESS_DENIED: &str = "AccessDeniedException";

/// The error this service states a bad parameter with, which `CreateCluster` declares.
const INVALID_PARAMETER: &str = "InvalidParameterException";

/// One request to this service, signed with `access_key_id` in its SigV4 credential scope —
/// which is where this emulator reads which principal a request speaks for.
async fn eks(router: &MultiServiceRouter, access_key_id: &str, uri: &str, body: &str) -> Answer {
    call_as(router, access_key_id, REGION, "POST", uri, body).await
}

/// The principal the ACCOUNT's own published credential speaks for ([`DEFAULT_ACCESS_KEY_ID`],
/// which the shared harness signs a peer-service call with), as `sts:GetCallerIdentity`
/// reports it — the same resolution a refusal names the caller by, read over the wire
/// rather than written out here.
async fn account_principal(router: &MultiServiceRouter) -> String {
    let (status, body) = query(router, "sts", "2011-06-15", "GetCallerIdentity", &[]).await;
    assert_eq!(
        status, 200,
        "setup: GetCallerIdentity must answer the caller, got {status} {body}"
    );
    let arn = xml_element(&body, "Arn")
        .unwrap_or_else(|| panic!("setup: GetCallerIdentity must report an Arn, got {body}"));
    assert!(
        !arn.is_empty(),
        "setup: the account's own principal must not be empty, got {body}"
    );
    arn
}

/// The refusal this service words for a request that named no resource to judge the action
/// on: the principal and the action, and nothing more.
fn no_resource_message(principal: &str, operation: &str) -> String {
    format!("User: {principal} is not authorized to perform: eks:{operation}")
}

/// An accepted `RegisterCluster` body's `connectorConfig`, so a row that breaks ONE member
/// of it differs from an accepted request only in that member.
fn connector_config() -> serde_json::Value {
    json!({
        "roleArn": format!(
            "arn:aws:iam::{}:role/AmazonEKSConnectorRole",
            engine::emulator_account_id()
        ),
        "provider": "OTHER",
    })
}

/// One row of the table: a request whose body does not carry the container a member of the
/// operation's input declares, so the walk cannot enter it.
struct Unbindable {
    case: &'static str,
    operation: &'static str,
    uri: &'static str,
    body: serde_json::Value,
}

/// The table itself: every row differs in the member whose container the body does not
/// carry, over both operations whose judged resource is named in the body. `name` is
/// well-formed in every row, so a row is refused for the body it carries and not for the
/// name it asks for.
fn unbindable_rows(cluster: &str) -> Vec<Unbindable> {
    vec![
        Unbindable {
            case: "a list member given a string",
            operation: "CreateCluster",
            uri: "/clusters",
            body: json!({
                "name": cluster,
                "roleArn": "arn:aws:iam::000000000000:role/eksClusterRole",
                "resourcesVpcConfig": { "subnetIds": "subnet-aaaa1111" },
            }),
        },
        Unbindable {
            case: "a structure member given a string",
            operation: "CreateCluster",
            uri: "/clusters",
            body: json!({
                "name": cluster,
                "roleArn": "arn:aws:iam::000000000000:role/eksClusterRole",
                "resourcesVpcConfig": "vpc-0a1b2c3d4e5f60718",
            }),
        },
        Unbindable {
            case: "a list member given an object",
            operation: "CreateCluster",
            uri: "/clusters",
            body: json!({
                "name": cluster,
                "roleArn": "arn:aws:iam::000000000000:role/eksClusterRole",
                "resourcesVpcConfig": { "subnetIds": ["subnet-aaaa1111", "subnet-bbbb2222"] },
                "encryptionConfig": { "provider": { "keyArn": "arn:aws:kms:us-west-2:000000000000:key/k" } },
            }),
        },
        Unbindable {
            case: "a map member given a list",
            operation: "CreateCluster",
            uri: "/clusters",
            body: json!({
                "name": cluster,
                "roleArn": "arn:aws:iam::000000000000:role/eksClusterRole",
                "resourcesVpcConfig": { "subnetIds": ["subnet-aaaa1111", "subnet-bbbb2222"] },
                "tags": ["owner"],
            }),
        },
        Unbindable {
            case: "a registration's structure member given a string",
            operation: "RegisterCluster",
            uri: "/cluster-registrations",
            body: json!({
                "name": cluster,
                "connectorConfig": "AmazonEKSConnectorRole",
            }),
        },
        Unbindable {
            case: "a registration's map member given a list",
            operation: "RegisterCluster",
            uri: "/cluster-registrations",
            body: json!({
                "name": cluster,
                "connectorConfig": connector_config(),
                "tags": ["owner"],
            }),
        },
    ]
}

/// Assert `answer` is the refusal a request that named no resource earns, for `case`.
fn assert_no_resource_refusal(case: &str, operation: &str, principal: &str, answer: &Answer) {
    assert_eq!(
        answer.status, 403,
        "case {case:?}: expected HTTP 403, got {answer:?}"
    );
    // Which also settles that the validation framework's own report of a body it could
    // not read — `ValidationException`, which `smithy_query(query="operation",
    // operation="CreateCluster")` shows this operation does not model — is not what a
    // caller is answered here.
    assert_eq!(
        error_code(answer),
        ACCESS_DENIED,
        "case {case:?}: expected {ACCESS_DENIED}, got {answer:?}"
    );
    assert_eq!(
        answer.message(),
        no_resource_message(principal, operation),
        "case {case:?}: expected the refusal to name the principal and the action alone, \
         got {:?}",
        answer.message()
    );
}

// ---------------------------------------------------------------------------
// RULE: a body this service cannot bind names no resource, so the decision
// taken ahead of the operation refuses the call — naming the principal and the
// action alone — and nothing the request asked for is written.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_body_that_cannot_be_bound_is_refused_before_it_is_read() {
    let router = emulator_with_identity();
    let principal = account_principal(&router).await;
    let cluster = "probe-cluster";

    for row in unbindable_rows(cluster) {
        let answer = eks(
            &router,
            DEFAULT_ACCESS_KEY_ID,
            row.uri,
            &row.body.to_string(),
        )
        .await;
        assert_no_resource_refusal(row.case, row.operation, &principal, &answer);
    }

    // Nothing the refused calls asked for exists: the decision is taken before anything is
    // read or written, so the cluster every row named was never created.
    let described = call_as(
        &router,
        DEFAULT_ACCESS_KEY_ID,
        REGION,
        "GET",
        &format!("/clusters/{cluster}"),
        "",
    )
    .await;
    assert_eq!(
        error_code(&described),
        "ResourceNotFoundException",
        "case \"after the refused calls\": expected no cluster to have been created, got \
         {described:?}"
    );
}

// ---------------------------------------------------------------------------
// RULE: the refusal is not a decision about the caller's policies — a caller
// every statement allows is refused the same way, while the same caller's
// well-formed request is served.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_caller_allowed_every_action_is_refused_the_same_way() {
    let router = emulator_with_identity();
    let user_name = "eks-admin-probe";
    let document = json!({
        "Version": "2012-10-17",
        "Statement": [{ "Effect": "Allow", "Action": "eks:*", "Resource": "*" }],
    })
    .to_string();

    let (status, body) = query(
        &router,
        "iam",
        "2010-05-08",
        "CreateUser",
        &[("UserName", user_name.to_string())],
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: creating the user must succeed, got {status} {body}"
    );
    let user_arn = xml_element(&body, "Arn")
        .unwrap_or_else(|| panic!("setup: CreateUser must report the user Arn, got {body}"));
    let (status, body) = query(
        &router,
        "iam",
        "2010-05-08",
        "PutUserPolicy",
        &[
            ("UserName", user_name.to_string()),
            ("PolicyName", "allow-everything".to_string()),
            ("PolicyDocument", document),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: putting the inline policy must succeed, got {status} {body}"
    );
    let (status, body) = query(
        &router,
        "iam",
        "2010-05-08",
        "CreateAccessKey",
        &[("UserName", user_name.to_string())],
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: creating the access key must succeed, got {status} {body}"
    );
    let access_key_id = xml_element(&body, "AccessKeyId")
        .unwrap_or_else(|| panic!("setup: CreateAccessKey must report an AccessKeyId, got {body}"));

    // Every row of the same table, as the caller every statement allows.
    for row in unbindable_rows("admin-probe-cluster") {
        let answer = eks(&router, &access_key_id, row.uri, &row.body.to_string()).await;
        assert_no_resource_refusal(row.case, row.operation, &user_arn, &answer);
    }

    // And that caller's well-formed request IS served, which is what makes the refusals
    // above a fact about the body rather than about the policy in force.
    let created = eks(
        &router,
        &access_key_id,
        "/clusters",
        &minimal_request("admin-probe-cluster").to_string(),
    )
    .await;
    assert_eq!(
        created.status, 200,
        "case \"the same caller's well-formed request\": expected the create to be served, \
         got {created:?}"
    );
}

// ---------------------------------------------------------------------------
// RULE: a body that DOES bind is untouched — a value read and then refused by a
// rule this API states earns that parameter's own sentence, and an accepted
// request is served.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_body_that_binds_reaches_the_rule_it_broke() {
    let router = emulator_with_identity();

    // (case, the body, the status, the error code, the sentence)
    let rows: Vec<(&str, serde_json::Value, u16, &str, String)> = vec![
        (
            "a required member the request omitted",
            json!({
                "roleArn": "arn:aws:iam::000000000000:role/eksClusterRole",
                "resourcesVpcConfig": { "subnetIds": ["subnet-aaaa1111", "subnet-bbbb2222"] },
            }),
            400,
            INVALID_PARAMETER,
            "The parameter name is required.".to_string(),
        ),
        (
            "a name outside the cluster-name grammar",
            minimal_request("probe cluster"),
            400,
            INVALID_PARAMETER,
            "The parameter name contains invalid characters. It should conform to the regular \
             expression \"^[0-9A-Za-z][A-Za-z0-9-_]*\"In other words, it should start with a \
             number or letter, and can contain numbers, letters, dashes, and underscores."
                .to_string(),
        ),
    ];

    for (case, body, status, code, message) in rows {
        let answer = eks(
            &router,
            DEFAULT_ACCESS_KEY_ID,
            "/clusters",
            &body.to_string(),
        )
        .await;
        assert_eq!(
            answer.status, status,
            "case {case:?}: expected HTTP {status}, got {answer:?}"
        );
        assert_eq!(
            error_code(&answer),
            code,
            "case {case:?}: expected {code}, got {answer:?}"
        );
        assert_eq!(
            answer.message(),
            message,
            "case {case:?}: expected the sentence this API states, got {:?}",
            answer.message()
        );
    }

    // A scalar member is read from whichever of JSON's scalar types the body carries
    // there, so a value that states nothing of the modelled type WAS read: it is refused
    // as the value it is, and never as a request that named no resource.
    for (case, members) in [
        (
            "a word at an integer member",
            json!({
                "kubeApiServerConfig": { "serviceNodePortRange": { "minPort": "many" } },
            }),
        ),
        (
            "a list at a boolean member",
            json!({ "deletionProtection": [true] }),
        ),
    ] {
        let mut body = minimal_request("states-nothing");
        let (Some(into), Some(extra)) = (body.as_object_mut(), members.as_object()) else {
            panic!("both the request and the members merged into it must be objects");
        };
        for (key, value) in extra {
            into.insert(key.clone(), value.clone());
        }
        let answer = eks(
            &router,
            DEFAULT_ACCESS_KEY_ID,
            "/clusters",
            &body.to_string(),
        )
        .await;
        assert_eq!(
            answer.status, 400,
            "case {case:?}: expected the value's own refusal, got {answer:?}"
        );
        assert_ne!(
            error_code(&answer),
            ACCESS_DENIED,
            "case {case:?}: a value the body stated is not a request that named no \
             resource, got {answer:?}"
        );
    }

    let created = eks(
        &router,
        DEFAULT_ACCESS_KEY_ID,
        "/clusters",
        &minimal_request("accepted-cluster").to_string(),
    )
    .await;
    assert_eq!(
        created.status, 200,
        "case \"a request this API accepts\": expected the create to be served, got {created:?}"
    );
}
