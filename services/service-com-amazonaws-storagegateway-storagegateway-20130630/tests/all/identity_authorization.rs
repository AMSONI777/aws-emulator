// SPDX-License-Identifier: CC0-1.0

//! IAM authorization of this service's operations, over the awsJson1_1 wire.
//!
//! The rule under test: every operation of this service is signed, so every call is made
//! by a principal, and a principal may only perform an action some policy in force on it
//! ALLOWS — an action no identity-based policy of the calling principal allows is refused
//! with the AWS-common `AccessDeniedException` BEFORE the operation reads or writes
//! anything. So a refused mutation changes nothing, a refused read reports nothing about
//! what the account holds, and adding the missing `Allow` makes the identical call
//! succeed. The decision is taken against the resource the action takes: the gateway, file
//! share or custom tape pool ARN the request names, and every resource for an action that
//! addresses none.
//!
//! The principals below are made with IAM's and STS's OWN operations over the same engine
//! (`CreateUser` + `PutUserPolicy` + `CreateAccessKey`, `CreateRole` + `PutRolePolicy` +
//! `AssumeRole`), so the documents this service reads are the ones those services wrote,
//! and the evaluation is `service_common::iam_authorization`, shared with every other
//! service that authorizes.
//!
//! It is asserted over TABLES that differ along what the rule generalises over: the
//! OPERATION asked for (every implemented one, each with its own action and its own
//! resource), what the caller's policies say (nothing, an `Allow` of this action, a
//! wildcard `Allow`, an `Allow` of another service's action, an `Allow` on another
//! resource, an action prefix pattern, an explicit `Deny` beside a wildcard `Allow`), and
//! which kind of principal signs (the account's own published credential, an IAM user, an
//! assumed-role session).

use std::sync::Arc;

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_storagegateway_storagegateway_20130630::state::{
    ARN_NAMESPACE, DEFAULT_REGION,
};

/// The `X-Amz-Target` prefix from the crate's `OPERATIONS.md` wire-protocol section.
const TARGET_PREFIX: &str = "StorageGateway_20130630";

/// The access-key id standing for the account's own published credential: neither STS nor
/// IAM holds a record for it, so it resolves to the account's ambient identity, which holds
/// no IAM policies and is allowed — the position AWS account root credentials are in.
const ACCOUNT_KEY: &str = "AKIDSTORAGEGATEWAY";

/// The status and the wire error code an authorization refusal carries: the AWS "Common
/// Errors" table's `AccessDeniedException`, which this service's model does not declare.
const ACCESS_DENIED: (u16, &str) = (400, "AccessDeniedException");

/// The one client error this service's model declares — what an authorized call that names
/// a resource nothing answers to is refused with, which is how this suite tells "the gate
/// let it through" from "the gate refused it".
const INVALID_GATEWAY_REQUEST: &str = "InvalidGatewayRequestException";

/// The resource a decision about an action that addresses none is made against
/// (`service::authorization::ANY_RESOURCE`).
const ANY_RESOURCE: &str = "*";

/// An IAM role ARN matching `CreateNFSFileShareInput$Role`'s pattern.
const ROLE: &str = "arn:aws:iam::000000000000:role/storage-gateway-share";

/// The emulator these tests drive: one shared engine carrying this service beside the IAM
/// and STS services the principals and their policies are made with — the same set
/// `core/router`'s `build_router` assembles, narrowed to what this rule touches.
struct Emulator {
    router: MultiServiceRouter,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        // The suite signs nothing: the `Authorization` header carries only the credential
        // scope, which is where a service reads the caller's access key id from.
        router.set_request_authentication(false);
        router.register_service(
            service_com_amazonaws_storagegateway_storagegateway_20130630::EmulatedService::new(
                Arc::clone(&engine),
            ),
        );
        router.register_service(
            service_com_amazonaws_iam_awsidentitymanagementv20100508::EmulatedService::new(
                Arc::clone(&engine),
            ),
        );
        router.register_service(
            service_com_amazonaws_sts_awssecuritytokenservicev20110615::EmulatedService::new(
                engine,
            ),
        );
        Self { router }
    }

    /// One call to this service, with `access_key_id` in the SigV4 credential scope.
    async fn call(&self, access_key_id: &str, operation: &str, body: &Value) -> (u16, Value) {
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "storagegateway.us-east-1.amazonaws.com")
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", format!("{TARGET_PREFIX}.{operation}"))
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={access_key_id}/20260101/{DEFAULT_REGION}\
                     /{ARN_NAMESPACE}/aws4_request, SignedHeaders=host;x-amz-target, \
                     Signature=00"
                ),
            )
            .body(bytes::Bytes::from(
                serde_json::to_vec(body).expect("the request body serializes"),
            ))
            .expect("a well-formed request");
        let response = self.router.dispatch(request).await;
        let status = response.status().as_u16();
        let payload = response.into_body();
        let parsed = if payload.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&payload)
                .unwrap_or_else(|_| json!({ "__unparsed": String::from_utf8_lossy(&payload) }))
        };
        (status, parsed)
    }

    /// One awsQuery call to IAM or STS, signed with the account's own credential.
    async fn query(
        &self,
        signing_name: &str,
        version: &str,
        action: &str,
        params: &[(&str, String)],
    ) -> String {
        let mut body = format!("Action={action}&Version={version}");
        for (name, value) in params {
            body.push('&');
            body.push_str(name);
            body.push('=');
            body.push_str(&form_encode(value));
        }
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{signing_name}.amazonaws.com/"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={ACCOUNT_KEY}/20260101/{DEFAULT_REGION}/\
                     {signing_name}/aws4_request, SignedHeaders=host, Signature=00"
                ),
            )
            .body(bytes::Bytes::from(body))
            .expect("a well-formed awsQuery request");
        let response = self.router.dispatch(request).await;
        let status = response.status().as_u16();
        let text = String::from_utf8_lossy(response.body()).to_string();
        assert_eq!(
            status, 200,
            "case {action:?}: the setup call must succeed, got {status} with {text}"
        );
        text
    }

    /// Create an IAM role carrying `policy` as its inline policy, assume it through STS,
    /// and answer the session's access key id with the session ARN.
    async fn assumed_role(&self, role_name: &str, policy: &str) -> Principal {
        let account = ::engine::emulator_account_id();
        let trust = format!(
            "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\
             \"Principal\":{{\"AWS\":\"arn:aws:iam::{account}:root\"}},\
             \"Action\":\"sts:AssumeRole\"}}]}}"
        );
        self.query(
            "iam",
            "2010-05-08",
            "CreateRole",
            &[
                ("RoleName", role_name.to_string()),
                ("AssumeRolePolicyDocument", trust),
            ],
        )
        .await;
        self.put_role_policy(role_name, policy).await;
        let assumed = self
            .query(
                "sts",
                "2011-06-15",
                "AssumeRole",
                &[
                    ("RoleArn", format!("arn:aws:iam::{account}:role/{role_name}")),
                    ("RoleSessionName", "probe".to_string()),
                ],
            )
            .await;
        Principal {
            access_key_id: xml_element(&assumed, "AccessKeyId")
                .unwrap_or_else(|| panic!("AssumeRole answers an AccessKeyId, got {assumed}")),
            arn: xml_element(&assumed, "Arn")
                .unwrap_or_else(|| panic!("AssumeRole answers the session's Arn, got {assumed}")),
        }
    }

    /// Write (or rewrite) the one inline policy of `role_name`, under the same policy name
    /// every time, so a put REPLACES what the principal carried.
    async fn put_role_policy(&self, role_name: &str, policy: &str) {
        self.query(
            "iam",
            "2010-05-08",
            "PutRolePolicy",
            &[
                ("RoleName", role_name.to_string()),
                ("PolicyName", "inline".to_string()),
                ("PolicyDocument", policy.to_string()),
            ],
        )
        .await;
    }

    /// Create an IAM user carrying `policy` as its inline policy, mint a long-term access
    /// key for it, and answer that key id with the user's own ARN.
    async fn user(&self, user_name: &str, policy: &str) -> Principal {
        let created = self
            .query(
                "iam",
                "2010-05-08",
                "CreateUser",
                &[("UserName", user_name.to_string())],
            )
            .await;
        let arn = xml_element(&created, "Arn")
            .unwrap_or_else(|| panic!("CreateUser answers the user's Arn, got {created}"));
        self.query(
            "iam",
            "2010-05-08",
            "PutUserPolicy",
            &[
                ("UserName", user_name.to_string()),
                ("PolicyName", "inline".to_string()),
                ("PolicyDocument", policy.to_string()),
            ],
        )
        .await;
        let minted = self
            .query(
                "iam",
                "2010-05-08",
                "CreateAccessKey",
                &[("UserName", user_name.to_string())],
            )
            .await;
        Principal {
            access_key_id: xml_element(&minted, "AccessKeyId").unwrap_or_else(|| {
                panic!("CreateAccessKey answers an AccessKeyId, got {minted}")
            }),
            arn,
        }
    }
}

/// A principal a call is signed as: the access key id it presents, and the ARN a refusal
/// must blame it by — what `sts:GetCallerIdentity` reports for that key.
struct Principal {
    access_key_id: String,
    arn: String,
}

/// Percent-encode one `application/x-www-form-urlencoded` component, leaving only RFC
/// 3986's unreserved characters literal — so a policy document's braces and quotes survive
/// the round trip.
fn form_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// The text of the first `<name>…</name>` element of an awsQuery response.
fn xml_element(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].to_string())
}

/// The wire error code a response carries (`__type` on the awsJson protocols), without its
/// namespace prefix, and the empty string for a response that is no error at all.
fn code_of(body: &Value) -> String {
    let raw = body["__type"].as_str().unwrap_or_default();
    match raw.rsplit_once('#') {
        Some((_, name)) => name.to_string(),
        None => raw.to_string(),
    }
}

/// The message a refusal carries.
fn message_of(body: &Value) -> String {
    body["message"]
        .as_str()
        .or_else(|| body["Message"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// An ARN of this service, in the region every call below is signed for.
fn resource_arn(kind: &str, id: &str) -> String {
    let account = ::engine::emulator_account_id();
    format!("arn:aws:{ARN_NAMESPACE}:{DEFAULT_REGION}:{account}:{kind}/{id}")
}

/// One call to this service: the operation, a request that satisfies every modelled
/// constraint (so the boundary validator passes it and the authorization decision is what
/// answers it), and the resource the action is decided against.
struct Call {
    operation: &'static str,
    body: Value,
    resource: String,
}

/// Every implemented operation of this service, with the resource its action addresses.
///
/// The ARNs name nothing the store holds: the decision is made from the request alone, so
/// an authorized call gets this service's own `InvalidGatewayRequestException` while an
/// unauthorized one never reaches the store at all.
fn calls() -> Vec<Call> {
    let gateway = resource_arn("gateway", "sgw-00000001");
    let share = resource_arn("share", "share-00000001");
    let pool = resource_arn("tapepool", "pool-00000001");
    vec![
        Call {
            operation: "ActivateGateway",
            body: json!({
                "ActivationKey": "activation-key-0001",
                "GatewayName": "authorized",
                "GatewayTimezone": "GMT",
                "GatewayRegion": DEFAULT_REGION,
            }),
            resource: ANY_RESOURCE.to_string(),
        },
        Call {
            operation: "ListGateways",
            body: json!({}),
            resource: ANY_RESOURCE.to_string(),
        },
        Call {
            operation: "DescribeGatewayInformation",
            body: json!({ "GatewayARN": gateway }),
            resource: gateway.clone(),
        },
        Call {
            operation: "DeleteGateway",
            body: json!({ "GatewayARN": gateway }),
            resource: gateway.clone(),
        },
        Call {
            operation: "CreateNFSFileShare",
            body: json!({
                "ClientToken": "token-0001",
                "GatewayARN": gateway,
                "Role": ROLE,
                "LocationARN": "arn:aws:s3:::amzn-s3-demo-bucket",
            }),
            resource: gateway.clone(),
        },
        Call {
            operation: "ListFileShares",
            body: json!({ "GatewayARN": gateway }),
            resource: gateway,
        },
        Call {
            operation: "DescribeNFSFileShares",
            body: json!({ "FileShareARNList": [share] }),
            resource: share.clone(),
        },
        Call {
            operation: "DeleteFileShare",
            body: json!({ "FileShareARN": share }),
            resource: share,
        },
        Call {
            operation: "CreateTapePool",
            body: json!({ "PoolName": "authorized", "StorageClass": "GLACIER" }),
            resource: ANY_RESOURCE.to_string(),
        },
        Call {
            operation: "ListTapePools",
            body: json!({}),
            resource: ANY_RESOURCE.to_string(),
        },
        Call {
            operation: "DeleteTapePool",
            body: json!({ "PoolARN": pool }),
            resource: pool,
        },
    ]
}

/// A policy document carrying one statement.
fn statement(effect: &str, action: &str, resource: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"{effect}","Action":"{action}","Resource":"{resource}"}}]}}"#
    )
}

/// RULE: with no grant, every implemented operation is refused `AccessDeniedException`
/// naming the principal, the action and the resource it addressed; with a wildcard grant
/// the identical call reaches the operation.
#[tokio::test]
async fn every_operation_is_refused_without_a_grant_and_reached_with_one() {
    let emulator = Emulator::new();
    // A principal with a policy that grants nothing of this service, and one granted every
    // action of it.
    let ungranted = emulator
        .assumed_role("no-storage-gateway", &statement("Allow", "s3:GetObject", "*"))
        .await;
    let granted = emulator
        .assumed_role(
            "all-storage-gateway",
            &statement("Allow", "storagegateway:*", "*"),
        )
        .await;

    for Call {
        operation,
        body,
        resource,
    } in calls()
    {
        let (status, refused) = emulator.call(&ungranted.access_key_id, operation, &body).await;
        assert_eq!(
            (status, code_of(&refused).as_str()),
            ACCESS_DENIED,
            "case {operation:?} ungranted: expected {ACCESS_DENIED:?}, got {status} {refused:?}"
        );
        let message = message_of(&refused);
        let action = format!("{ARN_NAMESPACE}:{operation}");
        assert!(
            message.contains(&ungranted.arn) && message.contains(&action),
            "case {operation:?} ungranted: the refusal must name the principal and \
             {action}, got {message:?}"
        );
        if resource != ANY_RESOURCE {
            assert!(
                message.contains(&format!("on resource: {resource}")),
                "case {operation:?} ungranted: the refusal must name the resource \
                 {resource}, got {message:?}"
            );
        }

        let (status, answer) = emulator.call(&granted.access_key_id, operation, &body).await;
        let code = code_of(&answer);
        assert_ne!(
            code, ACCESS_DENIED.1,
            "case {operation:?} granted: the call must reach the operation, got {status} \
             {answer:?}"
        );
        assert!(
            status == 200 || code == INVALID_GATEWAY_REQUEST,
            "case {operation:?} granted: expected the operation's own answer, got {status} \
             {answer:?}"
        );
    }
}

/// RULE: the decision is per ACTION, so a least-privilege policy naming one action of this
/// service allows that operation and nothing else of it.
#[tokio::test]
async fn a_grant_of_one_action_allows_only_that_operation() {
    let emulator = Emulator::new();
    let principal = emulator
        .assumed_role(
            "tape-pool-creator",
            &statement("Allow", "storagegateway:CreateTapePool", "*"),
        )
        .await;

    let (status, created) = emulator
        .call(
            &principal.access_key_id,
            "CreateTapePool",
            &json!({ "PoolName": "least-privilege", "StorageClass": "DEEP_ARCHIVE" }),
        )
        .await;
    assert_eq!(
        status, 200,
        "case the granted action: expected HTTP 200, got {status} with {created:?}"
    );
    let pool_arn = created["PoolARN"]
        .as_str()
        .unwrap_or_else(|| panic!("CreateTapePool answers a PoolARN, got {created:?}"))
        .to_string();

    // Every other action of this service — including the paired delete and the listing —
    // is outside the one grant.
    for (operation, body) in [
        ("DeleteTapePool", json!({ "PoolARN": pool_arn })),
        ("ListTapePools", json!({})),
    ] {
        let (status, refused) = emulator.call(&principal.access_key_id, operation, &body).await;
        assert_eq!(
            (status, code_of(&refused).as_str()),
            ACCESS_DENIED,
            "case {operation:?} outside the grant: expected {ACCESS_DENIED:?}, got {status} \
             {refused:?}"
        );
    }

    // Adding the missing `Allow` makes the identical calls succeed: nothing is cached.
    emulator
        .put_role_policy(
            "tape-pool-creator",
            &statement("Allow", "storagegateway:*", "*"),
        )
        .await;
    let (status, deleted) = emulator
        .call(
            &principal.access_key_id,
            "DeleteTapePool",
            &json!({ "PoolARN": pool_arn }),
        )
        .await;
    assert_eq!(
        (status, deleted["PoolARN"].as_str()),
        (200, Some(pool_arn.as_str())),
        "case the grant added: expected the delete to answer the pool it deleted, got \
         {status} with {deleted:?}"
    );
}

/// RULE: the decision is per RESOURCE, so a policy scoped to one custom tape pool allows
/// the action on that pool alone.
#[tokio::test]
async fn a_grant_scoped_to_one_resource_allows_only_that_resource() {
    let emulator = Emulator::new();
    // The pools are created with the account's own credential, which holds no policies.
    let mut pools = Vec::new();
    for name in ["scoped-first", "scoped-second"] {
        let (status, created) = emulator
            .call(
                ACCOUNT_KEY,
                "CreateTapePool",
                &json!({ "PoolName": name, "StorageClass": "GLACIER" }),
            )
            .await;
        assert_eq!(
            status, 200,
            "case {name}: the account's own credential holds no IAM policies and must be \
             allowed, got {status} with {created:?}"
        );
        pools.push(
            created["PoolARN"]
                .as_str()
                .unwrap_or_else(|| panic!("CreateTapePool answers a PoolARN, got {created:?}"))
                .to_string(),
        );
    }

    let principal = emulator
        .assumed_role(
            "one-pool-deleter",
            &statement("Allow", "storagegateway:DeleteTapePool", &pools[0]),
        )
        .await;

    let (status, refused) = emulator
        .call(
            &principal.access_key_id,
            "DeleteTapePool",
            &json!({ "PoolARN": pools[1] }),
        )
        .await;
    assert_eq!(
        (status, code_of(&refused).as_str()),
        ACCESS_DENIED,
        "case another pool: expected {ACCESS_DENIED:?}, got {status} {refused:?}"
    );

    let (status, deleted) = emulator
        .call(
            &principal.access_key_id,
            "DeleteTapePool",
            &json!({ "PoolARN": pools[0] }),
        )
        .await;
    assert_eq!(
        (status, deleted["PoolARN"].as_str()),
        (200, Some(pools[0].as_str())),
        "case the named pool: expected the delete to answer it, got {status} with {deleted:?}"
    );

    // The refused delete changed nothing: the pool it named is still there.
    let (status, listed) = emulator.call(ACCOUNT_KEY, "ListTapePools", &json!({})).await;
    let remaining: Vec<String> = listed["PoolInfos"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|info| info["PoolARN"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        (status, remaining.as_slice()),
        (200, &[pools[1].clone()][..]),
        "case after the refusal: only the pool the refused call named must remain, got \
         {listed:?}"
    );
}

/// RULE: what the document SAYS decides, whoever holds it and however it is written — an
/// explicit `Deny` beside a wildcard `Allow` refuses, an action prefix pattern grants, an
/// `Allow` of another service grants nothing, and a long-term IAM user's own policy is read
/// the same way an assumed role's is.
#[tokio::test]
async fn the_decision_follows_the_document_whoever_holds_it() {
    let emulator = Emulator::new();
    let create = json!({ "PoolName": "documents", "StorageClass": "GLACIER" });

    // (case, the document, whether CreateTapePool is allowed)
    let rows: Vec<(&str, String, bool)> = vec![
        (
            "an explicit deny beside a wildcard allow",
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":"*","Resource":"*"},
                {"Effect":"Deny","Action":"storagegateway:CreateTapePool","Resource":"*"}]}"#
                .to_string(),
            false,
        ),
        (
            "an action prefix pattern",
            statement("Allow", "storagegateway:Create*", "*"),
            true,
        ),
        (
            "an allow of another service's action",
            statement("Allow", "s3:CreateBucket", "*"),
            false,
        ),
        (
            "an allow of this action on another resource",
            statement(
                "Allow",
                "storagegateway:CreateTapePool",
                &resource_arn("tapepool", "pool-FFFFFFFF"),
            ),
            false,
        ),
        (
            "an allow of every action",
            statement("Allow", "*", "*"),
            true,
        ),
    ];

    for (index, (case, document, allowed)) in rows.into_iter().enumerate() {
        // The same document, held by an assumed role and by an IAM user with a long-term
        // key: where it lives does not change what it says.
        let role = emulator
            .assumed_role(&format!("document-role-{index}"), &document)
            .await;
        let user = emulator
            .user(&format!("document-user-{index}"), &document)
            .await;
        for principal in [&role, &user] {
            let (status, answer) = emulator
                .call(&principal.access_key_id, "CreateTapePool", &create)
                .await;
            let code = code_of(&answer);
            if allowed {
                assert_eq!(
                    status, 200,
                    "case {case:?} as {}: expected the call to be served, got {status} \
                     {answer:?}",
                    principal.arn
                );
            } else {
                assert_eq!(
                    (status, code.as_str()),
                    ACCESS_DENIED,
                    "case {case:?} as {}: expected {ACCESS_DENIED:?}, got {status} {answer:?}",
                    principal.arn
                );
            }
        }
    }
}

/// RULE: a refused mutation changes nothing — the refusal is answered before the store is
/// reached.
#[tokio::test]
async fn a_refused_call_writes_nothing() {
    let emulator = Emulator::new();
    let ungranted = emulator
        .assumed_role("writes-nothing", &statement("Deny", "storagegateway:*", "*"))
        .await;

    for (operation, body) in [
        (
            "CreateTapePool",
            json!({ "PoolName": "never-stored", "StorageClass": "GLACIER" }),
        ),
        (
            "ActivateGateway",
            json!({
                "ActivationKey": "activation-key-0002",
                "GatewayName": "never-activated",
                "GatewayTimezone": "GMT",
                "GatewayRegion": DEFAULT_REGION,
            }),
        ),
    ] {
        let (status, refused) = emulator.call(&ungranted.access_key_id, operation, &body).await;
        assert_eq!(
            (status, code_of(&refused).as_str()),
            ACCESS_DENIED,
            "case {operation:?}: expected {ACCESS_DENIED:?}, got {status} {refused:?}"
        );
        assert!(
            message_of(&refused).contains("explicit deny"),
            "case {operation:?}: an explicit deny must be named as the reason, got {:?}",
            message_of(&refused)
        );
    }

    // Read back with the account's own credential, which this gate does not bound.
    let (_, pools) = emulator.call(ACCOUNT_KEY, "ListTapePools", &json!({})).await;
    assert_eq!(
        pools["PoolInfos"].as_array().map(Vec::len),
        Some(0),
        "case after the refusals: no tape pool must have been stored, got {pools:?}"
    );
    let (_, gateways) = emulator.call(ACCOUNT_KEY, "ListGateways", &json!({})).await;
    assert_eq!(
        gateways["Gateways"].as_array().map(Vec::len),
        Some(0),
        "case after the refusals: no gateway must have been activated, got {gateways:?}"
    );
}
