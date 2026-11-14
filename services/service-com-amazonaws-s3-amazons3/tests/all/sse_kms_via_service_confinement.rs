// SPDX-License-Identifier: CC0-1.0

//! A KMS key confined to THIS service's path to it: the SSE-KMS envelope is permitted and the
//! same caller's direct cryptographic use of the same key is refused.
//!
//! The rule under test: a key-policy statement whose `Condition` compares `kms:ViaService`
//! grants its actions exactly for the requests that reach KMS THROUGH the named service on a
//! caller's behalf. An AWS service performing the envelope on the caller's behalf carries that
//! condition key with its own regional endpoint, so a statement naming this service's endpoint
//! grants the write's `kms:GenerateDataKey` and the read's `kms:Decrypt` and the object is
//! stored and served; a request the SAME caller makes straight to KMS carries no value for that
//! condition key, so the statement grants nothing, no other statement allows the action, and
//! KMS answers `AccessDeniedException` (HTTP 400) with its denial sentence naming the caller,
//! the action and the key. That is the whole point of confining a key to one service: the
//! envelope path works and direct crypto on the key does not.
//!
//! Only a suite that drives BOTH halves over one engine can pin it — the permitted half is an
//! S3 write and read, the refused half is a KMS call, and they have to be the same caller, the
//! same key and the same policy document for the contract to mean anything. The KMS crate's
//! `via_service_confinement` suite tables the refused half across every cryptographic
//! operation; this crate's `sse_kms_data_key_authorization` and `sse_kms_decrypt_authorization`
//! suites table which authority an SSE-KMS write and read need. What neither can state is that
//! one document does both at once, which is what this suite asserts.
//!
//! The rows span what the rule generalises over rather than one recorded policy:
//!
//! * the OPERATOR the condition is written with — equality, equality over a list of endpoints,
//!   a wildcard comparison, and a set qualifier over the same comparison;
//! * the SERVICE the condition names — this one, another one, and several at once;
//! * the ACTIONS the conditioned statement names — the canonical crypto set, and the read
//!   action alone, which the write's data key is not covered by;
//! * the PRINCIPAL the statement names — the account root the default policy delegates to, and
//!   the calling identity itself;
//! * and a control row carrying no condition at all, under which the very same direct call
//!   succeeds, so every refusal below is the condition's doing and not the policy's.
//!
//! Every key, key policy, bucket and object here is made with KMS's and S3's own operations
//! over one shared engine: nothing reaches into a store to plant a key, a policy or a decision.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use super::bucket_lifecycle::Answer;
use super::kms_key_references::{created_key, kms, router_with_kms, REGION};
use super::object_and_tagging_roundtrip::{bucket, get_object, put_object, text};

/// The `ServerSideEncryption` value whose data key belongs to a KMS key
/// (`smithy_query(query="shape",shape="ServerSideEncryption")`).
const SSE_KMS: &str = "aws:kms";

/// The response headers `ServerSideEncryption` and `SSEKMSKeyId` bind to
/// (`smithy_query(query="operation",operation="PutObject")`).
const ALGORITHM_HEADER: &str = "x-amz-server-side-encryption";
const KEY_ID_HEADER: &str = "x-amz-server-side-encryption-aws-kms-key-id";

/// The bytes every write in this suite carries: a key policy is about who may use the key, not
/// about what is in the object, so one payload serves every row.
const BODY: &[u8] = b"a key confined to one service";

/// The bucket every object below is stored in.
const BUCKET: &str = "sse-kms-via-service";

/// The code S3 refuses a write or read nothing granted with, and the status it carries (Amazon
/// S3 "Error responses": `AccessDenied`, HTTP 403).
const ACCESS_DENIED: &str = "AccessDenied";

/// The code KMS refuses a call no policy in force allows with, and the status it carries: the
/// service-common `AccessDeniedException`, HTTP 400.
const ACCESS_DENIED_EXCEPTION: &str = "AccessDeniedException";

/// The IAM action a write that stores an SSE-KMS object performs on the object's key, and the
/// one a read of it performs.
const GENERATE_DATA_KEY_ACTION: &str = "kms:GenerateDataKey";
const DECRYPT_ACTION: &str = "kms:Decrypt";

/// The length of the data key the `KeySpec` every direct call below asks for stands for
/// (`smithy_query(query="shape",shape="DataKeySpec")` names `AES_256`, a 256-bit key).
const AES_256_BYTES: usize = 32;

/// The regional endpoint name of an AWS service, which is the value `kms:ViaService` carries
/// for a request that service made on a caller's behalf: `<service>.<region>.amazonaws.com`.
fn endpoint(service: &str) -> String {
    format!("{service}.{REGION}.amazonaws.com")
}

/// The principal every request of this suite speaks for, on BOTH legs: an access key id neither
/// STS nor IAM holds a record of resolves to the account's own published credential, so the S3
/// write and the direct KMS call are made by the same identity — which is what makes the two
/// halves of the contract comparable. It is also the identity a refusal names.
fn principal() -> String {
    format!(
        "arn:aws:iam::{}:user/emulator",
        engine::emulator_account_id()
    )
}

/// The account's root user, the principal a DEFAULT key policy names: a statement naming it
/// delegates the decision to that account's own identity-based policies.
fn account_root() -> String {
    format!("arn:aws:iam::{}:root", engine::emulator_account_id())
}

/// The cryptographic actions the canonical confinement statement names — the set AWS writes a
/// `kms:ViaService` statement over, two of them action PATTERNS rather than action names.
fn crypto_actions() -> Value {
    json!([
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*"
    ])
}

/// The administrative actions the canonical pattern carries UNCONDITIONED beside the
/// cryptographic statement, so the key stays manageable: none of them is a cryptographic
/// action, so this statement grants no row its data key, and it carries `kms:PutKeyPolicy`,
/// which is what KMS's own policy-lockout safety check requires of a document it accepts.
fn admin_actions() -> Value {
    json!([
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:EnableKey",
        "kms:DisableKey",
        "kms:TagResource",
        "kms:ListResourceTags"
    ])
}

/// One statement over every resource of the key policy, with the principal, effect, actions and
/// condition given (no `Condition` element when it is [`Value::Null`]).
fn statement(principal: &str, effect: &str, actions: Value, condition: Value) -> Value {
    let mut statement = json!({
        "Effect": effect,
        "Principal": {"AWS": principal},
        "Action": actions,
        "Resource": "*",
    });
    if !condition.is_null() {
        statement["Condition"] = condition;
    }
    statement
}

/// A key policy document carrying exactly `statements`.
fn policy(statements: Vec<Value>) -> String {
    json!({"Version": "2012-10-17", "Id": "key-confined-to-one-service", "Statement": statements})
        .to_string()
}

/// The canonical confinement document: the unconditioned administrative statement, and the
/// cryptographic statement whose actions and condition the row under test states.
fn confinement(principal: &str, actions: Value, condition: Value) -> String {
    policy(vec![
        statement(principal, "Allow", admin_actions(), Value::Null),
        statement(principal, "Allow", actions, condition),
    ])
}

/// Attach `document` to `key_id` — the one call that changes who may use the key.
///
/// No `BypassPolicyLockoutSafetyCheck`: every document this suite attaches carries the
/// unconditioned administrative statement, so it leaves the caller a path to a later
/// `PutKeyPolicy` and KMS accepts it on its own terms.
async fn put_key_policy(router: &MultiServiceRouter, case: &str, key_id: &str, document: &str) {
    let (status, payload) = kms(
        router,
        "PutKeyPolicy",
        &json!({"KeyId": key_id, "Policy": document}),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: attaching the key policy must succeed, got {status} with {payload}"
    );
}

/// The sentence KMS words a refusal no resource-based policy allowed, written out here rather
/// than taken from the service's own helper so the wording has something to be wrong about:
/// who was refused, which action, on which key, and the clause naming the document that
/// decided it. Its variable parts come from the caller, the request and the key's stored ARN.
fn denial_sentence(action: &str, key_arn: &str) -> String {
    format!(
        "User: {} is not authorized to perform: {action} on resource: {key_arn} because no \
         resource-based policy allows the {action} action",
        principal()
    )
}

/// The headers an SSE-KMS write naming `key_id` carries.
fn write_headers(key_id: &str) -> Vec<(&str, &str)> {
    vec![
        (ALGORITHM_HEADER, SSE_KMS),
        (KEY_ID_HEADER, key_id),
    ]
}

/// Call `operation` directly at KMS as the same caller, requiring the refusal an authorization
/// decision no policy in force allowed: HTTP 400, `AccessDeniedException`, and AWS's denial
/// sentence naming the caller, the IAM action and the key.
async fn assert_direct_refusal(
    router: &MultiServiceRouter,
    case: &str,
    operation: &str,
    request: &Value,
    action: &str,
    key_arn: &str,
) {
    let (status, payload) = kms(router, operation, request).await;
    assert_eq!(
        status, 400,
        "case {case:?}: the direct {operation} must be refused with HTTP 400, got {status} with \
         {payload}"
    );
    let code = payload["__type"]
        .as_str()
        .unwrap_or_default()
        .rsplit(['#', ':'])
        .next()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        code, ACCESS_DENIED_EXCEPTION,
        "case {case:?}: expected {ACCESS_DENIED_EXCEPTION} from the direct {operation}, got \
         {payload}"
    );
    let message = payload["message"]
        .as_str()
        .or_else(|| payload["Message"].as_str())
        .unwrap_or_default();
    assert_eq!(
        message,
        denial_sentence(action, key_arn),
        "case {case:?}: expected KMS's denial sentence for the direct {operation}, got \
         {message:?}"
    );
}

/// Call `operation` directly at KMS as the same caller, requiring it to be served with a
/// ciphertext the key sealed — and, where the operation hands the data key back in the clear,
/// with a data key of the length `AES_256` names, so a served row cannot pass on a placeholder.
/// Answers the payload, for a caller that goes on to open that ciphertext.
async fn assert_direct_served(
    router: &MultiServiceRouter,
    case: &str,
    operation: &str,
    request: &Value,
) -> Value {
    let (status, payload) = kms(router, operation, request).await;
    assert_eq!(
        status, 200,
        "case {case:?}: the direct {operation} must be served, got {status} with {payload}"
    );
    assert!(
        payload["CiphertextBlob"].is_string(),
        "case {case:?}: expected a ciphertext from the direct {operation}, got {payload}"
    );
    if let Some(plaintext) = payload["Plaintext"].as_str() {
        let data_key = aws_smithy_types::base64::decode(plaintext)
            .unwrap_or_else(|_| panic!("case {case:?}: {operation} must answer base64, got \
                 {plaintext:?}"));
        assert_eq!(
            data_key.len(),
            AES_256_BYTES,
            "case {case:?}: expected a {AES_256_BYTES}-byte data key from {operation}, got {}",
            data_key.len()
        );
    }
    payload
}

/// Open the ciphertext a served `GenerateDataKey` answered, requiring `Decrypt` on the same key
/// to hand back exactly the data key the call returned in the clear: a served row's envelope has
/// to be a real one, not a blob that only looks like one.
async fn assert_data_key_opens(router: &MultiServiceRouter, case: &str, answer: &Value) {
    let ciphertext = answer["CiphertextBlob"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: GenerateDataKey must answer a ciphertext"));
    let (status, payload) = kms(
        router,
        "Decrypt",
        &json!({"CiphertextBlob": ciphertext}),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: the data key must open under the same key, got {status} with {payload}"
    );
    assert_eq!(
        payload["Plaintext"], answer["Plaintext"],
        "case {case:?}: expected the data key the call handed back, got {payload}"
    );
}

/// The direct cryptographic calls every row makes on its own key, each under its own IAM
/// action: the data-key pair the canonical statement covers through its `kms:GenerateDataKey*`
/// pattern, and the encryption it names outright.
fn direct_calls(key_id: &str) -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "GenerateDataKey",
            json!({"KeyId": key_id, "KeySpec": "AES_256"}),
            GENERATE_DATA_KEY_ACTION,
        ),
        (
            "GenerateDataKeyWithoutPlaintext",
            json!({"KeyId": key_id, "KeySpec": "AES_256"}),
            "kms:GenerateDataKeyWithoutPlaintext",
        ),
        (
            "Encrypt",
            json!({
                "KeyId": key_id,
                "Plaintext": aws_smithy_types::base64::encode(BODY),
            }),
            "kms:Encrypt",
        ),
    ]
}

/// One row: the key policy's cryptographic statement, and what the two halves of the contract
/// must answer under it.
struct Row {
    case: &'static str,
    /// The object this row's write stores — its own, so one row's policy cannot decide
    /// another's write.
    object_key: &'static str,
    /// The principal both statements of the document name.
    principal: String,
    /// The actions the cryptographic statement names.
    actions: Value,
    /// Its `Condition`, or [`Value::Null`] for the control row that carries none.
    condition: Value,
    /// Whether S3's envelope use of the key — the write's data key and the read's decrypt — is
    /// permitted.
    envelope: bool,
    /// Whether the SAME caller's DIRECT cryptographic call on the key is permitted.
    direct: bool,
}

/// The rows, built here because a `Condition` is a JSON document rather than a constant.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "StringEquals naming this service's regional endpoint",
            object_key: "via-this-service",
            principal: account_root(),
            actions: crypto_actions(),
            condition: json!({"StringEquals": {"kms:ViaService": endpoint("s3")}}),
            envelope: true,
            direct: false,
        },
        Row {
            case: "that same confinement, naming the calling identity itself",
            object_key: "via-this-service-named-caller",
            principal: principal(),
            actions: crypto_actions(),
            condition: json!({"StringEquals": {"kms:ViaService": endpoint("s3")}}),
            envelope: true,
            direct: false,
        },
        Row {
            case: "StringEquals naming ANOTHER service's regional endpoint",
            object_key: "via-another-service",
            principal: account_root(),
            actions: crypto_actions(),
            condition: json!({"StringEquals": {"kms:ViaService": endpoint("dynamodb")}}),
            envelope: false,
            direct: false,
        },
        Row {
            case: "StringEquals over several endpoints, this service's among them",
            object_key: "via-several-services",
            principal: account_root(),
            actions: crypto_actions(),
            condition: json!({"StringEquals": {
                "kms:ViaService": [endpoint("dynamodb"), endpoint("s3")],
            }}),
            envelope: true,
            direct: false,
        },
        Row {
            case: "StringLike wildcarding the Region of this service's endpoint",
            object_key: "via-this-service-wildcard",
            principal: account_root(),
            actions: crypto_actions(),
            condition: json!({"StringLike": {"kms:ViaService": "s3.*.amazonaws.com"}}),
            envelope: true,
            direct: false,
        },
        Row {
            case: "a set qualifier over that same comparison",
            object_key: "via-this-service-qualified",
            principal: account_root(),
            actions: crypto_actions(),
            condition: json!({"ForAnyValue:StringEquals": {"kms:ViaService": endpoint("s3")}}),
            envelope: true,
            direct: false,
        },
        Row {
            case: "this service's endpoint, on a statement naming the READ action only",
            object_key: "via-this-service-decrypt-only",
            principal: account_root(),
            actions: json!(DECRYPT_ACTION),
            condition: json!({"StringEquals": {"kms:ViaService": endpoint("s3")}}),
            envelope: false,
            direct: false,
        },
        Row {
            case: "the control: the same cryptographic statement with no condition at all",
            object_key: "unconfined",
            principal: account_root(),
            actions: crypto_actions(),
            condition: Value::Null,
            envelope: true,
            direct: true,
        },
    ]
}

/// Assert the envelope half: what the SSE-KMS write and the read of what it stored answer.
async fn assert_envelope(
    router: &MultiServiceRouter,
    row: &Row,
    key_id: &str,
    key_arn: &str,
) {
    let case = row.case;
    let headers = write_headers(key_id);
    let write = put_object(router, BUCKET, row.object_key, BODY, &headers).await;
    if row.envelope {
        assert_eq!(
            write.status,
            200,
            "case {case:?}: the SSE-KMS write must be stored, got {} with body {:?}",
            write.status,
            text(&write)
        );
        assert_eq!(
            write.header(ALGORITHM_HEADER).as_deref(),
            Some(SSE_KMS),
            "case {case:?}: expected the write to report {SSE_KMS}, got {:?}",
            write.header(ALGORITHM_HEADER)
        );
        assert_eq!(
            write.header(KEY_ID_HEADER).as_deref(),
            Some(key_arn),
            "case {case:?}: expected the write to report the key's ARN, got {:?}",
            write.header(KEY_ID_HEADER)
        );

        // The read of that object performs the key's `kms:Decrypt`, and it arrives through this
        // service too, so the same statement grants it and the stored bytes come back.
        let read = get_object(router, BUCKET, row.object_key, "", &[]).await;
        assert_eq!(
            read.status,
            200,
            "case {case:?}: the object must read back, got {} with body {:?}",
            read.status,
            text(&read)
        );
        assert_eq!(
            read.body.as_ref(),
            BODY,
            "case {case:?}: expected the stored bytes, got {:?}",
            text(&read)
        );
    } else {
        assert_refused_write(&write, case, key_arn);
        let missing = get_object(router, BUCKET, row.object_key, "", &[]).await;
        assert_eq!(
            missing.status,
            404,
            "case {case:?}: the refused write must have stored nothing, got {} with body {:?}",
            missing.status,
            text(&missing)
        );
    }
}

/// Assert one refused SSE-KMS write: S3's own 403 `AccessDenied`, carrying KMS's denial
/// sentence for the data-key action on that key.
fn assert_refused_write(write: &Answer, case: &str, key_arn: &str) {
    assert_eq!(
        write.status,
        403,
        "case {case:?}: the SSE-KMS write must be refused, got {} with body {:?}",
        write.status,
        text(write)
    );
    assert_eq!(
        write.error_code(),
        ACCESS_DENIED,
        "case {case:?}: expected the {ACCESS_DENIED:?} code, got {:?}",
        text(write)
    );
    assert_eq!(
        write.error_message(),
        denial_sentence(GENERATE_DATA_KEY_ACTION, key_arn),
        "case {case:?}: expected KMS's denial sentence, got {:?}",
        write.error_message()
    );
}

#[tokio::test]
async fn a_via_service_confined_key_serves_the_envelope_and_refuses_the_direct_call() {
    let router = router_with_kms();
    bucket(&router, BUCKET).await;

    for row in rows() {
        let case = row.case;
        let (key_id, key_arn) = created_key(&router, case).await;
        put_key_policy(
            &router,
            case,
            &key_id,
            &confinement(&row.principal, row.actions.clone(), row.condition.clone()),
        )
        .await;

        assert_envelope(&router, &row, &key_id, &key_arn).await;

        // The same caller, the same key, the same policy — straight to KMS, where the request
        // carries no value for the condition key the statement compares.
        for (operation, request, action) in direct_calls(&key_id) {
            if row.direct {
                let answer = assert_direct_served(&router, case, operation, &request).await;
                if operation == "GenerateDataKey" {
                    assert_data_key_opens(&router, case, &answer).await;
                }
            } else {
                assert_direct_refusal(&router, case, operation, &request, action, &key_arn).await;
            }
        }
    }
}

#[tokio::test]
async fn the_direct_refusal_lifts_and_returns_with_the_statement_that_grants_it() {
    let case = "the confinement is decided from the policy in force";
    let router = router_with_kms();
    let name = "sse-kms-via-service-lift";
    bucket(&router, name).await;
    let (key_id, key_arn) = created_key(&router, case).await;

    let condition = json!({"StringEquals": {"kms:ViaService": endpoint("s3")}});
    let confined = confinement(&account_root(), crypto_actions(), condition.clone());
    // The same document with an unconditioned grant of the data-key action beside the confined
    // statement: the one change that lets the caller reach the key directly.
    let also_unconditioned = policy(vec![
        statement(&account_root(), "Allow", admin_actions(), Value::Null),
        statement(
            &account_root(),
            "Allow",
            crypto_actions(),
            condition.clone(),
        ),
        statement(
            &account_root(),
            "Allow",
            json!(GENERATE_DATA_KEY_ACTION),
            Value::Null,
        ),
    ]);

    let data_key = json!({"KeyId": key_id.clone(), "KeySpec": "AES_256"});
    let headers = write_headers(&key_id);

    put_key_policy(&router, case, &key_id, &confined).await;
    let first = put_object(&router, name, "first.bin", BODY, &headers).await;
    assert_eq!(
        first.status,
        200,
        "case {case:?}: the envelope write must be stored under the confined policy, got {} with \
         body {:?}",
        first.status,
        text(&first)
    );
    assert_direct_refusal(
        &router,
        case,
        "GenerateDataKey",
        &data_key,
        GENERATE_DATA_KEY_ACTION,
        &key_arn,
    )
    .await;

    // The very next direct call is served once the unconditioned grant is attached, with no
    // other call in between: the decision is taken from the document in force each time.
    put_key_policy(&router, case, &key_id, &also_unconditioned).await;
    assert_direct_served(&router, case, "GenerateDataKey", &data_key).await;
    let second = put_object(&router, name, "second.bin", BODY, &headers).await;
    assert_eq!(
        second.status,
        200,
        "case {case:?}: the envelope write must still be stored, got {} with body {:?}",
        second.status,
        text(&second)
    );

    // And it is refused again the moment that grant is withdrawn, so nothing about the first
    // refusal was remembered.
    put_key_policy(&router, case, &key_id, &confined).await;
    assert_direct_refusal(
        &router,
        case,
        "GenerateDataKey",
        &data_key,
        GENERATE_DATA_KEY_ACTION,
        &key_arn,
    )
    .await;
    let third = put_object(&router, name, "third.bin", BODY, &headers).await;
    assert_eq!(
        third.status,
        200,
        "case {case:?}: the envelope write must still be stored, got {} with body {:?}",
        third.status,
        text(&third)
    );
    let read = get_object(&router, name, "third.bin", "", &[]).await;
    assert_eq!(
        read.body.as_ref(),
        BODY,
        "case {case:?}: expected the stored bytes, got {:?}",
        text(&read)
    );
}
