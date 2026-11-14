// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for the expression a `@pattern` refusal of this service QUOTES.
//!
//! Every case goes through the real front door — `MultiServiceRouter::dispatch` with a
//! restJson1 request, exactly as a signed `aws ivs-realtime` call arrives — so what it
//! asserts is the emulator's HTTP behaviour, not a handler called directly.
//!
//! The rule under test, stated once and then exercised over a SET of inputs: a member
//! whose value breaks its modelled `@pattern` is refused with the modelled
//! `ValidationException` (HTTP 400) stating `<Operation>.<member path> does not match the
//! required pattern <expression>`, where the expression is the one the WHOLE value has to
//! match. A Smithy `@pattern` is a partial match, so an expression that already pins both
//! of its ends is quoted as the model declares it, while an end the expression leaves open
//! is quoted with the unconstrained run that end admits and then anchored. No value from
//! the request is echoed, and a refused call persists nothing.
//!
//! Each modelled expression a row names comes from
//! `smithy_query(query="shape", shape="<shape>")`.

use std::sync::Arc;

use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_ivsrealtime_amazoninteractivevideoservicerealtime::EmulatedService;

/// The region every case here is signed for.
const REGION: &str = "us-east-1";

/// `PublicKeyMaterial`'s modelled expression, which pins NEITHER end.
const PUBLIC_KEY_MATERIAL_PATTERN: &str =
    r"-----BEGIN PUBLIC KEY-----\r?\n([a-zA-Z0-9+/=\r\n]+)\r?\n-----END PUBLIC KEY-----(\r?\n)?";

/// `PublicKeyName`'s modelled expression, which pins both ends. `StageName` and
/// `AttributeKey` declare the same one.
const NAME_PATTERN: &str = "^[a-zA-Z0-9-_]*$";

/// `PublicKeyArn`'s modelled expression, which pins both ends.
const PUBLIC_KEY_ARN_PATTERN: &str = "^arn:aws:ivs:[a-z0-9-]+:[0-9]+:public-key/[a-zA-Z0-9-]+$";

/// `StageArn`'s modelled expression, which pins both ends.
const STAGE_ARN_PATTERN: &str = "^arn:aws:ivs:[a-z0-9-]+:[0-9]+:stage/[a-zA-Z0-9-]+$";

/// `S3StorageConfiguration$bucketName`'s modelled expression, which pins both ends.
const BUCKET_NAME_PATTERN: &str = "^[a-z0-9-.]+$";

/// `PaginationToken`'s modelled expression, which pins both ends.
const PAGINATION_TOKEN_PATTERN: &str = "^[a-zA-Z0-9+/=_-]*$";

/// One IVS RealTime emulator over one shared engine, reached the way the router reaches
/// it.
///
/// Each suite under `tests/all/` is its own private module, so this is the per-suite copy
/// of that two-line harness rather than a shared one.
struct RealTime {
    router: MultiServiceRouter,
}

/// One answer from the emulator: the status, the wire error code (the restJson1 `__type`
/// discriminator), the stated message and the parsed body.
struct Reply {
    status: u16,
    error_code: String,
    message: String,
    body: Value,
}

impl RealTime {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        router.register_service(EmulatedService::new(engine));
        Self { router }
    }

    /// Call `operation` as an SDK does: `POST /<operation>`, signed for [`REGION`].
    async fn call(&self, operation: &str, body: &Value) -> Reply {
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential=AKIDTESTIVS/20260101/{REGION}/ivs/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=00"
        );
        let request = http::Request::builder()
            .method("POST")
            .uri(format!(
                "https://ivsrealtime.{REGION}.amazonaws.com/{operation}"
            ))
            .header("content-type", "application/json")
            .header("authorization", authorization)
            .body(bytes::Bytes::from(body.to_string()))
            .expect("the test request is well formed");
        let response = self.router.dispatch(request).await;
        let status = response.status().as_u16();
        let parsed: Value = if response.body().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(response.body()).unwrap_or(Value::Null)
        };
        Reply {
            status,
            error_code: text(&parsed, "__type"),
            message: text(&parsed, "message"),
            body: parsed,
        }
    }

    /// Call `operation` and require it to have succeeded.
    async fn ok(&self, case: &str, operation: &str, body: Value) -> Value {
        let reply = self.call(operation, &body).await;
        assert_eq!(
            reply.status, 200,
            "case {case:?} ({operation}): expected HTTP 200, got {} {}",
            reply.status, reply.body
        );
        reply.body
    }

    /// The ARNs `ListPublicKeys` reports, in the order it reports them.
    async fn held_public_keys(&self, case: &str) -> Vec<String> {
        let listed = self.ok(case, "ListPublicKeys", json!({})).await;
        listed["publicKeys"]
            .as_array()
            .map(|keys| keys.iter().map(|key| text(key, "arn")).collect())
            .unwrap_or_default()
    }
}

/// A string member, read as the empty string when absent — which is what a client sees for
/// a member the wire omits.
fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// A fresh ECDSA P-384 public key as the PEM `SubjectPublicKeyInfo` block
/// `openssl ... -pubout` writes.
///
/// Generated rather than hard-coded, so what the positive control imports is a real public
/// key.
fn fresh_material() -> String {
    let der = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
        .expect("the test key pair is generated")
        .public_key_der();
    pem::encode(&pem::Pem::new("PUBLIC KEY", der)).replace("\r\n", "\n")
}

/// The clause this service states for a `@pattern` violation: the operation, the dotted
/// member path and the expression the whole value has to match.
fn pattern_clause(operation: &str, member: &str, expression: &str) -> String {
    format!("{operation}.{member} does not match the required pattern {expression}")
}

/// The whole-value expression for a declared one that leaves BOTH ends open: the run each
/// open end admits, anchored.
fn opened_at_both_ends(declared: &str) -> String {
    format!("^.*{declared}.*$")
}

/// Rule: a `@pattern` refusal quotes the expression the whole value has to match.
///
/// The rows differ along what the rule generalises over: which ends the declared
/// expression pins, the operation and member carrying the value, whether the member is
/// required or optional, whether its path is a top-level member or a nested one, and
/// whether the value arrives in a create, a read or a listing.
#[tokio::test]
async fn a_pattern_refusal_quotes_the_expression_the_whole_value_must_match() {
    let realtime = RealTime::new();

    // (case, operation, request, member path, the expression the clause must quote)
    let rows: Vec<(&str, &str, Value, &str, String)> = vec![
        (
            "material whose declared expression pins neither end",
            "ImportPublicKey",
            json!({ "publicKeyMaterial": "not-a-pem-key" }),
            "publicKeyMaterial",
            opened_at_both_ends(PUBLIC_KEY_MATERIAL_PATTERN),
        ),
        (
            "a public-key name whose declared expression pins both ends",
            "ImportPublicKey",
            json!({ "publicKeyMaterial": fresh_material(), "name": "bad name!" }),
            "name",
            NAME_PATTERN.to_string(),
        ),
        (
            "a stage name whose declared expression pins both ends",
            "CreateStage",
            json!({ "name": "not a legal name!" }),
            "name",
            NAME_PATTERN.to_string(),
        ),
        (
            "a public-key ARN read back by a shape whose expression pins both ends",
            "GetPublicKey",
            json!({ "arn": "not-an-arn" }),
            "arn",
            PUBLIC_KEY_ARN_PATTERN.to_string(),
        ),
        (
            "a stage ARN carried by a token request",
            "CreateParticipantToken",
            json!({ "stageArn": "not-an-arn" }),
            "stageArn",
            STAGE_ARN_PATTERN.to_string(),
        ),
        (
            "a nested member, whose path the clause spells with a dot",
            "CreateStorageConfiguration",
            json!({ "name": "recordings", "s3": { "bucketName": "Studio_Recordings" } }),
            "s3.bucketName",
            BUCKET_NAME_PATTERN.to_string(),
        ),
        (
            "a pagination token offered to a listing",
            "ListPublicKeys",
            json!({ "nextToken": "not a token!" }),
            "nextToken",
            PAGINATION_TOKEN_PATTERN.to_string(),
        ),
    ];

    for (case, operation, request, member, expression) in rows {
        let reply = realtime.call(operation, &request).await;
        let expected = pattern_clause(operation, member, &expression);
        assert_eq!(
            (
                reply.status,
                reply.error_code.as_str(),
                reply.message.as_str()
            ),
            (400, "ValidationException", expected.as_str()),
            "case {case:?}: expected the stated refusal {expected:?}, got {} {} {}",
            reply.status,
            reply.error_code,
            reply.body
        );
    }
}

/// The same rule, over the VALUES one member can be refused for: the quoted expression is
/// the member's, so it does not move with the value offered, and the value itself is never
/// echoed.
///
/// The rows differ in HOW the material misses the expression: text that is no key at all,
/// a block of another label, a block missing its closing line, a body carrying characters
/// the expression's class excludes, and the empty string.
#[tokio::test]
async fn the_quoted_expression_is_the_members_and_echoes_no_submitted_value() {
    let realtime = RealTime::new();
    let expected = pattern_clause(
        "ImportPublicKey",
        "publicKeyMaterial",
        &opened_at_both_ends(PUBLIC_KEY_MATERIAL_PATTERN),
    );
    let held = realtime.held_public_keys("before the refusals").await;

    let body = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE";
    let rows: Vec<(&str, String)> = vec![
        ("text that is no key at all", "not-a-pem-key".to_string()),
        (
            "a PEM block of another label",
            format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"),
        ),
        (
            "a block missing its closing line",
            format!("-----BEGIN PUBLIC KEY-----\n{body}\n"),
        ),
        (
            "a body carrying characters the expression excludes",
            "-----BEGIN PUBLIC KEY-----\nnot base64 at all!\n-----END PUBLIC KEY-----\n"
                .to_string(),
        ),
        ("the empty string", String::new()),
    ];

    for (case, material) in rows {
        let reply = realtime
            .call(
                "ImportPublicKey",
                &json!({ "publicKeyMaterial": material.clone() }),
            )
            .await;
        assert_eq!(
            (
                reply.status,
                reply.error_code.as_str(),
                reply.message.as_str()
            ),
            (400, "ValidationException", expected.as_str()),
            "case {case:?}: expected the stated refusal {expected:?}, got {} {} {}",
            reply.status,
            reply.error_code,
            reply.body
        );
        assert!(
            material.is_empty() || !reply.message.contains(material.as_str()),
            "case {case:?}: the refusal must echo no submitted value, got {:?}",
            reply.message
        );

        // The refused call persisted nothing: the keys the service holds are exactly the
        // ones it held before it.
        let after = realtime.held_public_keys(case).await;
        assert_eq!(
            after, held,
            "case {case:?}: a refused import must persist nothing, expected the held keys \
             {held:?}, got {after:?}"
        );
    }
}

/// The other side of the rule: material the expression ADMITS is imported, under the name
/// the request asked for, and reads back through `GetPublicKey`.
#[tokio::test]
async fn material_the_expression_admits_is_imported_and_reads_back() {
    let realtime = RealTime::new();

    for (case, name) in [
        ("a named import", "signing-key_1"),
        ("an import with the name omitted", ""),
    ] {
        let mut request = json!({ "publicKeyMaterial": fresh_material() });
        if !name.is_empty() {
            request["name"] = json!(name);
        }
        let imported = realtime.ok(case, "ImportPublicKey", request).await;
        let public_key = imported["publicKey"].clone();
        assert_eq!(
            text(&public_key, "name"),
            name,
            "case {case:?}: expected the name the request asked for, got {public_key}"
        );

        let arn = text(&public_key, "arn");
        let read = realtime
            .ok(case, "GetPublicKey", json!({ "arn": arn }))
            .await;
        assert_eq!(
            read["publicKey"], public_key,
            "case {case:?}: the read must answer the key as imported, expected \
             {public_key}, got {read}"
        );
    }
}
