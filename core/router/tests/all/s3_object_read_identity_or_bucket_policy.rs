// SPDX-License-Identifier: CC0-1.0

//! What authorizes an object READ for a same-account IAM USER principal: the UNION of the
//! documents in force on it.
//!
//! RULE: Amazon S3 decides a signed object read against the identity-based policies in force
//! on the principal the presented access key id speaks for AND against the bucket's own
//! policy, before it reports anything about the object — an `Allow` of the read in EITHER
//! document suffices for a principal of the bucket's own account, an explicit `Deny` in either
//! refuses whatever the other says, and a read NEITHER allows is answered HTTP 403
//! `AccessDenied` with IAM's one sentence — the caller's principal ARN, the action the read
//! asks for and the object's ARN, double-quoted — and no object bytes. The same verdict IAM's
//! own simulator reports for that principal, that action and that object with the bucket policy
//! supplied as the resource-based document, is the one S3 enforces.
//!
//! Only a cross-service suite can pin it: IAM holds the users, their inline documents and the
//! access keys they sign with, STS resolves which principal a key speaks for, and S3 takes the
//! decision and serves (or withholds) the bytes — so a crate-local suite can only ever see one
//! side of the union, and could not compare enforcement with the simulator at all.
//!
//! The rows span what the rule generalises over: WHICH document carries the grant (the
//! identity's, the bucket's, both, neither), WHICH resource the grant names (every resource,
//! every object of this bucket, the one object addressed, another bucket's objects), WHICH
//! action it names (the read itself, a wildcard run, an unrelated S3 action), WHICH principal
//! the bucket policy names and in which spelling (this one alone, this one among a list,
//! another one), and which of IAM's two refusing
//! rules decides (an explicit deny in either document, and the implicit deny of no grant at
//! all).
//!
//! The per-service halves live beside their own services: S3's own refusal wording and the
//! bucket-policy half of the same decision are that crate's tests, and IAM's simulation of the
//! union is `tests/all/simulated_resource_policy.rs` there.

use std::sync::Arc;

use bytes::Bytes;
use smithy_server_runtime::MultiServiceRouter;

use crate::query_wire::{element, elements, form_encode, opt_element};

/// The account every generated emulator presents (`engine::EMULATOR_ACCOUNT_ID`), which owns
/// every bucket and every user this suite creates.
const ACCOUNT: &str = "000000000000";

/// The Region every request here signs for.
const REGION: &str = "us-east-1";

/// The long-term key every emulator publishes: the account's own credential, which no
/// identity-based document bounds, so every fixture call is made with it and no row's own
/// credential decides the setup.
const AMBIENT_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// The IAM API version an awsQuery call to IAM names.
const IAM_API_VERSION: &str = "2010-05-08";

/// The key the object every row reads is stored under, and the bytes it holds: a read that is
/// served must answer exactly these.
const OBJECT_KEY: &str = "reports/june.csv";
const OBJECT_BODY: &str = "region,amount\nus-east-1,17\n";

/// The action an object read that names no version is authorized under: "if you request the
/// current version of an object without a specific `versionId` in the request header, only the
/// `s3:GetObject` permission is required" (`GetObject`'s own documentation, read through
/// `smithy_query(query="doc",shape="com.amazonaws.s3#GetObject")`).
const GET_OBJECT: &str = "s3:GetObject";

/// An S3 action that is NOT the read, used by the row whose only grant names another action:
/// the write `PutObject`'s own documentation names ("you must have the `s3:PutObject`
/// permission").
const PUT_OBJECT: &str = "s3:PutObject";

/// The name the one inline document a row puts in force on its user is embedded under.
const POLICY_NAME: &str = "in-force";

/// The `EvalDecision` values IAM's simulator reports for the two verdicts this suite compares
/// against enforcement (`SimulatePrincipalPolicy$EvaluationResults`).
const ALLOWED: &str = "allowed";
const IMPLICIT_DENY: &str = "implicitDeny";

/// IAM, STS and Amazon S3 over ONE engine, exactly as `core/router/src/lib.rs` mounts them: the
/// users and documents IAM stores are the ones S3 decides a read against, and the access keys
/// IAM mints are the ones both resolve the caller from.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    // The signatures below are not real ones; what names the caller is the access key id in the
    // credential scope, which is what this suite varies.
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_iam_awsidentitymanagementv20100508::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(
        service_com_amazonaws_sts_awssecuritytokenservicev20110615::EmulatedService::new(
            Arc::clone(&engine),
        ),
    );
    router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
        engine,
    ));
    router
}

/// A SigV4 `Authorization` header whose credential scope names `signing_name` and whose
/// credential is `access_key_id` — the key a service reads the caller's identity from.
fn authorization(access_key_id: &str, signing_name: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/20260101/{REGION}/{signing_name}/\
         aws4_request, SignedHeaders=host, Signature=not-verified"
    )
}

/// One request, signed as `access_key_id` for `signing_name`, answered as `(status, body)`.
async fn dispatch(
    router: &MultiServiceRouter,
    access_key_id: &str,
    signing_name: &str,
    method: &str,
    path: &str,
    content_type: &str,
    body: &str,
) -> (u16, String) {
    let host = format!("{signing_name}.{REGION}.amazonaws.com");
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("host", host)
        .header("content-type", content_type)
        .header("authorization", authorization(access_key_id, signing_name))
        .body(Bytes::from(body.to_owned()))
        .expect("the test request builds");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(response.body()).to_string())
}

/// One S3 call on the path-style address, presented as signed by `access_key_id`.
async fn s3(
    router: &MultiServiceRouter,
    access_key_id: &str,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String) {
    dispatch(
        router,
        access_key_id,
        "s3",
        method,
        path,
        "application/xml",
        body,
    )
    .await
}

/// One IAM awsQuery call as the account's own credential, every component percent-encoded so a
/// policy document travels verbatim.
async fn iam(
    router: &MultiServiceRouter,
    action: &str,
    members: &[(&str, &str)],
) -> (u16, String) {
    let mut body = format!("Action={action}&Version={IAM_API_VERSION}");
    for (name, value) in members {
        body.push('&');
        body.push_str(&form_encode(name));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    dispatch(
        router,
        AMBIENT_KEY,
        "iam",
        "POST",
        "/",
        "application/x-www-form-urlencoded",
        &body,
    )
    .await
}

/// [`iam`], asserted served, for a fixture whose answer carries no credential material.
async fn iam_fixture(
    router: &MultiServiceRouter,
    case: &str,
    action: &str,
    members: &[(&str, &str)],
) -> String {
    let (status, body) = iam(router, action, members).await;
    assert_eq!(
        status, 200,
        "case {case:?}: the fixture {action} must be served, got {status}: {body}"
    );
    body
}

/// Create `user_name`, put `document` in force on it where a row names one, mint its long-term
/// access key, and answer `(the user's ARN, that key's id)`.
///
/// The `CreateAccessKey` answer CARRIES CREDENTIAL MATERIAL, so nothing here quotes it — not
/// even on a failure, which names the case and what it looked for instead.
async fn user_signing_key(
    router: &MultiServiceRouter,
    case: &str,
    user_name: &str,
    document: Option<&str>,
) -> (String, String) {
    let created = iam_fixture(router, case, "CreateUser", &[("UserName", user_name)]).await;
    let arn = element(&created, "Arn");
    if let Some(document) = document {
        iam_fixture(
            router,
            case,
            "PutUserPolicy",
            &[
                ("UserName", user_name),
                ("PolicyName", POLICY_NAME),
                ("PolicyDocument", document),
            ],
        )
        .await;
    }
    let (status, minted) = iam(router, "CreateAccessKey", &[("UserName", user_name)]).await;
    assert_eq!(
        status, 200,
        "case {case:?}: the fixture CreateAccessKey must be served, got {status}"
    );
    let access_key_id = opt_element(&minted, "AccessKeyId").unwrap_or_else(|| {
        panic!("case {case:?}: the minted-credential answer carries no <AccessKeyId> element")
    });
    (arn, access_key_id)
}

/// Create `bucket` and store [`OBJECT_BODY`] at [`OBJECT_KEY`] in it, as the account's own
/// credential — so what a row decides is the row's principal's access and nothing else.
async fn bucket_holding_the_object(router: &MultiServiceRouter, case: &str, bucket: &str) {
    let (status, body) = s3(router, AMBIENT_KEY, "PUT", &format!("/{bucket}"), "").await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateBucket must be served, got {status}: {body}"
    );
    let (status, body) = s3(
        router,
        AMBIENT_KEY,
        "PUT",
        &format!("/{bucket}/{OBJECT_KEY}"),
        OBJECT_BODY,
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: PutObject must be served, got {status}: {body}"
    );
}

/// `PUT /<bucket>?policy` — S3's `PutBucketPolicy`, as the account's own credential.
async fn put_bucket_policy(
    router: &MultiServiceRouter,
    case: &str,
    bucket: &str,
    document: &str,
) {
    let (status, body) = s3(
        router,
        AMBIENT_KEY,
        "PUT",
        &format!("/{bucket}?policy"),
        document,
    )
    .await;
    assert_eq!(
        status, 204,
        "case {case:?}: PutBucketPolicy must be served, got {status}: {body}"
    );
}

/// The ARN a policy and a refusal name the object addressed by.
fn object_arn(bucket: &str) -> String {
    format!("arn:aws:s3:::{bucket}/{OBJECT_KEY}")
}

/// The ARN a bucket policy scopes a grant over every object of the bucket by.
fn every_object_arn(bucket: &str) -> String {
    format!("arn:aws:s3:::{bucket}/*")
}

/// One identity-based document: no principal element, since the identity it is embedded in IS
/// the principal.
fn identity_document(effect: &str, action: &str, resource: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"{effect}","Action":"{action}","Resource":"{resource}"}}]}}"#
    )
}

/// An identity-based document allowing every action everywhere, beside an explicit `Deny` of
/// the read: the row that pins that a deny in the identity's own document is not lifted by a
/// grant in the bucket's.
fn identity_allow_all_but_the_read() -> String {
    format!(
        concat!(
            r#"{{"Version":"2012-10-17","Statement":["#,
            r#"{{"Effect":"Allow","Action":"*","Resource":"*"}},"#,
            r#"{{"Effect":"Deny","Action":"{}","Resource":"*"}}]}}"#
        ),
        GET_OBJECT
    )
}

/// One bucket policy statement: a resource-based document states WHO it is about, so every
/// statement names its principals — `principal` is written into the `Principal` element as the
/// row spells it.
fn bucket_document(effect: &str, principal: &str, resource: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"{effect}","Principal":{principal},"Action":"{GET_OBJECT}","Resource":"{resource}"}}]}}"#
    )
}

/// What a row's identity-based document says about the read.
#[derive(Debug, Clone, Copy)]
enum Identity {
    /// No inline document at all.
    Nothing,
    /// The read, over every object of the bucket addressed.
    AllowsOnThisBucket,
    /// The read, over the ONE object addressed.
    AllowsOnThisObject,
    /// The read, over another bucket's objects.
    AllowsOnAnotherBucket,
    /// Every action, over every resource.
    AllowsEverything,
    /// Another S3 action, over every object of the bucket addressed.
    AllowsAnotherAction,
    /// Every action everywhere, beside an explicit `Deny` of the read.
    AllowsEverythingButDeniesTheRead,
}

/// What a row's BUCKET policy says about the read.
#[derive(Debug, Clone, Copy)]
enum Resource {
    /// The bucket carries no policy.
    Nothing,
    /// The read, granted to the row's own principal.
    AllowsThisPrincipal,
    /// The read, granted to another principal of the same account.
    AllowsAnotherPrincipal,
    /// The read, granted to a LIST of principals this one is among.
    AllowsThisPrincipalAmongSeveral,
    /// The read, explicitly denied to the row's own principal.
    DeniesThisPrincipal,
}

/// What the policies in force must make of a row's read.
#[derive(Debug, Clone, Copy)]
enum Expected {
    /// The object's exact bytes.
    Served,
    /// HTTP 403 `AccessDenied`, whose sentence closes with this reason clause.
    Denied(Reason),
}

/// Which of IAM's refusing rules decided, as the refusal's closing clause words it.
#[derive(Debug, Clone, Copy)]
enum Reason {
    /// Nothing in force allowed the read — IAM's implicit deny.
    NoGrant,
    /// A statement of the IDENTITY's own documents said `Deny`.
    IdentityDeny,
    /// A statement of the BUCKET's own policy said `Deny`.
    ResourceDeny,
}

impl Reason {
    /// The clause closing the sentence; the withheld-grant one names the action it was withheld
    /// for.
    fn clause(self) -> String {
        match self {
            Self::NoGrant => {
                format!("because no identity-based policy allows the {GET_OBJECT} action")
            }
            Self::IdentityDeny => "with an explicit deny in an identity-based policy".to_string(),
            Self::ResourceDeny => "with an explicit deny in a resource-based policy".to_string(),
        }
    }
}

/// One row of the union table.
struct Row {
    case: &'static str,
    identity: Identity,
    resource: Resource,
    expected: Expected,
}

/// The rows the rule is asserted over: each gets its own bucket, its own user and its own
/// bucket policy, so one row's documents decide only that row's read.
const ROWS: &[Row] = &[
    Row {
        case: "neither document mentions the read",
        identity: Identity::Nothing,
        resource: Resource::Nothing,
        expected: Expected::Denied(Reason::NoGrant),
    },
    Row {
        case: "the identity policy alone, over every object of the bucket",
        identity: Identity::AllowsOnThisBucket,
        resource: Resource::Nothing,
        expected: Expected::Served,
    },
    Row {
        case: "the identity policy alone, over the one object addressed",
        identity: Identity::AllowsOnThisObject,
        resource: Resource::Nothing,
        expected: Expected::Served,
    },
    Row {
        case: "the identity policy alone, over every action and every resource",
        identity: Identity::AllowsEverything,
        resource: Resource::Nothing,
        expected: Expected::Served,
    },
    Row {
        case: "the identity policy names another bucket's objects",
        identity: Identity::AllowsOnAnotherBucket,
        resource: Resource::Nothing,
        expected: Expected::Denied(Reason::NoGrant),
    },
    Row {
        case: "the identity policy names another action on this bucket",
        identity: Identity::AllowsAnotherAction,
        resource: Resource::Nothing,
        expected: Expected::Denied(Reason::NoGrant),
    },
    Row {
        case: "the bucket policy alone names this principal",
        identity: Identity::Nothing,
        resource: Resource::AllowsThisPrincipal,
        expected: Expected::Served,
    },
    Row {
        case: "the bucket policy alone lists this principal among several",
        identity: Identity::Nothing,
        resource: Resource::AllowsThisPrincipalAmongSeveral,
        expected: Expected::Served,
    },
    Row {
        case: "the bucket policy alone names another principal",
        identity: Identity::Nothing,
        resource: Resource::AllowsAnotherPrincipal,
        expected: Expected::Denied(Reason::NoGrant),
    },
    Row {
        case: "both documents allow the read",
        identity: Identity::AllowsOnThisBucket,
        resource: Resource::AllowsThisPrincipal,
        expected: Expected::Served,
    },
    Row {
        case: "the bucket policy denies the principal its identity policy allows",
        identity: Identity::AllowsEverything,
        resource: Resource::DeniesThisPrincipal,
        expected: Expected::Denied(Reason::ResourceDeny),
    },
    Row {
        case: "the identity policy denies the read the bucket policy grants",
        identity: Identity::AllowsEverythingButDeniesTheRead,
        resource: Resource::AllowsThisPrincipal,
        expected: Expected::Denied(Reason::IdentityDeny),
    },
];

/// The document a row's identity carries, filled with that row's own bucket.
fn identity_policy_of(identity: Identity, bucket: &str, other_bucket: &str) -> Option<String> {
    match identity {
        Identity::Nothing => None,
        Identity::AllowsOnThisBucket => Some(identity_document(
            "Allow",
            GET_OBJECT,
            &every_object_arn(bucket),
        )),
        Identity::AllowsOnThisObject => {
            Some(identity_document("Allow", GET_OBJECT, &object_arn(bucket)))
        }
        Identity::AllowsOnAnotherBucket => Some(identity_document(
            "Allow",
            GET_OBJECT,
            &every_object_arn(other_bucket),
        )),
        Identity::AllowsEverything => Some(identity_document("Allow", "*", "*")),
        Identity::AllowsAnotherAction => Some(identity_document(
            "Allow",
            PUT_OBJECT,
            &every_object_arn(bucket),
        )),
        Identity::AllowsEverythingButDeniesTheRead => Some(identity_allow_all_but_the_read()),
    }
}

/// The policy a row's bucket carries, filled with that row's own principals.
fn bucket_policy_of(
    resource: Resource,
    bucket: &str,
    user_arn: &str,
    other_user_arn: &str,
) -> Option<String> {
    let every_object = every_object_arn(bucket);
    match resource {
        Resource::Nothing => None,
        Resource::AllowsThisPrincipal => Some(bucket_document(
            "Allow",
            &format!(r#"{{"AWS":"{user_arn}"}}"#),
            &every_object,
        )),
        Resource::AllowsAnotherPrincipal => Some(bucket_document(
            "Allow",
            &format!(r#"{{"AWS":"{other_user_arn}"}}"#),
            &every_object,
        )),
        Resource::AllowsThisPrincipalAmongSeveral => Some(bucket_document(
            "Allow",
            &format!(r#"{{"AWS":["{other_user_arn}","{user_arn}"]}}"#),
            &every_object,
        )),
        Resource::DeniesThisPrincipal => Some(bucket_document(
            "Deny",
            &format!(r#"{{"AWS":"{user_arn}"}}"#),
            &every_object,
        )),
    }
}

/// The whole sentence a withheld read is refused with: who, which action, which object —
/// double-quoted — and why.
fn expected_sentence(user_arn: &str, bucket: &str, reason: Reason) -> String {
    format!(
        "User: {user_arn} is not authorized to perform: {GET_OBJECT} on resource: \"{}\" {}",
        object_arn(bucket),
        reason.clause()
    )
}

/// The text of an error element, with the serializer's entity escaping undone — the reader
/// `query_wire` owns for exactly that ([`elements`]) — or a stand-in naming the element an
/// answer did not carry, so a failure quotes what was looked for.
fn first_element(body: &str, name: &str) -> String {
    elements(body, name)
        .into_iter()
        .next()
        .unwrap_or_else(|| format!("<no {name}>"))
}

/// Assert one read was refused with S3's authorization answer, carrying `reason`'s sentence and
/// none of the object's bytes.
fn assert_refused(
    case: &str,
    status: u16,
    body: &str,
    user_arn: &str,
    bucket: &str,
    reason: Reason,
) {
    assert_eq!(
        status, 403,
        "case {case:?}: expected HTTP 403 for a read no document allows, got {status}: {body}"
    );
    // Read through the DECODING reader: S3's XML serializer escapes the quotation marks the
    // sentence puts around the resource, so the element's text is compared as the service wrote
    // the sentence rather than as its escaping.
    let code = first_element(body, "Code");
    assert_eq!(
        code, "AccessDenied",
        "case {case:?}: expected the AccessDenied code, got {code:?} with {body}"
    );
    let message = first_element(body, "Message");
    assert_eq!(
        message,
        expected_sentence(user_arn, bucket, reason),
        "case {case:?}: expected IAM's sentence for this decision, got {message:?}"
    );
    assert!(
        !body.contains(OBJECT_BODY),
        "case {case:?}: a refused read must carry no object bytes, got {body}"
    );
}

/// RULE: an object read is served exactly when the identity's own documents OR the bucket's own
/// policy allow it and neither denies it, and a read neither allows is answered 403
/// `AccessDenied` with IAM's sentence and no bytes.
#[tokio::test]
async fn an_object_read_is_allowed_by_either_the_identity_or_the_bucket_policy() {
    let router = build_router();
    // The principal a row's "another principal" statements name: one real user of the same
    // account, so such a statement is a grant to SOMEBODY and not a malformed one.
    let (bystander_arn, _bystander_key) =
        user_signing_key(&router, "the bystander principal", "union-bystander", None).await;

    let mut served = 0_usize;
    let mut refused = 0_usize;
    for (index, row) in ROWS.iter().enumerate() {
        let bucket = format!("union-row-{index}-{ACCOUNT}");
        let other_bucket = format!("union-other-{index}-{ACCOUNT}");
        bucket_holding_the_object(&router, row.case, &bucket).await;

        let identity = identity_policy_of(row.identity, &bucket, &other_bucket);
        let (user_arn, access_key_id) = user_signing_key(
            &router,
            row.case,
            &format!("union-reader-{index}"),
            identity.as_deref(),
        )
        .await;
        if let Some(document) = bucket_policy_of(row.resource, &bucket, &user_arn, &bystander_arn) {
            put_bucket_policy(&router, row.case, &bucket, &document).await;
        }

        let (status, body) = s3(
            &router,
            &access_key_id,
            "GET",
            &format!("/{bucket}/{OBJECT_KEY}"),
            "",
        )
        .await;
        match row.expected {
            Expected::Served => {
                served += 1;
                assert_eq!(
                    (status, body.as_str()),
                    (200, OBJECT_BODY),
                    "case {:?}: expected the object's exact bytes, got {status}: {body:?}",
                    row.case
                );
            }
            Expected::Denied(reason) => {
                refused += 1;
                assert_refused(row.case, status, &body, &user_arn, &bucket, reason);
            }
        }
    }
    assert!(
        served > 0 && refused > 0,
        "the table must drive both served and refused reads, got {served} served and {refused} \
         refused"
    );
}

/// One `SimulatePrincipalPolicy` of `principal_arn` for the read of `bucket`'s object, with
/// `resource_policy` supplied as the resource-based document where one is in force, answered as
/// the `EvalDecision` the simulator reports.
async fn simulated_decision(
    router: &MultiServiceRouter,
    case: &str,
    principal_arn: &str,
    bucket: &str,
    resource_policy: Option<&str>,
) -> String {
    let object = object_arn(bucket);
    let mut members: Vec<(&str, &str)> = vec![
        ("PolicySourceArn", principal_arn),
        ("ActionNames.member.1", GET_OBJECT),
        ("ResourceArns.member.1", object.as_str()),
    ];
    if let Some(document) = resource_policy {
        members.push(("ResourcePolicy", document));
    }
    let (status, body) = iam(router, "SimulatePrincipalPolicy", &members).await;
    assert_eq!(
        status, 200,
        "case {case:?}: SimulatePrincipalPolicy must be served, got {status}: {body}"
    );
    let decisions = elements(&body, "EvalDecision");
    assert_eq!(
        decisions.len(),
        1,
        "case {case:?}: expected one EvalDecision for the one action asked about, got \
         {decisions:?}"
    );
    decisions.into_iter().next().expect("one decision")
}

/// Read the object as `access_key_id` and assert it was served the exact bytes.
async fn assert_served(router: &MultiServiceRouter, case: &str, access_key_id: &str, bucket: &str) {
    let (status, body) = s3(
        router,
        access_key_id,
        "GET",
        &format!("/{bucket}/{OBJECT_KEY}"),
        "",
    )
    .await;
    assert_eq!(
        (status, body.as_str()),
        (200, OBJECT_BODY),
        "case {case:?}: expected the object's exact bytes, got {status}: {body:?}"
    );
}

/// RULE, read as the relationship the two halves stand in: adding a bucket policy that names
/// ONE principal flips exactly that principal's read to served and leaves every other
/// principal's outcome where it was, and S3's three enforced outcomes equal IAM's own three
/// verdicts for the same action, object and resource-based document.
#[tokio::test]
async fn a_bucket_policy_flips_only_the_principal_it_names_and_agrees_with_the_simulator() {
    let router = build_router();
    let bucket = format!("composition-{ACCOUNT}");
    bucket_holding_the_object(&router, "the composed bucket", &bucket).await;

    // Three principals of the one account: one granted by its own identity policy, one that
    // will be granted by the bucket policy alone, and one granted by neither.
    let identity_grant = identity_document("Allow", GET_OBJECT, &every_object_arn(&bucket));
    let (identity_arn, identity_key) = user_signing_key(
        &router,
        "the identity-policy principal",
        "composition-identity",
        Some(&identity_grant),
    )
    .await;
    let (resource_arn, resource_key) = user_signing_key(
        &router,
        "the bucket-policy principal",
        "composition-resource",
        None,
    )
    .await;
    let (ungranted_arn, ungranted_key) = user_signing_key(
        &router,
        "the principal neither document grants",
        "composition-none",
        None,
    )
    .await;

    // State 1: no bucket policy. Only the identity-policy principal reads.
    assert_served(
        &router,
        "state 1: the identity-policy principal",
        &identity_key,
        &bucket,
    )
    .await;
    for (case, arn, key) in [
        (
            "state 1: the principal with no identity policy",
            &resource_arn,
            &resource_key,
        ),
        (
            "state 1: the principal neither document grants",
            &ungranted_arn,
            &ungranted_key,
        ),
    ] {
        let (status, body) = s3(&router, key, "GET", &format!("/{bucket}/{OBJECT_KEY}"), "").await;
        assert_refused(case, status, &body, arn, &bucket, Reason::NoGrant);
    }
    // What IAM's own simulator makes of the same three requests with no resource-based document
    // supplied: the enforced outcomes above, verdict for verdict.
    for (case, arn, expected) in [
        ("state 1: the identity-policy principal", &identity_arn, ALLOWED),
        (
            "state 1: the principal with no identity policy",
            &resource_arn,
            IMPLICIT_DENY,
        ),
        (
            "state 1: the principal neither document grants",
            &ungranted_arn,
            IMPLICIT_DENY,
        ),
    ] {
        let decision = simulated_decision(&router, case, arn, &bucket, None).await;
        assert_eq!(
            decision, expected,
            "case {case:?}: expected the simulator to agree with enforcement ({expected}), got \
             {decision:?}"
        );
    }

    // State 2: a bucket policy naming ONLY the second principal.
    let bucket_policy = bucket_document(
        "Allow",
        &format!(r#"{{"AWS":"{resource_arn}"}}"#),
        &every_object_arn(&bucket),
    );
    put_bucket_policy(&router, "state 2: the bucket policy", &bucket, &bucket_policy).await;

    assert_served(
        &router,
        "state 2: the principal the bucket policy names",
        &resource_key,
        &bucket,
    )
    .await;
    assert_served(
        &router,
        "state 2: the identity-policy principal is unaffected",
        &identity_key,
        &bucket,
    )
    .await;
    let (status, body) = s3(
        &router,
        &ungranted_key,
        "GET",
        &format!("/{bucket}/{OBJECT_KEY}"),
        "",
    )
    .await;
    assert_refused(
        "state 2: the principal neither document grants",
        status,
        &body,
        &ungranted_arn,
        &bucket,
        Reason::NoGrant,
    );
    for (case, arn, expected) in [
        (
            "state 2: the principal the bucket policy names",
            &resource_arn,
            ALLOWED,
        ),
        ("state 2: the identity-policy principal", &identity_arn, ALLOWED),
        (
            "state 2: the principal neither document grants",
            &ungranted_arn,
            IMPLICIT_DENY,
        ),
    ] {
        let decision =
            simulated_decision(&router, case, arn, &bucket, Some(&bucket_policy)).await;
        assert_eq!(
            decision, expected,
            "case {case:?}: expected the simulator to agree with enforcement ({expected}), got \
             {decision:?}"
        );
    }
}
