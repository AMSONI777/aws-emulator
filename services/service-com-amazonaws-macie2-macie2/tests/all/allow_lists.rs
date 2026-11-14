// SPDX-License-Identifier: CC0-1.0

//! The allow-list write and read loop, end to end over the wire.
//!
//! Every case drives the production `MultiServiceRouter` through the harness
//! `macie_session_and_custom_data_identifiers` builds, so what is pinned is the
//! HTTP behaviour and the response BODIES rather than a handler called
//! directly. The suite is the second one over this plane: where
//! `allow_list_criteria_and_status` pins one criterion's translation and the
//! status derived from it, these cases pin the RESOURCE — the identity a create
//! mints, what a read reports back of what was stored, and which region and
//! which session a list belongs to.
//!
//! The rules under test, each asserted over a SET of inputs rather than one
//! request:
//!
//! * `CreateAllowList` PERSISTS a list under a server-assigned id in the id
//!   grammar the model pins, so `GetAllowList` reports every member the request
//!   carried, and a retried `clientToken` replays the first list instead of
//!   minting a second one;
//! * criteria "must specify a regular expression (regex) or an S3 object
//!   (s3WordsList). It can't specify both", so criteria naming two alternatives
//!   or none are refused 400 `ValidationException` and nothing is stored, and so
//!   are criteria naming an S3 object the object store holds nothing at;
//! * `status` reports whether Macie can access and use the list's criteria: for
//!   a regex, whether the expression compiled, and for an S3 object whatever
//!   object storage answers for that object right now;
//! * an allow list belongs to the region its create addressed, and both
//!   operations are refused 403 until Macie is enabled there.

use std::sync::Arc;

use service_com_amazonaws_macie2_macie2 as macie2;
use smithy_server_runtime::MultiServiceRouter;

use super::macie_session_and_custom_data_identifiers::{
    call_in, emulator, emulator_with_engine, enable_in, error_code, error_message,
    reported_instant,
};

/// The collection's URI, from `CreateAllowList`'s `@http` binding.
const ALLOW_LISTS_URI: &str = "/allow-lists";

/// The account segment every emulated ARN carries.
const ACCOUNT: &str = "000000000000";

/// The regions the cases sign for: a rule about an allow list is not a rule
/// about one region, so every table below runs in each of them.
const REGIONS: [&str; 2] = ["us-west-2", "eu-central-1"];

/// The region the object-storage cases sign for. A bucket created with no
/// `LocationConstraint` lands here, so Macie and the objects its criteria name
/// are in the same Region.
const OBJECT_STORAGE_REGION: &str = "us-east-1";

/// A SigV4 `Authorization` header in the `s3` scope — the routing signal that
/// picks the S3 service for a request to the bucket front door.
const S3_AUTH: &str = "AWS4-HMAC-SHA256 Credential=AKIDTESTS3/20260101/us-east-1/s3/\
                       aws4_request, SignedHeaders=host, Signature=abcdef";

/// The `id` grammar the model pins for an allow list:
/// `CreateAllowListResponse$id` is `^[a-z0-9]{22}$`.
const ID_LEN: usize = 22;

/// A body carrying one `clientToken`, which `CreateAllowList` requires.
fn create_body(token: &str, name: &str, criteria: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "clientToken": token, "name": name, "criteria": criteria })
}

/// Criteria naming a regular expression.
fn regex_criteria(regex: &str) -> serde_json::Value {
    serde_json::json!({ "regex": regex })
}

/// Criteria naming an S3 object.
fn words_list_criteria(bucket: &str, key: &str) -> serde_json::Value {
    serde_json::json!({ "s3WordsList": { "bucketName": bucket, "objectKey": key } })
}

/// Create one allow list, requiring the documented 200, and hand back the
/// reported body.
async fn create(
    router: &MultiServiceRouter,
    region: &str,
    body: &serde_json::Value,
    case: &str,
) -> serde_json::Value {
    let (status, reply) = call_in(router, region, "POST", ALLOW_LISTS_URI, &body.to_string()).await;
    assert_eq!(
        status, 200,
        "case {case:?}: a create inside every bound must answer 200, got {status} with {reply:?}"
    );
    reply
}

/// Read one allow list back, requiring the documented 200.
async fn read(
    router: &MultiServiceRouter,
    region: &str,
    id: &str,
    case: &str,
) -> serde_json::Value {
    let (status, record) =
        call_in(router, region, "GET", &format!("{ALLOW_LISTS_URI}/{id}"), "").await;
    assert_eq!(
        status, 200,
        "case {case:?}: a read of a stored allow list must answer 200, got {status} with \
         {record:?}"
    );
    record
}

/// Assert `id` is in the grammar the model pins for an allow list's id: 22
/// lowercase alphanumerics.
fn assert_id_grammar(id: &str, case: &str) {
    assert_eq!(
        id.chars().count(),
        ID_LEN,
        "case {case:?}: an allow list's id is {ID_LEN} characters, got {id:?}"
    );
    assert!(
        id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "case {case:?}: an allow list's id is lowercase alphanumeric, got {id:?}"
    );
}

/// A router holding Macie AND S3 over one shared engine — what the assembled
/// emulator does — so an `s3WordsList`'s status is grounded in S3's own answer
/// rather than in anything this suite seeded.
///
/// Macie is mounted by the harness every other case builds
/// (`emulator_with_engine`), so the two forms cannot drift apart on how this
/// service is mounted; only the object store beside it is added here.
fn emulator_with_object_storage() -> MultiServiceRouter {
    let (mut router, engine) = emulator_with_engine();
    router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
        Arc::clone(&engine),
    ));
    router
}

/// One request to the emulator's S3 front door, path-style because the emulator
/// serves one endpoint per Region. Answers the HTTP status.
async fn s3_call(router: &MultiServiceRouter, method: &str, path: &str, body: &[u8]) -> u16 {
    let host = format!("s3.{OBJECT_STORAGE_REGION}.amazonaws.com");
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("host", host)
        .header("authorization", S3_AUTH)
        .body(bytes::Bytes::from(body.to_vec()))
        .expect("the S3 harness request is well formed");
    router.dispatch(request).await.status().as_u16()
}

/// `PUT /<bucket>[/<key>]` — `CreateBucket`, or `PutObject` with `body`.
async fn s3_put(router: &MultiServiceRouter, path: &str, body: &[u8]) -> u16 {
    s3_call(router, "PUT", path, body).await
}

/// `CreateAllowList` stores every member the request carried under an id in the
/// grammar the model pins, and `GetAllowList` reports them back. The rows span
/// what a create may carry: each kind of criteria, with and without the
/// optional `description` and `tags`.
#[tokio::test]
async fn a_created_allow_list_reads_back_with_every_stored_member() {
    let router = emulator();

    let cases: [(&str, serde_json::Value); 5] = [
        (
            "a regex, required members only",
            serde_json::json!({
                "clientToken": "token-regex-minimal",
                "name": "minimal",
                "criteria": regex_criteria("[0-9]{3}-[0-9]{2}-[0-9]{4}"),
            }),
        ),
        (
            "a regex with a description",
            serde_json::json!({
                "clientToken": "token-regex-described",
                "name": "described",
                "description": "ignores test account numbers",
                "criteria": regex_criteria("ACCT-[0-9]+"),
            }),
        ),
        (
            "a regex with every optional member",
            serde_json::json!({
                "clientToken": "token-regex-everything",
                "name": "everything",
                "description": "all members",
                "criteria": regex_criteria("^[a-z]+@example\\.com$"),
                "tags": { "team": "security", "env": "test" },
            }),
        ),
        (
            "an S3 object, required members only",
            serde_json::json!({
                "clientToken": "token-words-minimal",
                "name": "words",
                "criteria": words_list_criteria("macie-allow-lists", "lists/ignore.txt"),
            }),
        ),
        (
            "an S3 object with every optional member",
            serde_json::json!({
                "clientToken": "token-words-everything",
                "name": "words everything",
                "description": "ignores the words in an object",
                "criteria": words_list_criteria("macie-allow-lists", "nested/key with spaces.txt"),
                "tags": { "team": "security" },
            }),
        ),
    ];

    let mut minted: Vec<String> = Vec::new();
    for region in REGIONS {
        enable_in(&router, region, "{}").await;
        for (name, body) in &cases {
            let case = format!("{name} in {region}");
            let reply = create(&router, region, body, &case).await;

            let id = reply["id"]
                .as_str()
                .unwrap_or_else(|| panic!("case {case:?}: a create must report an id, got {reply:?}"))
                .to_string();
            assert_id_grammar(&id, &case);
            assert!(
                !minted.contains(&id),
                "case {case:?}: {id:?} was already minted for another create, among {minted:?}"
            );
            let expected_arn = format!("arn:aws:macie2:{region}:{ACCOUNT}:allow-list/{id}");
            assert_eq!(
                reply["arn"].as_str(),
                Some(expected_arn.as_str()),
                "case {case:?}: expected the ARN {expected_arn:?}, got {:?}",
                reply["arn"]
            );

            let record = read(&router, region, &id, &case).await;
            for member in ["id", "arn"] {
                assert_eq!(
                    record[member], reply[member],
                    "case {case:?}: the read must report the {member} the create did, got {record:?}"
                );
            }
            for member in ["name", "description", "criteria", "tags"] {
                let expected = body.get(member).cloned();
                assert_eq!(
                    record.get(member).cloned().filter(|v| !v.is_null()),
                    expected,
                    "case {case:?}: expected {member} {expected:?}, got {:?}",
                    record.get(member)
                );
            }
            // Both instants are reported, in the wire form the model pins, and
            // a list nothing has changed since it was created carries the same
            // instant in each.
            let created = reported_instant(&case, "createdAt", &record);
            let updated = reported_instant(&case, "updatedAt", &record);
            assert_eq!(
                created, updated,
                "case {case:?}: a list nothing has changed reports one instant in both \
                 members, got {created} and {updated}"
            );

            // A second read reports the same record: what the create stored is
            // read back, not synthesised per call.
            let again = read(&router, region, &id, &case).await;
            for member in ["id", "arn", "name", "description", "criteria", "tags", "createdAt"] {
                assert_eq!(
                    again.get(member),
                    record.get(member),
                    "case {case:?}: two reads must report the same {member}, got {:?} then {:?}",
                    record.get(member),
                    again.get(member)
                );
            }
            minted.push(id);
        }
    }
}

/// The criteria's own rule: exactly one alternative. Criteria naming both, or
/// neither, are refused 400 `ValidationException` and leave nothing in the
/// store.
#[tokio::test]
async fn criteria_must_specify_exactly_one_alternative() {
    let (router, engine) = emulator_with_engine();
    let region = REGIONS[0];
    enable_in(&router, region, "{}").await;

    let refused: [(&str, serde_json::Value); 3] = [
        (
            "both alternatives",
            serde_json::json!({
                "regex": "[0-9]+",
                "s3WordsList": { "bucketName": "macie-lists", "objectKey": "ignore.txt" },
            }),
        ),
        (
            "both alternatives, the other way round",
            serde_json::json!({
                "s3WordsList": { "bucketName": "other-lists", "objectKey": "deep/ignore.txt" },
                "regex": "^$",
            }),
        ),
        ("neither alternative", serde_json::json!({})),
    ];

    for (case, criteria) in &refused {
        let body = create_body(&format!("token-{case}"), "refused", criteria.clone());
        let (status, reply) =
            call_in(&router, region, "POST", ALLOW_LISTS_URI, &body.to_string()).await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected 400, got {status} with {reply:?}"
        );
        assert_eq!(
            error_code(&reply),
            "ValidationException",
            "case {case:?}: expected ValidationException, got {reply:?}"
        );
        assert!(
            !error_message(&reply).is_empty(),
            "case {case:?}: a refusal must say what is wrong, got {reply:?}"
        );
    }

    // A refused create leaves NOTHING behind: the store holds no allow list.
    let held = engine
        .state::<macie2::ComAmazonawsMacie2Macie2State>()
        .lock()
        .allow_lists
        .len();
    assert_eq!(
        held, 0,
        "a refused create must store nothing, got {held} allow list(s)"
    );

    // And criteria naming exactly one alternative are accepted, so the rows
    // above failed on the rule rather than on the operation being unreachable.
    for (case, criteria) in [
        ("a regex alone", regex_criteria("[0-9]{3}")),
        (
            "an S3 object alone",
            words_list_criteria("macie-lists", "ignore.txt"),
        ),
    ] {
        let body = create_body(&format!("token-accepted-{case}"), "accepted", criteria);
        create(&router, region, &body, case).await;
    }
    let held = engine
        .state::<macie2::ComAmazonawsMacie2Macie2State>()
        .lock()
        .allow_lists
        .len();
    assert_eq!(
        held, 2,
        "the two accepted creates must be the whole store, got {held} allow list(s)"
    );
}

/// `status` reports whether Macie can access and use the list's criteria: for a
/// regex, whether the service could compile the expression, and for an S3 object
/// what object storage answers for that object right now. The rows span the
/// answers each kind of criterion can produce — a pattern that compiles and one
/// that does not, an object with content and one with none — and the status is
/// re-resolved when the object changes.
///
/// Source of the codes: `AllowListStatusCode` in this service's Smithy model —
/// "OK - Macie can retrieve and parse the contents of the object",
/// "S3_OBJECT_EMPTY - Macie can retrieve the object but the object doesn't
/// contain any content", "S3_OBJECT_NOT_FOUND - The object doesn't exist in
/// Amazon S3", "UNKNOWN_ERROR - A transient or internal error occurred when
/// Macie attempted to retrieve or parse the object" — read with the `code` doc,
/// which says of a regex that the status is OK because "Amazon Macie can compile
/// the expression".
#[tokio::test]
async fn the_status_reports_what_object_storage_answers_for_the_criteria() {
    let router = emulator_with_object_storage();
    enable_in(&router, OBJECT_STORAGE_REGION, "{}").await;

    // The objects the rows below name, written through S3's OWN front door.
    assert_eq!(
        s3_put(&router, "/macie-allow-lists", &[]).await,
        200,
        "the bucket the rows name must be created through S3"
    );
    assert_eq!(
        s3_put(&router, "/macie-allow-lists/lists/ignore.txt", b"alice\nbob\n").await,
        200,
        "the object with content must be written through S3"
    );
    assert_eq!(
        s3_put(&router, "/macie-allow-lists/lists/empty.txt", &[]).await,
        200,
        "the object with no content must be written through S3"
    );

    let cases: [(&str, serde_json::Value, &str); 7] = [
        ("a regex", regex_criteria("[0-9]{3}"), "OK"),
        ("another regex", regex_criteria("^(alice|bob)$"), "OK"),
        // A pattern the service cannot compile is not a pattern Macie can use,
        // and the status says so rather than claiming the expression compiled.
        (
            "a regex with an unterminated class",
            regex_criteria("[0-9"),
            "UNKNOWN_ERROR",
        ),
        (
            "a regex with an unterminated group",
            regex_criteria("(unclosed"),
            "UNKNOWN_ERROR",
        ),
        (
            "a regex whose repetition has no bounds",
            regex_criteria("a{3,1}"),
            "UNKNOWN_ERROR",
        ),
        (
            "an object with content",
            words_list_criteria("macie-allow-lists", "lists/ignore.txt"),
            "OK",
        ),
        (
            "an object with no content",
            words_list_criteria("macie-allow-lists", "lists/empty.txt"),
            "S3_OBJECT_EMPTY",
        ),
    ];

    for (case, criteria, expected) in &cases {
        let body = create_body(&format!("token-{case}"), case, criteria.clone());
        let reply = create(&router, OBJECT_STORAGE_REGION, &body, case).await;
        let id = reply["id"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: a create must report an id, got {reply:?}"))
            .to_string();

        let record = read(&router, OBJECT_STORAGE_REGION, &id, case).await;
        assert_eq!(
            record["status"]["code"].as_str(),
            Some(*expected),
            "case {case:?}: expected status code {expected:?}, got {:?}",
            record["status"]
        );
    }

    // The status is RESOLVED on every read rather than frozen at create: an
    // object REMOVED after the list was created stops being an object Macie can
    // retrieve, and the status says so.
    let body = create_body(
        "token-removed-later",
        "removed later",
        words_list_criteria("macie-allow-lists", "lists/transient.txt"),
    );
    assert_eq!(
        s3_put(&router, "/macie-allow-lists/lists/transient.txt", b"carol\n").await,
        200,
        "case \"removed later\": the object must be written through S3 first"
    );
    let reply = create(&router, OBJECT_STORAGE_REGION, &body, "removed later").await;
    let id = reply["id"].as_str().unwrap_or_default().to_string();
    let before = read(&router, OBJECT_STORAGE_REGION, &id, "removed later").await;
    assert_eq!(
        before["status"]["code"].as_str(),
        Some("OK"),
        "case \"removed later\": while the object is there the status must be OK, got {:?}",
        before["status"]
    );
    let deleted = s3_call(
        &router,
        "DELETE",
        "/macie-allow-lists/lists/transient.txt",
        &[],
    )
    .await;
    assert!(
        (200..300).contains(&deleted),
        "case \"removed later\": the object must be deleted through S3, got {deleted}"
    );
    let after = read(&router, OBJECT_STORAGE_REGION, &id, "removed later").await;
    assert_eq!(
        after["status"]["code"].as_str(),
        Some("S3_OBJECT_NOT_FOUND"),
        "case \"removed later\": once the object is gone the status must say so, got {:?}",
        after["status"]
    );
}

/// Macie checks the S3 object a create names UP FRONT: criteria naming an object
/// that does not exist are refused 400 `ValidationException`, naming the bucket
/// and the key the request carried, and nothing is stored. The rows span the
/// ways an object can be absent — a key the bucket does not hold, a near miss of
/// a key it does, and a bucket the account does not hold.
#[tokio::test]
async fn criteria_naming_an_object_that_does_not_exist_are_refused_up_front() {
    let router = emulator_with_object_storage();
    enable_in(&router, OBJECT_STORAGE_REGION, "{}").await;

    assert_eq!(
        s3_put(&router, "/macie-allow-lists", &[]).await,
        200,
        "the bucket the rows are near-misses of must be created through S3"
    );
    assert_eq!(
        s3_put(&router, "/macie-allow-lists/lists/ignore.txt", b"alice\n").await,
        200,
        "the one object this account holds must be written through S3"
    );

    let absent: [(&str, &str, &str); 4] = [
        (
            "a key the bucket does not hold",
            "macie-allow-lists",
            "lists/absent.txt",
        ),
        (
            "a near miss of the held key",
            "macie-allow-lists",
            "lists/ignore.txt.bak",
        ),
        (
            "the held key in another case",
            "macie-allow-lists",
            "Lists/Ignore.txt",
        ),
        (
            "a bucket the account does not hold",
            "absent-allow-lists",
            "lists/ignore.txt",
        ),
    ];

    for (case, bucket, key) in &absent {
        let body = create_body(
            &format!("token-{case}"),
            "refused",
            words_list_criteria(bucket, key),
        );
        let (status, reply) =
            call_in(&router, OBJECT_STORAGE_REGION, "POST", ALLOW_LISTS_URI, &body.to_string())
                .await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected 400, got {status} with {reply:?}"
        );
        assert_eq!(
            error_code(&reply),
            "ValidationException",
            "case {case:?}: expected ValidationException, got {reply:?}"
        );
        let expected = format!("The S3 object doesn't exist: {bucket}, {key}");
        assert_eq!(
            error_message(&reply),
            expected,
            "case {case:?}: expected the refusal {expected:?}, got {:?}",
            error_message(&reply)
        );
    }

    // The object this account DOES hold is accepted, so the rows above failed on
    // the object rather than on the operation being unreachable.
    let body = create_body(
        "token-held-object",
        "held",
        words_list_criteria("macie-allow-lists", "lists/ignore.txt"),
    );
    let reply = create(&router, OBJECT_STORAGE_REGION, &body, "the held object").await;
    let id = reply["id"].as_str().unwrap_or_default().to_string();
    let record = read(&router, OBJECT_STORAGE_REGION, &id, "the held object").await;
    assert_eq!(
        record["status"]["code"].as_str(),
        Some("OK"),
        "case \"the held object\": an object Macie can retrieve reports OK, got {:?}",
        record["status"]
    );
}

/// A retried `clientToken` replays the allow list that token minted; a
/// different token mints a different list, however alike the two requests are.
#[tokio::test]
async fn a_retried_client_token_replays_the_first_allow_list() {
    let router = emulator();

    for region in REGIONS {
        enable_in(&router, region, "{}").await;
        for (case, criteria) in [
            ("a regex", regex_criteria("[0-9]{4}")),
            (
                "an S3 object",
                words_list_criteria("macie-allow-lists", "lists/ignore.txt"),
            ),
        ] {
            let case = format!("{case} in {region}");
            let body = create_body("retried-token", "retried", criteria.clone());
            let first = create(&router, region, &body, &case).await;
            let replayed = create(&router, region, &body, &case).await;
            assert_eq!(
                replayed, first,
                "case {case:?}: a retried clientToken must replay the first list, got \
                 {replayed:?} after {first:?}"
            );

            let other = create_body("another-token", "retried", criteria);
            let second = create(&router, region, &other, &case).await;
            assert_ne!(
                second["id"], first["id"],
                "case {case:?}: another clientToken must mint another list, got {second:?}"
            );
        }
    }
}

/// An allow list belongs to the region its create addressed: a read naming
/// another region does not find it, and an id nothing minted is refused 404
/// `ResourceNotFoundException`.
#[tokio::test]
async fn an_allow_list_is_only_visible_to_the_region_it_was_created_in() {
    let router = emulator();
    for region in REGIONS {
        enable_in(&router, region, "{}").await;
    }

    let body = create_body("token-region", "regional", regex_criteria("[0-9]+"));
    let reply = create(&router, REGIONS[0], &body, "regional").await;
    let id = reply["id"].as_str().unwrap_or_default().to_string();

    // Ids no region minted, and the live id read in the OTHER region: each one
    // addresses no allow list of the region the request names.
    let absent: [(&str, String); 3] = [
        ("an id nothing minted", "a".repeat(ID_LEN)),
        ("another id nothing minted", "0123456789abcdefghijkl".to_string()),
        ("the live id in another region", id.clone()),
    ];
    for (case, candidate) in &absent {
        let region = if case.contains("another region") {
            REGIONS[1]
        } else {
            REGIONS[0]
        };
        let (status, reply) = call_in(
            &router,
            region,
            "GET",
            &format!("{ALLOW_LISTS_URI}/{candidate}"),
            "",
        )
        .await;
        assert_eq!(
            status, 404,
            "case {case:?}: expected 404, got {status} with {reply:?}"
        );
        assert_eq!(
            error_code(&reply),
            "ResourceNotFoundException",
            "case {case:?}: expected ResourceNotFoundException, got {reply:?}"
        );
        assert!(
            error_message(&reply).contains(candidate.as_str()),
            "case {case:?}: the refusal must name the id the request addressed, got {reply:?}"
        );
    }

    // And the list is still there for the region that created it.
    let record = read(&router, REGIONS[0], &id, "regional").await;
    assert_eq!(
        record["id"].as_str(),
        Some(id.as_str()),
        "the created list must still read back in its own region, got {record:?}"
    );
}

/// Both operations are refused 403 `AccessDeniedException` until Macie is
/// enabled in the region the request names. The rows span a create whose
/// criteria are well formed, a create naming an object nothing holds (so the
/// refusal is the session's rather than the object's), and a read.
#[tokio::test]
async fn the_allow_list_operations_are_refused_until_macie_is_enabled() {
    let router = emulator();
    let region = REGIONS[0];

    let body = create_body("token-disabled", "disabled", regex_criteria("[0-9]+"));
    let absent = create_body(
        "token-disabled-absent",
        "disabled",
        words_list_criteria("absent-allow-lists", "lists/ignore.txt"),
    );
    let read_uri = format!("{ALLOW_LISTS_URI}/{}", "a".repeat(ID_LEN));
    let calls: [(&str, &str, &str, String); 3] = [
        ("a create", "POST", ALLOW_LISTS_URI, body.to_string()),
        (
            "a create naming an object nothing holds",
            "POST",
            ALLOW_LISTS_URI,
            absent.to_string(),
        ),
        ("a read", "GET", read_uri.as_str(), String::new()),
    ];
    for (case, method, uri, payload) in &calls {
        let (status, reply) = call_in(&router, region, method, uri, payload).await;
        assert_eq!(
            status, 403,
            "case {case:?}: expected 403 before Macie is enabled, got {status} with {reply:?}"
        );
        assert_eq!(
            error_code(&reply),
            "AccessDeniedException",
            "case {case:?}: expected AccessDeniedException, got {reply:?}"
        );
    }

    // Enabled, the create goes through: the rows above failed on the session
    // rather than on the operation being unreachable.
    enable_in(&router, region, "{}").await;
    create(&router, region, &body, "a create once enabled").await;
}
