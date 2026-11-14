// SPDX-License-Identifier: CC0-1.0

//! Which KEY a repository's `kmsKeyId` reports, with KMS mounted beside this
//! service on one shared engine so the answer is checked against the key KMS
//! itself holds — driven as awsJson1_1 requests through the router that serves the
//! real emulator.
//!
//! The rule under test: `RepositoryMetadata$kmsKeyId` is "The ID of the Key
//! Management Service encryption key used to encrypt and decrypt the repository"
//! (`smithy_query(query="doc",shape="RepositoryMetadata",member="kmsKeyId")`), so a
//! repository reports the KEY, resolved against KMS, whichever of the four forms
//! KMS documents for `KeyId` the request named it by — a key id, a key ARN, an
//! alias name or an alias ARN are four spellings of one key, and all four are
//! reported as that key's ARN. A request that names no key at all asks for the
//! Amazon Web Services managed key of this service, whose predefined alias
//! "exists in every account and Region" carrying no key until something asks for
//! it, when KMS associates one with it — so the create is what materialises it,
//! and every repository created without a key in that Region reports that same
//! key. A selector KMS holds no key for is held in the fullest form it names by
//! itself, which is the sibling suites' subject
//! (`crate::repository_encryption_key_projection`).
//!
//! The table spans what the rule generalises over: every selector form, keys of
//! both shapes KMS mints an id in, a key reached through its own alias, a request
//! naming no key, and selectors KMS resolves nothing for — on the create path and
//! on the rotation path alike.

use std::sync::Arc;

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::harness::{kms_key_arn_of, metadata_of, DEFAULT_ENCRYPTION_KEY_ALIAS};
use crate::repository_lifecycle::{is_uuid, ok, string_at, REGION};

/// The account every ARN this emulator mints is scoped to.
fn account() -> String {
    engine::emulator_account_id().to_string()
}

/// This service beside KMS on one shared engine, so a repository's key is resolved
/// against the very keys and aliases KMS's own operations write.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_codecommit_codecommit_20150413::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(service_com_amazonaws_kms_trentservice::EmulatedService::new(
        Arc::clone(&engine),
    ));
    crate::wire::hold_long_term_key(&engine, crate::wire::DEFAULT_ACCESS_KEY_ID);
    router
}

/// The access key id the KMS setup calls are signed with: NOT the key the account
/// holds for an IAM user ([`crate::wire::DEFAULT_ACCESS_KEY_ID`]), because that
/// user's identity-based policies are what decide `kms:CreateKey`, and this suite
/// is about the key a repository reports rather than about KMS authorization. A
/// key no store holds speaks for the account's own principal.
const KMS_CALLER: &str = "AKIDKMSSETUP";

/// One KMS call, the way an SDK sends it: awsJson1_1 under KMS's own target prefix
/// and signing name.
async fn kms(router: &MultiServiceRouter, operation: &str, body: &Value) -> Value {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", format!("TrentService.{operation}"))
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={KMS_CALLER}/20260101/{REGION}/kms/aws4_request, \
                 SignedHeaders=host;x-amz-target, Signature=0000"
            ),
        )
        .body(bytes::Bytes::from(
            serde_json::to_vec(body).expect("the request body serializes"),
        ))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload: Value = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    assert_eq!(
        status, 200,
        "KMS {operation}: expected 200, got {status} with {payload}"
    );
    payload
}

/// A KMS key of the account, answered as its key id and its ARN. `multi_region`
/// picks which of the two shapes KMS mints a key id in.
async fn given_key(router: &MultiServiceRouter, multi_region: bool) -> (String, String) {
    let created = kms(
        router,
        "CreateKey",
        &json!({
            "Description": "a key a repository is encrypted under",
            "MultiRegion": multi_region,
        }),
    )
    .await;
    (
        string_at(&created, "/KeyMetadata/KeyId"),
        string_at(&created, "/KeyMetadata/Arn"),
    )
}

/// An alias of the account for `key_id`, answered as the alias name.
async fn given_alias(router: &MultiServiceRouter, alias: &str, key_id: &str) -> String {
    kms(
        router,
        "CreateAlias",
        &json!({ "AliasName": alias, "TargetKeyId": key_id }),
    )
    .await;
    alias.to_string()
}

/// The ARN of the alias `alias` in the Region every suite signs for.
fn alias_arn(alias: &str) -> String {
    format!("arn:aws:kms:{REGION}:{}:{alias}", account())
}

/// Does `reported` name a KMS KEY of this account and Region — the identifier KMS
/// reports a key by — rather than a selector for one?
fn names_a_kms_key(reported: &str) -> bool {
    reported
        .strip_prefix(&format!("arn:aws:kms:{REGION}:{}:key/", account()))
        .is_some_and(is_uuid)
}

/// The `kmsKeyId` of a `CreateRepository` answer.
async fn created_with(router: &MultiServiceRouter, name: &str, selector: Option<&str>) -> String {
    let mut body = json!({ "repositoryName": name });
    if let Some(selector) = selector {
        body["kmsKeyId"] = json!(selector);
    }
    let created = ok(router, "CreateRepository", &body).await;
    string_at(&created, "/repositoryMetadata/kmsKeyId")
}

#[tokio::test]
async fn a_repository_created_with_no_key_reports_the_managed_key_kms_holds() {
    let router = emulator();

    // Two repositories, neither naming a key: both are encrypted under the one
    // Amazon Web Services managed key of this service in this Region.
    let first = created_with(&router, "managed-first", None).await;
    let second = created_with(&router, "managed-second", None).await;

    for (label, reported) in [("managed-first", &first), ("managed-second", &second)] {
        assert!(
            names_a_kms_key(reported),
            "case {label:?}: kmsKeyId must name a KMS key of this account and Region, got \
             {reported:?}"
        );
        assert_ne!(
            reported.as_str(), DEFAULT_ENCRYPTION_KEY_ALIAS,
            "case {label:?}: kmsKeyId must be the key the alias names, not the alias"
        );
    }
    assert_eq!(
        first, second,
        "two repositories created without a key must report the one managed key, got {first:?} \
         and {second:?}"
    );

    // The key is KMS's, not a value this service made up: KMS reports the same key
    // for the predefined alias of this service, and reports it as a key KMS itself
    // manages.
    let described = kms(
        &router,
        "DescribeKey",
        &json!({ "KeyId": DEFAULT_ENCRYPTION_KEY_ALIAS }),
    )
    .await;
    assert_eq!(
        string_at(&described, "/KeyMetadata/Arn"),
        first,
        "the repository's key must be the key KMS holds for {DEFAULT_ENCRYPTION_KEY_ALIAS}, got \
         {described}"
    );
    assert_eq!(
        described
            .pointer("/KeyMetadata/KeyManager")
            .and_then(Value::as_str),
        Some("AWS"),
        "the key behind a predefined alias must be an Amazon Web Services managed key, got \
         {described}"
    );

    // Stored, not just answered: every projection of the repository reports it.
    for name in ["managed-first", "managed-second"] {
        let read_back = metadata_of(&router, name).await;
        assert_eq!(
            read_back.get("kmsKeyId").and_then(Value::as_str),
            Some(first.as_str()),
            "case {name:?}: GetRepository must report the repository's key, got {read_back}"
        );
    }
}

#[tokio::test]
async fn every_selector_form_is_reported_as_the_key_it_names() {
    let router = emulator();

    let (single_id, single_arn) = given_key(&router, false).await;
    let single_alias = given_alias(&router, "alias/codecommit-single-key", &single_id).await;
    let (multi_id, multi_arn) = given_key(&router, true).await;
    let multi_alias = given_alias(&router, "alias/codecommit-multi-key", &multi_id).await;
    // A key id and an alias KMS holds nothing for: the key is the caller's own, in
    // an account or a key store this emulator does not keep.
    let unheld_id = "7c1f0b6e-4d2a-4f88-9c3b-5e6a7b8c9d01";
    let unheld_alias = "alias/codecommit-not-in-this-store";

    // Each row: why it is there, the `kmsKeyId` the request names, and the key the
    // service must report for it.
    let cases: Vec<(&str, String, String)> = vec![
        ("a bare key id", single_id.clone(), single_arn.clone()),
        ("a key ARN", single_arn.clone(), single_arn.clone()),
        ("an alias name", single_alias.clone(), single_arn.clone()),
        ("an alias ARN", alias_arn(&single_alias), single_arn.clone()),
        (
            "the multi-region shape of a key id",
            multi_id.clone(),
            multi_arn.clone(),
        ),
        (
            "an alias of a multi-region key",
            multi_alias.clone(),
            multi_arn.clone(),
        ),
        (
            "an alias ARN of a multi-region key",
            alias_arn(&multi_alias),
            multi_arn.clone(),
        ),
        (
            "a key id KMS holds no key for",
            unheld_id.to_string(),
            kms_key_arn_of(unheld_id),
        ),
        (
            "an alias KMS holds no key for",
            unheld_alias.to_string(),
            unheld_alias.to_string(),
        ),
    ];

    for (index, (why, selector, expected)) in cases.iter().enumerate() {
        // The create path: the key the selector names is what the answer and every
        // later read of the repository report.
        let name = format!("selector-{index}");
        let reported = created_with(&router, &name, Some(selector)).await;
        assert_eq!(
            &reported, expected,
            "case {why:?}: CreateRepository with kmsKeyId {selector:?} must report the key it \
             names, got {reported:?}"
        );
        let read_back = metadata_of(&router, &name).await;
        assert_eq!(
            read_back.get("kmsKeyId").and_then(Value::as_str),
            Some(expected.as_str()),
            "case {why:?}: GetRepository must report the stored key, got {read_back}"
        );
        let batch = ok(
            &router,
            "BatchGetRepositories",
            &json!({ "repositoryNames": [name] }),
        )
        .await;
        assert_eq!(
            batch
                .pointer("/repositories/0/kmsKeyId")
                .and_then(Value::as_str),
            Some(expected.as_str()),
            "case {why:?}: BatchGetRepositories must report the stored key, got {batch}"
        );

        // The rotation path: the same resolution, onto a repository that was
        // created under the managed key.
        let rotated_name = format!("rotated-{index}");
        let managed = created_with(&router, &rotated_name, None).await;
        let rotated = ok(
            &router,
            "UpdateRepositoryEncryptionKey",
            &json!({ "repositoryName": rotated_name, "kmsKeyId": selector }),
        )
        .await;
        assert_eq!(
            rotated.get("kmsKeyId").and_then(Value::as_str),
            Some(expected.as_str()),
            "case {why:?}: the rotation must report the key the selector names, got {rotated}"
        );
        assert_eq!(
            rotated.get("originalKmsKeyId").and_then(Value::as_str),
            Some(managed.as_str()),
            "case {why:?}: the rotation must report the managed key it left behind, got {rotated}"
        );
        let after = metadata_of(&router, &rotated_name).await;
        assert_eq!(
            after.get("kmsKeyId").and_then(Value::as_str),
            Some(expected.as_str()),
            "case {why:?}: the rotated repository must report the new key, got {after}"
        );
    }

    // The invariant behind the table: the four forms KMS documents for `KeyId` are
    // four spellings of ONE key, so every repository named by one of them reports
    // the very same key.
    let spellings = [
        single_id.clone(),
        single_arn.clone(),
        single_alias.clone(),
        alias_arn(&single_alias),
    ];
    for (index, selector) in spellings.iter().enumerate() {
        let name = format!("spelling-{index}");
        let reported = created_with(&router, &name, Some(selector)).await;
        assert_eq!(
            reported, single_arn,
            "case {selector:?}: every spelling of one key must report that key, got {reported:?}"
        );
    }
}
