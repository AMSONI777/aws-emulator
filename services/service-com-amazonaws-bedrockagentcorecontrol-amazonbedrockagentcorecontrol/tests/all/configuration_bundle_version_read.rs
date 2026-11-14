// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP tests for `GetConfigurationBundleVersion`: a read of ONE
//! version of a configuration bundle, addressed by the `versionId` a commit of
//! that bundle minted.
//!
//! Every test drives the service the way the router does: an `http::Request`
//! through [`MultiServiceRouter::dispatch`], so the wire protocol (`restJson1`),
//! the boundary constraint validation and the handlers are all exercised. The
//! store is the one shared engine, so what one request writes is what the next
//! request reads.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_bedrockagentcorecontrol_amazonbedrockagentcorecontrol::EmulatedService;

/// The region the tests sign for.
const REGION: &str = "us-east-1";

/// The account id every emulated ARN carries (`engine::mock_account_id`).
const ACCOUNT: &str = "000000000000";

/// The branch a version belongs to when the request names none, which the model
/// documents on `CreateConfigurationBundleRequest$branchName` ("Defaults to
/// mainline if not specified").
const DEFAULT_BRANCH: &str = "mainline";

/// A `ConfigurationBundleVersion` inside the modelled pattern
/// (`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`,
/// `smithy_query operation=GetConfigurationBundleVersion`) that no commit of
/// this emulator ever mints.
const UNHELD_VERSION_ID: &str = "00000000-0000-0000-0000-000000000000";

/// A `ConfigurationBundleId` inside the modelled pattern
/// (`^[a-zA-Z][a-zA-Z0-9-_]{0,99}-[a-zA-Z0-9]{10}$`) that no bundle holds.
const UNHELD_BUNDLE_ID: &str = "absent-aaaaaaaaaa";

fn router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::default();
    router.register_service(EmulatedService::new(engine));
    router
}

/// A SigV4 `Authorization` header for this service in `region`. It is what the
/// router routes on, and what the handlers read the ARN region from.
fn authorization(region: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/{region}/bedrock-agentcore/aws4_request, \
         SignedHeaders=host, Signature=abc"
    )
}

async fn send(
    router: &MultiServiceRouter,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let payload = body.map_or_else(Bytes::new, |value| {
        Bytes::from(serde_json::to_vec(value).expect("the request body serializes"))
    });
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", authorization(REGION))
        .header("host", "bedrock-agentcore-control.amazonaws.com");
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request.body(payload).expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let parsed = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// `CreateConfigurationBundle`: `POST /configuration-bundles/create`.
async fn create_bundle(router: &MultiServiceRouter, body: &Value) -> (u16, Value) {
    send(router, "POST", "/configuration-bundles/create", Some(body)).await
}

/// `GetConfigurationBundle`: `GET /configuration-bundles/{bundleId}`, with the
/// optional `branchName` as an `@httpQuery` — a read that names none reports
/// the latest version on the default branch.
async fn get_bundle(
    router: &MultiServiceRouter,
    bundle_id: &str,
    branch_name: Option<&str>,
) -> (u16, Value) {
    let uri = match branch_name {
        Some(branch) => format!(
            "/configuration-bundles/{bundle_id}?branchName={}",
            branch.replace('/', "%2F")
        ),
        None => format!("/configuration-bundles/{bundle_id}"),
    };
    send(router, "GET", &uri, None).await
}

/// `GetConfigurationBundleVersion`:
/// `GET /configuration-bundles/{bundleId}/versions/{versionId}`
/// (`smithy_query operation=GetConfigurationBundleVersion`).
async fn get_version(
    router: &MultiServiceRouter,
    bundle_id: &str,
    version_id: &str,
) -> (u16, Value) {
    send(
        router,
        "GET",
        &format!("/configuration-bundles/{bundle_id}/versions/{version_id}"),
        None,
    )
    .await
}

/// `DeleteConfigurationBundle`: `DELETE /configuration-bundles/{bundleId}`.
async fn delete_bundle(router: &MultiServiceRouter, bundle_id: &str) -> (u16, Value) {
    send(
        router,
        "DELETE",
        &format!("/configuration-bundles/{bundle_id}"),
        None,
    )
    .await
}

/// The error code `restJson1` puts in `__type` / `x-amzn-errortype`.
fn error_code(body: &Value) -> String {
    body.get("__type")
        .and_then(Value::as_str)
        .unwrap_or("<no __type>")
        .rsplit('#')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn text(body: &Value, member: &str) -> String {
    body.get(member)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Assert one timestamp member's wire form. `createdAt` and `versionCreatedAt`
/// target the plain `Timestamp` shape with no `@timestampFormat` (`smithy_query
/// operation=GetConfigurationBundleVersion`), so `restJson1` renders each as
/// epoch seconds: a JSON NUMBER naming a real instant.
fn assert_timestamp(case: &str, member: &str, value: &Value) {
    let seconds = value.as_f64().unwrap_or_else(|| {
        panic!("case {case:?}: {member} must be an epoch-seconds number, got {value:?}")
    });
    assert!(
        seconds > 0.0,
        "case {case:?}: {member} must name a real instant, got {seconds}"
    );
}

/// A version is read back by its own `versionId`, for every shape of commit a
/// create can mint.
///
/// The rows differ along what the rule generalises over: how many components the
/// version carries and what kind of document each configuration is, whether the
/// description, commit message, creation source and KMS key were supplied, and
/// which branch the version was committed on (none, `mainline` by name, a
/// path-shaped branch and a plain one). Sources for the member lists and their
/// constraints: `smithy_query
/// operation=CreateConfigurationBundle,GetConfigurationBundleVersion`,
/// `ComponentConfiguration$configuration` (a flexible JSON document) and
/// `BranchName`.
#[tokio::test]
async fn a_configuration_bundle_version_reads_back_by_its_version_id() {
    let router = router();

    // (case, bundleName, the members beyond `bundleName` and `components`,
    //  components, the branch the version lands on)
    let rows: [(&str, &str, Value, Value, &str); 6] = [
        (
            "only the required members, one object component",
            "minimal",
            json!({}),
            json!({"agent": {"configuration": {"model": "a-model", "temperature": 0}}}),
            DEFAULT_BRANCH,
        ),
        (
            "a described version with two components and a commit message",
            "described_bundle",
            json!({"description": "the evaluated agent", "commitMessage": "initial import"}),
            json!({
                "agent": {"configuration": {"model": "a-model"}},
                "tools/search": {"configuration": {"enabled": true, "topK": 5}}
            }),
            DEFAULT_BRANCH,
        ),
        (
            "the default branch named explicitly, a scalar component document",
            "scalarBundle",
            json!({"branchName": DEFAULT_BRANCH}),
            json!({"prompt": {"configuration": "answer briefly"}}),
            DEFAULT_BRANCH,
        ),
        (
            "a path-shaped branch and a list component document",
            "branched",
            json!({"branchName": "team/experiment-1", "commitMessage": "try a new order"}),
            json!({"pipeline": {"configuration": ["retrieve", "rerank", "generate"]}}),
            "team/experiment-1",
        ),
        (
            "a version committed by a named source, with tags on the bundle",
            "withSource",
            json!({
                "createdBy": {
                    "name": "optimization-job",
                    "arn": "arn:aws:bedrock-agentcore:us-east-1:000000000000:job/one"
                },
                "tags": {"owner": "team-a", "env": "test"}
            }),
            json!({"agent": {"configuration": {"nested": {"depth": 2}, "flags": [true, false]}}}),
            DEFAULT_BRANCH,
        ),
        (
            "a customer-managed key and an empty component map",
            "encrypted",
            json!({
                "kmsKeyArn":
                    "arn:aws:kms:us-east-1:000000000000:key/12345678-1234-1234-1234-123456789012",
                "branchName": "release-2024"
            }),
            json!({}),
            "release-2024",
        ),
    ];

    for (case, bundle_name, extra, components, branch) in rows {
        let mut body = json!({"bundleName": bundle_name, "components": components});
        for (member, value) in extra.as_object().expect("the row's members are an object") {
            body[member] = value.clone();
        }

        let (status, created) = create_bundle(&router, &body).await;
        assert_eq!(
            status, 201,
            "case {case:?}: expected HTTP 201 from CreateConfigurationBundle, got {status} \
             ({created})"
        );
        let bundle_id = text(&created, "bundleId");
        let version_id = text(&created, "versionId");

        let (status, fetched) = get_version(&router, &bundle_id, &version_id).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetConfigurationBundleVersion, got {status} \
             ({fetched})"
        );
        assert_eq!(
            text(&fetched, "versionId"),
            version_id,
            "case {case:?}: the read reports the version asked for, got {}",
            text(&fetched, "versionId")
        );
        assert_eq!(
            text(&fetched, "bundleId"),
            bundle_id,
            "case {case:?}: the read reports the bundle the version belongs to, got {}",
            text(&fetched, "bundleId")
        );
        assert_eq!(
            text(&fetched, "bundleName"),
            bundle_name,
            "case {case:?}: the bundleName reads back as sent, got {}",
            text(&fetched, "bundleName")
        );
        assert_eq!(
            text(&fetched, "bundleArn"),
            format!(
                "arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:configuration-bundle/{bundle_id}"
            ),
            "case {case:?}: expected the modelled ConfigurationBundleArn for {bundle_id}, got {}",
            text(&fetched, "bundleArn")
        );
        assert_eq!(
            fetched["components"], body["components"],
            "case {case:?}: the components of the version read back as committed, got {}",
            fetched["components"]
        );
        assert_eq!(
            fetched["description"],
            body.get("description").cloned().unwrap_or(Value::Null),
            "case {case:?}: the description reads back as committed, got {}",
            fetched["description"]
        );
        assert_eq!(
            fetched["kmsKeyArn"],
            body.get("kmsKeyArn").cloned().unwrap_or(Value::Null),
            "case {case:?}: the kmsKeyArn reads back as committed, got {}",
            fetched["kmsKeyArn"]
        );
        assert_eq!(
            fetched["lineageMetadata"]["branchName"],
            json!(branch),
            "case {case:?}: expected the version on branch {branch:?}, got {}",
            fetched["lineageMetadata"]["branchName"]
        );
        assert_eq!(
            fetched["lineageMetadata"]["parentVersionIds"],
            json!([]),
            "case {case:?}: the version a create mints has no parent, got {}",
            fetched["lineageMetadata"]["parentVersionIds"]
        );
        assert_eq!(
            fetched["lineageMetadata"]["commitMessage"],
            body.get("commitMessage").cloned().unwrap_or(Value::Null),
            "case {case:?}: the commitMessage reads back as committed, got {}",
            fetched["lineageMetadata"]["commitMessage"]
        );
        assert_eq!(
            fetched["lineageMetadata"]["createdBy"],
            body.get("createdBy").cloned().unwrap_or(Value::Null),
            "case {case:?}: the creation source reads back as committed, got {}",
            fetched["lineageMetadata"]["createdBy"]
        );
        for member in ["createdAt", "versionCreatedAt"] {
            assert_timestamp(case, member, &fetched[member]);
        }
        assert_eq!(
            fetched["createdAt"], created["createdAt"],
            "case {case:?}: the bundle's createdAt is the instant the create reported, got {} \
             against {}",
            fetched["createdAt"], created["createdAt"]
        );
        assert_eq!(
            fetched["versionCreatedAt"], created["createdAt"],
            "case {case:?}: the version the create minted was committed in that same instant, \
             got {} against {}",
            fetched["versionCreatedAt"], created["createdAt"]
        );

        // The version read reports the same commit the bundle read reports,
        // member for member, because both project one stored version.
        let read_branch = (branch != DEFAULT_BRANCH).then_some(branch);
        let (status, bundle) = get_bundle(&router, &bundle_id, read_branch).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetConfigurationBundle, got {status} \
             ({bundle})"
        );
        for member in [
            "bundleArn",
            "bundleId",
            "bundleName",
            "versionId",
            "components",
            "description",
            "kmsKeyArn",
            "lineageMetadata",
            "createdAt",
        ] {
            assert_eq!(
                fetched[member], bundle[member],
                "case {case:?}: the version read and the bundle read agree on {member}, got {} \
                 against {}",
                fetched[member], bundle[member]
            );
        }

        // A read changes nothing a later caller sees.
        let (status, again) = get_version(&router, &bundle_id, &version_id).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 reading the version again, got {status} ({again})"
        );
        assert_eq!(
            again, fetched,
            "case {case:?}: a read does not change what the next read reports, got {again}"
        );
    }
}

/// What `GetConfigurationBundleVersion` refuses: a bundle this service does not
/// hold, and a `versionId` the addressed bundle holds no commit for — including
/// one another bundle minted, and one whose bundle has since been deleted.
#[tokio::test]
async fn get_configuration_bundle_version_refuses_what_it_does_not_hold() {
    let router = router();

    let (status, first) = create_bundle(
        &router,
        &json!({
            "bundleName": "held",
            "components": {"agent": {"configuration": {"model": "a-model"}}},
        }),
    )
    .await;
    assert_eq!(status, 201, "the first create succeeds, got {status} ({first})");
    let (status, second) = create_bundle(
        &router,
        &json!({
            "bundleName": "other_bundle",
            "components": {"prompt": {"configuration": "answer briefly"}},
            "branchName": "team/other",
        }),
    )
    .await;
    assert_eq!(status, 201, "the second create succeeds, got {status} ({second})");

    let held_bundle = text(&first, "bundleId");
    let held_version = text(&first, "versionId");
    let other_bundle = text(&second, "bundleId");
    let other_version = text(&second, "versionId");

    // (case, bundleId, versionId, expected status)
    let rows: [(&str, &str, &str, u16); 5] = [
        (
            "the bundle's own version",
            held_bundle.as_str(),
            held_version.as_str(),
            200,
        ),
        (
            "a bundleId no bundle holds",
            UNHELD_BUNDLE_ID,
            held_version.as_str(),
            404,
        ),
        (
            "a versionId no commit minted",
            held_bundle.as_str(),
            UNHELD_VERSION_ID,
            404,
        ),
        (
            "a version another bundle minted",
            held_bundle.as_str(),
            other_version.as_str(),
            404,
        ),
        (
            "the other bundle's own version",
            other_bundle.as_str(),
            other_version.as_str(),
            200,
        ),
    ];

    for (case, bundle_id, version_id, expected_status) in rows {
        let (status, answered) = get_version(&router, bundle_id, version_id).await;
        assert_eq!(
            status, expected_status,
            "case {case:?}: expected HTTP {expected_status} from \
             GetConfigurationBundleVersion, got {status} ({answered})"
        );
        if expected_status == 404 {
            assert_eq!(
                error_code(&answered),
                "ResourceNotFoundException",
                "case {case:?}: expected ResourceNotFoundException, got {} ({answered})",
                error_code(&answered)
            );
        } else {
            assert_eq!(
                text(&answered, "versionId"),
                version_id,
                "case {case:?}: the read reports the version asked for, got {}",
                text(&answered, "versionId")
            );
        }
    }

    // A deleted bundle holds no version for a later read to report.
    let (status, deleted) = delete_bundle(&router, &held_bundle).await;
    assert_eq!(
        status, 202,
        "deleting the held bundle is accepted, got {status} ({deleted})"
    );
    let (status, answered) = get_version(&router, &held_bundle, &held_version).await;
    assert_eq!(
        status, 404,
        "a version of a deleted bundle is not readable, got {status} ({answered})"
    );
    assert_eq!(
        error_code(&answered),
        "ResourceNotFoundException",
        "expected ResourceNotFoundException for a deleted bundle's version, got {} ({answered})",
        error_code(&answered)
    );

    // The deletion of one bundle left the other one's version readable.
    let (status, survivor) = get_version(&router, &other_bundle, &other_version).await;
    assert_eq!(
        status, 200,
        "the other bundle's version is still readable, got {status} ({survivor})"
    );
    assert_eq!(
        survivor["components"],
        json!({"prompt": {"configuration": "answer briefly"}}),
        "the surviving version reports its own components, got {}",
        survivor["components"]
    );
}
