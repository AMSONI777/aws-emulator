// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the TRANSITION a `CreateDeployment` makes on the `execute-api` data
//! plane: the request that was refused for want of a stage, and the same request once the
//! deployment that names it has been created.
//!
//! The rule under test, one level above the recorded case:
//!
//! > A request to a REST API's invoke URL whose first path segment names no stage of that api
//! > is refused, because there is no deployment for it to reach. `CreateDeployment` carrying a
//! > `stageName` the api holds no stage for CREATES that stage pointing at the deployment this
//! > call took — "the name of the Stage resource for the Deployment resource to create"
//! > (`CreateDeployment$stageName`) — so from that point on the SAME request is SERVED by the
//! > matched method's integration, with the integration response's own status and rendered
//! > body. A deployment that names no stage mints none, so a path under a stage name nobody
//! > has deployed stays refused exactly as before, whatever other stages the api has.
//!
//! This is the invariant the issue this suite was written for recorded as broken in both
//! directions at once: the negative leg (an undeployed stage) and the positive leg (the same
//! path after `CreateDeployment`) both ended in a 5xx, so "a client cannot tell 'stage not
//! deployed' from 'deployed and broken': creating the deployment appears to have no effect."
//!
//! The rows differ along what the rule generalises over: the FORM of the stage name (one
//! lowercase word, a hyphenated one, an underscored one, a mixed-case one with a digit, a
//! single character, and one at the published 128-character maximum), the SHAPE of the
//! resource path the request reaches (the root resource, a literal child, a path parameter, a
//! greedy parameter), the VERB (`GET`, `POST`, `DELETE`, and a verb served by the `ANY`
//! catch-all) and the STATUS the matched integration response answers (`200`, `201`, `202`).
//!
//! Every case drives the real wire path — the control plane through this crate's one wire-test
//! harness ([`Gateway`]) and the data plane on the api's own
//! `{rest-api-id}.execute-api.{region}.amazonaws.com` invoke host — so what is asserted is
//! what a client of the published invoke URL sees, and each minted stage is read back through
//! `GetStage` rather than out of any store.

use serde_json::json;

use crate::execute_api_data_plane::{
    deploy, invoke, json_template, mock_method, mock_resource,
};
use crate::rest_api_lifecycle::{
    create_api, page_items, resource_under, string_member, Gateway,
};
use crate::stage_collection::get_stages;
use crate::stage_lifecycle::get_stage;
use crate::update_deployment::get_deployment;

/// The body each of the api's mocked methods answers, by the resource it hangs off: what tells
/// "the integration the stage matched" from "some other method of the same api".
const ROOT_BODY: &str = r#"{"at":"root"}"#;
const PETS_BODY: &str = r#"{"at":"pets"}"#;
const ONE_PET_BODY: &str = r#"{"at":"one-pet"}"#;
const PROXY_BODY: &str = r#"{"at":"proxy"}"#;
const THINGS_BODY: &str = r#"{"at":"things"}"#;

/// The status and message API Gateway refuses a request whose first path segment names no
/// stage of the api with: the `Forbidden` envelope an invoke address that resolves to no stage
/// of an api earns, whose body is fixed text for the class (the sibling
/// `stage_refusal_error_class` suite is where that envelope is held against its exception
/// class, distinct from the `Missing Authentication Token` one a path the deployment holds no
/// method for earns).
const NO_SUCH_STAGE: (u16, &str) = (403, "Forbidden");

/// The published maximum length of a stage name: `CreateDeployment$stageName` /
/// `CreateStage$stageName` — "Stage names can only contain alphanumeric characters, hyphens,
/// and underscores. Maximum length is 128 characters."
const MAX_STAGE_NAME_CHARS: usize = 128;

/// One row: the stage `CreateDeployment` is asked to mint, the request that reaches it, and
/// the answer the matched integration gives it.
struct Row {
    case: &'static str,
    /// The `stageName` the deployment names — a `String`, so a row can span a generated name
    /// at the published bound as well as the literal forms.
    stage: String,
    verb: &'static str,
    /// The path UNDER the stage segment, as the api's resource tree lays it out.
    path: &'static str,
    status: u16,
    body: &'static str,
}

/// The rows, in the order one api is deployed to each of their stages.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "a lowercase stage name, the root resource",
            stage: "v1".to_string(),
            verb: "GET",
            path: "/",
            status: 200,
            body: ROOT_BODY,
        },
        Row {
            case: "a hyphenated stage name, a literal path under POST",
            stage: "stage-two".to_string(),
            verb: "POST",
            path: "/pets",
            status: 201,
            body: PETS_BODY,
        },
        Row {
            case: "an underscored stage name, a path parameter",
            stage: "stage_three".to_string(),
            verb: "GET",
            path: "/pets/42",
            status: 200,
            body: ONE_PET_BODY,
        },
        Row {
            case: "a mixed-case stage name, a greedy parameter under the ANY catch-all",
            stage: "Stage4".to_string(),
            verb: "DELETE",
            path: "/files/a/b.txt",
            status: 202,
            body: PROXY_BODY,
        },
        Row {
            case: "a single-character stage name, a DELETE method",
            stage: "x".to_string(),
            verb: "DELETE",
            path: "/things",
            status: 200,
            body: THINGS_BODY,
        },
        Row {
            case: "a stage name at the published 128-character maximum",
            stage: "s".repeat(MAX_STAGE_NAME_CHARS),
            verb: "GET",
            path: "/",
            status: 200,
            body: ROOT_BODY,
        },
    ]
}

/// The invoke path of `row`: the stage segment the deployment mints, then the resource path.
fn invoke_path(row: &Row) -> String {
    format!("/{}{}", row.stage, row.path)
}

/// The api every row below is deployed to: one method per resource shape the rows reach,
/// every one of them a `MOCK` integration, which is the integration type that needs no
/// backend at all ("for testing without actually invoking the backend", `IntegrationType`).
///
/// All of them are put BEFORE any deployment, so what each row's deployment snapshots is the
/// same tree and the rows differ only in the stage the deployment mints.
async fn api_with_every_shape(gateway: &Gateway) -> String {
    let (api, root) = create_api(gateway, "deployment-mints-the-stage").await;
    // The root resource is the one a case cannot create — every api is created with it — so it
    // takes its method through the shared helper directly rather than through `mock_resource`.
    mock_method(gateway, &api, &root, "GET", "200", json_template(ROOT_BODY)).await;
    let pets = mock_resource(
        gateway,
        &api,
        &root,
        "pets",
        "POST",
        "201",
        json_template(PETS_BODY),
    )
    .await;
    mock_resource(
        gateway,
        &api,
        &pets,
        "{petId}",
        "GET",
        "200",
        json_template(ONE_PET_BODY),
    )
    .await;
    let files = resource_under(gateway, &api, &root, "files").await;
    mock_resource(
        gateway,
        &api,
        &files,
        "{proxy+}",
        "ANY",
        "202",
        json_template(PROXY_BODY),
    )
    .await;
    mock_resource(
        gateway,
        &api,
        &root,
        "things",
        "DELETE",
        "200",
        json_template(THINGS_BODY),
    )
    .await;
    api
}

#[tokio::test]
async fn a_deployment_mints_the_stage_it_names_and_that_stage_serves_the_integration() {
    let gateway = Gateway::new();
    let api = api_with_every_shape(&gateway).await;

    let rows = rows();
    for row in &rows {
        let case = row.case;
        let path = invoke_path(row);

        // 1. Before the deployment there is no stage of that name, so the request is refused
        //    — and refused as API Gateway refuses an unresolvable invoke address, not with a
        //    5xx that a client would read as "deployed and broken".
        let refused = invoke(&gateway, &api, row.verb, &path, &[]).await;
        assert_eq!(
            (refused.status, refused.message().as_deref()),
            (NO_SUCH_STAGE.0, Some(NO_SUCH_STAGE.1)),
            "case {case:?} ({} {path}): expected {NO_SUCH_STAGE:?} before the deployment, got \
             {} with {:?}",
            row.verb,
            refused.status,
            refused.body
        );
        let unknown = get_stage(&gateway, &api, &row.stage).await;
        assert_eq!(
            unknown.status, 404,
            "case {case:?}: expected GetStage to report no such stage yet, got {} with {:?}",
            unknown.status, unknown.body
        );

        // 2. The deployment that names the stage. It mints the stage pointing at ITSELF,
        //    which an independent GetStage reads back.
        let deployment = deploy(&gateway, &api, &row.stage).await;
        let minted = get_stage(&gateway, &api, &row.stage).await;
        assert_eq!(
            minted.status, 200,
            "case {case:?}: expected GetStage to report the minted stage, got {} with {:?}",
            minted.status, minted.body
        );
        assert_eq!(
            string_member(&minted.body, "stageName", case),
            row.stage,
            "case {case:?}: expected the minted stage to be named {:?}, got {:?}",
            row.stage,
            minted.body
        );
        assert_eq!(
            string_member(&minted.body, "deploymentId", case),
            deployment,
            "case {case:?}: expected the minted stage to serve the deployment the call \
             created, got {:?}",
            minted.body
        );

        // 3. And the SAME request is now served by the matched method's integration: the
        //    integration response's own status, and the body its template renders.
        let served = invoke(&gateway, &api, row.verb, &path, &[]).await;
        assert_eq!(
            served.status, row.status,
            "case {case:?} ({} {path}): expected {} once the deployment exists, got {} with \
             {:?}",
            row.verb, row.status, served.status, served.body
        );
        assert_eq!(
            served.body, row.body,
            "case {case:?} ({} {path}): expected the integration's body {:?}, got {:?}",
            row.verb, row.body, served.body
        );
    }

    // Every stage the rows minted is still serving its own request: a later deployment to
    // another stage name re-points nothing, so the whole set is reachable at once.
    for row in &rows {
        let path = invoke_path(row);
        let again = invoke(&gateway, &api, row.verb, &path, &[]).await;
        assert_eq!(
            (again.status, again.body.as_str()),
            (row.status, row.body),
            "case {:?} ({} {path}): expected the stage to still serve {} with {:?} after the \
             later deployments, got {} with {:?}",
            row.case,
            row.verb,
            row.status,
            row.body,
            again.status,
            again.body
        );
    }

    // And a stage name nobody deployed is refused exactly as every row's was before its own
    // deployment: minting is what the named `stageName` does, not what any deployment does.
    let never = invoke(&gateway, &api, "GET", "/never-deployed/", &[]).await;
    assert_eq!(
        (never.status, never.message().as_deref()),
        (NO_SUCH_STAGE.0, Some(NO_SUCH_STAGE.1)),
        "case \"a stage name nobody deployed\": expected {NO_SUCH_STAGE:?}, got {} with {:?}",
        never.status,
        never.body
    );
}

#[tokio::test]
async fn a_deployment_that_names_no_stage_mints_none_and_the_path_stays_refused() {
    let gateway = Gateway::new();
    let (api, root) = create_api(&gateway, "deployment-without-a-stage").await;
    mock_method(&gateway, &api, &root, "GET", "200", json_template(ROOT_BODY)).await;
    let case = "a deployment that names no stage";
    let stage = "live";
    let path = format!("/{stage}/");

    // Nothing is deployed, so the request is refused.
    let before = invoke(&gateway, &api, "GET", &path, &[]).await;
    assert_eq!(
        (before.status, before.message().as_deref()),
        (NO_SUCH_STAGE.0, Some(NO_SUCH_STAGE.1)),
        "case {case:?}: expected {NO_SUCH_STAGE:?} before anything is deployed, got {} with {:?}",
        before.status,
        before.body
    );

    // A deployment carrying no `stageName` at all: the deployment is created and readable,
    // and it mints NO stage, so the very same request is refused the very same way. The
    // deployment exists without being reachable, which is what makes the stage the thing that
    // publishes it.
    let answer = gateway
        .call("POST", &format!("/restapis/{api}/deployments"), Some(json!({})))
        .await;
    assert_eq!(
        answer.status, 201,
        "case {case:?}: expected 201 from CreateDeployment, got {} with {:?}",
        answer.status, answer.body
    );
    let deployment = string_member(&answer.body, "id", case);
    let read = get_deployment(&gateway, &api, &deployment, case).await;
    assert_eq!(
        string_member(&read, "id", case),
        deployment,
        "case {case:?}: expected GetDeployment to report the deployment the create minted, got \
         {read:?}"
    );
    let listed = get_stages(&gateway, &api, "").await;
    assert_eq!(
        page_items(&listed.body, case).len(),
        0,
        "case {case:?}: expected the api to hold no stage at all, got {:?}",
        listed.body
    );
    let still = invoke(&gateway, &api, "GET", &path, &[]).await;
    assert_eq!(
        (still.status, still.message().as_deref()),
        (NO_SUCH_STAGE.0, Some(NO_SUCH_STAGE.1)),
        "case {case:?}: expected {NO_SUCH_STAGE:?} while no stage names the deployment, got {} \
         with {:?}",
        still.status,
        still.body
    );

    // Binding a stage to that very deployment is what serves it — the same transition the
    // `stageName` of a deployment makes, reached through `CreateStage` instead.
    let created = gateway
        .call(
            "POST",
            &format!("/restapis/{api}/stages"),
            Some(json!({ "stageName": stage, "deploymentId": deployment })),
        )
        .await;
    assert_eq!(
        created.status, 201,
        "case {case:?}: expected 201 from CreateStage, got {} with {:?}",
        created.status, created.body
    );
    let served = invoke(&gateway, &api, "GET", &path, &[]).await;
    assert_eq!(
        (served.status, served.body.as_str()),
        (200, ROOT_BODY),
        "case {case:?}: expected the bound stage to serve the integration, got {} with {:?}",
        served.status,
        served.body
    );
}
