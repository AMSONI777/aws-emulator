// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP tests for the channel the tag plane reports an ABSENT resource on.
//!
//! Every case drives the real wire path — the production `MultiServiceRouter`, restJson1
//! serialization, the modelled-constraint walk and the handlers — so what is asserted is
//! what a signed AWS SDK request observes.
//!
//! The rule under test: a request on `/tags/{ResourceArn}` whose ARN belongs to this
//! service and to the account the request is signed for, but names no resource this
//! Region's endpoint holds, is answered by the operation's OWN modelled
//! `ResourceNotFoundException` — HTTP 404, the wire error code
//! `ResourceNotFoundException`, and the wholly fixed sentence that operation states under
//! the modelled `Message` member — whatever made the ARN name nothing. Non-existence is a
//! RESOURCE outcome, so it is never reported as an authorization one: no row here may
//! answer the front door's HTTP 401 / `UnauthorizedException`, which belongs to an ARN the
//! caller is not entitled to address at all (`tests/all/target_authorization.rs` owns that
//! half). Each tag-plane operation states its own sentence, so no row may carry the
//! manager routes' template either, nor anything taken from the request.
//!
//! The rows below span what the rule generalises over — every reason an entitled ARN names
//! nothing (never minted, whichever hex case its uuid takes; minted by another Region's
//! endpoint; a resource part this service does not mint; torn down after a full tag
//! round-trip, for more than one configuration type) — crossed with every route of the tag
//! plane: the read, and both mutations. The deleted rows are the sequence a client's
//! delete-then-reconcile loop walks: `TagResource` and `ListTagsForResource` on a live
//! manager, the delete, the teardown the clock owes, and then the tag plane on the ARN that
//! now names nothing. A live manager of another type, tagged the same way, is read back at
//! the end as the positive control.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use service_com_amazonaws_ssmquicksetup_quicksetup::state::QUICK_SETUP_TYPE_CATALOG;
use smithy_server_runtime::MultiServiceRouter;

/// The region every request below signs for.
const REGION: &str = "us-west-2";

/// One emulator with an empty store, mounted exactly as the router mounts it.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_ssmquicksetup_quicksetup::EmulatedService::new(engine),
    );
    router
}

/// A request signed for `ssm-quicksetup` in [`REGION`], the signal the router routes on
/// and the handlers read the Region from.
fn request(method: &str, uri: &str, body: Option<&Value>) -> http::Request<bytes::Bytes> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", format!("ssm-quicksetup.{REGION}.amazonaws.com"))
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDQUICKSETUP/20260101/{REGION}/ssm-quicksetup/aws4_request, \
                 SignedHeaders=host, Signature=0000"
            ),
        );
    let payload = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            bytes::Bytes::from(serde_json::to_vec(value).expect("serialize the request body"))
        }
        None => bytes::Bytes::new(),
    };
    builder.body(payload).expect("a well-formed test request")
}

/// Status and parsed body of one call. An empty body reads as `Value::Null`.
async fn call(
    router: &MultiServiceRouter,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let response = router.dispatch(request(method, uri, body)).await;
    let status = response.status().as_u16();
    let error_type = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let raw = response.into_body();
    let mut parsed: Value = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&raw).to_string()))
    };
    // restJson1 carries the error shape in `__type`, and the framework also sets the
    // `x-amzn-errortype` header; fold the header in so one accessor reads either.
    if let (Some(error_type), Value::Object(map)) = (error_type, &mut parsed) {
        map.entry("__type")
            .or_insert_with(|| Value::String(error_type));
    }
    (status, parsed)
}

/// The modelled error shape a failed call reported.
fn error_code(body: &Value) -> String {
    body.get("__type")
        .and_then(Value::as_str)
        .unwrap_or("<no __type>")
        // An error `__type` may be namespaced (`com.amazonaws.ssmquicksetup#Foo`).
        .rsplit('#')
        .next()
        .unwrap_or("<no __type>")
        .to_string()
}

/// The sentence a refusal carried, read through either casing a refusal body may name its
/// single message member under — this service's modelled `Message`, or the lower-case
/// `message` the layer in front of it uses — so a row asserting WHICH one it got cannot be
/// fooled by reading only the one it expects.
fn error_message(body: &Value) -> String {
    ["Message", "message"]
        .iter()
        .filter_map(|key| body.get(*key))
        .filter_map(Value::as_str)
        .next()
        .unwrap_or("<no Message>")
        .to_string()
}

/// Percent-encode a value for use as one `@httpLabel` path segment, which is what an SDK
/// does: a non-greedy label may not carry a raw `/`.
fn label(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '/' => "%2F".to_string(),
            ' ' => "%20".to_string(),
            other => other.to_string(),
        })
        .collect()
}

/// The one tag key every row below assigns and removes. Nothing about the rule turns on
/// the key, which is why one is enough here (`tests/all/resource_tags.rs` holds the rules
/// that do).
const TAG_KEY: &str = "owner";

/// `PUT /tags/{ResourceArn}` — `TagResource`. `Tags` is a body member, so the map travels
/// in the restJson1 payload.
async fn tag(router: &MultiServiceRouter, resource_arn: &str, value: &str) -> (u16, Value) {
    let mut tags = Map::new();
    tags.insert(TAG_KEY.to_string(), Value::String(value.to_string()));
    call(
        router,
        "PUT",
        &format!("/tags/{}", label(resource_arn)),
        Some(&json!({ "Tags": Value::Object(tags) })),
    )
    .await
}

/// `GET /tags/{ResourceArn}` — `ListTagsForResource`.
async fn list_tags(router: &MultiServiceRouter, resource_arn: &str) -> (u16, Value) {
    call(router, "GET", &format!("/tags/{}", label(resource_arn)), None).await
}

/// `DELETE /tags/{ResourceArn}?tagKeys=…` — `UntagResource`. `TagKeys` is `@required` and
/// bound to the `tagKeys` query parameter, so one key travels as one parameter.
async fn untag(router: &MultiServiceRouter, resource_arn: &str) -> (u16, Value) {
    call(
        router,
        "DELETE",
        &format!("/tags/{}?tagKeys={TAG_KEY}", label(resource_arn)),
        None,
    )
    .await
}

/// The tags `ListTagsForResource` reports for `resource_arn`, as a map.
async fn listed(router: &MultiServiceRouter, case: &str, resource_arn: &str) -> BTreeMap<String, String> {
    let (status, answer) = list_tags(router, resource_arn).await;
    assert_eq!(
        status, 200,
        "case {case:?}: ListTagsForResource on a live resource must answer 200, got \
         {status} / {answer:?}"
    );
    answer
        .get("Tags")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("case {case:?}: expected a Tags list, got {answer:?}"))
        .iter()
        .map(|entry| {
            (
                entry["Key"].as_str().unwrap_or_default().to_string(),
                entry["Value"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Every route of the tag plane, by the operation bound to it
/// (`smithy_query(query="digest")`: `GET`, `PUT` and `DELETE /tags/{ResourceArn}`), with
/// the sentence that operation must state for an ARN naming no resource — written out here
/// rather than read from the crate, so the test pins the text itself. Wholly fixed text in
/// both cases, and two DIFFERENT sentences: the sentence belongs to the error class of the
/// operation stating it, so the read's is not the mutations'.
const TAG_PLANE_ROUTES: &[(&str, &str)] = &[
    (
        "ListTagsForResource",
        "Configuration with requested id does not exist.",
    ),
    ("TagResource", "Resource arn not found."),
    ("UntagResource", "Resource arn not found."),
];

/// Drive one of [`TAG_PLANE_ROUTES`] against `resource_arn`.
async fn call_tag_plane(
    router: &MultiServiceRouter,
    operation: &str,
    resource_arn: &str,
) -> (u16, Value) {
    match operation {
        "ListTagsForResource" => list_tags(router, resource_arn).await,
        "TagResource" => tag(router, resource_arn, "post-delete").await,
        "UntagResource" => untag(router, resource_arn).await,
        other => panic!("no route is wired for operation {other:?}"),
    }
}

/// Assert one tag-plane refusal of an ARN naming no resource: the modelled status and
/// shape, the fixed sentence that operation states, under the modelled member — and that
/// it is the resource channel rather than the authorization one.
fn assert_absent_resource(case: &str, arn: &str, expected: &str, status: u16, answer: &Value) {
    let code = error_code(answer);
    // Non-existence is never an authorization outcome: the front door's refusal is the
    // 401 / `UnauthorizedException` an ARN the caller may not address earns, and no row
    // here is one of those.
    assert_ne!(
        status, 401,
        "case {case:?}: an absent resource is reported on the resource channel, not as an \
         authorization refusal, got {status} / {answer:?}"
    );
    assert_ne!(
        code, "UnauthorizedException",
        "case {case:?}: an absent resource is reported on the resource channel, not as an \
         authorization refusal, got {code:?} in {answer:?}"
    );
    assert_eq!(
        status, 404,
        "case {case:?}: expected the modelled 404, got {status} / {answer:?}"
    );
    assert_eq!(
        code, "ResourceNotFoundException",
        "case {case:?}: expected ResourceNotFoundException, got {code:?} in {answer:?}"
    );
    let actual = error_message(answer);
    assert_eq!(
        actual, expected,
        "case {case:?}: expected {expected:?}, got {actual:?}"
    );
    // The modelled shape names its single member `Message`, so that is where a client
    // reading `Error.Message` finds the sentence.
    assert_eq!(
        answer.get("Message").and_then(Value::as_str),
        Some(expected),
        "case {case:?}: expected the sentence under `Message`, got {answer:?}"
    );
    // Wholly fixed text: nothing of the request is rendered into it, and it is not the
    // sentence the manager routes state for the same resource.
    assert!(
        !actual.contains(arn),
        "case {case:?}: a wholly fixed sentence renders nothing of the request, got \
         {actual:?}"
    );
    assert!(
        !actual.contains("could not be found"),
        "case {case:?}: the tag plane states its own sentence rather than the manager \
         routes', got {actual:?}"
    );
}

/// Create one configuration manager of `type_`, answering its ARN.
async fn create_manager(router: &MultiServiceRouter, case: &str, type_: &str) -> String {
    // A definition is accepted only when its `Parameters` provide every parameter the
    // table documented for its `Type` marks `(Required)`; no case here is about the
    // parameters, so the rest are filled from the shared fixture.
    let body = json!({
        "Name": "tag-plane-absent-resource",
        "ConfigurationDefinitions": [{
            "Type": type_,
            "Parameters": super::type_parameter_fixtures::with_required_parameters(
                type_,
                json!({
                    "TargetOrganizationalUnits": "ou-1",
                    "TargetRegions": "us-east-1",
                }),
            ),
        }],
    });
    let (status, answer) = call(router, "POST", "/configurationManager", Some(&body)).await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateConfigurationManager must succeed, got {status} / {answer:?}"
    );
    answer
        .get("ManagerArn")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case {case:?}: expected a ManagerArn, got {answer:?}"))
        .to_string()
}

/// Tag a live manager through the wire and read the assignment back, so the ARN each
/// deleted row below sends did serve the tag plane while the manager was there.
async fn tag_round_trip(router: &MultiServiceRouter, case: &str, manager_arn: &str, value: &str) {
    let (status, answer) = tag(router, manager_arn, value).await;
    assert_eq!(
        status, 200,
        "case {case:?}: TagResource on a live resource must answer 200, got {status} / \
         {answer:?}"
    );
    let reported = listed(router, case, manager_arn).await;
    let expected: BTreeMap<String, String> =
        [(TAG_KEY.to_string(), value.to_string())].into_iter().collect();
    assert_eq!(
        reported, expected,
        "case {case:?}: expected {expected:?} read back, got {reported:?}"
    );
}

/// Delete one manager and wait for the teardown the clock owes it, so its ARN names
/// nothing afterwards.
async fn delete_manager(router: &MultiServiceRouter, case: &str, manager_arn: &str) {
    let (status, answer) = call(
        router,
        "DELETE",
        &format!("/configurationManager/{}", label(manager_arn)),
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: DeleteConfigurationManager must be accepted, got {status} / \
         {answer:?}"
    );
    // A delete starts an asynchronous teardown, so the manager leaves the store when that
    // teardown comes due: wait for that CONDITION, not for a duration
    // (`tests/all/target_authorization.rs` owns the one wait).
    super::target_authorization::poll_until_absent(router, case, manager_arn).await;
}

/// ARNs of this service and of the account the request is signed for that no create
/// minted, so each names no resource this endpoint holds while the caller is entitled to
/// address it. The rows differ in the uuid and in its hex case — both admitted by the
/// modelled `ManagerArn` pattern
/// `^arn:aws:ssm-quicksetup:([^:]+):(\d{12}):configuration-manager/<uuid>$` — in the
/// Region the ARN names, and in the resource part, none of which is part of the answer.
const UNSERVED_ARNS: &[(&str, &str)] = &[
    (
        "a well-formed ARN no create minted",
        "arn:aws:ssm-quicksetup:us-west-2:000000000000:configuration-manager/00000000-0000-0000-0000-000000000000",
    ),
    (
        "a well-formed ARN whose uuid is upper-case hex",
        "arn:aws:ssm-quicksetup:us-west-2:000000000000:configuration-manager/ABCDEF01-2345-6789-ABCD-EF0123456789",
    ),
    (
        "an ARN of this account minted by another Region's endpoint",
        "arn:aws:ssm-quicksetup:eu-central-1:000000000000:configuration-manager/11111111-2222-3333-4444-555555555555",
    ),
    (
        "an ARN naming a resource kind this service does not mint",
        "arn:aws:ssm-quicksetup:us-west-2:000000000000:configuration/not-a-manager",
    ),
];

/// Every route of the tag plane answers an entitled ARN naming no resource with its own
/// modelled 404 and fixed sentence, whichever form that ARN takes.
#[tokio::test]
async fn the_tag_plane_reports_an_absent_resource_as_the_modelled_not_found() {
    let router = emulator();
    // A live, tagged manager, so every refusal below is about the ARN that was sent rather
    // than about an empty store.
    let live = create_manager(&router, "a live manager", QUICK_SETUP_TYPE_CATALOG[0].type_).await;
    tag_round_trip(&router, "a live manager", &live, "manager-live").await;

    for (arn_case, arn) in UNSERVED_ARNS {
        for (operation, expected) in TAG_PLANE_ROUTES {
            let case = format!("{operation} on {arn_case}");
            let (status, answer) = call_tag_plane(&router, operation, arn).await;
            assert_absent_resource(&case, arn, expected, status, &answer);
        }
    }

    // Positive control: the live manager still reports exactly the tag it was assigned, so
    // none of the refused calls touched another resource.
    let reported = listed(&router, "a live manager", &live).await;
    assert_eq!(
        reported,
        [(TAG_KEY.to_string(), "manager-live".to_string())]
            .into_iter()
            .collect::<BTreeMap<String, String>>(),
        "the live manager's tags must still be reported after the refused calls, got \
         {reported:?}"
    );
}

/// The same answer for the ARN of a manager that WAS served by the tag plane and was then
/// deleted: once the teardown the clock owes has come due, the ARN names no resource, which
/// is each operation's own modelled 404 — not an authorization refusal, and not the manager
/// routes' sentence. Two configuration types are torn down, because what the manager
/// deployed is no part of the rule, and a third manager stays live as the control.
#[tokio::test]
async fn a_deleted_resource_s_arn_is_reported_as_the_modelled_not_found() {
    let router = emulator();
    let survivor_type = QUICK_SETUP_TYPE_CATALOG[0].type_;
    let survivor = create_manager(&router, "a surviving manager", survivor_type).await;
    tag_round_trip(&router, "a surviving manager", &survivor, "manager-b").await;

    // One row per configuration type torn down: the type a definition deploys is no part
    // of the rule, so a manager of either kind names nothing once it is gone.
    for type_ in ["AWSQuickSetupType-SSMHostMgmt", "AWSQuickSetupType-Distributor"] {
        let case = format!("a manager deployed from {type_}");
        let doomed = create_manager(&router, &case, type_).await;
        assert_ne!(
            doomed, survivor,
            "case {case:?}: each create must mint its own ARN, got {doomed:?} twice"
        );
        tag_round_trip(&router, &case, &doomed, "manager-a").await;
        delete_manager(&router, &case, &doomed).await;

        for (operation, expected) in TAG_PLANE_ROUTES {
            let case = format!("{operation} on the ARN of {case}");
            let (status, answer) = call_tag_plane(&router, operation, &doomed).await;
            assert_absent_resource(&case, &doomed, expected, status, &answer);
        }
    }

    // Positive control: the manager that was not deleted still reports its own tag.
    let reported = listed(&router, "a surviving manager", &survivor).await;
    assert_eq!(
        reported,
        [(TAG_KEY.to_string(), "manager-b".to_string())]
            .into_iter()
            .collect::<BTreeMap<String, String>>(),
        "the surviving manager's tags must still be reported after the deletions, got \
         {reported:?}"
    );
}
