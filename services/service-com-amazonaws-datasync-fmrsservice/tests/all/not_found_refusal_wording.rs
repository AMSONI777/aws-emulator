// SPDX-License-Identifier: CC0-1.0

//! How this service identifies a resource it could not resolve.
//!
//! RULE: every client failure of this service is the one modelled `InvalidRequestException`
//! (400), so the CLASS of a refusal travels in that error's two code members — `errorCode`
//! and `datasyncErrorCode`, always the same value — and a resource this service holds no
//! record of has its own class per resource kind: `LocationNotFound` for a transfer
//! location, `SyncSetNotFound` for a transfer task. The message identifies the resource the
//! way the SURFACE that raised the refusal addresses one: an operation of the task surface
//! by the bare resource id, an operation of the location surface by the ARN the request
//! carried. Neither names the request member that held the value.
//!
//! A refusal is about STATE, not about the shape of an ARN: a resource this service minted
//! resolves, and the same ARN stops resolving once the resource is deleted.
//!
//! Every case goes through the same front door a client uses: `POST /` with
//! `X-Amz-Target: FmrsService.<Operation>` and an `awsJson1_1` body, dispatched by the
//! multi-service router. Nothing reaches into the state struct.

use std::sync::Arc;

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

/// The region every request in this suite signs for.
const SIGNED_REGION: &str = "us-west-2";

/// The class a refusal naming a transfer location this account does not hold carries.
const LOCATION_NOT_FOUND: &str = "LocationNotFound";

/// The class a refusal naming a transfer task this account does not hold carries. It is the
/// name the surface holding tasks has for one, not the name the caller used.
const SYNC_SET_NOT_FOUND: &str = "SyncSetNotFound";

/// A router with just this service mounted on a fresh engine.
fn service() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_datasync_fmrsservice::EmulatedService::new(engine),
    );
    router
}

/// One `awsJson1_1` call, returning the HTTP status and the parsed response body.
async fn call(router: &MultiServiceRouter, operation: &str, body: Value) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", format!("FmrsService.{operation}"))
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDDATASYNCTEST/20260101/{SIGNED_REGION}\
                 /datasync/aws4_request, SignedHeaders=host;x-amz-target, Signature=00"
            ),
        )
        .body(bytes::Bytes::from(
            serde_json::to_vec(&body).expect("the request body serializes"),
        ))
        .expect("a well-formed request");

    let response = router.dispatch(request).await;
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

/// A call that must succeed, returning its body.
async fn ok(router: &MultiServiceRouter, operation: &str, body: Value, case: &str) -> Value {
    let (status, parsed) = call(router, operation, body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected {operation} to answer 200, got {status} with {parsed}"
    );
    parsed
}

/// A call that must be refused with the whole envelope a not-found class carries: HTTP 400,
/// the one modelled client error, that class in BOTH code members, and the whole message.
async fn refused_as_absent(
    router: &MultiServiceRouter,
    operation: &str,
    body: Value,
    class: &str,
    message: &str,
    case: &str,
) {
    let (status, parsed) = call(router, operation, body).await;
    assert_eq!(
        status, 400,
        "case {case:?}: expected {operation} to answer 400, got {status} with {parsed}"
    );
    assert!(
        parsed["__type"]
            .as_str()
            .unwrap_or_default()
            .ends_with("InvalidRequestException"),
        "case {case:?}: expected an InvalidRequestException from {operation}, got {parsed}"
    );
    for member in ["errorCode", "datasyncErrorCode"] {
        assert_eq!(
            parsed[member].as_str(),
            Some(class),
            "case {case:?}: expected {member} {class:?} from {operation}, got {parsed}"
        );
    }
    assert_eq!(
        parsed["message"].as_str(),
        Some(message),
        "case {case:?}: wrong refusal wording from {operation}, got {parsed}"
    );
}

/// A well-formed ARN of one of this service's resources that this service never minted:
/// `resource` is the ARN's resource part.
fn never_minted(resource: &str) -> String {
    format!(
        "arn:aws:datasync:{SIGNED_REGION}:{account}:{resource}",
        account = engine::emulator_account_id()
    )
}

/// The bare resource id an ARN addresses: what a refusal raised by the task surface
/// identifies a resource by.
fn resource_id(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

/// An Amazon S3 transfer location for `bucket`, created and returned by ARN.
async fn given_location(router: &MultiServiceRouter, bucket: &str, case: &str) -> String {
    let created = ok(
        router,
        "CreateLocationS3",
        json!({
            "S3BucketArn": format!("arn:aws:s3:::{bucket}"),
            "S3Config": {
                "BucketAccessRoleArn": format!(
                    "arn:aws:iam::{account}:role/datasync-bucket-access",
                    account = engine::emulator_account_id()
                ),
            },
        }),
        case,
    )
    .await;
    created["LocationArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a LocationArn, got {created}"))
        .to_string()
}

/// RULE: an operation of the TASK surface that cannot resolve the task a request names
/// refuses with the `SyncSetNotFound` class and identifies the task by its bare resource id.
///
/// The rows differ along what the rule generalises over: which operation of that surface was
/// called — a read, a delete, a start and a list — and which unheld task id it named.
#[tokio::test]
async fn the_task_surface_names_an_absent_task_by_its_resource_id() {
    let router = service();
    let absent = never_minted("task/task-0abcdef1234567890");
    let other_absent = never_minted("task/task-1234567890abcdef0");

    // (case, operation, the member carrying the task ARN, the ARN it carried)
    let rows: [(&str, &str, &str, &String); 5] = [
        ("a read", "DescribeTask", "TaskArn", &absent),
        ("a delete", "DeleteTask", "TaskArn", &absent),
        ("a start", "StartTaskExecution", "TaskArn", &absent),
        ("a list of its runs", "ListTaskExecutions", "TaskArn", &absent),
        ("another unheld task", "DescribeTask", "TaskArn", &other_absent),
    ];

    for (case, operation, member, arn) in rows {
        refused_as_absent(
            &router,
            operation,
            json!({ member: arn }),
            SYNC_SET_NOT_FOUND,
            &format!("Task {} is not found.", resource_id(arn)),
            case,
        )
        .await;
    }
}

/// RULE: a task's `LocationArn` members are references, so the TASK surface states a
/// location it cannot resolve by the bare resource id too — and names neither which member
/// carried it nor the ARN itself.
///
/// The rows differ along which member carried the unheld location and whether the other
/// member names one this account holds, so one refusal covers both sides of a task.
#[tokio::test]
async fn the_task_surface_names_an_absent_referenced_location_by_its_resource_id() {
    let router = service();
    let held = given_location(&router, "reference-held", "setup").await;
    let absent = never_minted("location/loc-0abcdef1234567890");
    let other_absent = never_minted("location/loc-1234567890abcdef0");

    // (case, the source the task names, the destination it names, the unheld location)
    let rows: [(&str, &String, &String, &String); 4] = [
        ("an unheld source", &absent, &held, &absent),
        ("an unheld destination", &held, &absent, &absent),
        ("two unheld locations", &absent, &other_absent, &absent),
        (
            "another unheld source",
            &other_absent,
            &held,
            &other_absent,
        ),
    ];

    for (case, source, destination, unheld) in rows {
        refused_as_absent(
            &router,
            "CreateTask",
            json!({
                "SourceLocationArn": source,
                "DestinationLocationArn": destination,
                "Name": case,
            }),
            LOCATION_NOT_FOUND,
            &format!("Location {} is not found.", resource_id(unheld)),
            case,
        )
        .await;
    }
}

/// RULE: an operation of the LOCATION surface — one whose own addressed resource is the
/// location — refuses an unheld location with the same class and identifies it by the ARN the
/// request carried.
///
/// The rows differ along which operation of that surface was called and which unheld
/// location it named.
#[tokio::test]
async fn the_location_surface_names_an_absent_location_by_the_arn_it_was_given() {
    let router = service();
    let absent = never_minted("location/loc-0abcdef1234567890");
    let other_absent = never_minted("location/loc-1234567890abcdef0");

    // (case, operation, the ARN the request carried)
    let rows: [(&str, &str, &String); 4] = [
        ("a read of an S3 location", "DescribeLocationS3", &absent),
        (
            "a read of an object storage location",
            "DescribeLocationObjectStorage",
            &absent,
        ),
        ("a delete", "DeleteLocation", &absent),
        (
            "another unheld location",
            "DescribeLocationS3",
            &other_absent,
        ),
    ];

    for (case, operation, arn) in rows {
        refused_as_absent(
            &router,
            operation,
            json!({ "LocationArn": arn }),
            LOCATION_NOT_FOUND,
            &format!("Location {arn} is not found."),
            case,
        )
        .await;
    }
}

/// RULE: the refusal reports STATE: a task and a location this service minted resolve, and
/// the same ARNs stop resolving — each under its own class and its own wording — once the
/// resources are deleted.
#[tokio::test]
async fn a_resource_resolves_until_it_is_deleted() {
    let router = service();
    let source = given_location(&router, "lifecycle-source", "setup").await;
    let destination = given_location(&router, "lifecycle-destination", "setup").await;
    let created = ok(
        &router,
        "CreateTask",
        json!({
            "SourceLocationArn": source,
            "DestinationLocationArn": destination,
            "Name": "lifecycle-task",
        }),
        "setup",
    )
    .await;
    let task_arn = created["TaskArn"]
        .as_str()
        .unwrap_or_else(|| panic!("case \"setup\": expected a TaskArn, got {created}"))
        .to_string();

    // Both resources resolve while this service holds them.
    let described = ok(
        &router,
        "DescribeTask",
        json!({ "TaskArn": &task_arn }),
        "the task it minted",
    )
    .await;
    assert_eq!(
        described["TaskArn"].as_str(),
        Some(task_arn.as_str()),
        "case \"the task it minted\": expected the task to read back, got {described}"
    );
    let described = ok(
        &router,
        "DescribeLocationS3",
        json!({ "LocationArn": &source }),
        "the location it minted",
    )
    .await;
    assert_eq!(
        described["LocationArn"].as_str(),
        Some(source.as_str()),
        "case \"the location it minted\": expected the location to read back, got {described}"
    );

    // Deleting them is what makes the two refusals due, each in its surface's own words.
    ok(
        &router,
        "DeleteTask",
        json!({ "TaskArn": &task_arn }),
        "deleting the task",
    )
    .await;
    refused_as_absent(
        &router,
        "DescribeTask",
        json!({ "TaskArn": &task_arn }),
        SYNC_SET_NOT_FOUND,
        &format!("Task {} is not found.", resource_id(&task_arn)),
        "the deleted task",
    )
    .await;

    ok(
        &router,
        "DeleteLocation",
        json!({ "LocationArn": &source }),
        "deleting the location",
    )
    .await;
    refused_as_absent(
        &router,
        "DescribeLocationS3",
        json!({ "LocationArn": &source }),
        LOCATION_NOT_FOUND,
        &format!("Location {source} is not found."),
        "the deleted location",
    )
    .await;
}
