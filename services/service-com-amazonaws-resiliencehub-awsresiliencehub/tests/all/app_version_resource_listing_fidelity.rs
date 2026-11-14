// SPDX-License-Identifier: CC0-1.0

//! `ListAppVersionResources` answers from persisted state, and answering it changes
//! nothing a later caller sees.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` with a
//! restJson1 request — and asserts the response BODY, not just the status.
//!
//! The rules under test:
//!
//! * the operation is SERVED (never the scaffold's 501) and each resource it lists
//!   is exactly the `PhysicalResource` the create persisted: the same record
//!   `DescribeAppVersionResource` reads back, member for member, whatever form the
//!   resource's identifiers, type, name, components and `additionalInfo` take;
//! * listing is a pure read: for every form of the request — unpaged, paged,
//!   resumed by `nextToken`, against a named `resolutionId`, against the draft and
//!   against a published version — what a later caller reads is unchanged, and a
//!   listing of a version nobody resolved mints no resolution for it, whatever it
//!   answers such a caller.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use service_com_amazonaws_resiliencehub_awsresiliencehub::state::{
    DRAFT_APP_VERSION, RELEASE_APP_VERSION, SUPPORTED_RESOURCE_TYPES,
};
use smithy_server_runtime::MultiServiceRouter;

// The wire harness every suite in this crate shares: the one-service router, the
// signed restJson1 POST and the reply it answers with.
use super::application_lifecycle::{emulator, post, Reply, ACCOUNT, REGION};

/// The modelled `@length` of `String255`, the shape the output's `resolutionId`
/// targets (`smithy_query query="operation"
/// operation="ListAppVersionResources"`: `resolutionId` targets `String255`,
/// required, length 1..255).
const RESOLUTION_ID_LENGTH: std::ops::RangeInclusive<usize> = 1..=255;

/// An application to list the resources of, and its ARN.
async fn create_an_app(router: &MultiServiceRouter, name: &str) -> String {
    let reply = post(router, "/create-app", &json!({"name": name})).await;
    reply.ok(name)["app"]["appArn"]
        .as_str()
        .expect("a minted appArn")
        .to_string()
}

/// `ListAppVersionResources` for one version of one application, with whatever
/// extra members `request` carries.
async fn list_resources(
    router: &MultiServiceRouter,
    app_arn: &str,
    app_version: &str,
    request: &Value,
) -> Reply {
    let mut body = request.clone();
    body["appArn"] = json!(app_arn);
    body["appVersion"] = json!(app_version);
    post(router, "/list-app-version-resources", &body).await
}

/// `DescribeAppVersionResource` for the resource `logical_identifier` names.
async fn describe_resource(
    router: &MultiServiceRouter,
    app_arn: &str,
    app_version: &str,
    logical_identifier: &str,
) -> Reply {
    post(
        router,
        "/describe-app-version-resource",
        &json!({
            "appArn": app_arn,
            "appVersion": app_version,
            "logicalResourceId": {"identifier": logical_identifier},
        }),
    )
    .await
}

/// The `physicalResources` of a successful listing.
fn physical_resources(reply: &Reply, case: &str) -> Vec<Value> {
    reply.ok(case)["physicalResources"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: physicalResources is @required, got {:?}",
                reply.body
            )
        })
        .clone()
}

/// The whole listing of one version, read without a page bound, keyed by each
/// resource's `logicalResourceId.identifier`, together with the `resolutionId` the
/// listing is against.
async fn whole_listing(
    router: &MultiServiceRouter,
    app_arn: &str,
    app_version: &str,
    case: &str,
) -> (String, BTreeMap<String, Value>) {
    let reply = list_resources(router, app_arn, app_version, &json!({})).await;
    let resolution_id = reply.ok(case)["resolutionId"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: resolutionId is @required, got {:?}",
                reply.body
            )
        })
        .to_string();
    assert!(
        RESOLUTION_ID_LENGTH.contains(&resolution_id.chars().count()),
        "case {case:?}: resolutionId {resolution_id:?} is outside the modelled \
         length {RESOLUTION_ID_LENGTH:?}"
    );
    let listed = physical_resources(&reply, case)
        .into_iter()
        .map(|resource| {
            let identifier = resource["logicalResourceId"]["identifier"]
                .as_str()
                .expect("logicalResourceId.identifier is @required")
                .to_string();
            (identifier, resource)
        })
        .collect();
    (resolution_id, listed)
}

/// Start a resolution of `app_version` of `app_arn` and answer its id.
async fn resolve(router: &MultiServiceRouter, app_arn: &str, app_version: &str) -> String {
    post(
        router,
        "/resolve-app-version-resources",
        &json!({"appArn": app_arn, "appVersion": app_version}),
    )
    .await
    .ok(&format!("resolve {app_version}"))["resolutionId"]
        .as_str()
        .expect("a minted resolutionId")
        .to_string()
}

/// One row of the resource table: a resource to add to the draft, and what the
/// listing has to report for it.
struct Row {
    case: &'static str,
    /// `logicalResourceId.identifier` — a `String255` with no modelled pattern, so
    /// a row can carry a form the modelled `EntityName` does not admit.
    identifier: &'static str,
    /// `resourceName`, when the request names one.
    resource_name: Option<&'static str>,
    /// The name the listing has to report, `None` for a resource that can carry
    /// none.
    expected_resource_name: Option<&'static str>,
    /// `physicalResourceId`, in either of the two forms a client holds a resource
    /// by.
    physical_resource_id: &'static str,
    /// The `PhysicalResourceId$type` that identifier is: the modelled
    /// `PhysicalIdentifierType` is `Arn` for "an Amazon Resource Name (ARN)" and
    /// `Native` for "an Resilience Hub-native identifier" (the member's own doc,
    /// `smithy_query query="shape" shape="PhysicalResourceId"`).
    expected_identifier_type: &'static str,
    /// A `resourceType` from this service's supported-resource catalogue,
    /// `service_..::state::SUPPORTED_RESOURCE_TYPES`.
    resource_type: &'static str,
    app_components: &'static [&'static str],
    /// An `additionalInfo` entry: one key and its value list.
    additional_info: Option<(&'static str, &'static [&'static str])>,
}

/// The table: one resource per row, all added to ONE application's draft.
///
/// The rows differ along what the rule generalises over — the form of the logical
/// identifier (a plain name, one carrying an underscore, one a single character,
/// one outside the modelled `EntityName`), whether the request names the resource
/// or leaves it to be named by its identifier, the form of the physical identifier
/// (native id or ARN, so both `PhysicalIdentifierType` values), the resource type
/// (five catalogue entries, none of them the `AWS::S3::Bucket` the issue cited),
/// how many Application Components a resource belongs to and whether it shares one
/// with another row, and whether it carries `additionalInfo`.
fn resource_table() -> Vec<Row> {
    vec![
        Row {
            case: "native id, name derived from the identifier",
            identifier: "orders_table",
            resource_name: None,
            expected_resource_name: Some("orders_table"),
            physical_resource_id: "orders-table",
            expected_identifier_type: "Native",
            resource_type: "AWS::DynamoDB::Table",
            app_components: &["data-tier"],
            additional_info: None,
        },
        Row {
            case: "ARN id, explicit name, additionalInfo",
            identifier: "payments-fn",
            resource_name: Some("payments-function"),
            expected_resource_name: Some("payments-function"),
            physical_resource_id: "arn:aws:lambda:us-east-1:000000000000:function:payments",
            expected_identifier_type: "Arn",
            resource_type: "AWS::Lambda::Function",
            app_components: &["compute-tier"],
            additional_info: Some(("failover-regions", &["[{\"region\":\"us-west-2\"}]"])),
        },
        Row {
            case: "identifier outside EntityName, so no name to derive",
            identifier: "stacks/orders/queue",
            resource_name: None,
            expected_resource_name: None,
            physical_resource_id: "arn:aws:sqs:us-east-1:000000000000:orders-events",
            expected_identifier_type: "Arn",
            resource_type: "AWS::SQS::Queue",
            app_components: &["messaging-tier"],
            additional_info: None,
        },
        Row {
            case: "two components, one shared with another resource",
            identifier: "edge-api",
            resource_name: None,
            expected_resource_name: Some("edge-api"),
            physical_resource_id: "a1b2c3d4e5",
            expected_identifier_type: "Native",
            resource_type: "AWS::ApiGateway::RestApi",
            app_components: &["edge-tier", "compute-tier"],
            additional_info: None,
        },
        Row {
            case: "single-character identifier, shorter than EntityName admits",
            identifier: "x",
            resource_name: None,
            expected_resource_name: None,
            physical_resource_id: "db-primary",
            expected_identifier_type: "Native",
            resource_type: "AWS::RDS::DBInstance",
            app_components: &["data-tier"],
            additional_info: None,
        },
    ]
}

/// Add one row's resource to `app_arn`'s draft and answer the `physicalResource`
/// the create persisted.
async fn create_row(router: &MultiServiceRouter, app_arn: &str, row: &Row) -> Value {
    assert!(
        SUPPORTED_RESOURCE_TYPES.contains(&row.resource_type),
        "case {:?}: {} is outside this service's supported-resource catalogue",
        row.case,
        row.resource_type
    );
    let mut request = json!({
        "appArn": app_arn,
        "logicalResourceId": {"identifier": row.identifier},
        "physicalResourceId": row.physical_resource_id,
        "resourceType": row.resource_type,
        "appComponents": row.app_components,
    });
    if let Some(resource_name) = row.resource_name {
        request["resourceName"] = json!(resource_name);
    }
    if let Some((key, values)) = row.additional_info {
        request["additionalInfo"] = json!({key: values});
    }
    let reply = post(router, "/create-app-version-resource", &request).await;
    let created = reply.ok(row.case)["physicalResource"].clone();
    assert!(
        created.is_object(),
        "case {:?}: the create reported no physicalResource, got {:?}",
        row.case,
        reply.body
    );
    created
}

/// Every resource the listing reports is the record the create persisted — the
/// same one `DescribeAppVersionResource` reads back — for every form a resource's
/// members take.
#[tokio::test]
async fn lists_each_resource_exactly_as_it_was_persisted() {
    let router = emulator();
    let app_arn = create_an_app(&router, "listing-fidelity").await;

    let table = resource_table();
    let mut created: BTreeMap<&str, Value> = BTreeMap::new();
    for row in &table {
        created.insert(row.identifier, create_row(&router, &app_arn, row).await);
    }
    // The composed draft is RESOLVED before it is listed: a listing is a read over a
    // resolution, so the fixture gives it one rather than relying on what the
    // service answers for a version nobody resolved.
    resolve(&router, &app_arn, DRAFT_APP_VERSION).await;

    let (_, listed) = whole_listing(&router, &app_arn, DRAFT_APP_VERSION, "draft listing").await;
    assert_eq!(
        listed.len(),
        table.len(),
        "case \"draft listing\": expected the {} created resources, got {:?}",
        table.len(),
        listed.keys().collect::<Vec<_>>()
    );

    for row in &table {
        let case = row.case;
        let entry = listed.get(row.identifier).unwrap_or_else(|| {
            panic!(
                "case {case:?}: the listing holds no resource {:?}, only {:?}",
                row.identifier,
                listed.keys().collect::<Vec<_>>()
            )
        });

        // The listing reports the persisted record, not a response assembled per
        // call: it is the same object the create answered with.
        assert_eq!(
            entry,
            created.get(row.identifier).expect("a created resource"),
            "case {case:?}: the listed resource differs from the created one, got {entry:?}"
        );

        // ... and the same object the single-resource reader answers with.
        let described = describe_resource(&router, &app_arn, DRAFT_APP_VERSION, row.identifier)
            .await
            .ok(case)["physicalResource"]
            .clone();
        assert_eq!(
            entry, &described,
            "case {case:?}: the listed resource differs from the described one, got {described:?}"
        );

        assert_eq!(
            entry["physicalResourceId"]["identifier"].as_str(),
            Some(row.physical_resource_id),
            "case {case:?}: expected physicalResourceId.identifier {:?}, got {:?}",
            row.physical_resource_id,
            entry["physicalResourceId"]
        );
        assert_eq!(
            entry["physicalResourceId"]["type"].as_str(),
            Some(row.expected_identifier_type),
            "case {case:?}: expected physicalResourceId.type {:?}, got {:?}",
            row.expected_identifier_type,
            entry["physicalResourceId"]
        );
        assert_eq!(
            entry["physicalResourceId"]["awsAccountId"].as_str(),
            Some(ACCOUNT),
            "case {case:?}: expected the emulator's account, got {:?}",
            entry["physicalResourceId"]
        );
        assert_eq!(
            entry["physicalResourceId"]["awsRegion"].as_str(),
            Some(REGION),
            "case {case:?}: expected the request's Region, got {:?}",
            entry["physicalResourceId"]
        );
        assert_eq!(
            entry["resourceType"].as_str(),
            Some(row.resource_type),
            "case {case:?}: expected resourceType {:?}, got {:?}",
            row.resource_type,
            entry["resourceType"]
        );
        assert_eq!(
            entry["resourceName"].as_str(),
            row.expected_resource_name,
            "case {case:?}: expected resourceName {:?}, got {:?}",
            row.expected_resource_name,
            entry["resourceName"]
        );
        let components: Vec<&str> = entry["appComponents"]
            .as_array()
            .unwrap_or_else(|| panic!("case {case:?}: expected appComponents, got {entry:?}"))
            .iter()
            .map(|component| {
                component["name"]
                    .as_str()
                    .expect("AppComponent$name is @required")
            })
            .collect();
        assert_eq!(
            components, row.app_components,
            "case {case:?}: expected appComponents {:?}, got {components:?}",
            row.app_components
        );
        match row.additional_info {
            None => assert!(
                entry["additionalInfo"].is_null(),
                "case {case:?}: the resource carried no additionalInfo, got {:?}",
                entry["additionalInfo"]
            ),
            Some((key, values)) => assert_eq!(
                entry["additionalInfo"],
                json!({key: values}),
                "case {case:?}: expected the additionalInfo the create carried, got {:?}",
                entry["additionalInfo"]
            ),
        }
    }
}

/// Listing is a READ: whatever form the request takes, and whichever version it
/// addresses, a later caller reads exactly what it would have read before — and a
/// listing of a version nobody resolved mints no resolution for it.
#[tokio::test]
async fn listing_the_resources_changes_nothing_a_later_caller_sees() {
    let router = emulator();
    let app_arn = create_an_app(&router, "listing-is-a-read").await;
    let table = resource_table();
    for row in &table {
        create_row(&router, &app_arn, row).await;
    }

    // A draft nobody has resolved yet: WHATEVER the service answers such a listing,
    // the call mints no resolution for the version — the resolution status read
    // after it still finds none — and asking twice answers the same thing both
    // times. Asserted on the answer the first call gave, so this case pins the read
    // invariant without pinning which answer that is.
    let first = list_resources(&router, &app_arn, DRAFT_APP_VERSION, &json!({})).await;
    post(
        &router,
        "/describe-app-version-resources-resolution-status",
        &json!({"appArn": app_arn, "appVersion": DRAFT_APP_VERSION}),
    )
    .await
    .refused(
        "no resolution after a listing",
        404,
        "ResourceNotFoundException",
    );
    let again = list_resources(&router, &app_arn, DRAFT_APP_VERSION, &json!({})).await;
    assert_eq!(
        (again.status, &again.error_code, &again.body),
        (first.status, &first.error_code, &first.body),
        "case \"listed twice\": the second listing of an unchanged, unresolved draft \
         answered differently from the first"
    );

    // Now publish the draft, and resolve each of the two versions, so the request
    // forms below can address a named resolution of whichever version they list: a
    // resolution belongs to ONE app version.
    let published = post(&router, "/publish-app-version", &json!({"appArn": app_arn}))
        .await
        .ok("publish")["appVersion"]
        .as_str()
        .expect("a published appVersion")
        .to_string();
    assert_eq!(
        published, RELEASE_APP_VERSION,
        "case \"publish\": expected the published version to be addressable as \
         {RELEASE_APP_VERSION:?}, got {published:?}"
    );
    let mut resolutions: BTreeMap<&str, String> = BTreeMap::new();
    for app_version in [DRAFT_APP_VERSION, RELEASE_APP_VERSION] {
        resolutions.insert(app_version, resolve(&router, &app_arn, app_version).await);
    }

    // What a later caller reads, before any of the listings below runs.
    let draft_before = whole_listing(&router, &app_arn, DRAFT_APP_VERSION, "draft before").await;
    let release_before =
        whole_listing(&router, &app_arn, RELEASE_APP_VERSION, "release before").await;
    let versions_before = post(&router, "/list-app-versions", &json!({"appArn": app_arn}))
        .await
        .ok("versions before")["appVersions"]
        .clone();

    // Every form of the request: unpaged, at each published bound of `maxResults`,
    // resumed by a `nextToken`, against the named resolution, and against each of
    // the two versions.
    // The fixture holds one resource per table row, so a page bound of one still
    // walks the whole listing in that many pages, plus the last empty-tokened one.
    let most_pages = table.len() + 1;
    for app_version in [DRAFT_APP_VERSION, RELEASE_APP_VERSION] {
        let resolution_id = resolutions
            .get(app_version)
            .expect("a resolution of this version");
        for request in [
            json!({}),
            json!({"maxResults": 1}),
            json!({"maxResults": 100}),
            json!({"resolutionId": resolution_id}),
            json!({"maxResults": 2, "resolutionId": resolution_id}),
        ] {
            let case = format!("{app_version} listed with {request}");
            let mut body = request.clone();
            let mut pages = 0;
            loop {
                let reply = list_resources(&router, &app_arn, app_version, &body).await;
                reply.ok(&case);
                pages += 1;
                assert!(
                    pages <= most_pages,
                    "case {case:?}: pagination did not terminate after {pages} pages"
                );
                match reply.body["nextToken"].as_str() {
                    Some(next) => body["nextToken"] = json!(next),
                    None => break,
                }
            }
        }
    }

    let draft_after = whole_listing(&router, &app_arn, DRAFT_APP_VERSION, "draft after").await;
    let release_after =
        whole_listing(&router, &app_arn, RELEASE_APP_VERSION, "release after").await;
    let versions_after = post(&router, "/list-app-versions", &json!({"appArn": app_arn}))
        .await
        .ok("versions after")["appVersions"]
        .clone();

    assert_eq!(
        draft_after, draft_before,
        "case \"draft after\": listing the resources changed what the draft reports"
    );
    assert_eq!(
        release_after, release_before,
        "case \"release after\": listing the resources changed what the release reports"
    );
    assert_eq!(
        versions_after, versions_before,
        "case \"versions after\": listing the resources changed the application's versions"
    );
}
