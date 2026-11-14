// SPDX-License-Identifier: CC0-1.0

//! A CloudFormation stack that templates a table bucket's unreferenced-file-removal
//! maintenance settings deploys, and Amazon S3 Tables reports the bucket running exactly the
//! settings the declaration asked for — before and after a stack update rewrites them.
//!
//! The rule under test: **a property a resource type publishes is APPLIED through the owning
//! service's own call for it — the one call that writes that part of the resource, even where
//! the type's create takes no member for it — so the resource a completed stack publishes
//! carries what its declaration states, and a later declaration that states only such a
//! property is applied to the resource the stack already has rather than replacing it.** For
//! `AWS::S3Tables::TableBucket`'s `UnreferencedFileRemoval` that call is
//! `PutTableBucketMaintenanceConfiguration` (`PUT
//! /buckets/{tableBucketARN}/maintenance/{type}`, HTTP 204), which "creates a new maintenance
//! configuration or replaces an existing maintenance configuration for a table bucket" and is
//! therefore both halves of it; what the bucket then runs is what
//! `GetTableBucketMaintenanceConfiguration` reports for the `icebergUnreferencedFileRemoval`
//! task. Two crates have to agree for that to hold (CloudFormation makes the call, S3 Tables
//! serves it and decides the configuration in force), so the suite lives here rather than in
//! either one.
//!
//! The rows differ along what the rule generalises over: both `MaintenanceStatus` values, each
//! day count on its own and both together, the `@range(1, 2147483647)` bounds of the
//! `PositiveInteger` both of them target, a declaration that states no status, one that states
//! no maintenance block at all, a day count a template PARAMETER supplies as text, and both
//! template spellings. Every row that updates changes only day counts or the status, so every
//! one of them is an in-place change: the bucket keeps the ARN that is the resource's physical
//! id, and the identity and creation instant S3 Tables minted for it.
//!
//! Every expected value is computed here from what the row declares, never read back out of
//! the answer being checked.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Map, Value};
use smithy_server_runtime::MultiServiceRouter;

// The awsQuery CloudFormation caller, the poll that waits for a stack to FIRST report a
// status, the XML element readers and the SigV4 header builder are each written ONCE in this
// test crate: a suite that copies one drifts from the others.
use crate::cloudformation_apigatewayv2_resources::cloudformation;
use crate::cloudformation_firehose_stream_stabilisation::wait_for_stack_status;
use crate::query_wire::{elements, outputs_of, physical_ids_of};
use crate::rds_docdb_neptune_signing_name_routing::authorization;

/// The Region every request here is signed for — the Region the reused CloudFormation caller
/// and stack poll work in — and so the Region the table bucket belongs to and the one its ARN
/// carries.
const REGION: &str = "us-east-1";

/// The account id every ARN this emulator mints carries.
const ACCOUNT: &str = "000000000000";

/// The `StackStatus` values the rule is stated in.
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";
const UPDATE_COMPLETE: &str = "UPDATE_COMPLETE";

/// The resource type under test, the logical id every row declares it under, and the attribute
/// that type publishes.
const TABLE_BUCKET_TYPE: &str = "AWS::S3Tables::TableBucket";
const BUCKET_LOGICAL_ID: &str = "Bucket";
const TABLE_BUCKET_ARN_ATTRIBUTE: &str = "TableBucketARN";

/// The property that type publishes the maintenance settings under, and the three members it
/// publishes inside it.
const UNREFERENCED_FILE_REMOVAL: &str = "UnreferencedFileRemoval";
const STATUS_PROPERTY: &str = "Status";
const UNREFERENCED_DAYS_PROPERTY: &str = "UnreferencedDays";
const NONCURRENT_DAYS_PROPERTY: &str = "NoncurrentDays";

/// The maintenance task those settings configure, as `TableBucketMaintenanceType` spells its
/// one value — the key the read answers the task's configuration under, and the member of the
/// `TableBucketMaintenanceSettings` union its settings travel in.
const UNREFERENCED_FILE_REMOVAL_TASK: &str = "icebergUnreferencedFileRemoval";

/// The settings S3 Tables removes a table bucket's unreferenced files under when nothing
/// configured it, from the S3 Tables maintenance documentation: unreferenced file removal is
/// on, a file is marked noncurrent once it has been unreferenced for 3 days, and a noncurrent
/// file is deleted after 10 days. Written out here rather than read from either crate's
/// constants, so the suite states the published figures independently.
const DEFAULT_STATUS: &str = "enabled";
const DEFAULT_UNREFERENCED_DAYS: i64 = 3;
const DEFAULT_NONCURRENT_DAYS: i64 = 10;

/// The two values `MaintenanceStatus` takes on the wire
/// (`com.amazonaws.s3tables#MaintenanceStatus`: `enabled`, `disabled`), which the resource
/// type publishes with the upper-case initial CloudFormation spells an enum value with.
const DECLARED_ENABLED: &str = "Enabled";
const DECLARED_DISABLED: &str = "Disabled";
const WIRE_ENABLED: &str = "enabled";
const WIRE_DISABLED: &str = "disabled";

/// The bounds of the `PositiveInteger` both day counts target (`@range(min: 1, max:
/// 2147483647)`).
const SMALLEST_DAYS: i64 = 1;
const LARGEST_DAYS: i64 = 2_147_483_647;

/// The emulator with the two services this suite exercises, mounted on ONE engine exactly as
/// `core/router/src/lib.rs` mounts them: CloudFormation makes the calls, S3 Tables serves them
/// and decides the maintenance configuration in force.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_cloudformation_cloudformation::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(
        service_com_amazonaws_s3tables_s3tablebuckets::EmulatedService::new(engine),
    );
    router
}

/// An ARN as a single `@httpLabel` path segment: its `:` and `/` travel percent-encoded, or
/// the request addresses a different route.
fn label(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

/// Call one Amazon S3 Tables operation over its restJson1 wire, on the method and URI its own
/// `@http` binding declares.
async fn s3tables(router: &MultiServiceRouter, method: &str, uri: &str) -> (u16, Value) {
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", format!("s3tables.{REGION}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("s3tables"))
        .body(Bytes::new())
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, payload)
}

/// A table bucket's ARN: the same total function of the Region and the bucket's name both
/// services compute it from (`arn:aws:s3tables:<region>:<account>:bucket/<name>`).
fn table_bucket_arn(name: &str) -> String {
    format!("arn:aws:s3tables:{REGION}:{ACCOUNT}:bucket/{name}")
}

/// One maintenance configuration as the read reports it, reduced to the members the model
/// declares for the task: `status`, and the two day counts of
/// `settings.icebergUnreferencedFileRemoval`.
#[derive(Debug, PartialEq, Eq)]
struct Reported {
    status: Option<String>,
    unreferenced_days: Option<i64>,
    noncurrent_days: Option<i64>,
}

impl Reported {
    /// What the read must report for a bucket running `status` with those day counts.
    fn of(status: &str, unreferenced_days: i64, noncurrent_days: i64) -> Self {
        Self {
            status: Some(status.to_string()),
            unreferenced_days: Some(unreferenced_days),
            noncurrent_days: Some(noncurrent_days),
        }
    }
}

/// What `GetTableBucketMaintenanceConfiguration` reports for the unreferenced-file-removal
/// task of the bucket `arn` names — the read a client holding only the handle the stack
/// published makes.
async fn reported_maintenance(
    router: &MultiServiceRouter,
    case: &str,
    arn: &str,
) -> Reported {
    let (status, body) =
        s3tables(router, "GET", &format!("/buckets/{}/maintenance", label(arn))).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from GetTableBucketMaintenanceConfiguration on the \
         ARN the stack published, got {status} with body {body}"
    );
    assert_eq!(
        body.get("tableBucketARN").and_then(Value::as_str),
        Some(arn),
        "case {case:?}: expected the read to report the bucket {arn:?}, got {body}"
    );
    let task = body
        .get("configuration")
        .and_then(|configuration| configuration.get(UNREFERENCED_FILE_REMOVAL_TASK))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: expected the read to report an \
                 {UNREFERENCED_FILE_REMOVAL_TASK} entry, got {body}"
            )
        });
    let day = |member: &str| {
        task.get("settings")
            .and_then(|settings| settings.get(UNREFERENCED_FILE_REMOVAL_TASK))
            .and_then(|days| days.get(member))
            .and_then(Value::as_i64)
    };
    Reported {
        status: task
            .get("status")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        unreferenced_days: day("unreferencedDays"),
        noncurrent_days: day("nonCurrentDays"),
    }
}

/// The identity S3 Tables minted for the bucket `arn` names: the instant it was created and
/// the id that service keys it by, which an IN-PLACE change leaves alone and a replacement
/// could not keep.
async fn bucket_identity(router: &MultiServiceRouter, case: &str, arn: &str) -> (String, String) {
    let (status, body) = s3tables(router, "GET", &format!("/buckets/{}", label(arn))).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from GetTableBucket on the ARN the stack published, \
         got {status} with body {body}"
    );
    let text = |member: &str| {
        body.get(member)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (text("createdAt"), text("tableBucketId"))
}

/// The physical id the stack publishes for its table bucket — the handle a client calls S3
/// Tables with.
async fn published_arn(router: &MultiServiceRouter, case: &str, stack: &str) -> String {
    let (status, resources) =
        cloudformation(router, "DescribeStackResources", &[("StackName", stack)]).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from DescribeStackResources, got {status} with body \
         {resources}"
    );
    physical_ids_of(&resources)
        .remove(BUCKET_LOGICAL_ID)
        .unwrap_or_else(|| panic!("case {case:?}: no physical id for the bucket in {resources}"))
}

/// The reasons the stack recorded for its resources, read only when an operation did not reach
/// the status the rule says it must, so a failure names what the provider refused.
async fn failure_reasons(router: &MultiServiceRouter, stack: &str) -> Vec<String> {
    let (_, events) =
        cloudformation(router, "DescribeStackEvents", &[("StackName", stack)]).await;
    elements(&events, "ResourceStatusReason")
}

/// A JSON template declaring one table bucket under `bucket`, carrying `removal` as its
/// `UnreferencedFileRemoval` property where the row states one, and publishing the handle the
/// stack hands back twice — once with `Ref` and once with `Fn::GetAtt`.
fn json_template(bucket: &str, removal: Option<Value>) -> String {
    let mut properties = Map::new();
    properties.insert("TableBucketName".to_string(), json!(bucket));
    if let Some(removal) = removal {
        properties.insert(UNREFERENCED_FILE_REMOVAL.to_string(), removal);
    }
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            BUCKET_LOGICAL_ID: {
                "Type": TABLE_BUCKET_TYPE,
                "UpdateReplacePolicy": "Retain",
                "Properties": Value::Object(properties),
            }
        },
        "Outputs": {
            "BucketRef": { "Value": { "Ref": BUCKET_LOGICAL_ID } },
            "BucketArn": {
                "Value": { "Fn::GetAtt": [BUCKET_LOGICAL_ID, TABLE_BUCKET_ARN_ATTRIBUTE] }
            }
        }
    })
    .to_string()
}

/// The `UnreferencedFileRemoval` block a row declares: the members it states and no others, so
/// a row that states one day count really states one.
fn removal(status: Option<&str>, unreferenced: Option<i64>, noncurrent: Option<i64>) -> Value {
    let mut members = Map::new();
    if let Some(status) = status {
        members.insert(STATUS_PROPERTY.to_string(), json!(status));
    }
    if let Some(days) = unreferenced {
        members.insert(UNREFERENCED_DAYS_PROPERTY.to_string(), json!(days));
    }
    if let Some(days) = noncurrent {
        members.insert(NONCURRENT_DAYS_PROPERTY.to_string(), json!(days));
    }
    Value::Object(members)
}

/// A YAML template declaring the same resource, so the rule is asked of both spellings a
/// template may be written in.
fn yaml_template(bucket: &str, status: &str, noncurrent: i64) -> String {
    [
        "Resources:",
        "  Bucket:",
        "    Type: AWS::S3Tables::TableBucket",
        "    UpdateReplacePolicy: Retain",
        "    Properties:",
        "      TableBucketName: BUCKET_NAME",
        "      UnreferencedFileRemoval:",
        "        Status: STATUS",
        "        NoncurrentDays: NONCURRENT",
        "Outputs:",
        "  BucketRef:",
        "    Value: !Ref Bucket",
        "",
    ]
    .join("\n")
    .replace("BUCKET_NAME", bucket)
    .replace("STATUS", status)
    .replace("NONCURRENT", &noncurrent.to_string())
}

/// A template whose day counts come from PARAMETERS, which a template resolves to TEXT: the
/// settings members are integers, so this is the row that asks whether a declared day count
/// reaches that service as the number it states.
fn parameterised_template(bucket: &str) -> String {
    json!({
        "Parameters": {
            "Unreferenced": { "Type": "String" },
            "Noncurrent": { "Type": "String" }
        },
        "Resources": {
            BUCKET_LOGICAL_ID: {
                "Type": TABLE_BUCKET_TYPE,
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "TableBucketName": bucket,
                    UNREFERENCED_FILE_REMOVAL: {
                        STATUS_PROPERTY: DECLARED_ENABLED,
                        UNREFERENCED_DAYS_PROPERTY: { "Ref": "Unreferenced" },
                        NONCURRENT_DAYS_PROPERTY: { "Ref": "Noncurrent" }
                    }
                }
            }
        },
        "Outputs": { "BucketRef": { "Value": { "Ref": BUCKET_LOGICAL_ID } } }
    })
    .to_string()
}

/// The awsQuery members a parameter list travels as.
fn parameter_members(parameters: &[(&str, String)]) -> Vec<(String, String)> {
    parameters
        .iter()
        .enumerate()
        .flat_map(|(position, (key, value))| {
            let entry = position + 1;
            [
                (
                    format!("Parameters.member.{entry}.ParameterKey"),
                    (*key).to_string(),
                ),
                (
                    format!("Parameters.member.{entry}.ParameterValue"),
                    value.clone(),
                ),
            ]
        })
        .collect()
}

/// What one row's update declares, and what the read must report once it has been applied.
struct Update {
    /// The template the update deploys — the same bucket name, so the change is an in-place
    /// one rather than a replacement.
    template: String,
    expected: Reported,
}

/// One row: a template declaring a table bucket, what the read must report for its
/// unreferenced-file-removal task, and the update that then rewrites it.
struct Row {
    case: &'static str,
    /// The bucket's name, which is distinct per row: every row deploys into the one account
    /// and Region this suite's engine holds.
    bucket: &'static str,
    template: String,
    /// The parameters both of this row's deployments carry.
    parameters: Vec<(&'static str, String)>,
    expected: Reported,
    update: Option<Update>,
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            // The reported case: the documented maintenance block, declared in full.
            case: "the declared status and both day counts",
            bucket: "cfn-s3tables-ufr-both",
            template: json_template(
                "cfn-s3tables-ufr-both",
                Some(removal(Some(DECLARED_ENABLED), Some(4), Some(12))),
            ),
            parameters: Vec::new(),
            expected: Reported::of(WIRE_ENABLED, 4, 12),
            update: Some(Update {
                template: json_template(
                    "cfn-s3tables-ufr-both",
                    Some(removal(Some(DECLARED_ENABLED), Some(9), Some(30))),
                ),
                expected: Reported::of(WIRE_ENABLED, 9, 30),
            }),
        },
        Row {
            case: "the task declared off, then switched back on by the update",
            bucket: "cfn-s3tables-ufr-off",
            template: json_template(
                "cfn-s3tables-ufr-off",
                Some(removal(Some(DECLARED_DISABLED), Some(7), Some(21))),
            ),
            parameters: Vec::new(),
            expected: Reported::of(WIRE_DISABLED, 7, 21),
            update: Some(Update {
                template: json_template(
                    "cfn-s3tables-ufr-off",
                    Some(removal(Some(DECLARED_ENABLED), Some(7), Some(21))),
                ),
                expected: Reported::of(WIRE_ENABLED, 7, 21),
            }),
        },
        Row {
            case: "both day counts at the smallest published value, raised to the largest",
            bucket: "cfn-s3tables-ufr-bounds",
            template: json_template(
                "cfn-s3tables-ufr-bounds",
                Some(removal(
                    Some(DECLARED_ENABLED),
                    Some(SMALLEST_DAYS),
                    Some(SMALLEST_DAYS),
                )),
            ),
            parameters: Vec::new(),
            expected: Reported::of(WIRE_ENABLED, SMALLEST_DAYS, SMALLEST_DAYS),
            update: Some(Update {
                template: json_template(
                    "cfn-s3tables-ufr-bounds",
                    Some(removal(
                        Some(DECLARED_ENABLED),
                        Some(LARGEST_DAYS),
                        Some(LARGEST_DAYS),
                    )),
                ),
                expected: Reported::of(WIRE_ENABLED, LARGEST_DAYS, LARGEST_DAYS),
            }),
        },
        Row {
            // No status and one day count: what the declaration states is applied, and what it
            // leaves out is the setting that service itself decides.
            case: "one day count only, with no status at all",
            bucket: "cfn-s3tables-ufr-one-day",
            template: json_template(
                "cfn-s3tables-ufr-one-day",
                Some(removal(None, Some(30), None)),
            ),
            parameters: Vec::new(),
            expected: Reported::of(DEFAULT_STATUS, 30, DEFAULT_NONCURRENT_DAYS),
            update: Some(Update {
                template: json_template(
                    "cfn-s3tables-ufr-one-day",
                    Some(removal(None, Some(31), None)),
                ),
                expected: Reported::of(DEFAULT_STATUS, 31, DEFAULT_NONCURRENT_DAYS),
            }),
        },
        Row {
            case: "the other day count only, declared in YAML",
            bucket: "cfn-s3tables-ufr-yaml",
            template: yaml_template("cfn-s3tables-ufr-yaml", DECLARED_ENABLED, 45),
            parameters: Vec::new(),
            expected: Reported::of(WIRE_ENABLED, DEFAULT_UNREFERENCED_DAYS, 45),
            update: Some(Update {
                template: yaml_template("cfn-s3tables-ufr-yaml", DECLARED_DISABLED, 46),
                expected: Reported::of(WIRE_DISABLED, DEFAULT_UNREFERENCED_DAYS, 46),
            }),
        },
        Row {
            case: "day counts a template parameter supplies as text",
            bucket: "cfn-s3tables-ufr-parameters",
            template: parameterised_template("cfn-s3tables-ufr-parameters"),
            parameters: vec![("Unreferenced", "6".to_string()), ("Noncurrent", "13".to_string())],
            expected: Reported::of(WIRE_ENABLED, 6, 13),
            update: None,
        },
        Row {
            // Nothing is declared, so nothing is configured: the bucket runs the maintenance
            // that service runs every table bucket under, which is what the read reports.
            case: "no maintenance block declared at all",
            bucket: "cfn-s3tables-ufr-absent",
            template: json_template("cfn-s3tables-ufr-absent", None),
            parameters: Vec::new(),
            expected: Reported::of(
                DEFAULT_STATUS,
                DEFAULT_UNREFERENCED_DAYS,
                DEFAULT_NONCURRENT_DAYS,
            ),
            update: None,
        },
    ]
}

/// Every row: the stack deploys, the handle it publishes is the bucket's own ARN, and S3 Tables
/// reports the unreferenced-file-removal configuration the declaration asked for — then the
/// update rewrites it on the very same bucket.
#[tokio::test]
async fn a_stack_applies_the_declared_unreferenced_file_removal_settings() {
    let router = build_router();

    for (index, row) in rows().into_iter().enumerate() {
        let case = row.case;
        let stack_name = format!("s3tables-maintenance-{index}");
        let arn = table_bucket_arn(row.bucket);

        // ---- The create. ----
        let mut members = vec![
            ("StackName".to_string(), stack_name.clone()),
            ("TemplateBody".to_string(), row.template.clone()),
        ];
        members.extend(parameter_members(&row.parameters));
        let borrowed: Vec<(&str, &str)> = members
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let (status, body) = cloudformation(&router, "CreateStack", &borrowed).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from CreateStack, got {status} with body {body}"
        );
        let (stack_status, described) =
            wait_for_stack_status(&router, &stack_name, CREATE_COMPLETE).await;
        assert_eq!(
            stack_status,
            CREATE_COMPLETE,
            "case {case:?}: expected the stack to reach {CREATE_COMPLETE}, got {described} with \
             resource failures {:?}",
            failure_reasons(&router, &stack_name).await
        );

        let published = published_arn(&router, case, &stack_name).await;
        assert_eq!(
            published, arn,
            "case {case:?}: expected the stack to publish the table bucket ARN {arn:?}, got \
             {published:?}"
        );
        let outputs = outputs_of(&described);
        assert_eq!(
            outputs.get("BucketRef"),
            Some(&arn),
            "case {case:?}: expected the BucketRef output to be {arn:?}, got {:?}",
            outputs.get("BucketRef")
        );

        let reported = reported_maintenance(&router, case, &arn).await;
        assert_eq!(
            reported, row.expected,
            "case {case:?}: expected the declared maintenance configuration {:?}, got \
             {reported:?}",
            row.expected
        );
        let identity = bucket_identity(&router, case, &arn).await;

        // ---- The in-place update, for the rows that make one. ----
        let Some(update) = row.update else {
            continue;
        };
        let mut members = vec![
            ("StackName".to_string(), stack_name.clone()),
            ("TemplateBody".to_string(), update.template.clone()),
        ];
        members.extend(parameter_members(&row.parameters));
        let borrowed: Vec<(&str, &str)> = members
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let (status, body) = cloudformation(&router, "UpdateStack", &borrowed).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from UpdateStack, got {status} with body {body}"
        );
        let (stack_status, described) =
            wait_for_stack_status(&router, &stack_name, UPDATE_COMPLETE).await;
        assert_eq!(
            stack_status,
            UPDATE_COMPLETE,
            "case {case:?}: expected the stack to reach {UPDATE_COMPLETE}, got {described} with \
             resource failures {:?}",
            failure_reasons(&router, &stack_name).await
        );

        // The resource is the SAME one: the handle the stack publishes has not moved, and
        // neither has the identity S3 Tables minted for the bucket behind it.
        let after = published_arn(&router, case, &stack_name).await;
        assert_eq!(
            after, arn,
            "case {case:?}: an in-place update keeps the bucket's handle, expected {arn:?}, got \
             {after:?}"
        );
        let identity_after = bucket_identity(&router, case, &arn).await;
        assert_eq!(
            identity_after, identity,
            "case {case:?}: an in-place update keeps the bucket S3 Tables created, expected \
             {identity:?}, got {identity_after:?}"
        );
        let reported = reported_maintenance(&router, case, &arn).await;
        assert_eq!(
            reported, update.expected,
            "case {case:?}: expected the updated maintenance configuration {:?}, got \
             {reported:?}",
            update.expected
        );
    }
}
