// SPDX-License-Identifier: CC0-1.0

//! `DeleteNetworkMigrationDefinition`, end to end over HTTP.
//!
//! The rule these tests pin: a delete removes the named definition of the caller's
//! account together with the metadata recorded under it (its executions and the jobs
//! those executions ran) and concludes with the modelled no-content answer, so every
//! later read of that id — the get, the listing, and the execution listing that is only
//! addressable within it — is the modelled 404 `ResourceNotFoundException`, while every
//! other definition of the account is untouched; an id the account holds no record of
//! (never created, already deleted, or a definition of another account) removes nothing
//! and is refused with that same 404; and work still in flight under the definition makes
//! the removal a 409 `ConflictException` that removes nothing, until the clock has
//! finished that work.
//!
//! Every assertion goes through the router's `dispatch`, so it exercises the same
//! restJson1 deserialize → handle → serialize path a client drives, and what the delete
//! left is read back through the service's own implemented readers. The store is reached
//! directly only to seed a precondition no sequence of calls can reach (another account's
//! definition, a job whose work the clock has already finished) and to check the cascade,
//! the way the other network-migration suites do.
//!
//! The harness (`Mgn`, `error_code`, the region and account constants) is the one
//! `application_lifecycle.rs` defines; `call` takes the operation's modelled URI path, so
//! these operations are reached under `/network-migration/<Operation>`.

use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use service_com_amazonaws_mgn_applicationmigrationservice::ops::types::{
    TargetNetwork, TargetS3Configuration,
};
use service_com_amazonaws_mgn_applicationmigrationservice::state::{
    NetworkMigrationDefinition, NetworkMigrationDefinitionConfiguration,
};

use crate::application_lifecycle::{error_code, Mgn, EMULATOR_ACCOUNT, OTHER_ACCOUNT, REGION};

/// The modelled `http.uri` of `CreateNetworkMigrationDefinition`
/// (`smithy_query(query="operation",operation="CreateNetworkMigrationDefinition")`),
/// without the leading slash the harness adds.
const CREATE: &str = "network-migration/CreateNetworkMigrationDefinition";

/// The modelled `http.uri` of `GetNetworkMigrationDefinition`, likewise.
const GET: &str = "network-migration/GetNetworkMigrationDefinition";

/// The modelled `http.uri` of `ListNetworkMigrationDefinitions`, likewise.
const LIST: &str = "network-migration/ListNetworkMigrationDefinitions";

/// The modelled `http.uri` of `ListNetworkMigrationExecutions`, likewise.
const LIST_EXECUTIONS: &str = "network-migration/ListNetworkMigrationExecutions";

/// The modelled `http.uri` of `StartNetworkMigrationMapping`, likewise.
const START_MAPPING: &str = "network-migration/StartNetworkMigrationMapping";

/// The modelled `http.uri` of `DeleteNetworkMigrationDefinition`, likewise.
const DELETE: &str = "network-migration/DeleteNetworkMigrationDefinition";

/// The status and stated length the delete's modelled `@http(code: 204)` answer carries.
const NO_CONTENT: u16 = 204;

/// The `resourceType` a network-migration-definition refusal names: the modelled resource
/// shape `com.amazonaws.mgn#NetworkMigrationDefinitionResource` without its suffix.
const DEFINITION_RESOURCE_TYPE: &str = "NetworkMigrationDefinition";

/// A `sourceConfigurations` element as the model requires it (every member of
/// `SourceConfiguration` and of its `sourceS3Configuration` is `@required`).
fn source(environment: &str, bucket: &str, key: &str) -> Value {
    json!({
        "sourceEnvironment": environment,
        "sourceS3Configuration": {
            "s3Bucket": bucket,
            "s3BucketOwner": EMULATOR_ACCOUNT,
            "s3Key": key,
        },
    })
}

/// A `CreateNetworkMigrationDefinition` body carrying only the members the model marks
/// `@required` (`smithy_query(query="closure",operation="CreateNetworkMigrationDefinition")`).
fn minimal_request(name: &str) -> Value {
    json!({
        "name": name,
        "targetS3Configuration": {
            "s3Bucket": "migration-artifacts",
            "s3BucketOwner": EMULATOR_ACCOUNT,
        },
        "targetNetwork": {"topology": "ISOLATED_VPC"},
    })
}

/// The class a deletable definition spans, one row per axis the rule generalises over:
/// how many members the record carries, how many source configurations and CIDR mappings
/// it holds, which provisioning strategy it was created under, and whether it carries
/// tags or scope tags. A delete must remove each one the same way — the recorded
/// create-update-delete round trip is ONE row.
fn definition_cases() -> Vec<(&'static str, Value)> {
    vec![
        (
            "the required members only",
            minimal_request("delete-minimal"),
        ),
        (
            "one source configuration and a description",
            json!({
                "name": "delete-one-source",
                "description": "one source environment",
                "sourceConfigurations": [source("NSX", "nsx-exports", "exports/nsx.json")],
                "targetS3Configuration": {
                    "s3Bucket": "migration-artifacts",
                    "s3BucketOwner": EMULATOR_ACCOUNT,
                },
                "targetNetwork": {"topology": "ISOLATED_VPC", "inboundCidr": "10.0.0.0/16"},
            }),
        ),
        (
            "every member, two source configurations, CIDR mappings under USE_EXISTING",
            json!({
                "name": "delete-everything",
                "description": "two regions, one inspection VPC",
                "sourceConfigurations": [
                    source("NSX", "nsx-exports", "exports/nsx.json"),
                    source("VSPHERE", "vsphere-exports", "exports/vsphere.zip"),
                ],
                "targetS3Configuration": {
                    "s3Bucket": "migration-artifacts",
                    "s3BucketOwner": EMULATOR_ACCOUNT,
                },
                "targetNetwork": {
                    "topology": "HUB_AND_SPOKE",
                    "inboundCidr": "10.0.0.0/16",
                    "outboundCidr": "10.1.0.0/24",
                    "inspectionCidr": "192.168.1.0/28",
                },
                "targetDeployment": "MULTI_ACCOUNT",
                "vpcProvisioningStrategy": "USE_EXISTING",
                "cidrMappings": [
                    {"originalCidr": "10.0.0.0/16", "updatedCidr": "10.8.0.0/16"},
                    {"originalCidr": "10.1.0.0/24", "updatedCidr": "10.9.0.0/24"},
                ],
                "tags": {"env": "prod", "team": "migration"},
                "scopeTags": {"BusinessUnit": "retail"},
            }),
        ),
        (
            "tags only, under the default provisioning strategy",
            json!({
                "name": "delete-tagged",
                "targetS3Configuration": {
                    "s3Bucket": "migration-artifacts",
                    "s3BucketOwner": EMULATOR_ACCOUNT,
                },
                "targetNetwork": {"topology": "ISOLATED_VPC"},
                "tags": {"env": "dev"},
            }),
        ),
        (
            "a 256-character name — the modelled maximum",
            json!({
                "name": "n".repeat(256),
                "description": "d".repeat(600),
                "targetS3Configuration": {
                    "s3Bucket": "migration-artifacts",
                    "s3BucketOwner": EMULATOR_ACCOUNT,
                },
                "targetNetwork": {"topology": "ISOLATED_VPC"},
            }),
        ),
    ]
}

/// `CreateNetworkMigrationDefinition`, asserting the modelled 201 and answering the
/// minted `networkMigrationDefinitionID`.
async fn create(mgn: &Mgn, case: &str, request: &Value) -> String {
    let (status, created) = mgn.call(CREATE, request).await;
    assert_eq!(
        status, 201,
        "case {case:?}: CreateNetworkMigrationDefinition expected 201, got {status} with \
         {created:?}"
    );
    created["networkMigrationDefinitionID"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: no networkMigrationDefinitionID in {created:?}"))
        .to_string()
}

/// `DeleteNetworkMigrationDefinition` for `definition_id`, answering the status, the
/// `x-amzn-errortype` header and the parsed body.
async fn delete(mgn: &Mgn, definition_id: &str) -> (u16, Option<String>, Value) {
    mgn.call_reporting_error_type(DELETE, &json!({"networkMigrationDefinitionID": definition_id}))
        .await
}

/// The ids `ListNetworkMigrationDefinitions` reports for the caller's account.
async fn listed_ids(mgn: &Mgn, case: &str) -> Vec<String> {
    let (status, listed) = mgn.call(LIST, &json!({})).await;
    assert_eq!(
        status, 200,
        "case {case:?}: ListNetworkMigrationDefinitions expected 200, got {status} with \
         {listed:?}"
    );
    listed["items"]
        .as_array()
        .unwrap_or_else(|| panic!("case {case:?}: no items array in {listed:?}"))
        .iter()
        .map(|item| {
            item["networkMigrationDefinitionID"]
                .as_str()
                .unwrap_or_else(|| panic!("case {case:?}: no id in {item:?}"))
                .to_string()
        })
        .collect()
}

/// Assert `body` is this service's not-found refusal naming `definition_id`.
fn assert_definition_not_found(case: &str, operation: &str, status: u16, body: &Value) {
    assert_eq!(
        status, 404,
        "case {case:?}: {operation} on a removed definition expected 404, got {status} with \
         {body:?}"
    );
    assert_eq!(
        error_code(body),
        "ResourceNotFoundException",
        "case {case:?}: {operation} must refuse with ResourceNotFoundException, got {body:?}"
    );
}

/// A delete removes the definition, its executions and its jobs, concludes with the
/// modelled no-content answer, and leaves every later read of that id a 404 — for every
/// shape of definition the create admits.
#[tokio::test]
async fn a_delete_removes_the_definition_and_everything_recorded_under_it() {
    // Neither operation models an `accountID` member or an `UninitializedAccountException`,
    // so no `InitializeService` runs here.
    for (case, request) in definition_cases() {
        let mgn = Mgn::new();
        let definition_id = create(&mgn, case, &request).await;

        // A second definition of the same account, so the removal is shown to take only
        // the record it named.
        let survivor = create(&mgn, case, &minimal_request("delete-survivor")).await;

        // The definition is staged one execution by its create, and a mapping run records
        // a job under it: both are metadata recorded UNDER the definition, so both must go
        // with it.
        let (status, executions) = mgn
            .call(
                LIST_EXECUTIONS,
                &json!({"networkMigrationDefinitionID": definition_id}),
            )
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: ListNetworkMigrationExecutions expected 200, got {status} with \
             {executions:?}"
        );
        let execution_id = executions["items"][0]["networkMigrationExecutionID"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: no staged execution in {executions:?}"))
            .to_string();
        let (status, started) = mgn
            .call(
                START_MAPPING,
                &json!({
                    "networkMigrationDefinitionID": definition_id,
                    "networkMigrationExecutionID": execution_id,
                    "securityGroupMappingStrategy": "MAP",
                }),
            )
            .await;
        assert_eq!(
            status, 202,
            "case {case:?}: StartNetworkMigrationMapping expected 202, got {status} with \
             {started:?}"
        );
        let job_id = started["jobID"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: no jobID in {started:?}"))
            .to_string();
        // The clock finishes that job's work, so nothing is in flight when the delete
        // runs: rewinding the instant its completion is owed at is what no call can reach
        // without waiting for it.
        {
            let store = mgn.store();
            let mut guard = store.lock();
            let job = guard
                .network_migration_mapping_jobs
                .get_mut(&job_id)
                .unwrap_or_else(|| panic!("case {case:?}: the started job is in the store"));
            job.completes_at = SystemTime::now() - Duration::from_secs(1);
        }

        // The delete itself: the modelled 204, with no entity at all.
        let (status, _, raw) = mgn
            .call_http_raw(
                "POST",
                &format!("/{DELETE}"),
                Some(&json!({"networkMigrationDefinitionID": definition_id})),
            )
            .await;
        assert_eq!(
            status,
            NO_CONTENT,
            "case {case:?}: DeleteNetworkMigrationDefinition expected {NO_CONTENT}, got \
             {status} with {:?}",
            String::from_utf8_lossy(&raw)
        );
        assert!(
            raw.is_empty(),
            "case {case:?}: a {NO_CONTENT} answer carries no body, got {:?}",
            String::from_utf8_lossy(&raw)
        );

        // Every read of the removed id is the not-found refusal, through each implemented
        // reader that addresses it.
        let (status, body) = mgn
            .call(GET, &json!({"networkMigrationDefinitionID": definition_id}))
            .await;
        assert_definition_not_found(case, "GetNetworkMigrationDefinition", status, &body);
        assert_eq!(
            body["resourceId"].as_str(),
            Some(definition_id.as_str()),
            "case {case:?}: the refusal must name the id asked for, got {body:?}"
        );
        assert_eq!(
            body["resourceType"].as_str(),
            Some(DEFINITION_RESOURCE_TYPE),
            "case {case:?}: the refusal must name the resource kind, got {body:?}"
        );

        let (status, body) = mgn
            .call(
                LIST_EXECUTIONS,
                &json!({"networkMigrationDefinitionID": definition_id}),
            )
            .await;
        assert_definition_not_found(case, "ListNetworkMigrationExecutions", status, &body);

        // A repeat of the delete removes nothing and is refused the same way: the record
        // is gone, so the id names nothing.
        let (status, error_type, body) = delete(&mgn, &definition_id).await;
        assert_definition_not_found(case, "the repeated delete", status, &body);
        assert_eq!(
            error_type.as_deref(),
            Some("ResourceNotFoundException"),
            "case {case:?}: the refusal's x-amzn-errortype must state the shape, got \
             {error_type:?}"
        );

        // The listing reports the other definition of the account and only it.
        let ids = listed_ids(&mgn, case).await;
        assert_eq!(
            ids,
            vec![survivor.clone()],
            "case {case:?}: only the definition the delete did not name may remain, got {ids:?}"
        );
        let (status, kept) = mgn
            .call(GET, &json!({"networkMigrationDefinitionID": survivor}))
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the other definition must still be readable, got {status} with \
             {kept:?}"
        );

        // The cascade, in the store: no execution and no job of the removed definition is
        // left addressable, while the survivor keeps its own staged execution.
        {
            let store = mgn.store();
            let guard = store.lock();
            let left_executions = guard.network_migration_executions.len();
            assert!(
                guard
                    .network_migration_executions
                    .values()
                    .all(|execution| execution.network_migration_definition_id != definition_id),
                "case {case:?}: no execution of the removed definition may remain, got \
                 {left_executions} executions"
            );
            assert!(
                guard
                    .network_migration_mapping_jobs
                    .values()
                    .all(|job| job.network_migration_definition_id != definition_id),
                "case {case:?}: no job of the removed definition may remain"
            );
            assert!(
                !guard.network_migration_execution_order.contains(&execution_id),
                "case {case:?}: the removed execution must leave the creation order too, got \
                 {:?}",
                guard.network_migration_execution_order
            );
            assert!(
                !guard.network_migration_mapping_job_order.contains(&job_id),
                "case {case:?}: the removed job must leave the creation order too, got {:?}",
                guard.network_migration_mapping_job_order
            );
            assert_eq!(
                guard
                    .network_migration_executions_of(EMULATOR_ACCOUNT, &survivor)
                    .len(),
                1,
                "case {case:?}: the other definition keeps its own staged execution"
            );
        }
    }
}

/// An id the account holds no record of removes nothing and is refused with the modelled
/// 404 — for each way an id can name nothing: never created, well-formed but unknown, and
/// a definition another account holds.
#[tokio::test]
async fn a_definition_the_account_holds_no_record_of_is_refused_and_removes_nothing() {
    let mgn = Mgn::new();
    let own = create(&mgn, "the account's own definition", &minimal_request("delete-own")).await;

    // Another account's definition: nothing a call of this account can create, so it is
    // seeded.
    let foreign = "nmd-aaaaaaaaaaaaaaaaa";
    {
        let store = mgn.store();
        let mut guard = store.lock();
        let stored = guard.insert_network_migration_definition(NetworkMigrationDefinition {
            network_migration_definition_id: foreign.to_string(),
            arn: format!(
                "arn:aws:mgn:{REGION}:{OTHER_ACCOUNT}:network-migration-definition/{foreign}"
            ),
            account_id: OTHER_ACCOUNT.to_string(),
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            configuration: NetworkMigrationDefinitionConfiguration {
                name: "other-account-plan".to_string(),
                target_s3_configuration: TargetS3Configuration {
                    s3_bucket: "migration-artifacts".to_string(),
                    s3_bucket_owner: OTHER_ACCOUNT.to_string(),
                },
                target_network: TargetNetwork {
                    topology: "ISOLATED_VPC".to_string(),
                    ..TargetNetwork::default()
                },
                ..NetworkMigrationDefinitionConfiguration::default()
            },
        });
        assert!(stored, "seeding another account's definition must store it");
    }

    let cases = [
        ("a well-formed id no account holds", "nmd-zzzzzzzzzzzzzzzzz"),
        ("an id of all zeroes", "nmd-00000000000000000"),
        ("a definition of another account", foreign),
    ];
    for (case, definition_id) in cases {
        let (status, _, body) = delete(&mgn, definition_id).await;
        assert_definition_not_found(case, "DeleteNetworkMigrationDefinition", status, &body);
        assert_eq!(
            body["resourceId"].as_str(),
            Some(definition_id),
            "case {case:?}: the refusal must name the id asked for, got {body:?}"
        );
    }

    // Nothing was removed: the other account still holds its record, and this account
    // still holds its own.
    {
        let store = mgn.store();
        let guard = store.lock();
        assert!(
            guard
                .network_migration_definition_of(OTHER_ACCOUNT, foreign)
                .is_some(),
            "a refused delete must leave the other account's definition in place"
        );
    }
    let (status, kept) = mgn
        .call(GET, &json!({"networkMigrationDefinitionID": own}))
        .await;
    assert_eq!(
        status, 200,
        "the account's own definition must be untouched by the refusals, got {status} with \
         {kept:?}"
    );
}

/// Work in flight under a definition makes its removal a conflict: while a mapping job of
/// one of its executions is still running the delete is refused with 409 and removes
/// nothing, and once the clock has finished that work the same delete succeeds.
#[tokio::test]
async fn a_delete_conflicts_with_a_mapping_job_still_running_under_the_definition() {
    let mgn = Mgn::new();
    let case = "a mapping job still running";
    let definition_id = create(&mgn, case, &minimal_request("delete-while-running")).await;
    let (status, executions) = mgn
        .call(
            LIST_EXECUTIONS,
            &json!({"networkMigrationDefinitionID": definition_id}),
        )
        .await;
    assert_eq!(
        status, 200,
        "ListNetworkMigrationExecutions expected 200, got {status} with {executions:?}"
    );
    let execution_id = executions["items"][0]["networkMigrationExecutionID"]
        .as_str()
        .unwrap_or_else(|| panic!("no staged execution in {executions:?}"))
        .to_string();

    let (status, started) = mgn
        .call(
            START_MAPPING,
            &json!({
                "networkMigrationDefinitionID": definition_id,
                "networkMigrationExecutionID": execution_id,
            }),
        )
        .await;
    assert_eq!(
        status, 202,
        "StartNetworkMigrationMapping expected 202, got {status} with {started:?}"
    );
    let job_id = started["jobID"]
        .as_str()
        .unwrap_or_else(|| panic!("no jobID in {started:?}"))
        .to_string();

    let (status, error_type, body) = delete(&mgn, &definition_id).await;
    assert_eq!(
        status, 409,
        "case {case:?}: the delete expected 409, got {status} with {body:?}"
    );
    assert_eq!(
        error_code(&body),
        "ConflictException",
        "case {case:?}: the delete must refuse with ConflictException, got {body:?}"
    );
    assert_eq!(
        error_type.as_deref(),
        Some("ConflictException"),
        "case {case:?}: the refusal's x-amzn-errortype must state the shape, got {error_type:?}"
    );
    assert_eq!(
        body["resourceId"].as_str(),
        Some(definition_id.as_str()),
        "case {case:?}: the conflict must name the definition it is about, got {body:?}"
    );
    assert_eq!(
        body["resourceType"].as_str(),
        Some(DEFINITION_RESOURCE_TYPE),
        "case {case:?}: the conflict must name the resource kind, got {body:?}"
    );
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&definition_id) && message.contains(&job_id),
        "case {case:?}: the conflict must say which definition and which job, got {message:?}"
    );

    // The refusal removed nothing: the definition and its execution still read back.
    let (status, kept) = mgn
        .call(GET, &json!({"networkMigrationDefinitionID": definition_id}))
        .await;
    assert_eq!(
        status, 200,
        "case {case:?}: a refused delete must leave the definition readable, got {status} with \
         {kept:?}"
    );
    let (status, listed) = mgn
        .call(
            LIST_EXECUTIONS,
            &json!({"networkMigrationDefinitionID": definition_id}),
        )
        .await;
    assert_eq!(
        status, 200,
        "case {case:?}: a refused delete must leave the execution listable, got {status} with \
         {listed:?}"
    );

    // The clock finishes the job's work, which no call can reach without waiting for it.
    {
        let store = mgn.store();
        let mut guard = store.lock();
        let job = guard
            .network_migration_mapping_jobs
            .get_mut(&job_id)
            .expect("the started job is in the store");
        job.completes_at = SystemTime::now() - Duration::from_secs(1);
    }

    let (status, _, body) = delete(&mgn, &definition_id).await;
    assert_eq!(
        status, NO_CONTENT,
        "case {case:?}: once nothing is in flight the delete expected {NO_CONTENT}, got \
         {status} with {body:?}"
    );
    let (status, body) = mgn
        .call(GET, &json!({"networkMigrationDefinitionID": definition_id}))
        .await;
    assert_definition_not_found(case, "GetNetworkMigrationDefinition", status, &body);
}
