// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP tests for `UpdateWorker`.
//!
//! The rules under test:
//!
//! * `UpdateWorker` is a PATCH of one worker: every member the request carries is applied
//!   to the worker its path names and every member it leaves out keeps the value the
//!   worker already holds, which `GetWorker` then reports;
//! * the status a worker carries is the last one reported for it, for each value of
//!   `UpdatedWorkerStatus` and in any order the agent reports them in, and one worker's
//!   report moves no other worker;
//! * an update records that it happened (`updatedAt`/`updatedBy`) and leaves the
//!   registration's own `createdAt`/`createdBy` alone;
//! * the `hostConfiguration` the response hands back is the FLEET's startup script as the
//!   fleet currently holds it, so it follows `UpdateFleet` and is absent for a fleet with
//!   no script;
//! * a worker hangs off its fleet and a fleet off its farm, so a call naming a level this
//!   emulator does not hold is a 404 naming that level and writes nothing.
//!
//! The harness (`Emulator`) and the fleet and worker helpers are the ones the `fleet` and
//! `worker` suites drive the service with, so these tests go through routing,
//! deserialization, constraint validation, the handler and serialization, exactly as the
//! router does in production.

use serde_json::{json, Value};

use crate::farm_queue_job::{absent_id, error_code, string_at, Emulator};
use crate::fleet::{create_fleet, create_fleet_path, customer_managed, get_fleet_path, ROLE_ARN};
use crate::worker::{create_fleet_with_max, create_worker, get_worker_path};

/// `UpdateWorker` is a `PATCH` on the worker's own path
/// (`smithy_query(query="operation", operation="UpdateWorker")`).
async fn update_worker(
    emulator: &Emulator,
    farm_id: &str,
    fleet_id: &str,
    worker_id: &str,
    body: Value,
) -> (u16, Value) {
    emulator
        .call(
            "PATCH",
            &get_worker_path(farm_id, fleet_id, worker_id),
            Some(body),
            None,
        )
        .await
}

/// Read a worker back, failing the test if the read did not succeed.
async fn get_worker(emulator: &Emulator, farm_id: &str, fleet_id: &str, worker_id: &str) -> Value {
    let (status, worker) = emulator
        .get(&get_worker_path(farm_id, fleet_id, worker_id))
        .await;
    assert_eq!(
        status, 200,
        "GetWorker {worker_id}: expected 200, got {status} with {worker}"
    );
    worker
}

/// Register one worker under a fresh fleet of a fresh farm, and return
/// `(farm_id, fleet_id, worker_id)`.
async fn one_registered_worker(emulator: &Emulator, name: &str, body: Value) -> (String, String, String) {
    let farm_id = emulator.farm(name).await;
    let fleet_id = create_fleet_with_max(emulator, &farm_id, name, 8).await;
    let (status, created) = create_worker(emulator, &farm_id, &fleet_id, body, None).await;
    assert_eq!(
        status, 200,
        "CreateWorker {name}: expected 200, got {status} with {created}"
    );
    let worker_id = string_at(&created, "workerId");
    (farm_id, fleet_id, worker_id)
}

/// A capabilities report satisfying the modeled shape
/// (`smithy_query(query="shape", shape="WorkerCapabilities")`: `amounts` and `attributes`
/// are both required, each `len 2..17`, and their names satisfy
/// `^([a-zA-Z][a-zA-Z0-9]{0,63}:)?amount(\.[a-zA-Z][a-zA-Z0-9]{0,63})+$` and the same with
/// `attr`).
fn capabilities(v_cpu: f64) -> Value {
    json!({
        "amounts": [
            {"name": "amount.worker.vcpu", "value": v_cpu},
            {"name": "amount.worker.memory", "value": 16384.0},
        ],
        "attributes": [
            {"name": "attr.worker.os.family", "values": ["linux"]},
            {"name": "attr.worker.cpu.arch", "values": ["x86_64", "arm64"]},
        ],
    })
}

#[tokio::test]
async fn update_worker_applies_what_it_carries_and_keeps_the_rest() {
    let emulator = Emulator::new();
    let (farm_id, fleet_id, worker_id) = one_registered_worker(
        &emulator,
        "patching",
        json!({"hostProperties": {"hostName": "render-07", "ipAddresses": {"ipV4Addresses": ["10.0.0.7"]}}}),
    )
    .await;

    let registered = get_worker(&emulator, &farm_id, &fleet_id, &worker_id).await;
    let created_at = registered.get("createdAt").cloned();
    let created_by = registered.get("createdBy").cloned();

    // The rule: each member the request carries replaces the worker's value for it and each
    // member it omits leaves that value alone. The rows differ along WHICH members the
    // request carries — none, each one on its own, pairs, all three — and the expectations
    // are carried forward from row to row, so a row that omits a member asserts the value
    // an earlier row left behind.
    //
    // `capabilities` is accepted and persisted the same way, but no implemented read of
    // this service reports it (`GetWorker`'s output models no such member), so the rows
    // that carry it assert only that it is accepted and disturbs nothing else.
    let long_host_name = "w".repeat(255);
    let cases: Vec<(&str, Value, &str, Option<Value>)> = vec![
        ("nothing but the path", json!({}), "CREATED", Some(json!({"hostName": "render-07", "ipAddresses": {"ipV4Addresses": ["10.0.0.7"]}}))),
        (
            "the status only",
            json!({"status": "STARTED"}),
            "STARTED",
            Some(json!({"hostName": "render-07", "ipAddresses": {"ipV4Addresses": ["10.0.0.7"]}})),
        ),
        (
            "the host properties only",
            json!({"hostProperties": {"hostName": "render-08"}}),
            "STARTED",
            Some(json!({"hostName": "render-08"})),
        ),
        (
            "the capabilities only",
            json!({"capabilities": capabilities(8.0)}),
            "STARTED",
            Some(json!({"hostName": "render-08"})),
        ),
        (
            "the status and the host properties together",
            json!({
                "status": "STOPPING",
                "hostProperties": {
                    "hostName": long_host_name.clone(),
                    "ipAddresses": {
                        "ipV4Addresses": ["10.0.0.9", "192.168.1.200"],
                        "ipV6Addresses": ["2001:0DB8:0000:0000:0000:0000:0000:0001"],
                    },
                },
            }),
            "STOPPING",
            Some(json!({
                "hostName": long_host_name.clone(),
                "ipAddresses": {
                    "ipV4Addresses": ["10.0.0.9", "192.168.1.200"],
                    "ipV6Addresses": ["2001:0DB8:0000:0000:0000:0000:0000:0001"],
                },
            })),
        ),
        (
            "every member at once",
            json!({
                "status": "STOPPED",
                "capabilities": capabilities(64.0),
                "hostProperties": {"ipAddresses": {"ipV6Addresses": ["FE80:0000:0000:0000:0202:B3FF:FE1E:8329"]}},
            }),
            "STOPPED",
            Some(json!({"ipAddresses": {"ipV6Addresses": ["FE80:0000:0000:0000:0202:B3FF:FE1E:8329"]}})),
        ),
        (
            "nothing but the path, after every member was set",
            json!({}),
            "STOPPED",
            Some(json!({"ipAddresses": {"ipV6Addresses": ["FE80:0000:0000:0000:0202:B3FF:FE1E:8329"]}})),
        ),
    ];

    for (case, request, expected_status, expected_host_properties) in cases {
        let (status, answer) = update_worker(&emulator, &farm_id, &fleet_id, &worker_id, request).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected UpdateWorker to answer 200, got {status} with {answer}"
        );

        let worker = get_worker(&emulator, &farm_id, &fleet_id, &worker_id).await;
        assert_eq!(
            string_at(&worker, "status"),
            expected_status,
            "case {case:?}: expected the worker to carry the reported status, got {worker}"
        );
        let read = worker.get("hostProperties").cloned();
        let expected_read = expected_host_properties.as_ref().map(|expected| {
            // The response shape adds the host EC2 instance's members, which this emulator
            // launched no instance for, so only the two members a request can carry are
            // compared.
            json!({
                "hostName": expected.get("hostName"),
                "ipAddresses": expected.get("ipAddresses"),
            })
        });
        let read_compared = read.as_ref().map(|read| {
            json!({
                "hostName": read.get("hostName"),
                "ipAddresses": read.get("ipAddresses"),
            })
        });
        assert_eq!(
            read_compared, expected_read,
            "case {case:?}: expected the host properties the updates left behind, got {worker}"
        );
        assert_eq!(
            (worker.get("createdAt").cloned(), worker.get("createdBy").cloned()),
            (created_at.clone(), created_by.clone()),
            "case {case:?}: expected the registration's createdAt/createdBy untouched, got {worker}"
        );
        assert!(
            worker.get("updatedAt").and_then(Value::as_str).is_some()
                && worker
                    .get("updatedBy")
                    .and_then(Value::as_str)
                    .is_some_and(|principal| !principal.is_empty()),
            "case {case:?}: expected the update to be recorded as updatedAt/updatedBy, got {worker}"
        );
        assert!(
            worker.get("log").is_none(),
            "case {case:?}: expected no log configuration for a worker nothing logs for, got {worker}"
        );
    }
}

#[tokio::test]
async fn a_worker_carries_the_last_status_reported_for_it() {
    let emulator = Emulator::new();
    let farm_id = emulator.farm("worker status lifecycle").await;
    let fleet_id = create_fleet_with_max(&emulator, &farm_id, "reporting", 8).await;

    // The rule: the status a worker carries is the last one `UpdateWorker` reported for it.
    // The rows differ along the sequence the agent reports — each value of
    // `UpdatedWorkerStatus` (`smithy_query(query="shape", shape="UpdatedWorkerStatus")`:
    // STARTED | STOPPING | STOPPED) reached on its own, the whole walk down to STOPPED, and
    // sequences that go back up again — and each row runs on its own worker, so no row
    // depends on another.
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("started", vec!["STARTED"]),
        ("stopping without having started", vec!["STOPPING"]),
        ("stopped straight away", vec!["STOPPED"]),
        ("the whole walk down to stopped", vec!["STARTED", "STOPPING", "STOPPED"]),
        ("started again after stopping", vec!["STARTED", "STOPPING", "STARTED"]),
        ("restarted after being stopped", vec!["STARTED", "STOPPED", "STARTED"]),
        (
            "the same status reported twice",
            vec!["STARTED", "STARTED", "STOPPING", "STOPPING"],
        ),
    ];

    let mut walked: Vec<(String, String)> = Vec::new();
    for (case, sequence) in &cases {
        let (status, created) = create_worker(&emulator, &farm_id, &fleet_id, json!({}), None).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected CreateWorker to answer 200, got {status} with {created}"
        );
        let worker_id = string_at(&created, "workerId");

        for reported in sequence {
            let (status, answer) = update_worker(
                &emulator,
                &farm_id,
                &fleet_id,
                &worker_id,
                json!({"status": reported}),
            )
            .await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected the report of {reported} to answer 200, got {status} with {answer}"
            );
            let worker = get_worker(&emulator, &farm_id, &fleet_id, &worker_id).await;
            assert_eq!(
                string_at(&worker, "status"),
                *reported,
                "case {case:?}: expected the worker to carry the status just reported, got {worker}"
            );
        }

        let last = (*sequence.last().expect("a non-empty sequence")).to_string();
        walked.push((worker_id, last));
    }

    // One worker's reports moved no other worker: each is still in the status its own last
    // report left it in.
    for (worker_id, expected) in &walked {
        let worker = get_worker(&emulator, &farm_id, &fleet_id, worker_id).await;
        assert_eq!(
            string_at(&worker, "status"),
            *expected,
            "after every walk: expected {worker_id} to still carry {expected}, got {worker}"
        );
    }
}

#[tokio::test]
async fn update_worker_hands_back_the_fleets_host_configuration() {
    let emulator = Emulator::new();
    let farm_id = emulator.farm("host configuration").await;

    // The rule: the `hostConfiguration` the response carries is the startup script the
    // WORKER'S FLEET holds, so it is whatever `GetFleet` reports for that fleet and is
    // absent for a fleet with no script. The rows differ along the script the fleet was
    // created with: none at all, a body with the timeout left at its modeled default, and a
    // body with the timeout at each published bound of
    // `HostConfigurationScriptTimeoutSeconds` (`range 300..3600`).
    let cases: Vec<(&str, Option<Value>)> = vec![
        ("a fleet with no script", None),
        (
            "a script with the default timeout",
            Some(json!({"scriptBody": "echo configuring"})),
        ),
        (
            "a script with the lowest timeout",
            Some(json!({"scriptBody": "#!/bin/sh\nexit 0\n", "scriptTimeoutSeconds": 300})),
        ),
        (
            "a script with the highest timeout",
            Some(json!({"scriptBody": "s".repeat(1000), "scriptTimeoutSeconds": 3600})),
        ),
    ];

    for (case, host_configuration) in cases {
        let mut request = json!({
            "displayName": "scripted",
            "roleArn": ROLE_ARN,
            "minWorkerCount": 0,
            "maxWorkerCount": 2,
            "configuration": customer_managed("LINUX", "x86_64", json!({})),
        });
        if let Some(configuration) = host_configuration.clone() {
            request["hostConfiguration"] = configuration;
        }
        let (status, created) = emulator.post(&create_fleet_path(&farm_id), request).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected CreateFleet to answer 200, got {status} with {created}"
        );
        let fleet_id = string_at(&created, "fleetId");

        let (status, created) = create_worker(&emulator, &farm_id, &fleet_id, json!({}), None).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected CreateWorker to answer 200, got {status} with {created}"
        );
        let worker_id = string_at(&created, "workerId");

        // What the fleet itself reports is the only thing the worker may be handed.
        let (status, fleet) = emulator.get(&get_fleet_path(&farm_id, &fleet_id)).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected GetFleet to answer 200, got {status} with {fleet}"
        );

        let (status, answer) = update_worker(
            &emulator,
            &farm_id,
            &fleet_id,
            &worker_id,
            json!({"status": "STARTED"}),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected UpdateWorker to answer 200, got {status} with {answer}"
        );
        assert_eq!(
            answer.get("hostConfiguration"),
            fleet.get("hostConfiguration"),
            "case {case:?}: expected the fleet's own host configuration, got {answer} for a \
             fleet reporting {fleet}"
        );
        assert!(
            answer.get("log").is_none(),
            "case {case:?}: expected no log configuration for a worker nothing logs for, got {answer}"
        );

        // The same rule after the fleet's script changes: a script set on the fleet reaches
        // the worker, and the empty body the model documents for removing one leaves the
        // worker with none.
        for (step, patch) in [
            (
                "a script set on the fleet",
                json!({"hostConfiguration": {"scriptBody": "echo replaced", "scriptTimeoutSeconds": 900}}),
            ),
            (
                "the script taken off the fleet",
                json!({"hostConfiguration": {"scriptBody": ""}}),
            ),
        ] {
            let (status, patched) = emulator
                .call("PATCH", &get_fleet_path(&farm_id, &fleet_id), Some(patch), None)
                .await;
            assert_eq!(
                status, 200,
                "case {case:?} / {step}: expected UpdateFleet to answer 200, got {status} with {patched}"
            );
            let (_, fleet) = emulator.get(&get_fleet_path(&farm_id, &fleet_id)).await;
            let (status, answer) = update_worker(
                &emulator,
                &farm_id,
                &fleet_id,
                &worker_id,
                json!({"status": "STARTED"}),
            )
            .await;
            assert_eq!(
                status, 200,
                "case {case:?} / {step}: expected UpdateWorker to answer 200, got {status} with {answer}"
            );
            assert_eq!(
                answer.get("hostConfiguration"),
                fleet.get("hostConfiguration"),
                "case {case:?} / {step}: expected the fleet's own host configuration, got \
                 {answer} for a fleet reporting {fleet}"
            );
        }
    }
}

#[tokio::test]
async fn update_worker_refuses_a_path_it_does_not_hold_and_writes_nothing() {
    let emulator = Emulator::new();
    let farm_id = emulator.farm("owner").await;
    let other_farm_id = emulator.farm("stranger").await;
    let fleet_id = create_fleet_with_max(&emulator, &farm_id, "owned", 8).await;
    let sibling_fleet_id = create_fleet(&emulator, &farm_id, "sibling").await;
    let other_fleet_id = create_fleet(&emulator, &other_farm_id, "elsewhere").await;
    let absent_farm = absent_id("farm", "00000000000000000000000000000041");
    let absent_fleet = absent_id("fleet", "00000000000000000000000000000042");
    let absent_worker = absent_id("worker", "00000000000000000000000000000043");

    let (status, created) = create_worker(
        &emulator,
        &farm_id,
        &fleet_id,
        json!({"hostProperties": {"hostName": "untouched"}}),
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "the registration: expected 200, got {status} with {created}"
    );
    let worker_id = string_at(&created, "workerId");

    // The rule: a worker is reached only through its own fleet and a fleet only through its
    // own farm, so an update naming a level this emulator does not hold at that level
    // answers a 404 naming that level. The rows differ along which level is wrong.
    let cases: Vec<(&str, String, String, String, &str, String)> = vec![
        (
            "an unheld farm",
            absent_farm.clone(),
            fleet_id.clone(),
            worker_id.clone(),
            "farm",
            absent_farm.clone(),
        ),
        (
            "an unheld fleet",
            farm_id.clone(),
            absent_fleet.clone(),
            worker_id.clone(),
            "fleet",
            absent_fleet.clone(),
        ),
        (
            "a fleet of another farm",
            farm_id.clone(),
            other_fleet_id.clone(),
            worker_id.clone(),
            "fleet",
            other_fleet_id.clone(),
        ),
        (
            "another fleet of the same farm",
            farm_id.clone(),
            sibling_fleet_id.clone(),
            worker_id.clone(),
            "worker",
            worker_id.clone(),
        ),
        (
            "an unheld worker",
            farm_id.clone(),
            fleet_id.clone(),
            absent_worker.clone(),
            "worker",
            absent_worker.clone(),
        ),
    ];

    for (case, farm, fleet, worker, resource_type, resource_id) in cases {
        let (status, body) = update_worker(
            &emulator,
            &farm,
            &fleet,
            &worker,
            json!({"status": "STOPPED", "hostProperties": {"hostName": "overwritten"}}),
        )
        .await;
        assert_eq!(
            (
                status,
                error_code(&body),
                string_at(&body, "resourceType"),
                string_at(&body, "resourceId"),
            ),
            (
                404,
                "ResourceNotFoundException".to_string(),
                resource_type.to_string(),
                resource_id.clone(),
            ),
            "case {case:?}: expected a 404 naming what is missing, got {status} with {body}"
        );
    }

    // A request whose body breaks a modeled constraint is refused the same way, and writes
    // nothing either: `WorkerCapabilities` requires at least two amounts and two
    // attributes.
    let (status, body) = update_worker(
        &emulator,
        &farm_id,
        &fleet_id,
        &worker_id,
        json!({
            "status": "STOPPED",
            "capabilities": {
                "amounts": [{"name": "amount.worker.vcpu", "value": 4.0}],
                "attributes": [{"name": "attr.worker.os.family", "values": ["linux"]}],
            },
        }),
    )
    .await;
    assert_eq!(
        (status, error_code(&body)),
        (400, "ValidationException".to_string()),
        "a capabilities report below its modeled length: expected a 400 ValidationException, \
         got {status} with {body}"
    );

    // None of those refusals wrote anything: the worker still carries what its registration
    // left it with, and nothing recorded an update against it.
    let worker = get_worker(&emulator, &farm_id, &fleet_id, &worker_id).await;
    assert_eq!(
        (
            string_at(&worker, "status"),
            worker
                .get("hostProperties")
                .and_then(|properties| properties.get("hostName"))
                .cloned(),
        ),
        ("CREATED".to_string(), Some(json!("untouched"))),
        "after the refusals: expected the worker exactly as registered, got {worker}"
    );
    assert!(
        worker.get("updatedAt").is_none() && worker.get("updatedBy").is_none(),
        "after the refusals: expected no updatedAt/updatedBy on a worker nothing updated, got {worker}"
    );
}
