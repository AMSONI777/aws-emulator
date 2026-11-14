// SPDX-License-Identifier: CC0-1.0

//! The connection test a data source's create and update settle on, and what a data
//! set may be built on.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` with a signed
//! request, QuickSight over restJson1 and Athena over awsJson1_1 on the same emulator —
//! so what is asserted is what an SDK client would see.
//!
//! The rule under test: the TERMINAL `ResourceStatus` of a data source is the outcome
//! of the connection test of the source its `DataSourceParameters` describe. A test
//! that resolves settles the resource successfully with no `ErrorInfo`; one that names
//! a resource the owning service does not hold settles it in the failed status of that
//! write — `CREATION_FAILED` for a create, `UPDATE_FAILED` for an update — carrying
//! `ErrorInfo` of type `GENERIC_SQL_FAILURE` whose message names what was missing. A
//! data source in a failed status cannot back a data set, so a physical table naming
//! one is refused with `InvalidParameterValueException`.
//!
//! The rows therefore vary what the rule generalises over: which parameter set the
//! union carries, whether the named workgroup exists (the account's default, one
//! Athena's own `CreateWorkGroup` registered, and names nothing holds), whether the
//! name is submitted at all, the write that ran the test (create or update), the
//! physical-table kind and the import mode of the data set built on the result, and
//! the account.

use serde_json::{json, Value};

use service_com_amazonaws_quicksight_quicksight_20180401::state as qs_state;

use super::data_source_data_set_lifecycle::Harness;

/// The account every case uses unless it is about account keying.
const ACCOUNT: &str = "000000000000";
/// A second, unrelated 12-digit account id.
const OTHER_ACCOUNT: &str = "210987654321";
/// The region the test client signs for; it is the region in every ARN below.
const REGION: &str = "us-west-2";

/// `ResourceStatus` values (model enum `com.amazonaws.quicksight#ResourceStatus`).
const CREATION_IN_PROGRESS: &str = "CREATION_IN_PROGRESS";
const CREATION_SUCCESSFUL: &str = "CREATION_SUCCESSFUL";
const CREATION_FAILED: &str = "CREATION_FAILED";
const UPDATE_SUCCESSFUL: &str = "UPDATE_SUCCESSFUL";
const UPDATE_FAILED: &str = "UPDATE_FAILED";

/// The `DataSourceErrorInfoType` a refused connection test reports (model enum
/// `com.amazonaws.quicksight#DataSourceErrorInfoType`, whose members are
/// ACCESS_DENIED, COPY_SOURCE_NOT_FOUND, TIMEOUT, ENGINE_VERSION_NOT_SUPPORTED,
/// UNKNOWN_HOST, GENERIC_SQL_FAILURE, CONFLICT and UNKNOWN).
const GENERIC_SQL_FAILURE: &str = "GENERIC_SQL_FAILURE";

/// Athena's own default workgroup: the one every account has without creating it.
const DEFAULT_WORK_GROUP: &str = "primary";

fn data_source_arn(account: &str, id: &str) -> String {
    format!("arn:aws:quicksight:{REGION}:{account}:datasource/{id}")
}

async fn create_data_source(harness: &Harness, account: &str, body: Value) -> (u16, Value) {
    harness
        .call(
            "POST",
            &format!("/accounts/{account}/data-sources"),
            Some(body),
        )
        .await
}

async fn update_data_source(
    harness: &Harness,
    account: &str,
    id: &str,
    body: Value,
) -> (u16, Value) {
    harness
        .call(
            "PUT",
            &format!("/accounts/{account}/data-sources/{id}"),
            Some(body),
        )
        .await
}

async fn describe_data_source(harness: &Harness, account: &str, id: &str) -> (u16, Value) {
    harness
        .call(
            "GET",
            &format!("/accounts/{account}/data-sources/{id}"),
            None,
        )
        .await
}

async fn create_data_set(
    harness: &Harness,
    account: &str,
    id: &str,
    import_mode: &str,
    physical_table_map: Value,
) -> (u16, Value) {
    harness
        .call(
            "POST",
            &format!("/accounts/{account}/data-sets"),
            Some(json!({
                "DataSetId": id,
                "Name": id,
                "ImportMode": import_mode,
                "PhysicalTableMap": physical_table_map,
            })),
        )
        .await
}

/// One row of the connection-test table.
struct Case {
    /// What this row varies, named in every assertion it makes.
    label: &'static str,
    /// The `DataSourceParameters` the create submits, or `None` for a create that
    /// submits none at all.
    parameters: Option<Value>,
    /// The workgroup name the failure message has to name, or `None` when the test is
    /// expected to pass.
    missing_work_group: Option<&'static str>,
}

/// The rows: the union member the parameters carry, and — for the member that names a
/// resource this emulator holds — whether the account holds it.
///
/// `reporting` is registered through Athena's own `CreateWorkGroup` by the test below;
/// `primary` is the default workgroup Athena gives every account.
fn cases() -> Vec<Case> {
    vec![
        Case {
            label: "the account's default Athena workgroup",
            parameters: Some(json!({ "AthenaParameters": { "WorkGroup": DEFAULT_WORK_GROUP } })),
            missing_work_group: None,
        },
        Case {
            label: "an Athena workgroup the account created",
            parameters: Some(json!({ "AthenaParameters": { "WorkGroup": "reporting" } })),
            missing_work_group: None,
        },
        Case {
            label: "no WorkGroup at all, so the default one",
            parameters: Some(json!({
                "AthenaParameters": {
                    "RoleArn": format!("arn:aws:iam::{ACCOUNT}:role/service-role/quicksight-athena")
                }
            })),
            missing_work_group: None,
        },
        Case {
            label: "no DataSourceParameters at all",
            parameters: None,
            missing_work_group: None,
        },
        Case {
            label: "a parameter set naming a source outside this emulator",
            parameters: Some(json!({
                "PostgreSqlParameters": { "Host": "db.internal", "Port": 5432, "Database": "sales" }
            })),
            missing_work_group: None,
        },
        Case {
            label: "an Athena workgroup nothing created",
            parameters: Some(json!({ "AthenaParameters": { "WorkGroup": "no-such-workgroup" } })),
            missing_work_group: Some("no-such-workgroup"),
        },
        Case {
            label: "another Athena workgroup nothing created, so another message",
            parameters: Some(json!({
                "AthenaParameters": {
                    "WorkGroup": "finance-eu",
                    "RoleArn": format!("arn:aws:iam::{ACCOUNT}:role/service-role/quicksight-athena")
                }
            })),
            missing_work_group: Some("finance-eu"),
        },
        Case {
            label: "a workgroup whose name differs from a held one only in case",
            parameters: Some(json!({ "AthenaParameters": { "WorkGroup": "PRIMARY" } })),
            missing_work_group: Some("PRIMARY"),
        },
    ]
}

/// The `ErrorInfo` a read reports, asserted against what the row expects.
fn assert_error_info(label: &str, source: &Value, missing_work_group: Option<&str>) {
    match missing_work_group {
        None => assert_eq!(
            source["ErrorInfo"],
            Value::Null,
            "case {label:?}: a connection test that passed carries no ErrorInfo, got {source}"
        ),
        Some(work_group) => {
            assert_eq!(
                source["ErrorInfo"]["Type"],
                json!(GENERIC_SQL_FAILURE),
                "case {label:?}: expected ErrorInfo.Type {GENERIC_SQL_FAILURE}, got {source}"
            );
            let message = source["ErrorInfo"]["Message"]
                .as_str()
                .unwrap_or_else(|| panic!("case {label:?}: expected an ErrorInfo.Message: {source}"));
            assert!(
                message.contains(work_group),
                "case {label:?}: expected the message to name the workgroup {work_group:?}, got {message:?}"
            );
            assert!(
                message.to_lowercase().contains("workgroup"),
                "case {label:?}: expected the message to be about the workgroup, got {message:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_create_settles_on_the_outcome_of_the_connection_test() {
    let harness = Harness::new();
    harness.create_athena_work_group("reporting").await;

    for (index, case) in cases().into_iter().enumerate() {
        let Case {
            label,
            parameters,
            missing_work_group,
        } = case;
        let id = format!("ds-create-{index}");
        let mut body = json!({ "DataSourceId": id, "Name": id, "Type": "ATHENA" });
        if let Some(parameters) = parameters.clone() {
            body["DataSourceParameters"] = parameters;
        }

        let (status, response) = create_data_source(&harness, ACCOUNT, body).await;
        assert_eq!(
            status, 202,
            "case {label:?}: the create is accepted as asynchronous work, got {status} with {response}"
        );
        assert_eq!(
            response["CreationStatus"],
            json!(CREATION_IN_PROGRESS),
            "case {label:?}: the create reports the non-terminal status, got {response}"
        );

        // Until the clock owes the transition, the test has no reported outcome: the
        // status is the non-terminal one and no ErrorInfo is reported, whichever way
        // the test will settle.
        let (_, in_flight) = describe_data_source(&harness, ACCOUNT, &id).await;
        assert_eq!(
            in_flight["DataSource"]["Status"],
            json!(CREATION_IN_PROGRESS),
            "case {label:?}: before the span is over the create is still in progress: {in_flight}"
        );
        assert_eq!(
            in_flight["DataSource"]["ErrorInfo"],
            Value::Null,
            "case {label:?}: a write in flight reports no ErrorInfo yet: {in_flight}"
        );

        harness.settle_data_source(ACCOUNT, &id);
        let (status, settled) = describe_data_source(&harness, ACCOUNT, &id).await;
        assert_eq!(
            status, 200,
            "case {label:?}: describe expected 200, got {status} with {settled}"
        );
        let source = &settled["DataSource"];
        let expected_status = if missing_work_group.is_some() {
            CREATION_FAILED
        } else {
            CREATION_SUCCESSFUL
        };
        assert_eq!(
            source["Status"],
            json!(expected_status),
            "case {label:?}: expected the settled Status {expected_status}, got {settled}"
        );
        assert_eq!(
            source["DataSourceParameters"],
            parameters.unwrap_or(Value::Null),
            "case {label:?}: the submitted parameters are stored verbatim: {settled}"
        );
        assert_error_info(label, source, missing_work_group);
    }
}

#[tokio::test]
async fn an_update_settles_on_the_outcome_of_its_own_connection_test() {
    let harness = Harness::new();
    harness.create_athena_work_group("reporting").await;

    for (index, case) in cases().into_iter().enumerate() {
        let Case {
            label,
            parameters,
            missing_work_group,
        } = case;
        let id = format!("ds-update-{index}");
        // Every row starts from a data source whose create PASSED its test, so what
        // the row observes is the outcome of the update's own test.
        let (status, response) = create_data_source(
            &harness,
            ACCOUNT,
            json!({
                "DataSourceId": id,
                "Name": id,
                "Type": "ATHENA",
                "DataSourceParameters": { "AthenaParameters": { "WorkGroup": DEFAULT_WORK_GROUP } },
            }),
        )
        .await;
        assert_eq!(status, 202, "case {label:?}: fixture create: {response}");
        harness.settle_data_source(ACCOUNT, &id);

        let mut body = json!({ "Name": id });
        if let Some(parameters) = parameters.clone() {
            body["DataSourceParameters"] = parameters;
        }
        let (status, response) = update_data_source(&harness, ACCOUNT, &id, body).await;
        assert_eq!(
            status, 202,
            "case {label:?}: the update is accepted, got {status} with {response}"
        );

        harness.settle_data_source(ACCOUNT, &id);
        let (_, settled) = describe_data_source(&harness, ACCOUNT, &id).await;
        let source = &settled["DataSource"];
        let expected_status = if missing_work_group.is_some() {
            UPDATE_FAILED
        } else {
            UPDATE_SUCCESSFUL
        };
        assert_eq!(
            source["Status"],
            json!(expected_status),
            "case {label:?}: expected the settled Status {expected_status}, got {settled}"
        );
        assert_error_info(label, source, missing_work_group);
    }
}

#[tokio::test]
async fn an_update_that_passes_clears_the_error_a_failed_create_left() {
    let harness = Harness::new();
    harness.create_athena_work_group("reporting").await;

    let (status, body) = create_data_source(
        &harness,
        ACCOUNT,
        json!({
            "DataSourceId": "ds-recovers",
            "Name": "recovers",
            "Type": "ATHENA",
            "DataSourceParameters": { "AthenaParameters": { "WorkGroup": "not-yet-created" } },
        }),
    )
    .await;
    assert_eq!(status, 202, "fixture create: got {status} with {body}");
    harness.settle_data_source(ACCOUNT, "ds-recovers");
    let (_, failed) = describe_data_source(&harness, ACCOUNT, "ds-recovers").await;
    assert_eq!(
        failed["DataSource"]["Status"],
        json!(CREATION_FAILED),
        "the fixture must start from a failed connection test: {failed}"
    );

    // Rows: the same data source pointed at each workgroup the account holds, then at
    // one it does not — so the error follows the current test, not the first one.
    let rows: [(&str, &str, &str); 3] = [
        ("onto the default workgroup", DEFAULT_WORK_GROUP, UPDATE_SUCCESSFUL),
        ("onto a created workgroup", "reporting", UPDATE_SUCCESSFUL),
        ("back onto a missing workgroup", "gone-again", UPDATE_FAILED),
    ];
    for (label, work_group, expected_status) in rows {
        let (status, body) = update_data_source(
            &harness,
            ACCOUNT,
            "ds-recovers",
            json!({
                "Name": "recovers",
                "DataSourceParameters": { "AthenaParameters": { "WorkGroup": work_group } },
            }),
        )
        .await;
        assert_eq!(
            status, 202,
            "case {label:?}: the update is accepted, got {status} with {body}"
        );
        harness.settle_data_source(ACCOUNT, "ds-recovers");
        let (_, settled) = describe_data_source(&harness, ACCOUNT, "ds-recovers").await;
        let source = &settled["DataSource"];
        assert_eq!(
            source["Status"],
            json!(expected_status),
            "case {label:?}: expected the settled Status {expected_status}, got {settled}"
        );
        let expected_missing = (expected_status == UPDATE_FAILED).then_some(work_group);
        match expected_missing {
            None => assert_eq!(
                source["ErrorInfo"],
                Value::Null,
                "case {label:?}: a test that passed clears the stored ErrorInfo, got {settled}"
            ),
            Some(work_group) => {
                let message = source["ErrorInfo"]["Message"].as_str().unwrap_or_default();
                assert!(
                    message.contains(work_group),
                    "case {label:?}: expected the message to name {work_group:?}, got {message:?}"
                );
            }
        }
    }
}

/// A workgroup Athena registers AFTER a data source failed on it does not rewrite that
/// data source's settled outcome: the test ran once, and only another write runs it
/// again.
#[tokio::test]
async fn a_settled_failure_is_not_rewritten_by_a_later_athena_create() {
    let harness = Harness::new();
    let (status, body) = create_data_source(
        &harness,
        ACCOUNT,
        json!({
            "DataSourceId": "ds-late-workgroup",
            "Name": "late",
            "Type": "ATHENA",
            "DataSourceParameters": { "AthenaParameters": { "WorkGroup": "late-arrival" } },
        }),
    )
    .await;
    assert_eq!(status, 202, "fixture create: got {status} with {body}");
    harness.settle_data_source(ACCOUNT, "ds-late-workgroup");
    harness.create_athena_work_group("late-arrival").await;

    let (_, settled) = describe_data_source(&harness, ACCOUNT, "ds-late-workgroup").await;
    assert_eq!(
        settled["DataSource"]["Status"],
        json!(CREATION_FAILED),
        "a read must not re-run the connection test: {settled}"
    );
}

/// A one-entry `PhysicalTableMap` of each modelled kind, on `arn`.
fn physical_table_maps(arn: &str) -> Vec<(&'static str, Value)> {
    vec![
        (
            "CustomSql",
            json!({ "tbl1": { "CustomSql": {
                "DataSourceArn": arn, "Name": "q1", "SqlQuery": "SELECT 1 AS col",
                "Columns": [{ "Name": "col", "Type": "INTEGER" }] } } }),
        ),
        (
            "RelationalTable",
            json!({ "tbl1": { "RelationalTable": {
                "DataSourceArn": arn, "Schema": "public", "Name": "orders",
                "InputColumns": [{ "Name": "order_id", "Type": "INTEGER" }] } } }),
        ),
        (
            "S3Source",
            json!({ "tbl1": { "S3Source": {
                "DataSourceArn": arn,
                "InputColumns": [{ "Name": "col", "Type": "STRING" }] } } }),
        ),
    ]
}

#[tokio::test]
async fn a_data_set_on_a_data_source_whose_connection_failed_is_refused() {
    let harness = Harness::new();

    // Two failed data sources, one failed by its create and one by its update, so the
    // refusal reports whichever failed status the data source is actually in.
    for (id, status_after) in [("ds-bad-create", CREATION_FAILED), ("ds-bad-update", UPDATE_FAILED)]
    {
        let (code, body) = create_data_source(
            &harness,
            ACCOUNT,
            json!({
                "DataSourceId": id,
                "Name": id,
                "Type": "ATHENA",
                "DataSourceParameters": { "AthenaParameters": { "WorkGroup": match status_after {
                    CREATION_FAILED => "missing-at-create",
                    _ => DEFAULT_WORK_GROUP,
                } } },
            }),
        )
        .await;
        assert_eq!(code, 202, "fixture {id}: create got {code} with {body}");
        harness.settle_data_source(ACCOUNT, id);
        if status_after == UPDATE_FAILED {
            let (code, body) = update_data_source(
                &harness,
                ACCOUNT,
                id,
                json!({
                    "Name": id,
                    "DataSourceParameters": { "AthenaParameters": { "WorkGroup": "missing-at-update" } },
                }),
            )
            .await;
            assert_eq!(code, 202, "fixture {id}: update got {code} with {body}");
            harness.settle_data_source(ACCOUNT, id);
        }
        let (_, settled) = describe_data_source(&harness, ACCOUNT, id).await;
        assert_eq!(
            settled["DataSource"]["Status"],
            json!(status_after),
            "fixture {id}: expected {status_after}, got {settled}"
        );
    }

    // Rows: each physical-table kind, each import mode, and each of the two failed
    // statuses — the rule is about the data source's status, not about either.
    let mut data_set_index = 0;
    for (source_id, source_status) in
        [("ds-bad-create", CREATION_FAILED), ("ds-bad-update", UPDATE_FAILED)]
    {
        let arn = data_source_arn(ACCOUNT, source_id);
        for (kind, physical_table_map) in physical_table_maps(&arn) {
            for import_mode in ["SPICE", "DIRECT_QUERY"] {
                let label = format!("{source_status} / {kind} / {import_mode}");
                data_set_index += 1;
                let data_set_id = format!("dset-{data_set_index}");
                let (status, body) = create_data_set(
                    &harness,
                    ACCOUNT,
                    &data_set_id,
                    import_mode,
                    physical_table_map.clone(),
                )
                .await;
                assert_eq!(
                    status, 400,
                    "case {label:?}: expected 400 for a failed data source, got {status} with {body}"
                );
                assert_eq!(
                    body["__type"],
                    json!("InvalidParameterValueException"),
                    "case {label:?}: expected InvalidParameterValueException, got {body}"
                );
                assert_eq!(
                    body["Message"],
                    json!(format!("DataSource {arn} is in status {source_status}")),
                    "case {label:?}: unexpected refusal message: {body}"
                );
                // The refused call stored nothing.
                let (status, body) = harness
                    .call(
                        "GET",
                        &format!("/accounts/{ACCOUNT}/data-sets/{data_set_id}"),
                        None,
                    )
                    .await;
                assert_eq!(
                    status, 404,
                    "case {label:?}: a refused create must store no data set, got {status} with {body}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_data_set_on_a_data_source_whose_connection_passed_is_accepted() {
    let harness = Harness::new();
    harness.create_athena_work_group("reporting").await;

    // Rows: a source that passed its create's test, one that passed an update's test,
    // one with no parameters at all, and one belonging to another account — each may
    // back a data set. The last row proves the refusal is not about the account.
    let (status, body) = create_data_source(
        &harness,
        ACCOUNT,
        json!({
            "DataSourceId": "ds-ok",
            "Name": "ok",
            "Type": "ATHENA",
            "DataSourceParameters": { "AthenaParameters": { "WorkGroup": DEFAULT_WORK_GROUP } },
        }),
    )
    .await;
    assert_eq!(status, 202, "fixture ds-ok: got {status} with {body}");
    harness.settle_data_source(ACCOUNT, "ds-ok");

    let (status, body) = create_data_source(
        &harness,
        ACCOUNT,
        json!({ "DataSourceId": "ds-updated", "Name": "updated", "Type": "ATHENA" }),
    )
    .await;
    assert_eq!(status, 202, "fixture ds-updated: got {status} with {body}");
    harness.settle_data_source(ACCOUNT, "ds-updated");
    let (status, body) = update_data_source(
        &harness,
        ACCOUNT,
        "ds-updated",
        json!({
            "Name": "updated",
            "DataSourceParameters": { "AthenaParameters": { "WorkGroup": "reporting" } },
        }),
    )
    .await;
    assert_eq!(status, 202, "fixture ds-updated: update got {status} with {body}");
    harness.settle_data_source(ACCOUNT, "ds-updated");

    let (status, body) = create_data_source(
        &harness,
        OTHER_ACCOUNT,
        json!({ "DataSourceId": "ds-elsewhere", "Name": "elsewhere", "Type": "S3" }),
    )
    .await;
    assert_eq!(status, 202, "fixture ds-elsewhere: got {status} with {body}");
    harness.settle_data_source(OTHER_ACCOUNT, "ds-elsewhere");

    let rows: [(&str, &str, &str, &str); 4] = [
        ("a create that passed", ACCOUNT, "ds-ok", "SPICE"),
        ("an update that passed", ACCOUNT, "ds-updated", "SPICE"),
        ("a source still being created", ACCOUNT, "ds-in-flight", "DIRECT_QUERY"),
        ("another account's source", OTHER_ACCOUNT, "ds-elsewhere", "DIRECT_QUERY"),
    ];
    for (index, (label, account, source_id, import_mode)) in rows.into_iter().enumerate() {
        if source_id == "ds-in-flight" {
            // A create whose span is not over has not failed its test, so it is not
            // refused: only a FAILED status is.
            let (status, body) = create_data_source(
                &harness,
                account,
                json!({ "DataSourceId": source_id, "Name": source_id, "Type": "ATHENA" }),
            )
            .await;
            assert_eq!(status, 202, "case {label:?}: fixture create: {body}");
            let (_, in_flight) = describe_data_source(&harness, account, source_id).await;
            assert_eq!(
                in_flight["DataSource"]["Status"],
                json!(CREATION_IN_PROGRESS),
                "case {label:?}: the fixture must still be in flight: {in_flight}"
            );
        }
        let arn = data_source_arn(account, source_id);
        let data_set_id = format!("dset-ok-{index}");
        let (status, body) = create_data_set(
            &harness,
            account,
            &data_set_id,
            import_mode,
            json!({ "tbl1": { "CustomSql": {
                "DataSourceArn": arn, "Name": "q1", "SqlQuery": "SELECT 1 AS col",
                "Columns": [{ "Name": "col", "Type": "INTEGER" }] } } }),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {label:?}: expected the data set to be created, got {status} with {body}"
        );
        let (status, read_back) = harness
            .call(
                "GET",
                &format!("/accounts/{account}/data-sets/{data_set_id}"),
                None,
            )
            .await;
        assert_eq!(
            status, 200,
            "case {label:?}: the created data set must read back, got {status} with {read_back}"
        );
        assert_eq!(
            read_back["DataSet"]["ImportMode"],
            json!(import_mode),
            "case {label:?}: the data set lost its ImportMode: {read_back}"
        );
    }
}

/// The failed outcome is in the STORE, not only in the response: the record carries the
/// failed settled status and its error, which is what every reader answers from.
#[tokio::test]
async fn the_failed_outcome_is_stored_on_the_record() {
    let harness = Harness::new();
    let (status, body) = create_data_source(
        &harness,
        ACCOUNT,
        json!({
            "DataSourceId": "ds-stored",
            "Name": "stored",
            "Type": "ATHENA",
            "DataSourceParameters": { "AthenaParameters": { "WorkGroup": "absent-workgroup" } },
        }),
    )
    .await;
    assert_eq!(status, 202, "fixture create: got {status} with {body}");

    let state = qs_state::service_state(&*harness.engine).expect("the QuickSight store");
    let store = state.lock();
    let record = store
        .data_sources
        .get(&(ACCOUNT.to_string(), "ds-stored".to_string()))
        .expect("the created data source");
    assert_eq!(
        record.settled_status, CREATION_FAILED,
        "expected the stored settled status {CREATION_FAILED}, got {record:?}"
    );
    let error_info = record
        .error_info
        .as_ref()
        .unwrap_or_else(|| panic!("expected the stored record to carry an error: {record:?}"));
    assert_eq!(
        error_info.r#type.as_deref(),
        Some(GENERIC_SQL_FAILURE),
        "expected the stored error type {GENERIC_SQL_FAILURE}, got {error_info:?}"
    );
    assert!(
        error_info
            .message
            .as_deref()
            .is_some_and(|message| message.contains("absent-workgroup")),
        "expected the stored message to name the workgroup, got {error_info:?}"
    );
}
