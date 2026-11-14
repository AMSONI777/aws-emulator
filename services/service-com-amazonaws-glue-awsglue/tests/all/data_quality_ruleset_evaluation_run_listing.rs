// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for `ListDataQualityRulesetEvaluationRuns`.
//!
//! Every call goes over the wire through the shared [`crate::wire`] harness, so what is
//! asserted is HTTP behaviour and not a direct call into a handler.
//!
//! The rule under test: the listing reports the data quality ruleset evaluation runs this
//! account holds — the records `StartDataQualityRulesetEvaluationRun` wrote — newest first,
//! one `MaxResults`-sized page at a time with a `NextToken` that resumes the walk, narrowed
//! to the runs every member of the `Filter` admits: the runs whose own data source addresses
//! the table the filter's `DataSource` names, that evaluate a ruleset under its
//! `RulesetName`, and that started strictly inside the window its `StartedBefore` and
//! `StartedAfter` describe. A listed run carries what the single-run read reports for it, and
//! the listing writes nothing beyond the status the CLOCK had already made due.
//!
//! The recorded case — a listing over an account whose only start was refused, so it holds no
//! run at all — is ONE row of the tables below; the rows differ along which `DataSource`
//! member carries the table, the casing of its names, whether a catalog id is named, which
//! filter members narrow the set, whether a run reads a further table as an additional data
//! source, how many runs the account holds, the page size and where the page resumes.
//!
//! The due instants the run lifecycle turns on are read and moved THROUGH THE STORE rather
//! than slept for, so the transient window is deterministic.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use service_com_amazonaws_glue_awsglue::state::{
    ComAmazonawsGlueAwsglueState, DATA_QUALITY_RUN_STATE_STARTING,
    TERMINAL_DATA_QUALITY_RUN_STATES,
};
use smithy_server_runtime::MultiServiceRouter;

use crate::wire::{call, emulator_on, error_code, error_message, ok, ACCOUNT_ID};

/// The IAM role every start below names: "An IAM role supplied to encrypt the results of the
/// run."
const ROLE: &str = "arn:aws:iam::000000000000:role/glue-data-quality-role";

/// The bucket every table below points its data at.
const DATA_BUCKET: &str = "dq-run-listing-data";

/// The databases and tables the runs below cover: two tables of one database and a table of
/// another sharing a name with one of them, so a filter naming a table has a same-named table
/// of another database to tell it apart from.
const DATABASE: &str = "dq_listing_db";
const OTHER_DATABASE: &str = "dq_listing_other_db";
const TABLE: &str = "events";
const OTHER_TABLE: &str = "orders";

/// The rulesets the runs below evaluate.
const RULESET: &str = "listing-events-ruleset";
const OTHER_RULESET: &str = "listing-orders-ruleset";

/// The smallest and the largest page `MaxResults` accepts, from the member's own range
/// (`ListDataQualityRulesetEvaluationRunsRequest$MaxResults`, `PageSize` range 1..1000).
const MIN_MAX_RESULTS: i64 = 1;
const MAX_MAX_RESULTS: i64 = 1_000;

/// An emulator plus the engine it runs on, so a test can move the due instants the run
/// lifecycle turns on instead of waiting for them.
///
/// Amazon S3 is mounted on the same engine because an evaluation run READS the objects behind
/// its data source's table, through the emulator's own in-process callback.
fn emulator_with_engine() -> (MultiServiceRouter, Arc<engine::InMemoryEngine>) {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = emulator_on(engine.clone());
    router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
        Arc::clone(&engine),
    ));
    (router, engine)
}

/// Store `database` holding `table`, whose data is staged in this emulator's own Amazon S3.
/// A database several tables share is created once — a repeat create is the catalog's
/// `AlreadyExistsException`, which is not what these tests are about.
async fn store_table(router: &MultiServiceRouter, database: &str, table: &str) {
    let (status, parsed) = call(
        router,
        "CreateDatabase",
        &json!({ "DatabaseInput": { "Name": database } }),
    )
    .await;
    assert!(
        status == 200 || error_code(&parsed).ends_with("AlreadyExistsException"),
        "CreateDatabase must answer 200 or report the database is already stored, got {status} \
         with {parsed}"
    );
    stage_table_data(router, database, table).await;
    ok(
        router,
        "CreateTable",
        &json!({
            "DatabaseName": database,
            "TableInput": {
                "Name": table,
                "TableType": "EXTERNAL_TABLE",
                "StorageDescriptor": {
                    "Location": format!("s3://{DATA_BUCKET}/{database}/{table}/"),
                    "Columns": [{ "Name": "id", "Type": "string" }],
                },
            },
        }),
    )
    .await;
}

/// Put one object under the prefix the table's storage descriptor names, creating the bucket
/// the first time: one row carrying the one column those tables declare.
async fn stage_table_data(router: &MultiServiceRouter, database: &str, table: &str) {
    let client = crate::wire::s3_client(router);
    // The bucket is shared by every table, so the create of an existing one is no failure.
    let _ = client.create_bucket().bucket(DATA_BUCKET).send().await;
    client
        .put_object()
        .bucket(DATA_BUCKET)
        .key(format!("{database}/{table}/rows.csv"))
        .body(aws_sdk_s3::primitives::ByteStream::from(
            b"row-1\n".to_vec(),
        ))
        .send()
        .await
        .unwrap_or_else(|error| panic!("the data of {database}.{table} must be staged, got {error:?}"));
}

/// Store a data quality ruleset under `name`, so a start may evaluate it.
async fn store_ruleset(router: &MultiServiceRouter, name: &str) {
    ok(
        router,
        "CreateDataQualityRuleset",
        &json!({ "Name": name, "Ruleset": "Rules = [\n    ColumnExists \"id\"\n]" }),
    )
    .await;
}

/// A `DataSource` addressing `database`.`table` through the named member: either the plain
/// `GlueTable` ("An Glue table") or the `DataQualityGlueTable` ("An Glue table for Data
/// Quality Operations"), which address a table the same way.
fn source_through(member: &str, database: &str, table: &str, catalog_id: Option<&str>) -> Value {
    let mut glue_table = json!({ "DatabaseName": database, "TableName": table });
    if let Some(catalog) = catalog_id {
        glue_table["CatalogId"] = json!(catalog);
    }
    json!({ member: glue_table })
}

/// Start an evaluation run of `rulesets` over `data_source`, plus whatever `extra` adds to
/// the three `@required` members, and answer the `RunId` it reports.
async fn start_run(
    router: &MultiServiceRouter,
    data_source: &Value,
    rulesets: &[&str],
    extra: &Value,
) -> String {
    let mut body = json!({
        "DataSource": data_source,
        "Role": ROLE,
        "RulesetNames": rulesets,
    });
    if let Some(members) = extra.as_object() {
        for (member, value) in members {
            body[member] = value.clone();
        }
    }
    let started = ok(router, "StartDataQualityRulesetEvaluationRun", &body).await;
    started
        .get("RunId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("StartDataQualityRulesetEvaluationRun must answer a RunId, got {started}")
        })
        .to_string()
}

/// One page of the listing: the `Runs` it reports, in the order it reports them, and its
/// `NextToken`.
async fn list_page(router: &MultiServiceRouter, body: &Value) -> (Vec<Value>, Option<String>) {
    let page = ok(router, "ListDataQualityRulesetEvaluationRuns", body).await;
    let runs = page
        .get("Runs")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the listing must report a Runs list, got {page}"))
        .clone();
    let next = page
        .get("NextToken")
        .and_then(Value::as_str)
        .map(str::to_string);
    (runs, next)
}

/// The `RunId` of every run one page reports, in the order it reports them.
fn listed_ids(runs: &[Value]) -> Vec<String> {
    runs.iter()
        .map(|run| {
            run.get("RunId")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("every listed run carries a RunId, got {run}"))
                .to_string()
        })
        .collect()
}

/// The ids the whole listing reports for `body`, in order, with no page size of its own.
async fn listed_ids_for(router: &MultiServiceRouter, body: &Value) -> Vec<String> {
    let (runs, _) = list_page(router, body).await;
    listed_ids(&runs)
}

/// What `GetDataQualityRulesetEvaluationRun` reports for one run.
async fn get_run(router: &MultiServiceRouter, run_id: &str) -> Value {
    ok(
        router,
        "GetDataQualityRulesetEvaluationRun",
        &json!({ "RunId": run_id }),
    )
    .await
}

/// Move the due instant of every unsettled run to `at`, so a test can hold the transient
/// window open or make the owed transition due without sleeping.
fn set_due_instant(engine: &Arc<engine::InMemoryEngine>, at: SystemTime) {
    let state = engine.state::<ComAmazonawsGlueAwsglueState>();
    let mut store = state.lock();
    for run in &mut store.data_quality_ruleset_evaluation_runs {
        if run.settles_at.is_some() {
            run.settles_at = Some(at);
        }
    }
}

/// An instant far enough out that no owed transition falls due during a test.
fn far_future() -> SystemTime {
    SystemTime::now() + Duration::from_secs(3600)
}

/// An instant already past, so the next call settles what the clock owed.
fn already_past() -> SystemTime {
    SystemTime::now() - Duration::from_secs(1)
}

/// The catalog state every test below starts from, and the runs it holds: five runs, started
/// in this order, over four tables of two databases, through both members a `DataSource` can
/// carry, evaluating one ruleset or several, and one of them reading a further table as an
/// `AdditionalDataSources` entry.
///
/// Answers the ids in the order they were started, so the newest-first order the listing must
/// report is this list reversed.
async fn started_runs(router: &MultiServiceRouter) -> Vec<(&'static str, String)> {
    store_table(router, DATABASE, TABLE).await;
    store_table(router, DATABASE, OTHER_TABLE).await;
    store_table(router, OTHER_DATABASE, TABLE).await;
    store_table(router, OTHER_DATABASE, OTHER_TABLE).await;
    store_ruleset(router, RULESET).await;
    store_ruleset(router, OTHER_RULESET).await;

    let starts: [(&'static str, Value, &[&str], Value); 5] = [
        (
            "a GlueTable and one ruleset",
            source_through("GlueTable", DATABASE, TABLE, None),
            &[RULESET],
            json!({}),
        ),
        (
            "a DataQualityGlueTable and two rulesets",
            source_through("DataQualityGlueTable", DATABASE, OTHER_TABLE, None),
            &[OTHER_RULESET, RULESET],
            json!({}),
        ),
        (
            "a same-named table of another database",
            source_through("GlueTable", OTHER_DATABASE, TABLE, None),
            &[RULESET],
            json!({}),
        ),
        (
            "a second run of the first table, of the other ruleset",
            source_through("GlueTable", DATABASE, TABLE, Some(ACCOUNT_ID)),
            &[OTHER_RULESET],
            json!({}),
        ),
        (
            // Its data source is its OWN table; the table it reads as an additional data
            // source is one two other runs cover as their own.
            "a run that reads a further table as an additional data source",
            source_through("GlueTable", OTHER_DATABASE, OTHER_TABLE, None),
            &[RULESET],
            json!({
                "AdditionalDataSources": {
                    "reference_one": source_through("GlueTable", DATABASE, TABLE, None),
                },
            }),
        ),
    ];

    let mut started = Vec::new();
    for (case, data_source, rulesets, extra) in starts {
        started.push((case, start_run(router, &data_source, rulesets, &extra).await));
    }
    started
}

// ---------------------------------------------------------------------------
// What the listing reports
// ---------------------------------------------------------------------------

/// The listing reports every run the account holds, newest first, across tables and databases
/// alike — and every run it reports carries what the single-run read reports for it.
#[tokio::test]
async fn the_listing_reports_every_stored_run_newest_first() {
    let (router, engine) = emulator_with_engine();

    // An account with no run at all has an empty listing: the operation models no miss for
    // it, and the recorded unit's account is exactly this one.
    let (empty, next) = list_page(&router, &json!({})).await;
    assert!(
        empty.is_empty() && next.is_none(),
        "case {:?}: an account with no run reports an empty page and no token, got {empty:?} \
         with {next:?}",
        "no run yet"
    );

    let started = started_runs(&router).await;
    // The runs are held in flight, so what the listing reports is the status the single-run
    // read reports at the same instant rather than whatever the clock settled in between.
    set_due_instant(&engine, far_future());
    let newest_first: Vec<String> = started.iter().rev().map(|(_, id)| id.clone()).collect();

    // (case, the request that must report exactly those runs)
    for (case, body) in [
        ("no page size at all", json!({})),
        (
            "the largest page the model accepts",
            json!({ "MaxResults": MAX_MAX_RESULTS }),
        ),
        (
            "a page size past the number of runs there are",
            json!({ "MaxResults": 7 }),
        ),
    ] {
        let (runs, next) = list_page(&router, &body).await;
        let ids = listed_ids(&runs);
        assert_eq!(
            ids, newest_first,
            "case {case:?}: the listing reports every run of the account, newest first; got \
             {ids:?}"
        );
        assert!(
            next.is_none(),
            "case {case:?}: a page that reached the end carries no token, got {next:?}"
        );

        // Every run the listing reports is the run the single-run read serves under that id:
        // the four members the description carries are the ones that read reports.
        for run in &runs {
            let id = run["RunId"].as_str().unwrap_or_default().to_string();
            let read = get_run(&router, &id).await;
            for member in ["RunId", "Status", "StartedOn", "DataSource"] {
                assert_eq!(
                    run.get(member),
                    read.get(member),
                    "case {case:?}: the listed run {id} must report the {member} the single-run \
                     read reports; got {run} against {read}"
                );
            }
        }
    }
}

/// A page is at most `MaxResults` runs, and its token resumes the listing where it stopped —
/// so paging the whole listing walks every run exactly once, in its order, at every page size.
#[tokio::test]
async fn paging_the_listing_walks_every_run_once() {
    let (router, engine) = emulator_with_engine();
    let started = started_runs(&router).await;
    set_due_instant(&engine, far_future());
    let newest_first: Vec<String> = started.iter().rev().map(|(_, id)| id.clone()).collect();

    // The smallest and the largest page the model accepts, and the sizes in between that
    // split these runs into several pages.
    for page_size in [MIN_MAX_RESULTS, 2, 3, 4, MAX_MAX_RESULTS] {
        let case = format!("pages of {page_size}");
        let mut walked: Vec<String> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut body = json!({ "MaxResults": page_size });
            if let Some(cursor) = token.as_deref() {
                body["NextToken"] = json!(cursor);
            }
            let (runs, next) = list_page(&router, &body).await;
            assert!(
                i64::try_from(runs.len()).unwrap_or(i64::MAX) <= page_size,
                "case {case:?}: a page carries at most MaxResults runs, got {} of them",
                runs.len()
            );
            walked.extend(listed_ids(&runs));
            match next {
                Some(cursor) => token = Some(cursor),
                None => break,
            }
        }
        assert_eq!(
            walked, newest_first,
            "case {case:?}: paging walks every run exactly once, in the listing's order; got \
             {walked:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// What the filter narrows the listing to
// ---------------------------------------------------------------------------

/// One row of the filter table below: the criteria, and which of the started runs they admit.
struct FilterCase<'a> {
    /// What this row varies, named in each of its assertions.
    case: &'a str,
    /// The `Filter` the request carries.
    filter: Value,
    /// The indexes, in start order, of the runs the criteria admit.
    admitted: &'a [usize],
}

/// A `Filter` narrows the listing to the runs every one of its members admits: its
/// `@required` `DataSource` to the runs whose own data source addresses that table, whichever
/// member carries it and however its names are cased, its `RulesetName` to the runs that
/// evaluate a ruleset under that name, and its instant pair to the runs started strictly
/// inside the window it describes.
#[tokio::test]
async fn a_filter_narrows_the_listing_to_the_runs_it_admits() {
    let (router, engine) = emulator_with_engine();
    let started = started_runs(&router).await;
    set_due_instant(&engine, far_future());

    // A `Timestamp` arrives as seconds since the epoch, so these two bracket every run
    // started during this test: one instant long past and one long ahead.
    let long_past = json!(0);
    let long_ahead = json!(4_102_444_800i64);

    let cases = vec![
        FilterCase {
            case: "the table one run covers",
            filter: json!({ "DataSource": source_through("GlueTable", DATABASE, OTHER_TABLE, None) }),
            admitted: &[1],
        },
        FilterCase {
            case: "a table two runs cover",
            filter: json!({ "DataSource": source_through("GlueTable", DATABASE, TABLE, None) }),
            admitted: &[0, 3],
        },
        FilterCase {
            // The newest run READS this table, as an `AdditionalDataSources` entry, but its
            // own data source is another table: the criteria's `DataSource` names the run's
            // own, which is the one a listed run reports.
            case: "a table a further run reads only as an additional data source",
            filter: json!({ "DataSource": source_through("GlueTable", DATABASE, TABLE, None) }),
            admitted: &[0, 3],
        },
        FilterCase {
            case: "the own table of the run that reads an additional data source",
            filter: json!({
                "DataSource": source_through("GlueTable", OTHER_DATABASE, OTHER_TABLE, None),
            }),
            admitted: &[4],
        },
        FilterCase {
            case: "the same-named table of another database",
            filter: json!({ "DataSource": source_through("GlueTable", OTHER_DATABASE, TABLE, None) }),
            admitted: &[2],
        },
        FilterCase {
            // The catalog folds a name, so another casing of a stored table addresses that
            // same table.
            case: "the names of a covered table in another casing",
            filter: json!({
                "DataSource": source_through(
                    "GlueTable",
                    &DATABASE.to_uppercase(),
                    &TABLE.to_uppercase(),
                    None,
                ),
            }),
            admitted: &[0, 3],
        },
        FilterCase {
            // "If none is provided, the Amazon Web Services account ID is used by default",
            // so naming it explicitly addresses the same catalog.
            case: "the account's own catalog named explicitly",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, Some(ACCOUNT_ID)),
            }),
            admitted: &[0, 3],
        },
        FilterCase {
            case: "another account's catalog",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, Some("111122223333")),
            }),
            admitted: &[],
        },
        FilterCase {
            // The run under test was started through the OTHER member, so which member
            // carries the table cannot decide what a filter admits.
            case: "a DataQualityGlueTable naming a table a GlueTable run covers",
            filter: json!({
                "DataSource": source_through("DataQualityGlueTable", DATABASE, TABLE, None),
            }),
            admitted: &[0, 3],
        },
        FilterCase {
            case: "a GlueTable naming a table a DataQualityGlueTable run covers",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, OTHER_TABLE, None),
            }),
            admitted: &[1],
        },
        FilterCase {
            case: "a table the catalog holds no run for",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, "never_evaluated", None),
            }),
            admitted: &[],
        },
        FilterCase {
            case: "a ruleset only the older of the two runs evaluates",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "RulesetName": RULESET,
            }),
            admitted: &[0],
        },
        FilterCase {
            case: "a ruleset only the newer of the two runs evaluates",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "RulesetName": OTHER_RULESET,
            }),
            admitted: &[3],
        },
        FilterCase {
            // The run lists this ruleset second, so a run qualifies on any ruleset it
            // evaluates and not only on the first.
            case: "a ruleset a run lists second",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, OTHER_TABLE, None),
                "RulesetName": RULESET,
            }),
            admitted: &[1],
        },
        FilterCase {
            case: "a ruleset no run of that table evaluates",
            filter: json!({
                "DataSource": source_through("GlueTable", OTHER_DATABASE, TABLE, None),
                "RulesetName": OTHER_RULESET,
            }),
            admitted: &[],
        },
        FilterCase {
            case: "runs started after an instant long past",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "StartedAfter": long_past,
            }),
            admitted: &[0, 3],
        },
        FilterCase {
            case: "runs started before an instant long past",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "StartedBefore": long_past,
            }),
            admitted: &[],
        },
        FilterCase {
            case: "runs started before an instant long ahead",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "StartedBefore": long_ahead,
            }),
            admitted: &[0, 3],
        },
        FilterCase {
            case: "runs started after an instant long ahead",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "StartedAfter": long_ahead,
            }),
            admitted: &[],
        },
        FilterCase {
            case: "a window around every run, with a ruleset one of them evaluates",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "StartedAfter": long_past,
                "StartedBefore": long_ahead,
                "RulesetName": OTHER_RULESET,
            }),
            admitted: &[3],
        },
        FilterCase {
            case: "a window that excludes every run, with a ruleset one of them evaluates",
            filter: json!({
                "DataSource": source_through("GlueTable", DATABASE, TABLE, None),
                "StartedAfter": long_ahead,
                "StartedBefore": long_past,
                "RulesetName": OTHER_RULESET,
            }),
            admitted: &[],
        },
    ];

    for FilterCase {
        case,
        filter,
        admitted,
    } in cases
    {
        // The admitted runs, newest first: the listing's own order, narrowed.
        let expected: Vec<String> = admitted
            .iter()
            .rev()
            .map(|index| started[*index].1.clone())
            .collect();
        let got = listed_ids_for(&router, &json!({ "Filter": filter })).await;
        assert_eq!(
            got, expected,
            "case {case:?}: the listing reports exactly the runs the criteria admit, newest \
             first; got {got:?}"
        );

        // A filter narrows the listing without changing how it pages: walking it one run at a
        // time reaches the same runs in the same order.
        let mut walked: Vec<String> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut body = json!({ "Filter": filter, "MaxResults": MIN_MAX_RESULTS });
            if let Some(cursor) = token.as_deref() {
                body["NextToken"] = json!(cursor);
            }
            let (runs, next) = list_page(&router, &body).await;
            walked.extend(listed_ids(&runs));
            match next {
                Some(cursor) => token = Some(cursor),
                None => break,
            }
        }
        assert_eq!(
            walked, expected,
            "case {case:?}: paging a filtered listing walks the admitted runs once, in that \
             same order; got {walked:?}"
        );
    }
}

/// A `Filter` whose `@required` `DataSource` carries neither kind of Glue table addresses no
/// data source to filter on, so it is refused as the bad input it is — 400 with the
/// operation's modelled `InvalidInputException` — and never answered as an empty listing.
#[tokio::test]
async fn a_filter_whose_data_source_addresses_no_table_is_refused() {
    let (router, _engine) = emulator_with_engine();
    started_runs(&router).await;

    // (case, the `Filter` the request carries) — the refusal is decided by the data source
    // the criteria address, whatever else they narrow by.
    for (case, filter) in [
        (
            "criteria carrying nothing but an empty DataSource",
            json!({ "DataSource": {} }),
        ),
        (
            "criteria that also name a ruleset and a window",
            json!({
                "DataSource": {},
                "RulesetName": RULESET,
                "StartedAfter": 0,
                "StartedBefore": 4_102_444_800i64,
            }),
        ),
    ] {
        let (status, parsed) = call(
            &router,
            "ListDataQualityRulesetEvaluationRuns",
            &json!({ "Filter": filter }),
        )
        .await;
        assert_eq!(
            status, 400,
            "case {case:?}: a filter naming no table is refused as bad input, got {status} with \
             {parsed}"
        );
        assert!(
            error_code(&parsed).ends_with("InvalidInputException"),
            "case {case:?}: the refusal is the operation's modelled InvalidInputException, got \
             {parsed}"
        );
        assert!(
            error_message(&parsed).contains("GlueTable"),
            "case {case:?}: the refusal names the members the input has to carry one of, got \
             {:?}",
            error_message(&parsed)
        );
    }
}

/// The listing reports the status the CLOCK owes each run, exactly as the single-run read
/// does, and reports it without moving anything else: listing a run in flight twice leaves it
/// in flight, and the run the clock has finished is reported in a terminal status by the
/// listing and by the read alike.
#[tokio::test]
async fn the_listing_reports_the_status_the_clock_owes_and_moves_nothing_else() {
    let (router, engine) = emulator_with_engine();
    let started = started_runs(&router).await;
    let ids: BTreeSet<String> = started.iter().map(|(_, id)| id.clone()).collect();

    // Held in flight: a listing is a report, so it may not finish a run whose transition is
    // not due, however many times it is called.
    set_due_instant(&engine, far_future());
    for probe in ["the first listing", "the second listing"] {
        let (runs, _) = list_page(&router, &json!({})).await;
        for run in &runs {
            assert_eq!(
                run.get("Status").and_then(Value::as_str),
                Some(DATA_QUALITY_RUN_STATE_STARTING),
                "case {probe:?}: a run whose transition is not due yet is still reported in \
                 flight, got {run}"
            );
        }
    }
    // And the single-run read agrees: the listing left the store as it found it.
    for id in &ids {
        let read = get_run(&router, id).await;
        assert_eq!(
            read.get("Status").and_then(Value::as_str),
            Some(DATA_QUALITY_RUN_STATE_STARTING),
            "case {:?}: the run {id} the listing reported in flight is still in flight, got \
             {read}",
            "after two listings"
        );
    }

    // Once the clock owes the transition, the listing materialises it, and reports what the
    // single-run read reports.
    set_due_instant(&engine, already_past());
    let (runs, _) = list_page(&router, &json!({})).await;
    assert_eq!(
        listed_ids(&runs).into_iter().collect::<BTreeSet<_>>(),
        ids,
        "case {:?}: the listing still reports every run of the account, got {runs:?}",
        "once the transition is due"
    );
    for run in &runs {
        let id = run["RunId"].as_str().unwrap_or_default().to_string();
        let status = run
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("every listed run carries a Status, got {run}"));
        assert!(
            TERMINAL_DATA_QUALITY_RUN_STATES.contains(&status),
            "case {:?}: the run {id} the clock has finished is reported in a terminal status, \
             got {status:?}",
            "once the transition is due"
        );
        let read = get_run(&router, &id).await;
        assert_eq!(
            read.get("Status").and_then(Value::as_str),
            Some(status),
            "case {:?}: the run {id} is reported in the same status by the listing and by the \
             read, got {read}",
            "once the transition is due"
        );
    }
}
