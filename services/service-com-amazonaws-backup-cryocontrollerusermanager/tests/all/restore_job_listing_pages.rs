// SPDX-License-Identifier: CC0-1.0

//! The PAGE a caller asks a listing for, and the requests a page could not serve.
//!
//! The sibling suite (`restore_job_listing.rs`) covers what `ListRestoreJobs` reports and
//! which jobs each `By*` filter selects. The RULES under test here are the ones about the
//! page itself:
//!
//! * `MaxResults` is the page size the model publishes a `@range(min: 1, max: 1000)` for
//!   (`smithy_query` operation `ListRestoreJobs`, member `MaxResults`), and AWS Backup
//!   refuses one outside it with the operation's OWN modelled
//!   `InvalidParameterValueException` — the body a client reads this service's `Code` and
//!   `Message` out of — on every operation that takes a page size, not with a generic
//!   constraint report in a shape the model does not declare; each published bound is served;
//! * every admitted page size walks the stored jobs exactly once, in one order, in as many
//!   pages as that size needs, because the cursor resumes exactly where the page stopped;
//! * `ByRestoreTestingPlanArn` is typed `ARN`, so a value that is not one is refused as a
//!   parameter value rather than answered with a page, while one that IS an ARN selects the
//!   jobs started from that plan — none, in a slice that starts no restore from one.
//!
//! Every case drives real HTTP through the router, on the Backup wire shared with the other
//! suites (`vault_and_backup_job.rs`). The restores here are of a type this emulator
//! performs no restore of, because what the page reports is every job `StartRestoreJob`
//! stored, whatever each one's status becomes.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::recovery_point_deletion::{completed_point, router_with_engine};
use crate::vault_and_backup_job::{call, create_vault, error_code, string_at, ACCOUNT, REGION};

/// The vault the recovery points of this suite are backed up into.
const VAULT: &str = "restore-paging-source";

/// How many restore jobs the paging cases walk. Three is the smallest set that makes a page
/// size of two end on a partial page, which is what the cursor has to resume from.
const STORED_JOBS: usize = 3;

/// The page sizes the walk is performed with: below, at and above the stored count, so a
/// page that stops short, one that ends exactly on the last job and one that holds the whole
/// set are all covered.
const PAGE_SIZES: [usize; 4] = [1, 2, 3, 4];

/// The published ends of the `MaxResults` range, from the model's `@range` on the
/// `MaxResults` shape every one of these operations binds its page size to.
const MAX_RESULTS_MIN: i64 = 1;
const MAX_RESULTS_MAX: i64 = 1000;

/// The `Code` and `Message` this service words a page size outside that range with.
const MAX_RESULTS_CODE: &str = "ERROR_3607";
const MAX_RESULTS_MESSAGE: &str = "Max Results is invalid";

/// `PUT /restore-jobs` for one recovery point; answers the `RestoreJobId`.
async fn start_restore(router: &MultiServiceRouter, recovery_point_arn: &str) -> String {
    let body = json!({
        "RecoveryPointArn": recovery_point_arn,
        "ResourceType": "EFS",
        "Metadata": {"newFileSystem": "true"},
        "IamRoleArn": format!("arn:aws:iam::{ACCOUNT}:role/service-role/AWSBackupDefaultServiceRole"),
    })
    .to_string();
    let (status, started) = call(router, "PUT", "/restore-jobs", Some(&body)).await;
    assert_eq!(
        status, 200,
        "setup: expected StartRestoreJob 200, got {status} {started:?}"
    );
    string_at(&started, "RestoreJobId")
}

/// `GET /restore-jobs?{query}`: the status and the whole body, so a case reads the jobs, the
/// cursor or the refusal out of the same answer.
async fn list_restores(router: &MultiServiceRouter, query: &str) -> (u16, Value) {
    call(router, "GET", &format!("/restore-jobs?{query}"), None).await
}

/// The `RestoreJobId`s one page reports, in the order it reports them.
fn ids_of(listed: &Value) -> Vec<String> {
    listed["RestoreJobs"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|job| string_at(job, "RestoreJobId"))
        .collect()
}

/// Back up `STORED_JOBS` distinct file systems and start one restore of each, answering the
/// router and the job ids the unfiltered page reports, in its order.
async fn stored_restores() -> (MultiServiceRouter, Vec<String>) {
    let (router, _engine) = router_with_engine();
    let (status, created) = create_vault(&router, VAULT, "{}").await;
    assert_eq!(
        status, 200,
        "setup: expected CreateBackupVault 200, got {status} {created:?}"
    );
    for index in 0..STORED_JOBS {
        let resource =
            format!("arn:aws:elasticfilesystem:{REGION}:{ACCOUNT}:file-system/fs-0{index}");
        let point = completed_point(&router, VAULT, &resource).await;
        start_restore(&router, &point).await;
    }

    let (status, all) = list_restores(&router, "").await;
    assert_eq!(
        status, 200,
        "setup: expected ListRestoreJobs 200, got {status} {all:?}"
    );
    let ids = ids_of(&all);
    assert_eq!(
        ids.len(),
        STORED_JOBS,
        "setup: the unfiltered page must report every started restore, got {all:?}"
    );
    (router, ids)
}

/// RULE: every admitted page size walks the stored jobs exactly once, in the unfiltered
/// page's order, in as many pages as that size needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_page_size_walks_the_stored_restore_jobs_exactly_once() {
    let (router, ids) = stored_restores().await;

    for page_size in PAGE_SIZES {
        let mut seen: Vec<String> = Vec::new();
        let mut token: Option<String> = None;
        let mut pages = 0_usize;
        loop {
            let mut query = format!("maxResults={page_size}");
            if let Some(cursor) = &token {
                query.push_str(&format!("&nextToken={cursor}"));
            }
            let (status, listed) = list_restores(&router, &query).await;
            assert_eq!(
                status, 200,
                "case page_size={page_size}: expected 200, got {status} {listed:?}"
            );
            let page = ids_of(&listed);
            assert!(
                page.len() <= page_size,
                "case page_size={page_size}: a page must hold at most MaxResults jobs, got \
                 {page:?}"
            );
            seen.extend(page);
            token = listed
                .get("NextToken")
                .and_then(Value::as_str)
                .map(str::to_string);
            pages += 1;
            assert!(
                pages <= ids.len() + 1,
                "case page_size={page_size}: the walk did not terminate after {pages} pages, \
                 having seen {seen:?}"
            );
            if token.is_none() {
                break;
            }
        }
        assert_eq!(
            seen, ids,
            "case page_size={page_size}: expected every stored job once, in the listing's \
             order, got {seen:?}"
        );
        let expected_pages = ids.len().div_ceil(page_size);
        assert_eq!(
            pages, expected_pages,
            "case page_size={page_size}: expected {expected_pages} page(s), got {pages}"
        );
    }
}

/// Every route of this service that takes a page size and owns the refusal for one outside
/// the published range: the operation, its path and the name its `@httpQuery` binds the page
/// size under (`smithy_query` operation `List*`, member `MaxResults`).
///
/// A path label is filled with a value the model admits; the refusal is answered before the
/// resource the label names is resolved, so it is the page size and nothing else each row
/// turns on.
fn max_results_routes() -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("ListRestoreJobs", "/restore-jobs".to_string(), "maxResults"),
        ("ListBackupJobs", "/backup-jobs".to_string(), "maxResults"),
        ("ListLegalHolds", "/legal-holds".to_string(), "maxResults"),
        (
            "ListTieringConfigurations",
            "/tiering-configurations".to_string(),
            "maxResults",
        ),
        (
            "ListBackupSelections",
            "/backup/plans/paging-plan/selections".to_string(),
            "maxResults",
        ),
        (
            "ListRecoveryPointsByLegalHold",
            "/legal-holds/paging-hold/recovery-points".to_string(),
            "maxResults",
        ),
        (
            "ListRestoreAccessBackupVaults",
            "/logically-air-gapped-backup-vaults/paging-vault/restore-access-backup-vaults"
                .to_string(),
            "maxResults",
        ),
        (
            "ListTags",
            format!("/tags/arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:paging-vault"),
            "maxResults",
        ),
        // The rows below already answered this refusal before the change these cases pin, so
        // they are the comparison the others are held to rather than new coverage.
        ("ListBackupVaults", "/backup-vaults".to_string(), "maxResults"),
        (
            "ListProtectedResources",
            "/resources".to_string(),
            "maxResults",
        ),
        (
            "ListRestoreJobSummaries",
            "/audit/restore-job-summaries".to_string(),
            "MaxResults",
        ),
    ]
}

/// The routes of that table that name no resource in their path, so a page size the model
/// admits is served on them with nothing set up first.
const UNLABELLED_ROUTES: [(&str, &str, &str); 6] = [
    ("ListRestoreJobs", "/restore-jobs", "maxResults"),
    ("ListBackupJobs", "/backup-jobs", "maxResults"),
    ("ListLegalHolds", "/legal-holds", "maxResults"),
    (
        "ListTieringConfigurations",
        "/tiering-configurations",
        "maxResults",
    ),
    ("ListBackupVaults", "/backup-vaults", "maxResults"),
    ("ListProtectedResources", "/resources", "maxResults"),
];

/// RULE: a page size outside the published range is refused with the operation's own modelled
/// `InvalidParameterValueException` — the body carrying this service's `Code` and `Message`
/// for that condition — on every operation that takes one, and carries no page; each
/// published bound is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_size_outside_the_published_range_is_the_modelled_refusal() {
    let (router, _engine) = router_with_engine();

    // One step past each published bound, and well past each.
    for (operation, path, parameter) in max_results_routes() {
        for (case, value) in [
            ("one below the published minimum", MAX_RESULTS_MIN - 1),
            ("negative", -1),
            ("far below the published minimum", -1000),
            ("one above the published maximum", MAX_RESULTS_MAX + 1),
            ("far above the published maximum", 100_000),
        ] {
            let (status, refused) =
                call(&router, "GET", &format!("{path}?{parameter}={value}"), None).await;
            assert_eq!(
                (
                    status,
                    error_code(&refused).as_str(),
                    string_at(&refused, "Code").as_str(),
                    string_at(&refused, "Message").as_str(),
                ),
                (
                    400,
                    "InvalidParameterValueException",
                    MAX_RESULTS_CODE,
                    MAX_RESULTS_MESSAGE,
                ),
                "case {case:?} ({operation} {parameter}={value}): expected the modelled \
                 page-size refusal, got {status} {refused:?}"
            );
            assert!(
                refused.get("RestoreJobs").is_none(),
                "case {case:?} ({operation} {parameter}={value}): a refusal carries no page, got \
                 {refused:?}"
            );
        }
    }

    // Non-vacuity: a page size the model admits is NOT answered with that refusal, so the
    // refusals above are the range's answer and not the route's. An operation still
    // scaffolded answers 501 for it, which is a different claim and not this refusal.
    for (operation, path, parameter) in UNLABELLED_ROUTES {
        for (case, value) in [
            ("the published minimum", MAX_RESULTS_MIN),
            ("the published maximum", MAX_RESULTS_MAX),
        ] {
            let (status, listed) =
                call(&router, "GET", &format!("{path}?{parameter}={value}"), None).await;
            assert!(
                status == 200 || status == 501,
                "case {case:?} ({operation} {parameter}={value}): a page size the model admits \
                 is served, got {status} {listed:?}"
            );
        }
    }
}

/// RULE, on the operation this suite's other cases page through: the page the caller asks for
/// holds at most `MaxResults` jobs, and the published bounds select that many of the stored
/// set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_published_page_size_bounds_select_the_stored_restore_jobs() {
    let (router, ids) = stored_restores().await;

    for (case, value, expected) in [
        ("the published minimum", MAX_RESULTS_MIN, 1),
        ("the published maximum", MAX_RESULTS_MAX, ids.len()),
    ] {
        let (status, listed) = list_restores(&router, &format!("maxResults={value}")).await;
        assert_eq!(
            status, 200,
            "case {case:?} (maxResults={value}): expected 200, got {status} {listed:?}"
        );
        assert_eq!(
            ids_of(&listed).len(),
            expected,
            "case {case:?} (maxResults={value}): expected {expected} job(s) on the page, got \
             {listed:?}"
        );
    }
}

/// RULE: a cursor this listing did not vend names no page of the result set, and is refused
/// as a parameter value; one it DID vend resumes the walk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cursor_the_listing_did_not_vend_is_refused() {
    let (router, ids) = stored_restores().await;

    // The cursor the listing vends for a page of one, which is the control: the same
    // parameter resumes the walk when its value is one of this result set's positions.
    let (status, first) = list_restores(&router, "maxResults=1").await;
    assert_eq!(
        status, 200,
        "setup: expected ListRestoreJobs 200, got {status} {first:?}"
    );
    let vended = string_at(&first, "NextToken");
    let (status, resumed) =
        list_restores(&router, &format!("maxResults=1&nextToken={vended}")).await;
    assert_eq!(
        (status, ids_of(&resumed).first().cloned()),
        (200, ids.get(1).cloned()),
        "a cursor this listing vended must resume at the next stored job, got {status} \
         {resumed:?}"
    );

    // The ways a cursor can name no position: not the form a cursor takes at all, the form
    // but decoding to no stored job id, and empty.
    for (case, token) in [
        ("not the form a cursor takes", "zzzz"),
        ("hex that decodes to no stored job id", "6e6f7065"),
        ("empty", ""),
    ] {
        let (status, refused) = list_restores(&router, &format!("nextToken={token}")).await;
        assert_eq!(
            (status, error_code(&refused).as_str()),
            (400, "InvalidParameterValueException"),
            "case {case:?} (nextToken={token:?}): expected the modelled refusal, got {status} \
             {refused:?}"
        );
        assert!(
            refused.get("RestoreJobs").is_none(),
            "case {case:?} (nextToken={token:?}): a refusal carries no page, got {refused:?}"
        );
    }
}

/// RULE: `ByRestoreTestingPlanArn` takes an ARN — a value that is not one is a parameter-value
/// refusal, and one that is selects only the jobs started from that plan.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_testing_plan_filter_that_is_not_an_arn_is_refused() {
    let (router, _ids) = stored_restores().await;

    // The ways a value can fail to be an ARN: no scheme, too few fields, an empty partition,
    // an empty service, an empty resource.
    for (case, value) in [
        ("no arn scheme", "not-an-arn".to_string()),
        ("too few fields", "arn:aws:backup".to_string()),
        (
            "an empty partition",
            format!("arn::backup:{REGION}:{ACCOUNT}:restore-testing-plan:plan"),
        ),
        (
            "an empty service",
            format!("arn:aws::{REGION}:{ACCOUNT}:restore-testing-plan:plan"),
        ),
        (
            "an empty resource",
            format!("arn:aws:backup:{REGION}:{ACCOUNT}:"),
        ),
    ] {
        let (status, refused) =
            list_restores(&router, &format!("restoreTestingPlanArn={value}")).await;
        assert_eq!(
            (status, error_code(&refused).as_str()),
            (400, "InvalidParameterValueException"),
            "case {case:?} ({value}): expected the modelled refusal, got {status} {refused:?}"
        );
    }

    // An ARN of a restore testing plan is served: nothing here was started from one, so the
    // page is empty rather than refused.
    let plan = format!("arn:aws:backup:{REGION}:{ACCOUNT}:restore-testing-plan:paging-plan");
    let (status, listed) = list_restores(&router, &format!("restoreTestingPlanArn={plan}")).await;
    assert_eq!(
        (status, ids_of(&listed).len()),
        (200, 0),
        "a well-formed plan ARN selects only the jobs started from it, got {status} {listed:?}"
    );
}
