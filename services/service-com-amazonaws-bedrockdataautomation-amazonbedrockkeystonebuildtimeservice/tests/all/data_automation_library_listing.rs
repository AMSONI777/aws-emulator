// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of `ListDataAutomationLibraries`.
//!
//! Every case drives the real `restJson1` wire path — `MultiServiceRouter::dispatch` with
//! a signed-looking request — so routing, HTTP binding, constraint validation, the handler
//! and response serialization are all exercised, exactly as an AWS SDK
//! `bedrock-data-automation` client would.
//!
//! RULE. A listing enumerates the libraries the store HOLDS, in this service's listing
//! order (`creationTime`, then ARN), one page at a time: `maxResults` caps the page, a
//! `nextToken` is handed back only while something is left after it and resumes exactly
//! after the last item served, and `projectFilter` narrows the listing to the libraries one
//! project's stored configuration references. Each item carries what the modelled
//! `DataAutomationLibrarySummary` declares
//! (`smithy_query(query="shape",shape="DataAutomationLibrarySummary")`: `libraryArn`,
//! `libraryName`, `creationTime`), read back out of the record the create persisted.
//!
//! The suites are TABLE-driven: the rows differ along the page size asked for, the number
//! of libraries stored, whether a filter is applied and what it names, and the form of a
//! resumption token — never over one recorded request. Beside the enumeration itself they
//! pin the modelled bounds on a request (`maxResults`' published range, `nextToken`'s
//! constraint and provenance) and that a listing REPORTS: it leaves a later caller the
//! same page.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Value};
use service_com_amazonaws_bedrockdataautomation_amazonbedrockkeystonebuildtimeservice::state;
use service_com_amazonaws_bedrockdataautomation_amazonbedrockkeystonebuildtimeservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

use crate::support::{encode_label, error_code, string_at, timestamp_at};

/// The region every case signs for.
const REGION: &str = "us-east-1";

/// A SigV4 `Authorization` header for this service's signing name (`bedrock`, per
/// `OPERATIONS.md`).
fn authorization() -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDTESTKEY/20240101/{REGION}/bedrock/aws4_request, \
         SignedHeaders=host, Signature=0123456789abcdef"
    )
}

fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(EmulatedService::new(engine));
    router
}

/// Dispatch one request and return its status and decoded JSON body.
async fn call(router: &MultiServiceRouter, method: &str, uri: &str, body: &Value) -> (u16, Value) {
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "bedrock-data-automation.amazonaws.com")
        .header("content-type", "application/json")
        .header("authorization", authorization())
        .body(Bytes::from(
            serde_json::to_vec(body).expect("serializable body"),
        ))
        .expect("a valid test request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let bytes = response.into_body();
    let decoded = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, decoded)
}

/// `CreateDataAutomationLibrary`, per its modelled `@http`
/// `{method: PUT, uri: /data-automation-libraries/, code: 201}`. Returns the ARN.
async fn create_library(router: &MultiServiceRouter, name: &str) -> String {
    let (status, payload) = call(
        router,
        "PUT",
        "/data-automation-libraries/",
        &json!({ "libraryName": name }),
    )
    .await;
    assert_eq!(
        status, 201,
        "case {name:?}: expected CreateDataAutomationLibrary 201, got {status} with \
         {payload:?}"
    );
    string_at(&payload, "libraryArn", name)
}

/// `ListDataAutomationLibraries`, per its modelled `@http`
/// `{method: POST, uri: /data-automation-libraries/}`.
async fn list_libraries(router: &MultiServiceRouter, body: &Value) -> (u16, Value) {
    call(router, "POST", "/data-automation-libraries/", body).await
}

/// The `libraryArn`s one page carries, in the order the page served them.
fn arns_of(page: &Value, case: &str) -> Vec<String> {
    page.get("libraries")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("case {case:?}: no libraries in {page:?}"))
        .iter()
        .map(|item| string_at(item, "libraryArn", case))
        .collect()
}

/// RULE: the listing enumerates every library the store holds, each item carrying the
/// members the summary declares, and an empty store answers an empty page with no token.
#[tokio::test]
async fn the_listing_reports_every_stored_library() {
    let router = emulator();

    let (status, empty) = list_libraries(&router, &json!({})).await;
    assert_eq!(
        status, 200,
        "case \"an empty store\": expected 200, got {status} with {empty:?}"
    );
    assert!(
        arns_of(&empty, "an empty store").is_empty(),
        "case \"an empty store\": expected no libraries, got {empty:?}"
    );
    assert!(
        empty.get("nextToken").is_none(),
        "case \"an empty store\": a last page carries no token, got {empty:?}"
    );

    // The rows differ along the COUNT stored, which is what the enumeration generalises
    // over: one library, then a second, then a third.
    let mut created: Vec<(String, String)> = Vec::new();
    for index in 0..3 {
        let name = format!("listing-library-{index}");
        let arn = create_library(&router, &name).await;
        created.push((name, arn));

        let case = format!("{} stored", created.len());
        let (status, page) = list_libraries(&router, &json!({})).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected 200, got {status} with {page:?}"
        );
        let listed = arns_of(&page, &case);
        let expected: Vec<String> = created.iter().map(|(_, arn)| arn.clone()).collect();
        assert_eq!(
            listed, expected,
            "case {case:?}: expected the stored libraries in creation order, got {listed:?}"
        );
        let items = page
            .get("libraries")
            .and_then(Value::as_array)
            .expect("the page carries libraries");
        for ((name, arn), item) in created.iter().zip(items) {
            assert_eq!(
                string_at(item, "libraryName", &case),
                *name,
                "case {case:?}: the summary names the library the create named"
            );
            assert_eq!(
                string_at(item, "libraryArn", &case),
                *arn,
                "case {case:?}: the summary carries the ARN the create minted"
            );
            assert!(
                item.get("creationTime").is_some(),
                "case {case:?}: the summary carries the creation instant, got {item:?}"
            );
        }
    }
}

/// RULE: `maxResults` caps the page and the `nextToken` resumes exactly after the last
/// item served, so walking the pages visits every library once, in order, whatever page
/// size is asked for.
#[tokio::test]
async fn paging_walks_every_library_once_whatever_the_page_size() {
    let router = emulator();
    let mut all: Vec<String> = Vec::new();
    for index in 0..5 {
        all.push(create_library(&router, &format!("paged-library-{index}")).await);
    }

    // (case, the page size asked for)
    let rows: [(&str, Option<i32>); 5] = [
        ("no page size, the server's own limit", None),
        ("one at a time", Some(1)),
        ("two at a time", Some(2)),
        ("exactly the stored count", Some(5)),
        ("more than the stored count", Some(50)),
    ];
    for (case, max_results) in rows {
        let mut walked: Vec<String> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut body = json!({});
            if let Some(max) = max_results {
                body["maxResults"] = json!(max);
            }
            if let Some(next) = &token {
                body["nextToken"] = json!(next);
            }
            let (status, page) = list_libraries(&router, &body).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected 200, got {status} with {page:?}"
            );
            let listed = arns_of(&page, case);
            if let Some(max) = max_results {
                assert!(
                    listed.len() <= max as usize,
                    "case {case:?}: a page served {} items, over the {max} asked for",
                    listed.len()
                );
            }
            walked.extend(listed);
            token = page
                .get("nextToken")
                .and_then(Value::as_str)
                .map(str::to_string);
            if token.is_none() {
                break;
            }
            assert!(
                walked.len() <= all.len(),
                "case {case:?}: paging served {} items for {} stored",
                walked.len(),
                all.len()
            );
        }
        assert_eq!(
            walked, all,
            "case {case:?}: expected every stored library once, in order, got {walked:?}"
        );
    }
}

/// RULE: `projectFilter` narrows the listing to the libraries ONE project's stored
/// configuration references — and because this operation models no not-found refusal, a
/// filter naming a project that holds no reference, or no project at all, narrows the
/// listing to nothing rather than being refused.
#[tokio::test]
async fn the_project_filter_narrows_the_listing_to_the_projects_libraries() {
    let router = emulator();
    let referenced = create_library(&router, "filtered-library").await;
    let unreferenced = create_library(&router, "other-library").await;

    let (status, project) = call(
        &router,
        "PUT",
        "/data-automation-projects/",
        &json!({
            "projectName": "library-filter-project",
            "standardOutputConfiguration": {},
            "dataAutomationLibraryConfiguration": {
                "libraries": [{ "libraryArn": referenced }],
            },
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "the fixture project must be created, got {status} with {project:?}"
    );
    let project_arn = string_at(&project, "projectArn", "fixture");
    let empty_project_arn = {
        let (status, other) = call(
            &router,
            "PUT",
            "/data-automation-projects/",
            &json!({
                "projectName": "library-filter-empty",
                "standardOutputConfiguration": {},
            }),
        )
        .await;
        assert_eq!(
            status, 201,
            "the second fixture project must be created, got {status} with {other:?}"
        );
        string_at(&other, "projectArn", "fixture")
    };

    // (case, the filter, the libraries the listing then serves)
    let rows: Vec<(&str, Value, Vec<String>)> = vec![
        (
            "no filter at all",
            json!({}),
            vec![referenced.clone(), unreferenced.clone()],
        ),
        (
            "a project that references one library",
            json!({ "projectFilter": { "projectArn": project_arn } }),
            vec![referenced.clone()],
        ),
        (
            "a project that references none",
            json!({ "projectFilter": { "projectArn": empty_project_arn } }),
            Vec::new(),
        ),
        (
            "a project this store does not hold",
            json!({
                "projectFilter": {
                    "projectArn": format!(
                        "arn:aws:bedrock:{REGION}:000000000000:data-automation-project/\
                         000000000000-0000000000000000"
                    ),
                },
            }),
            Vec::new(),
        ),
    ];
    for (case, body, expected) in rows {
        let (status, page) = list_libraries(&router, &body).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected 200, got {status} with {page:?}"
        );
        let listed = arns_of(&page, case);
        assert_eq!(
            listed, expected,
            "case {case:?}: expected {expected:?}, got {listed:?}"
        );
    }
}

/// RULE: `maxResults` is bounded by the range the model publishes for it, so a page size
/// at either published bound is served and one past a bound is refused with the modelled
/// `ValidationException` (HTTP 400) instead of a page.
///
/// The bounds come from the model, not from this suite:
/// `smithy_query(query="operation",operation="ListDataAutomationLibraries")` gives
/// `maxResults` `@range(min: 1, max: 1000)`, which is also what
/// `state::LIBRARY_PAGE_LIMIT` records.
#[tokio::test]
async fn the_page_size_is_bounded_by_the_modelled_range() {
    let router = emulator();
    const STORED: usize = 3;
    for index in 0..STORED {
        create_library(&router, &format!("bounded-library-{index}")).await;
    }

    let published_max = state::LIBRARY_PAGE_LIMIT;
    // (case, the maxResults asked for, the items a served page then carries)
    let accepted: [(&str, i32, usize); 3] = [
        ("the published minimum", 1, 1),
        ("inside the range", 2, 2),
        ("the published maximum", published_max, STORED),
    ];
    for (case, max_results, expected) in accepted {
        let (status, page) = list_libraries(&router, &json!({ "maxResults": max_results })).await;
        assert_eq!(
            status, 200,
            "case {case:?}: a page size inside the modelled range must be served, got \
             {status} with {page:?}"
        );
        let listed = arns_of(&page, case);
        assert_eq!(
            listed.len(),
            expected,
            "case {case:?}: expected {expected} item(s) on the page, got {listed:?}"
        );
    }

    // One past each published bound.
    let refused: [(&str, i32); 2] = [
        ("one below the published minimum", 0),
        ("one above the published maximum", published_max + 1),
    ];
    for (case, max_results) in refused {
        let (status, payload) = list_libraries(&router, &json!({ "maxResults": max_results })).await;
        assert_eq!(
            status, 400,
            "case {case:?}: a page size outside the modelled range must be refused, got \
             {status} with {payload:?}"
        );
        assert_eq!(
            error_code(&payload),
            "ValidationException",
            "case {case:?}: wrong error code in {payload:?}"
        );
        assert!(
            payload.get("libraries").is_none(),
            "case {case:?}: a refusal must not carry a page, got {payload:?}"
        );
    }
}

/// RULE: a listing resumes only from a `nextToken` this service itself issued, so a token
/// it did not mint — or one outside the modelled `NextToken` constraint (length 1..2048,
/// pattern `^\S*$`) — is refused with the modelled `ValidationException` (HTTP 400) and no
/// page.
#[tokio::test]
async fn a_next_token_this_service_did_not_issue_is_refused() {
    let router = emulator();
    create_library(&router, "token-library").await;

    // The rows differ along the FORM of the token: not base64 at all, base64 of bytes that
    // are not a cursor, base64 of a cursor whose ARN field is empty, a token carrying
    // whitespace (outside the modelled pattern) and one past the modelled maximum length.
    let over_long = "a".repeat(2_049);
    let rows: Vec<(&str, String)> = vec![
        ("not base64", "not-a-token-this-service-issued".to_string()),
        ("base64 of something that is not a cursor", "aGVsbG8=".to_string()),
        ("a cursor with no ARN", "MTIzOjQ1Njo=".to_string()),
        ("whitespace, outside the modelled pattern", "a token".to_string()),
        ("past the modelled maximum length", over_long),
    ];
    for (case, token) in rows {
        let (status, payload) = list_libraries(&router, &json!({ "nextToken": token })).await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected the modelled refusal, got {status} with {payload:?}"
        );
        assert_eq!(
            error_code(&payload),
            "ValidationException",
            "case {case:?}: wrong error code in {payload:?}"
        );
        assert!(
            payload.get("libraries").is_none(),
            "case {case:?}: a refusal must not carry a page, got {payload:?}"
        );
    }
}

/// RULE: the listing REPORTS — it changes nothing a later caller sees, and what it reports
/// is the record the create persisted, so each summary's `creationTime` is the instant
/// `GetDataAutomationLibrary` reports for that same library.
#[tokio::test]
async fn the_listing_reports_without_changing_what_a_later_caller_sees() {
    let router = emulator();
    let mut created: Vec<String> = Vec::new();
    for index in 0..3 {
        created.push(create_library(&router, &format!("reported-library-{index}")).await);
    }

    let (status, before) = list_libraries(&router, &json!({})).await;
    assert_eq!(
        status, 200,
        "the first listing must answer 200, got {status} with {before:?}"
    );

    // The rows differ along the page size the read in between uses: the whole listing in one
    // page, then a walk one item at a time, then two at a time.
    let walks: [(&str, i32); 3] = [
        ("a whole listing", 50),
        ("one item at a time", 1),
        ("two at a time", 2),
    ];
    for (case, max_results) in walks {
        let mut token: Option<String> = None;
        // One page per stored library is the most a walk can need before the page that
        // carries no token: a handler that reissued one token forever fails here rather than
        // spinning.
        let mut pages = 0usize;
        loop {
            let mut body = json!({ "maxResults": max_results });
            if let Some(next) = &token {
                body["nextToken"] = json!(next);
            }
            let (status, page) = list_libraries(&router, &body).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected 200, got {status} with {page:?}"
            );
            pages += 1;
            token = page
                .get("nextToken")
                .and_then(Value::as_str)
                .map(str::to_string);
            if token.is_none() {
                break;
            }
            assert!(
                pages <= created.len(),
                "case {case:?}: the walk served {pages} page(s) for {} stored libraries and \
                 is still handing back a token",
                created.len()
            );
        }

        let (status, after) = list_libraries(&router, &json!({})).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected 200, got {status} with {after:?}"
        );
        assert_eq!(
            after, before,
            "case {case:?}: reading the listing must leave a later caller the same page"
        );
    }

    for arn in &created {
        let case = format!("{arn} read back");
        let summary = before
            .get("libraries")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("case {case:?}: no libraries in {before:?}"))
            .iter()
            .find(|item| string_at(item, "libraryArn", &case) == *arn)
            .unwrap_or_else(|| panic!("case {case:?}: {arn} missing from {before:?}"))
            .clone();

        let uri = format!("/data-automation-libraries/{}/", encode_label(arn));
        let (status, read) = call(&router, "POST", &uri, &json!({})).await;
        assert_eq!(
            status, 200,
            "case {case:?}: GetDataAutomationLibrary must answer 200, got {status} with \
             {read:?}"
        );
        let library = read
            .get("library")
            .unwrap_or_else(|| panic!("case {case:?}: no library in {read:?}"));
        assert_eq!(
            timestamp_at(&summary, "creationTime", &case),
            timestamp_at(library, "creationTime", &case),
            "case {case:?}: the summary must report the persisted creation instant"
        );
        assert_eq!(
            string_at(&summary, "libraryName", &case),
            string_at(library, "libraryName", &case),
            "case {case:?}: the summary must report the persisted name"
        );
    }
}
