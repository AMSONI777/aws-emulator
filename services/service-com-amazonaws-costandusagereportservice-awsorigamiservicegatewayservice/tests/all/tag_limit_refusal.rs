// SPDX-License-Identifier: CC0-1.0

//! The per-report tag-limit refusal, through the TWO operations that attach tags.
//!
//! Rule: a request that would leave one report definition holding more than the modelled
//! per-report maximum of 50 tags ("You can add up to 50 tags to a report definition", the
//! modelled `Tag` doc, `smithy_query(shape="Tag")`) is refused with a 400
//! `ValidationException` whose message names the member, that limit and the count that
//! crossed it — the same sentence whichever operation attached the tags, because both
//! answer it from the one constructor in `crate::state`.
//!
//! The rows differ in which operation refuses (`PutReportDefinition`, which takes tags
//! beside a definition being created, and `TagResource`, which merges them onto a report
//! the account already holds), in how far past the limit the request goes, and — for the
//! merge path — in how the count splits between keys the report already holds and fresh
//! keys the request adds.

use serde_json::{json, Value};

use super::report_definition_lifecycle::{error_code, minimal_definition, Cur};

/// The per-report tag maximum, from the modelled `Tag` doc quoted in the module header.
const LIMIT: usize = 50;

/// The clause of the refusal that is the same for every path and every count: the member
/// it is about and the limit that was crossed.
fn shared_prefix() -> String {
    format!("Tags: a report definition can hold at most {LIMIT} tags; ")
}

/// The `message` member of an error body, under either spelling: the model names the
/// member `Message`, and the JSON protocols render an error message member lowercase.
fn error_message(body: &Value) -> String {
    ["Message", "message"]
        .into_iter()
        .find_map(|key| body.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// `count` tags whose keys all differ, prefixed so two sets can be made disjoint.
fn tags(prefix: &str, count: usize) -> Value {
    Value::Array(
        (0..count)
            .map(|index| json!({ "Key": format!("{prefix}-{index}"), "Value": "v" }))
            .collect(),
    )
}

#[tokio::test]
async fn the_create_path_refuses_tags_past_the_per_report_limit() {
    // How many distinct keys the creation supplies. Every row is within the modelled
    // `TagList` 0..200 request bound (`smithy_query(shape="TagList")`), so each reaches
    // the handler and is refused for the per-REPORT limit rather than by the request
    // constraint.
    for supplied in [LIMIT + 1, LIMIT + 2, 100, 200] {
        let case = format!("PutReportDefinition supplying {supplied} tags");
        let cur = Cur::new();
        let (status, body) = cur
            .put(&minimal_definition("bounded-report"), Some(&tags("new", supplied)))
            .await;

        assert_eq!(
            status, 400,
            "case {case:?}: expected HTTP 400, got {status} {body:?}"
        );
        assert_eq!(
            error_code(&body),
            "ValidationException",
            "case {case:?}: expected ValidationException, got {:?}",
            error_code(&body)
        );
        let expected = format!("{}the request supplies {supplied}.", shared_prefix());
        let actual = error_message(&body);
        assert_eq!(
            actual, expected,
            "case {case:?}: expected {expected:?}, got {actual:?}"
        );

        // The refusal is whole: no report was stored.
        let stored = cur.describe_all().await;
        assert!(
            stored.is_empty(),
            "case {case:?}: a refused creation must store nothing, got {stored:?}"
        );
    }
}

#[tokio::test]
async fn the_merge_path_refuses_tags_past_the_per_report_limit() {
    // case, keys the report already holds, fresh keys the request adds. The count the
    // refusal names is the key set the report would be LEFT holding, which is the two
    // added together because the two key sets are disjoint.
    let table: Vec<(&str, usize, usize)> = vec![
        ("a full report gaining one fresh key", LIMIT, 1),
        ("a full report gaining many fresh keys", LIMIT, 20),
        ("an empty report tagged one key past the limit", 0, LIMIT + 1),
        ("a part-full report tagged one key too many", 30, 21),
        ("a part-full report tagged far past the limit", 30, 150),
    ];

    for (case, held, fresh) in table {
        let cur = Cur::new();
        let (status, body) = cur
            .put(&minimal_definition("bounded-report"), Some(&tags("held", held)))
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the report TagResource tags must exist first, got {status} {body:?}"
        );

        let (status, body) = cur
            .call(
                "TagResource",
                &json!({ "ReportName": "bounded-report", "Tags": tags("fresh", fresh) }),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected HTTP 400, got {status} {body:?}"
        );
        assert_eq!(
            error_code(&body),
            "ValidationException",
            "case {case:?}: expected ValidationException, got {:?}",
            error_code(&body)
        );
        let expected = format!(
            "{}the request would leave it holding {}.",
            shared_prefix(),
            held + fresh
        );
        let actual = error_message(&body);
        assert_eq!(
            actual, expected,
            "case {case:?}: expected {expected:?}, got {actual:?}"
        );

        // The refusal is whole: the report still holds exactly the tags it had.
        let (status, listed) = cur.tags_of("bounded-report").await;
        assert_eq!(
            status, 200,
            "case {case:?}: ListTagsForResource got {status} {listed:?}"
        );
        let attached = listed["Tags"].as_array().map_or(0, Vec::len);
        assert_eq!(
            attached, held,
            "case {case:?}: expected the stored tag set untouched at {held} tags, got {listed:?}"
        );
    }
}

#[tokio::test]
async fn both_paths_state_the_limit_the_same_way() {
    // The rule lives in one place, so the clause naming the member and the limit is
    // byte-identical whichever operation refused: a drift in either copy fails here.
    let cur = Cur::new();
    let (status, created) = cur
        .put(
            &minimal_definition("bounded-report"),
            Some(&tags("new", LIMIT + 1)),
        )
        .await;
    assert_eq!(
        status, 400,
        "the creation past the limit must be refused, got {status} {created:?}"
    );

    let cur = Cur::new();
    let (status, body) = cur
        .put(&minimal_definition("bounded-report"), Some(&tags("held", LIMIT)))
        .await;
    assert_eq!(
        status, 200,
        "the report TagResource tags must exist first, got {status} {body:?}"
    );
    let (status, merged) = cur
        .call(
            "TagResource",
            &json!({ "ReportName": "bounded-report", "Tags": tags("fresh", 1) }),
        )
        .await;
    assert_eq!(
        status, 400,
        "the merge past the limit must be refused, got {status} {merged:?}"
    );

    let prefix = shared_prefix();
    for (path, body) in [("PutReportDefinition", created), ("TagResource", merged)] {
        let actual = error_message(&body);
        assert!(
            actual.starts_with(&prefix),
            "path {path:?}: expected the refusal to open with {prefix:?}, got {actual:?}"
        );
        assert!(
            actual.ends_with(&format!("{}.", LIMIT + 1)),
            "path {path:?}: expected the refusal to name the resulting count {}, got {actual:?}",
            LIMIT + 1
        );
    }
}
