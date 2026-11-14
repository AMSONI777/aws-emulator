// SPDX-License-Identifier: CC0-1.0

//! The billing views a request names as SOURCES must exist, end to end over the
//! awsJson1_0 wire.
//!
//! One rule: a billing view draws its data from OTHER billing views, so every
//! ARN a request names in `sourceViews` must identify a billing view this
//! service holds — for the create that mints a view over them exactly as for
//! the association that adds one later — and a request naming an ARN no view
//! answers to is refused with the modeled `ResourceNotFoundException` (404)
//! with no record left behind. So no read can report a source view the same
//! store answers 404 for, and no `sourceViewCount` counts one.
//!
//! Sources (the model, not a recording):
//! `smithy_query(query="operation", operation="CreateBillingView")` —
//! `sourceViews` (`BillingViewSourceViewsList`, len 1..10) is the operation's
//! only ARN-bearing input member, and the operation declares
//! `ResourceNotFoundException`: "The specified ARN in the request doesn't
//! exist."
//!
//! The rows differ along everything the rule generalises over: how many sources
//! the request names (one, three, the modeled maximum of ten), where in the
//! list the unresolvable entry sits (first, middle, last), the FORM of the ARN
//! that resolves to nothing (one never created, one deleted since, a nested
//! resource id, one in another account), and which writer of the field was
//! asked.
//!
//! The harness (`call`, `emulator_with_engine`, `plant_source_views`, …) is the
//! one `billing_views.rs` owns.

use serde_json::{json, Value};

use crate::billing_views::{
    call, emulator_with_engine, error_code, plant_source_views, ABSENT_ARN, ACCOUNT_ID, PRIMARY_ARN,
};
use crate::rejection_fidelity::message;

/// A pattern-valid `BillingViewArn` of `account` for the resource id `view_id`.
fn view_arn(account: &str, view_id: &str) -> String {
    format!("arn:aws:billing::{account}:billingview/{view_id}")
}

/// The source views the rows draw from that the store really holds: as many as
/// the modeled `BillingViewSourceViewsList` maximum, so a row can fill a whole
/// request with resolvable sources but one.
fn held_sources() -> Vec<String> {
    (0..10)
        .map(|index| view_arn(ACCOUNT_ID, &format!("held-source-{index}")))
        .collect()
}

/// One row: the `sourceViews` a request names, and the single entry in it no
/// billing view answers to.
struct Row {
    case: String,
    sources: Vec<String>,
    missing: String,
}

/// The rows, given the ARN of a view that was created and then deleted (an ARN
/// the store answered for once and answers for no longer).
fn rows(deleted: &str) -> Vec<Row> {
    let held = held_sources();
    let mut ten_with_one_missing = held[..9].to_vec();
    ten_with_one_missing.push(ABSENT_ARN.to_string());

    let cases: Vec<(String, Vec<String>, String)> = vec![
        (
            "the only source, never created".to_string(),
            vec![ABSENT_ARN.to_string()],
            ABSENT_ARN.to_string(),
        ),
        (
            "the first of three".to_string(),
            vec![ABSENT_ARN.to_string(), held[0].clone(), held[1].clone()],
            ABSENT_ARN.to_string(),
        ),
        (
            "the middle of three".to_string(),
            vec![held[0].clone(), ABSENT_ARN.to_string(), held[1].clone()],
            ABSENT_ARN.to_string(),
        ),
        (
            "the last of three".to_string(),
            vec![held[0].clone(), held[1].clone(), ABSENT_ARN.to_string()],
            ABSENT_ARN.to_string(),
        ),
        (
            "one of ten, the modeled maximum".to_string(),
            ten_with_one_missing,
            ABSENT_ARN.to_string(),
        ),
        (
            "a source deleted since it was created".to_string(),
            vec![held[0].clone(), deleted.to_string()],
            deleted.to_string(),
        ),
        (
            "a nested resource id no view carries".to_string(),
            vec![view_arn(ACCOUNT_ID, "never/created")],
            view_arn(ACCOUNT_ID, "never/created"),
        ),
        (
            "a source in another account the store does not hold".to_string(),
            vec![held[0].clone(), view_arn("111122223333", "primary")],
            view_arn("111122223333", "primary"),
        ),
    ];

    cases
        .into_iter()
        .map(|(case, sources, missing)| Row {
            case,
            sources,
            missing,
        })
        .collect()
}

/// Every billing-view ARN `ListBillingViews` reports, in the order it reports
/// them: the store as a caller can see it.
async fn listed_arns(router: &smithy_server_runtime::MultiServiceRouter, case: &str) -> Vec<String> {
    let (status, listed) = call(router, "ListBillingViews", &json!({ "maxResults": 100 })).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected ListBillingViews to answer 200, got {status} {listed:?}"
    );
    listed["billingViews"]
        .as_array()
        .unwrap_or_else(|| panic!("case {case:?}: billingViews is a list, got {listed:?}"))
        .iter()
        .map(|view| view["arn"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The `sourceViews` an answer carries; an omitted list and `[]` mean the same.
fn source_views(body: &Value) -> Vec<String> {
    body.get("sourceViews")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| entry.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// A world holding the rows' resolvable source views, plus one `CUSTOM` view
/// that was created and deleted again, so a row can name an ARN that resolved
/// once and resolves no longer.
async fn world() -> (smithy_server_runtime::MultiServiceRouter, String) {
    let (router, engine) = emulator_with_engine();
    plant_source_views(&engine, &held_sources());

    let (status, created) = call(
        &router,
        "CreateBillingView",
        &json!({
            "name": "deleted-since",
            "sourceViews": [PRIMARY_ARN],
            "clientToken": "deleted-since",
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: expected the view that is deleted next to be created, got {status} {created:?}"
    );
    let deleted = created["arn"]
        .as_str()
        .unwrap_or_else(|| panic!("setup: CreateBillingView must answer an arn, got {created:?}"))
        .to_string();
    let (status, body) = call(&router, "DeleteBillingView", &json!({ "arn": deleted })).await;
    assert_eq!(
        status, 200,
        "setup: expected the delete to answer 200, got {status} {body:?}"
    );

    (router, deleted)
}

#[tokio::test]
async fn a_create_naming_a_source_no_view_is_stored_under_is_refused_and_stores_nothing() {
    let (router, deleted) = world().await;

    for (index, row) in rows(&deleted).iter().enumerate() {
        let case = &row.case;
        let before = listed_arns(&router, case).await;

        let (status, refused) = call(
            &router,
            "CreateBillingView",
            &json!({
                "name": format!("dangling-{index}"),
                "sourceViews": row.sources,
                "clientToken": format!("dangling-{index}"),
            }),
        )
        .await;
        assert_eq!(
            (status, error_code(&refused).as_str()),
            (404, "ResourceNotFoundException"),
            "case {case:?}: expected 404 ResourceNotFoundException for {:?}, got {status} \
             {refused:?}",
            row.missing
        );
        assert_eq!(
            message(&refused),
            format!("sourceViews: billing view {} does not exist", row.missing),
            "case {case:?}: the refusal must name the member and the unresolvable ARN, got {:?}",
            message(&refused)
        );
        assert_eq!(
            refused["resourceId"].as_str(),
            Some(row.missing.as_str()),
            "case {case:?}: expected the unresolvable ARN as resourceId, got {:?}",
            refused["resourceId"]
        );
        assert_eq!(
            refused["resourceType"].as_str(),
            Some("billingview"),
            "case {case:?}: expected the billing-view resource type, got {:?}",
            refused["resourceType"]
        );

        let after = listed_arns(&router, case).await;
        assert_eq!(
            after, before,
            "case {case:?}: a refused create must store no view, got {after:?}"
        );
    }
}

#[tokio::test]
async fn both_writers_of_the_field_refuse_the_same_unresolvable_source_the_same_way() {
    // The create that mints a view over its sources and the association that
    // adds one later are the two writers of the same stored field, so the same
    // unresolvable ARN draws the same answer from both — the inconsistency the
    // rule forbids is one of them accepting what the other refuses.
    let (router, deleted) = world().await;
    let held = held_sources();

    let (status, created) = call(
        &router,
        "CreateBillingView",
        &json!({
            "name": "association-target",
            "sourceViews": [held[0].clone()],
            "clientToken": "association-target",
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: expected the target view to be created, got {status} {created:?}"
    );
    let target = created["arn"].as_str().unwrap_or_default().to_string();

    for row in rows(&deleted) {
        let case = &row.case;
        let (create_status, create_body) = call(
            &router,
            "CreateBillingView",
            &json!({ "name": "pair-create", "sourceViews": row.sources }),
        )
        .await;
        let (associate_status, associate_body) = call(
            &router,
            "AssociateSourceViews",
            &json!({ "arn": target, "sourceViews": row.sources }),
        )
        .await;

        assert_eq!(
            (
                create_status,
                error_code(&create_body),
                message(&create_body)
            ),
            (
                associate_status,
                error_code(&associate_body),
                message(&associate_body)
            ),
            "case {case:?}: both writers of sourceViews must answer alike, got \
             {create_status} {create_body:?} and {associate_status} {associate_body:?}"
        );
        assert_eq!(
            create_status, 404,
            "case {case:?}: expected both to refuse with 404, got {create_status} {create_body:?}"
        );

        // The refused association left the target's stored set alone.
        let (status, listed) =
            call(&router, "ListSourceViewsForBillingView", &json!({ "arn": target })).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected the target's sources to be listed, got {status} {listed:?}"
        );
        assert_eq!(
            source_views(&listed),
            vec![held[0].clone()],
            "case {case:?}: a refused association changes nothing, got {listed:?}"
        );
    }
}

#[tokio::test]
async fn every_source_a_created_view_reports_resolves_through_the_reads() {
    // The control, and the invariant the rule exists for: over source counts
    // from the modeled minimum of 1 to its maximum of 10, a create is served
    // and every ARN the view then reports as a source is a view the same store
    // answers for, with `sourceViewCount` counting exactly those.
    let (router, _deleted) = world().await;
    let held = held_sources();

    for count in 1..=held.len() {
        let case = format!("{count} source views the store holds");
        let sources = held[..count].to_vec();
        let (status, created) = call(
            &router,
            "CreateBillingView",
            &json!({
                "name": format!("resolvable-{count}"),
                "sourceViews": sources,
                "clientToken": format!("resolvable-{count}"),
            }),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected CreateBillingView to answer 200, got {status} {created:?}"
        );
        let arn = created["arn"].as_str().unwrap_or_default().to_string();

        let (status, listed) =
            call(&router, "ListSourceViewsForBillingView", &json!({ "arn": arn })).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected the sources to be listed, got {status} {listed:?}"
        );
        let reported = source_views(&listed);
        assert_eq!(
            reported, sources,
            "case {case:?}: expected the stored sources, got {reported:?}"
        );

        let (status, got) = call(&router, "GetBillingView", &json!({ "arn": arn })).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected GetBillingView to answer 200, got {status} {got:?}"
        );
        assert_eq!(
            got["billingView"]["sourceViewCount"].as_u64(),
            Some(count as u64),
            "case {case:?}: sourceViewCount must count the stored sources, got {:?}",
            got["billingView"]["sourceViewCount"]
        );

        for source in &reported {
            let (status, resolved) = call(&router, "GetBillingView", &json!({ "arn": source })).await;
            assert_eq!(
                status, 200,
                "case {case:?}: the source {source} a read reports must resolve, got {status} \
                 {resolved:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_refused_create_leaves_its_client_token_free() {
    // The refusal is decided before anything is minted, so the idempotency
    // token the refused request carried names no view: the same token with
    // sources the store holds creates one, and only then is a replay of it the
    // first call's answer.
    let (router, _deleted) = world().await;
    let held = held_sources();
    let token = "token-reused-after-the-refusal";

    let (status, refused) = call(
        &router,
        "CreateBillingView",
        &json!({
            "name": "refused-then-created",
            "sourceViews": [ABSENT_ARN],
            "clientToken": token,
        }),
    )
    .await;
    assert_eq!(
        (status, error_code(&refused).as_str()),
        (404, "ResourceNotFoundException"),
        "case \"refused\": expected 404 ResourceNotFoundException, got {status} {refused:?}"
    );

    let body = json!({
        "name": "refused-then-created",
        "sourceViews": [held[0].clone()],
        "clientToken": token,
    });
    let (status, created) = call(&router, "CreateBillingView", &body).await;
    assert_eq!(
        status, 200,
        "case \"the token again, with sources the store holds\": expected 200, got {status} \
         {created:?}"
    );
    let arn = created["arn"].as_str().unwrap_or_default().to_string();
    assert!(
        !arn.is_empty(),
        "case \"the token again, with sources the store holds\": expected a minted ARN, got \
         {created:?}"
    );

    let (status, replayed) = call(&router, "CreateBillingView", &body).await;
    assert_eq!(status, 200, "case \"replay\": expected 200, got {replayed:?}");
    assert_eq!(
        replayed["arn"].as_str(),
        Some(arn.as_str()),
        "case \"replay\": an idempotent replay answers the first ARN, got {:?}",
        replayed["arn"]
    );
}
