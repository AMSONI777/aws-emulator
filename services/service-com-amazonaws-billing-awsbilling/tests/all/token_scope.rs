// SPDX-License-Identifier: CC0-1.0

//! Which `nextToken` each paginated read of this service takes back, end to end
//! over the awsJson1_0 wire.
//!
//! Every assertion here is about ONE rule: a paginated read resumes a walk only
//! from a `nextToken` THAT READ issued, and refuses every other token — one this
//! service cannot read back at all, and one another of its reads minted — with
//! the modeled `ValidationException` instead of answering a page. A token is a
//! cut point in the sequence the read that minted it walks; fed to another read
//! it names some other entry of another sequence, or none, so honouring it would
//! answer a page that is wrong rather than report a bad request.
//!
//! The table spans every paginated read of this crate that mints a token
//! through the shared codec — the credit-allocation history, the billing-view
//! list, one view's source views, the Business Support account charges, the
//! Enterprise Support linked-account charges, the Business Support
//! subscription history and one billing view's segments — crossed with every
//! token source: each read's own
//! token, each OTHER read's token, and tokens no read ever minted. The two
//! Support charge reads are the sharpest rows: they page over the same spend
//! store, so their payloads are drawn from one key space and only the read named
//! in the token tells their cut points apart.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use service_com_amazonaws_billing_awsbilling::state::{
    BillingViewSegment, CreditAllocation, CreditAmount, SupportEligibleSpend, SupportServiceSpend,
    BILLING_DOMAIN_BILLABLE, SPEND_ITEM_TYPE_USAGE, SUPPORT_PLAN_BUSINESS, SUPPORT_PLAN_ENTERPRISE,
};
use service_com_amazonaws_billing_awsbilling::ComAmazonawsBillingAwsbillingState;
use service_common::page_tokens::AUTHENTICATOR_BYTES;
use smithy_server_runtime::MultiServiceRouter;

// The awsJson1_0 harness — a router over ONE shared engine, plus `call` and
// `error_code` — already exists for the billing-view lifecycle suite, so this
// module reuses it instead of building a second one.
use crate::billing_views::{
    call, emulator_with_engine, error_code, plant_source_views, ACCOUNT_ID, PRIMARY_ARN,
};
// The epoch-seconds helper the credit-allocation suite already carries, so the
// date ranges below need no second copy of it.
use crate::credit_allocation_history::at;
// The codec suite owns the one place a token is spelled by hand, and the one
// way a suite asks the store to mint one for a cut point a read would not
// offer from a page of its own.
use crate::page_token_codec::{
    cursor_without_its_authenticator, token_with_a_made_up_authenticator,
};
// The source-view ARN helper the disassociation suite already exposes.
use crate::source_view_disassociation::source_arn;

/// Further 12-digit accounts of the consolidated billing family, so each
/// Support read has more than one entry to page over.
const MEMBER_ACCOUNT_ID: &str = "111111111111";
const OTHER_MEMBER_ACCOUNT_ID: &str = "222222222222";
const THIRD_MEMBER_ACCOUNT_ID: &str = "333333333333";

/// A billing month far enough in the past that the clock cannot move it, so
/// every Support read answers for it whatever day the suite runs on.
const PAST_MONTH: &str = "2024-03";

/// The `message` every paginated read refuses an unusable `nextToken` with.
const PAGE_TOKEN_REFUSAL: &str = "nextToken is not a token this service issued";

/// The `ValidationExceptionReason` that refusal carries: the value for input the
/// service cannot read back (`cannotParse`).
const PAGE_TOKEN_REASON: &str = "cannotParse";

/// The two instants the seeded billing-view segments meet at, and the ends of
/// the period the segment read below asks about: two whole UTC months, so the
/// view's timeline holds two segments to page over.
const SEGMENTS_BEGIN: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z
const SEGMENTS_MIDDLE: i64 = 1_738_368_000; // 2025-02-01T00:00:00Z
const SEGMENTS_END: i64 = 1_740_787_200; // 2025-03-01T00:00:00Z

/// Epoch seconds as the instant the store holds.
fn instant(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).expect("a post-epoch instant"))
}

/// One segment of the caller's PRIMARY billing view, over the half-open period
/// `begin..end`.
fn segment(begin: i64, end: i64) -> BillingViewSegment {
    BillingViewSegment {
        begin_date_inclusive: Some(instant(begin)),
        end_date_exclusive: Some(instant(end)),
        ..BillingViewSegment::in_effect(PRIMARY_ARN, BILLING_DOMAIN_BILLABLE)
    }
}

/// One account-month of Support-eligible spend, under the Support plan the row
/// names.
fn spend(account_id: &str, support_plan_name: &str) -> SupportEligibleSpend {
    SupportEligibleSpend {
        account_id: account_id.to_string(),
        billing_month: PAST_MONTH.to_string(),
        support_plan_name: support_plan_name.to_string(),
        currency_code: "USD".to_string(),
        by_service: vec![SupportServiceSpend {
            contributing_service: "AmazonEC2".to_string(),
            item_type: SPEND_ITEM_TYPE_USAGE.to_string(),
            description: None,
            charge_amount_minor: 100_000,
        }],
        discount: None,
        reserved_instance_spend_minor: 0,
        savings_plan_spend_minor: 0,
        is_estimated_bill: false,
    }
}

/// One credit applied to the caller's bill for `billing_month`.
fn allocation(billing_month: &str) -> CreditAllocation {
    CreditAllocation {
        credit_id: "7".to_string(),
        credit_amount: CreditAmount {
            currency_code: "USD".to_string(),
            currency_amount: "12.34".to_string(),
        },
        description: None,
        account_id: ACCOUNT_ID.to_string(),
        applied_service_name: "Amazon Elastic Compute Cloud".to_string(),
        billing_month: billing_month.to_string(),
        is_estimated_bill: false,
    }
}

/// Put the records every read below pages over in the shared engine: the
/// consolidated billing family, one month of Support-eligible spend per account
/// (two under the Enterprise plan, two under the Business plan, so the
/// Enterprise report and the subscription history each have entries of their
/// own), and three months of credit allocations.
///
/// The emulator runs no billing pipeline, so these stores are empty on a fresh
/// emulator and the suites they belong to seed them the same way.
fn seed(engine: &Arc<engine::InMemoryEngine>) {
    let state = engine.state::<ComAmazonawsBillingAwsbillingState>();
    let mut state = state.lock();
    for account_id in [
        ACCOUNT_ID,
        MEMBER_ACCOUNT_ID,
        OTHER_MEMBER_ACCOUNT_ID,
        THIRD_MEMBER_ACCOUNT_ID,
    ] {
        state
            .consolidated_billing_family
            .insert(account_id.to_string(), "Linked Account".to_string());
    }
    for (account_id, plan) in [
        (ACCOUNT_ID, SUPPORT_PLAN_ENTERPRISE),
        (MEMBER_ACCOUNT_ID, SUPPORT_PLAN_ENTERPRISE),
        (OTHER_MEMBER_ACCOUNT_ID, SUPPORT_PLAN_BUSINESS),
        (THIRD_MEMBER_ACCOUNT_ID, SUPPORT_PLAN_BUSINESS),
    ] {
        assert!(
            state.record_support_eligible_spend(spend(account_id, plan)),
            "setup: the seeded spend of {account_id:?} must fit in the store"
        );
    }
    for billing_month in ["2025-01", "2025-02", "2025-03"] {
        assert!(
            state.record_credit_allocation(allocation(billing_month)),
            "setup: the seeded allocation of {billing_month:?} must fit in the store"
        );
    }
    for (begin, end) in [
        (SEGMENTS_BEGIN, SEGMENTS_MIDDLE),
        (SEGMENTS_MIDDLE, SEGMENTS_END),
    ] {
        assert!(
            state.record_billing_view_segment(segment(begin, end)),
            "setup: the seeded segment of {begin}..{end} must fit in the store"
        );
    }
}

/// Create one `CUSTOM` billing view holding three source views, so the
/// billing-view list has two views to page over and that view's source-view
/// list has three.
///
/// A create resolves every `sourceViews` entry against the store, so the views
/// those ARNs name are planted first, the way the billing-view suite plants
/// them.
async fn create_view(router: &MultiServiceRouter, engine: &Arc<engine::InMemoryEngine>) -> String {
    let sources = vec![
        source_arn("token-scope-a"),
        source_arn("token-scope-b"),
        source_arn("token-scope-c"),
    ];
    plant_source_views(engine, &sources);
    let (status, created) = call(
        router,
        "CreateBillingView",
        &json!({ "name": "token-scope", "sourceViews": sources }),
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: expected CreateBillingView to answer 200, got {status} {created:?}"
    );
    created["arn"]
        .as_str()
        .unwrap_or_else(|| panic!("setup: CreateBillingView must answer an arn, got {created:?}"))
        .to_string()
}

/// One paginated read: its operation name and the request members that select
/// its walk.
struct Read {
    operation: &'static str,
    base: Value,
}

/// Every paginated read of this crate that mints a `nextToken` through the
/// shared codec, each over a walk the seeded state gives at least two entries.
fn reads(view_arn: &str) -> Vec<Read> {
    vec![
        Read {
            operation: "GetCreditAllocationHistory",
            base: json!({
                "accountId": ACCOUNT_ID,
                "startDate": at(2025, 1, 1, 0),
                "endDate": at(2025, 4, 1, 0),
            }),
        },
        Read {
            operation: "ListBillingViews",
            base: json!({}),
        },
        Read {
            operation: "ListSourceViewsForBillingView",
            base: json!({ "arn": view_arn }),
        },
        Read {
            operation: "ListBusinessSupportAccountCharges",
            base: json!({ "billingMonth": PAST_MONTH }),
        },
        Read {
            operation: "ListEnterpriseSupportLinkedAccountCharges",
            base: json!({ "billingMonth": PAST_MONTH }),
        },
        Read {
            operation: "ListBusinessSupportSubscriptionHistory",
            base: json!({ "billingMonth": PAST_MONTH }),
        },
        Read {
            operation: "ListBillingViewSegments",
            base: json!({
                "arn": PRIMARY_ARN,
                "timeRange": {
                    "beginDateInclusive": SEGMENTS_BEGIN,
                    "endDateExclusive": SEGMENTS_END,
                },
            }),
        },
    ]
}

/// A reported value as the text that identifies it, whether the wire carries it
/// as a string or as a number.
fn text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToString::to_string)
}

/// The entries a read reports, as the one value that identifies each of them in
/// that read's own answer, in the order the read reports them.
fn entries(operation: &str, body: &Value) -> Vec<String> {
    let (list, identity): (&str, fn(&Value) -> String) = match operation {
        "GetCreditAllocationHistory" => ("creditAllocationHistoryList", |entry| {
            text(&entry["billingMonth"])
        }),
        "ListBillingViews" => ("billingViews", |entry| text(&entry["arn"])),
        "ListSourceViewsForBillingView" => ("sourceViews", text),
        "ListBusinessSupportAccountCharges" => ("accountCharges", |entry| {
            text(&entry["accountId"])
        }),
        "ListEnterpriseSupportLinkedAccountCharges" => ("linkedAccount", |entry| {
            text(&entry["accountId"])
        }),
        "ListBusinessSupportSubscriptionHistory" => ("subscriptionContracts", |entry| {
            text(&entry["accountId"])
        }),
        "ListBillingViewSegments" => ("items", |entry| {
            text(&entry["timeRange"]["beginDateInclusive"])
        }),
        other => panic!("case {other:?}: this suite knows no such read"),
    };
    body.get(list)
        .and_then(Value::as_array)
        .map(|listed| listed.iter().map(identity).collect())
        .unwrap_or_default()
}

/// Assert that `refused` is the refusal a paginated read answers an unusable
/// `nextToken` with: 400 `ValidationException`, the shared message and reason,
/// and a `fieldList` naming the member that carried the token.
fn assert_token_refusal(case: &str, status: u16, refused: &Value) {
    assert_eq!(
        (status, error_code(refused).as_str()),
        (400, "ValidationException"),
        "case {case:?}: expected 400 ValidationException, got {status} {refused:?}"
    );
    assert_eq!(
        refused["message"].as_str(),
        Some(PAGE_TOKEN_REFUSAL),
        "case {case:?}: expected the shared refusal message, got {refused:?}"
    );
    assert_eq!(
        refused["reason"].as_str(),
        Some(PAGE_TOKEN_REASON),
        "case {case:?}: expected the reason for input that cannot be read back, got {refused:?}"
    );
    assert_eq!(
        refused["fieldList"][0]["name"].as_str(),
        Some("nextToken"),
        "case {case:?}: expected the fieldList to name nextToken, got {refused:?}"
    );
}

/// The whole walk of `read`, and the token its first page of one entry carries.
async fn whole_walk_and_first_token(
    router: &MultiServiceRouter,
    read: &Read,
) -> (Vec<String>, String) {
    let case = read.operation;
    let (status, whole) = call(router, read.operation, &read.base).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected 200 for the unpaged walk, got {status} {whole:?}"
    );
    let every = entries(read.operation, &whole);
    assert!(
        every.len() >= 2,
        "setup {case:?}: the walk must hold at least two entries to page over, got {every:?}"
    );

    let mut request = read.base.clone();
    request["maxResults"] = json!(1);
    let (status, page) = call(router, read.operation, &request).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected 200 for a first page of one entry, got {status} {page:?}"
    );
    let token = page["nextToken"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("case {case:?}: a first page of one of many entries must carry a nextToken, got {page:?}")
        })
        .to_string();
    (every, token)
}

#[tokio::test]
async fn every_paginated_read_resumes_its_own_token() {
    let (router, engine) = emulator_with_engine();
    seed(&engine);
    let view_arn = create_view(&router, &engine).await;

    for read in reads(&view_arn) {
        let case = read.operation;
        let (every, token) = whole_walk_and_first_token(&router, &read).await;
        let mut request = read.base.clone();
        request["nextToken"] = json!(token);
        let (status, resumed) = call(&router, read.operation, &request).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected 200 for the read's own token, got {status} {resumed:?}"
        );
        assert_eq!(
            entries(read.operation, &resumed),
            every[1..].to_vec(),
            "case {case:?}: expected the entries after the first, got {resumed:?}"
        );
    }
}

#[tokio::test]
async fn a_token_another_read_issued_is_refused_rather_than_answered_with_a_page() {
    let (router, engine) = emulator_with_engine();
    seed(&engine);
    let view_arn = create_view(&router, &engine).await;
    let reads = reads(&view_arn);

    // What each read issues, collected first so every read can then be offered
    // every other read's token.
    let mut issued: Vec<(&'static str, String)> = Vec::new();
    for read in &reads {
        let (_, token) = whole_walk_and_first_token(&router, read).await;
        issued.push((read.operation, token));
    }

    for read in &reads {
        for (minted_by, token) in &issued {
            if *minted_by == read.operation {
                continue;
            }
            let case = format!("{} resuming a {minted_by} token", read.operation);
            let mut request = read.base.clone();
            request["nextToken"] = json!(token);
            let (status, refused) = call(&router, read.operation, &request).await;
            assert_token_refusal(&case, status, &refused);
        }
    }
}

/// The cut point inside the token `read`'s own first page carried, read out of
/// that token: the authenticator comes first and the cursor behind it names the
/// read and then its payload. A continuation token is opaque, not confidential,
/// so a caller can read its own cut point out of one — what it cannot do is
/// authenticate a cut point of its own, which is what the rows built from this
/// payload assert.
async fn minted_payload(router: &MultiServiceRouter, read: &Read) -> String {
    let case = read.operation;
    let (_, token) = whole_walk_and_first_token(router, read).await;
    let bytes = hex::decode(&token)
        .unwrap_or_else(|error| panic!("case {case:?}: expected a hex token, got {token:?} ({error})"));
    let cursor = bytes
        .get(AUTHENTICATOR_BYTES..)
        .map(<[u8]>::to_vec)
        .and_then(|cursor| String::from_utf8(cursor).ok())
        .unwrap_or_else(|| {
            panic!("case {case:?}: expected an authenticator and a text cursor, got {token:?}")
        });
    cursor
        .split_once('\u{0}')
        .map(|(_, payload)| payload.to_string())
        .unwrap_or_else(|| {
            panic!("case {case:?}: the cursor must name the read that minted it, got {cursor:?}")
        })
}

#[tokio::test]
async fn a_token_no_read_ever_issued_is_refused_by_every_paginated_read() {
    let (router, engine) = emulator_with_engine();
    seed(&engine);
    let view_arn = create_view(&router, &engine).await;

    // Each row is a `nextToken` inside the modeled `PageToken` pattern
    // (`^[-a-zA-Z0-9+=/_]+$`, so the boundary validator passes it through) that
    // this service never minted. The rows differ along how far they get: text
    // that is not hex, hex too short to carry an authenticator, a bare cut
    // point with no authenticator in front of it (a digit, an ARN, a store
    // key), a cut point of THIS very read behind an authenticator the caller
    // made up, and one naming a read that does not exist.
    let cases: Vec<(&str, String)> = vec![
        ("text that is not hex at all", "not-a-token".to_string()),
        (
            "hex too short to carry an authenticator",
            "ff".to_string(),
        ),
        (
            "hex one digit short of a whole byte",
            "30a".to_string(),
        ),
        (
            "hex of a single digit, with no authenticator in front of it",
            hex::encode("0"),
        ),
        (
            "hex of a billing-view ARN, a bare cut point",
            hex::encode(PRIMARY_ARN),
        ),
        (
            "hex of a spend store key, a bare cut point",
            hex::encode(format!("{PAST_MONTH}\u{1f}{MEMBER_ACCOUNT_ID}")),
        ),
        (
            "a cut point naming a read this service does not have",
            token_with_a_made_up_authenticator("ListNothingAtAll", "0"),
        ),
    ];

    for read in reads(&view_arn) {
        // The rows above are the same for every read; these two are about THIS
        // read, so a caller cannot get a page by naming the read it is calling:
        // the cursor of a page this read really issued with its authenticator
        // stripped off, and that same cursor behind an authenticator of the
        // caller's own making.
        let payload = minted_payload(&router, &read).await;
        let own_cases: Vec<(&str, String)> = vec![
            (
                "this read's own cut point with no authenticator in front of it",
                cursor_without_its_authenticator(read.operation, &payload),
            ),
            (
                "this read's own cut point behind an authenticator the caller made up",
                token_with_a_made_up_authenticator(read.operation, &payload),
            ),
            (
                "a cut point of this read the store never minted",
                token_with_a_made_up_authenticator(read.operation, "9999-99"),
            ),
        ];
        for (row, token) in cases.iter().chain(own_cases.iter()) {
            let case = format!("{}: {row}", read.operation);
            let mut request = read.base.clone();
            request["nextToken"] = json!(token);
            let (status, refused) = call(&router, read.operation, &request).await;
            assert_token_refusal(&case, status, &refused);
        }
    }
}

#[tokio::test]
async fn refusing_a_token_changes_nothing_a_later_caller_sees() {
    let (router, engine) = emulator_with_engine();
    seed(&engine);
    let view_arn = create_view(&router, &engine).await;

    for read in reads(&view_arn) {
        let case = read.operation;
        let (before, token) = whole_walk_and_first_token(&router, &read).await;

        let mut forged = read.base.clone();
        forged["nextToken"] = json!(hex::encode("0"));
        let (status, refused) = call(&router, read.operation, &forged).await;
        assert_token_refusal(&format!("{case}: a token no read issued"), status, &refused);

        // The refusal consumed no cut point: the read's own token still reports
        // exactly the entries after the first, and the unpaged walk is unchanged.
        let mut resumed = read.base.clone();
        resumed["nextToken"] = json!(token);
        let (status, after) = call(&router, read.operation, &resumed).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected 200 for the read's own token after a refusal, \
             got {status} {after:?}"
        );
        assert_eq!(
            entries(read.operation, &after),
            before[1..].to_vec(),
            "case {case:?}: expected the entries after the first, got {after:?}"
        );
        let (status, whole) = call(&router, read.operation, &read.base).await;
        assert_eq!(
            (status, entries(read.operation, &whole)),
            (200, before),
            "case {case:?}: the whole walk must be unchanged by a refused token, got {whole:?}"
        );
    }
}

/// `GetBillingPreferences` spells its own tokens in base64 rather than hex — a
/// `PreferenceKey` is long enough that hex would not fit the modeled `PageToken`
/// once the authenticator travels with it — so it is not a row of the table
/// above. The rule is the same one, and the only thing that can refuse a cut
/// point of its OWN walk that a caller assembled is the authenticator over it.
#[tokio::test]
async fn the_preference_read_refuses_a_cut_point_of_its_own_walk_a_caller_assembled() {
    let (router, engine) = emulator_with_engine();
    // The per-feature access gate the default state leaves closed for this
    // feature is opened the way the preference suite opens it: this test is
    // about the token, not the gate (which `billing_feature_access.rs` pins).
    engine
        .state::<ComAmazonawsBillingAwsbillingState>()
        .lock()
        .grant_feature_access("RI_SHARING");
    let (status, updated) = call(
        &router,
        "UpdateBillingPreferences",
        &json!({
            "feature": "RI_SHARING",
            "billingPreferencesPerKey": [
                { "key": "a", "value": "ENABLED" },
                { "key": "b", "value": "ENABLED" },
            ],
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: expected UpdateBillingPreferences to answer 200, got {status} {updated:?}"
    );

    let first = json!({ "features": ["RI_SHARING"], "maxResults": 1 });
    let (status, page) = call(&router, "GetBillingPreferences", &first).await;
    assert_eq!(
        status, 200,
        "case \"the first page\": expected 200, got {status} {page:?}"
    );
    let issued = page["nextToken"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("case \"the first page\": a page of one of two entries must carry a nextToken, got {page:?}")
        })
        .to_string();

    // The token this read issued resumes the walk at the next entry.
    let mut resumed = first.clone();
    resumed["nextToken"] = json!(issued.clone());
    let (status, after) = call(&router, "GetBillingPreferences", &resumed).await;
    assert_eq!(
        (status, after["billingPreferences"][0]["key"].as_str()),
        (200, Some("b")),
        "case \"its own token\": expected the entry after the first, got {status} {after:?}"
    );

    // The same cut point, behind an authenticator the caller made up: the
    // feature and the filter scope inside it are this very walk's, so only the
    // authenticator tells it from the token above.
    let bytes = ::aws_smithy_types::base64::decode(&issued)
        .unwrap_or_else(|error| panic!("case \"its own token\": expected base64, got {issued:?} ({error})"));
    let mut forged = first.clone();
    forged["nextToken"] = json!(::aws_smithy_types::base64::encode(
        crate::page_token_codec::bytes_with_a_made_up_authenticator(&bytes)
    ));
    let (status, refused) = call(&router, "GetBillingPreferences", &forged).await;
    assert_token_refusal(
        "GetBillingPreferences: its own cut point behind an authenticator the caller made up",
        status,
        &refused,
    );
}
