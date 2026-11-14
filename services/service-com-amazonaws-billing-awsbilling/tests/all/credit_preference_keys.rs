// SPDX-License-Identifier: CC0-1.0

//! The credit a `CREDIT_PREFERENCE_OPTIONS` preference key names, end to end over
//! the awsJson1_0 wire.
//!
//! One rule: a preference key that NAMES a resource is honoured only when that
//! resource is one the caller's consolidated billing family holds and the caller
//! may speak for. So the `{creditId}` of a `credit/{creditId}/{option}` key is
//! resolved against the credits this crate stores — the store `GetCredits`
//! reports from — exactly as an account-list key's trailing account is resolved
//! against the family: an id segment outside the modelled `CreditId` shape names
//! no credit at all and is refused 400 `ValidationException`, a credit the family
//! does not hold or the caller does not speak for is refused 403
//! `AccessDeniedException`, and either way nothing is written.
//!
//! The rows span what the rule generalises over: the id segment's shape (digits,
//! letters, a mix, empty, and each modelled length bound plus one past the
//! maximum), whether a credit is stored under it, which account of the family
//! owns that credit, whether the caller is the family's payer account, which
//! option the key carries (`status` and a sharing option) and how many keys one
//! request sends.
//!
//! The wire harness (`call`, `error_code`, `message`) and the credit builder are
//! the ones `billing_views.rs`, `rejection_fidelity.rs` and `credits.rs` own.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use service_com_amazonaws_billing_awsbilling::{
    ComAmazonawsBillingAwsbillingState, EmulatedService,
};
use smithy_server_runtime::MultiServiceRouter;

use crate::billing_views::{call, error_code, ACCOUNT_ID};
use crate::credits::{credit, seed};
use crate::rejection_fidelity::message;

/// The feature whose keys name one credit.
const FEATURE: &str = "CREDIT_PREFERENCE_OPTIONS";

/// A second, linked account of the same consolidated billing family — a 12-digit
/// id that is not the account every request here authenticates as.
const MEMBER_ACCOUNT_ID: &str = "210987654321";

/// The display name a seeded family member carries.
const MEMBER_NAME: &str = "Linked Account";

/// A 12-digit account id that is in no consolidated billing family this emulator
/// holds.
const OUTSIDE_ACCOUNT_ID: &str = "999999999999";

/// The shortest `CreditId` the model admits: `@length(min: 1)` over `^[0-9]+$`
/// (`smithy_query(query="shape", shape="CreditId")`).
const SHORTEST_CREDIT_ID: &str = "1";

/// A credit of the linked account of the family.
const MEMBER_CREDIT_ID: &str = "7";

/// A credit held by an account outside the family.
const OUTSIDE_CREDIT_ID: &str = "9";

/// The longest `CreditId` the model admits: `@length(max: 32)`.
const LONGEST_CREDIT_ID: &str = "12345678901234567890123456789012";

/// One character past that maximum, so the segment cannot be a `CreditId`.
const TOO_LONG_CREDIT_ID: &str = "123456789012345678901234567890123";

/// The credits the world under test holds, as `(creditId, owning account)`.
const SEEDED_CREDITS: &[(&str, &str)] = &[
    (SHORTEST_CREDIT_ID, ACCOUNT_ID),
    (MEMBER_CREDIT_ID, MEMBER_ACCOUNT_ID),
    (OUTSIDE_CREDIT_ID, OUTSIDE_ACCOUNT_ID),
    (LONGEST_CREDIT_ID, ACCOUNT_ID),
];

/// One router over ONE shared engine — what `core/router` builds in production,
/// so every call in a test observes the same state — holding the family and the
/// credits of [`SEEDED_CREDITS`].
///
/// Most of the credits an account holds are minted by AWS's billing systems
/// rather than by an API of this service, so the store is seeded the way those
/// systems would and then driven over the wire (the same seam `tests/all/credits.rs`
/// uses).
fn emulator() -> (MultiServiceRouter, Arc<engine::InMemoryEngine>) {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    {
        let state = engine.state::<ComAmazonawsBillingAwsbillingState>();
        state
            .lock()
            .consolidated_billing_family
            .insert(MEMBER_ACCOUNT_ID.to_string(), MEMBER_NAME.to_string());
    }
    seed(
        &engine,
        SEEDED_CREDITS
            .iter()
            .map(|(credit_id, account_id)| credit(credit_id, account_id))
            .collect(),
    );
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(EmulatedService::new(Arc::clone(&engine)));
    (router, engine)
}

/// `UpdateBillingPreferences` for `FEATURE` and one or more key/value pairs.
async fn update(router: &MultiServiceRouter, pairs: &[(&str, &str)]) -> (u16, Value) {
    let keys: Vec<Value> = pairs
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect();
    call(
        router,
        "UpdateBillingPreferences",
        &json!({ "feature": FEATURE, "billingPreferencesPerKey": keys }),
    )
    .await
}

/// The `(key, value)` pairs `GetBillingPreferences` reports for `FEATURE`.
async fn stored(router: &MultiServiceRouter) -> Vec<(String, String)> {
    let (status, body) = call(
        router,
        "GetBillingPreferences",
        &json!({ "features": [FEATURE] }),
    )
    .await;
    assert_eq!(status, 200, "the preference read must answer: {body:?}");
    body["billingPreferences"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let field = |name: &str| entry[name].as_str().unwrap_or_default().to_string();
            (field("key"), field("value"))
        })
        .collect()
}

/// The `creditId`s `GetCredits` reports for `account_id` over a period that
/// covers every seeded credit and stays inside the documented one-year lookback.
async fn reported_credits(router: &MultiServiceRouter, account_id: &str) -> Vec<String> {
    let start = SystemTime::now() - Duration::from_secs(90 * 24 * 60 * 60);
    let epoch = |at: SystemTime| {
        at.duration_since(UNIX_EPOCH)
            .expect("an instant after the epoch")
            .as_secs() as i64
    };
    let (status, body) = call(
        router,
        "GetCredits",
        &json!({
            "accountId": account_id,
            "startDate": epoch(start),
            "endDate": epoch(SystemTime::now()),
        }),
    )
    .await;
    assert_eq!(status, 200, "the credit read must answer: {body:?}");
    body["credits"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|entry| entry["creditId"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// One row of the key table: the id segment and option a key carries, and what
/// the rule answers for it.
struct Row {
    case: &'static str,
    credit_id: &'static str,
    option: &'static str,
    status: u16,
    code: &'static str,
}

/// The key a row sends.
fn key_of(row: &Row) -> String {
    format!("credit/{}/{}", row.credit_id, row.option)
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "a credit the caller owns, shortest modelled id",
            credit_id: SHORTEST_CREDIT_ID,
            option: "status",
            status: 200,
            code: "",
        },
        Row {
            case: "a sharing option of a credit the caller owns",
            credit_id: SHORTEST_CREDIT_ID,
            option: "sharing",
            status: 200,
            code: "",
        },
        Row {
            case: "a credit another account of the family owns",
            credit_id: MEMBER_CREDIT_ID,
            option: "status",
            status: 200,
            code: "",
        },
        Row {
            case: "a credit the caller owns, longest modelled id",
            credit_id: LONGEST_CREDIT_ID,
            option: "status",
            status: 200,
            code: "",
        },
        Row {
            case: "one character past the longest modelled id",
            credit_id: TOO_LONG_CREDIT_ID,
            option: "status",
            status: 400,
            code: "ValidationException",
        },
        Row {
            case: "a credit held by an account outside the family",
            credit_id: OUTSIDE_CREDIT_ID,
            option: "status",
            status: 403,
            code: "AccessDeniedException",
        },
        Row {
            case: "a sharing option of a credit outside the family",
            credit_id: OUTSIDE_CREDIT_ID,
            option: "sharing",
            status: 403,
            code: "AccessDeniedException",
        },
        Row {
            case: "an id no credit is held under",
            credit_id: "999",
            option: "status",
            status: 403,
            code: "AccessDeniedException",
        },
        Row {
            case: "a zero id no credit is held under",
            credit_id: "0",
            option: "status",
            status: 403,
            code: "AccessDeniedException",
        },
        Row {
            case: "an id of letters and dashes, which no CreditId matches",
            credit_id: "CR-ABC-123",
            option: "status",
            status: 400,
            code: "ValidationException",
        },
        Row {
            case: "an id mixing a digit and a letter",
            credit_id: "1a",
            option: "status",
            status: 400,
            code: "ValidationException",
        },
        Row {
            case: "an empty id segment",
            credit_id: "",
            option: "status",
            status: 400,
            code: "ValidationException",
        },
    ]
}

#[tokio::test]
async fn the_modelled_credit_id_bounds_are_what_the_key_admits() {
    // The lengths the rows above stand for, so a typo in one of the id constants
    // fails here instead of silently testing another case. Source: the modelled
    // `CreditId`, `@length(min: 1, max: 32)` over `^[0-9]+$`.
    for (case, id, expected) in [
        ("the shortest id", SHORTEST_CREDIT_ID, 1),
        ("the longest id", LONGEST_CREDIT_ID, 32),
        ("one past the longest id", TOO_LONG_CREDIT_ID, 33),
    ] {
        assert_eq!(
            id.len(),
            expected,
            "case {case:?}: expected a {expected}-character id, got {id:?}"
        );
    }
}

#[tokio::test]
async fn a_credit_key_is_honoured_only_for_a_credit_of_the_family() {
    for row in rows() {
        let (router, _engine) = emulator();
        let key = key_of(&row);
        let (status, body) = update(&router, &[(key.as_str(), "DISABLED")]).await;
        assert_eq!(
            status, row.status,
            "case {:?}: expected HTTP {} for key {key:?}, got {status} {body:?}",
            row.case, row.status
        );
        if row.status == 200 {
            assert_eq!(
                stored(&router).await,
                vec![(key.clone(), "DISABLED".to_string())],
                "case {:?}: expected the key read back, got {body:?}",
                row.case
            );
            continue;
        }
        assert_eq!(
            error_code(&body),
            row.code,
            "case {:?}: expected {}, got {body:?}",
            row.case,
            row.code
        );
        let stated = message(&body);
        let names = if row.status == 403 {
            row.credit_id.to_string()
        } else {
            key.clone()
        };
        assert!(
            stated.contains(&names),
            "case {:?}: expected the refusal to name {names:?}, got {stated:?}",
            row.case
        );
        assert_eq!(
            stored(&router).await,
            Vec::new(),
            "case {:?}: a refused key stores nothing, got {:?}",
            row.case,
            stored(&router).await
        );
    }
}

#[tokio::test]
async fn the_credit_a_key_names_is_the_one_the_credit_read_reports() {
    // The round trip the rule is about: the credit exists in the store that owns
    // it (`GetCredits`), so the key naming it is honoured and read back; the ids
    // that read does NOT report are refused.
    let (router, _engine) = emulator();
    let held = reported_credits(&router, ACCOUNT_ID).await;
    assert_eq!(
        held,
        vec![
            SHORTEST_CREDIT_ID.to_string(),
            LONGEST_CREDIT_ID.to_string()
        ],
        "case \"seeded credits\": expected the caller's own credits, got {held:?}"
    );

    for credit_id in &held {
        let key = format!("credit/{credit_id}/status");
        let (status, body) = update(&router, &[(key.as_str(), "ENABLED")]).await;
        assert_eq!(
            status, 200,
            "case {credit_id:?}: a credit the read reports is settable, got {status} {body:?}"
        );
    }
    let mut expected: Vec<(String, String)> = held
        .iter()
        .map(|credit_id| (format!("credit/{credit_id}/status"), "ENABLED".to_string()))
        .collect();
    expected.sort();
    assert_eq!(
        stored(&router).await,
        expected,
        "case \"round trip\": expected one preference per reported credit"
    );

    // An id that read reports for nobody: the request is refused and the stored
    // preferences are exactly what they were.
    let absent = format!("credit/{}/status", "123456");
    let (status, body) = update(&router, &[(absent.as_str(), "DISABLED")]).await;
    assert_eq!(
        (status, error_code(&body).as_str()),
        (403, "AccessDeniedException"),
        "case \"an unheld id\": expected the refusal, got {status} {body:?}"
    );
    assert_eq!(
        stored(&router).await,
        expected,
        "case \"an unheld id\": a refused key leaves every stored key unchanged"
    );
}

#[tokio::test]
async fn a_member_account_sets_only_the_credits_it_owns() {
    // The two halves of the documented sentence: a member account may set the key
    // "for credits they own", and only the management account may set it "for any
    // credit in the family". The rows are the same two credits read by a caller
    // that is the family's payer account and by one that is not.
    for payer in [ACCOUNT_ID, MEMBER_ACCOUNT_ID] {
        let (router, engine) = emulator();
        engine
            .state::<ComAmazonawsBillingAwsbillingState>()
            .lock()
            .billing_family_management_account_id = payer.to_string();
        for (credit_id, owner) in SEEDED_CREDITS {
            if *owner == OUTSIDE_ACCOUNT_ID {
                continue;
            }
            let key = format!("credit/{credit_id}/status");
            let (status, body) = update(&router, &[(key.as_str(), "ENABLED")]).await;
            // The caller is `ACCOUNT_ID`: its own credits always, and every
            // credit of the family while it is the payer account.
            let expected = if *owner == ACCOUNT_ID || payer == ACCOUNT_ID {
                200
            } else {
                403
            };
            assert_eq!(
                status, expected,
                "case \"credit {credit_id} with payer {payer}\": expected HTTP {expected}, \
                 got {status} {body:?}"
            );
            if expected == 403 {
                assert_eq!(
                    error_code(&body),
                    "AccessDeniedException",
                    "case \"credit {credit_id} with payer {payer}\": expected the modeled \
                     refusal, got {body:?}"
                );
                assert!(
                    message(&body).contains(ACCOUNT_ID),
                    "case \"credit {credit_id} with payer {payer}\": the refusal names the \
                     caller, got {:?}",
                    message(&body)
                );
            }
        }
    }
}

#[tokio::test]
async fn a_key_outside_the_documented_three_segment_form_is_refused() {
    // The key form the doc states is `credit/{creditId}/{option}`: a fourth
    // segment makes the key no key of this feature at all, whichever credit the
    // second segment names, so the whole request is refused and stores nothing.
    let (router, _engine) = emulator();
    let keys: Vec<String> = ["sharing/scope", "status/all"]
        .iter()
        .map(|option| format!("credit/{MEMBER_CREDIT_ID}/{option}"))
        .collect();
    for key in &keys {
        let (status, body) = update(&router, &[(key.as_str(), "ENABLED")]).await;
        assert_eq!(
            (status, error_code(&body).as_str()),
            (400, "ValidationException"),
            "case {key:?}: expected the modeled refusal, got {status} {body:?}"
        );
        assert_eq!(
            stored(&router).await,
            Vec::new(),
            "case {key:?}: a refused key stores nothing"
        );
    }
}

#[tokio::test]
async fn several_options_of_one_credit_share_its_lookup() {
    // A request carries several options of ONE credit, so the credit lookup is
    // made once for the whole request: all of them land for a credit the family
    // holds, and none of them for an id it does not.
    let (router, _engine) = emulator();
    let good: Vec<String> = ["status", "sharing"]
        .iter()
        .map(|option| format!("credit/{MEMBER_CREDIT_ID}/{option}"))
        .collect();
    let pairs: Vec<(&str, &str)> = good.iter().map(|key| (key.as_str(), "ENABLED")).collect();
    let (status, body) = update(&router, &pairs).await;
    assert_eq!(
        status, 200,
        "case \"two options of a family credit\": got {status} {body:?}"
    );
    let mut expected: Vec<(String, String)> = good
        .iter()
        .map(|key| (key.clone(), "ENABLED".to_string()))
        .collect();
    expected.sort();
    assert_eq!(
        stored(&router).await,
        expected,
        "case \"two options of a family credit\": expected both options stored"
    );

    let absent: Vec<String> = ["status", "sharing"]
        .iter()
        .map(|option| format!("credit/4242/{option}"))
        .collect();
    let pairs: Vec<(&str, &str)> = absent.iter().map(|key| (key.as_str(), "ENABLED")).collect();
    let (status, body) = update(&router, &pairs).await;
    assert_eq!(
        (status, error_code(&body).as_str()),
        (403, "AccessDeniedException"),
        "case \"two options of an unheld credit\": expected the refusal, got {status} {body:?}"
    );
    assert_eq!(
        stored(&router).await,
        expected,
        "case \"two options of an unheld credit\": a refused request stores nothing"
    );
}
