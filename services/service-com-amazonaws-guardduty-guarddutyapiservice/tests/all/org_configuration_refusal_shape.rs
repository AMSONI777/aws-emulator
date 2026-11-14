// SPDX-License-Identifier: CC0-1.0

//! The ONE answer each single-rule organization-configuration operation gives a caller
//! that does not hold the delegated-administrator standing, end to end over the wire.
//!
//! Every request goes through [`smithy_server_runtime::MultiServiceRouter::dispatch`]
//! (the harness lives in the `detector_lifecycle` suite), so routing, restJson1
//! (de)serialization, modelled-constraint validation and the handlers are exercised
//! together.
//!
//! The rules under test, each asserted over a SET of inputs rather than one call:
//!
//! 1. An operation "available only to the delegated administrator account"
//!    (`smithy_query(query="doc",shape="CreateCustomDetectionRuleOrgConfiguration")`)
//!    refuses a caller without that standing with ONE fixed answer: HTTP 400, the
//!    `AccessDeniedException` shape in `x-amzn-errortype`, the `InvalidInputException`
//!    class in both the body's `__type` and its own `type` member, and the fixed
//!    authorization sentence — and NOTHING else in the body. The whole answer is
//!    compared, so no part of the request (the rule id, the mode, the account ids, the
//!    client token) and no part of the store can be interpolated into it. The rows
//!    differ along the operation, the `AssociationMode`, the Region the request is
//!    signed for, whether the rule id is one the catalogue publishes, and why the
//!    standing is absent.
//! 2. The refusal comes BEFORE anything the request names is resolved and before
//!    anything is written: over one store, a refused create carrying a `ClientToken`, a
//!    refused read, a refused update and a refused delete leave the pair unconfigured
//!    and the token unrecorded, so once the standing is established the create records
//!    the pair for the first time and the read reports exactly the scope IT carried.
//! 3. The complement: with the standing in place each of the four is answered by its
//!    own contract, in either mode.
//!
//! The delegated-administrator gate over the whole family, including the listing, and
//! the standings the clock settles live in the `org_configuration_authorization` suite;
//! this one pins the refusal's wire ANSWER and the fact that nothing of a refused call
//! survives it.

use serde_json::{json, Value};

use crate::detector_lifecycle::{
    as_delegated_admin, call_in, error_code, error_shape, new_router, published_rule_ids, Router,
};
// The path, the modes, the refusal's class, shape and sentence, the account ids and the
// standings are the `org_configuration_authorization` suite's, reused rather than
// re-declared: one definition of each, so the two suites cannot come to disagree about
// what the refusal is. `ACCOUNTS[0]` is the scope an AUTHORIZED create records below
// and `ACCOUNTS[1]` the one a REFUSED call tries to, so a refused write that landed
// would be visible in the read.
use crate::org_configuration_authorization::{
    establish, Standing, ACCESS_DENIED, ACCOUNTS, INVALID_INPUT, MODES, NOT_AUTHORIZED,
    ORG_CONFIGURATION_PATH,
};

/// The Regions the rows are signed for: the refusal is the same answer at every
/// endpoint, so one row per partition of the store.
const REGIONS: [&str; 3] = ["us-east-1", "eu-west-1", "ap-southeast-2"];

/// A `RuleId` the catalogue does not publish, well formed for the member
/// (`len 1..100`, `^[a-z0-9]+(-[a-z0-9]+)*$` —
/// `smithy_query(operation="GetCustomDetectionRuleOrgConfiguration")`), so it reaches
/// the handler rather than being refused at the request boundary.
const UNPUBLISHED_RULE_ID: &str = "no-such-published-rule-7";

/// A `ClientToken` the refused create carries, so rule 2 can show the refusal left no
/// idempotency record behind either.
const CLIENT_TOKEN: &str = "refused-create-token";

// ---------------------------------------------------------------------------
// The four operations that address ONE rule's organization configuration.
// ---------------------------------------------------------------------------

/// One operation, as a request this suite can send for a given rule and mode.
struct Operation {
    name: &'static str,
    method: &'static str,
    /// The path, given the rule and the mode the case is about.
    path: fn(&str, &str) -> String,
    /// The body, or `None` for the operations that carry none.
    body: fn(&str, &str) -> Option<Value>,
    /// What the DELEGATED ADMINISTRATOR is answered on a store where the rule has no
    /// organization configuration: the create records one (200) and the three that
    /// address an existing configuration answer the modelled 404
    /// (`smithy_query(operation="GetCustomDetectionRuleOrgConfiguration")`).
    served_status: u16,
}

/// The four single-rule operations, each driven with a well-formed request that
/// carries as much of the caller's own input as the operation accepts — a rule id, a
/// mode, an account scope and, where it is modelled, a client token.
const OPERATIONS: [Operation; 4] = [
    Operation {
        name: "CreateCustomDetectionRuleOrgConfiguration",
        method: "POST",
        path: |_, _| ORG_CONFIGURATION_PATH.to_string(),
        body: |rule_id, mode| {
            Some(json!({
                "ruleId": rule_id,
                "mode": mode,
                "excludeAccountIds": [ACCOUNTS[1]],
                "clientToken": CLIENT_TOKEN,
            }))
        },
        served_status: 200,
    },
    Operation {
        name: "GetCustomDetectionRuleOrgConfiguration",
        method: "GET",
        path: |rule_id, mode| format!("{ORG_CONFIGURATION_PATH}/{rule_id}?mode={mode}"),
        body: |_, _| None,
        served_status: 404,
    },
    Operation {
        name: "UpdateCustomDetectionRuleOrgConfiguration",
        method: "PUT",
        path: |rule_id, _| format!("{ORG_CONFIGURATION_PATH}/{rule_id}"),
        body: |_, mode| Some(json!({"mode": mode, "includeAccountIds": [ACCOUNTS[1]]})),
        served_status: 404,
    },
    Operation {
        name: "DeleteCustomDetectionRuleOrgConfiguration",
        method: "DELETE",
        path: |rule_id, mode| format!("{ORG_CONFIGURATION_PATH}/{rule_id}?mode={mode}"),
        body: |_, _| None,
        served_status: 404,
    },
];

/// Send `operation` through `region`'s endpoint, for `rule_id` in `mode`.
async fn send(
    router: &Router,
    region: &str,
    operation: &Operation,
    rule_id: &str,
    mode: &str,
) -> (u16, Value) {
    call_in(
        router,
        region,
        operation.method,
        &(operation.path)(rule_id, mode),
        (operation.body)(rule_id, mode),
    )
    .await
}

/// The WHOLE answer an authorization refusal is, reduced to the facts a client reads:
/// the status, the members the body carries (its key set, so an answer carrying
/// anything more is a failure), the class in `__type`, the class in the body's own
/// `type` member, the shape `x-amzn-errortype` names and the message.
///
/// `__errorType` is the harness's fold of the `x-amzn-errortype` header into the
/// parsed body, so it is one of the keys a refusal carries here.
fn answer(status: u16, body: &Value) -> Value {
    let mut members: Vec<String> = body
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    members.sort();
    json!({
        "status": status,
        "members": members,
        "class": error_code(body),
        "type": body.get("type").cloned().unwrap_or(Value::Null),
        "shape": error_shape(body),
        "message": body.get("message").cloned().unwrap_or(Value::Null),
    })
}

/// The refusal every row of rule 1 must be answered with, to the member.
fn the_refusal() -> Value {
    json!({
        "status": 400,
        "members": ["__errorType", "__type", "message", "type"],
        "class": INVALID_INPUT,
        "type": INVALID_INPUT,
        "shape": ACCESS_DENIED,
        "message": NOT_AUTHORIZED,
    })
}

/// Leave every Region of [`REGIONS`] in `standing`, through the one helper that
/// establishes a standing for this crate's tests.
async fn establish_everywhere(router: &Router, standing: Standing) {
    for region in REGIONS {
        establish(router, region, standing).await;
    }
}

// ---------------------------------------------------------------------------
// Rule 1: one fixed answer, whatever the request and whatever the store.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unauthorized_caller_is_answered_the_same_refusal_whatever_it_asks() {
    let catalogue = published_rule_ids(&new_router()).await;
    // A rule the catalogue publishes and one it does not: the refusal is decided
    // before the rule id is resolved, so the two are answered alike.
    let rules = [
        ("a published rule", catalogue[0].as_str()),
        ("a rule the catalogue does not publish", UNPUBLISHED_RULE_ID),
    ];

    // The two standings that need no clock to be absent — nothing designated, and
    // another well-formed account designated. The standings a settled removal and
    // another Region's designation leave are the `org_configuration_authorization`
    // suite's rows.
    for (why, standing) in [
        ("no delegated administrator at all", Standing::Undesignated),
        (
            "another account is the delegated administrator",
            Standing::AnotherAccount,
        ),
    ] {
        // One store per standing: no row can see what another one wrote.
        let router = new_router();
        establish_everywhere(&router, standing).await;

        for region in REGIONS {
            for operation in &OPERATIONS {
                for mode in MODES {
                    for (which_rule, rule_id) in rules {
                        let case = format!(
                            "{} in {mode} through {region}, {which_rule}, {why}",
                            operation.name
                        );
                        let (status, body) = send(&router, region, operation, rule_id, mode).await;
                        assert_eq!(
                            answer(status, &body),
                            the_refusal(),
                            "case {case:?}: expected the fixed authorization refusal, got {status} {body:?}"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rule 2: a refused call resolves nothing and records nothing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_refused_call_records_neither_the_configuration_nor_its_client_token() {
    for mode in MODES {
        // One store per mode, so the create below is the FIRST one for its pair.
        let router = new_router();
        let catalogue = published_rule_ids(&router).await;
        let rule_id = catalogue[1].as_str();
        let region = REGIONS[0];

        // Nothing is designated, so every one of the four is refused — including the
        // create, which carries a client token and a scope of its own.
        for operation in &OPERATIONS {
            let case = format!("{} in {mode}, before any designation", operation.name);
            let (status, body) = send(&router, region, operation, rule_id, mode).await;
            assert_eq!(
                answer(status, &body),
                the_refusal(),
                "case {case:?}: expected the fixed authorization refusal, got {status} {body:?}"
            );
        }

        // The standing, established over the SAME store.
        as_delegated_admin(&router, region).await;

        // The create succeeds, which it could not do had the refused one written: a
        // configured pair is the modelled conflict. It replays the token the refused
        // create carried, so a recorded token would make this a no-op the read below
        // would find nothing for.
        let (status, created) = call_in(
            &router,
            region,
            "POST",
            ORG_CONFIGURATION_PATH,
            Some(json!({
                "ruleId": rule_id,
                "mode": mode,
                "includeAccountIds": [ACCOUNTS[0]],
                "clientToken": CLIENT_TOKEN,
            })),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {mode:?}: the first create of the pair expected 200, got {status} {created:?}"
        );

        // The round trip: what the AUTHORIZED create recorded is what the read
        // reports — the scope it carried, not the one a refused call tried to.
        let (status, read) = call_in(
            &router,
            region,
            "GET",
            &format!("{ORG_CONFIGURATION_PATH}/{rule_id}?mode={mode}"),
            None,
        )
        .await;
        assert_eq!(
            status, 200,
            "case {mode:?}: reading the configuration back expected 200, got {status} {read:?}"
        );
        let configuration = &read["configuration"];
        assert_eq!(
            configuration["mode"],
            json!(mode),
            "case {mode:?}: expected the mode the create carried, got {read:?}"
        );
        assert_eq!(
            configuration["ruleId"],
            json!(rule_id),
            "case {mode:?}: expected the rule the create named, got {read:?}"
        );
        assert_eq!(
            configuration["includeAccountIds"],
            json!([ACCOUNTS[0]]),
            "case {mode:?}: expected the scope the authorized create carried, got {read:?}"
        );
        assert_eq!(
            configuration["excludeAccountIds"],
            json!([]),
            "case {mode:?}: a refused call must have recorded no scope of its own, got {read:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Rule 3: the complement — with the standing, each one is served.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_delegated_administrator_is_served_in_either_mode() {
    let catalogue = published_rule_ids(&new_router()).await;
    let rule_id = catalogue[0].as_str();

    for operation in &OPERATIONS {
        for mode in MODES {
            // One store per case, so each operation is answered about a pair nothing
            // has configured and the status is the one its own contract gives.
            let router = new_router();
            as_delegated_admin(&router, REGIONS[0]).await;
            let case = format!("{} in {mode}", operation.name);

            let (status, body) = send(&router, REGIONS[0], operation, rule_id, mode).await;
            assert_eq!(
                status, operation.served_status,
                "case {case:?}: expected the delegated administrator to be answered {}, got {status} {body:?}",
                operation.served_status
            );
            assert_ne!(
                error_shape(&body),
                ACCESS_DENIED,
                "case {case:?}: the delegated administrator must not be refused, got {status} {body:?}"
            );
            assert_ne!(
                body["message"],
                json!(NOT_AUTHORIZED),
                "case {case:?}: the delegated administrator must not be refused, got {status} {body:?}"
            );
        }
    }
}
