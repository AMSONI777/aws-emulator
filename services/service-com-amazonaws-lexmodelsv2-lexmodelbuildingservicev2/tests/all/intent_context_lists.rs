// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP tests for the context lists of an intent, as `UpdateIntent` writes and
//! reports them.
//!
//! The rule: an update stores exactly the context lists the request named, and a response
//! carries such a member only when the stored intent holds a value for it — so an update
//! that names no context list reports no `inputContexts` and no `outputContexts` key at
//! all, whatever the intent carried before, while one that names a list reports it back as
//! given, the empty list and a list filled to the published maximum included. That
//! presence/absence is the difference a client reads with `'inputContexts' in response`,
//! which an empty array answers the wrong way round.
//!
//! Both halves are asserted over TABLES: rows differ in what the intent carried before the
//! update, in which other members the update names beside the required intent name, in
//! which context list the update names, and in how many entries that list carries — zero,
//! one, and the published maximum of the modelled list shape, plus one entry past it, and
//! each published bound of the modelled entry members plus one step outside it.
//!
//! The harness and the bot/locale/intent helpers are the other suites', reused rather than
//! copied.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::bot_lifecycle::{call, emulator, error_code, member, text};
use crate::intents_and_builds::{create_intent, intent_body, intent_uri};
use crate::optional_collections::{assert_echoed, has_key, output_context};
use crate::slot_type::host_locale;

/// The two context list members of an intent, which `UpdateIntent` takes and reports and
/// `DescribeIntent` reports (`smithy_query(query="operation",operation="UpdateIntent")`):
/// neither is `@required` and neither carries a `@default`.
const CONTEXT_LISTS: [&str; 2] = ["inputContexts", "outputContexts"];

/// `n` `inputContexts` entries. A modelled `InputContext` carries just the required
/// `name` (`smithy_query(query="shape",shape="InputContext")`).
fn input_contexts(n: usize) -> Value {
    (0..n)
        .map(|index| json!({ "name": format!("InContext{index}") }))
        .collect()
}

/// `n` `outputContexts` entries, each with the three members a modelled `OutputContext`
/// requires.
fn output_contexts(n: usize) -> Value {
    (0..n)
        .map(|index| output_context(&format!("OutContext{index}")))
        .collect()
}

/// Update the intent and return the status and body of the answer.
async fn update_intent(
    router: &MultiServiceRouter,
    bot_id: &str,
    locale_id: &str,
    intent_id: &str,
    body: &Value,
) -> (u16, Value) {
    call(
        router,
        "PUT",
        &intent_uri(bot_id, "DRAFT", locale_id, intent_id),
        Some(body.clone()),
    )
    .await
}

/// Read the intent back through `DescribeIntent`, asserting it is still there.
async fn describe_intent(
    router: &MultiServiceRouter,
    bot_id: &str,
    locale_id: &str,
    intent_id: &str,
) -> Value {
    let (status, described) = call(
        router,
        "GET",
        &intent_uri(bot_id, "DRAFT", locale_id, intent_id),
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "expected DescribeIntent to answer 200, got {status} {described:?}"
    );
    described
}

#[tokio::test]
async fn an_update_naming_no_context_list_reports_neither_context_key() {
    let router = emulator();
    let bot_id = host_locale(&router, "ContextListUpdateBot", "en_US").await;

    // What the intent carries BEFORE the update: nothing, one list, or both. The rule is
    // the same whichever it is — the update's own document decides what the intent holds.
    let starting_points: Vec<(&str, Value)> = vec![
        ("an intent created with no context list", json!({})),
        (
            "an intent created with an empty input context list",
            json!({ "inputContexts": [] }),
        ),
        (
            "an intent created with contexts of both kinds",
            json!({
                "inputContexts": input_contexts(2),
                "outputContexts": output_contexts(3),
            }),
        ),
    ];

    // Updates that name NO context list, differing in the other members they carry.
    let updates: Vec<(&str, Value)> = vec![
        ("an update carrying only the required name", json!({})),
        (
            "an update carrying a new description",
            json!({ "description": "Takes a pizza order" }),
        ),
        (
            "an update carrying a display name and sample utterances",
            json!({
                "intentDisplayName": "Order Pizza",
                "sampleUtterances": [{ "utterance": "I want to order a pizza" }],
            }),
        ),
        (
            "an update carrying an empty sample utterance list",
            json!({ "sampleUtterances": [] }),
        ),
        (
            "an update carrying a dialog code hook",
            json!({ "dialogCodeHook": { "enabled": false } }),
        ),
    ];

    for (start_index, (start_case, start_lists)) in starting_points.into_iter().enumerate() {
        for (update_index, (update_case, extra)) in updates.iter().enumerate() {
            let case = format!("{start_case} then {update_case}");
            let name = format!("OrderPizza_{start_index}_{update_index}");
            let intent_id = create_intent(
                &router,
                &bot_id,
                "en_US",
                &intent_body(&name, start_lists.clone()),
            )
            .await;

            let request = intent_body(&name, extra.clone());
            let (status, updated) =
                update_intent(&router, &bot_id, "en_US", &intent_id, &request).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected UpdateIntent to answer 200, got {status} {updated:?}"
            );
            for list in CONTEXT_LISTS {
                assert!(
                    !has_key(&updated, list),
                    "case {case:?}: UpdateIntent must carry no {list} key when the update \
                     named none, got {updated:?}"
                );
            }
            // The members the update DID name are reported as it gave them, so the two
            // absent keys are absence and not a response that dropped everything.
            for named in ["description", "intentDisplayName", "sampleUtterances"] {
                assert_echoed(&case, "UpdateIntent", &request, &updated, named);
            }

            // And the record the update left behind holds no context list either.
            let described = describe_intent(&router, &bot_id, "en_US", &intent_id).await;
            for list in CONTEXT_LISTS {
                assert!(
                    !has_key(&described, list),
                    "case {case:?}: DescribeIntent must carry no {list} key after an update \
                     that named none, got {described:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn an_update_reports_the_context_list_it_named_up_to_the_published_maximum() {
    let router = emulator();
    let bot_id = host_locale(&router, "ContextListBoundBot", "en_US").await;
    let intent_id = create_intent(
        &router,
        &bot_id,
        "en_US",
        &intent_body(
            "OrderPizza",
            json!({
                "inputContexts": input_contexts(1),
                "outputContexts": output_contexts(1),
            }),
        ),
    )
    .await;

    // Counts on and inside the published bounds of the modelled list shapes:
    // `InputContextsList` is @length 0..5 and `OutputContextsList` @length 0..10
    // (`smithy_query(query="shape",shape="InputContextsList,OutputContextsList")`).
    let accepted: Vec<(&str, Value)> = vec![
        (
            "an explicitly empty input context list, the published minimum",
            json!({ "inputContexts": [] }),
        ),
        (
            "one input context",
            json!({ "inputContexts": input_contexts(1) }),
        ),
        (
            "input contexts at the published maximum of five",
            json!({ "inputContexts": input_contexts(5) }),
        ),
        (
            "an explicitly empty output context list, the published minimum",
            json!({ "outputContexts": [] }),
        ),
        (
            "one output context",
            json!({ "outputContexts": output_contexts(1) }),
        ),
        (
            "output contexts at the published maximum of ten",
            json!({ "outputContexts": output_contexts(10) }),
        ),
        (
            "both lists at their published maxima",
            json!({
                "inputContexts": input_contexts(5),
                "outputContexts": output_contexts(10),
            }),
        ),
        (
            "an output context on the published minima of its own bounds",
            json!({
                "outputContexts": [
                    { "name": "Shortest", "timeToLiveInSeconds": 5, "turnsToLive": 1 },
                ],
            }),
        ),
        (
            "an output context on the published maxima of its own bounds",
            json!({
                "outputContexts": [
                    { "name": "Longest", "timeToLiveInSeconds": 86_400, "turnsToLive": 20 },
                ],
            }),
        ),
    ];

    for (case, extra) in accepted {
        let request = intent_body("OrderPizza", extra);
        let (status, updated) = update_intent(&router, &bot_id, "en_US", &intent_id, &request).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected UpdateIntent to answer 200, got {status} {updated:?}"
        );
        for list in CONTEXT_LISTS {
            assert_echoed(case, "UpdateIntent", &request, &updated, list);
        }
        let described = describe_intent(&router, &bot_id, "en_US", &intent_id).await;
        for list in CONTEXT_LISTS {
            assert_echoed(case, "DescribeIntent", &request, &described, list);
        }
    }
}

#[tokio::test]
async fn an_update_outside_a_published_context_bound_is_refused_and_stores_nothing() {
    let router = emulator();
    let bot_id = host_locale(&router, "ContextListRefusalBot", "en_US").await;
    let intent_id = create_intent(&router, &bot_id, "en_US", &intent_body("OrderPizza", json!({})))
        .await;

    // The baseline the refused updates must leave untouched.
    let baseline = intent_body(
        "OrderPizza",
        json!({
            "inputContexts": input_contexts(2),
            "outputContexts": output_contexts(2),
        }),
    );
    let (status, updated) = update_intent(&router, &bot_id, "en_US", &intent_id, &baseline).await;
    assert_eq!(
        status, 200,
        "the baseline update must be accepted, got {status} {updated:?}"
    );

    // One step outside each published bound: one entry past each list's maximum, and each
    // modelled `OutputContext` member one step outside its own range — `name` is `Name`
    // (len 1..100, pattern `^([0-9a-zA-Z][_-]?){1,100}$`), `timeToLiveInSeconds` is
    // @range 5..86400 and `turnsToLive` @range 1..20
    // (`smithy_query(query="shape",shape="InputContext,OutputContext")`).
    let refused: Vec<(&str, Value)> = vec![
        (
            "one input context past the published maximum of five",
            json!({ "inputContexts": input_contexts(6) }),
        ),
        (
            "one output context past the published maximum of ten",
            json!({ "outputContexts": output_contexts(11) }),
        ),
        (
            "an output context lifetime one second short of the minimum",
            json!({
                "outputContexts": [
                    { "name": "TooShort", "timeToLiveInSeconds": 4, "turnsToLive": 1 },
                ],
            }),
        ),
        (
            "an output context lifetime one second past the maximum",
            json!({
                "outputContexts": [
                    { "name": "TooLong", "timeToLiveInSeconds": 86_401, "turnsToLive": 1 },
                ],
            }),
        ),
        (
            "an output context living no conversation turn, one short of the minimum",
            json!({
                "outputContexts": [
                    { "name": "NoTurn", "timeToLiveInSeconds": 60, "turnsToLive": 0 },
                ],
            }),
        ),
        (
            "an output context living one turn past the maximum",
            json!({
                "outputContexts": [
                    { "name": "TooManyTurns", "timeToLiveInSeconds": 60, "turnsToLive": 21 },
                ],
            }),
        ),
        (
            "an input context name the modelled pattern rejects",
            json!({ "inputContexts": [{ "name": "Order In Progress" }] }),
        ),
        (
            "an input context name one character past its maximum length",
            json!({ "inputContexts": [{ "name": "C".repeat(101) }] }),
        ),
    ];

    for (case, extra) in refused {
        let request = intent_body("OrderPizza", extra);
        let (status, response) =
            update_intent(&router, &bot_id, "en_US", &intent_id, &request).await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected UpdateIntent to refuse with 400, got {status} {response:?}"
        );
        assert_eq!(
            error_code(&response),
            "ValidationException",
            "case {case:?}: expected ValidationException, got {response:?}"
        );

        // A refused update writes nothing: the intent still holds the baseline lists.
        let described = describe_intent(&router, &bot_id, "en_US", &intent_id).await;
        assert_eq!(
            text(&described, "intentName"),
            "OrderPizza",
            "case {case:?}: the refused update must leave the intent as it was, got \
             {described:?}"
        );
        for list in CONTEXT_LISTS {
            assert_eq!(
                member(&described, list),
                member(&baseline, list),
                "case {case:?}: the refused update must leave {list} as the baseline left it, \
                 got {described:?}"
            );
        }
    }
}
