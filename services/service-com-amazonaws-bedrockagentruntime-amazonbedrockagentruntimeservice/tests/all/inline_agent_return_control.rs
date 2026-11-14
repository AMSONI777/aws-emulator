// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the two halves of the RETURN CONTROL contract of
//! `InvokeInlineAgent`, and for the orchestration TRACE a turn reports when `enableTrace`
//! is set.
//!
//! THE RULES UNDER TEST:
//!
//! * an action group whose `actionGroupExecutor` is `customControl: RETURN_CONTROL` is
//!   carried out by the CALLER, so the turn hands the functions that action group's
//!   `functionSchema` declares back as the modelled `returnControl` member of the stream,
//!   the LAST member of the turn, under a service-issued `invocationId`; each
//!   `functionInvocationInput` carries the declared action group, the declared function and
//!   the declared parameter names and types, and no parameter VALUE, which is what a model
//!   would elicit. An action group executed by a Lambda function, or one declaring no
//!   functions, hands nothing back and the turn answers with `chunk` alone;
//! * the caller returns the results under that same id in
//!   `inlineSessionState.returnControlInvocationResults`, and they re-enter the NEXT turn's
//!   orchestration prompt; an `invocationId` no response of that conversation issued — and
//!   results carrying none at all — is `ValidationException` (400), and a result list
//!   outside the modelled 1..5 is refused by the model's own bound;
//! * `enableTrace` adds a report alongside the answer: the turn carries the modelled
//!   `trace` member for the orchestration step it performed, whose
//!   `orchestrationTrace.modelInvocationInput.text` is the prompt the turn was assembled
//!   from, and a turn that returns control also traces that invocation under `executionType`
//!   `RETURN_CONTROL`. A request that does not enable a trace carries no `trace` member.
//!
//! The tables span what those rules generalise over: how many return-control action groups
//! a request declares, how many functions each declares (none, one, several, more than the
//! modelled maximum of five), how many parameters a function declares and whether each is
//! required, which executor an action group names, how many results the caller returns,
//! which result member they come back as, and where the `invocationId` they are returned
//! under came from.

use serde_json::{json, Value};

use crate::agent_memory::{Emulator, ACCOUNT_KEY};
use crate::inline_agent_invocations::{request, served, Answer, INSTRUCTION};

/// The model every row composes its agent against, which the catalogue publishes under this
/// id.
const MODEL: &str = "amazon.nova-lite-v1:0";

/// The most invocation inputs one returned control may carry, which is the modelled
/// `@length` maximum of `InvocationInputs`
/// (`smithy_query(query="shape",shape="InvocationInputs")` -> min 1, max 5). The same bound
/// is on `ReturnControlInvocationResults`.
const MAX_INVOCATION_INPUTS: usize = 5;

/// The one value of the modelled `CustomControlMethod`
/// (`smithy_query(query="shape",shape="CustomControlMethod")`).
const RETURN_CONTROL: &str = "RETURN_CONTROL";

/// One parameter declaration of a function, as `functionSchema` carries it: the modelled
/// `ParameterDetail` with its `@required` `type`
/// (`smithy_query(query="shape",shape="ParameterDetail,ParameterType")` -> `string`,
/// `number`, `integer`, `boolean`, `array`).
fn parameter(parameter_type: &str, required: bool) -> Value {
    json!({
        "description": "the value the function is carried out for",
        "type": parameter_type,
        "required": required,
    })
}

/// One action group whose actions the CALLER carries out, declaring `functions`.
fn return_control_group(name: &str, functions: Value) -> Value {
    json!({
        "actionGroupName": name,
        "actionGroupExecutor": { "customControl": RETURN_CONTROL },
        "functionSchema": { "functions": functions },
    })
}

/// One declared function, with the parameters named in `parameters`.
fn function(name: &str, parameters: Value) -> Value {
    json!({
        "name": name,
        "description": "carries out one step the agent cannot carry out itself",
        "parameters": parameters,
    })
}

/// The `returnControl` frames of one answer, as a client reading the stream's union sees
/// them.
fn return_control_payloads(case: &str, answer: &Answer) -> Vec<Value> {
    answer
        .frames(case)
        .into_iter()
        .filter(|frame| frame.name == "returnControl")
        .map(|frame| frame.payload)
        .collect()
}

/// The `trace` frames of one answer.
fn trace_payloads(case: &str, answer: &Answer) -> Vec<Value> {
    answer
        .frames(case)
        .into_iter()
        .filter(|frame| frame.name == "trace")
        .map(|frame| frame.payload)
        .collect()
}

/// The text of the one `orchestrationTrace.modelInvocationInput` of an answer's trace: the
/// prompt the turn was assembled from.
fn orchestration_prompt(case: &str, answer: &Answer) -> String {
    let prompts: Vec<Value> = trace_payloads(case, answer)
        .into_iter()
        .filter_map(|payload| {
            payload
                .get("trace")?
                .get("orchestrationTrace")?
                .get("modelInvocationInput")
                .cloned()
        })
        .collect();
    assert_eq!(
        prompts.len(),
        1,
        "case {case:?}: a turn assembles one prompt, so its trace reports one \
         modelInvocationInput, got {prompts:?}"
    );
    prompts[0]
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: the traced prompt must carry its text, got {:?}",
                prompts[0]
            )
        })
        .to_string()
}

/// The `invocationId` the one `returnControl` member of an answer was handed back under.
fn issued_invocation_id(case: &str, answer: &Answer) -> String {
    let payloads = return_control_payloads(case, answer);
    assert_eq!(
        payloads.len(),
        1,
        "case {case:?}: a turn that returns control returns it once, got {payloads:?}"
    );
    payloads[0]
        .get("invocationId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: the returned control must carry a non-empty invocationId, \
                 got {:?}",
                payloads[0]
            )
        })
        .to_string()
}

/// One body composing an inline agent with `action_groups`, asking it for the action in
/// `input_text`.
fn invocation(action_groups: Value, input_text: &str, enable_trace: bool) -> Value {
    let mut body = request(MODEL);
    body["actionGroups"] = action_groups;
    body["inputText"] = json!(input_text);
    if enable_trace {
        body["enableTrace"] = json!(true);
    }
    body
}

/// RULE: an action group the CALLER carries out makes the turn hand its declared functions
/// back as the last member of the stream, under a service-issued `invocationId`; one carried
/// out by a Lambda function, or declaring no function, hands nothing back.
#[tokio::test]
async fn an_action_group_executed_by_the_caller_hands_its_functions_back() {
    /// One invocation: the action groups it declares, and the functions the turn must hand
    /// back for them as `(actionGroup, function, [parameter names])`.
    struct Row {
        case: &'static str,
        session: &'static str,
        action_groups: Value,
        expected: Vec<(&'static str, &'static str, Vec<&'static str>)>,
    }

    let rows = vec![
        Row {
            case: "one return-control action group with one one-parameter function",
            session: "control-session-01",
            action_groups: json!([return_control_group(
                "LaunchCodeLookup",
                json!([function(
                    "get_launch_code",
                    json!({ "project": parameter("string", true) })
                )]),
            )]),
            expected: vec![("LaunchCodeLookup", "get_launch_code", vec!["project"])],
        },
        Row {
            case: "a function declaring several parameters of several types",
            session: "control-session-02",
            action_groups: json!([return_control_group(
                "FleetDispatch",
                json!([function(
                    "schedule_visit",
                    json!({
                        "site": parameter("string", true),
                        "priority": parameter("integer", false),
                        "urgent": parameter("boolean", false),
                    })
                )]),
            )]),
            // The parameters of one function arrive ordered by name, so one turn's inputs
            // are stable whatever order the request's map was read in.
            expected: vec![(
                "FleetDispatch",
                "schedule_visit",
                vec!["priority", "site", "urgent"],
            )],
        },
        Row {
            case: "a function declaring no parameters at all",
            session: "control-session-03",
            action_groups: json!([return_control_group(
                "FleetStatus",
                json!([function("list_open_work_orders", json!({}))]),
            )]),
            expected: vec![("FleetStatus", "list_open_work_orders", vec![])],
        },
        Row {
            case: "two action groups, each declaring one function",
            session: "control-session-04",
            action_groups: json!([
                return_control_group(
                    "LaunchCodeLookup",
                    json!([function(
                        "get_launch_code",
                        json!({ "project": parameter("string", true) })
                    )]),
                ),
                return_control_group(
                    "FleetDispatch",
                    json!([function(
                        "schedule_visit",
                        json!({ "site": parameter("string", true) })
                    )]),
                ),
            ]),
            expected: vec![
                ("LaunchCodeLookup", "get_launch_code", vec!["project"]),
                ("FleetDispatch", "schedule_visit", vec!["site"]),
            ],
        },
        Row {
            case: "a Lambda-executed action group beside a return-control one",
            session: "control-session-05",
            action_groups: json!([
                {
                    "actionGroupName": "Billing",
                    "actionGroupExecutor": {
                        "lambda": "arn:aws:lambda:us-west-2:000000000000:function:billing",
                    },
                    "functionSchema": {
                        "functions": [function("issue_invoice", json!({}))],
                    },
                },
                return_control_group(
                    "FleetStatus",
                    json!([function("list_open_work_orders", json!({}))]),
                ),
            ]),
            // Only the action group the CALLER carries out is handed back: the Lambda one's
            // action is carried out by that function.
            expected: vec![("FleetStatus", "list_open_work_orders", vec![])],
        },
        Row {
            case: "a return-control action group declaring no functionSchema",
            session: "control-session-06",
            action_groups: json!([{
                "actionGroupName": "FleetStatus",
                "actionGroupExecutor": { "customControl": RETURN_CONTROL },
            }]),
            expected: vec![],
        },
        Row {
            case: "an action group with no executor at all",
            session: "control-session-07",
            action_groups: json!([{ "actionGroupName": "FleetStatus" }]),
            expected: vec![],
        },
        Row {
            case: "a Lambda-executed action group alone",
            session: "control-session-08",
            action_groups: json!([{
                "actionGroupName": "Billing",
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-west-2:000000000000:function:billing",
                },
                "functionSchema": { "functions": [function("issue_invoice", json!({}))] },
            }]),
            expected: vec![],
        },
    ];

    let emulator = Emulator::new();
    for row in rows {
        let answer = emulator
            .invoke_inline_agent(
                ACCOUNT_KEY,
                row.session,
                invocation(
                    row.action_groups.clone(),
                    "carry out the action and tell me what it says",
                    false,
                ),
            )
            .await;
        let keys = answer.event_keys(row.case);
        if row.expected.is_empty() {
            assert_eq!(
                keys,
                vec!["chunk".to_string()],
                "case {:?}: a turn with no action for the caller answers with chunk alone, \
                 got {keys:?}",
                row.case
            );
            let text = served(row.case, &answer, row.session);
            assert!(
                text.contains(MODEL),
                "case {:?}: the answer must name the model the agent was composed against, \
                 got {text:?}",
                row.case
            );
            continue;
        }
        assert_eq!(
            keys,
            vec!["returnControl".to_string()],
            "case {:?}: a turn that hands an action back carries the returnControl member \
             last and no answer beside it, got {keys:?}",
            row.case
        );
        let payloads = return_control_payloads(row.case, &answer);
        let invocation_id = issued_invocation_id(row.case, &answer);
        let inputs = payloads[0]["invocationInputs"]
            .as_array()
            .unwrap_or_else(|| {
                panic!(
                    "case {:?}: the returned control must carry invocationInputs, got {:?}",
                    row.case, payloads[0]
                )
            })
            .clone();
        assert_eq!(
            inputs.len(),
            row.expected.len(),
            "case {:?}: expected one invocation input per function offered, got {inputs:?}",
            row.case
        );
        assert!(
            inputs.len() <= MAX_INVOCATION_INPUTS,
            "case {:?}: invocationInputs may carry at most {MAX_INVOCATION_INPUTS}, got {}",
            row.case,
            inputs.len()
        );
        for (input, (action_group, function_name, parameters)) in
            inputs.iter().zip(row.expected.iter())
        {
            let elicited = input.get("functionInvocationInput").unwrap_or_else(|| {
                panic!(
                    "case {:?}: a function the agent elicited travels as a \
                     functionInvocationInput, got {input:?}",
                    row.case
                )
            });
            assert_eq!(
                (
                    elicited["actionGroup"].as_str(),
                    elicited["function"].as_str()
                ),
                (Some(*action_group), Some(*function_name)),
                "case {:?}: the input must name the declared action group and function, got \
                 {elicited:?}",
                row.case
            );
            let declared: Vec<&str> = elicited
                .get("parameters")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .map(|parameter| parameter["name"].as_str().unwrap_or_default())
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(
                &declared, parameters,
                "case {:?}: the input must carry the declared parameter names, got \
                 {elicited:?}",
                row.case
            );
            for parameter in elicited
                .get("parameters")
                .and_then(Value::as_array)
                .unwrap_or(&Vec::new())
            {
                assert!(
                    parameter.get("type").and_then(Value::as_str).is_some(),
                    "case {:?}: a parameter carries the type it was declared with, got \
                     {parameter:?}",
                    row.case
                );
                // A parameter VALUE is what a model elicits from the conversation, and no
                // model runs here, so none is invented.
                assert!(
                    parameter.get("value").is_none(),
                    "case {:?}: no parameter value may be invented, got {parameter:?}",
                    row.case
                );
            }
        }
        // The id is the SERVICE's: it is not any value the request carried.
        assert!(
            !invocation_id.is_empty() && !row.action_groups.to_string().contains(&invocation_id),
            "case {:?}: the invocationId must be issued by the service, got \
             {invocation_id:?}",
            row.case
        );
    }
}

/// RULE: a turn offering more functions than the modelled maximum hands back exactly that
/// maximum, because `invocationInputs` cannot carry more.
#[tokio::test]
async fn a_turn_hands_back_at_most_the_modelled_maximum_of_inputs() {
    let emulator = Emulator::new();
    // (case, how many functions the action group declares, how many inputs come back)
    let rows: Vec<(&str, usize, usize)> = vec![
        ("one function", 1, 1),
        ("four functions", 4, 4),
        ("exactly the modelled maximum", MAX_INVOCATION_INPUTS, MAX_INVOCATION_INPUTS),
        ("one function past it", MAX_INVOCATION_INPUTS + 1, MAX_INVOCATION_INPUTS),
        ("far past it", MAX_INVOCATION_INPUTS + 4, MAX_INVOCATION_INPUTS),
    ];
    for (index, (case, declared, expected)) in rows.into_iter().enumerate() {
        let functions: Vec<Value> = (0..declared)
            .map(|position| {
                function(
                    &format!("step_{position}"),
                    json!({ "site": parameter("string", true) }),
                )
            })
            .collect();
        let answer = emulator
            .invoke_inline_agent(
                ACCOUNT_KEY,
                &format!("max-inputs-session-{index}"),
                invocation(
                    json!([return_control_group("FleetDispatch", json!(functions))]),
                    "carry out every step",
                    false,
                ),
            )
            .await;
        let payloads = return_control_payloads(case, &answer);
        let inputs = payloads[0]["invocationInputs"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            inputs.len(),
            expected,
            "case {case:?}: expected {expected} invocation inputs for {declared} declared \
             functions, got {}",
            inputs.len()
        );
        let names: Vec<&str> = inputs
            .iter()
            .map(|input| input["functionInvocationInput"]["function"]
                .as_str()
                .unwrap_or_default())
            .collect();
        let offered: Vec<String> = (0..expected).map(|p| format!("step_{p}")).collect();
        assert_eq!(
            names, offered,
            "case {case:?}: the inputs must be the functions the request declared, in order"
        );
    }
}

/// RULE: the results the caller returns under the issued `invocationId` re-enter the next
/// turn's orchestration prompt, and that turn answers instead of handing control back again.
#[tokio::test]
async fn a_returned_result_re_enters_the_next_turns_prompt() {
    /// One two-turn exchange: how many functions the first turn hands back, and the bodies
    /// the caller returns for them.
    struct Row {
        case: &'static str,
        session: &'static str,
        functions: Vec<&'static str>,
        /// The body returned for each function, in the same order.
        bodies: Vec<&'static str>,
        /// Whether the results come back as `apiResult` instead of `functionResult`.
        as_api_result: bool,
    }

    let rows = vec![
        Row {
            case: "one function, one returned result",
            session: "returned-session-01",
            functions: vec!["get_launch_code"],
            bodies: vec!["the launch code is 4815162342"],
            as_api_result: false,
        },
        Row {
            case: "three functions, three returned results",
            session: "returned-session-02",
            functions: vec!["get_launch_code", "schedule_visit", "list_parts"],
            bodies: vec![
                "the launch code is 4815162342",
                "the visit is booked for the morning shift",
                "two impellers and one seal kit are in stock",
            ],
            as_api_result: false,
        },
        Row {
            case: "the modelled maximum of returned results",
            session: "returned-session-03",
            functions: vec!["step_a", "step_b", "step_c", "step_d", "step_e"],
            bodies: vec![
                "result a",
                "result b",
                "result c",
                "result d",
                "result e",
            ],
            as_api_result: false,
        },
        Row {
            case: "a result returned as an apiResult",
            session: "returned-session-04",
            functions: vec!["get_launch_code"],
            bodies: vec!["the launch code is 4815162342"],
            as_api_result: true,
        },
    ];

    let emulator = Emulator::new();
    for row in rows {
        let functions: Vec<Value> = row
            .functions
            .iter()
            .map(|name| function(name, json!({ "project": parameter("string", true) })))
            .collect();
        let action_groups = json!([return_control_group(
            "LaunchCodeLookup",
            json!(functions)
        )]);
        let first = emulator
            .invoke_inline_agent(
                ACCOUNT_KEY,
                row.session,
                invocation(
                    action_groups.clone(),
                    "carry out the action and tell me what it says",
                    true,
                ),
            )
            .await;
        assert_eq!(
            first.status, 200,
            "case {:?}: the first turn must be served, got {} {:?}",
            row.case,
            first.status,
            first.json(row.case)
        );
        let invocation_id = issued_invocation_id(row.case, &first);
        assert_eq!(
            first.event_keys(row.case).last().map(String::as_str),
            Some("returnControl"),
            "case {:?}: returnControl is the last member of the turn, got {:?}",
            row.case,
            first.event_keys(row.case)
        );

        let results: Vec<Value> = row
            .functions
            .iter()
            .zip(row.bodies.iter())
            .map(|(name, body)| {
                let payload = json!({
                    "actionGroup": "LaunchCodeLookup",
                    "responseBody": { "TEXT": { "body": body } },
                });
                if row.as_api_result {
                    let mut api = payload;
                    api["apiPath"] = json!(format!("/{name}"));
                    api["httpMethod"] = json!("POST");
                    api["httpStatusCode"] = json!(200);
                    json!({ "apiResult": api })
                } else {
                    let mut result = payload;
                    result["function"] = json!(name);
                    result["confirmationState"] = json!("CONFIRM");
                    json!({ "functionResult": result })
                }
            })
            .collect();
        let mut body = invocation(action_groups, "and now summarise what came back", true);
        body["inlineSessionState"] = json!({
            "invocationId": invocation_id,
            "returnControlInvocationResults": results,
        });
        let second = emulator
            .invoke_inline_agent(ACCOUNT_KEY, row.session, body)
            .await;
        let text = served(row.case, &second, row.session);
        let keys = second.event_keys(row.case);
        assert!(
            !keys.iter().any(|key| key == "returnControl"),
            "case {:?}: a turn answering an invocation does not hand control back again, \
             got {keys:?}",
            row.case
        );
        assert!(
            keys.iter().any(|key| key == "chunk"),
            "case {:?}: the turn that takes the results answers the caller, got {keys:?}",
            row.case
        );
        assert!(
            text.contains(&format!(
                "{} result(s) returned under invocation {invocation_id}",
                row.bodies.len()
            )),
            "case {:?}: the answer must report the results that re-entered the turn, got \
             {text:?}",
            row.case
        );
        let prompt = orchestration_prompt(row.case, &second);
        for body in &row.bodies {
            assert!(
                prompt.contains(body),
                "case {:?}: the returned result must re-enter the turn's prompt, got \
                 {prompt:?}",
                row.case
            );
        }
        assert!(
            prompt.contains(&invocation_id),
            "case {:?}: the prompt must name the invocation the results answered, got \
             {prompt:?}",
            row.case
        );
        assert!(
            prompt.contains("and now summarise what came back"),
            "case {:?}: the prompt must carry the input the turn was submitted with, got \
             {prompt:?}",
            row.case
        );
    }
}

/// RULE: results are taken only under an `invocationId` the same conversation really
/// returned control under; anything else is the modelled `ValidationException` (400), and a
/// turn refused that way records nothing.
#[tokio::test]
async fn results_under_an_invocation_the_service_never_issued_are_refused() {
    /// Where the `invocationId` a second turn returns results under comes from.
    enum Source {
        /// The id the conversation's own first turn was handed.
        OwnTurn,
        /// The id another conversation's turn was handed.
        AnotherSession,
        /// An id no response ever carried.
        Unknown(&'static str),
        /// No `invocationId` member at all.
        Absent,
    }

    /// One attempt at the caller's half of the contract.
    struct Row {
        case: &'static str,
        session: &'static str,
        issued: Source,
        /// How many results the attempt returns.
        results: usize,
        /// `None` when the turn is served, else the phrase the refusal must state.
        refused: Option<&'static str>,
    }

    let rows = vec![
        Row {
            case: "the id this conversation was handed",
            session: "unissued-session-01",
            issued: Source::OwnTurn,
            results: 1,
            refused: None,
        },
        Row {
            case: "the modelled maximum of results under that id",
            session: "unissued-session-02",
            issued: Source::OwnTurn,
            results: MAX_INVOCATION_INPUTS,
            refused: None,
        },
        Row {
            case: "one result past the modelled maximum",
            session: "unissued-session-03",
            issued: Source::OwnTurn,
            results: MAX_INVOCATION_INPUTS + 1,
            refused: Some("returnControlInvocationResults"),
        },
        Row {
            case: "an empty result list, under the modelled minimum",
            session: "unissued-session-08",
            issued: Source::OwnTurn,
            results: 0,
            refused: Some("returnControlInvocationResults"),
        },
        Row {
            case: "an id no response of this emulator ever carried",
            session: "unissued-session-04",
            issued: Source::Unknown("11111111-2222-3333-4444-555555555555"),
            results: 1,
            refused: Some("inlineSessionState.invocationId"),
        },
        Row {
            case: "an id that is not even an identifier",
            session: "unissued-session-05",
            issued: Source::Unknown("not-an-invocation"),
            results: 1,
            refused: Some("inlineSessionState.invocationId"),
        },
        Row {
            case: "the id another conversation was handed",
            session: "unissued-session-06",
            issued: Source::AnotherSession,
            results: 1,
            refused: Some("inlineSessionState.invocationId"),
        },
        Row {
            case: "results carrying no invocationId at all",
            session: "unissued-session-07",
            issued: Source::Absent,
            results: 1,
            refused: Some("inlineSessionState.invocationId"),
        },
    ];

    let emulator = Emulator::new();
    let action_groups = json!([return_control_group(
        "LaunchCodeLookup",
        json!([
            function("get_launch_code", json!({ "project": parameter("string", true) })),
            function("schedule_visit", json!({ "site": parameter("string", true) })),
            function("list_parts", json!({ "site": parameter("string", true) })),
            function("close_order", json!({ "site": parameter("string", true) })),
            function("reopen_order", json!({ "site": parameter("string", true) })),
        ])
    )]);

    // The conversation whose id every "another conversation" row borrows from.
    let elsewhere = emulator
        .invoke_inline_agent(
            ACCOUNT_KEY,
            "unissued-elsewhere",
            invocation(action_groups.clone(), "carry out the action", false),
        )
        .await;
    let elsewhere_id = issued_invocation_id("the other conversation", &elsewhere);

    for row in rows {
        let first = emulator
            .invoke_inline_agent(
                ACCOUNT_KEY,
                row.session,
                invocation(action_groups.clone(), "carry out the action", false),
            )
            .await;
        let own_id = issued_invocation_id(row.case, &first);
        let results: Vec<Value> = (0..row.results)
            .map(|position| {
                json!({
                    "functionResult": {
                        "actionGroup": "LaunchCodeLookup",
                        "function": format!("step_{position}"),
                        "responseBody": { "TEXT": { "body": format!("result {position}") } },
                    },
                })
            })
            .collect();
        let mut state = json!({ "returnControlInvocationResults": results });
        match row.issued {
            Source::OwnTurn => state["invocationId"] = json!(own_id),
            Source::AnotherSession => state["invocationId"] = json!(elsewhere_id),
            Source::Unknown(id) => state["invocationId"] = json!(id),
            Source::Absent => {}
        }
        let mut body = invocation(action_groups.clone(), "summarise what came back", false);
        let submitted = state
            .get("invocationId")
            .and_then(Value::as_str)
            .map(str::to_string);
        body["inlineSessionState"] = state;
        let answer = emulator
            .invoke_inline_agent(ACCOUNT_KEY, row.session, body)
            .await;
        match row.refused {
            Some(phrase) => {
                assert_eq!(
                    (answer.error_code(row.case).as_str(), answer.status),
                    ("ValidationException", 400),
                    "case {:?}: expected the modelled validation refusal, got {} {:?}",
                    row.case,
                    answer.status,
                    answer.json(row.case)
                );
                assert!(
                    answer.message(row.case).contains(phrase),
                    "case {:?}: the refusal must state {phrase:?}, got {:?}",
                    row.case,
                    answer.message(row.case)
                );
                // A refusal about the identifier quotes the one the REQUEST submitted, so
                // the caller can see which value did not match.
                if phrase == "inlineSessionState.invocationId" {
                    if let Some(id) = submitted.as_deref() {
                        assert!(
                            answer.message(row.case).contains(id),
                            "case {:?}: the refusal must quote the invocationId the request \
                             submitted ({id:?}), got {:?}",
                            row.case,
                            answer.message(row.case)
                        );
                    }
                }
                // The refused turn recorded nothing: the next served turn is the second of
                // the conversation, the first having been the one that returned control.
                let next = emulator
                    .invoke_inline_agent(
                        ACCOUNT_KEY,
                        row.session,
                        request(MODEL),
                    )
                    .await;
                let text = served(row.case, &next, row.session);
                assert!(
                    text.contains(&format!("turn 2 of session {}", row.session)),
                    "case {:?}: a refused turn records nothing, got {text:?}",
                    row.case
                );
            }
            None => {
                let text = served(row.case, &answer, row.session);
                assert!(
                    text.contains(&format!(
                        "{} result(s) returned under invocation {own_id}",
                        row.results
                    )),
                    "case {:?}: the served turn must report the results it took, got \
                     {text:?}",
                    row.case
                );
            }
        }
    }
}

/// RULE: every member of `inlineSessionState` is either SERVED — `invocationId` with
/// `returnControlInvocationResults`, the pair that answers an invocation the service
/// returned control for — or REFUSED by name; none is dropped and answered as if the work it
/// asks for had been done. A member that asks for work nothing here performs is refused
/// whether or not the served pair is there beside it.
#[tokio::test]
async fn every_inline_session_state_member_is_served_or_refused_by_name() {
    /// One session state and what the turn carrying it must answer.
    struct Row {
        case: &'static str,
        session: &'static str,
        /// The members to merge into the session state beside (optionally) the served pair.
        extra: Value,
        /// Whether the state also carries the issued id and one result.
        with_served_pair: bool,
        /// Whether the state carries the issued id ALONE, answering nothing with it.
        with_issued_id_only: bool,
        /// The member path a refusal must name, or `None` for a state that is served.
        refused_member: Option<&'static str>,
    }

    let rows = vec![
        Row {
            case: "attributes that persist across the session",
            session: "state-session-01",
            extra: json!({ "sessionAttributes": { "fleet": "west" } }),
            with_served_pair: false,
            with_issued_id_only: false,
            refused_member: Some("inlineSessionState.sessionAttributes"),
        },
        Row {
            case: "attributes that populate a prompt",
            session: "state-session-02",
            extra: json!({ "promptSessionAttributes": { "shift": "morning" } }),
            with_served_pair: false,
            with_issued_id_only: false,
            refused_member: Some("inlineSessionState.promptSessionAttributes"),
        },
        Row {
            case: "files for a code interpreter",
            session: "state-session-03",
            extra: json!({
                "files": [{
                    "name": "pump-specs.csv",
                    "useCase": "CODE_INTERPRETER",
                    "source": {
                        "sourceType": "BYTE_CONTENT",
                        "byteContent": { "mediaType": "text/csv", "data": "c2l0ZQo=" },
                    },
                }],
            }),
            with_served_pair: false,
            with_issued_id_only: false,
            refused_member: Some("inlineSessionState.files"),
        },
        Row {
            case: "a conversation history supplied by the caller",
            session: "state-session-04",
            extra: json!({
                "conversationHistory": {
                    "messages": [{ "role": "user", "content": [{ "text": "earlier turn" }] }],
                },
            }),
            with_served_pair: false,
            with_issued_id_only: false,
            refused_member: Some("inlineSessionState.conversationHistory"),
        },
        Row {
            case: "attributes smuggled in beside the served pair",
            session: "state-session-05",
            extra: json!({ "sessionAttributes": { "fleet": "west" } }),
            with_served_pair: true,
            with_issued_id_only: false,
            refused_member: Some("inlineSessionState.sessionAttributes"),
        },
        Row {
            case: "files smuggled in beside the served pair",
            session: "state-session-06",
            extra: json!({
                "files": [{
                    "name": "pump-specs.csv",
                    "useCase": "CODE_INTERPRETER",
                    "source": {
                        "sourceType": "BYTE_CONTENT",
                        "byteContent": { "mediaType": "text/csv", "data": "c2l0ZQo=" },
                    },
                }],
            }),
            with_served_pair: true,
            with_issued_id_only: false,
            refused_member: Some("inlineSessionState.files"),
        },
        Row {
            case: "the served pair alone",
            session: "state-session-07",
            extra: json!({}),
            with_served_pair: true,
            with_issued_id_only: false,
            refused_member: None,
        },
        Row {
            case: "a session state that carries nothing at all",
            session: "state-session-08",
            extra: json!({}),
            with_served_pair: false,
            with_issued_id_only: false,
            // It answers no invocation and names none, so the turn is served from the
            // request's own inputText, as it is with no session state at all.
            refused_member: None,
        },
        Row {
            case: "an invocationId alone, answering nothing",
            session: "state-session-09",
            extra: json!({}),
            with_served_pair: false,
            with_issued_id_only: true,
            refused_member: None,
        },
    ];

    let emulator = Emulator::new();
    let action_groups = json!([return_control_group(
        "LaunchCodeLookup",
        json!([function(
            "get_launch_code",
            json!({ "project": parameter("string", true) })
        )])
    )]);
    for row in rows {
        // Every row's first turn returns control, so the id the served pair carries is one
        // this conversation really issued.
        let first = emulator
            .invoke_inline_agent(
                ACCOUNT_KEY,
                row.session,
                invocation(action_groups.clone(), "carry out the action", false),
            )
            .await;
        let invocation_id = issued_invocation_id(row.case, &first);
        let mut state = json!({});
        if row.with_served_pair {
            state["invocationId"] = json!(invocation_id);
            state["returnControlInvocationResults"] = json!([{
                "functionResult": {
                    "actionGroup": "LaunchCodeLookup",
                    "function": "get_launch_code",
                    "responseBody": { "TEXT": { "body": "the launch code is 4815162342" } },
                },
            }]);
        }
        if row.with_issued_id_only {
            state["invocationId"] = json!(invocation_id);
        }
        if let Some(extra) = row.extra.as_object() {
            for (member, value) in extra {
                state[member] = value.clone();
            }
        }
        let mut body = invocation(action_groups.clone(), "summarise what came back", false);
        body["inlineSessionState"] = state;
        let answer = emulator
            .invoke_inline_agent(ACCOUNT_KEY, row.session, body)
            .await;
        match row.refused_member {
            Some(member) => {
                assert_eq!(
                    (answer.error_code(row.case).as_str(), answer.status),
                    ("ValidationException", 400),
                    "case {:?}: a member asking for work nothing performs is refused, got \
                     {} {:?}",
                    row.case,
                    answer.status,
                    answer.json(row.case)
                );
                assert!(
                    answer.message(row.case).contains(member),
                    "case {:?}: the refusal must name {member:?}, got {:?}",
                    row.case,
                    answer.message(row.case)
                );
            }
            None => {
                let text = served(row.case, &answer, row.session);
                if row.with_served_pair {
                    assert!(
                        text.contains(&format!(
                            "1 result(s) returned under invocation {invocation_id}"
                        )),
                        "case {:?}: the served pair must be taken, got {text:?}",
                        row.case
                    );
                } else {
                    // The request still declares the action group and answers no
                    // invocation, so the turn hands control back again rather than taking a
                    // result: a state that answers nothing changes nothing.
                    assert_eq!(
                        answer.event_keys(row.case),
                        vec!["returnControl".to_string()],
                        "case {:?}: a state answering nothing leaves the turn the one it \
                         would have been without it, got {:?}",
                        row.case,
                        answer.event_keys(row.case)
                    );
                    assert!(
                        !issued_invocation_id(row.case, &answer).is_empty(),
                        "case {:?}: that turn hands control back under an issued id",
                        row.case
                    );
                }
            }
        }
    }
}

/// RULE: `enableTrace` makes the turn report the orchestration step it performed — the
/// prompt it assembled, and the invocation it returned control for — and a request that
/// enables none carries no `trace` member.
#[tokio::test]
async fn enable_trace_reports_the_prompt_the_turn_was_assembled_from() {
    /// One invocation and what its trace must report.
    struct Row {
        case: &'static str,
        session: &'static str,
        enable_trace: bool,
        input_text: Option<&'static str>,
        /// Extra members merged into the request.
        extra: Value,
        /// Whether the turn also traces an action-group invocation it returned control for.
        traces_invocation: bool,
    }

    let rows = vec![
        Row {
            case: "a plain traced turn with no capability configured",
            session: "trace-session-01",
            enable_trace: true,
            input_text: Some("what is the pump service interval"),
            extra: json!({}),
            traces_invocation: false,
        },
        Row {
            case: "a traced turn carrying no inputText",
            session: "trace-session-02",
            enable_trace: true,
            input_text: None,
            extra: json!({}),
            traces_invocation: false,
        },
        Row {
            case: "a traced turn that returns control",
            session: "trace-session-03",
            enable_trace: true,
            input_text: Some("get the launch code for Falcon"),
            extra: json!({
                "actionGroups": [return_control_group(
                    "LaunchCodeLookup",
                    json!([function(
                        "get_launch_code",
                        json!({ "project": parameter("string", true) })
                    )]),
                )],
            }),
            traces_invocation: true,
        },
        Row {
            case: "a traced turn whose answer is streamed",
            session: "trace-session-04",
            enable_trace: true,
            input_text: Some("what is the pump service interval"),
            extra: json!({ "streamingConfigurations": { "streamFinalResponse": true } }),
            traces_invocation: false,
        },
        Row {
            case: "a traced turn configuring a knowledge base",
            session: "trace-session-05",
            enable_trace: true,
            input_text: Some("what does the manual say"),
            extra: json!({
                "knowledgeBases": [
                    { "knowledgeBaseId": "KB12345678", "description": "service manuals" },
                ],
            }),
            traces_invocation: false,
        },
        Row {
            case: "a turn that enables no trace",
            session: "trace-session-06",
            enable_trace: false,
            input_text: Some("what is the pump service interval"),
            extra: json!({}),
            traces_invocation: false,
        },
    ];

    let emulator = Emulator::new();
    for row in rows {
        let mut body = request(MODEL);
        if row.enable_trace {
            body["enableTrace"] = json!(true);
        }
        if let Some(input_text) = row.input_text {
            body["inputText"] = json!(input_text);
        }
        if let Some(extra) = row.extra.as_object() {
            for (member, value) in extra {
                body[member] = value.clone();
            }
        }
        let answer = emulator
            .invoke_inline_agent(ACCOUNT_KEY, row.session, body)
            .await;
        assert_eq!(
            answer.status, 200,
            "case {:?}: the turn must be served, got {} {:?}",
            row.case,
            answer.status,
            answer.json(row.case)
        );
        let traces = trace_payloads(row.case, &answer);
        if !row.enable_trace {
            assert!(
                traces.is_empty(),
                "case {:?}: a request that enables no trace carries no trace member, got \
                 {traces:?}",
                row.case
            );
            continue;
        }
        for trace in &traces {
            assert_eq!(
                trace["sessionId"].as_str(),
                Some(row.session),
                "case {:?}: a trace names the session it was performed in, got {trace:?}",
                row.case
            );
            let event_time = trace["eventTime"].as_str().unwrap_or_else(|| {
                panic!(
                    "case {:?}: eventTime travels in the modelled date-time form, got \
                     {trace:?}",
                    row.case
                )
            });
            assert!(
                event_time.contains('T') && event_time.contains(':'),
                "case {:?}: eventTime must be an ISO-8601 instant, got {event_time:?}",
                row.case
            );
        }
        let prompt = orchestration_prompt(row.case, &answer);
        assert!(
            prompt.contains(INSTRUCTION),
            "case {:?}: the traced prompt opens with the instruction the agent was composed \
             with, got {prompt:?}",
            row.case
        );
        assert!(
            prompt.contains(&format!("Session {}, turn 1", row.session)),
            "case {:?}: the traced prompt states the turn it was assembled for, got \
             {prompt:?}",
            row.case
        );
        match row.input_text {
            Some(input_text) => assert!(
                prompt.contains(input_text),
                "case {:?}: the traced prompt carries the input the turn was submitted \
                 with, got {prompt:?}",
                row.case
            ),
            None => assert!(
                !prompt.contains("User input"),
                "case {:?}: a turn with no input carries none in its prompt, got {prompt:?}",
                row.case
            ),
        }
        let step = trace_payloads(row.case, &answer)
            .into_iter()
            .filter_map(|payload| {
                payload
                    .get("trace")?
                    .get("orchestrationTrace")?
                    .get("modelInvocationInput")
                    .cloned()
            })
            .next()
            .expect("the traced prompt was already asserted to be there");
        assert_eq!(
            (step["type"].as_str(), step["foundationModel"].as_str()),
            (Some("ORCHESTRATION"), Some(MODEL)),
            "case {:?}: the traced step names the agent sequence step and the model it was \
             assembled for, got {step:?}",
            row.case
        );
        let invocations: Vec<Value> = trace_payloads(row.case, &answer)
            .into_iter()
            .filter_map(|payload| {
                payload
                    .get("trace")?
                    .get("orchestrationTrace")?
                    .get("invocationInput")
                    .cloned()
            })
            .collect();
        assert_eq!(
            !invocations.is_empty(),
            row.traces_invocation,
            "case {:?}: an action-group invocation is traced exactly when the turn returned \
             control for one, got {invocations:?}",
            row.case
        );
        if row.traces_invocation {
            let invocation_id = issued_invocation_id(row.case, &answer);
            let action = &invocations[0]["actionGroupInvocationInput"];
            assert_eq!(
                (
                    invocations[0]["invocationType"].as_str(),
                    action["actionGroupName"].as_str(),
                    action["function"].as_str(),
                    action["executionType"].as_str(),
                    action["invocationId"].as_str(),
                ),
                (
                    Some("ACTION_GROUP"),
                    Some("LaunchCodeLookup"),
                    Some("get_launch_code"),
                    Some(RETURN_CONTROL),
                    Some(invocation_id.as_str()),
                ),
                "case {:?}: the traced invocation must name the action it returned control \
                 for, got {:?}",
                row.case,
                invocations[0]
            );
        }
    }
}
