// SPDX-License-Identifier: CC0-1.0

//! What an INLINE AGENT invocation reads and writes: the model it orchestrates with, the
//! conversation its `sessionId` addresses, and the text its response stream carries.
//!
//! An inline agent is composed BY THE REQUEST — "Invokes an inline Amazon Bedrock agent
//! using the configurations you provide with the request"
//! (`smithy_query(query="operation",operation="InvokeInlineAgent")`) — so there is no
//! stored agent to resolve and nothing here looks one up. What IS resolved is the
//! `foundationModel` the agent orchestrates with ([`resolve_model`]), read in the plane that
//! OWNS the model catalogue, so the models an inline agent can be composed against are
//! exactly the models this emulator serves inference from and the two planes cannot
//! disagree about which exist.
//!
//! What is WRITTEN is the conversation: "The unique identifier of the session. Use the same
//! value across requests to continue the same conversation"
//! (`InvokeInlineAgentRequest$sessionId`), so unlike the knowledge-base session of
//! [`super::knowledge_base_session`] the id is the CALLER's and a request carrying a fresh
//! one opens a conversation rather than being refused. Three rules follow, and all three
//! are the model's own:
//!
//! * a request carrying an id this store holds CONTINUES that conversation, appending its
//!   turn to the turns already recorded under it;
//! * a request whose `endSession` is `true` ends it — "Specifies whether to end the session
//!   with the inline agent or not" — and the conversation's turns are released with it;
//! * a conversation idle longer than its `idleSessionTTLInSeconds` is gone: "The number of
//!   seconds for which the inline agent should maintain session information. After this time
//!   expires, the subsequent `InvokeInlineAgent` request begins a new session. … If no
//!   conversation occurs during this time, the session expires and the data provided before
//!   the timeout is deleted" ([`expire_idle_conversations`]). That expiry is owed by the
//!   CLOCK at the same instant whether or not anybody calls, so it is materialised rather
//!   than decided per request.
//!
//! NO LANGUAGE MODEL RUNS IN THIS EMULATOR, and nothing here pretends otherwise. The text
//! the response stream carries is the notice the Bedrock Runtime plane of this same emulator
//! answers every inference surface with (`EMULATED_COMPLETION_FLOOR`, the one place that
//! sentence is worded), extended with the facts of the invocation that was really served:
//! the model the agent was composed against, which turn of which conversation it is, and
//! which of the capabilities the request configured went unused because no model elicited
//! them. It is never the caller's own `inputText` handed back as if an agent had replied,
//! and never prose synthesised to look like orchestration.
//!
//! What an action group whose executor is the CUSTOM CONTROL method asks for is the
//! exception to that, and it needs no model: "To return the action group invocation results
//! directly in the `InvokeInlineAgent` response, specify `RETURN_CONTROL`"
//! (`ActionGroupExecutor$customControl`) — the action is carried out by the CALLER, so the
//! service's half is to hand the invocation back and then take the results. Both halves are
//! here:
//!
//! * [`offered_functions`] reads the functions such an action group declares, straight from
//!   the request's own `functionSchema`, and the turn hands them back under an
//!   `invocationId` this plane issues and REMEMBERS on the conversation
//!   ([`InlineAgentSession::issue_invocation`]);
//! * [`returned_results`] reads the results the next turn's
//!   `inlineSessionState.returnControlInvocationResults` carries, which are accepted only
//!   under an `invocationId` this conversation really issued
//!   ([`InlineAgentSession::has_issued`]) and re-enter that turn's orchestration prompt
//!   ([`orchestration_prompt`]).
//!
//! No parameter VALUE is invented for an offered function: a value is what the model elicits
//! from the conversation, so what is handed back is the parameter the request declared — its
//! name and its data type — and nothing more.

use std::collections::BTreeMap;

use ::aws_smithy_types::DateTime;

use ::service_com_amazonaws_bedrockruntime_amazonbedrockfrontendservice::state as runtime_state;

use crate::ops::types::{
    ActionGroupExecutor, AgentActionGroup, FunctionSchema, InvocationResultMember,
};

/// Resource guard, NOT an AWS quota: the most inline-agent conversations this store holds at
/// once. The same guard the rest of this service's store declares
/// ([`crate::state::MAX_SESSIONS`]), and far above any plausible test or demo workload; past
/// it the invocation answers its modelled `ServiceQuotaExceededException` (HTTP 400) instead
/// of allocating.
pub const MAX_INLINE_AGENT_SESSIONS: usize = 1_000;

/// Resource guard: the most turns one inline-agent conversation records. See
/// [`MAX_INLINE_AGENT_SESSIONS`].
pub const MAX_TURNS_PER_INLINE_AGENT_SESSION: usize = 100;

/// The `idleSessionTTLInSeconds` a conversation is kept for when the opening request names
/// none.
///
/// CHOSEN, not documented: the API reference publishes only the member's valid range
/// (`range 60..3600`), so this is the emulator's own idle lifetime, inside that range.
pub const DEFAULT_IDLE_SESSION_TTL_SECONDS: i32 = 600;

/// How long a chunk of a STREAMED final response is, in characters.
///
/// The model documents the interval the response is chunked at on
/// `StreamingConfigurations$applyGuardrailInterval` — "By default, the guardrail interval is
/// set to 50 characters. If a larger interval is specified, the response will be generated
/// in larger chunks … Each chunk has at least 3 characters except for the last chunk"
/// (`smithy_query(query="shape",shape="StreamingConfigurations")`) — so the default interval
/// is what sizes a chunk when the request asks for the final response to be streamed and
/// configures no interval of its own.
pub const STREAMED_CHUNK_CHARACTERS: usize = 50;

/// One turn of a conversation with an inline agent: what the caller submitted, the model the
/// agent was composed against for it, and when it was served.
#[derive(Debug, Clone)]
pub struct InlineAgentTurn {
    /// How long the submitted `inputText` was, in characters — a fact about the request that
    /// was served, where the text itself is the caller's and is never handed back.
    pub input_characters: usize,
    /// The model the agent orchestrated with, as the catalogue spells its id.
    pub model_id: String,
    /// When the turn was served.
    pub at: DateTime,
}

/// One conversation with an inline agent, addressed by the `sessionId` the caller chose.
#[derive(Debug, Clone)]
pub struct InlineAgentSession {
    /// The `sessionId` the opening request carried.
    pub session_id: String,
    pub created_at: DateTime,
    /// When the last turn of the conversation was served, which is the instant the idle
    /// lifetime is measured from.
    pub last_used_at: DateTime,
    /// The idle lifetime the conversation is kept for, in seconds: the opening request's own
    /// `idleSessionTTLInSeconds`, or [`DEFAULT_IDLE_SESSION_TTL_SECONDS`] when it named none.
    pub idle_ttl_seconds: i32,
    /// The customer-managed key the opening request named, when it named one.
    pub encryption_key_arn: Option<String>,
    /// The turns taken in the conversation, oldest first.
    pub turns: Vec<InlineAgentTurn>,
    /// The `invocationId`s this conversation has RETURNED CONTROL under, oldest first.
    ///
    /// The model's own rule for the caller's half of the contract is what this is for:
    /// `inlineSessionState.invocationId` "must match the `invocationId` returned in the
    /// `InvokeInlineAgent` response for the action whose results are provided in the
    /// `returnControlInvocationResults` field", so the ids this conversation issued are the
    /// ids its later turns accept results under. Bounded by
    /// [`MAX_TURNS_PER_INLINE_AGENT_SESSION`]: a turn returns control at most once, and the
    /// conversation records at most that many turns.
    pub issued_invocations: Vec<String>,
}

impl InlineAgentSession {
    /// A conversation opened at `at` under the TTL and key its opening request named.
    pub fn opened(
        session_id: String,
        idle_ttl_seconds: i32,
        encryption_key_arn: Option<String>,
        at: DateTime,
    ) -> Self {
        Self {
            session_id,
            created_at: at,
            last_used_at: at,
            idle_ttl_seconds,
            encryption_key_arn,
            turns: Vec::new(),
            issued_invocations: Vec::new(),
        }
    }

    /// Record one served turn, which restarts the idle lifetime.
    pub fn record(&mut self, turn: InlineAgentTurn) {
        self.last_used_at = turn.at;
        self.turns.push(turn);
    }

    /// Remember that this conversation returned control under `invocation_id`, which is what
    /// lets a later turn of it carry the results of that invocation.
    pub fn issue_invocation(&mut self, invocation_id: String) {
        self.issued_invocations.push(invocation_id);
    }

    /// Whether this conversation really returned control under `invocation_id`.
    pub fn has_issued(&self, invocation_id: &str) -> bool {
        self.issued_invocations
            .iter()
            .any(|issued| issued == invocation_id)
    }

    /// The instant the conversation's idle lifetime ends: the last turn plus the TTL it is
    /// maintained for.
    pub fn expires_at(&self) -> DateTime {
        DateTime::from_secs(
            self.last_used_at
                .secs()
                .saturating_add(i64::from(self.idle_ttl_seconds)),
        )
    }

    /// Whether the clock has already ended this conversation's idle lifetime at `at`.
    pub fn has_expired(&self, at: DateTime) -> bool {
        at.secs() >= self.expires_at().secs()
    }
}

/// Release every conversation whose idle lifetime the clock has already ended.
///
/// Owed by the clock at the same instant whether or not anybody calls, so materialising it
/// changes nothing a caller could otherwise have observed: the next request for an expired
/// id begins a new session either way, which is what the member documents.
pub fn expire_idle_conversations(
    sessions: &mut BTreeMap<String, InlineAgentSession>,
    at: DateTime,
) {
    sessions.retain(|_, session| !session.has_expired(at));
}

/// Why an inline agent cannot be composed against the model a request names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestrationRefusal {
    /// The catalogue is not on this engine, so nothing can be said about the model —
    /// answered with a modelled server error, never with a client fault.
    StoreUnavailable,
    /// Not an identifier this emulator can read as naming a model it offers: a client input
    /// fault, answered with `ValidationException` (HTTP 400).
    InvalidModel(String),
    /// It names a model or a resource this emulator does not hold: answered with
    /// `ResourceNotFoundException` (HTTP 404).
    ModelNotFound(String),
}

/// The model `foundation_model` names, as the Bedrock Runtime data plane's catalogue holds
/// it.
///
/// `foundationModel` is "The model identifier (ID) of the model to use for orchestration",
/// and every spelling of such a reference — the bare model id, a cross-region
/// inference-profile id, a `foundation-model` ARN and an ARN of an account-scoped inference
/// resource — is read by the plane that OWNS the catalogue (`recognise_model`), which also
/// decides which failures are a 400 and which a 404.
///
/// What this operation needs of the reference is that it NAMES a model this emulator
/// publishes, because that is what makes the answer's statement of which model the agent was
/// bound to true. It does not need the model to serve INFERENCE: no model is invoked here,
/// and "a model id stays a recognised identifier after its model reaches end of life", so a
/// model past its end of life composes an inline agent while an identifier naming no model
/// at all does not. A model of a non-text modality is refused: it generates no turn of a
/// conversation at all, whatever ran it.
///
/// `member` is the member path the reference travelled in, so a refusal names the member the
/// request actually carried.
///
/// READ-ONLY: the catalogue is published, not stored per account, so nothing is written.
pub fn resolve_model<Eng: Send + Sync + 'static>(
    engine: &Eng,
    member: &str,
    foundation_model: &str,
) -> Result<String, OrchestrationRefusal> {
    let Some(runtime) = runtime_state::service_state(engine) else {
        return Err(OrchestrationRefusal::StoreUnavailable);
    };
    let guard = runtime.lock();
    match guard.recognise_model(foundation_model) {
        Ok(entry) if entry.modality != runtime_state::ModelModality::Text => {
            Err(OrchestrationRefusal::InvalidModel(format!(
                "{member}: {} generates {}, not text, so it orchestrates no inline agent turn",
                entry.model_id,
                entry.modality.label()
            )))
        }
        Ok(entry) => Ok(entry.model_id.clone()),
        Err(runtime_state::ModelRejection::Invalid(detail)) => {
            Err(OrchestrationRefusal::InvalidModel(format!("{member}: {detail}")))
        }
        Err(runtime_state::ModelRejection::NotFound(detail)) => {
            Err(OrchestrationRefusal::ModelNotFound(detail))
        }
    }
}

/// The `CustomControlMethod` an action group names when the CALLER carries its actions out
/// (`smithy_query(query="shape",shape="CustomControlMethod")` -> the one value,
/// `RETURN_CONTROL`), which is also the `ExecutionType` such an invocation is traced under.
pub const RETURN_CONTROL: &str = "RETURN_CONTROL";

/// The most invocation inputs ONE returned control hands back
/// (`smithy_query(query="shape",shape="InvocationInputs")` -> `@length` min 1, max 5). A
/// turn offering more functions than that hands back the first five, because the member
/// cannot carry more.
pub const MAX_INVOCATION_INPUTS: usize = 5;

/// The content type a returned result's body travels under when it is text
/// (`FunctionResult$responseBody` -> "The key of the object is the content type. You can
/// only specify one type"), which is the one form a prompt can read.
pub const TEXT_RESPONSE_BODY: &str = "TEXT";

/// One parameter of a function an action group offers, as the request DECLARED it.
///
/// No `value`: the value of a parameter is what a model elicits from the conversation, and
/// no model runs here, so none is invented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedParameter {
    /// The parameter name, as the `functionSchema` spells it.
    pub name: String,
    /// Its declared `ParameterType` (`string`, `number`, `integer`, `boolean`, `array`).
    pub parameter_type: String,
    /// Whether the function needs it to be fulfilled.
    pub required: bool,
}

/// One function a turn hands back to its caller: the action group that declared it, the
/// function itself, and the parameters it declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedFunction {
    pub action_group: String,
    pub function: String,
    /// The declared parameters, by name, so one turn's invocation inputs are ordered.
    pub parameters: Vec<OfferedParameter>,
}

/// Whether `group` is carried out by the CALLER: its `actionGroupExecutor` is the custom
/// control method, which is the only executor that returns the invocation in the response.
fn returns_control(group: &AgentActionGroup) -> bool {
    matches!(
        group.action_group_executor.as_ref(),
        Some(ActionGroupExecutor::customControl(method)) if method == RETURN_CONTROL
    )
}

/// The functions the turn hands back: every function declared by an action group whose
/// executor is the custom control method, in the order the request declared them, capped at
/// [`MAX_INVOCATION_INPUTS`].
///
/// An action group executed by a Lambda function offers none — its action is carried out by
/// that function, not by the caller — and one that declares no `functionSchema` offers none
/// either, because an action group's functions are what that member declares.
pub fn offered_functions(action_groups: &[AgentActionGroup]) -> Vec<OfferedFunction> {
    let mut offered: Vec<OfferedFunction> = Vec::new();
    for group in action_groups.iter().filter(|group| returns_control(group)) {
        let Some(FunctionSchema::Functions(functions)) = group.function_schema.as_ref() else {
            continue;
        };
        for function in functions {
            if offered.len() >= MAX_INVOCATION_INPUTS {
                return offered;
            }
            let mut parameters: Vec<OfferedParameter> = function
                .parameters
                .iter()
                .flatten()
                .map(|(name, detail)| OfferedParameter {
                    name: name.clone(),
                    parameter_type: detail.r#type.clone(),
                    required: detail.required == Some(true),
                })
                .collect();
            parameters.sort_by(|left, right| left.name.cmp(&right.name));
            offered.push(OfferedFunction {
                action_group: group.action_group_name.clone(),
                function: function.name.clone(),
                parameters,
            });
        }
    }
    offered
}

/// One result the CALLER returned for an invocation this service handed control for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedResult {
    /// The action group the result belongs to (`@required` on both result members).
    pub action_group: String,
    /// What the result answers for: the function that was called, or the API path of the
    /// operation that was.
    pub operation: Option<String>,
    /// The body the caller returned, when it returned one under a content type.
    pub body: Option<String>,
}

/// The one body a returned result carries: `responseBody` maps a content type to the body
/// under it and "you can only specify one type", so the `TEXT` entry is taken when there is
/// one and otherwise the lowest-named entry, which keeps the reading of a map deterministic.
fn result_body(
    response_body: Option<&std::collections::HashMap<String, crate::ops::types::ContentBody>>,
) -> Option<String> {
    let body = response_body?;
    let mut entries: Vec<(&String, &crate::ops::types::ContentBody)> = body.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    let chosen = entries
        .iter()
        .find(|(content_type, _)| content_type.as_str() == TEXT_RESPONSE_BODY)
        .or_else(|| entries.first())?;
    chosen.1.body.clone()
}

/// The results `inlineSessionState.returnControlInvocationResults` carries, read as the
/// prompt of the next turn reads them: which action group's function (or API operation) each
/// one answers for, and the body it returned.
pub fn returned_results(results: &[InvocationResultMember]) -> Vec<ReturnedResult> {
    results
        .iter()
        .map(|result| match result {
            InvocationResultMember::functionResult(function) => ReturnedResult {
                action_group: function.action_group.clone(),
                operation: function.function.clone(),
                body: result_body(function.response_body.as_ref()),
            },
            InvocationResultMember::apiResult(api) => ReturnedResult {
                action_group: api.action_group.clone(),
                operation: api.api_path.clone(),
                body: result_body(api.response_body.as_ref()),
            },
        })
        .collect()
}

/// The refusal a session state earns when the invocation its results answer is not one this
/// conversation returned control under: an `invocationId` no response of it issued, or
/// results carrying none at all.
///
/// THE SOURCE OF THIS WORDING is the rule the MODEL states on the member, which is the
/// requirement where no refusal of AWS's is recorded for the member: `invocationId` "must
/// match the `invocationId` returned in the `InvokeInlineAgent` response for the action
/// whose results are provided in the `returnControlInvocationResults` field"
/// (`smithy_query(query="shape",shape="InlineSessionState")`). The sentence names the member
/// and, when the request carried one, the identifier it submitted — taken from the request,
/// never from any one exchange — so the caller can fix the request from the text alone.
pub fn unissued_invocation_message(submitted: Option<&str>) -> String {
    let opening = match submitted {
        Some(invocation_id) => {
            format!("inlineSessionState.invocationId: {invocation_id} does not match an")
        }
        None => "inlineSessionState.invocationId: it is required alongside \
                 returnControlInvocationResults and must match the"
            .to_string(),
    };
    format!(
        "{opening} invocationId returned in the InvokeInlineAgent response for the action \
         whose results are provided in the returnControlInvocationResults field"
    )
}

/// The results an earlier invocation of the conversation was answered with, under the id it
/// was issued as.
#[derive(Debug, Clone)]
pub struct ReturnedInvocation {
    pub invocation_id: String,
    pub results: Vec<ReturnedResult>,
}

/// The facts of one served invocation the response stream reports.
#[derive(Debug, Clone)]
pub struct ServedInvocation {
    /// The conversation the turn was served in.
    pub session_id: String,
    /// The model the agent orchestrated with, as the catalogue spells its id.
    pub model_id: String,
    /// The `agentName` the request composed the agent under, when it named one.
    pub agent_name: Option<String>,
    /// Which turn of the conversation this is, counting from one.
    pub turn: usize,
    /// How many action groups the request configured.
    pub action_groups: usize,
    /// How many knowledge bases the request configured, none of which was queried.
    pub knowledge_bases: usize,
    /// Whether this request ended the conversation.
    pub session_ended: bool,
    /// Whether the request asked for the orchestration TRACE.
    pub trace_requested: bool,
    /// The `instruction` the agent was composed with, which the orchestration prompt opens
    /// with.
    pub instruction: String,
    /// The `inputText` the turn was submitted with, when it carried one.
    pub input_text: Option<String>,
    /// When the turn was served.
    pub at: DateTime,
    /// The functions the request's return-control action groups offer the caller, which are
    /// the actions this turn can hand back.
    pub offered: Vec<OfferedFunction>,
    /// The identifier this turn handed those functions back under, when it handed them back:
    /// a turn that carries the results of an earlier invocation answers instead of handing
    /// control back again.
    pub returned_control: Option<String>,
    /// The results the caller returned for an earlier invocation of this conversation, when
    /// the request carried them.
    pub returned: Option<ReturnedInvocation>,
}

/// The text the `chunk` events of a served invocation carry: that no model ran, the model
/// the agent was composed against, which turn of which conversation was served, which
/// configured capabilities went unused, what a requested trace reports, which returned
/// results re-entered the turn, and whether the conversation was ended.
///
/// The caller's own `inputText` is NOT part of it: a prompt handed back would read as an
/// agent that had replied to it.
pub fn completion_notice(served: &ServedInvocation) -> String {
    let agent = match served.agent_name.as_deref() {
        Some(name) => format!("named {name}"),
        None => "this request composed".to_string(),
    };
    let mut notice = format!(
        "{} The inline agent {agent} is bound to {} and generated no response: this was \
         turn {} of session {}.",
        runtime_state::EMULATED_COMPLETION_FLOOR, served.model_id, served.turn, served.session_id
    );
    if served.action_groups > 0 || served.knowledge_bases > 0 {
        notice.push_str(&format!(
            " The {} action group(s) and {} knowledge base(s) this request configured went \
             unused: an action is carried out, and a knowledge base queried, only once a \
             model elicits one.",
            served.action_groups, served.knowledge_bases
        ));
    }
    if let Some(returned) = served.returned.as_ref() {
        notice.push_str(&format!(
            " The {} result(s) returned under invocation {} re-entered this turn's \
             orchestration prompt.",
            returned.results.len(),
            returned.invocation_id
        ));
    }
    if served.trace_requested {
        notice.push_str(
            " The trace this request enabled reports the prompt this turn was assembled \
             from: the orchestration steps past it are a model's, and no model took any.",
        );
    }
    if served.session_ended {
        notice.push_str(" The session was ended by this request.");
    }
    notice
}

/// `notice` split into the chunks a STREAMED final response is delivered in: successive
/// runs of [`STREAMED_CHUNK_CHARACTERS`] characters, the last one carrying what is left, so
/// the chunks concatenate back to exactly `notice`.
///
/// Split on CHARACTERS rather than bytes, because the interval the model documents is a
/// character count.
pub fn streamed_chunks(notice: &str) -> Vec<String> {
    let characters: Vec<char> = notice.chars().collect();
    if characters.is_empty() {
        return vec![String::new()];
    }
    characters
        .chunks(STREAMED_CHUNK_CHARACTERS)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// The `PromptType` the orchestration step of the agent sequence is traced under
/// (`smithy_query(query="shape",shape="PromptType")` -> PRE_PROCESSING, ORCHESTRATION,
/// KNOWLEDGE_BASE_RESPONSE_GENERATION, POST_PROCESSING, ROUTING_CLASSIFIER).
pub const ORCHESTRATION_PROMPT_TYPE: &str = "ORCHESTRATION";

/// The `CreationMode` of a prompt no `promptOverrideConfiguration` replaced
/// (`smithy_query(query="shape",shape="CreationMode")` -> DEFAULT, OVERRIDDEN); this
/// service refuses an override, so every prompt it assembles is the default one.
pub const DEFAULT_PROMPT_CREATION_MODE: &str = "DEFAULT";

/// The `InvocationType` an action-group step is traced under
/// (`smithy_query(query="shape",shape="InvocationType")` -> ACTION_GROUP, KNOWLEDGE_BASE,
/// FINISH, ACTION_GROUP_CODE_INTERPRETER, AGENT_COLLABORATOR).
pub const ACTION_GROUP_INVOCATION_TYPE: &str = "ACTION_GROUP";

/// The identifier one traced step of a turn carries.
///
/// The modelled `TraceId` is a string of 2..16 characters
/// (`smithy_query(query="shape",shape="TraceId")`), too short for a UUID, so a step is
/// identified by the turn it belongs to and its position in that turn — unique inside the
/// conversation the trace reports on, which is what a trace reader correlates by.
pub fn trace_id(turn: usize, step: usize) -> String {
    format!("{turn}-{step}")
}

/// The prompt the turn was assembled from, which `enableTrace` reports as the orchestration
/// step's `modelInvocationInput.text`.
///
/// Assembled from the REQUEST and this conversation's state, never from anything a model
/// produced: the instruction the agent was composed with, the conversation and turn the
/// prompt was assembled for, the actions the caller can carry out, the input the caller
/// submitted, and the results the caller returned for an earlier invocation — which is what
/// makes a returned result observably re-enter the next turn's prompt.
pub fn orchestration_prompt(served: &ServedInvocation) -> String {
    let mut prompt = format!("Instruction: {}\n", served.instruction);
    prompt.push_str(&format!(
        "Session {}, turn {}, orchestrated with {}.\n",
        served.session_id, served.turn, served.model_id
    ));
    for function in &served.offered {
        let parameters: Vec<String> = function
            .parameters
            .iter()
            .map(|parameter| {
                let requirement = if parameter.required {
                    "required"
                } else {
                    "optional"
                };
                format!(
                    "{} ({}, {requirement})",
                    parameter.name, parameter.parameter_type
                )
            })
            .collect();
        prompt.push_str(&format!(
            "Action: {}.{} returns control to the caller; parameters: {}.\n",
            function.action_group,
            function.function,
            if parameters.is_empty() {
                "none declared".to_string()
            } else {
                parameters.join(", ")
            }
        ));
    }
    if let Some(input_text) = served.input_text.as_deref() {
        prompt.push_str(&format!("User input: {input_text}\n"));
    }
    if let Some(returned) = served.returned.as_ref() {
        for result in &returned.results {
            prompt.push_str(&format!(
                "Result of {}.{} under invocation {}: {}\n",
                result.action_group,
                result.operation.as_deref().unwrap_or_default(),
                returned.invocation_id,
                result.body.as_deref().unwrap_or_default()
            ));
        }
    }
    prompt
}
