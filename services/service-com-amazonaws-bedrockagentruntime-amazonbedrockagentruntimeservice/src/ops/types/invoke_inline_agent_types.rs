// SPDX-License-Identifier: CC0-1.0

//! Type definitions reached only by the `invoke_inline_agent` operation, HAND-AUTHORED:
//! the op-stub generator declined `InvokeInlineAgent` because its output carries a
//! `@streaming` event-stream member it cannot frame (`../SKIPPED_STUBS.md`), and an
//! operation with no types and no handler is not in the service's routing table at all —
//! so nothing validated this operation's own request.
//!
//! The split follows the one the other hand-authored streaming surfaces in this tree use
//! (`agentic_retrieve_stream_types.rs`): the members the framework's own codec can read are
//! declared, so this operation's `@required`, `@length`, `@range`, `@pattern` and ENUM
//! members are checked against the MODEL rather than by hand, and the event stream sits in
//! `unsupported = [..]`, which keeps it out of the schema. The EVENT the stream carries is
//! declared here, because the handler frames it itself.
//!
//! Every configuration the handler has to REFUSE or report on is declared rather than left
//! unsupported: a member the schema drops is one the handler cannot see, and a request
//! asking for work this emulator performs none of has to be refused rather than served with
//! the member ignored. Where only the PRESENCE of such a configuration decides what the
//! handler does, its deeper members are unsupported — that is what each
//! `unsupported = [..]` list below is.
#![allow(unused_imports)]

use super::*;

smithy_macros::smithy_model!("smithy-model/com-amazonaws-bedrockagentruntime-amazonbedrockagentruntimeservice.json");

/// `InvokeInlineAgentRequest`: the `sessionId` URI label, the model and instruction the
/// inline agent is composed from, and every configuration the request may carry.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#InvokeInlineAgentRequest")]
#[derive(Debug, Clone, Default)]
pub struct InvokeInlineAgentInput {
    pub session_id: String,
    pub foundation_model: String,
    pub instruction: String,
    pub customer_encryption_key_arn: Option<String>,
    pub idle_session_ttl_in_seconds: Option<i32>,
    pub agent_collaboration: Option<String>,
    pub agent_name: Option<String>,
    pub end_session: Option<bool>,
    pub enable_trace: Option<bool>,
    pub input_text: Option<String>,
    pub orchestration_type: Option<String>,
    pub action_groups: Option<Vec<AgentActionGroup>>,
    pub knowledge_bases: Option<Vec<KnowledgeBase>>,
    pub guardrail_configuration: Option<GuardrailConfigurationWithArn>,
    pub prompt_override_configuration: Option<PromptOverrideConfiguration>,
    pub collaborator_configurations: Option<Vec<CollaboratorConfiguration>>,
    pub collaborators: Option<Vec<Collaborator>>,
    pub inline_session_state: Option<InlineSessionState>,
    pub streaming_configurations: Option<StreamingConfigurations>,
    pub prompt_creation_configurations: Option<PromptCreationConfigurations>,
    pub bedrock_model_configurations: Option<InlineBedrockModelConfigurations>,
    pub custom_orchestration: Option<CustomOrchestration>,
}

/// The header half of `InvokeInlineAgentResponse`; `completion` is the `@streaming`
/// `@httpPayload`, which the handler frames itself, so the declared half carries the two
/// modelled response headers.
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#InvokeInlineAgentResponse",
    unsupported = ["completion"]
)]
#[derive(Debug, Clone, Default)]
pub struct InvokeInlineAgentOutput {
    pub content_type: String,
    pub session_id: String,
}

/// One action group of the inline agent, with the two members that decide whether this
/// invocation can hand the action back to its caller: `actionGroupExecutor` says HOW an
/// action is carried out — a Lambda function, or the custom control method that returns the
/// invocation to the caller — and `functionSchema` declares the functions it offers.
///
/// `apiSchema` and the computer-use parameters stay unsupported: an API-schema action group
/// names its operations inside an OpenAPI document nothing here parses, so no operation of
/// one can be elicited.
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#AgentActionGroup",
    unsupported = ["apiSchema", "parentActionGroupSignatureParams"]
)]
#[derive(Debug, Clone, Default)]
pub struct AgentActionGroup {
    pub action_group_name: String,
    pub description: Option<String>,
    pub parent_action_group_signature: Option<String>,
    pub action_group_executor: Option<ActionGroupExecutor>,
    pub function_schema: Option<FunctionSchema>,
}

/// `ActionGroupExecutor`: how an action of the group is carried out — the Lambda function
/// holding its business logic, or the custom control method that hands the invocation back
/// to the caller instead ("To return the action group invocation results directly in the
/// `InvokeInlineAgent` response, specify `RETURN_CONTROL`",
/// `smithy_query(query="shape",shape="ActionGroupExecutor")`).
#[smithy_macros::smithy(union_for = "com.amazonaws.bedrockagentruntime#ActionGroupExecutor")]
#[derive(Debug, Clone)]
pub enum ActionGroupExecutor {
    Lambda(String),
    customControl(String),
}

/// `FunctionSchema`: the functions an action group declares, each one an action of it.
#[smithy_macros::smithy(union_for = "com.amazonaws.bedrockagentruntime#FunctionSchema")]
#[derive(Debug, Clone)]
pub enum FunctionSchema {
    Functions(Vec<FunctionDefinition>),
}

/// One function of an action group: its name, and the parameters the agent elicits to
/// fulfill it.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#FunctionDefinition")]
#[derive(Debug, Clone, Default)]
pub struct FunctionDefinition {
    pub name: String,
    pub description: Option<String>,
    pub parameters: Option<std::collections::HashMap<String, ParameterDetail>>,
    pub require_confirmation: Option<String>,
}

/// One parameter of such a function: its data type, and whether the function needs it.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#ParameterDetail")]
#[derive(Debug, Clone, Default)]
pub struct ParameterDetail {
    pub description: Option<String>,
    pub r#type: String,
    pub required: Option<bool>,
}

/// One knowledge base the inline agent may query.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#KnowledgeBase")]
#[derive(Debug, Clone, Default)]
pub struct KnowledgeBase {
    pub knowledge_base_id: String,
    pub description: String,
    pub retrieval_configuration: Option<KnowledgeBaseRetrievalConfiguration>,
}

/// The guardrail an inline agent invocation asks to be governed by.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#GuardrailConfigurationWithArn")]
#[derive(Debug, Clone, Default)]
pub struct GuardrailConfigurationWithArn {
    pub guardrail_identifier: String,
    pub guardrail_version: String,
}

/// The prompt templates an invocation overrides. `promptConfigurations` is unsupported: the
/// handler only has to see THAT a request overrides a prompt, because no prompt is read
/// here, so which part of the sequence is overridden changes nothing it could answer.
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#PromptOverrideConfiguration",
    unsupported = ["promptConfigurations"]
)]
#[derive(Debug, Clone, Default)]
pub struct PromptOverrideConfiguration {
    pub override_lambda: Option<String>,
}

/// The settings of one inline collaborator agent.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#CollaboratorConfiguration")]
#[derive(Debug, Clone, Default)]
pub struct CollaboratorConfiguration {
    pub collaborator_name: String,
    pub collaborator_instruction: String,
    pub agent_alias_arn: Option<String>,
    pub relay_conversation_history: Option<String>,
}

/// One inline collaborator agent of a supervisor invocation.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#Collaborator")]
#[derive(Debug, Clone, Default)]
pub struct Collaborator {
    pub customer_encryption_key_arn: Option<String>,
    pub foundation_model: String,
    pub instruction: String,
    pub idle_session_ttl_in_seconds: Option<i32>,
    pub action_groups: Option<Vec<AgentActionGroup>>,
    pub knowledge_bases: Option<Vec<KnowledgeBase>>,
    pub guardrail_configuration: Option<GuardrailConfigurationWithArn>,
    pub prompt_override_configuration: Option<PromptOverrideConfiguration>,
    pub agent_collaboration: Option<String>,
    pub collaborator_configurations: Option<Vec<CollaboratorConfiguration>>,
    pub agent_name: Option<String>,
}

/// `InlineSessionState`, declared MEMBER FOR MEMBER, because every one of them either is
/// served or has to be refused — a member the schema drops is one the handler cannot see:
///
/// * `invocationId`, which "must match the `invocationId` returned in the
///   `InvokeInlineAgent` response", and `returnControlInvocationResults` (`@length` 1..5),
///   the results themselves, are SERVED: they answer an action-group invocation this service
///   returned control for, and re-enter the next turn's orchestration prompt;
/// * `sessionAttributes` and `promptSessionAttributes` replace the placeholders of a prompt
///   nothing reads, `files` are read by a code interpreter nothing runs, and
///   `conversationHistory` replaces the conversation this plane records itself, so a request
///   carrying any of those is REFUSED rather than served with the member ignored.
///
/// The four refused ones are declared for their PRESENCE alone — what the handler has to
/// know is that the request asked for that work — so `InputFile` and `ConversationHistory`
/// are declared the same way.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#InlineSessionState")]
#[derive(Debug, Clone, Default)]
pub struct InlineSessionState {
    pub session_attributes: Option<std::collections::HashMap<String, String>>,
    pub prompt_session_attributes: Option<std::collections::HashMap<String, String>>,
    pub return_control_invocation_results: Option<Vec<InvocationResultMember>>,
    pub invocation_id: Option<String>,
    pub files: Option<Vec<InputFile>>,
    pub conversation_history: Option<ConversationHistory>,
}

/// `InputFile`, declared for its PRESENCE alone: the file's name, its source and its use
/// case describe what a code interpreter would read it for, and nothing here runs one.
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#InputFile",
    unsupported = ["name", "source", "useCase"]
)]
#[derive(Debug, Clone, Default)]
pub struct InputFile {}

/// `ConversationHistory`, declared for its PRESENCE alone: its `messages` would replace the
/// conversation this plane records from the turns it really served.
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#ConversationHistory",
    unsupported = ["messages"]
)]
#[derive(Debug, Clone, Default)]
pub struct ConversationHistory {}

/// `InlineBedrockModelConfigurations`: the settings for the model the inline agent calls.
/// Its one member names a latency profile, which does not change what an answer says.
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#InlineBedrockModelConfigurations"
)]
#[derive(Debug, Clone, Default)]
pub struct InlineBedrockModelConfigurations {
    pub performance_config: Option<PerformanceConfiguration>,
}

/// `CustomOrchestration`, declared for its PRESENCE alone: its `executor` names the
/// function that would drive the orchestration, and nothing orchestrates here, so the
/// handler only has to see that a request configured one.
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#CustomOrchestration",
    unsupported = ["executor"]
)]
#[derive(Debug, Clone, Default)]
pub struct CustomOrchestration {}

/// The `chunk` member of the inline agent's response stream: one part of the agent's
/// answer, and the citations for it.
#[smithy_macros::smithy(shape = "com.amazonaws.bedrockagentruntime#InlineAgentPayloadPart")]
#[derive(Debug, Clone, Default)]
pub struct InlineAgentPayloadPart {
    pub bytes: Option<Vec<u8>>,
    pub attribution: Option<Attribution>,
}

/// The `returnControl` member of that stream: the invocation the agent hands back to the
/// caller, carrying the identifier the caller answers it under and one input per function
/// the agent elicited (`invocationInputs`, `@length` 1..5).
#[smithy_macros::smithy(
    shape = "com.amazonaws.bedrockagentruntime#InlineAgentReturnControlPayload"
)]
#[derive(Debug, Clone, Default)]
pub struct InlineAgentReturnControlPayload {
    pub invocation_inputs: Option<Vec<InvocationInputMember>>,
    pub invocation_id: Option<String>,
}

/// The `trace` member of that stream: one part of the orchestration the turn performed, in
/// the conversation it was performed in, at the instant it happened.
///
/// `callerChain` and `collaboratorName` are left out for the reason the handler refuses
/// `collaborators`: nothing here orchestrates a collaboration, so no trace of this service's
/// belongs to another agent. Its schema and codec come from
/// [`session_schema_and_codec!`] rather than `#[smithy_macros::smithy(shape = ...)]` because
/// `eventTime` carries `@timestampFormat("date-time")`
/// (`smithy_query(query="shape",shape="InlineAgentTracePart")`), which the derive does not
/// put on a member schema — see `types/date_time_wire.rs` for that whole story.
#[derive(Debug, Clone)]
pub struct InlineAgentTracePart {
    pub session_id: Option<String>,
    pub trace: Option<Trace>,
    pub event_time: Option<::aws_smithy_types::DateTime>,
}

session_schema_and_codec!(
    InlineAgentTracePart,
    INLINE_AGENT_TRACE_PART_SCHEMA,
    "com.amazonaws.bedrockagentruntime#InlineAgentTracePart",
    "com.amazonaws.bedrockagentruntime",
    "InlineAgentTracePart",
    (M_SESSION_ID, session_id, "sessionId", 0, opt, string),
    (M_TRACE, trace, "trace", 1, opt, union_of(Trace)),
    (M_EVENT_TIME, event_time, "eventTime", 2, opt, date_time),
);
