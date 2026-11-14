// SPDX-License-Identifier: CC0-1.0

//! The CPU-BOUND stage of a served inference call, run off the async worker.
//!
//! Counting a request's input tokens is a byte-pair encode over caller-supplied
//! prompt text ([`super::count_text_tokens`]), so its cost is the size of the
//! prompt the CALLER chose, up to the largest body the transport accepts. Run on
//! the worker serving the request it would hold that worker for as long as the
//! encode takes, and the health, timeout and shutdown paths with it, so every
//! surface composes its turn here instead: the whole stage — the input-token
//! count, the input-size refusal the count decides, the tool request the turn
//! makes, the prompt cache and the composed turn — runs on the blocking pool, and
//! the CALLER waits at most [`COMPOSITION_TIME_BUDGET`] for it. It is the pattern
//! the guardrail stage of the same handlers already follows for its own
//! caller-text work.
//!
//! Nothing about what is composed changes here: the stages run in the order the
//! handlers ran them in, so the same request earns the same refusal and the same
//! turn, and `Converse` and `ConverseStream` now compose one turn through ONE
//! function rather than through two copies of the sequence (likewise the two
//! invoke surfaces).

use super::*;

/// How long a caller waits for its own turn to be composed.
///
/// The ONE budget every CPU-bound stage of this service makes a caller wait for
/// ([`guardrail_checks::EVALUATION_TIME_BUDGET`]): the work is the same kind —
/// synchronous analysis of the text one request carries — so no stage may hold a
/// caller longer than another. It bounds what the CALLER waits for, not the work:
/// a blocking task cannot be cancelled from outside, so a task past the budget
/// runs to its natural end and releases its blocking-pool slot then.
pub const COMPOSITION_TIME_BUDGET: ::std::time::Duration =
    guardrail_checks::EVALUATION_TIME_BUDGET;

/// Why no turn was composed: the stage did not answer inside
/// [`COMPOSITION_TIME_BUDGET`], or the blocking pool could not run it.
///
/// The caller answers it with its own modelled server error, carrying
/// [`Self::message`] — nothing of the request reaches that sentence.
#[derive(Debug, Clone)]
pub struct CompositionFailed {
    pub message: String,
}

impl CompositionFailed {
    /// The sentence a stage that did not finish inside the budget is reported
    /// with.
    fn timed_out() -> Self {
        Self {
            message: format!(
                "the inference did not complete within {} seconds",
                COMPOSITION_TIME_BUDGET.as_secs()
            ),
        }
    }

    /// The sentence a stage the blocking pool could not run is reported with.
    fn not_run(error: impl ::std::fmt::Display) -> Self {
        Self {
            message: format!("the inference did not complete: {error}"),
        }
    }
}

/// One composed stage: the turn it served, or the sentence its refusal carries.
///
/// A refusal is the caller's own modelled `ValidationException` (400) — the
/// input-size stage's, or the tool stage's — stated in the words the stage that
/// made it owns.
#[derive(Debug, Clone)]
pub enum Composed<T> {
    Refused(String),
    Served(T),
}

/// Run one stage on the blocking pool, bounded by [`COMPOSITION_TIME_BUDGET`].
///
/// Every stage of this service that is synchronous, CPU-bound work over
/// caller-supplied text goes through here, so no such stage can be composed
/// without the blocking pool and the budget, and there is ONE place that owns
/// both. The caller words the failure itself from [`CompositionFailed::message`].
pub async fn off_worker<T, F>(stage: F) -> Result<T, CompositionFailed>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match ::tokio::time::timeout(
        COMPOSITION_TIME_BUDGET,
        ::tokio::task::spawn_blocking(stage),
    )
    .await
    {
        Ok(Ok(composed)) => Ok(composed),
        Ok(Err(error)) => Err(CompositionFailed::not_run(error)),
        Err(_) => Err(CompositionFailed::timed_out()),
    }
}

/// The Converse-API turn both Converse surfaces serve, composed off the worker.
///
/// The stages, in the order the surfaces ran them: the input tokens are counted,
/// an input past the model's context window is refused with the model-side
/// sentence, the tool request the turn makes is minted, the prompt cache is
/// served, and the turn is composed from all of it.
pub async fn compose_converse_turn(
    state: &::engine::ServiceState<ComAmazonawsBedrockruntimeAmazonbedrockfrontendserviceState>,
    model: &ModelEntry,
    system: Option<&Vec<SystemContentBlock>>,
    messages: Option<&Vec<Message>>,
    tool_config: Option<&ToolConfiguration>,
    inference_config: Option<&InferenceConfiguration>,
) -> Result<Composed<ConverseTurn>, CompositionFailed> {
    // Owned copies, because a blocking task outlives the borrow of the request
    // that started it.
    let state = state.clone();
    let model = model.clone();
    let system = system.cloned();
    let messages = messages.cloned();
    let tool_config = tool_config.cloned();
    let inference_config = inference_config.cloned();
    off_worker(move || {
        let submitted_tokens =
            converse_input_tokens(system.as_ref(), messages.as_ref(), tool_config.as_ref());
        if context_window::exceeds_context_window(&model, submitted_tokens) {
            return Composed::Refused(context_window::model_errors_message(
                context_window::INPUT_TOKENS_EXCEEDED_MESSAGE,
            ));
        }
        let tool_use = match state.lock().tool_use_for_turn(
            tool_config.as_ref(),
            messages.as_ref(),
            now_millis(),
        ) {
            Ok(tool_use) => tool_use,
            Err(message) => return Composed::Refused(message),
        };
        let cache = serve_prompt_cache(
            &state,
            &model.model_id,
            system.as_ref(),
            messages.as_ref(),
            tool_config.as_ref(),
        );
        Composed::Served(converse_turn(
            &model,
            messages.as_ref(),
            TurnInference::of(inference_config.as_ref()),
            tool_use,
            cache,
            submitted_tokens,
        ))
    })
    .await
}

/// The invoke-API inference both invoke surfaces serve, composed off the worker.
///
/// The stages, in the order the surfaces ran them: the body's prompt tokens are
/// counted, a body past the model's context window is refused, and the turn is
/// served from the body.
pub async fn compose_invoke_turn(
    model: &ModelEntry,
    family: ModelFamily,
    body: &[u8],
) -> Result<Composed<InvokeTurn>, CompositionFailed> {
    let model = model.clone();
    let body = body.to_vec();
    off_worker(move || {
        let input_tokens = body_input_tokens(&body);
        if context_window::exceeds_context_window(&model, input_tokens) {
            return Composed::Refused(context_window::INPUT_TOKENS_EXCEEDED_MESSAGE.to_string());
        }
        Composed::Served(invoke_turn(&model, family, &body, input_tokens))
    })
    .await
}

/// The tokens of an `InvokeModel` body, counted off the worker — what
/// `CountTokens` answers for that input.
pub async fn counted_body_tokens(body: &[u8]) -> Result<u32, CompositionFailed> {
    let body = body.to_vec();
    off_worker(move || body_input_tokens(&body)).await
}

/// The tokens of a `Converse`-shaped input, counted off the worker — what
/// `CountTokens` answers for that input.
pub async fn counted_converse_tokens(
    system: Option<&Vec<SystemContentBlock>>,
    messages: Option<&Vec<Message>>,
    tool_config: Option<&ToolConfiguration>,
) -> Result<u32, CompositionFailed> {
    let system = system.cloned();
    let messages = messages.cloned();
    let tool_config = tool_config.cloned();
    off_worker(move || {
        converse_input_tokens(system.as_ref(), messages.as_ref(), tool_config.as_ref())
    })
    .await
}
