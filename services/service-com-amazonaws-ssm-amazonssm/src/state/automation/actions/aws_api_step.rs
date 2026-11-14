// SPDX-License-Identifier: CC0-1.0

//! The ONE Amazon Web Services API call an `aws:executeAwsApi` step makes.
//!
//! "aws:executeAwsApi … calls and runs a single Amazon Web Services API action": the step
//! names the service and the API in its own inputs (`Service`, `Api`) and carries that API's
//! parameters beside them, so the call this makes is the one the step named, with the
//! parameters the walk resolved into it — document parameters and earlier steps' outputs
//! included, because the walk substitutes every `{{ … }}` reference before the step is parked
//! ([`super`]).
//!
//! The call is dispatched through the generic in-process AWS API seam this workspace already
//! has, which builds the request the CALLED service's own protocol describes, signs it as the
//! role the automation runs as, and hands it to this same emulator over the framework's
//! in-process callback — so the effect of the call is a real effect of the service that
//! served it, and a later read of that service sees it. Nothing leaves this process.
//!
//! What the step reports is that service's own answer: the declared outputs selected out of
//! the answer's document ([`super::selectors`]), or the service's own refusal as the step's
//! failure. A call that was NOT made — a service that seam does not reach, a request it could
//! not build, a span it did not finish in — is reported as a call that was not made rather
//! than as a step that produced anything.

use ::serde_json::{Map, Value};

use ::service_com_amazonaws_lambda_awsgirapiservice::state::execution::aws_api::{
    Answer, AwsAccess, Refusal,
};

use super::{selectors, text_input, ActionOutcome, ClaimedAction, ACTION_CEILING};

/// The step input naming the service whose API is called: "The Amazon Web Services service
/// namespace that contains the API operation you want to run" (`aws:executeAwsApi` inputs).
pub const SERVICE_INPUT: &str = "Service";

/// The step input naming the API operation: "The name of the API operation you want to run"
/// (same inputs).
pub const API_INPUT: &str = "Api";

/// The step inputs that are the ACTION's own rather than the called API's, so they are not
/// sent as parameters of the call.
const ACTION_INPUTS: &[&str] = &[SERVICE_INPUT, API_INPUT];

/// Make the call the step names and answer what the step came to.
pub async fn run(claimed: &ClaimedAction, access: Option<&AwsAccess>) -> ActionOutcome {
    let Some(service) = text_input(&claimed.inputs, SERVICE_INPUT) else {
        return missing(SERVICE_INPUT, claimed);
    };
    let Some(api) = text_input(&claimed.inputs, API_INPUT) else {
        return missing(API_INPUT, claimed);
    };
    let Some(access) = access else {
        return ActionOutcome::Failed(format!(
            "The {} action of step {} could not reach {service}:{api}: this emulator has no \
             in-process seam to dispatch the call on",
            claimed.action, claimed.step_name
        ));
    };
    // Everything the step declared besides the two action inputs IS the API's own input
    // document: "specify the API operation's parameters as inputs of the step".
    let mut parameters = Map::new();
    for (member, value) in &claimed.inputs {
        if !ACTION_INPUTS.contains(&member.as_str()) {
            parameters.insert(member.clone(), value.clone());
        }
    }
    let body = Value::Object(parameters).to_string();
    match access
        .call_within(&service, &api, &claimed.region, &body, ACTION_CEILING)
        .await
    {
        Ok(answer) if (200..300).contains(&answer.status) => served(claimed, &answer),
        Ok(answer) => ActionOutcome::Failed(client_error(&api, &answer)),
        Err(refusal) => ActionOutcome::Failed(format!(
            "The {} action of step {} could not call {service}:{api}: {}",
            claimed.action,
            claimed.step_name,
            not_made(&refusal)
        )),
    }
}

/// The step's outputs, selected out of the document the service answered.
///
/// An answer that is not a document at all carries no place a selector could name, so a step
/// that declared outputs over it is one whose outputs the service did not produce; a step
/// that declared none produces nothing and succeeds, which is what a call made for its effect
/// alone does.
fn served(claimed: &ClaimedAction, answer: &Answer) -> ActionOutcome {
    if claimed.outputs.is_empty() {
        return ActionOutcome::Succeeded(::std::collections::BTreeMap::new());
    }
    let document: Value = ::serde_json::from_str(&answer.body).unwrap_or(Value::Null);
    match selectors::selected(&document, &claimed.outputs) {
        Ok(selected) => ActionOutcome::Succeeded(selected),
        Err(why) => ActionOutcome::Failed(why),
    }
}

/// The step's failure for an API that REFUSED the call, worded the way the AWS SDK the real
/// action calls through words a refusal: `An error occurred (<code>) when calling the <Api>
/// operation: <message>`.
///
/// The code and the message are the called service's own, read off the answer it sent: the
/// error shape it named in its error-type header, or the one its body names, and the message
/// that body carries. Nothing of either is this emulator's.
fn client_error(api: &str, answer: &Answer) -> String {
    let document: Value = ::serde_json::from_str(&answer.body).unwrap_or(Value::Null);
    let code = answer
        .error_type
        .as_deref()
        .or_else(|| document.get("__type").and_then(Value::as_str))
        .map(error_code)
        .unwrap_or_else(|| format!("{}", answer.status));
    let message = ["message", "Message"]
        .into_iter()
        .filter_map(|member| document.get(member).and_then(Value::as_str))
        .next()
        .unwrap_or_default();
    format!("An error occurred ({code}) when calling the {api} operation: {message}")
}

/// The error CODE an error-type value names: a shape name, which an AWS answer may carry
/// with its namespace in front of it and the sending URL after it.
fn error_code(error_type: &str) -> String {
    error_type
        .split(':')
        .next()
        .unwrap_or(error_type)
        .split('#')
        .next_back()
        .unwrap_or(error_type)
        .to_string()
}

/// Why a call was not made at all, as the step reports it.
fn not_made(refusal: &Refusal) -> String {
    match refusal {
        Refusal::UnknownService => {
            "this emulator reaches no service of that name in process".to_string()
        }
        Refusal::UnknownOperation => "that is not a name an API operation carries".to_string(),
        Refusal::RequestTooLarge => {
            "the resolved parameters are larger than one call may carry".to_string()
        }
        Refusal::ResponseTooLarge => {
            "the answer is larger than one call may read back".to_string()
        }
        Refusal::TimedOut => format!(
            "the call did not finish inside the {} seconds one step may take",
            ACTION_CEILING.as_secs()
        ),
        Refusal::NotMade(detail) => detail.clone(),
    }
}

/// The step's failure for a step that named neither the service nor the API to call.
fn missing(member: &str, claimed: &ClaimedAction) -> ActionOutcome {
    ActionOutcome::Failed(format!(
        "The {} action of step {} declares no {member} to call",
        claimed.action, claimed.step_name
    ))
}
