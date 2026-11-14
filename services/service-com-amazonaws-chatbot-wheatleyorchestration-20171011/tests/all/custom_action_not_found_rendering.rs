// SPDX-License-Identifier: CC0-1.0

//! How each custom-action operation RENDERS the modelled 404 it answers for one of this
//! account's custom-action ARNs that holds no action, driven over the wire (restJson1)
//! through the same `MultiServiceRouter` the production router serves with.
//!
//! The rule every assertion here is about: a not-found refusal carries the message AWS
//! Chatbot words for THAT operation's own error class — `GetCustomAction` speaks of an
//! action not found for the account, `UpdateCustomAction` of an action that does not exist
//! in the account, and `DeleteCustomAction` words NOTHING, so its document states no message
//! text at all — rather than one sentence shared across the operations on the resource. The
//! variable parts of a stated sentence are the action name taken from the requested
//! `CustomActionArn` and the account id serving the request; the status (404) and the error
//! code (`ResourceNotFoundException`, `errorKind` client, `httpError` 404 —
//! `smithy_query(query="operation",operation="GetCustomAction,UpdateCustomAction,DeleteCustomAction")`)
//! are the same for all three.
//!
//! The table spans what the rule generalises over rather than one recorded request: it
//! crosses every custom-action operation that can answer this error with action names
//! differing in length (both published bounds of `CustomActionName`, len 1..64, included)
//! and charset, and it asserts the rendering twice over — for a name nothing was ever
//! created under, and for an action that was created and then deleted, which the store
//! cannot tell apart.

use serde_json::{json, Value};

use crate::wire::{Answer, Emulator};

/// The canonical emulator account id (`emulator_server::EMULATOR_ACCOUNT_ID`), spelled out
/// here so the test pins the account a client actually reads in the sentence.
const ACCOUNT: &str = "000000000000";

const CREATE_PATH: &str = "/create-custom-action";

/// The modelled error every row expects (`smithy_query` shape=ResourceNotFoundException,
/// whose single member is the optional `Message`).
const RESOURCE_NOT_FOUND_EXCEPTION: &str = "ResourceNotFoundException";

/// A custom action is account-scoped, so the ARN a create mints carries an EMPTY region
/// segment (`state::custom_action_arn`).
fn custom_action_arn(action_name: &str) -> String {
    format!("arn:aws:chatbot::{ACCOUNT}:custom-action/{action_name}")
}

/// One operation addressed by a `CustomActionArn` that can answer the modelled 404, and the
/// message its own error class words for it.
struct Rendering {
    label: &'static str,
    path: &'static str,
    /// The request body addressing `arn`, carrying whatever else the operation requires.
    request: fn(&str) -> Value,
    /// The `Message` the operation's error class states for the action named by the ARN, or
    /// `None` for the operation AWS Chatbot words nothing for.
    message: fn(&str) -> Option<String>,
}

/// Every operation addressed by a custom-action ARN whose miss is the modelled 404, with the
/// sentence each one words.
fn renderings() -> Vec<Rendering> {
    vec![
        Rendering {
            label: "the read",
            path: "/get-custom-action",
            request: |arn| json!({"CustomActionArn": arn}),
            message: |action_name| {
                Some(format!(
                    "sdk action [{action_name}] not found for account [{ACCOUNT}]"
                ))
            },
        },
        Rendering {
            label: "the update",
            path: "/update-custom-action",
            request: |arn| {
                json!({
                    "CustomActionArn": arn,
                    "Definition": {"CommandText": "s3 ls"},
                })
            },
            message: |action_name| {
                Some(format!(
                    "Sdk action with id [{action_name}] does not exist in account [{ACCOUNT}]"
                ))
            },
        },
        Rendering {
            label: "the delete",
            path: "/delete-custom-action",
            request: |arn| json!({"CustomActionArn": arn}),
            // The one operation on this resource AWS Chatbot words no sentence for: its
            // document states no message text, and never borrows the read's or the update's.
            message: |_| None,
        },
    ]
}

/// The action names the table runs every operation over: the published bounds of
/// `CustomActionName` (len 1..64) and the charset its pattern admits (`^[A-Za-z0-9_-]+$`),
/// so no answer can follow from one spelling of the name.
fn action_names() -> Vec<String> {
    vec![
        "never-created".to_string(),
        "a".to_string(),
        "z".repeat(64),
        "Mixed_Case-9".to_string(),
        "under_score_1".to_string(),
    ]
}

/// The message text a stated sentence reads, or `None` where the error states none — an
/// absent member and the explicit null this service's error document carries for a class
/// that words none (`src/service/wire.rs`) are both "no message stated".
fn stated_message(answer: &Answer) -> Option<&str> {
    answer.body.get("Message").and_then(Value::as_str)
}

/// Assert `answer` is the modelled 404 `rendering` words for the action `arn` names.
fn assert_rendered(rendering: &Rendering, case: &str, arn: &str, answer: &Answer) {
    assert_eq!(
        answer.status, 404,
        "case {case:?} on {} ({arn}): expected HTTP 404, got {} with {}",
        rendering.path, answer.status, answer.body
    );
    assert_eq!(
        answer.error_type.as_deref(),
        Some(RESOURCE_NOT_FOUND_EXCEPTION),
        "case {case:?} on {} ({arn}): expected x-amzn-errortype \
         {RESOURCE_NOT_FOUND_EXCEPTION}, got {:?}",
        rendering.path,
        answer.error_type
    );
    assert_eq!(
        answer.code(),
        RESOURCE_NOT_FOUND_EXCEPTION,
        "case {case:?} on {} ({arn}): expected the modelled {RESOURCE_NOT_FOUND_EXCEPTION}, \
         got {}",
        rendering.path,
        answer.body
    );

    let action_name = arn
        .rsplit('/')
        .next()
        .unwrap_or_else(|| panic!("case {case:?}: {arn} names no custom action"));
    let expected = (rendering.message)(action_name);
    assert_eq!(
        stated_message(answer),
        expected.as_deref(),
        "case {case:?} on {} ({arn}): expected the message {expected:?} this operation's \
         error class words, got {}",
        rendering.path,
        answer.body
    );
    if expected.is_none() {
        // An error class this service words nothing for reports its message member as an
        // explicit null rather than dropping the key, so a client can tell "this class
        // states no message" from "the member was not reported at all"
        // (`src/service/wire.rs`).
        assert_eq!(
            answer.body.get("Message"),
            Some(&Value::Null),
            "case {case:?} on {} ({arn}): this error class states no message, so the member \
             is reported as a null, got {}",
            rendering.path,
            answer.body
        );
    }

    // `ResourceNotFoundException` declares only the capitalised member (`smithy_query`
    // shape=ResourceNotFoundException), so the lowercase spelling other services use is
    // never reported here.
    assert_eq!(
        answer.body.get("message"),
        None,
        "case {case:?} on {} ({arn}): this error class declares no lowercase member, got {}",
        rendering.path,
        answer.body
    );
}

/// Every sentence any of the operations words for `action_name`, so a row can assert the one
/// it got is not another operation's.
fn every_other_sentence(label: &str, action_name: &str) -> Vec<String> {
    renderings()
        .iter()
        .filter(|rendering| rendering.label != label)
        .filter_map(|rendering| (rendering.message)(action_name))
        .collect()
}

#[tokio::test]
async fn each_custom_action_operation_words_its_own_not_found_message() {
    let emulator = Emulator::new();

    for name in action_names() {
        let arn = custom_action_arn(&name);
        for rendering in renderings() {
            let answer = emulator.call(rendering.path, &(rendering.request)(&arn)).await;
            let case = format!("{} of {name:?}, never created", rendering.label);
            assert_rendered(&rendering, &case, &arn, &answer);

            // The sentence is the operation's own: no operation borrows another's, which is
            // what a single shared formatter would produce.
            for other in every_other_sentence(rendering.label, &name) {
                assert_ne!(
                    stated_message(&answer),
                    Some(other.as_str()),
                    "case {case:?} on {}: this operation must not word another operation's \
                     sentence {other:?}, got {}",
                    rendering.path,
                    answer.body
                );
            }
        }
    }
}

#[tokio::test]
async fn a_deleted_action_is_refused_exactly_as_one_that_never_existed() {
    for name in action_names() {
        // A fresh store per row, so the row's action is the only one the store ever held.
        let emulator = Emulator::new();
        let created = emulator
            .call(
                CREATE_PATH,
                &json!({
                    "ActionName": name,
                    "Definition": {"CommandText": "s3 ls"},
                    "AliasName": "an-alias",
                    "Tags": [{"TagKey": "env", "TagValue": "dev"}],
                }),
            )
            .await;
        assert_eq!(
            created.status, 200,
            "case {name:?}: the create answers 200, got {} with {}",
            created.status, created.body
        );
        let arn = created.body["CustomActionArn"]
            .as_str()
            .unwrap_or_else(|| panic!("case {name:?}: no CustomActionArn in {}", created.body))
            .to_string();

        let deleted = emulator
            .call("/delete-custom-action", &json!({"CustomActionArn": arn}))
            .await;
        assert_eq!(
            deleted.status, 200,
            "case {name:?}: the delete of the action answers 200, got {} with {}",
            deleted.status, deleted.body
        );

        // The store cannot tell an action deleted a moment ago from a name nothing was ever
        // created under, so every operation words exactly the sentence it words for an
        // absent name — the delete still wording none.
        for rendering in renderings() {
            let answer = emulator.call(rendering.path, &(rendering.request)(&arn)).await;
            let case = format!("{} of {name:?}, after its delete", rendering.label);
            assert_rendered(&rendering, &case, &arn, &answer);
        }
    }
}
