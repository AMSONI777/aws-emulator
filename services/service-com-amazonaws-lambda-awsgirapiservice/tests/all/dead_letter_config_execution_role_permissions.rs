// SPDX-License-Identifier: CC0-1.0

//! What the EXECUTION ROLE of a function has to be allowed before Lambda will store a
//! `DeadLetterConfig` on it.
//!
//! RULE: a call that WRITES a function's dead-letter target — `CreateFunction`, and
//! `UpdateFunctionConfiguration` when it states a `DeadLetterConfig` or a new `Role` — is
//! refused with the modelled `InvalidParameterValueException` (HTTP 400), persisting nothing,
//! when the identity-based policies in force on that function's execution role do not allow
//! the write Lambda would make to deliver a failed asynchronous invocation's event to the
//! target: the refusal names that write and the service it is made to. "The dead-letter queue
//! for failed asynchronous invocations" names "an Amazon SQS queue or Amazon SNS topic"
//! (`smithy_query(query="shape", shape="DeadLetterConfig")`), and Lambda writes it acting as
//! the function's own role, so a target the role may not write is a dead-letter queue no
//! event could ever reach.
//!
//! Every row drives real HTTP requests through the production `MultiServiceRouter` with IAM
//! mounted beside Lambda on ONE engine — each role is created through the real `CreateRole`
//! and `PutRolePolicy`, so what the gate reads is the document IAM persisted — and reads the
//! outcome back through `GetFunctionConfiguration`, so a target that was refused but still
//! stored, and one that was served but never stored, both fail here.
//!
//! The rows differ along what the rule generalises over: WHICH kind of target the
//! configuration names (a queue and a topic, each taking its own write), WHETHER the role is
//! granted that write (not at all, exactly, through a namespace wildcard, through an ARN
//! wildcard, on another resource, on the other kind's write, granted and explicitly denied),
//! WHICH call writes the configuration (`CreateFunction` and `UpdateFunctionConfiguration`,
//! the latter both by stating a target and by replacing the role under a stored one), and
//! whether the configuration names a target at all — the empty string the member's pattern
//! admits takes no write. The last test pins the case where nothing is KNOWN about the role,
//! which refuses nothing.

use std::sync::Arc;

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::event_source_mapping_role_access::{
    allow, assert_refused, create_function_as, given_role, logs_only,
};
use crate::event_source_mappings::{call, router_on, Answer};
use crate::function_lifecycle::{function_arn, make_activation_due};

/// Where `CreateFunction` is bound.
const FUNCTIONS_URI: &str = "/2015-03-31/functions";

/// The two kinds of dead-letter target the member documents: "The Amazon Resource Name (ARN)
/// of an Amazon SQS queue or Amazon SNS topic"
/// (`smithy_query(query="doc", shape="DeadLetterConfig", member="TargetArn")`).
const QUEUE: &str = "arn:aws:sqs:us-east-1:000000000000:dead-letters";
/// See [`QUEUE`].
const TOPIC: &str = "arn:aws:sns:us-east-1:000000000000:dead-letters";

/// Another queue of the same account, for the rows whose grant names the wrong resource.
const OTHER_QUEUE: &str = "arn:aws:sqs:us-east-1:000000000000:other-letters";

/// The queue named with wildcards, as a least-privilege policy writes it.
const QUEUE_WILDCARD: &str = "arn:aws:sqs:*:*:dead-*";

/// The write delivering an event to a QUEUE takes, and the service it is made to.
const QUEUE_WRITE: (&str, &str, &str) = ("sqs", "SendMessage", "SQS");

/// The write delivering an event to a TOPIC takes, and the service it is made to.
const TOPIC_WRITE: (&str, &str, &str) = ("sns", "Publish", "SNS");

/// How Lambda words the refusal of a role that may not make the write `action` on `service`.
fn refusal((_, action, service): (&str, &str, &str)) -> String {
    format!("The provided execution role does not have permissions to call {action} on {service}")
}

/// Lambda and IAM on ONE engine — exactly what `core/router` assembles — with the engine
/// handed back so a row can settle the clock-owed moves without sleeping.
fn emulator() -> (MultiServiceRouter, Arc<engine::InMemoryEngine>) {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = router_on(&engine);
    router.register_service(
        service_com_amazonaws_iam_awsidentitymanagementv20100508::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    (router, engine)
}

/// The `DeadLetterConfig` a request states to name `target`.
fn dead_letter_config(target: &str) -> Value {
    json!({ "TargetArn": target })
}

/// `CreateFunction` running as `role_arn`, with the `DeadLetterConfig` body `config`.
async fn create_with_dead_letter(
    router: &MultiServiceRouter,
    name: &str,
    role_arn: &str,
    config: &Value,
) -> Answer {
    call(
        router,
        "POST",
        FUNCTIONS_URI,
        &json!({
            "FunctionName": name,
            "Role": role_arn,
            "Runtime": "python3.12",
            "Handler": "index.handler",
            "Code": { "ZipFile": "" },
            "DeadLetterConfig": config,
        }),
    )
    .await
}

/// `UpdateFunctionConfiguration` on the function `name`.
async fn update_configuration(router: &MultiServiceRouter, name: &str, patch: &Value) -> Answer {
    call(
        router,
        "PUT",
        &format!("{FUNCTIONS_URI}/{name}/configuration"),
        patch,
    )
    .await
}

/// `GetFunctionConfiguration` on the function `name`.
async fn get_configuration(router: &MultiServiceRouter, name: &str) -> Answer {
    call(
        router,
        "GET",
        &format!("{FUNCTIONS_URI}/{name}/configuration"),
        &Value::Null,
    )
    .await
}

/// `GetFunction` on the function `name`.
async fn get_function(router: &MultiServiceRouter, name: &str) -> Answer {
    call(
        router,
        "GET",
        &format!("{FUNCTIONS_URI}/{name}"),
        &Value::Null,
    )
    .await
}

/// The `DeadLetterConfig$TargetArn` the configuration `name` holds reports, or `None` when it
/// reports no dead-letter configuration at all.
async fn stored_target(router: &MultiServiceRouter, case: &str, name: &str) -> Option<String> {
    let reading = get_configuration(router, name).await;
    assert_eq!(
        reading.status,
        200,
        "case {case:?}: expected HTTP 200 from GetFunctionConfiguration, got {} {}",
        reading.status,
        reading.text()
    );
    reading
        .json()
        .get("DeadLetterConfig")
        .and_then(|config| config.get("TargetArn"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Assert that the function `name` does not exist: a refused create stores nothing, so the
/// read answers the modelled 404 naming the function the request asked for.
async fn assert_no_function(router: &MultiServiceRouter, case: &str, name: &str) {
    let reading = get_function(router, name).await;
    assert_eq!(
        reading.status,
        404,
        "case {case:?}: a refused create must store no function, got {} {}",
        reading.status,
        reading.text()
    );
    assert_eq!(
        reading.error_code(),
        "ResourceNotFoundException",
        "case {case:?}: expected ResourceNotFoundException, got {} in {}",
        reading.error_code(),
        reading.text()
    );
    let expected = format!("Function not found: {}", function_arn(name));
    let message = reading
        .string("message")
        .or_else(|| reading.string("Message"))
        .unwrap_or_default();
    assert_eq!(
        message, expected,
        "case {case:?}: expected the message {expected:?}, got {message:?} in {}",
        reading.text()
    );
}

/// One row: the statements of the role's one inline policy, the dead-letter target the call
/// states, and the sentence it must be refused with (`None` when it must be served).
struct Row {
    case: &'static str,
    statements: Value,
    target: &'static str,
    refusal: Option<String>,
}

/// The catalog: which kind of target the configuration names, and whether the role may make
/// the write that kind of target takes.
fn rows() -> Vec<Row> {
    let (sqs, send_message, _) = QUEUE_WRITE;
    let (sns, publish, _) = TOPIC_WRITE;
    vec![
        Row {
            // The recorded case: a role carrying only the log writes a basic execution role
            // grants, and a queue it may not send to.
            case: "a queue target, with only the log writes granted",
            statements: json!([logs_only()]),
            target: QUEUE,
            refusal: Some(refusal(QUEUE_WRITE)),
        },
        Row {
            // The positive control: exactly the write, on the queue itself.
            case: "a queue target, with the send granted on it",
            statements: json!([logs_only(), allow(sqs, &[send_message], QUEUE)]),
            target: QUEUE,
            refusal: None,
        },
        Row {
            case: "a queue target, granted through a namespace wildcard",
            statements: json!([allow(sqs, &["*"], "*")]),
            target: QUEUE,
            refusal: None,
        },
        Row {
            case: "a queue target, granted through an ARN wildcard",
            statements: json!([allow(sqs, &[send_message], QUEUE_WILDCARD)]),
            target: QUEUE,
            refusal: None,
        },
        Row {
            case: "a queue target, granted on another queue",
            statements: json!([allow(sqs, &[send_message], OTHER_QUEUE)]),
            target: QUEUE,
            refusal: Some(refusal(QUEUE_WRITE)),
        },
        Row {
            // IAM's deny precedence: an explicit `Deny` wins over the grant beside it.
            case: "a queue target, granted and explicitly denied",
            statements: json!([
                allow(sqs, &[send_message], QUEUE),
                { "Effect": "Deny", "Action": format!("{sqs}:{send_message}"), "Resource": QUEUE },
            ]),
            target: QUEUE,
            refusal: Some(refusal(QUEUE_WRITE)),
        },
        Row {
            case: "a topic target, with only the log writes granted",
            statements: json!([logs_only()]),
            target: TOPIC,
            refusal: Some(refusal(TOPIC_WRITE)),
        },
        Row {
            case: "a topic target, with the publish granted on it",
            statements: json!([logs_only(), allow(sns, &[publish], TOPIC)]),
            target: TOPIC,
            refusal: None,
        },
        Row {
            // A target's write is its OWN service's: a grant of the queue write says nothing
            // about a topic.
            case: "a topic target, with only the queue write granted",
            statements: json!([allow(sqs, &[send_message], QUEUE)]),
            target: TOPIC,
            refusal: Some(refusal(TOPIC_WRITE)),
        },
        Row {
            // `TargetArn`'s pattern is `^(arn:…)|()$`: the empty string names no target, so
            // it takes no write and is never refused for one.
            case: "the empty target the member's pattern admits",
            statements: json!([logs_only()]),
            target: "",
            refusal: None,
        },
    ]
}

#[tokio::test]
async fn a_create_stores_a_dead_letter_target_only_where_the_role_may_write_it() {
    for (index, row) in rows().into_iter().enumerate() {
        let case = row.case;
        let (router, _engine) = emulator();
        let role = given_role(
            &router,
            case,
            &format!("dlq-creator-{index}"),
            Some(row.statements.clone()),
        )
        .await;
        let function = format!("dlq-create-probe-{index}");

        let answer =
            create_with_dead_letter(&router, &function, &role, &dead_letter_config(row.target))
                .await;

        match row.refusal.as_deref() {
            Some(expected) => {
                assert_refused(case, &answer, expected);
                assert_no_function(&router, case, &function).await;
            }
            None => {
                assert_eq!(
                    answer.status,
                    201,
                    "case {case:?}: expected HTTP 201, got {} {}",
                    answer.status,
                    answer.text()
                );
                // Round trip: what the create stored is what the configuration reports.
                let held = stored_target(&router, case, &function).await;
                assert_eq!(
                    held.as_deref(),
                    Some(row.target),
                    "case {case:?}: expected the stored TargetArn {:?}, got {held:?}",
                    row.target
                );
            }
        }
    }
}

#[tokio::test]
async fn an_update_stores_a_dead_letter_target_only_where_the_role_may_write_it() {
    for (index, row) in rows().into_iter().enumerate() {
        let case = row.case;
        let (router, engine) = emulator();
        let role = given_role(
            &router,
            case,
            &format!("dlq-updater-{index}"),
            Some(row.statements.clone()),
        )
        .await;
        let function = format!("dlq-update-probe-{index}");
        // The function starts out with no dead-letter target at all, so the update is the one
        // call that writes one.
        create_function_as(&router, case, &function, &role).await;
        // A function is not modifiable until it has finished being created, so the row starts
        // from the settled record a caller that waited would see.
        make_activation_due(&engine);

        let answer = update_configuration(
            &router,
            &function,
            &json!({ "DeadLetterConfig": dead_letter_config(row.target) }),
        )
        .await;

        match row.refusal.as_deref() {
            Some(expected) => {
                assert_refused(case, &answer, expected);
                // The refusal is instead of the configuration, not beside it.
                let held = stored_target(&router, case, &function).await;
                assert_eq!(
                    held, None,
                    "case {case:?}: a refused update must leave no dead-letter target behind, \
                     got {held:?}"
                );
            }
            None => {
                assert_eq!(
                    answer.status,
                    200,
                    "case {case:?}: expected HTTP 200, got {} {}",
                    answer.status,
                    answer.text()
                );
                let held = stored_target(&router, case, &function).await;
                assert_eq!(
                    held.as_deref(),
                    Some(row.target),
                    "case {case:?}: expected the stored TargetArn {:?}, got {held:?}",
                    row.target
                );
            }
        }
    }
}

#[tokio::test]
async fn an_update_that_replaces_the_role_is_judged_on_the_stored_target() {
    // The pair is the one the function would RUN with, so replacing the role under a stored
    // target asks the same question of the new role: one that may write the target it would
    // inherit installs, and one that may not is refused with nothing changed.
    //
    // (case, the statements of the role the update installs, the refusal it must answer)
    let rows: [(&str, Value, Option<String>); 3] = [
        (
            "a replacement role carrying only the log writes",
            json!([logs_only()]),
            Some(refusal(QUEUE_WRITE)),
        ),
        (
            "a replacement role granted the send on the stored target",
            json!([logs_only(), allow(QUEUE_WRITE.0, &[QUEUE_WRITE.1], QUEUE)]),
            None,
        ),
        (
            "a replacement role granted the send on another queue",
            json!([allow(QUEUE_WRITE.0, &[QUEUE_WRITE.1], OTHER_QUEUE)]),
            Some(refusal(QUEUE_WRITE)),
        ),
    ];

    for (index, (case, statements, refused)) in rows.into_iter().enumerate() {
        let (router, engine) = emulator();
        let granted = given_role(
            &router,
            case,
            &format!("dlq-holder-{index}"),
            Some(json!([
                logs_only(),
                allow(QUEUE_WRITE.0, &[QUEUE_WRITE.1], QUEUE)
            ])),
        )
        .await;
        let replacement = given_role(
            &router,
            case,
            &format!("dlq-replacement-{index}"),
            Some(statements),
        )
        .await;
        let function = format!("dlq-role-swap-{index}");
        let created =
            create_with_dead_letter(&router, &function, &granted, &dead_letter_config(QUEUE)).await;
        assert_eq!(
            created.status,
            201,
            "case {case:?}: expected the seed create to answer 201, got {} {}",
            created.status,
            created.text()
        );
        make_activation_due(&engine);

        let answer =
            update_configuration(&router, &function, &json!({ "Role": replacement })).await;

        let expected_role = match refused.as_deref() {
            Some(expected) => {
                assert_refused(case, &answer, expected);
                granted.clone()
            }
            None => {
                assert_eq!(
                    answer.status,
                    200,
                    "case {case:?}: expected HTTP 200, got {} {}",
                    answer.status,
                    answer.text()
                );
                replacement.clone()
            }
        };
        // Either way the target stands: the refusal changes nothing, and the served update
        // changes only the role.
        let held = stored_target(&router, case, &function).await;
        assert_eq!(
            held.as_deref(),
            Some(QUEUE),
            "case {case:?}: expected the stored TargetArn {QUEUE:?}, got {held:?}"
        );
        let reading = get_configuration(&router, &function).await;
        let role = reading
            .json()
            .get("Role")
            .and_then(Value::as_str)
            .map(str::to_string);
        assert_eq!(
            role.as_deref(),
            Some(expected_role.as_str()),
            "case {case:?}: expected the stored Role {expected_role:?}, got {role:?}"
        );
    }
}

#[tokio::test]
async fn a_role_nothing_is_known_about_refuses_no_dead_letter_target() {
    // A role ARN IAM holds no record of: an execution role is normally provisioned outside the
    // client that creates the function, so an absent record is no evidence about what the role
    // may do, and the target is stored.
    let case = "a role this account's IAM holds no record of";
    let (router, _engine) = emulator();
    let role = "arn:aws:iam::000000000000:role/service-role/provisioned-elsewhere";
    let function = "dlq-unknown-role";

    let answer = create_with_dead_letter(&router, function, role, &dead_letter_config(QUEUE)).await;
    assert_eq!(
        answer.status,
        201,
        "case {case:?}: expected HTTP 201, got {} {}",
        answer.status,
        answer.text()
    );
    let held = stored_target(&router, case, function).await;
    assert_eq!(
        held.as_deref(),
        Some(QUEUE),
        "case {case:?}: expected the stored TargetArn {QUEUE:?}, got {held:?}"
    );
}
