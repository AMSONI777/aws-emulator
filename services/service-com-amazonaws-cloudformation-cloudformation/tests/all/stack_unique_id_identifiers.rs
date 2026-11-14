// SPDX-License-Identifier: CC0-1.0

//! How this service answers a stack identifier written as a stack's UNIQUE ID — the segment
//! a stack id (`arn:…:stack/<name>/<unique-id>`) ends in — over the awsQuery wire.
//!
//! **The rule every case here holds the service to:** a request carrying a stack's unique id
//! is a request about a STACK: the value is taken as an identifier and RESOLVED, and since
//! only a name or a WHOLE stack id addresses a stack, it is answered as the missing stack it
//! names — the operation's own not-found sentence, with the value spelled as the request
//! spelled it — and never as a malformed request. The forms a stack IS addressed by — its
//! name and its whole stack id — still reach the lookup and are served.
//!
//! What the identifier check reads is the FORM of the value: the five hyphen-separated groups
//! of hexadecimal a stack id ends in are admitted whichever character they start with and in
//! either case of hexadecimal, so a unique id led by a digit is answered exactly as one led
//! by a letter. Both sides are rows below.
//!
//! The tables span the class rather than one recorded request: five unique ids differing
//! along what the rule generalises over (a live stack's own led by a digit and by a letter,
//! that digit-led value in the other case of hexadecimal, and two nothing ever minted)
//! crossed with every operation whose identifier member this service checks itself. The
//! values that are only NEARLY a unique id are rows of the malformed-identifier table in
//! `stack_identifier_refusals.rs`, which is the one suite that pins the shape of that
//! refusal.

use crate::harness::{call, create_stack, member, router, wait_for_the_transition, xml_text};

/// A template with one resource, so every read a row makes has something to report for the
/// control cases.
const TEMPLATE: &str = r#"{"Resources":{
     "First":{"Type":"AWS::SNS::Topic","Properties":{"DisplayName":"unique-id-first"}}}}"#;

/// A stack policy body, for the row that reaches `SetStackPolicy`.
const POLICY: &str = r#"{"Statement":[{"Effect":"Allow","Action":"Update:*",
     "Principal":"*","Resource":"*"}]}"#;

/// The expression CloudFormation's own input validation states a stack identifier has to
/// match, quoted in a constraint refusal exactly as the service states it — the clause NO row
/// of this suite may answer, since every value here is one the service resolves.
///
/// Source: the service's own constant (`state::stack_identifier::STACK_IDENTIFIER_PATTERN`),
/// spelled out here because the sentence IS the requirement — a reworded message must fail
/// this suite.
const IDENTIFIER_PATTERN: &str = "[a-zA-Z][-a-zA-Z0-9]*|arn:[-a-zA-Z0-9:/._+]*";

/// The refusal a value the expression does not match is answered with, at the member path the
/// operation states it at — built here so a row can assert it is NOT what came back.
fn constraint_refusal(path: &str, value: &str) -> String {
    format!(
        "1 validation error detected: Value '{value}' at '{path}' failed to satisfy \
         constraint: Member must satisfy regular expression pattern: {IDENTIFIER_PATTERN}"
    )
}

/// One operation that takes a stack identifier this service checks itself: the members it
/// needs besides `StackName`, the member path its refusal states the identifier at, and
/// whether a request naming a LIVE stack is served (a mutation is left out of that control,
/// since it would move the stack the other rows read).
struct UniqueIdRow {
    action: &'static str,
    extra: &'static [(&'static str, &'static str)],
    path: &'static str,
    serves_a_live_stack: bool,
}

const ROWS: &[UniqueIdRow] = &[
    UniqueIdRow {
        action: "ListStackResources",
        extra: &[],
        // The one operation whose validator names the member `StackNameOrId`.
        path: "stackNameOrId",
        serves_a_live_stack: true,
    },
    UniqueIdRow {
        action: "DescribeStackResources",
        extra: &[],
        path: "stackName",
        serves_a_live_stack: true,
    },
    UniqueIdRow {
        action: "DescribeStacks",
        extra: &[],
        path: "stackName",
        serves_a_live_stack: true,
    },
    UniqueIdRow {
        action: "GetTemplate",
        extra: &[],
        path: "stackName",
        serves_a_live_stack: true,
    },
    UniqueIdRow {
        action: "DescribeStackResource",
        extra: &[("LogicalResourceId", "First")],
        path: "stackName",
        serves_a_live_stack: true,
    },
    UniqueIdRow {
        action: "DescribeStackEvents",
        extra: &[],
        path: "stackName",
        serves_a_live_stack: true,
    },
    UniqueIdRow {
        action: "GetStackPolicy",
        extra: &[],
        path: "stackName",
        serves_a_live_stack: true,
    },
    UniqueIdRow {
        action: "CancelUpdateStack",
        extra: &[],
        path: "stackName",
        serves_a_live_stack: false,
    },
    // Two operations that WRITE: an identifier the expression does not admit is refused by
    // them too, so the rule holds for the mutating reads of a stack as well as the reporting
    // ones. Neither is crossed with the live stack, since a write would move the stack the
    // rows above read.
    UniqueIdRow {
        action: "SetStackPolicy",
        extra: &[("StackPolicyBody", POLICY)],
        path: "stackName",
        serves_a_live_stack: false,
    },
    UniqueIdRow {
        action: "UpdateStack",
        extra: &[("TemplateBody", TEMPLATE)],
        path: "stackName",
        serves_a_live_stack: false,
    },
];

/// A unique id nothing ever minted, in the 8-4-4-4-12 hexadecimal form a stack id ends in and
/// starting with a digit.
const UNMINTED_UNIQUE_ID: &str = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

/// A value in the same form that starts with a LETTER, which nothing ever minted either.
const LETTER_LED_UNIQUE_ID: &str = "af2504e0-4f89-11d3-9a0c-0305e82c3301";

fn members_of(row: &UniqueIdRow, identifier: &str) -> Vec<(String, String)> {
    let mut members = vec![member("StackName", identifier)];
    members.extend(row.extra.iter().map(|(key, value)| member(key, value)));
    members
}

/// The unique id a stack id ends in: everything after the last `/`.
fn unique_id_of(stack_id: &str) -> String {
    stack_id
        .rsplit('/')
        .next()
        .expect("a stack id's last segment")
        .to_string()
}

#[tokio::test]
async fn a_stack_unique_id_is_answered_as_the_stack_it_does_not_name() {
    let router = router();
    let (status, body) = create_stack(&router, "unique-id-live", TEMPLATE, &[]).await;
    assert_eq!(
        status, 200,
        "expected CreateStack to be accepted, got {status} {body}"
    );
    wait_for_the_transition().await;

    let (status, described) = call(
        &router,
        "DescribeStacks",
        &[member("StackName", "unique-id-live")],
    )
    .await;
    assert_eq!(
        status, 200,
        "expected the stack to be readable, got {status} {described}"
    );
    let stack_id = xml_text(&described, "StackId").expect("the stack's own id");
    let minted = unique_id_of(&stack_id);
    // The minted id's own leading character is random hexadecimal, so each side of the
    // boundary is built from it: the same 8-4-4-4-12 value led by a digit (which the name
    // alternative cannot admit) and led by a letter (which it does).
    let digit_led = format!("0{}", &minted[1..]);
    let letter_led = format!("a{}", &minted[1..]);

    // Every unique id: the live stack's own led by a digit and by a letter, that digit-led
    // value in the other case of hexadecimal, and two nothing ever minted. No stack is
    // addressed by any of them — only a name or a whole stack id is — so each is answered as
    // the missing stack it names rather than for its own shape.
    let upper = digit_led.to_ascii_uppercase();
    for (case, identifier) in [
        ("the live stack's own unique id", digit_led.as_str()),
        ("that unique id in upper-case hexadecimal", upper.as_str()),
        ("the live stack's unique id led by a letter", letter_led.as_str()),
        ("a unique id nothing ever minted", UNMINTED_UNIQUE_ID),
        ("a letter-led value nothing ever minted", LETTER_LED_UNIQUE_ID),
    ] {
        for row in ROWS {
            let case = format!("{} naming {case}", row.action);
            let (status, body) = call(&router, row.action, &members_of(row, identifier)).await;
            assert_eq!(
                status, 400,
                "case {case:?}: expected HTTP 400, got {status} {body}"
            );
            assert_eq!(
                xml_text(&body, "Code").as_deref(),
                Some("ValidationError"),
                "case {case:?}: expected <Code>ValidationError</Code>, got {body}"
            );
            let message = xml_text(&body, "Message").unwrap_or_default();
            assert!(
                message.contains("does not exist") && message.contains(identifier),
                "case {case:?}: expected the operation's stack-not-found sentence naming \
                 {identifier:?}, got {message:?}"
            );
            let never = constraint_refusal(row.path, identifier);
            assert_ne!(
                message, never,
                "case {case:?}: a value of the unique-id form must not be refused for its \
                 own shape"
            );
        }
    }

    // ...and the forms that DO address the stack are still served, so answering the unique id
    // for the stack costs none of them.
    for (case, identifier) in [
        ("its name", "unique-id-live"),
        ("its whole stack id", stack_id.as_str()),
    ] {
        for row in ROWS {
            if !row.serves_a_live_stack {
                continue;
            }
            let case = format!("{} naming {case}", row.action);
            let (status, body) = call(&router, row.action, &members_of(row, identifier)).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected the call to be served, got {status} {body}"
            );
        }
    }
}
