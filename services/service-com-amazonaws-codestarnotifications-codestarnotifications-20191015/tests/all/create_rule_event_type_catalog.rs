// SPDX-License-Identifier: CC0-1.0

//! Catalog resolution of `EventTypeIds` is a property of the ID ALONE, over the wire.
//!
//! The service resolves every submitted `EventTypeIds` entry against the one event-type
//! catalog `ListEventTypes` publishes, and refuses the first entry that does not resolve
//! with 400 `ValidationException` before anything is persisted. The sibling suite
//! `create_rule_input_validation` pins that refusal over the shape of the submitted LIST
//! (where the unresolvable id sits, what form it takes); this suite pins the other half of
//! the same rule — the refusal depends on NOTHING ELSE in the request:
//!
//! * it holds for every resource type the service does support (the resource is valid, so
//!   only the event type can refuse the call),
//! * it holds whatever targets, detail type, status, tags and idempotency token travel
//!   with it,
//! * it persists nothing — the resource lists no rule afterwards, the submitted name is
//!   still free, and the idempotency token still has no answer to replay,
//! * and the SAME request with a published id of that resource's own service succeeds and
//!   reads back (the positive control), so what the refusal rejects is catalog resolution.
//!
//! The ids each row submits are checked against what `ListEventTypes` actually publishes,
//! so the table cannot drift from the catalog it claims to be outside of.
//!
//! The harness (`Emulator`, `error_code`, `message`, `string`) is the one
//! `notification_rule_lifecycle` builds: one shared engine behind the same
//! `MultiServiceRouter` dispatch the emulator serves production requests with.

use serde_json::{json, Value};

use crate::notification_rule_lifecycle::{error_code, message, string, Emulator};

/// The service's wording for an event-type id that does not resolve: fixed text either
/// side of ONE slot, the first submitted id that did not resolve.
const MESSAGE_PREFIX: &str = "The notification rule cannot be created or modified because \
                              the following notification event type ID is not valid: ";
const MESSAGE_SUFFIX: &str = ". For more information, see the AWS CodeStar Notifications \
                              API Reference.";

fn expected_message(id: &str) -> String {
    format!("{MESSAGE_PREFIX}{id}{MESSAGE_SUFFIX}")
}

/// One request context: everything AROUND the event type ids, which the rule must not
/// depend on.
struct Context {
    label: &'static str,
    /// A resource of a type the service supports, so the resource rule cannot refuse it.
    resource: &'static str,
    detail_type: &'static str,
    status: Option<&'static str>,
    targets: &'static [(&'static str, &'static str)],
    tags: &'static [(&'static str, &'static str)],
    client_request_token: Option<&'static str>,
    /// An id the catalog publishes for that resource's own service (asserted published).
    published: &'static str,
    /// An id the catalog does not publish (asserted not published).
    unpublished: &'static str,
}

impl Context {
    fn request(&self, name: &str, event_type_ids: &[&str]) -> Value {
        let mut body = json!({
            "Name": name,
            "Resource": self.resource,
            "DetailType": self.detail_type,
            "EventTypeIds": event_type_ids,
            "Targets": self
                .targets
                .iter()
                .map(|(target_type, address)| {
                    json!({ "TargetType": target_type, "TargetAddress": address })
                })
                .collect::<Vec<_>>(),
        });
        if let Some(status) = self.status {
            body["Status"] = json!(status);
        }
        if !self.tags.is_empty() {
            body["Tags"] = Value::Object(
                self.tags
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), json!(value)))
                    .collect(),
            );
        }
        if let Some(token) = self.client_request_token {
            body["ClientRequestToken"] = json!(token);
        }
        body
    }
}

/// An id the catalog cannot hold because it is the modelled maximum length of 200
/// characters (`EventTypeId`: `smithy_query(query="shape",shape="EventTypeId")` — string,
/// len 1..200), built from a published id's own prefix so only its length sets it apart.
fn longest_possible_unpublished_id() -> String {
    let mut id = String::from("codecommit-repository-");
    while id.len() < 200 {
        id.push('x');
    }
    id
}

/// The rows: one per resource type the service supports, differing also in detail type,
/// status, target count and type, tag count, idempotency token, and in the FORM of the
/// unpublished id (foreign, a published id with a typo, a published id of the wrong case,
/// a published id with trailing whitespace).
const CONTEXTS: &[Context] = &[
    Context {
        label: "a CodeCommit repository, BASIC, default status, no targets, no tags",
        resource: "arn:aws:codecommit:us-east-1:123456789012:CatalogRepo",
        detail_type: "BASIC",
        status: None,
        targets: &[],
        tags: &[],
        client_request_token: None,
        published: "codecommit-repository-pull-request-created",
        unpublished: "codecommit-repository-pull-request-destroyed",
    },
    Context {
        label: "a CodeBuild project, FULL, DISABLED, one SNS target, one tag",
        resource: "arn:aws:codebuild:us-east-1:123456789012:project/widget",
        detail_type: "FULL",
        status: Some("DISABLED"),
        targets: &[("SNS", "arn:aws:sns:us-east-1:123456789012:builds")],
        tags: &[("Team", "dev")],
        client_request_token: None,
        published: "codebuild-project-build-state-failed",
        // A published id of this service with one character dropped.
        unpublished: "codebuild-project-build-state-faile",
    },
    Context {
        label: "a CodeDeploy application, BASIC, ENABLED, two targets, an idempotency token",
        resource: "arn:aws:codedeploy:us-east-1:123456789012:application:app",
        detail_type: "BASIC",
        status: Some("ENABLED"),
        targets: &[
            ("SNS", "arn:aws:sns:us-east-1:123456789012:deploys"),
            (
                "AWSChatbotSlack",
                "arn:aws:chatbot::123456789012:chat-configuration/slack-channel/eng",
            ),
        ],
        tags: &[],
        client_request_token: Some("catalog-token-codedeploy"),
        published: "codedeploy-application-deployment-succeeded",
        // A published id of this service in the wrong case.
        unpublished: "CodeDeploy-Application-Deployment-Succeeded",
    },
    Context {
        label: "a CodePipeline pipeline, FULL, DISABLED, one Teams target, two tags",
        resource: "arn:aws:codepipeline:us-east-1:123456789012:release",
        detail_type: "FULL",
        status: Some("DISABLED"),
        targets: &[(
            "AWSChatbotMicrosoftTeams",
            "arn:aws:chatbot::123456789012:chat-configuration/microsoft-teams-channel/ops",
        )],
        tags: &[("env", "prod"), ("owner", "release")],
        client_request_token: None,
        published: "codepipeline-pipeline-manual-approval-needed",
        // A published id with trailing whitespace: `EventTypeId` permits the character,
        // the catalog does not hold the value.
        unpublished: "codepipeline-pipeline-manual-approval-needed ",
    },
];

/// Every event type id `ListEventTypes` publishes, walked through its own pagination.
async fn published_catalog(emulator: &Emulator) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut request = json!({ "MaxResults": 100 });
        if let Some(value) = &token {
            request["NextToken"] = json!(value);
        }
        let listed = emulator.ok("catalog", "/listEventTypes", &request).await;
        ids.extend(
            listed
                .get("EventTypes")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .map(|summary| string(summary, "EventTypeId"))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default(),
        );
        match listed.get("NextToken").and_then(Value::as_str) {
            Some(next) => token = Some(next.to_string()),
            None => break,
        }
    }
    ids
}

/// The rules the account holds for `resource`, through the RESOURCE filter.
async fn rules_for(emulator: &Emulator, resource: &str) -> Vec<Value> {
    let listed = emulator
        .ok(
            resource,
            "/listNotificationRules",
            &json!({ "Filters": [{ "Name": "RESOURCE", "Value": resource }] }),
        )
        .await;
    listed
        .get("NotificationRules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The event type ids a rule reports through `DescribeNotificationRule`.
fn described_event_type_ids(described: &Value) -> Vec<String> {
    described
        .get("EventTypes")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|summary| string(summary, "EventTypeId"))
                .collect()
        })
        .unwrap_or_default()
}

/// RULE: an `EventTypeIds` entry that does not resolve against the published catalog is
/// refused with 400 `ValidationException` and the service's text naming that id, whatever
/// else the request carries, and nothing is persisted — while the same request with a
/// published id succeeds and reads back.
#[tokio::test]
async fn catalog_resolution_refuses_an_unpublished_id_whatever_else_the_request_carries() {
    let emulator = Emulator::new();
    let catalog = published_catalog(&emulator).await;
    assert!(
        !catalog.is_empty(),
        "ListEventTypes must publish the catalog the ids resolve against"
    );

    for (index, context) in CONTEXTS.iter().enumerate() {
        let case = context.label;
        // The row's own grounding: one id the listing reports, one it does not.
        assert!(
            catalog.iter().any(|id| id == context.published),
            "case {case:?}: {:?} must be published by ListEventTypes, which reports {catalog:?}",
            context.published
        );
        assert!(
            !catalog.iter().any(|id| id == context.unpublished),
            "case {case:?}: {:?} must NOT be published by ListEventTypes",
            context.unpublished
        );

        // The name this row uses for BOTH the refused and the accepted call, so the
        // accepted one also proves the refusal reserved nothing.
        let name = format!("catalog-context-{index}");

        let (status, answered) = emulator
            .post(
                "/createNotificationRule",
                &context.request(&name, &[context.unpublished]),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected 400, got {status} with {answered}"
        );
        assert_eq!(
            error_code(&answered),
            "ValidationException",
            "case {case:?}: got {answered}"
        );
        let stated = message(&answered);
        let expected = expected_message(context.unpublished);
        assert_eq!(
            stated, expected,
            "case {case:?}: expected {expected:?}, got {stated:?}"
        );
        assert!(
            !stated.contains(context.resource) && !stated.contains(&name),
            "case {case:?}: the refusal states the id and nothing else of the request, got \
             {stated:?}"
        );

        let listed = rules_for(&emulator, context.resource).await;
        assert!(
            listed.is_empty(),
            "case {case:?}: a refused create persists no rule, got {listed:?}"
        );

        // The positive control: the very same request, with a published id of that
        // resource's own service in the slot, is accepted and reads back.
        let created = emulator
            .ok(
                case,
                "/createNotificationRule",
                &context.request(&name, &[context.published]),
            )
            .await;
        let arn = string(&created, "Arn");
        assert!(
            !arn.is_empty(),
            "case {case:?}: a published id must create a rule, got {created}"
        );
        let described = emulator
            .ok(case, "/describeNotificationRule", &json!({ "Arn": arn }))
            .await;
        assert_eq!(
            string(&described, "Name"),
            name,
            "case {case:?}: the refused create must not have taken the name, got {described}"
        );
        assert_eq!(
            described_event_type_ids(&described),
            vec![context.published.to_string()],
            "case {case:?}: the rule carries the published id it was created with, got \
             {described}"
        );
        assert_eq!(
            rules_for(&emulator, context.resource).await.len(),
            1,
            "case {case:?}: exactly the accepted rule is listed for the resource"
        );
    }
}

/// RULE (same rule, the length bound): an id that cannot be in the catalog because of its
/// size is refused the same way as any other unpublished id — the refusal is resolution,
/// not a guess from the id's shape.
#[tokio::test]
async fn catalog_resolution_refuses_an_id_at_the_modelled_length_bound() {
    let emulator = Emulator::new();
    let context = &CONTEXTS[0];
    let longest = longest_possible_unpublished_id();
    assert_eq!(
        longest.len(),
        200,
        "the case must submit the modelled maximum length, got {}",
        longest.len()
    );

    for (case, submitted) in [
        ("the longest id the model permits", longest.as_str()),
        ("a single character", "x"),
    ] {
        let (status, answered) = emulator
            .post(
                "/createNotificationRule",
                &context.request("catalog-bound", &[submitted]),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected 400, got {status} with {answered}"
        );
        assert_eq!(
            error_code(&answered),
            "ValidationException",
            "case {case:?}: got {answered}"
        );
        let stated = message(&answered);
        let expected = expected_message(submitted);
        assert_eq!(
            stated, expected,
            "case {case:?}: expected {expected:?}, got {stated:?}"
        );
        assert!(
            rules_for(&emulator, context.resource).await.is_empty(),
            "case {case:?}: a refused create persists no rule"
        );
    }
}

/// RULE: the UPDATE path resolves against the SAME catalog, for every resource type a rule
/// can watch — a stored rule cannot be re-pointed at an unpublished id, and the refused
/// update leaves the rule exactly as it was.
#[tokio::test]
async fn an_update_cannot_repoint_a_rule_of_any_resource_type_at_an_unpublished_id() {
    let emulator = Emulator::new();

    for (index, context) in CONTEXTS.iter().enumerate() {
        let case = context.label;
        let name = format!("catalog-update-{index}");
        let created = emulator
            .ok(
                case,
                "/createNotificationRule",
                &context.request(&name, &[context.published]),
            )
            .await;
        let arn = string(&created, "Arn");

        let (status, answered) = emulator
            .post(
                "/updateNotificationRule",
                &json!({ "Arn": arn, "EventTypeIds": [context.unpublished] }),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case:?}: expected 400, got {status} with {answered}"
        );
        assert_eq!(
            error_code(&answered),
            "ValidationException",
            "case {case:?}: got {answered}"
        );
        let stated = message(&answered);
        let expected = expected_message(context.unpublished);
        assert_eq!(
            stated, expected,
            "case {case:?}: expected {expected:?}, got {stated:?}"
        );

        let described = emulator
            .ok(case, "/describeNotificationRule", &json!({ "Arn": arn }))
            .await;
        assert_eq!(
            described_event_type_ids(&described),
            vec![context.published.to_string()],
            "case {case:?}: a refused update leaves the stored ids alone, got {described}"
        );
        assert_eq!(
            string(&described, "Name"),
            name,
            "case {case:?}: a refused update leaves the rule's name alone, got {described}"
        );
    }
}
