// SPDX-License-Identifier: CC0-1.0

//! A recorded configuration item's RELATIONSHIP GRAPH and the counter its `configuration`
//! derives from the same links.
//!
//! The rule under test: **a configuration item's `relationships` and the counter its
//! `configuration` document reports over those same links are two views of ONE observed
//! state, so for every recorded resource the number of relationships of the related kind
//! equals that counter, each relationship names the related resource by the id the service
//! that owns it minted, by its custom name, and by the wording Config reports that kind of
//! link with — and a resource the recorded one is NOT linked to appears in neither view.**
//! A link made after the resource was first recorded is a further state of it, so it is
//! reported as a FURTHER configuration item carrying both views raised together.
//!
//! Exercised here on the link Config observes between an IAM customer managed policy and
//! the identities it is attached to: the item's `AWS::IAM::Role` relationships against the
//! `attachmentCount` of the SAME item. `BatchGetResourceConfig` reads the same recorded
//! state, so the counter it reports for a key is the counter the history read reports;
//! `BaseConfigurationItem` carries no `relationships` member, so the graph itself is read
//! back only through the history item.
//!
//! Config and IAM are mounted on ONE engine, reusing the harness
//! `conformance_pack_rule_evaluation` builds: the recorder reads what it records from IAM's
//! own API. No row calls `PutResourceConfig` — every item read back got into the inventory
//! because a recorder was recording while the policy existed in IAM.
//!
//! The rows differ along what the rule generalises over: how many identities the policy is
//! attached to (none, one, two, three), how many co-existing identities it is NOT attached
//! to, and whether the links were in place when the policy was first recorded or made
//! afterwards.

use std::collections::BTreeSet;
use std::time::Instant;

use serde_json::{json, Value};

use crate::conformance_pack_rule_evaluation::{Emulator, CONVERGENCE_BUDGET, POLL_INTERVAL};

/// The resource type Config records an IAM customer managed policy under, an entry of
/// `com.amazonaws.configservice#ResourceType`.
const IAM_POLICY_RESOURCE_TYPE: &str = "AWS::IAM::Policy";

/// The entry of that same enum an IAM role is recorded under, which is the
/// `Relationship$resourceType` of a link to a role.
const IAM_ROLE_RESOURCE_TYPE: &str = "AWS::IAM::Role";

/// The wording Config reports a managed policy's attachment to a role by
/// (`Relationship$relationshipName`: "the type of relationship with the related
/// resource").
const ATTACHED_TO_ROLE: &str = "Is attached to Role";

/// The operation that reads the same recorded state by resource key.
const BATCH: &str = "BatchGetResourceConfig";

/// The error a history read answers for a resource key Config recorded nothing for
/// (`GetResourceConfigHistory` models it: "you have specified a resource that is either
/// unknown or has not been discovered"), which is the ONE refusal a poll reads as "nothing
/// recorded yet".
const NOT_DISCOVERED: &str = "ResourceNotDiscoveredException";

/// The policy document a created policy grants, as `CreatePolicy` requires one.
fn document() -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{ "Effect": "Allow", "Action": "config:DescribeConfigRules", "Resource": "*" }],
    })
    .to_string()
}

/// The trust document every role below carries, which `CreateRole` requires.
fn trust() -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": "ec2.amazonaws.com" },
            "Action": "sts:AssumeRole",
        }],
    })
    .to_string()
}

/// Create a customer managed policy through IAM's own API and answer its `PolicyId` and
/// the ARN IAM minted — the id a configuration item records it under, and the ARN the
/// attachments below name it by.
async fn create_policy(case: &str, emulator: &Emulator, name: &str) -> (String, String) {
    let policy = emulator
        .iam()
        .create_policy()
        .policy_name(name)
        .policy_document(document())
        .send()
        .await
        .unwrap_or_else(|error| {
            panic!("case {case:?}: creating the policy {name} must succeed, got {error:?}")
        })
        .policy
        .unwrap_or_else(|| panic!("case {case:?}: CreatePolicy answers the policy"));
    (
        policy
            .policy_id
            .unwrap_or_else(|| panic!("case {case:?}: CreatePolicy answers a PolicyId")),
        policy
            .arn
            .unwrap_or_else(|| panic!("case {case:?}: CreatePolicy answers an ARN")),
    )
}

/// Create the role `name` through IAM's own API and answer the `RoleId` IAM minted for it
/// — the id a link to that role names it by.
async fn create_role(case: &str, emulator: &Emulator, name: &str) -> String {
    emulator
        .iam()
        .create_role()
        .role_name(name)
        .assume_role_policy_document(trust())
        .send()
        .await
        .unwrap_or_else(|error| {
            panic!("case {case:?}: creating the role {name} must succeed, got {error:?}")
        })
        .role
        .unwrap_or_else(|| panic!("case {case:?}: CreateRole answers the role"))
        .role_id
}

/// Attach `policy_arn` to the role `name` through IAM's own API.
async fn attach(case: &str, emulator: &Emulator, name: &str, policy_arn: &str) {
    emulator
        .iam()
        .attach_role_policy()
        .role_name(name)
        .policy_arn(policy_arn)
        .send()
        .await
        .unwrap_or_else(|error| {
            panic!("case {case:?}: attaching the policy to {name} must succeed, got {error:?}")
        });
}

/// The configuration items a history read reports for the policy `resource_id`, newest
/// first — empty while Config has recorded nothing for that key, which the read refuses
/// about rather than answering empty.
///
/// Only that modelled refusal is read as an empty history: any other answer is a defect of
/// the read itself, so it fails here naming the status and the body rather than being
/// polled over until a deadline.
async fn recorded_items(case: &str, emulator: &Emulator, resource_id: &str) -> Vec<Value> {
    let (status, body) = emulator
        .call(
            "GetResourceConfigHistory",
            &json!({ "resourceType": IAM_POLICY_RESOURCE_TYPE, "resourceId": resource_id }),
        )
        .await;
    if status == 200 {
        return body["configurationItems"]
            .as_array()
            .cloned()
            .unwrap_or_default();
    }
    let code = body["__type"]
        .as_str()
        .map(|wire| wire.rsplit('#').next().unwrap_or(wire).to_string())
        .unwrap_or_default();
    assert_eq!(
        (status, code.as_str()),
        (400, NOT_DISCOVERED),
        "case {case:?}: an unrecorded policy is refused as undiscovered, got {status} with \
         {body}"
    );
    Vec::new()
}

/// The `configuration` document of one configuration item, parsed.
fn configuration(case: &str, item: &Value) -> Value {
    let encoded = item["configuration"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: an item reports a configuration, got {item}"));
    serde_json::from_str(encoded).unwrap_or_else(|error| {
        panic!("case {case:?}: the configuration is a JSON document, got {encoded} ({error})")
    })
}

/// The counter one item's configuration derives from the identities the policy is attached
/// to (`Policy$AttachmentCount`).
fn attachment_count(case: &str, item: &Value) -> i64 {
    configuration(case, item)["attachmentCount"]
        .as_i64()
        .unwrap_or_else(|| panic!("case {case:?}: the configuration reports attachmentCount"))
}

/// Every relationship one item carries, of any kind.
fn relationships(item: &Value) -> Vec<Value> {
    item["relationships"].as_array().cloned().unwrap_or_default()
}

/// The links of one item that name a ROLE, each as the triple the rule pins: the id the
/// role is named by, its custom name, and the wording the link is reported with.
fn role_links(item: &Value) -> Vec<(String, String, String)> {
    relationships(item)
        .iter()
        .filter(|link| link["resourceType"].as_str() == Some(IAM_ROLE_RESOURCE_TYPE))
        .map(|link| {
            (
                link["resourceId"].as_str().unwrap_or_default().to_string(),
                link["resourceName"].as_str().unwrap_or_default().to_string(),
                link["relationshipName"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

/// Every resource id any relationship of one item names, whatever its kind: what a row
/// checks an unattached identity's absence against.
fn linked_ids(item: &Value) -> BTreeSet<String> {
    relationships(item)
        .iter()
        .map(|link| link["resourceId"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Read the policy's history until its NEWEST item reports `count` attachments, and answer
/// every item that read reported, newest first.
///
/// What is waited for is the recording pass the recorder owes, never a span of time: the
/// assertion that fails at the deadline names the counter the read did report.
async fn await_attachment_count(
    case: &str,
    emulator: &Emulator,
    resource_id: &str,
    count: i64,
) -> Vec<Value> {
    let deadline = Instant::now() + CONVERGENCE_BUDGET;
    loop {
        let items = recorded_items(case, emulator, resource_id).await;
        let reported = items.first().map(|item| attachment_count(case, item));
        if reported == Some(count) {
            return items;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected a configuration item reporting attachmentCount {count}, \
             got {reported:?} over {} item(s)",
            items.len()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The counter `BatchGetResourceConfig` reports for the policy `resource_id`, read from the
/// one base configuration item it answers for that key.
async fn batch_attachment_count(case: &str, emulator: &Emulator, resource_id: &str) -> i64 {
    let body = emulator
        .ok(
            BATCH,
            &json!({
                "resourceKeys": [
                    { "resourceType": IAM_POLICY_RESOURCE_TYPE, "resourceId": resource_id },
                ],
            }),
        )
        .await;
    let items = body["baseConfigurationItems"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("case {case:?}: expected baseConfigurationItems, got {body}"));
    assert_eq!(
        items.len(),
        1,
        "case {case:?}: a key the inventory holds is one base configuration item, got {body}"
    );
    assert_eq!(
        (
            items[0]["resourceType"].as_str(),
            items[0]["resourceId"].as_str(),
        ),
        (Some(IAM_POLICY_RESOURCE_TYPE), Some(resource_id)),
        "case {case:?}: the batch read answers the key it was asked about, got {body}"
    );
    attachment_count(case, &items[0])
}

/// One row of the table: the policy it records, the roles the policy is attached to, and
/// the co-existing roles it is NOT attached to.
struct Row {
    /// See [`Row`].
    case: &'static str,
    /// See [`Row`].
    policy_name: &'static str,
    /// See [`Row`].
    attached: &'static [&'static str],
    /// See [`Row`].
    bystanders: &'static [&'static str],
}

#[tokio::test]
async fn an_items_relationship_graph_and_its_counter_report_one_state() {
    let emulator = Emulator::new();
    emulator.recording().await;

    // The rows differ along how many roles the policy is attached to and how many roles
    // co-exist unattached. Every policy and every role is created through IAM's own API;
    // Config is told nothing about any of them.
    let rows: [Row; 4] = [
        Row {
            case: "no role attached, two bystanders",
            policy_name: "graph-none",
            attached: &[],
            bystanders: &["graph-none-by-a", "graph-none-by-b"],
        },
        Row {
            case: "one role attached, one bystander",
            policy_name: "graph-one",
            attached: &["graph-one-attached"],
            bystanders: &["graph-one-bystander"],
        },
        Row {
            case: "two roles attached, two bystanders",
            policy_name: "graph-two",
            attached: &["graph-two-first", "graph-two-second"],
            bystanders: &["graph-two-by-a", "graph-two-by-b"],
        },
        Row {
            case: "three roles attached, no bystander",
            policy_name: "graph-three",
            attached: &["graph-three-a", "graph-three-b", "graph-three-c"],
            bystanders: &[],
        },
    ];

    for row in rows {
        let case = row.case;
        let (policy_id, policy_arn) = create_policy(case, &emulator, row.policy_name).await;

        // The roles the policy is attached to, each with the id IAM minted for it.
        let mut expected: Vec<(String, String, String)> = Vec::new();
        for name in row.attached {
            let role_id = create_role(case, &emulator, name).await;
            attach(case, &emulator, name, &policy_arn).await;
            expected.push((role_id, (*name).to_string(), ATTACHED_TO_ROLE.to_string()));
        }
        // The roles that merely co-exist: created, never attached.
        let mut unrelated = BTreeSet::new();
        for name in row.bystanders {
            unrelated.insert(create_role(case, &emulator, name).await);
        }

        let items =
            await_attachment_count(case, &emulator, &policy_id, row.attached.len() as i64).await;
        let item = items
            .first()
            .unwrap_or_else(|| panic!("case {case:?}: the policy is recorded"));

        // The item is the POLICY's own: a row attaching nothing would otherwise be carried
        // by an item recorded for some other resource.
        assert_eq!(
            (item["resourceType"].as_str(), item["resourceId"].as_str()),
            (Some(IAM_POLICY_RESOURCE_TYPE), Some(policy_id.as_str())),
            "case {case:?}: expected the item recorded for this policy, got {item}"
        );

        // The two views of one state: as many role links as the counter counts.
        let mut links = role_links(item);
        links.sort();
        expected.sort();
        let counter = attachment_count(case, item);
        assert_eq!(
            links.len() as i64,
            counter,
            "case {case:?}: expected {counter} role relationship(s) beside attachmentCount \
             {counter}, got {links:?}"
        );
        assert_eq!(
            links, expected,
            "case {case:?}: expected the roles the policy is attached to, each by its RoleId, \
             its name and the attachment wording, got {item}"
        );

        // A role the policy is not attached to is in neither view.
        let present = linked_ids(item);
        let leaked: Vec<&String> = unrelated.intersection(&present).collect();
        assert!(
            leaked.is_empty(),
            "case {case:?}: a role the policy is not attached to is related to nothing, got \
             {leaked:?} in {item}"
        );

        // The batch read is the same recorded state, so it reports the same counter.
        let batched = batch_attachment_count(case, &emulator, &policy_id).await;
        assert_eq!(
            batched, counter,
            "case {case:?}: expected the batch read to report attachmentCount {counter}, got \
             {batched}"
        );
    }
}

#[tokio::test]
async fn a_link_made_later_raises_both_views_in_a_further_item() {
    let emulator = Emulator::new();
    emulator.recording().await;

    let case = "a policy whose attachments grow one at a time";
    let (policy_id, policy_arn) = create_policy(case, &emulator, "graph-growing").await;

    // A role the policy is never attached to, created first so that every later item has
    // had the chance to relate it.
    let bystander = create_role(case, &emulator, "graph-growing-bystander").await;

    // The links the policy gains, one per step: each is a state the policy changed into,
    // so each is reported as a further configuration item whose two views rise together.
    let steps = ["graph-growing-first", "graph-growing-second"];
    let mut expected: Vec<(String, String, String)> = Vec::new();
    let mut items_before = 0usize;
    for name in steps {
        let role_id = create_role(case, &emulator, name).await;
        attach(case, &emulator, name, &policy_arn).await;
        expected.push((role_id, name.to_string(), ATTACHED_TO_ROLE.to_string()));
        expected.sort();

        let items =
            await_attachment_count(case, &emulator, &policy_id, expected.len() as i64).await;
        let item = &items[0];
        let mut links = role_links(item);
        links.sort();
        assert_eq!(
            links, expected,
            "case {case:?} after attaching {name}: expected every role attached so far, got \
             {item}"
        );
        assert_eq!(
            links.len() as i64,
            attachment_count(case, item),
            "case {case:?} after attaching {name}: the counter counts the links, got {item}"
        );
        assert!(
            !linked_ids(item).contains(&bystander),
            "case {case:?} after attaching {name}: the unattached role {bystander} is related \
             to nothing, got {item}"
        );
        assert!(
            items.len() > items_before,
            "case {case:?} after attaching {name}: a changed state is a further item, got \
             {} item(s) after {items_before}",
            items.len()
        );
        items_before = items.len();

        let batched = batch_attachment_count(case, &emulator, &policy_id).await;
        assert_eq!(
            batched,
            expected.len() as i64,
            "case {case:?} after attaching {name}: expected the batch read to report \
             attachmentCount {}, got {batched}",
            expected.len()
        );
    }

    // The state the policy LEFT is still reported, with the single link it was recorded
    // with: the history is the states the resource went through, not just the latest.
    let items = recorded_items(case, &emulator, &policy_id).await;
    let one_link = items
        .iter()
        .find(|item| attachment_count(case, item) == 1)
        .unwrap_or_else(|| panic!("case {case:?}: the state with one attachment is kept"));
    assert_eq!(
        role_links(one_link).len(),
        1,
        "case {case:?}: the kept state carries the one link it was recorded with, got \
         {one_link}"
    );
}
