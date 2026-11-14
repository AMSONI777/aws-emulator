// SPDX-License-Identifier: CC0-1.0

//! What the ACCESS POLICY of the Amazon SNS topic a receipt rule's action notifies decides
//! about storing that rule — end to end over the wire, with Amazon SNS mounted beside this
//! service on ONE engine exactly as the assembled router mounts them.
//!
//! The RULE these cases pin: a receipt rule's action publishes to its topic as the Amazon SES
//! service principal, so the topic's own resource policy decides that publish, and the
//! decision is made whoever owns the topic — a document's explicit `Deny` of the publish for
//! that principal is terminal, so the rule is refused with the refusal the addressed member
//! carries (`InvalidSnsTopic`, HTTP 400, "Could not publish to SNS topic: <TopicArn>") and
//! NOTHING is persisted. A topic of the account the rule belongs to needs no grant of its own,
//! so every other answer its policy gives leaves the rule storable: an allow, the access policy
//! Amazon SNS generates for a topic whose owner set none, a deny about another principal,
//! another action, another resource, another account or another receipt rule.
//!
//! The table spans what the rule generalises over: the effect and the shape of the statements
//! the topic's policy carries (the action spelled out, spelled with a wildcard and spelled as
//! another action; the principal named as this service, as another service and as every
//! principal; the resource named as this topic, as every resource and as another topic; a deny
//! beside an allow), the condition keys a statement scopes itself by and the values the publish
//! carries for them (the account the rule belongs to and the receipt rule itself, each matched
//! and each mismatched), and which member of the action names the topic (`SNSAction.TopicArn`
//! and the notification topic of a `BounceAction`). The recorded case is ONE row of it.
//!
//! Every topic and policy here is written through Amazon SNS's OWN operations over the
//! in-process callback, so what the pre-flight reads is what Amazon SNS really holds. Each row
//! also holds the pre-flight to being a READ of the destination: after the call the topic's
//! policy is byte-identical to the one the row stored (Amazon SES granted itself nothing) and
//! the topic has no subscription (storing a rule subscribes nothing).
//!
//! The same pre-flight backs `CreateReceiptRule` and `UpdateReceiptRule`, so the table is
//! driven through both.

use crate::harness::{account, call, element, elements, error_envelope, field, sns, Field, REGION};
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

/// The rule set every rule below is added to.
const RULE_SET: &str = "sns-policy-rules";

/// The service principal Amazon SES acts under when it carries out a receipt rule's actions,
/// and so the principal a topic policy names to say something about those actions.
const SES_SERVICE_PRINCIPAL: &str = "ses.amazonaws.com";

/// An account that is NOT the one this emulator serves, for the rows whose condition names
/// another account.
const ANOTHER_ACCOUNT: &str = "210987654321";

/// The action whose last-good state a refused UPDATE must leave the stored rule at: it
/// addresses no destination of its own, so no pre-flight stands between it and the store.
fn harmless_action() -> Vec<Field> {
    vec![
        field("Rule.Actions.member.1.AddHeaderAction.HeaderName", "X-Probe"),
        field("Rule.Actions.member.1.AddHeaderAction.HeaderValue", "kept"),
    ]
}

/// What a row's policy is written about: the topic it is attached to, the account the rule
/// belongs to, the receipt rule being stored, and a topic that is NOT the one the action names.
struct Target {
    /// The ARN Amazon SNS minted for the row's own topic.
    topic_arn: String,
    /// The account this emulator serves, which is the account the rule belongs to.
    account_id: String,
    /// The ARN of the receipt rule the row stores, which is what `aws:SourceArn` carries.
    rule_arn: String,
    /// Another topic's ARN, for a statement that is about a different resource.
    other_topic_arn: String,
}

/// Which member of the action names the topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Member {
    /// `SNSAction.TopicArn` — the action that exists to publish a notification.
    SnsAction,
    /// `BounceAction.TopicArn` — the notification topic of another action.
    BounceAction,
}

impl Member {
    /// The `Rule.Actions.member.1.*` form fields of an action naming `topic_arn` through this
    /// member.
    fn fields(self, topic_arn: &str) -> Vec<Field> {
        match self {
            Self::SnsAction => vec![
                field("Rule.Actions.member.1.SNSAction.TopicArn", topic_arn),
                field("Rule.Actions.member.1.SNSAction.Encoding", "UTF-8"),
            ],
            Self::BounceAction => vec![
                field("Rule.Actions.member.1.BounceAction.TopicArn", topic_arn),
                field("Rule.Actions.member.1.BounceAction.SmtpReplyCode", "550"),
                field("Rule.Actions.member.1.BounceAction.Message", "Mailbox full"),
                field(
                    "Rule.Actions.member.1.BounceAction.Sender",
                    "bounces@example.com",
                ),
            ],
        }
    }
}

/// One row of the table: what the action's topic says about the publish, and whether the rule
/// may be stored.
struct PolicyCase {
    /// What the row is, named in every assertion it makes.
    case: &'static str,
    /// The rule and the topic the row uses, which are its own.
    name: &'static str,
    /// Which member names the topic.
    member: Member,
    /// The topic's access policy, or `None` to leave the one Amazon SNS generates in place.
    policy: Option<fn(&Target) -> Value>,
    /// Whether the rule must be refused.
    refused: bool,
}

/// A policy document carrying `statements`.
fn policy(statements: Value) -> Value {
    json!({"Version": "2008-10-17", "Id": "case-policy", "Statement": statements})
}

/// One statement denying the service principal the publish on `topic_arn` — the statement the
/// recorded case appends to the topic's own policy.
fn deny_ses_publish(topic_arn: &str) -> Value {
    json!({
        "Sid": "deny-ses-publish",
        "Effect": "Deny",
        "Principal": {"Service": SES_SERVICE_PRINCIPAL},
        "Action": "sns:Publish",
        "Resource": topic_arn,
    })
}

/// One statement allowing the service principal that same publish.
fn allow_ses_publish(topic_arn: &str) -> Value {
    json!({
        "Sid": "allow-ses-publish",
        "Effect": "Allow",
        "Principal": {"Service": SES_SERVICE_PRINCIPAL},
        "Action": "sns:Publish",
        "Resource": topic_arn,
    })
}

/// The rows: the same rule, differing in what its topic's policy says about the publish.
const POLICY_CASES: &[PolicyCase] = &[
    PolicyCase {
        case: "the access policy Amazon SNS generates for a topic whose owner set none",
        name: "default-policy",
        member: Member::SnsAction,
        policy: None,
        refused: false,
    },
    PolicyCase {
        case: "an explicit deny of the publish to the Amazon SES service principal",
        name: "denied",
        member: Member::SnsAction,
        policy: Some(|target| policy(json!([deny_ses_publish(&target.topic_arn)]))),
        refused: true,
    },
    PolicyCase {
        case: "that same deny, named by another action's notification member",
        name: "denied-bounce",
        member: Member::BounceAction,
        policy: Some(|target| policy(json!([deny_ses_publish(&target.topic_arn)]))),
        refused: true,
    },
    PolicyCase {
        case: "a deny written with a wildcard action",
        name: "denied-wildcard-action",
        member: Member::SnsAction,
        policy: Some(|target| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": {"Service": SES_SERVICE_PRINCIPAL},
                "Action": "SNS:*",
                "Resource": target.topic_arn,
            }]))
        }),
        refused: true,
    },
    PolicyCase {
        case: "a deny of the publish to every principal on every resource",
        name: "denied-every-principal",
        member: Member::SnsAction,
        policy: Some(|_| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sns:Publish",
                "Resource": "*",
            }]))
        }),
        refused: true,
    },
    PolicyCase {
        case: "an allow and a deny of the same publish, where the deny wins",
        name: "denied-beside-allow",
        member: Member::SnsAction,
        policy: Some(|target| {
            policy(json!([
                allow_ses_publish(&target.topic_arn),
                deny_ses_publish(&target.topic_arn),
            ]))
        }),
        refused: true,
    },
    PolicyCase {
        case: "a deny scoped to the account the receipt rule belongs to",
        name: "denied-this-account",
        member: Member::SnsAction,
        policy: Some(|target| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": {"Service": SES_SERVICE_PRINCIPAL},
                "Action": "sns:Publish",
                "Resource": target.topic_arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": target.account_id}},
            }]))
        }),
        refused: true,
    },
    PolicyCase {
        case: "a deny scoped to the receipt rule being stored",
        name: "denied-this-rule",
        member: Member::SnsAction,
        policy: Some(|target| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": {"Service": SES_SERVICE_PRINCIPAL},
                "Action": "sns:Publish",
                "Resource": target.topic_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": target.rule_arn}},
            }]))
        }),
        refused: true,
    },
    PolicyCase {
        case: "an allow of the publish to the Amazon SES service principal",
        name: "allowed",
        member: Member::SnsAction,
        policy: Some(|target| policy(json!([allow_ses_publish(&target.topic_arn)]))),
        refused: false,
    },
    PolicyCase {
        case: "a deny of another Amazon SNS action",
        name: "denied-other-action",
        member: Member::SnsAction,
        policy: Some(|target| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": {"Service": SES_SERVICE_PRINCIPAL},
                "Action": "sns:Subscribe",
                "Resource": target.topic_arn,
            }]))
        }),
        refused: false,
    },
    PolicyCase {
        case: "a deny of the publish to another service principal",
        name: "denied-other-principal",
        member: Member::SnsAction,
        policy: Some(|target| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": target.topic_arn,
            }]))
        }),
        refused: false,
    },
    PolicyCase {
        case: "a deny of the publish on another topic",
        name: "denied-other-topic",
        member: Member::SnsAction,
        policy: Some(|target| policy(json!([deny_ses_publish(&target.other_topic_arn)]))),
        refused: false,
    },
    PolicyCase {
        case: "a deny scoped to another account",
        name: "denied-other-account",
        member: Member::SnsAction,
        policy: Some(|target| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": {"Service": SES_SERVICE_PRINCIPAL},
                "Action": "sns:Publish",
                "Resource": target.topic_arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": ANOTHER_ACCOUNT}},
            }]))
        }),
        refused: false,
    },
    PolicyCase {
        case: "a deny scoped to another receipt rule",
        name: "denied-other-rule",
        member: Member::SnsAction,
        policy: Some(|_| {
            policy(json!([{
                "Effect": "Deny",
                "Principal": {"Service": SES_SERVICE_PRINCIPAL},
                "Action": "sns:Publish",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceArn": receipt_rule_arn("some-other-rule")}},
            }]))
        }),
        refused: false,
    },
];

/// The ARN of the receipt rule `rule_name` of [`RULE_SET`], which is the value the publish
/// Amazon SES makes for that rule carries in `aws:SourceArn`.
fn receipt_rule_arn(rule_name: &str) -> String {
    format!(
        "arn:aws:ses:{REGION}:{}:receipt-rule-set/{RULE_SET}:receipt-rule/{rule_name}",
        account()
    )
}

/// The sentence a refused action carries: the fixed prefix plus the `TopicArn` the REQUEST
/// named. Written out here, so the suite pins the wording rather than reading it back from the
/// code under test.
fn refusal(topic_arn: &str) -> String {
    format!("Could not publish to SNS topic: {topic_arn}")
}

/// `CreateReceiptRuleSet`.
async fn create_rule_set(router: &MultiServiceRouter) {
    let (status, body) = call(
        router,
        "CreateReceiptRuleSet",
        &[field("RuleSetName", RULE_SET)],
    )
    .await;
    assert_eq!(
        status, 200,
        "creating the rule set: expected 200, got {status} with {body}"
    );
}

/// Create the topic `name` through Amazon SNS's own operation, and answer its ARN.
async fn create_topic(router: &MultiServiceRouter, case: &str, name: &str) -> String {
    sns(router)
        .create_topic()
        .name(name)
        .send()
        .await
        .unwrap_or_else(|error| panic!("case {case:?}: creating the topic {name}: {error}"))
        .topic_arn()
        .unwrap_or_else(|| panic!("case {case:?}: the created topic has an ARN"))
        .to_string()
}

/// Make `document` the access policy of the topic `topic_arn`.
async fn set_topic_policy(router: &MultiServiceRouter, case: &str, topic_arn: &str, document: &str) {
    sns(router)
        .set_topic_attributes()
        .topic_arn(topic_arn)
        .attribute_name("Policy")
        .attribute_value(document)
        .send()
        .await
        .unwrap_or_else(|error| panic!("case {case:?}: storing the topic's policy: {error}"));
}

/// The `Policy` attribute the topic `topic_arn` reports, read through Amazon SNS itself.
async fn stored_topic_policy(router: &MultiServiceRouter, case: &str, topic_arn: &str) -> String {
    sns(router)
        .get_topic_attributes()
        .topic_arn(topic_arn)
        .send()
        .await
        .unwrap_or_else(|error| panic!("case {case:?}: reading the topic's attributes: {error}"))
        .attributes()
        .and_then(|attributes| attributes.get("Policy"))
        .cloned()
        .unwrap_or_default()
}

/// How many subscriptions Amazon SNS holds for the topic `topic_arn`.
async fn subscription_count(router: &MultiServiceRouter, case: &str, topic_arn: &str) -> usize {
    sns(router)
        .list_subscriptions_by_topic()
        .topic_arn(topic_arn)
        .send()
        .await
        .unwrap_or_else(|error| panic!("case {case:?}: listing the topic's subscriptions: {error}"))
        .subscriptions()
        .len()
}

/// `CreateReceiptRule` carrying the rule `rule_name` whose only action is `action`.
async fn create_rule(
    router: &MultiServiceRouter,
    rule_name: &str,
    action: &[Field],
) -> (u16, String) {
    write_rule(router, "CreateReceiptRule", rule_name, action).await
}

/// `UpdateReceiptRule` carrying that same rule.
async fn update_rule(
    router: &MultiServiceRouter,
    rule_name: &str,
    action: &[Field],
) -> (u16, String) {
    write_rule(router, "UpdateReceiptRule", rule_name, action).await
}

/// The one request shape `CreateReceiptRule` and `UpdateReceiptRule` share.
async fn write_rule(
    router: &MultiServiceRouter,
    action_name: &str,
    rule_name: &str,
    action: &[Field],
) -> (u16, String) {
    let mut params = vec![
        field("RuleSetName", RULE_SET),
        field("Rule.Name", rule_name),
        field("Rule.Enabled", "true"),
        field("Rule.ScanEnabled", "false"),
    ];
    params.extend(action.iter().cloned());
    call(router, action_name, &params).await
}

/// The `<Rule>` element `DescribeReceiptRule` reports for `rule_name`, or `None` when the set
/// holds no rule of that name.
async fn described_rule(router: &MultiServiceRouter, rule_name: &str) -> Option<String> {
    let (status, body) = call(
        router,
        "DescribeReceiptRule",
        &[field("RuleSetName", RULE_SET), field("RuleName", rule_name)],
    )
    .await;
    (status == 200).then(|| element(&body, "Rule")).flatten()
}

/// The names of the rules `DescribeReceiptRuleSet` reports for [`RULE_SET`], in the order the
/// set holds them.
async fn rule_names(router: &MultiServiceRouter) -> Vec<String> {
    let (status, body) = call(
        router,
        "DescribeReceiptRuleSet",
        &[field("RuleSetName", RULE_SET)],
    )
    .await;
    assert_eq!(
        status, 200,
        "reading the rule set: expected 200, got {status} with {body}"
    );
    elements(&element(&body, "Rules").unwrap_or_default(), "Name")
}

/// Assert that `body` is the modelled refusal of the topic `topic_arn`, at HTTP 400.
fn assert_refused(case: &str, status: u16, body: &str, topic_arn: &str) {
    assert_eq!(
        status, 400,
        "case {case:?}: expected HTTP 400, got {status} with {body}"
    );
    let envelope = error_envelope(body);
    let expected = (
        Some("InvalidSnsTopic".to_string()),
        Some(refusal(topic_arn)),
    );
    assert_eq!(
        envelope, expected,
        "case {case:?}: expected {expected:?}, got {envelope:?}"
    );
}

/// Assert that storing the rule left the topic exactly as the row did: the policy it stored and
/// no subscription of its own.
async fn assert_topic_untouched(
    router: &MultiServiceRouter,
    case: &str,
    topic_arn: &str,
    policy_before: &str,
) {
    let policy_after = stored_topic_policy(router, case, topic_arn).await;
    assert_eq!(
        policy_after, policy_before,
        "case {case:?}: expected the topic's policy to be left as it was, got {policy_after:?}"
    );
    let subscriptions = subscription_count(router, case, topic_arn).await;
    assert_eq!(
        subscriptions, 0,
        "case {case:?}: expected the topic to have no subscription, got {subscriptions}"
    );
}

/// Set up the row's topic and answer `(topic_arn, the policy it stored, the action's fields)`.
async fn given_topic(router: &MultiServiceRouter, row: &PolicyCase) -> (String, String, Vec<Field>) {
    let topic_arn = create_topic(router, row.case, &format!("{}-topic", row.name)).await;
    if let Some(write) = row.policy {
        let target = Target {
            topic_arn: topic_arn.clone(),
            account_id: account(),
            rule_arn: receipt_rule_arn(row.name),
            other_topic_arn: create_topic(
                router,
                row.case,
                &format!("{}-other-topic", row.name),
            )
            .await,
        };
        set_topic_policy(router, row.case, &topic_arn, &write(&target).to_string()).await;
    }
    let stored = stored_topic_policy(router, row.case, &topic_arn).await;
    let action = row.member.fields(&topic_arn);
    (topic_arn, stored, action)
}

/// `CreateReceiptRule` stores a rule only where the topic its action notifies does not deny the
/// Amazon SES service principal the publish, and a refused call persists nothing.
#[tokio::test]
async fn an_action_topic_policy_decides_whether_the_created_rule_is_stored() {
    let router = crate::harness::emulator_with_sns();
    create_rule_set(&router).await;

    for row in POLICY_CASES {
        let case = row.case;
        let (topic_arn, policy_before, action) = given_topic(&router, row).await;

        let (status, body) = create_rule(&router, row.name, &action).await;
        if row.refused {
            assert_refused(case, status, &body, &topic_arn);
            let reported = described_rule(&router, row.name).await;
            assert_eq!(
                reported, None,
                "case {case:?}: expected the refused rule not to be stored, got {reported:?}"
            );
            let names = rule_names(&router).await;
            assert!(
                !names.iter().any(|name| name == row.name),
                "case {case:?}: expected the set not to list {:?}, got {names:?}",
                row.name
            );
        } else {
            assert_eq!(
                status, 200,
                "case {case:?}: expected the rule to be stored, got {status} with {body}"
            );
            let reported = described_rule(&router, row.name).await.unwrap_or_default();
            assert_eq!(
                element(&reported, "TopicArn").as_deref(),
                Some(topic_arn.as_str()),
                "case {case:?}: expected the stored rule to carry {topic_arn:?}, got {reported}"
            );
        }
        assert_topic_untouched(&router, case, &topic_arn, &policy_before).await;
    }
}

/// `UpdateReceiptRule` runs the SAME pre-flight, and a refused update leaves the stored rule at
/// its last-good state.
#[tokio::test]
async fn an_action_topic_policy_decides_whether_the_updated_rule_is_stored() {
    let router = crate::harness::emulator_with_sns();
    create_rule_set(&router).await;

    for row in POLICY_CASES {
        let case = row.case;
        let (topic_arn, policy_before, action) = given_topic(&router, row).await;

        // The rule the update replaces: an action with no destination of its own, so the
        // last-good state a refused update must leave behind is one this suite can read back.
        let (status, body) = create_rule(&router, row.name, &harmless_action()).await;
        assert_eq!(
            status, 200,
            "case {case:?}: seeding the last-good rule: expected 200, got {status} with {body}"
        );
        let before = described_rule(&router, row.name).await;

        let (status, body) = update_rule(&router, row.name, &action).await;
        if row.refused {
            assert_refused(case, status, &body, &topic_arn);
            let after = described_rule(&router, row.name).await;
            assert_eq!(
                after, before,
                "case {case:?}: expected the refused update to leave the stored rule untouched, \
                 got {after:?}"
            );
        } else {
            assert_eq!(
                status, 200,
                "case {case:?}: expected the update to be stored, got {status} with {body}"
            );
            let reported = described_rule(&router, row.name).await.unwrap_or_default();
            assert_eq!(
                element(&reported, "TopicArn").as_deref(),
                Some(topic_arn.as_str()),
                "case {case:?}: expected the updated rule to carry {topic_arn:?}, got {reported}"
            );
        }
        assert_topic_untouched(&router, case, &topic_arn, &policy_before).await;
    }
}

/// The refusal is the POLICY's, not the topic's: appending the deny to a topic that took the
/// identical rule a moment ago refuses it, and removing the deny again lets the same bytes
/// through — with the topic left exactly as the caller left it both times, and still publishable
/// by the caller that owns it while Amazon SES is denied.
#[tokio::test]
async fn the_refusal_follows_the_deny_statement_onto_and_off_the_topic() {
    let router = crate::harness::emulator_with_sns();
    create_rule_set(&router).await;
    let case = "a deny appended to the topic's own policy and then removed";
    let rule = "sns-notify";

    let topic_arn = create_topic(&router, case, "lifecycle-topic").await;
    let baseline = stored_topic_policy(&router, case, &topic_arn).await;
    assert!(
        !baseline.contains(SES_SERVICE_PRINCIPAL),
        "case {case:?}: expected the generated policy to state nothing about \
         {SES_SERVICE_PRINCIPAL}, got {baseline:?}"
    );
    let action = Member::SnsAction.fields(&topic_arn);

    // With the generated policy the rule is stored, and is then taken back out of the set.
    let (status, body) = create_rule(&router, rule, &action).await;
    assert_eq!(
        status, 200,
        "case {case:?} (baseline): expected the rule to be stored, got {status} with {body}"
    );
    let (status, body) = call(
        &router,
        "DeleteReceiptRule",
        &[field("RuleSetName", RULE_SET), field("RuleName", rule)],
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: deleting the control rule: expected 200, got {status} with {body}"
    );

    // ONE deny statement appended to the document the topic already carried.
    let mut document: Value = serde_json::from_str(&baseline)
        .unwrap_or_else(|error| panic!("case {case:?}: the stored policy is a document: {error}"));
    let statements = document
        .get_mut("Statement")
        .and_then(Value::as_array_mut)
        .unwrap_or_else(|| panic!("case {case:?}: the stored policy carries a Statement list"));
    statements.push(deny_ses_publish(&topic_arn));
    let denying = document.to_string();
    set_topic_policy(&router, case, &topic_arn, &denying).await;
    let stored = stored_topic_policy(&router, case, &topic_arn).await;
    assert!(
        stored.contains("deny-ses-publish"),
        "case {case:?}: expected the stored policy to carry the deny, got {stored:?}"
    );

    let (status, body) = create_rule(&router, rule, &action).await;
    assert_refused(case, status, &body, &topic_arn);
    let names = rule_names(&router).await;
    assert!(
        names.is_empty(),
        "case {case:?}: expected the refused call to persist nothing, got {names:?}"
    );
    assert_topic_untouched(&router, case, &topic_arn, &stored).await;
    // The deny is PRINCIPAL-scoped, so the topic itself is healthy: what it withholds from the
    // service principal it does not withhold from the caller that owns it, whose own publish
    // still answers with a message id. That is what tells "the deny blocked Amazon SES" apart
    // from "the topic became unusable".
    let published = sns(&router)
        .publish()
        .topic_arn(&topic_arn)
        .subject("still reachable")
        .message("the owner's own publish is not what the deny is about")
        .send()
        .await
        .unwrap_or_else(|error| panic!("case {case:?}: the caller's own publish: {error}"));
    assert!(
        published.message_id().is_some_and(|id| !id.is_empty()),
        "case {case:?}: expected the caller's own publish to answer a message id, got {:?}",
        published.message_id()
    );

    // The baseline restored: the identical call goes through again.
    set_topic_policy(&router, case, &topic_arn, &baseline).await;
    let restored = stored_topic_policy(&router, case, &topic_arn).await;
    let (status, body) = create_rule(&router, rule, &action).await;
    assert_eq!(
        status, 200,
        "case {case:?} (restored): expected the identical rule to be stored, got {status} with \
         {body}"
    );
    assert_eq!(
        rule_names(&router).await,
        vec![rule.to_string()],
        "case {case:?}: expected the set to hold only {rule:?}"
    );
    assert_topic_untouched(&router, case, &topic_arn, &restored).await;
}
