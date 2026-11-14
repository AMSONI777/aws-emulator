// SPDX-License-Identifier: CC0-1.0

//! The PRECISION of the rule patterns an `aws.rds` DB instance event is matched against.
//!
//! A lifecycle change this service records is published onto the account's default
//! EventBridge bus ([`crate::db_instance_bus_events`] asserts the envelope itself). What this
//! suite asserts is the other half of that path: which rules such a publication is delivered
//! to. EventBridge matches an event against a rule's pattern FIELD BY FIELD and value for
//! value, so a rule whose pattern differs from the published envelope in any ONE field — the
//! `source`, the `detail-type`, a `detail` member it pins that the envelope carries another
//! value for, or one more `detail` member it pins — receives nothing from that publication,
//! while the rule whose pattern agrees with every field it pins receives it at each of its
//! targets.
//!
//! The rule generalises over WHICH field is off, so the table below spans one row per field
//! of the pattern a DB instance restart is matched by, each row differing from the matching
//! pattern in exactly that one field: another event identifier of the same source type, the
//! ARN of ANOTHER DB instance the account really holds, the ARN of an instance it holds no
//! record of, the detail-type of another RDS source type, another service's source, and one
//! further pinned `detail` member. Every one of those rules must stay silent on a publication
//! the matching rule receives — and, once `PutRule` rewrites its pattern to the matching one,
//! the very same rule and target must receive the next publication, so a queue that was
//! silent because the emulator delivers nothing at all could not pass.
//!
//! Every ARN a pattern pins is read off the service's own answer (`DBInstance$DBInstanceArn`,
//! `PutRule`'s `RuleArn`) rather than spelled here, and every assertion reads a message a
//! queue really handed over, with EventBridge and Amazon SQS mounted beside this service on
//! ONE engine exactly as the assembled router mounts them.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::db_instance_bus_events::{
    collect, drain, emulator, events, queue_arn, sqs, wait_for_status, ACCOUNT, DB_INSTANCE_EVENT,
    DB_SNAPSHOT_EVENT, EVENT_SOURCE,
};
use crate::db_instances::{call, expect_ok, subtrees, text, REGION};

/// `detail.EventID` of the change a reboot records.
///
/// Source: the per-source-type tables of "Amazon RDS event categories and event messages"
/// (Amazon RDS User Guide) — the DB instance row whose message is `DB instance restarted`,
/// which is the row this service records a restart from
/// (`service_com_amazonaws_rds_amazonrdsv19::state::events`).
const RESTART_EVENT_ID: &str = "RDS-EVENT-0006";

/// `detail.EventID` of ANOTHER change of the SAME source type — the stop of a DB instance —
/// which is what the "one event identifier off" row pins. Same source.
const STOP_EVENT_ID: &str = "RDS-EVENT-0087";

/// The instance every pattern below is written for.
const PRIMARY: &str = "emu-pattern-db";

/// A SECOND DB instance of the same account, so a pattern can pin the ARN of an instance that
/// really exists and is not the one that changed.
const SIBLING: &str = "emu-pattern-other";

/// An identifier the account holds no DB instance for, so a pattern can pin an ARN that
/// resolves to nothing.
const ABSENT: &str = "emu-pattern-absent";

/// The pattern that matches the restart of the instance at `arn` exactly: the `source` and
/// `detail-type` of an RDS DB instance event, and the restart's own identifier and source
/// ARN.
fn matching_pattern(arn: &str) -> Value {
    json!({
        "source": [EVENT_SOURCE],
        "detail-type": [DB_INSTANCE_EVENT],
        "detail": { "EventID": [RESTART_EVENT_ID], "SourceArn": [arn] },
    })
}

/// One rule whose pattern is the matching one with a single field changed.
struct NearMiss {
    /// What this row changes, for the assertion messages.
    case: &'static str,
    /// The name of this row's rule and of the queue it targets.
    slug: &'static str,
    /// The pattern itself.
    pattern: Value,
}

/// The table: one row per field of the matching pattern, each differing in that field alone.
fn near_misses(arn: &str, sibling_arn: &str) -> Vec<NearMiss> {
    vec![
        NearMiss {
            case: "another event identifier of the same source type",
            slug: "emu-pattern-event-id",
            pattern: json!({
                "source": [EVENT_SOURCE],
                "detail-type": [DB_INSTANCE_EVENT],
                "detail": { "EventID": [STOP_EVENT_ID], "SourceArn": [arn] },
            }),
        },
        NearMiss {
            case: "the ARN of another DB instance the account holds",
            slug: "emu-pattern-other-arn",
            pattern: matching_pattern(sibling_arn),
        },
        NearMiss {
            case: "the ARN of an instance the account holds no record of",
            slug: "emu-pattern-absent-arn",
            pattern: matching_pattern(&format!("arn:aws:rds:{REGION}:{ACCOUNT}:db:{ABSENT}")),
        },
        NearMiss {
            case: "the detail-type of another RDS source type",
            slug: "emu-pattern-detail-type",
            pattern: json!({
                "source": [EVENT_SOURCE],
                "detail-type": [DB_SNAPSHOT_EVENT],
                "detail": { "EventID": [RESTART_EVENT_ID], "SourceArn": [arn] },
            }),
        },
        NearMiss {
            case: "another service's source",
            slug: "emu-pattern-source",
            pattern: json!({
                "source": ["aws.ec2"],
                "detail-type": [DB_INSTANCE_EVENT],
                "detail": { "EventID": [RESTART_EVENT_ID], "SourceArn": [arn] },
            }),
        },
        NearMiss {
            case: "one further pinned detail member, carrying another source type",
            slug: "emu-pattern-source-type",
            pattern: json!({
                "source": [EVENT_SOURCE],
                "detail-type": [DB_INSTANCE_EVENT],
                "detail": {
                    "EventID": [RESTART_EVENT_ID],
                    "SourceArn": [arn],
                    "SourceType": ["DB_CLUSTER"],
                },
            }),
        },
    ]
}

/// Put the rule `name` on the default bus with `pattern`, give it its own queue, and grant
/// EventBridge the send on that queue scoped by `aws:SourceArn` to this rule — the grant a
/// client writes for a rule's SQS target. Answers the queue's URL.
async fn rule_to_its_own_queue(router: &MultiServiceRouter, name: &str, pattern: &Value) -> String {
    let put = events(
        router,
        "PutRule",
        &json!({ "Name": name, "EventPattern": pattern.to_string(), "State": "ENABLED" }),
    )
    .await;
    // The ARN the grant below is scoped to is the one EventBridge answered with, not one
    // spelled here.
    let rule_arn = put["RuleArn"]
        .as_str()
        .unwrap_or_else(|| panic!("PutRule must answer the rule's ARN, got {put}"))
        .to_string();
    let created = sqs(router, "CreateQueue", &json!({ "QueueName": name })).await;
    let url = created["QueueUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("CreateQueue must answer a QueueUrl, got {created}"))
        .to_string();
    let document = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": "events.amazonaws.com" },
            "Action": "sqs:SendMessage",
            "Resource": queue_arn(name),
            "Condition": { "ArnEquals": { "aws:SourceArn": rule_arn } },
        }],
    });
    sqs(
        router,
        "SetQueueAttributes",
        &json!({ "QueueUrl": url, "Attributes": { "Policy": document.to_string() } }),
    )
    .await;
    let targeted = events(
        router,
        "PutTargets",
        &json!({
            "Rule": name,
            "Targets": [{ "Id": "the-queue", "Arn": queue_arn(name) }],
        }),
    )
    .await;
    assert_eq!(
        targeted["FailedEntryCount"].as_i64(),
        Some(0),
        "case {name:?}: the target must be accepted, got {targeted}"
    );
    url
}

/// Two DB instances of one account, and one rule per pattern of the table, each delivering to
/// its own queue.
struct Scenario {
    router: MultiServiceRouter,
    /// The ARN this service reports for [`PRIMARY`].
    arn: String,
    /// The ARN this service reports for [`SIBLING`].
    sibling_arn: String,
    /// The queue of the rule whose pattern matches [`PRIMARY`]'s restart exactly.
    matching_queue: String,
    /// Each near-miss row and the queue its rule targets.
    near: Vec<(NearMiss, String)>,
}

impl Scenario {
    async fn build() -> Self {
        let router = emulator();
        let arn = create_available(&router, PRIMARY).await;
        let sibling_arn = create_available(&router, SIBLING).await;
        let matching_queue =
            rule_to_its_own_queue(&router, "emu-pattern-matching", &matching_pattern(&arn)).await;
        let mut near = Vec::new();
        for row in near_misses(&arn, &sibling_arn) {
            let url = rule_to_its_own_queue(&router, row.slug, &row.pattern).await;
            near.push((row, url));
        }
        Self {
            router,
            arn,
            sibling_arn,
            matching_queue,
            near,
        }
    }

    /// Restart `identifier` once it is available again, which is what publishes the event the
    /// rules above are matched against.
    async fn reboot(&self, identifier: &str) {
        wait_for_status(&self.router, identifier, "available").await;
        expect_ok(
            identifier,
            call(
                &self.router,
                "RebootDBInstance",
                &[("DBInstanceIdentifier", identifier)],
            )
            .await,
        );
    }
}

/// `CreateDBInstance` for `identifier`, waited until it is available, as the ARN the service
/// itself reports for it.
async fn create_available(router: &MultiServiceRouter, identifier: &str) -> String {
    let created = expect_ok(
        identifier,
        call(
            router,
            "CreateDBInstance",
            &[
                ("DBInstanceIdentifier", identifier),
                ("Engine", "postgres"),
                ("DBInstanceClass", "db.t4g.micro"),
            ],
        )
        .await,
    );
    let instance = subtrees(&created, "DBInstance")
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("CreateDBInstance must answer a DBInstance, got {created}"));
    wait_for_status(router, identifier, "available").await;
    text(&instance, "DBInstanceArn")
}

/// Assert `body` is the envelope of the restart of the instance at `arn`.
fn assert_restart_of(case: &str, body: &str, arn: &str) {
    let event: Value = serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("case {case:?}: {body} must be JSON: {error}"));
    for (member, expected) in [
        ("source", json!(EVENT_SOURCE)),
        ("detail-type", json!(DB_INSTANCE_EVENT)),
    ] {
        assert_eq!(
            event[member], expected,
            "case {case:?}: expected {member} {expected}, got {event}"
        );
    }
    assert_eq!(
        event["detail"]["EventID"],
        json!(RESTART_EVENT_ID),
        "case {case:?}: expected the restart's identifier {RESTART_EVENT_ID}, got {event}"
    );
    assert_eq!(
        event["detail"]["SourceArn"],
        json!(arn),
        "case {case:?}: expected the source ARN {arn:?}, got {event}"
    );
}

/// Assert the queue holds nothing: both depth attributes report zero, and a read of it hands
/// over no message at all.
async fn assert_holds_nothing(router: &MultiServiceRouter, case: &str, queue_url: &str) {
    let reported = sqs(
        router,
        "GetQueueAttributes",
        &json!({
            "QueueUrl": queue_url,
            "AttributeNames": [
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
            ],
        }),
    )
    .await;
    for attribute in [
        "ApproximateNumberOfMessages",
        "ApproximateNumberOfMessagesNotVisible",
    ] {
        assert_eq!(
            reported["Attributes"][attribute],
            json!("0"),
            "case {case:?}: expected {attribute} \"0\", got {reported}"
        );
    }
    let held = drain(router, queue_url).await;
    assert!(
        held.is_empty(),
        "case {case:?}: expected no message on the queue, got {held:?}"
    );
}

/// RULE: a publication is delivered to the rule whose pattern agrees with every field it
/// pins, and to no rule that differs from the envelope in any one of them.
#[tokio::test]
async fn only_the_rule_whose_pattern_agrees_with_the_envelope_is_delivered_it() {
    let scenario = Scenario::build().await;
    scenario.reboot(PRIMARY).await;

    // The matching rule's queue is the positive control AND the witness for the rows below:
    // one publication is matched against every rule of the bus, so once it has arrived here
    // every other rule has been decided against the same event.
    let delivered = collect(&scenario.router, &scenario.matching_queue, 1).await;
    assert_eq!(
        delivered.len(),
        1,
        "the exactly matching rule receives the restart exactly once, got {delivered:?}"
    );
    assert_restart_of("the exactly matching pattern", &delivered[0], &scenario.arn);

    for (row, url) in &scenario.near {
        assert_holds_nothing(&scenario.router, row.case, url).await;
    }
}

/// RULE: the pattern a rule is matched by is the one it holds NOW — `PutRule` over an
/// existing name rewrites it, keeping the rule's targets, so a rule that received nothing
/// receives the next publication once its pattern agrees with the envelope.
#[tokio::test]
async fn a_rule_rewritten_to_the_matching_pattern_receives_the_next_restart() {
    let scenario = Scenario::build().await;
    let matching = matching_pattern(&scenario.arn);
    for (row, _) in &scenario.near {
        events(
            &scenario.router,
            "PutRule",
            &json!({
                "Name": row.slug,
                "EventPattern": matching.to_string(),
                "State": "ENABLED",
            }),
        )
        .await;
        // The rewrite leaves the rule's own target in place: it is the SAME rule and the
        // same queue that was silent before.
        let targets = events(
            &scenario.router,
            "ListTargetsByRule",
            &json!({ "Rule": row.slug }),
        )
        .await;
        assert_eq!(
            targets["Targets"],
            json!([{ "Id": "the-queue", "Arn": queue_arn(row.slug) }]),
            "case {:?}: the rewritten rule keeps its target, got {targets}",
            row.case
        );
    }

    scenario.reboot(PRIMARY).await;

    for (row, url) in &scenario.near {
        let delivered = collect(&scenario.router, url, 1).await;
        assert_eq!(
            delivered.len(),
            1,
            "case {:?}: the rewritten rule receives the restart, got {delivered:?}",
            row.case
        );
        assert_restart_of(row.case, &delivered[0], &scenario.arn);
    }
}

/// RULE: the `detail.SourceArn` a pattern pins is the ARN of the resource that CHANGED, so a
/// rule written for one instance is not delivered another instance's restart — the pinned
/// value is matched against the publication's own, not against the shape of the pattern.
#[tokio::test]
async fn a_pattern_pinning_one_instance_is_not_delivered_anothers_restart() {
    let scenario = Scenario::build().await;
    // A rule for the SIBLING's restart, so this publication has a rule it must reach: once
    // its queue holds the event, the same publication has been decided against the rule
    // written for the primary.
    let witness = rule_to_its_own_queue(
        &scenario.router,
        "emu-pattern-sibling",
        &matching_pattern(&scenario.sibling_arn),
    )
    .await;

    scenario.reboot(SIBLING).await;

    let delivered = collect(&scenario.router, &witness, 1).await;
    assert_eq!(
        delivered.len(),
        1,
        "the sibling instance's own rule receives its restart, got {delivered:?}"
    );
    assert_restart_of(
        "the rule pinning the sibling instance",
        &delivered[0],
        &scenario.sibling_arn,
    );

    assert_holds_nothing(
        &scenario.router,
        "the rule pinning the primary instance, on the sibling's restart",
        &scenario.matching_queue,
    )
    .await;
}
