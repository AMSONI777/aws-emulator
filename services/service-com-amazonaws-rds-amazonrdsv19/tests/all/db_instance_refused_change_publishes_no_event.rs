// SPDX-License-Identifier: CC0-1.0

//! What a REFUSED Amazon RDS call publishes onto the account's default EventBridge bus, and
//! what it adds to the log the control plane projects: nothing, in both places.
//!
//! The sibling suites assert the publication itself ([`crate::db_instance_bus_events`]) and
//! which rules it is delivered to ([`crate::db_instance_event_pattern_precision`]). What this
//! one asserts is the other side of the same rule: a published `aws.rds` envelope exists only
//! because this service PERFORMED the change it describes, so a call it refused leaves both
//! the bus and `DescribeEvents` exactly as they were. That is what makes the stream usable at
//! all — automation that reacts to a restart must not be woken by a restart that never
//! happened.
//!
//! The table spans what the rule generalises over, which is the REFUSAL, not any one
//! operation: a resource the account holds no record of (HTTP 404), a resource that exists in
//! another Region (404, the regional scope of every record of this service), a member whose
//! value the addressed resource's own configuration forbids (400 `InvalidParameterValue`), a
//! resource in a status the change is not accepted from (400 `InvalidDBInstanceState`), an
//! identifier already taken (400 `DBInstanceAlreadyExists` / `DBSnapshotAlreadyExists`) — over
//! four operations (`RebootDBInstance`, `CreateDBSnapshot`, `DeleteDBSnapshot`,
//! `CreateDBInstance`) and two event source types.
//!
//! Each test ends with a POSITIVE CONTROL: the same operation, accepted, must deliver exactly
//! one envelope to the very queue the refusals were asserted silent on. One publication is
//! matched against every rule of the bus, so once the control's envelope has arrived every
//! refusal above has been decided against the same bus and the same target — a queue that was
//! empty because the emulator delivers nothing at all could not pass.
//!
//! EventBridge and Amazon SQS are mounted beside this service on ONE engine, exactly as the
//! assembled router mounts them, and every assertion reads a message a queue really handed
//! over or a row the control plane really reported.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::db_instance_bus_events::{
    collect, drain, emulator, sqs, wait_for_status, DB_INSTANCE_EVENT, DB_SNAPSHOT_EVENT,
    EVENT_SOURCE,
};
use crate::db_instance_event_pattern_precision::{create_available, rule_to_its_own_queue};
use crate::db_instances::{call, call_in, expect_error, expect_ok, subtrees, text, REGION};

/// `detail.EventID` of the change a reboot records, and the one category a DB instance
/// restart is published under.
///
/// Source: the per-source-type tables of "Amazon RDS event categories and event messages"
/// (Amazon RDS User Guide) — the DB instance row whose message is `DB instance restarted`.
const RESTART_EVENT_ID: &str = "RDS-EVENT-0006";
const AVAILABILITY: &str = "availability";

/// `detail.EventID` of the change taking a manual DB snapshot records, from the DB snapshot
/// rows of that same published table.
const SNAPSHOT_EVENT_ID: &str = "RDS-EVENT-0040";

/// The instance every accepted call below is made to.
const PRIMARY: &str = "emu-refused-db";

/// A second instance, stopped: a status a reboot is not accepted from and one the instance
/// does not leave on its own, so the row that pins it cannot race the clock.
const STOPPED: &str = "emu-refused-stopped";

/// Identifiers the account holds no record of.
const ABSENT: &str = "emu-refused-absent";
const ABSENT_SNAPSHOT: &str = "emu-refused-absent-snapshot";

/// A second Region, so a row can address an instance that really exists — in the Region it
/// was NOT created in.
const OTHER_REGION: &str = "eu-west-1";

/// The manual snapshot the second test takes.
const SNAPSHOT: &str = "emu-refused-snapshot";

/// One refused call: where it is sent, what it asks for, and the modelled failure it must
/// answer.
struct Refused {
    /// What this row refuses, for the assertion messages.
    case: &'static str,
    /// The Region the call is signed for.
    region: &'static str,
    /// The `Action` it names.
    action: &'static str,
    /// Its query parameters.
    params: Vec<(&'static str, String)>,
    /// The HTTP status the refusal answers.
    status: u16,
    /// The wire error `<Code>` it carries.
    code: &'static str,
}

/// Make every call of `rows` and assert each is refused as its row states.
async fn refuse_each(router: &MultiServiceRouter, rows: Vec<Refused>) {
    for row in rows {
        expect_error(
            row.case,
            call_in(router, row.region, row.action, &row.params).await,
            row.status,
            row.code,
        );
    }
}

/// Every DB instance event the control plane reports under the restart's category, in this
/// Region.
async fn availability_events(router: &MultiServiceRouter) -> Vec<String> {
    let body = expect_ok(
        "the DB instance events of the restart's category",
        call(
            router,
            "DescribeEvents",
            &[
                ("SourceType", "db-instance"),
                ("EventCategories.EventCategory.1", AVAILABILITY),
            ],
        )
        .await,
    );
    subtrees(&body, "Event")
}

/// Every DB snapshot event the control plane reports in this Region.
async fn snapshot_events(router: &MultiServiceRouter) -> Vec<String> {
    let body = expect_ok(
        "the DB snapshot events",
        call(router, "DescribeEvents", &[("SourceType", "db-snapshot")]).await,
    );
    subtrees(&body, "Event")
}

/// The one message `queue_url` holds, parsed, having waited for it to arrive.
async fn the_one_envelope(router: &MultiServiceRouter, case: &str, queue_url: &str) -> Value {
    let delivered = collect(router, queue_url, 1).await;
    assert_eq!(
        delivered.len(),
        1,
        "case {case:?}: the accepted change must be delivered exactly once, got {delivered:?}"
    );
    serde_json::from_str(&delivered[0])
        .unwrap_or_else(|error| panic!("case {case:?}: {} must be JSON: {error}", delivered[0]))
}

/// Assert `queue_url` holds nothing a consumer could still take: its reported depth is zero
/// and a read of it hands over no message at all.
///
/// NOT the sibling suite's `assert_holds_nothing`, which also requires
/// `ApproximateNumberOfMessagesNotVisible` to be zero: the queues here have already handed
/// the positive control's own envelope to this test, so that second attribute counts the
/// in-flight control message and is one by construction.
async fn assert_nothing_more(router: &MultiServiceRouter, case: &str, queue_url: &str) {
    let reported = sqs(
        router,
        "GetQueueAttributes",
        &json!({
            "QueueUrl": queue_url,
            "AttributeNames": ["ApproximateNumberOfMessages"],
        }),
    )
    .await;
    assert_eq!(
        reported["Attributes"]["ApproximateNumberOfMessages"],
        json!("0"),
        "case {case:?}: expected ApproximateNumberOfMessages \"0\", got {reported}"
    );
    let held = drain(router, queue_url).await;
    assert!(
        held.is_empty(),
        "case {case:?}: expected no further message on the queue, got {held:?}"
    );
}

/// RULE: a refused `RebootDBInstance` performs no restart, so it publishes no restart onto
/// the default bus and records none for `DescribeEvents` — whatever the refusal was.
#[tokio::test]
async fn no_refused_reboot_publishes_or_records_a_restart() {
    let router = emulator();
    let arn = create_available(&router, PRIMARY).await;
    create_available(&router, STOPPED).await;
    expect_ok(
        "stop the second instance",
        call(
            &router,
            "StopDBInstance",
            &[("DBInstanceIdentifier", STOPPED)],
        )
        .await,
    );
    wait_for_status(&router, STOPPED, "stopped").await;

    // The rule pins the restart of ANY DB instance of this account rather than one ARN, so a
    // restart wrongly published for EITHER instance below would reach this queue.
    let url = rule_to_its_own_queue(
        &router,
        "emu-refused-restart",
        &json!({
            "source": [EVENT_SOURCE],
            "detail-type": [DB_INSTANCE_EVENT],
            "detail": { "EventID": [RESTART_EVENT_ID] },
        }),
    )
    .await;

    refuse_each(
        &router,
        vec![
            Refused {
                case: "an identifier the account holds no instance for",
                region: REGION,
                action: "RebootDBInstance",
                params: vec![("DBInstanceIdentifier", ABSENT.to_string())],
                status: 404,
                code: "DBInstanceNotFound",
            },
            Refused {
                case: "an instance that exists, addressed in another Region",
                region: OTHER_REGION,
                action: "RebootDBInstance",
                params: vec![("DBInstanceIdentifier", PRIMARY.to_string())],
                status: 404,
                code: "DBInstanceNotFound",
            },
            Refused {
                case: "a forced failover of an instance that is not Multi-AZ",
                region: REGION,
                action: "RebootDBInstance",
                params: vec![
                    ("DBInstanceIdentifier", PRIMARY.to_string()),
                    ("ForceFailover", "true".to_string()),
                ],
                status: 400,
                code: "InvalidParameterValue",
            },
            Refused {
                case: "an instance in a status a reboot is not accepted from",
                region: REGION,
                action: "RebootDBInstance",
                params: vec![("DBInstanceIdentifier", STOPPED.to_string())],
                status: 400,
                code: "InvalidDBInstanceState",
            },
        ],
    )
    .await;

    // The control plane projects the same records the bus is fed from, so a restart neither
    // place holds is a restart that was never performed.
    let logged = availability_events(&router).await;
    assert!(
        logged.is_empty(),
        "no refused reboot may record a restart, got {logged:?}"
    );

    // The positive control: the same operation, accepted.
    expect_ok(
        "reboot the available instance",
        call(
            &router,
            "RebootDBInstance",
            &[("DBInstanceIdentifier", PRIMARY)],
        )
        .await,
    );
    let event = the_one_envelope(&router, "the accepted reboot", &url).await;
    assert_eq!(
        event["detail"]["EventID"],
        json!(RESTART_EVENT_ID),
        "the accepted reboot publishes the restart's identifier, got {event}"
    );
    assert_eq!(
        event["detail"]["SourceArn"],
        json!(arn),
        "the accepted reboot publishes the rebooted instance's ARN {arn:?}, got {event}"
    );
    assert_nothing_more(&router, "after the accepted reboot", &url).await;

    let logged = availability_events(&router).await;
    assert_eq!(
        logged.len(),
        1,
        "exactly the one restart that happened is recorded, got {logged:?}"
    );
    assert_eq!(
        text(&logged[0], "SourceIdentifier"),
        PRIMARY,
        "the recorded restart is the rebooted instance's, got {:?}",
        logged[0]
    );
}

/// RULE: the same holds for every other change this service publishes — a refused create or
/// delete publishes nothing and records nothing, whichever resource it addressed.
#[tokio::test]
async fn no_refused_create_or_delete_publishes_an_event() {
    let router = emulator();
    // The instance's own creation is published before any rule exists, so the bus has
    // nothing to deliver it to and the queue below starts empty by construction.
    create_available(&router, PRIMARY).await;
    let url = rule_to_its_own_queue(
        &router,
        "emu-refused-any",
        &json!({ "source": [EVENT_SOURCE] }),
    )
    .await;

    refuse_each(
        &router,
        vec![
            Refused {
                case: "a snapshot of an instance the account holds no record of",
                region: REGION,
                action: "CreateDBSnapshot",
                params: vec![
                    ("DBSnapshotIdentifier", SNAPSHOT.to_string()),
                    ("DBInstanceIdentifier", ABSENT.to_string()),
                ],
                status: 404,
                code: "DBInstanceNotFound",
            },
            Refused {
                case: "the deletion of a snapshot the account holds no record of",
                region: REGION,
                action: "DeleteDBSnapshot",
                params: vec![("DBSnapshotIdentifier", ABSENT_SNAPSHOT.to_string())],
                status: 404,
                code: "DBSnapshotNotFound",
            },
            Refused {
                case: "a snapshot of an instance that exists, addressed in another Region",
                region: OTHER_REGION,
                action: "CreateDBSnapshot",
                params: vec![
                    ("DBSnapshotIdentifier", SNAPSHOT.to_string()),
                    ("DBInstanceIdentifier", PRIMARY.to_string()),
                ],
                status: 404,
                code: "DBInstanceNotFound",
            },
            Refused {
                case: "the creation of an instance whose identifier is taken",
                region: REGION,
                action: "CreateDBInstance",
                params: vec![
                    ("DBInstanceIdentifier", PRIMARY.to_string()),
                    ("Engine", "postgres".to_string()),
                    ("DBInstanceClass", "db.t4g.micro".to_string()),
                ],
                status: 400,
                code: "DBInstanceAlreadyExists",
            },
        ],
    )
    .await;

    let logged = snapshot_events(&router).await;
    assert!(
        logged.is_empty(),
        "no refused snapshot call may record an event, got {logged:?}"
    );

    // The positive control: the snapshot the refusals above asked for, accepted.
    let taken = expect_ok(
        "snapshot the instance",
        call(
            &router,
            "CreateDBSnapshot",
            &[
                ("DBSnapshotIdentifier", SNAPSHOT),
                ("DBInstanceIdentifier", PRIMARY),
            ],
        )
        .await,
    );
    // The ARN the envelope must name is the one the service itself reports for the snapshot,
    // read off its own answer rather than spelled here.
    let snapshot_arn = text(
        subtrees(&taken, "DBSnapshot")
            .first()
            .unwrap_or_else(|| panic!("CreateDBSnapshot must answer a DBSnapshot, got {taken}")),
        "DBSnapshotArn",
    );
    let event = the_one_envelope(&router, "the accepted snapshot", &url).await;
    assert_eq!(
        event["detail-type"],
        json!(DB_SNAPSHOT_EVENT),
        "the accepted snapshot publishes its own source type's detail-type, got {event}"
    );
    assert_eq!(
        event["detail"]["EventID"],
        json!(SNAPSHOT_EVENT_ID),
        "the accepted snapshot publishes the manual-snapshot identifier, got {event}"
    );
    assert_eq!(
        event["resources"],
        json!([snapshot_arn]),
        "the accepted snapshot names the snapshot's ARN {snapshot_arn:?}, got {event}"
    );
    assert_nothing_more(&router, "after the accepted snapshot", &url).await;

    // And the identifier is taken now, so the same call is refused — and publishes nothing,
    // with the accepted one's envelope already delivered above.
    refuse_each(
        &router,
        vec![Refused {
            case: "a snapshot whose identifier is taken",
            region: REGION,
            action: "CreateDBSnapshot",
            params: vec![
                ("DBSnapshotIdentifier", SNAPSHOT.to_string()),
                ("DBInstanceIdentifier", PRIMARY.to_string()),
            ],
            status: 400,
            code: "DBSnapshotAlreadyExists",
        }],
    )
    .await;
    assert_nothing_more(&router, "after the refused duplicate snapshot", &url).await;

    let logged = snapshot_events(&router).await;
    assert_eq!(
        logged.len(),
        1,
        "exactly the one snapshot that was taken is recorded, got {logged:?}"
    );
    assert_eq!(
        text(&logged[0], "SourceIdentifier"),
        SNAPSHOT,
        "the recorded event is the snapshot's own, got {:?}",
        logged[0]
    );
}
