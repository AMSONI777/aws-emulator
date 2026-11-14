// SPDX-License-Identifier: CC0-1.0

//! What a scheduled-action write resolves BEFORE it reads the caller's own
//! expression values, and the sentences the refusals carry, end to end over the
//! awsQuery wire.
//!
//! Every case drives a real HTTP request through the same `MultiServiceRouter`
//! the production router builds (the harness is shared with
//! [`crate::cluster_lifecycle`]), so each assertion covers the whole walk:
//! form-urlencoded deserialize -> handler -> XML serialize.
//!
//! Two rules are under test, and each row is one member of the class the rule
//! generalises over rather than one recorded request:
//!
//! 1. ORDER. A write resolves its preconditions against STATE first — the
//!    resource it names, and the IAM role the work would run as — and only then
//!    parses the values the request carries. So a request that is wrong in both
//!    ways is refused on the precondition: a create naming a role the Amazon
//!    Redshift scheduler cannot assume reports the role however the `Schedule`
//!    reads, and a modify naming an action this account does not hold reports
//!    the action.
//! 2. WORDING. A refusal carries the sentence Amazon Redshift words for that
//!    fault and that operation, with only the value the request sent varying: a
//!    missing scheduled action is `The scheduled action <name> was not found.`,
//!    an unassumable scheduler role is `The IAM role <arn> is not valid. The IAM
//!    role must delegate access to Amazon Redshift scheduler.`, and
//!    `PauseCluster` words a missing cluster as `Cluster <identifier> can't be
//!    found.` — a sentence of its OWN, which a read of the same identifier does
//!    not answer.

use service_com_amazonaws_redshift_redshiftserviceversion20121201::state;

use crate::cluster_lifecycle::{Answer, Emulator};

/// The service principal a scheduled action's role has to let assume it.
///
/// Spelled out here rather than read off the crate under test: the model states
/// it (`smithy_query(query="doc", shape="ScheduledAction", member="IamRole")` —
/// "This IAM role must allow the Amazon Redshift scheduler (Principal
/// scheduler.redshift.amazonaws.com) to assume permissions on your behalf").
const SCHEDULER_PRINCIPAL: &str = "scheduler.redshift.amazonaws.com";

/// A cron expression of the format `ScheduledAction$Schedule` documents —
/// "cron(Minutes Hours Day-of-month Month Day-of-week Year)", whose own example
/// is `cron(0 10 ? * MON *)`.
const WEEKLY_CRON: &str = "cron(0 10 ? * MON *)";

/// A `Schedule` written in NEITHER published expression type, so the request is
/// wrong in its own right as well as in the precondition a row is about: `rate`
/// is published for a snapshot schedule and not for a scheduled action.
const UNREADABLE_SCHEDULE: &str = "rate(24 hours)";

/// A trust policy that lets `principal` assume the role it is attached to.
fn trusts(principal: &str) -> String {
    format!(
        "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\
         \"Principal\":{{\"Service\":\"{principal}\"}},\"Action\":\"sts:AssumeRole\"}}]}}"
    )
}

/// A trust policy that explicitly DENIES `principal` the assume.
fn denies(principal: &str) -> String {
    format!(
        "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Deny\",\
         \"Principal\":{{\"Service\":\"{principal}\"}},\"Action\":\"sts:AssumeRole\"}}]}}"
    )
}

/// Create one IAM role through the mounted IAM service and answer the ARN it
/// reports, so a role a case means to be REAL is one IAM holds.
async fn create_role(emulator: &Emulator, name: &str, path: Option<&str>, trust: &str) -> String {
    let mut params: Vec<(&str, &str)> =
        vec![("RoleName", name), ("AssumeRolePolicyDocument", trust)];
    if let Some(path) = path {
        params.push(("Path", path));
    }
    let created = emulator.call_iam("CreateRole", &params).await;
    assert_eq!(
        created.status, 200,
        "case seed the role {name}: expected 200 from IAM, got {} with body {}",
        created.status, created.body
    );
    created.text("Arn").unwrap_or_else(|| {
        panic!("case seed the role {name}: CreateRole must report the role's ARN, got {}", created.body)
    })
}

/// The ARN a role of this account carries at the default path. The grammar is
/// IAM's own (`arn:<partition>:iam::<account>:role/<name>`), so a name nothing
/// created still produces a well-formed value — which is the point of the rows
/// that use it.
fn absent_role_arn(name: &str) -> String {
    format!("arn:aws:iam::{}:role/{name}", engine::emulator_account_id())
}

/// The sentence a refusal of an unassumable scheduler role carries, spelled out
/// here rather than read off the crate under test.
fn role_refusal(role_arn: &str) -> String {
    format!(
        "The IAM role {role_arn} is not valid. \
         The IAM role must delegate access to Amazon Redshift scheduler."
    )
}

/// The sentence a refusal of a scheduled action this account does not hold
/// carries, spelled out here rather than read off the crate under test.
fn action_refusal(name: &str) -> String {
    format!("The scheduled action {name} was not found.")
}

/// Create one cluster and wait for it to be serving, by POLLING the read.
async fn available_cluster(emulator: &Emulator, identifier: &str) {
    let created = emulator.create_minimal(identifier).await;
    assert_eq!(
        created.status, 200,
        "case seed cluster {identifier}: expected 200, got {} with body {}",
        created.status, created.body
    );
    emulator
        .poll_until(
            &format!("seed cluster {identifier}"),
            "DescribeClusters",
            &[("ClusterIdentifier", identifier)],
            |answer| answer.text("ClusterStatus").as_deref() == Some(state::STATUS_AVAILABLE),
        )
        .await;
}

/// One `CreateScheduledAction` naming a `PauseCluster` target action.
async fn create_action(
    emulator: &Emulator,
    name: &str,
    cluster: &str,
    role_arn: &str,
    schedule: &str,
) -> Answer {
    emulator
        .call(
            "CreateScheduledAction",
            &[
                ("ScheduledActionName", name),
                ("Schedule", schedule),
                ("IamRole", role_arn),
                ("TargetAction.PauseCluster.ClusterIdentifier", cluster),
            ],
        )
        .await
}

/// One role a create names, and whether IAM's answer about it refuses the write.
struct RoleRow {
    case: &'static str,
    /// The value the request's `IamRole` carries.
    arn: String,
    /// Whether the scheduler is unable to assume it, so the write is refused on
    /// the role.
    refused: bool,
}

#[tokio::test]
async fn a_create_resolves_its_scheduler_role_before_the_schedule_it_carries() {
    let emulator = Emulator::with_iam();
    available_cluster(&emulator, "role-order-cluster").await;

    // The rows differ along what the rule generalises over: whether IAM holds a
    // role under the name the ARN carries, what its trust policy says about the
    // scheduler (grants, grants another service, denies), the path the role
    // lives under, and whether the ARN names this account at all.
    let rows: Vec<RoleRow> = vec![
        RoleRow {
            case: "a role this account holds that trusts the scheduler",
            arn: create_role(
                &emulator,
                "scheduler-role",
                None,
                &trusts(SCHEDULER_PRINCIPAL),
            )
            .await,
            refused: false,
        },
        RoleRow {
            case: "the same, under a path",
            arn: create_role(
                &emulator,
                "scheduler-role-under-a-path",
                Some("/service-role/"),
                &trusts(SCHEDULER_PRINCIPAL),
            )
            .await,
            refused: false,
        },
        RoleRow {
            // Another account's IAM is not this emulator's to ask, so nothing
            // is refused on it: the refusals above are grounded in an answer.
            case: "a role of another account",
            arn: "arn:aws:iam::210987654321:role/elsewhere".to_string(),
            refused: false,
        },
        RoleRow {
            case: "a name this account holds no role under",
            arn: absent_role_arn("no-such-scheduler-role"),
            refused: true,
        },
        RoleRow {
            case: "a held role one character off the held name",
            arn: absent_role_arn("scheduler-rol"),
            refused: true,
        },
        RoleRow {
            case: "a role whose trust policy names another service",
            arn: create_role(
                &emulator,
                "lambda-role",
                None,
                &trusts("lambda.amazonaws.com"),
            )
            .await,
            refused: true,
        },
        RoleRow {
            case: "a role whose trust policy denies the scheduler",
            arn: create_role(
                &emulator,
                "denied-role",
                None,
                &denies(SCHEDULER_PRINCIPAL),
            )
            .await,
            refused: true,
        },
    ];

    for (index, row) in rows.iter().enumerate() {
        // ORDER: the request is wrong in BOTH ways — an unreadable `Schedule`
        // beside the role the row is about — so which fault comes back says
        // which was resolved first.
        let name = format!("ordered-action-{index}");
        let both_wrong =
            create_action(&emulator, &name, "role-order-cluster", &row.arn, UNREADABLE_SCHEDULE)
                .await;
        let expected = if row.refused {
            role_refusal(&row.arn)
        } else {
            // The row's role is one IAM says nothing against, so the refusal is
            // the one the request's own value earns.
            state::unsupported_schedule_expression_message(UNREADABLE_SCHEDULE)
        };
        assert_eq!(
            (both_wrong.status, both_wrong.error_code().as_deref()),
            (400, Some("InvalidParameterValue")),
            "case {:?}: expected 400 InvalidParameterValue, got {} / {:?} with body {}",
            row.case,
            both_wrong.status,
            both_wrong.error_code(),
            both_wrong.body
        );
        assert_eq!(
            both_wrong.text("Message").as_deref(),
            Some(expected.as_str()),
            "case {:?}: expected the message {expected:?}, got {:?}",
            row.case,
            both_wrong.text("Message")
        );

        // And with a schedule this service reads, the role alone decides.
        let created =
            create_action(&emulator, &name, "role-order-cluster", &row.arn, WEEKLY_CRON).await;
        if row.refused {
            assert_eq!(
                (created.status, created.text("Message")),
                (400, Some(role_refusal(&row.arn))),
                "case {:?}: expected the role refusal, got {} with body {}",
                row.case,
                created.status,
                created.body
            );
            // Nothing was stored: a refused create leaves no action to read.
            let read = emulator
                .call("DescribeScheduledActions", &[("ScheduledActionName", &name)])
                .await;
            assert_eq!(
                (read.status, read.error_code().as_deref()),
                (400, Some("ScheduledActionNotFound")),
                "case {:?}: expected the refused create to store nothing, got {} / {:?}",
                row.case,
                read.status,
                read.error_code()
            );
        } else {
            assert_eq!(
                created.status, 200,
                "case {:?}: expected the create to be served, got {} with body {}",
                row.case, created.status, created.body
            );
            // ROUND TRIP: the role the create accepted is the one a read reports.
            let read = emulator
                .call("DescribeScheduledActions", &[("ScheduledActionName", &name)])
                .await;
            assert_eq!(
                (read.status, read.text("IamRole")),
                (200, Some(row.arn.clone())),
                "case {:?}: expected the read to report the stored role, got {} with body {}",
                row.case,
                read.status,
                read.body
            );
        }
    }
}

#[tokio::test]
async fn a_modify_resolves_the_action_then_its_role_then_the_values_it_carries() {
    let emulator = Emulator::with_iam();
    available_cluster(&emulator, "modify-order-cluster").await;
    let role = create_role(
        &emulator,
        "modify-scheduler-role",
        None,
        &trusts(SCHEDULER_PRINCIPAL),
    )
    .await;

    // One action that DOES exist, so a refusal below cannot be an "everything is
    // refused" artefact, and one created-then-deleted name.
    for name in ["held-action", "doomed-action"] {
        let created = create_action(
            &emulator,
            name,
            "modify-order-cluster",
            &role,
            WEEKLY_CRON,
        )
        .await;
        assert_eq!(
            created.status, 200,
            "case seed {name}: expected 200, got {} with body {}",
            created.status, created.body
        );
    }
    let deleted = emulator
        .call(
            "DeleteScheduledAction",
            &[("ScheduledActionName", "doomed-action")],
        )
        .await;
    assert_eq!(
        deleted.status, 200,
        "case delete the doomed action: expected 200, got {} with body {}",
        deleted.status, deleted.body
    );

    // The class is the absent NAME crossed with what else the request carries:
    // the action is resolved first, so the same fault comes back whatever the
    // rest of the request says.
    let absent: Vec<(&str, &str)> = vec![
        ("a name nothing created", "no-such-action"),
        ("a name one character off a stored one", "held-actio"),
        ("a name in another case", "Held-Action"),
        ("a created-then-deleted name", "doomed-action"),
    ];
    let unassumable = absent_role_arn("no-such-modify-role");
    let carried: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("naming nothing else", vec![]),
        (
            "carrying a schedule this service cannot read",
            vec![("Schedule", UNREADABLE_SCHEDULE)],
        ),
        (
            "carrying a schedule of a published type that states none",
            vec![("Schedule", "cron(0 10)")],
        ),
        (
            "carrying a role the scheduler cannot assume",
            vec![("IamRole", unassumable.as_str())],
        ),
        (
            "carrying a target action naming two operations",
            vec![
                (
                    "TargetAction.PauseCluster.ClusterIdentifier",
                    "modify-order-cluster",
                ),
                (
                    "TargetAction.ResumeCluster.ClusterIdentifier",
                    "modify-order-cluster",
                ),
            ],
        ),
    ];

    for (name_case, name) in &absent {
        for (carried_case, extra) in &carried {
            let mut params: Vec<(&str, &str)> = vec![("ScheduledActionName", name)];
            params.extend_from_slice(extra);
            let refused = emulator.call("ModifyScheduledAction", &params).await;
            let case = format!("a modify of {name_case} {carried_case}");
            assert_eq!(
                (refused.status, refused.error_code().as_deref()),
                (400, Some("ScheduledActionNotFound")),
                "case {case:?}: expected 400 ScheduledActionNotFound, got {} / {:?} with body {}",
                refused.status,
                refused.error_code(),
                refused.body
            );
            let expected = action_refusal(name);
            assert_eq!(
                refused.text("Message").as_deref(),
                Some(expected.as_str()),
                "case {case:?}: expected the message {expected:?}, got {:?}",
                refused.text("Message")
            );
        }

        // The delete and the read of a missing action carry the SAME sentence.
        for action in ["DeleteScheduledAction", "DescribeScheduledActions"] {
            let refused = emulator
                .call(action, &[("ScheduledActionName", name)])
                .await;
            let expected = action_refusal(name);
            assert_eq!(
                (
                    refused.status,
                    refused.error_code().as_deref(),
                    refused.text("Message").as_deref()
                ),
                (400, Some("ScheduledActionNotFound"), Some(expected.as_str())),
                "case {action} on {name_case}: expected 400 ScheduledActionNotFound with \
                 {expected:?}, got {} / {:?} with body {}",
                refused.status,
                refused.error_code(),
                refused.body
            );
        }
    }

    // On the action that IS there, the ROLE is resolved before the request's own
    // values: a modify carrying both an unassumable role and an unreadable
    // schedule reports the role.
    let role_first = emulator
        .call(
            "ModifyScheduledAction",
            &[
                ("ScheduledActionName", "held-action"),
                ("IamRole", unassumable.as_str()),
                ("Schedule", UNREADABLE_SCHEDULE),
            ],
        )
        .await;
    let expected = role_refusal(&unassumable);
    assert_eq!(
        (role_first.status, role_first.text("Message")),
        (400, Some(expected.clone())),
        "case a modify carrying an unassumable role and an unreadable schedule: expected \
         {expected:?}, got {} with body {}",
        role_first.status,
        role_first.body
    );

    // With a role the scheduler can assume, the request's own value is what is
    // reported — so the order is action, then role, then values.
    let schedule_last = emulator
        .call(
            "ModifyScheduledAction",
            &[
                ("ScheduledActionName", "held-action"),
                ("IamRole", role.as_str()),
                ("Schedule", UNREADABLE_SCHEDULE),
            ],
        )
        .await;
    let expected = state::unsupported_schedule_expression_message(UNREADABLE_SCHEDULE);
    assert_eq!(
        (schedule_last.status, schedule_last.text("Message")),
        (400, Some(expected.clone())),
        "case a modify carrying an assumable role and an unreadable schedule: expected \
         {expected:?}, got {} with body {}",
        schedule_last.status,
        schedule_last.body
    );

    // Every refusal above changed nothing: the stored action still carries what
    // its create gave it.
    let read = emulator
        .call(
            "DescribeScheduledActions",
            &[("ScheduledActionName", "held-action")],
        )
        .await;
    assert_eq!(
        (read.status, read.text("Schedule"), read.text("IamRole")),
        (200, Some(WEEKLY_CRON.to_string()), Some(role.clone())),
        "case the refused modifies leave the action alone: got {} with body {}",
        read.status,
        read.body
    );
}

#[tokio::test]
async fn pause_cluster_words_its_cluster_not_found_refusal_as_its_own_sentence() {
    let emulator = Emulator::new();
    // One cluster that DOES exist, so the refusals below cannot be an "every
    // request is refused" artefact.
    available_cluster(&emulator, "pause-present-cluster").await;

    // The identifier table this operation is held to lives in
    // [`crate::pause_cluster`]; what this case adds is that the sentence is
    // this OPERATION's — the same missing identifier, asked about through a
    // read, is worded differently, so the two cannot have been collapsed onto
    // one template.
    let shared = "pause-wording-probe";
    let paused = emulator
        .call("PauseCluster", &[("ClusterIdentifier", shared)])
        .await;
    assert_eq!(
        (paused.status, paused.error_code().as_deref()),
        (404, Some("ClusterNotFound")),
        "case a pause of an identifier nothing created: expected 404 ClusterNotFound, got {} / \
         {:?} with body {}",
        paused.status,
        paused.error_code(),
        paused.body
    );
    let expected = format!("Cluster {shared} can't be found.");
    assert_eq!(
        paused.text("Message").as_deref(),
        Some(expected.as_str()),
        "case a pause of an identifier nothing created: expected the message {expected:?}, got \
         {:?}",
        paused.text("Message")
    );
    let described = emulator
        .call("DescribeClusters", &[("ClusterIdentifier", shared)])
        .await;
    assert_ne!(
        paused.text("Message"),
        described.text("Message"),
        "case one identifier through two operations: expected per-operation sentences, got {:?} \
         and {:?}",
        paused.text("Message"),
        described.text("Message")
    );

    // The cluster that IS there is still pausable: the refusal above was about
    // the identifier, not the operation.
    let served = emulator
        .call(
            "PauseCluster",
            &[("ClusterIdentifier", "pause-present-cluster")],
        )
        .await;
    assert_eq!(
        served.status, 200,
        "case the cluster this account holds: expected 200, got {} with body {}",
        served.status, served.body
    );
}
