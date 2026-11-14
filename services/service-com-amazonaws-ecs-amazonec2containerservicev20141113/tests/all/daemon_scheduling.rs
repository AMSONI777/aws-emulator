// SPDX-License-Identifier: CC0-1.0

//! The ECS MANAGED DAEMON scheduler: the rollout a `CreateDaemon`/`UpdateDaemon` starts,
//! the revisions it captures, the one daemon task each container instance runs, and the
//! reads that report them.
//!
//! The rules under test, each asserted over a table that spans its class rather than over
//! one request:
//!
//! * "A daemon deployment orchestrates the progressive rollout of daemon task updates
//!   across container instances" — a rollout is reported in a non-terminal
//!   `DaemonDeploymentStatus` when the call that started it answers and reaches `SUCCESSFUL`
//!   on the CLOCK, with `startedAt` and `finishedAt` dating the two steps, for a daemon over
//!   any number of container instances (none, one, several);
//! * "Amazon ECS deploys exactly one daemon task on each container instance of the specified
//!   capacity providers. When a container instance registers with the cluster, Amazon ECS
//!   automatically starts daemon tasks" — so the converged daemon holds exactly one RUNNING
//!   task per instance that accepts a placement, an instance that joins LATER is given one
//!   without any further call, and an instance that stops accepting placements gives its
//!   task up;
//! * "A daemon revision is a snapshot of the daemon's configuration at the time a deployment
//!   was initiated" — an update captures a new revision, rolls the daemon's tasks over onto
//!   it, and leaves the earlier revision readable exactly as it was captured;
//! * "Amazon ECS daemons are cluster specific and Region specific" — every daemon operation
//!   resolves its `daemonArn` and refuses what it cannot resolve: the cluster first, then
//!   the daemon, and a value that is no daemon ARN at all last;
//! * `DeleteDaemon`: "Deleting a daemon stops all running daemon tasks on the associated
//!   container instances", the daemon is answered `DELETE_IN_PROGRESS`, and it leaves
//!   `ListDaemons` on the clock;
//! * the same placement rule over the other daemon-scheduled workload this service has:
//!   "The daemon scheduling strategy deploys exactly one task on each active container
//!   instance", so a `schedulingStrategy=DAEMON` SERVICE's `desiredCount` follows the
//!   capacity its cluster holds as instances join and drain.
//!
//! Every case drives the emulator through the shared wire harness in [`crate::ecs_wire`],
//! the same front door a client uses, so nothing reaches into the state struct and a
//! response that is not computed from persisted state cannot pass.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::capacity_providers::managed_instances;
use crate::ecs_wire::{
    count, create_cluster, list, ok, refusal, register_instance, service, string, ACCOUNT,
    SIGNED_REGION,
};

/// How long a poll waits for a clock-owed daemon transition before failing. Generous
/// against the spans this emulator owes (a rollout is two of them), so a loaded or slow
/// host does not fail a case about WHETHER the transition happens.
const POLL_BUDGET: Duration = Duration::from_secs(60);

/// How often a poll looks again. Short enough that a settled condition is seen promptly and
/// long enough that the loop is not a spin.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The image the daemon task definitions here run; irrelevant to every rule, so one value.
const IMAGE: &str = "public.ecr.aws/aws-observability/aws-otel-collector:latest";

/// Every `DaemonDeploymentStatus` a rollout that has not ended may be in, from the model's
/// own enum (`smithy_query(query="shape", shape="DaemonDeploymentStatus")`: `PENDING`,
/// `SUCCESSFUL`, `STOPPED`, `STOP_REQUESTED`, `IN_PROGRESS`, `ROLLBACK_IN_PROGRESS`,
/// `ROLLBACK_SUCCESSFUL`, `ROLLBACK_FAILED`) — the two a rollout of this emulator passes
/// through before it ends.
const ONGOING_STATUSES: [&str; 2] = ["PENDING", "IN_PROGRESS"];

/// Create a MANAGED INSTANCES capacity provider scoped to `cluster` and return its ARN.
/// "Managed instances capacity providers are cluster-scoped", so the create names one.
async fn create_managed_provider(
    router: &MultiServiceRouter,
    cluster: &str,
    name: &str,
    case: &str,
) -> String {
    let body = ok(
        router,
        "CreateCapacityProvider",
        json!({
            "name": name,
            "cluster": cluster,
            "managedInstancesProvider": managed_instances(),
        }),
        case,
    )
    .await;
    string(&body["capacityProvider"], "capacityProviderArn", case)
}

/// Register one daemon task-definition revision of `family` running `image`, and return its
/// ARN. The image is what tells two revisions of one family apart in a report.
async fn register_daemon_definition(
    router: &MultiServiceRouter,
    family: &str,
    image: &str,
    case: &str,
) -> String {
    let body = ok(
        router,
        "RegisterDaemonTaskDefinition",
        json!({
            "family": family,
            "containerDefinitions": [{ "name": "agent", "image": image, "memory": 128 }],
        }),
        case,
    )
    .await;
    string(&body, "daemonTaskDefinitionArn", case)
}

/// Create one daemon over `providers` running `definition`, and return its ARN with the ARN
/// of the initial daemon deployment the create answered.
async fn create_daemon(
    router: &MultiServiceRouter,
    cluster: &str,
    name: &str,
    providers: &[String],
    definition: &str,
    case: &str,
) -> (String, String) {
    let body = ok(
        router,
        "CreateDaemon",
        json!({
            "clusterArn": cluster,
            "daemonName": name,
            "daemonTaskDefinitionArn": definition,
            "capacityProviderArns": providers,
        }),
        case,
    )
    .await;
    (
        string(&body, "daemonArn", case),
        string(&body, "deploymentArn", case),
    )
}

/// `DescribeDaemon` for one daemon.
async fn describe_daemon(router: &MultiServiceRouter, daemon_arn: &str, case: &str) -> Value {
    let body = ok(
        router,
        "DescribeDaemon",
        json!({ "daemonArn": daemon_arn }),
        case,
    )
    .await;
    body["daemon"].clone()
}

/// `ListDaemonDeployments` for one request, returning the summaries and the token.
async fn list_deployments_page(
    router: &MultiServiceRouter,
    request: Value,
    case: &str,
) -> (Vec<Value>, Option<String>) {
    let body = ok(router, "ListDaemonDeployments", request, case).await;
    let token = body
        .get("nextToken")
        .and_then(Value::as_str)
        .map(str::to_string);
    (list(&body, "daemonDeployments", case), token)
}

/// Every deployment of one daemon, newest first, in one unpaged listing.
async fn list_deployments(
    router: &MultiServiceRouter,
    daemon_arn: &str,
    case: &str,
) -> Vec<Value> {
    list_deployments_page(router, json!({ "daemonArn": daemon_arn }), case)
        .await
        .0
}

/// `DescribeDaemonDeployments` for one rollout.
async fn describe_deployment(
    router: &MultiServiceRouter,
    deployment_arn: &str,
    case: &str,
) -> Value {
    let body = ok(
        router,
        "DescribeDaemonDeployments",
        json!({ "daemonDeploymentArns": [deployment_arn] }),
        case,
    )
    .await;
    list(&body, "daemonDeployments", case)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("case {case:?}: expected the rollout back, got {body}"))
}

/// `DescribeDaemonRevisions` for one revision.
async fn describe_revision(router: &MultiServiceRouter, revision_arn: &str, case: &str) -> Value {
    let body = ok(
        router,
        "DescribeDaemonRevisions",
        json!({ "daemonRevisionArns": [revision_arn] }),
        case,
    )
    .await;
    list(&body, "daemonRevisions", case)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("case {case:?}: expected the revision back, got {body}"))
}

/// Every task of one daemon that Amazon ECS wants running, as `ListTasks`' own `daemonName`
/// filter selects them, described.
async fn daemon_tasks(
    router: &MultiServiceRouter,
    cluster: &str,
    daemon_name: &str,
    case: &str,
) -> Vec<Value> {
    let listed = ok(
        router,
        "ListTasks",
        json!({ "cluster": cluster, "daemonName": daemon_name }),
        case,
    )
    .await;
    let arns = list(&listed, "taskArns", case);
    if arns.is_empty() {
        return Vec::new();
    }
    let described = ok(
        router,
        "DescribeTasks",
        json!({ "cluster": cluster, "tasks": arns }),
        case,
    )
    .await;
    list(&described, "tasks", case)
}

/// Poll one daemon until `settled` holds of its `DaemonDetail`, and answer that detail.
async fn poll_daemon(
    router: &MultiServiceRouter,
    daemon_arn: &str,
    case: &str,
    what: &str,
    settled: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + POLL_BUDGET;
    loop {
        let daemon = describe_daemon(router, daemon_arn, case).await;
        if settled(&daemon) {
            return daemon;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected {what}, got {daemon}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll one rollout until `settled` holds of its `DaemonDeployment`, and answer it.
async fn poll_deployment(
    router: &MultiServiceRouter,
    deployment_arn: &str,
    case: &str,
    what: &str,
    settled: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + POLL_BUDGET;
    loop {
        let deployment = describe_deployment(router, deployment_arn, case).await;
        if settled(&deployment) {
            return deployment;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected {what}, got {deployment}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The RUNNING tasks of `tasks`, by the container instance each of them is placed on.
fn running_hosts(tasks: &[Value], case: &str) -> Vec<String> {
    let mut hosts: Vec<String> = tasks
        .iter()
        .filter(|task| task["lastStatus"].as_str() == Some("RUNNING"))
        .map(|task| string(task, "containerInstanceArn", case))
        .collect();
    hosts.sort();
    hosts
}

/// The one `currentRevisions` entry of a converged daemon.
fn sole_revision(daemon: &Value, case: &str) -> Value {
    let revisions = list(daemon, "currentRevisions", case);
    assert_eq!(
        revisions.len(),
        1,
        "case {case:?}: a converged daemon runs ONE revision, got {daemon}"
    );
    revisions[0].clone()
}

#[tokio::test]
async fn a_rollout_reaches_its_terminal_status_and_places_one_task_per_container_instance() {
    let router = service();
    // The rows differ along what the rule generalises over: HOW MUCH capacity the daemon's
    // cluster holds — none at all, one instance, and several — because "exactly one daemon
    // task on each container instance" is a statement about every count of them.
    let rows: [(&str, usize); 3] = [
        ("a cluster with no container instance", 0),
        ("a cluster with one container instance", 1),
        ("a cluster with three container instances", 3),
    ];
    for (case, instances) in rows {
        let cluster = format!("daemon-rollout-{instances}");
        create_cluster(&router, &cluster, case).await;
        for ordinal in 0..instances {
            register_instance(
                &router,
                &cluster,
                &format!("i-0daemonrollout{ordinal:04}"),
                case,
            )
            .await;
        }
        let provider =
            create_managed_provider(&router, &cluster, &format!("mi-rollout-{instances}"), case)
                .await;
        let definition =
            register_daemon_definition(&router, "daemonrollout", IMAGE, case).await;
        let (daemon_arn, deployment_arn) = create_daemon(
            &router,
            &cluster,
            "agents",
            std::slice::from_ref(&provider),
            &definition,
            case,
        )
        .await;

        // The rollout the create started has not reached its end when the call answers:
        // "A daemon deployment orchestrates the progressive rollout", so it is reported in
        // one of the statuses a rollout under way carries.
        let opening = describe_deployment(&router, &deployment_arn, case).await;
        let opening_status = string(&opening, "status", case);
        assert!(
            ONGOING_STATUSES.contains(&opening_status.as_str())
                || opening_status == "SUCCESSFUL",
            "case {case:?}: expected the rollout under way or already finished, got \
             {opening_status:?}"
        );
        assert!(
            opening.get("createdAt").is_some(),
            "case {case:?}: a rollout carries the instant it was created, got {opening}"
        );

        // ... and the clock takes it to its terminal, successful end.
        let finished = poll_deployment(
            &router,
            &deployment_arn,
            case,
            "the rollout to reach SUCCESSFUL",
            |deployment| deployment["status"].as_str() == Some("SUCCESSFUL"),
        )
        .await;
        for member in ["startedAt", "finishedAt"] {
            assert!(
                finished.get(member).and_then(Value::as_f64).is_some(),
                "case {case:?}: a finished rollout dates its {member}, got {finished}"
            );
        }
        let started_at = finished["startedAt"].as_f64().unwrap_or_default();
        let created_at = finished["createdAt"].as_f64().unwrap_or_default();
        let finished_at = finished["finishedAt"].as_f64().unwrap_or_default();
        assert!(
            created_at <= started_at && started_at <= finished_at,
            "case {case:?}: expected createdAt <= startedAt <= finishedAt, got \
             {created_at}/{started_at}/{finished_at}"
        );

        // Exactly one RUNNING daemon task per container instance, and each of them on a
        // DIFFERENT instance.
        let daemon = poll_daemon(
            &router,
            &daemon_arn,
            case,
            "the daemon to report one running task per container instance",
            |daemon| {
                list(daemon, "currentRevisions", case)
                    .first()
                    .map(|revision| count(revision, "totalRunningCount", case))
                    == Some(instances as i64)
            },
        )
        .await;
        let tasks = daemon_tasks(&router, &cluster, "agents", case).await;
        let hosts = running_hosts(&tasks, case);
        assert_eq!(
            hosts.len(),
            instances,
            "case {case:?}: expected one running daemon task per instance, got {tasks:?}"
        );
        let mut distinct = hosts.clone();
        distinct.dedup();
        assert_eq!(
            distinct, hosts,
            "case {case:?}: expected each daemon task on its own instance, got {hosts:?}"
        );
        for task in &tasks {
            assert_eq!(
                string(task, "group", case),
                "daemon:agents",
                "case {case:?}: a daemon's task carries its daemon's group, got {task}"
            );
            assert_eq!(
                string(task, "taskDefinitionArn", case),
                definition,
                "case {case:?}: a daemon task runs the daemon's revision, got {task}"
            );
        }

        // The per-capacity-provider counts add up to the totals: the daemon deploys onto the
        // providers it names, so each of them reports the instances it carries.
        let revision = sole_revision(&daemon, case);
        let providers = list(&revision, "capacityProviders", case);
        assert_eq!(
            providers.len(),
            1,
            "case {case:?}: the daemon names one provider, got {revision}"
        );
        assert_eq!(
            string(&providers[0], "arn", case),
            provider,
            "case {case:?}: expected the provider the daemon deploys onto, got {revision}"
        );
        let per_provider: i64 = providers
            .iter()
            .map(|entry| count(entry, "runningCount", case))
            .sum();
        assert_eq!(
            per_provider,
            instances as i64,
            "case {case:?}: expected the provider counts to add up to the total, got \
             {revision}"
        );
    }
}

#[tokio::test]
async fn an_instance_that_joins_later_is_given_a_daemon_task_and_a_draining_one_gives_it_up() {
    let router = service();
    const CLUSTER: &str = "daemon-capacity-moves";
    const CASE: &str = "capacity that moves under a converged daemon";
    create_cluster(&router, CLUSTER, CASE).await;
    let first = register_instance(&router, CLUSTER, "i-0daemonjoinfirst0", CASE).await;
    let provider = create_managed_provider(&router, CLUSTER, "mi-moves", CASE).await;
    let definition = register_daemon_definition(&router, "daemonmoves", IMAGE, CASE).await;
    let (daemon_arn, _) = create_daemon(
        &router,
        CLUSTER,
        "agents",
        &[provider],
        &definition,
        CASE,
    )
    .await;
    poll_daemon(
        &router,
        &daemon_arn,
        CASE,
        "the daemon to run on the instance it was created over",
        |daemon| {
            list(daemon, "currentRevisions", CASE)
                .first()
                .map(|revision| count(revision, "totalRunningCount", CASE))
                == Some(1)
        },
    )
    .await;

    // "When a container instance registers with the cluster, Amazon ECS automatically
    // starts daemon tasks": the join alone is what the task is owed by, with no further
    // daemon call.
    let joined = register_instance(&router, CLUSTER, "i-0daemonjoinlater0", CASE).await;
    poll_daemon(
        &router,
        &daemon_arn,
        CASE,
        "the daemon to run on the instance that joined later too",
        |daemon| {
            list(daemon, "currentRevisions", CASE)
                .first()
                .map(|revision| count(revision, "totalRunningCount", CASE))
                == Some(2)
        },
    )
    .await;
    let tasks = daemon_tasks(&router, CLUSTER, "agents", CASE).await;
    let hosts = running_hosts(&tasks, CASE);
    let mut expected = vec![first.clone(), joined.clone()];
    expected.sort();
    assert_eq!(
        hosts, expected,
        "case {CASE:?}: expected a daemon task on both instances, got {tasks:?}"
    );

    // An instance that no longer accepts a placement — "DRAINING ... prevents new tasks
    // from being scheduled for placement on the container instance" — is not one the daemon
    // runs on, so the task on it is taken off it.
    ok(
        &router,
        "UpdateContainerInstancesState",
        json!({
            "cluster": CLUSTER,
            "containerInstances": [joined.clone()],
            "status": "DRAINING",
        }),
        CASE,
    )
    .await;
    let drained = poll_daemon(
        &router,
        &daemon_arn,
        CASE,
        "the drained instance to stop counting towards the daemon",
        |daemon| {
            list(daemon, "currentRevisions", CASE)
                .first()
                .map(|revision| count(revision, "totalRunningCount", CASE))
                == Some(1)
        },
    )
    .await;
    let remaining = daemon_tasks(&router, CLUSTER, "agents", CASE).await;
    assert_eq!(
        running_hosts(&remaining, CASE),
        vec![first],
        "case {CASE:?}: expected the daemon task only on the instance still accepting \
         placements, got {remaining:?}"
    );
    assert!(
        list(&drained, "currentRevisions", CASE)
            .first()
            .map(|revision| count(revision, "totalRunningCount", CASE))
            == Some(1),
        "case {CASE:?}: expected the running count to follow the capacity, got {drained}"
    );
}

#[tokio::test]
async fn an_update_captures_a_new_revision_and_rolls_the_daemon_tasks_over_onto_it() {
    let router = service();
    const CLUSTER: &str = "daemon-revisions";
    const FAMILY: &str = "daemonrevisions";
    const CASE: &str = "an update over a converged daemon";
    /// The image the SECOND daemon task definition revision runs, so the two revisions a
    /// report carries are told apart by what they run rather than by their ARNs alone.
    const NEXT_IMAGE: &str = "public.ecr.aws/aws-observability/aws-otel-collector:1.32.0";
    /// How many container instances the daemon rolls over ACROSS: more than one, because a
    /// rollout replaces the task of every instance rather than of one.
    const INSTANCES: i64 = 3;
    create_cluster(&router, CLUSTER, CASE).await;
    for ordinal in 0..INSTANCES {
        register_instance(
            &router,
            CLUSTER,
            &format!("i-0daemonrevision{ordinal:03}"),
            CASE,
        )
        .await;
    }
    let provider = create_managed_provider(&router, CLUSTER, "mi-revisions", CASE).await;
    let first_definition = register_daemon_definition(&router, FAMILY, IMAGE, CASE).await;
    let (daemon_arn, first_deployment) = create_daemon(
        &router,
        CLUSTER,
        "agents",
        std::slice::from_ref(&provider),
        &first_definition,
        CASE,
    )
    .await;
    let converged = poll_daemon(
        &router,
        &daemon_arn,
        CASE,
        "the daemon to converge on its first revision across every instance",
        |daemon| {
            list(daemon, "currentRevisions", CASE)
                .first()
                .map(|revision| count(revision, "totalRunningCount", CASE))
                == Some(INSTANCES)
        },
    )
    .await;
    let first_revision = string(&sole_revision(&converged, CASE), "arn", CASE);

    // A second revision of the same family, and the update that points the daemon at it.
    let next_definition = register_daemon_definition(&router, FAMILY, NEXT_IMAGE, CASE).await;
    assert_ne!(
        next_definition, first_definition,
        "case {CASE:?}: a second registration of a family is a second revision"
    );
    let updated = ok(
        &router,
        "UpdateDaemon",
        json!({
            "daemonArn": daemon_arn,
            "daemonTaskDefinitionArn": next_definition,
            "capacityProviderArns": [provider],
        }),
        CASE,
    )
    .await;
    let second_deployment = string(&updated, "deploymentArn", CASE);
    assert_ne!(
        second_deployment, first_deployment,
        "case {CASE:?}: an update triggers a NEW daemon deployment, got {updated}"
    );
    assert_eq!(
        string(&updated, "status", CASE),
        "ACTIVE",
        "case {CASE:?}: an updated daemon is still ACTIVE, got {updated}"
    );
    assert!(
        updated["updatedAt"].as_f64() >= updated["createdAt"].as_f64(),
        "case {CASE:?}: an update is not earlier than the create, got {updated}"
    );

    // The new rollout names the revision it is deploying and the one it is replacing.
    let described = describe_deployment(&router, &second_deployment, CASE).await;
    let target = string(&described["targetDaemonRevision"], "arn", CASE);
    assert_ne!(
        target, first_revision,
        "case {CASE:?}: an update captures a NEW revision, got {described}"
    );
    let sources = list(&described, "sourceDaemonRevisions", CASE);
    assert_eq!(
        sources
            .iter()
            .map(|source| string(source, "arn", CASE))
            .collect::<Vec<String>>(),
        vec![first_revision.clone()],
        "case {CASE:?}: expected the revision being replaced as the source, got {described}"
    );

    // The listing reports both rollouts, NEWEST first, and the one the update replaced has
    // ended.
    let listed = list_deployments(&router, &daemon_arn, CASE).await;
    assert_eq!(
        listed
            .iter()
            .map(|deployment| string(deployment, "daemonDeploymentArn", CASE))
            .collect::<Vec<String>>(),
        vec![second_deployment.clone(), first_deployment.clone()],
        "case {CASE:?}: expected the daemon's rollouts newest first, got {listed:?}"
    );
    let replaced = describe_deployment(&router, &first_deployment, CASE).await;
    let replaced_status = string(&replaced, "status", CASE);
    // The rollout the update replaced has ENDED, whichever end it reached: one still open
    // when the update arrived is STOPPED and names its replacement, and one that had
    // already converged keeps the SUCCESSFUL end it reached — a rollout that ended is never
    // re-ended. Either way it carries the instant it finished at.
    assert!(
        ["STOPPED", "SUCCESSFUL"].contains(&replaced_status.as_str())
            && replaced.get("finishedAt").is_some(),
        "case {CASE:?}: expected the earlier rollout to have ended, got {replaced}"
    );
    if replaced_status == "STOPPED" {
        assert!(
            replaced["statusReason"]
                .as_str()
                .is_some_and(|reason| reason.contains(&second_deployment)),
            "case {CASE:?}: expected a replaced rollout to name its replacement, got \
             {replaced}"
        );
    }

    // The daemon's task on EVERY instance is rolled over onto the new revision, and the
    // rollout then ends.
    poll_deployment(
        &router,
        &second_deployment,
        CASE,
        "the second rollout to reach SUCCESSFUL",
        |deployment| deployment["status"].as_str() == Some("SUCCESSFUL"),
    )
    .await;
    let rolled = poll_daemon(
        &router,
        &daemon_arn,
        CASE,
        "the daemon to run the revision the update captured on every instance",
        |daemon| {
            let revisions = list(daemon, "currentRevisions", CASE);
            revisions.len() == 1
                && revisions[0]["arn"].as_str() == Some(target.as_str())
                && count(&revisions[0], "totalRunningCount", CASE) == INSTANCES
        },
    )
    .await;
    let tasks = daemon_tasks(&router, CLUSTER, "agents", CASE).await;
    let running: Vec<String> = tasks
        .iter()
        .filter(|task| task["lastStatus"].as_str() == Some("RUNNING"))
        .map(|task| string(task, "taskDefinitionArn", CASE))
        .collect();
    assert_eq!(
        running,
        vec![next_definition.clone(); INSTANCES as usize],
        "case {CASE:?}: expected every running task to run the new revision, got {tasks:?}"
    );
    assert_eq!(
        running_hosts(&tasks, CASE).len(),
        INSTANCES as usize,
        "case {CASE:?}: expected one task per instance after the rollout, got {tasks:?}"
    );
    assert_eq!(
        string(&rolled, "deploymentArn", CASE),
        second_deployment,
        "case {CASE:?}: a daemon names its most recent deployment, got {rolled}"
    );
    // "Daemon revisions are immutable": each one reports the configuration it captured,
    // so the earlier revision still names the image it was created over.
    let rows: [(&str, &str, &str); 2] = [
        ("the revision the create captured", &first_revision, IMAGE),
        ("the revision the update captured", &target, NEXT_IMAGE),
    ];
    for (row, revision_arn, image) in rows {
        let revision = describe_revision(&router, revision_arn, row).await;
        assert_eq!(
            string(&revision, "daemonArn", row),
            daemon_arn,
            "case {row:?}: a revision names the daemon it belongs to, got {revision}"
        );
        let images = list(&revision, "containerImages", row);
        assert_eq!(
            images
                .iter()
                .map(|entry| string(entry, "image", row))
                .collect::<Vec<String>>(),
            vec![image.to_string()],
            "case {row:?}: expected the images of the revision as captured, got {revision}"
        );
        assert_eq!(
            string(&images[0], "containerName", row),
            "agent",
            "case {row:?}: expected the container the revision declares, got {revision}"
        );
    }

    // An ARN under a cluster that IS there but names no stored revision is reported as a
    // failure of its own entry rather than refusing the whole read.
    let unknown = format!(
        "arn:aws:ecs:{SIGNED_REGION}:{ACCOUNT}:daemon-revision/{CLUSTER}/agents/\
         0000000000000009999"
    );
    let body = ok(
        &router,
        "DescribeDaemonRevisions",
        json!({ "daemonRevisionArns": [unknown.clone(), first_revision.clone()] }),
        CASE,
    )
    .await;
    assert_eq!(
        list(&body, "daemonRevisions", CASE).len(),
        1,
        "case {CASE:?}: expected the revision that resolves, got {body}"
    );
    let failures = list(&body, "failures", CASE);
    assert_eq!(
        failures.len(),
        1,
        "case {CASE:?}: expected one failure, got {body}"
    );
    assert_eq!(
        (
            string(&failures[0], "arn", CASE),
            string(&failures[0], "reason", CASE)
        ),
        (unknown, "MISSING".to_string()),
        "case {CASE:?}: expected the entry echoed with MISSING, got {body}"
    );
}

#[tokio::test]
async fn a_delete_drains_the_daemon_tasks_and_the_daemon_leaves_the_listing() {
    let router = service();
    const CLUSTER: &str = "daemon-delete";
    const CASE: &str = "a delete over a converged daemon";
    create_cluster(&router, CLUSTER, CASE).await;
    register_instance(&router, CLUSTER, "i-0daemondelete0000", CASE).await;
    let provider = create_managed_provider(&router, CLUSTER, "mi-delete", CASE).await;
    let definition = register_daemon_definition(&router, "daemondelete", IMAGE, CASE).await;
    let (daemon_arn, deployment_arn) = create_daemon(
        &router,
        CLUSTER,
        "agents",
        &[provider],
        &definition,
        CASE,
    )
    .await;
    poll_daemon(
        &router,
        &daemon_arn,
        CASE,
        "the daemon to converge before it is deleted",
        |daemon| {
            list(daemon, "currentRevisions", CASE)
                .first()
                .map(|revision| count(revision, "totalRunningCount", CASE))
                == Some(1)
        },
    )
    .await;

    let deleted = ok(
        &router,
        "DeleteDaemon",
        json!({ "daemonArn": daemon_arn }),
        CASE,
    )
    .await;
    assert_eq!(
        string(&deleted, "status", CASE),
        "DELETE_IN_PROGRESS",
        "case {CASE:?}: \"After you call DeleteDaemon, the status changes to \
         DELETE_IN_PROGRESS\", got {deleted}"
    );
    let drain = string(&deleted, "deploymentArn", CASE);
    assert_ne!(
        drain, deployment_arn,
        "case {CASE:?}: the delete triggers its own daemon deployment, got {deleted}"
    );
    assert!(
        drain.starts_with(&format!(
            "arn:aws:ecs:{SIGNED_REGION}:{ACCOUNT}:daemon-deployment/{CLUSTER}/agents/"
        )),
        "case {CASE:?}: expected a daemon-deployment ARN of this daemon, got {drain:?}"
    );

    // "Deleting a daemon stops all running daemon tasks on the associated container
    // instances": no task of the daemon is wanted running any more.
    let deadline = Instant::now() + POLL_BUDGET;
    loop {
        let tasks = daemon_tasks(&router, CLUSTER, "agents", CASE).await;
        if tasks.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "case {CASE:?}: expected the daemon's tasks to stop, got {tasks:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // ... and the daemon itself leaves the listing on the clock, with no further call.
    let deadline = Instant::now() + POLL_BUDGET;
    loop {
        let body = ok(
            &router,
            "ListDaemons",
            json!({ "clusterArn": CLUSTER }),
            CASE,
        )
        .await;
        let listed = list(&body, "daemonSummariesList", CASE);
        if listed.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "case {CASE:?}: expected the deleted daemon to leave the listing, got {listed:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let (code, message) = refusal(
        &router,
        "DescribeDaemon",
        json!({ "daemonArn": daemon_arn }),
        CASE,
    )
    .await;
    assert_eq!(
        (code.as_str(), message.as_str()),
        (
            "DaemonNotFoundException",
            format!("Daemon not found: {daemon_arn}").as_str()
        ),
        "case {CASE:?}: expected the deleted daemon to be gone"
    );
}

#[tokio::test]
async fn every_daemon_operation_refuses_an_arn_it_cannot_resolve() {
    let router = service();
    const CLUSTER: &str = "daemon-refusals";
    const CASE: &str = "setup";
    create_cluster(&router, CLUSTER, CASE).await;
    let provider = create_managed_provider(&router, CLUSTER, "mi-refusals", CASE).await;
    let definition = register_daemon_definition(&router, "daemonrefusals", IMAGE, CASE).await;

    let daemon_of = |cluster: &str, name: &str| {
        format!("arn:aws:ecs:{SIGNED_REGION}:{ACCOUNT}:daemon/{cluster}/{name}")
    };
    // The rows differ along WHICH part of the identifier fails to resolve: the cluster the
    // ARN carries, the daemon within a cluster that is there, and the value's being no
    // daemon ARN at all. Which refusal each earns follows what the operation DOES: one that
    // acts in the daemon's cluster resolves that cluster first and is refused about it,
    // while the read of the one daemon the ARN identifies answers about the daemon.
    let identifiers: [(&str, String, bool); 3] = [
        (
            "a daemon ARN under a cluster this account does not hold",
            daemon_of("daemon-nowhere", "agents"),
            true,
        ),
        (
            "a daemon name no daemon of an existing cluster answers to",
            daemon_of(CLUSTER, "nosuchdaemon"),
            false,
        ),
        (
            "a value that is no daemon ARN at all",
            "agents".to_string(),
            false,
        ),
    ];
    for (identifier_case, daemon_arn, cluster_missing) in identifiers {
        // Every operation addressed to ONE daemon by ARN, each with the smallest request
        // the model accepts beside it — so the refusal is the identifier's and not another
        // member's — paired with what it does with the daemon's cluster and the error it
        // answers for a daemon that is not there. `ListDaemonDeployments` models no
        // not-found error for a daemon, so it reports that condition as the invalid
        // identifier it is.
        let operations: [(&str, Value, bool, &str); 4] = [
            (
                "DescribeDaemon",
                json!({ "daemonArn": daemon_arn }),
                false,
                "DaemonNotFoundException",
            ),
            (
                "UpdateDaemon",
                json!({
                    "daemonArn": daemon_arn,
                    "daemonTaskDefinitionArn": definition,
                    "capacityProviderArns": [provider],
                }),
                true,
                "DaemonNotFoundException",
            ),
            (
                "DeleteDaemon",
                json!({ "daemonArn": daemon_arn }),
                true,
                "DaemonNotFoundException",
            ),
            (
                "ListDaemonDeployments",
                json!({ "daemonArn": daemon_arn }),
                true,
                "ClientException",
            ),
        ];
        for (operation, request, acts_in_the_cluster, not_found_code) in operations {
            let case = format!("{operation} on {identifier_case}");
            let (code, message) = refusal(&router, operation, request, &case).await;
            let (expected_code, expected_message) = if cluster_missing && acts_in_the_cluster {
                ("ClusterNotFoundException", "Cluster not found.".to_string())
            } else {
                (not_found_code, format!("Daemon not found: {daemon_arn}"))
            };
            assert_eq!(
                (code.as_str(), message.as_str()),
                (expected_code, expected_message.as_str()),
                "case {case:?}: expected the refusal the identifier earns"
            );
        }
    }
}

#[tokio::test]
async fn a_deployment_listing_filters_by_status_and_creation_window_and_pages() {
    let router = service();
    const CLUSTER: &str = "daemon-listing";
    const CASE: &str = "a daemon with a rollout history";
    create_cluster(&router, CLUSTER, CASE).await;
    let provider = create_managed_provider(&router, CLUSTER, "mi-listing", CASE).await;
    let definition = register_daemon_definition(&router, "daemonlisting", IMAGE, CASE).await;
    let (daemon_arn, first) = create_daemon(
        &router,
        CLUSTER,
        "agents",
        std::slice::from_ref(&provider),
        &definition,
        CASE,
    )
    .await;
    // Two updates, so the daemon holds three rollouts: two ended and one current.
    let mut arns = vec![first];
    for _ in 0..2 {
        let body = ok(
            &router,
            "UpdateDaemon",
            json!({
                "daemonArn": daemon_arn,
                "daemonTaskDefinitionArn": definition,
                "capacityProviderArns": [provider],
            }),
            CASE,
        )
        .await;
        arns.push(string(&body, "deploymentArn", CASE));
    }
    let newest_first: Vec<String> = arns.iter().rev().cloned().collect();

    // Every rollout of the history has ENDED before the filters are read, so what each
    // filter selects is settled: a terminal rollout carries the instant it finished at and
    // its status never moves again, which is what makes the comparisons below about the
    // FILTER rather than about how far the clock has taken each rollout.
    let deadline = Instant::now() + POLL_BUDGET;
    let listed = loop {
        let listed = list_deployments(&router, &daemon_arn, CASE).await;
        if listed.len() == arns.len()
            && listed
                .iter()
                .all(|deployment| deployment.get("finishedAt").is_some())
        {
            break listed;
        }
        assert!(
            Instant::now() < deadline,
            "case {CASE:?}: expected every rollout of the history to end, got {listed:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    };
    assert_eq!(
        listed
            .iter()
            .map(|deployment| string(deployment, "daemonDeploymentArn", CASE))
            .collect::<Vec<String>>(),
        newest_first,
        "case {CASE:?}: expected every rollout of the daemon, newest first"
    );
    let created: Vec<f64> = listed
        .iter()
        .map(|deployment| deployment["createdAt"].as_f64().unwrap_or_default())
        .collect();
    // One second either side of the window the history occupies — a margin, so the rows
    // below are about which SIDE of a bound a rollout falls on rather than about how
    // exactly a timestamp survives a round trip through the wire's number form.
    let before_all = created.last().copied().unwrap_or_default() - 1.0;
    let after_all = created.first().copied().unwrap_or_default() + 1.0;

    // The rows differ along WHICH filter narrows the listing, and each is checked against
    // the rollouts it selects out of the same history — the statuses being the ones the
    // unfiltered listing itself reports, so the case is about the FILTER rather than about
    // how far the clock has taken each rollout.
    let mut statuses: Vec<String> = listed
        .iter()
        .map(|deployment| string(deployment, "status", CASE))
        .collect();
    statuses.sort();
    statuses.dedup();
    for status in &statuses {
        let row = format!("the rollouts in {status}");
        let (page, _) = list_deployments_page(
            &router,
            json!({ "daemonArn": daemon_arn, "status": [status] }),
            &row,
        )
        .await;
        let expected: Vec<String> = listed
            .iter()
            .filter(|deployment| string(deployment, "status", CASE) == *status)
            .map(|deployment| string(deployment, "daemonDeploymentArn", CASE))
            .collect();
        assert_eq!(
            page.iter()
                .map(|deployment| string(deployment, "daemonDeploymentArn", &row))
                .collect::<Vec<String>>(),
            expected,
            "case {row:?}: expected exactly the rollouts in that status"
        );
    }
    let filter_rows: [(&str, Value, usize); 5] = [
        (
            "no filter at all",
            json!({ "daemonArn": daemon_arn }),
            arns.len(),
        ),
        (
            "a status no rollout of this daemon is in",
            json!({ "daemonArn": daemon_arn, "status": ["ROLLBACK_FAILED"] }),
            0,
        ),
        (
            "a window that ends before every rollout of the history",
            json!({
                "daemonArn": daemon_arn,
                "createdAt": { "before": before_all },
            }),
            0,
        ),
        (
            "a window that starts after every rollout of the history",
            json!({
                "daemonArn": daemon_arn,
                "createdAt": { "after": after_all },
            }),
            0,
        ),
        (
            "a window that starts before every rollout of the history",
            json!({
                "daemonArn": daemon_arn,
                "createdAt": { "after": before_all },
            }),
            arns.len(),
        ),
    ];
    for (row, request, expected) in filter_rows {
        let (page, _) = list_deployments_page(&router, request, row).await;
        assert_eq!(
            page.len(),
            expected,
            "case {row:?}: expected {expected} rollout(s), got {page:?}"
        );
    }

    // "maxResults ... along with a nextToken response element": the walk reports every
    // rollout exactly once, one page at a time.
    let mut walked = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut request = json!({ "daemonArn": daemon_arn, "maxResults": 1 });
        if let Some(token) = token.as_deref() {
            request["nextToken"] = json!(token);
        }
        let (page, next) = list_deployments_page(&router, request, "one rollout per page").await;
        assert!(
            page.len() <= 1,
            "case {CASE:?}: expected at most one rollout a page, got {page:?}"
        );
        walked.extend(
            page.iter()
                .map(|deployment| string(deployment, "daemonDeploymentArn", CASE)),
        );
        match next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!(
        walked, newest_first,
        "case {CASE:?}: expected the paged walk to report every rollout once"
    );
}

#[tokio::test]
async fn a_daemon_scheduled_service_keeps_one_task_per_instance_its_cluster_holds() {
    let router = service();
    const CLUSTER: &str = "daemon-service-capacity";
    const SERVICE: &str = "agents";
    const CASE: &str = "a DAEMON-scheduled service over capacity that moves";
    create_cluster(&router, CLUSTER, CASE).await;
    let first = register_instance(&router, CLUSTER, "i-0daemonservice000", CASE).await;
    let definition = crate::ecs_wire::register_definition(&router, "daemonservice", CASE).await;
    let created = ok(
        &router,
        "CreateService",
        json!({
            "cluster": CLUSTER,
            "serviceName": SERVICE,
            "taskDefinition": definition,
            "schedulingStrategy": "DAEMON",
        }),
        CASE,
    )
    .await;
    assert_eq!(
        count(&created["service"], "desiredCount", CASE),
        1,
        "case {CASE:?}: \"exactly one task on each active container instance\", got {created}"
    );

    // The rows differ along what the rule generalises over: HOW the capacity of the
    // cluster moves after the service was created — an instance joining, and an instance
    // that stops accepting placements. The count the scheduler keeps follows each move with
    // no call on the service at all.
    let joined = register_instance(&router, CLUSTER, "i-0daemonservice001", CASE).await;
    let rows: [(&str, Option<String>, i64); 2] = [
        ("an instance that joined after the create", None, 2),
        (
            "an instance taken out of service",
            Some(joined.clone()),
            1,
        ),
    ];
    for (row, drain, expected) in rows {
        if let Some(instance) = drain {
            ok(
                &router,
                "UpdateContainerInstancesState",
                json!({
                    "cluster": CLUSTER,
                    "containerInstances": [instance],
                    "status": "DRAINING",
                }),
                row,
            )
            .await;
        }
        let deadline = Instant::now() + POLL_BUDGET;
        loop {
            let body = ok(
                &router,
                "DescribeServices",
                json!({ "cluster": CLUSTER, "services": [SERVICE] }),
                row,
            )
            .await;
            let services = list(&body, "services", row);
            let service = services
                .first()
                .unwrap_or_else(|| panic!("case {row:?}: expected the service back, got {body}"));
            let desired = count(service, "desiredCount", row);
            let running = count(service, "runningCount", row);
            if desired == expected && running == expected {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "case {row:?}: expected a desired and running count of {expected}, got \
                 {desired}/{running} in {service}"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    // The task the service kept is on the instance that still accepts placements.
    let listed = ok(
        &router,
        "ListTasks",
        json!({ "cluster": CLUSTER, "serviceName": SERVICE }),
        CASE,
    )
    .await;
    let arns = list(&listed, "taskArns", CASE);
    let described = ok(
        &router,
        "DescribeTasks",
        json!({ "cluster": CLUSTER, "tasks": arns }),
        CASE,
    )
    .await;
    let tasks = list(&described, "tasks", CASE);
    assert_eq!(
        running_hosts(&tasks, CASE),
        vec![first],
        "case {CASE:?}: expected the service's task on the instance still accepting \
         placements, got {tasks:?}"
    );
}
