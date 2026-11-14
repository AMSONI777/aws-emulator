// SPDX-License-Identifier: CC0-1.0

//! The network interface of an instance an Auto Scaling group launched belongs to THAT
//! instance, and goes away with it.
//!
//! RULE under test: **an instance a group launches is an Amazon EC2 instance like any
//! other, so Amazon EC2 holds a primary network interface for it: the interface reports an
//! attachment to the instance the group launched — at that instance's own id, in the
//! terminal `attached` status, because the group's launch is what attached it and no caller
//! was ever answered that attachment being made — and the interface is DELETED with the
//! instance when the group scales back in, so afterwards neither the interface nor its id
//! resolves.** An interface that reported an attachment to another instance, or one left in
//! a non-terminal status, is one no client could follow from the group's own instance to the
//! address it is reachable at.
//!
//! The rows differ along what the rule generalises over: how much capacity the group
//! launches (one instance, several), how it is placed (one subnet, two), and how the
//! scale-in is asked for (`SetDesiredCapacity` to zero, `UpdateAutoScalingGroup` to zero).
//!
//! Both services are mounted on ONE engine and driven over their own wire protocols —
//! awsQuery for Auto Scaling, ec2Query for Amazon EC2 — the way the emulator serves them,
//! so every id these assertions follow is an id a client is given.

use std::sync::Arc;
use std::time::{Duration, Instant};

use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_autoscaling_autoscaling_2011_01_01 as autoscaling;
use service_com_amazonaws_ec2_amazonec2 as ec2_service;
use service_com_amazonaws_ec2_amazonec2::state as ec2;

use crate::support::{borrowed, ec2_query, p, query, seed_subnets, tag_value, tag_values};

/// How long a case polls for a clock-owed transition, and how often it looks. Generous on
/// purpose: nothing inside the emulator sleeps for a due instant, so every wait here polls
/// for the CONDITION it needs and this deadline is only the backstop that turns something
/// nothing will ever settle into a readable failure.
const DEADLINE: Duration = Duration::from_secs(60);
/// See [`DEADLINE`].
const SPACING: Duration = Duration::from_millis(50);

/// One emulator with BOTH services on one engine: an Auto Scaling group's instances live
/// in the same account's Amazon EC2 store, so one engine is what makes the two views one
/// account.
fn emulator() -> (MultiServiceRouter, Arc<engine::InMemoryEngine>) {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(autoscaling::EmulatedService::new(Arc::clone(&engine)));
    router.register_service(ec2_service::EmulatedService::new(Arc::clone(&engine)));
    (router, engine)
}

/// Create one Amazon EC2 launch template over the wire.
async fn create_launch_template(router: &MultiServiceRouter, name: &str) {
    let (status, body) = ec2_query(
        router,
        "CreateLaunchTemplate",
        &[
            p("LaunchTemplateName", name),
            p("LaunchTemplateData.ImageId", "ami-00000000000000021"),
            p("LaunchTemplateData.InstanceType", "t3.micro"),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "setup: CreateLaunchTemplate for {name} expected 200, got {status}: {body}"
    );
}

/// The instance ids the group reports, in the order it reports them.
async fn reported_instances(router: &MultiServiceRouter, group: &str) -> Vec<String> {
    let (status, body) = query(
        router,
        "DescribeAutoScalingGroups",
        &[("AutoScalingGroupNames.member.1", group)],
    )
    .await;
    assert_eq!(
        status, 200,
        "DescribeAutoScalingGroups expected 200, got {status}: {body}"
    );
    tag_values(&body, "InstanceId")
}

/// Poll the group until it reports `wanted` instances, answering their ids.
async fn instances_once_launched(
    router: &MultiServiceRouter,
    case: &str,
    group: &str,
    wanted: usize,
) -> Vec<String> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let reported = reported_instances(router, group).await;
        if reported.len() == wanted {
            return reported;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected the group to report {wanted} instances, got {reported:?}"
        );
        tokio::time::sleep(SPACING).await;
    }
}

/// The interface Amazon EC2 holds for `instance_id`, read through the attachment filter —
/// `None` while it holds none.
async fn interface_of(router: &MultiServiceRouter, instance_id: &str) -> Option<String> {
    let (status, body) = ec2_query(
        router,
        "DescribeNetworkInterfaces",
        &[
            p("Filter.1.Name", "attachment.instance-id"),
            p("Filter.1.Value.1", instance_id),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "DescribeNetworkInterfaces expected 200, got {status}: {body}"
    );
    let found = tag_values(&body, "networkInterfaceId");
    found.first().cloned()
}

/// The attachment Amazon EC2 reports for one interface, as `(instance id, status)`.
async fn attachment_of(router: &MultiServiceRouter, interface_id: &str) -> (String, String) {
    let (status, body) = ec2_query(
        router,
        "DescribeNetworkInterfaces",
        &[p("NetworkInterfaceId.1", interface_id)],
    )
    .await;
    assert_eq!(
        status, 200,
        "DescribeNetworkInterfaces for {interface_id} expected 200, got {status}: {body}"
    );
    let attachment = tag_value(&body, "attachment");
    (
        tag_value(&attachment, "instanceId"),
        tag_value(&attachment, "status"),
    )
}

/// How the scale-in to zero is asked for.
#[derive(Debug, Clone, Copy)]
enum ScaleIn {
    /// `SetDesiredCapacity` with `DesiredCapacity` 0.
    SetDesiredCapacity,
    /// `UpdateAutoScalingGroup` with `DesiredCapacity` 0.
    UpdateGroup,
}

#[tokio::test]
async fn an_instance_the_group_launched_holds_an_interface_attached_to_it() {
    // (case, how much capacity, how many subnets, how the scale-in is asked for)
    let rows: &[(&str, usize, usize, ScaleIn)] = &[
        (
            "one instance in one subnet, scaled in by SetDesiredCapacity",
            1,
            1,
            ScaleIn::SetDesiredCapacity,
        ),
        (
            "two instances across two subnets, scaled in by UpdateAutoScalingGroup",
            2,
            2,
            ScaleIn::UpdateGroup,
        ),
        (
            "three instances in one subnet, scaled in by SetDesiredCapacity",
            3,
            1,
            ScaleIn::SetDesiredCapacity,
        ),
    ];

    for (index, (case, capacity, subnets, scale_in)) in rows.iter().enumerate() {
        // One emulator per row: each row is its own account, so the ids of one row never
        // explain another's.
        let (router, engine) = emulator();
        let seeded = seed_subnets(&engine, *subnets);
        let identifier = seeded
            .iter()
            .map(|subnet| subnet.id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let template = format!("lt-eni-{index}");
        create_launch_template(&router, &template).await;

        let group = format!("asg-eni-{index}");
        let params = vec![
            p("AutoScalingGroupName", group.clone()),
            p("MinSize", "0"),
            p("MaxSize", capacity.to_string()),
            p("DesiredCapacity", capacity.to_string()),
            p("LaunchTemplate.LaunchTemplateName", template.clone()),
            p("VPCZoneIdentifier", identifier.clone()),
        ];
        let (status, body) = query(&router, "CreateAutoScalingGroup", &borrowed(&params)).await;
        assert_eq!(
            status, 200,
            "case {case:?}: CreateAutoScalingGroup expected 200, got {status}: {body}"
        );

        let instances = instances_once_launched(&router, case, &group, *capacity).await;
        // Each instance holds an interface of its own, which reports an attachment to THAT
        // instance in the terminal attached status — on the FIRST look, with no wait: the
        // group's launch is what attached it.
        let mut interfaces: Vec<(String, String)> = Vec::new();
        for instance_id in &instances {
            let interface = interface_of(&router, instance_id).await.unwrap_or_else(|| {
                panic!(
                    "case {case:?}: expected Amazon EC2 to hold an interface attached to \
                     {instance_id}"
                )
            });
            let (attached_to, status) = attachment_of(&router, &interface).await;
            assert_eq!(
                (attached_to.as_str(), status.as_str()),
                (instance_id.as_str(), ec2::ATTACHMENT_STATUS_ATTACHED),
                "case {case:?}: expected {interface} to read attached to {instance_id}"
            );
            interfaces.push((instance_id.clone(), interface));
        }
        // One interface per instance: no two instances of the group share one.
        let mut distinct: Vec<&str> = interfaces
            .iter()
            .map(|(_, interface)| interface.as_str())
            .collect();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            interfaces.len(),
            "case {case:?}: expected one interface per instance, got {interfaces:?}"
        );

        // The scale-in to zero terminates those instances, and the interfaces that went
        // with them are deleted: neither the attachment filter nor the id itself resolves
        // to one afterwards.
        let zero = "0";
        let (status, body) = match scale_in {
            ScaleIn::SetDesiredCapacity => {
                query(
                    &router,
                    "SetDesiredCapacity",
                    &[
                        ("AutoScalingGroupName", group.as_str()),
                        ("DesiredCapacity", zero),
                    ],
                )
                .await
            }
            ScaleIn::UpdateGroup => {
                query(
                    &router,
                    "UpdateAutoScalingGroup",
                    &[
                        ("AutoScalingGroupName", group.as_str()),
                        ("DesiredCapacity", zero),
                        ("MinSize", zero),
                    ],
                )
                .await
            }
        };
        assert_eq!(
            status, 200,
            "case {case:?}: the scale-in expected 200, got {status}: {body}"
        );

        let deadline = Instant::now() + DEADLINE;
        for (instance_id, interface) in &interfaces {
            loop {
                let (status, body) = ec2_query(
                    &router,
                    "DescribeNetworkInterfaces",
                    &[p("NetworkInterfaceId.1", interface.as_str())],
                )
                .await;
                if status != 200 {
                    assert!(
                        body.contains("InvalidNetworkInterfaceID.NotFound"),
                        "case {case:?}: expected the deleted {interface} to be refused as an \
                         id nothing holds, got {status}: {body}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "case {case:?}: expected {interface} to go with {instance_id}, and Amazon \
                     EC2 still reports it: {body}"
                );
                tokio::time::sleep(SPACING).await;
            }
            assert_eq!(
                interface_of(&router, instance_id).await,
                None,
                "case {case:?}: expected no interface attached to the terminated \
                 {instance_id}"
            );
        }
    }
}
