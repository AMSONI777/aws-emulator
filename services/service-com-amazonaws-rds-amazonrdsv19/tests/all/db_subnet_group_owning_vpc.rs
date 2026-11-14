// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for `DBSubnetGroup$VpcId` — "the VpcId of the DB subnet group".
//!
//! RULE: a DB subnet group is a set of subnets of ONE VPC, and the VPC it reports is the one
//! the service that OWNS subnets names as the owner of the subnets the request listed in
//! `SubnetIds` — so the id reads back equal to the `VpcId` `ec2:DescribeSubnets` reports for
//! those very identifiers, and it is never an id this service minted for the group.
//!
//! The sibling suite `db_subnet_group_ec2_zones` asserts the per-subnet half of the same
//! resolution (each `Subnet$SubnetAvailabilityZone`); this one spans the group-level half over
//! a TABLE whose rows differ in WHICH VPC owns the subnets: two VPCs this test minted through
//! EC2 and the account's own default VPC, whose subnets this process did not see created.
//!
//! Every expected value is one EC2 answered with, so no assertion recomputes what the code
//! under test computes.

use crate::db_instances::{expect_ok, text};
use crate::db_subnet_group_ec2_zones::{default_subnets, Account};

/// The CIDR blocks of the VPCs this suite mints, outside the default VPC's own block and
/// outside the sibling suite's so every network can exist at once.
const VPC_CIDRS: [&str; 2] = ["10.60.0.0/16", "10.61.0.0/16"];

/// The `VpcId` EC2 reports for `subnet_id`: what the group's own id is asserted against, read
/// from the owner of subnets rather than derived here.
async fn vpc_of(account: &Account, subnet_id: &str) -> String {
    account
        .ec2
        .describe_subnets()
        .subnet_ids(subnet_id)
        .send()
        .await
        .unwrap_or_else(|error| panic!("EC2 must report the subnet {subnet_id}: {error:?}"))
        .subnets()
        .iter()
        .find(|subnet| subnet.subnet_id() == Some(subnet_id))
        .and_then(::aws_sdk_ec2::types::Subnet::vpc_id)
        .unwrap_or_else(|| panic!("EC2 must report a VPC for the subnet {subnet_id}"))
        .to_string()
}

/// RULE: the `VpcId` a DB subnet group reports is the VPC EC2 names as the owner of the
/// subnets the request listed — on the create and on every read back.
#[tokio::test]
async fn a_group_reports_the_vpc_ec2_says_owns_the_subnets_it_was_given() {
    let account = Account::new();
    let zones = account.zones().await;

    // Rows: one pair of subnets per VPC this test mints, plus the account's own default
    // subnets — three different owning VPCs, each named by two subnets in two zones so every
    // row is a group the service will serve.
    let mut rows: Vec<(String, Vec<String>)> = Vec::new();
    for (index, cidr) in VPC_CIDRS.into_iter().enumerate() {
        let vpc = account.create_vpc(cidr).await;
        let subnets = vec![
            account
                .create_subnet(&vpc, &format!("10.6{index}.1.0/24"), &zones[0])
                .await,
            account
                .create_subnet(&vpc, &format!("10.6{index}.2.0/24"), &zones[1])
                .await,
        ];
        rows.push((format!("two subnets of the VPC {cidr}"), subnets));
    }
    // The subnets of the VPC every account has, which a client names without having created
    // anything: asked of the owner of subnets through the one helper the discovered-subnet
    // suites share (`db_subnet_group_ec2_zones::default_subnets`).
    let discovered: Vec<String> = default_subnets(&account)
        .await
        .into_iter()
        .map(|(_, subnet_id)| subnet_id)
        .collect();
    assert!(
        discovered.len() >= 2,
        "the account's network must carry a default subnet in at least two Availability Zones \
         for this row, got {discovered:?}"
    );
    rows.push((
        "two default subnets of the account's own VPC".to_string(),
        discovered[..2].to_vec(),
    ));

    for (index, (case, subnets)) in rows.into_iter().enumerate() {
        // The expectation: the VPC the OWNER of subnets reports for each identifier, which is
        // one id because a group's subnets are of one VPC.
        let mut owners: Vec<String> = Vec::with_capacity(subnets.len());
        for subnet_id in &subnets {
            owners.push(vpc_of(&account, subnet_id).await);
        }
        let expected = owners[0].clone();
        assert!(
            owners.iter().all(|owner| *owner == expected),
            "case {case:?}: the row must name subnets of ONE VPC, got {owners:?}"
        );

        let name = format!("emu-owning-vpc-{index}");
        let created = expect_ok(&case, account.create_group(&name, &subnets).await);
        let read_back = expect_ok(&case, account.describe_group(&name).await);
        for (label, envelope) in [
            ("CreateDBSubnetGroup", &created),
            ("DescribeDBSubnetGroups", &read_back),
        ] {
            let reported = text(envelope, "VpcId");
            assert_eq!(
                reported, expected,
                "case {case:?} ({label}): EC2 reports these subnets in {expected:?}, so the \
                 group must report that VPC, got {reported:?}"
            );
        }
    }
}
