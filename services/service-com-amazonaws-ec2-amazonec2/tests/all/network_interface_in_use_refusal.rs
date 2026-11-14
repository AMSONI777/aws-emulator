// SPDX-License-Identifier: CC0-1.0

//! The ONE refusal every operation of this service answers when it is asked to do something
//! to a network interface SOMETHING ELSE STILL HOLDS, driven end to end over the wire the
//! service speaks (`ec2Query`: an `application/x-www-form-urlencoded` POST carrying
//! `Action=<Operation>`, answered with XML — README.md / OPERATIONS.md "Wire protocol").
//!
//! The rule under test: an action asked of a network interface an attachment still holds is
//! refused HTTP 400 with the PARAMETER-VALUE class — what the caller got wrong is the
//! interface id it passed — and with the one sentence that class carries, `Network interface
//! '<id>' is currently in use.`, whose single variable part is the id the REQUEST named. One
//! rule, so every operation that resolves a `NetworkInterfaceId` and finds it held answers
//! it the same way, and nothing the refusal touched is written.
//!
//! The rows span what that generalises over: the OPERATION that asks (the delete of an
//! interface, the attach of one to an instance, and a launch that names an existing
//! interface to attach), whether the request also carries `DryRun` (the dry run reports the
//! reason the call would have failed for, not the permission check), the `AttachmentStatus`
//! of the attachment that holds it — every non-terminal status of
//! `smithy_query(query="shape",shape="AttachmentStatus")` plus an attachment that reports no
//! status at all — and the interface id itself, which differs per row because each row seeds
//! its own interface. The companion test pins the other side of the same rule: an interface
//! nothing holds — one whose attachment has reached `detached`, and one that never had an
//! attachment at all — is refused by none of those calls.

use ec2::ops::types::NetworkInterfaceAttachment;
use ec2::state::{
    ComAmazonawsEc2Amazonec2State as Ec2State, NetworkInterfaceSpec, ATTACHMENT_STATUS_ATTACHED,
    ATTACHMENT_STATUS_ATTACHING, ATTACHMENT_STATUS_DETACHED, ATTACHMENT_STATUS_DETACHING,
    NETWORK_INTERFACE_ATTACHMENT_ID_PREFIX, NETWORK_INTERFACE_TYPE_INTERFACE,
};
use service_com_amazonaws_ec2_amazonec2 as ec2;
use smithy_server_runtime::MultiServiceRouter;

use super::ec2_query::{call, element, error_code, error_message};
use super::wire::{param, Param};

/// The Region every call here is signed for.
const REGION: &str = "us-east-1";

/// The image every launch names: a launch only has to accept the id, and which image an
/// instance ran from has no bearing on the interfaces it may be given.
const AMI: &str = "ami-0123456789abcdef0";

/// An instance type whose network-interface limit is well above the one interface these
/// attaches ask for, so no row is refused by a limit instead of by the rule under test.
const INSTANCE_TYPE: &str = "m5.4xlarge";

/// The error code EC2 answers a bad `NetworkInterfaceId` with. EC2's model declares no error
/// shapes at all (`smithy_query(query="operation",operation="DeleteNetworkInterface")` →
/// `errors: []`), so the code is matched as the wire string the service answers.
const INVALID_PARAMETER_VALUE: &str = "InvalidParameterValue";

/// The status a refusal about the request is answered with.
const REFUSAL_STATUS: u16 = 400;

/// The status a `DryRun` of a call that would have succeeded is answered with.
const DRY_RUN_STATUS: u16 = 412;

/// The sentence the in-use class carries, with the id from the request interpolated.
fn in_use_message(network_interface_id: &str) -> String {
    format!("Network interface '{network_interface_id}' is currently in use.")
}

/// Where a seeded interface sits: the account's default VPC, one of its default subnets and
/// that subnet's Availability Zone — a subnet the store really holds rather than an invented
/// one, so an instance launched into it shares the interface's zone.
#[derive(Debug, Clone)]
struct Place {
    vpc_id: String,
    subnet_id: String,
    availability_zone: String,
    availability_zone_id: String,
}

/// The place a fresh store already offers: its default VPC's first default subnet.
fn place(engine: &engine::InMemoryEngine) -> Place {
    let store = engine.state::<Ec2State>();
    let store = store.lock();
    let vpc_id = store
        .default_vpc_id(REGION)
        .expect("a fresh account has a default VPC");
    let (subnet_id, subnet) = store
        .subnets
        .iter()
        .find(|(_, subnet)| subnet.vpc_id.as_deref() == Some(&vpc_id))
        .expect("the default VPC comes with default subnets");
    Place {
        vpc_id: vpc_id.clone(),
        subnet_id: subnet_id.clone(),
        availability_zone: subnet.availability_zone.clone().unwrap_or_default(),
        availability_zone_id: subnet.availability_zone_id.clone().unwrap_or_default(),
    }
}

/// One interface of `place` holding an attachment in `status` — `None` for an attachment
/// that reports no status at all, which still holds the interface. Seeded through the
/// store's own writer seam, so the record under test is the one every reader of the store
/// sees, and the attachment statuses a clock-driven attach passes through can all be covered
/// without waiting on the clock.
fn seed_held(
    engine: &engine::InMemoryEngine,
    place: &Place,
    suffix: &str,
    status: Option<&str>,
) -> String {
    let attachment = NetworkInterfaceAttachment {
        attachment_id: Some(format!("{NETWORK_INTERFACE_ATTACHMENT_ID_PREFIX}-{suffix}")),
        device_index: Some(1),
        instance_id: Some("i-0aaaaaaaaaaaaaaaa".to_string()),
        status: status.map(str::to_string),
        ..NetworkInterfaceAttachment::default()
    };
    engine
        .state::<Ec2State>()
        .lock()
        .insert_network_interface(NetworkInterfaceSpec {
            subnet_id: place.subnet_id.clone(),
            vpc_id: place.vpc_id.clone(),
            availability_zone: place.availability_zone.clone(),
            availability_zone_id: place.availability_zone_id.clone(),
            interface_type: NETWORK_INTERFACE_TYPE_INTERFACE.to_string(),
            attachment: Some(attachment),
            ..NetworkInterfaceSpec::default()
        })
        .expect("the store holds the seeded network interface")
}

/// What the store holds for `network_interface_id`: its status and the instance and status of
/// the attachment on it — the reading a "the refusal wrote nothing" assertion compares.
fn held_by(
    engine: &engine::InMemoryEngine,
    network_interface_id: &str,
) -> Option<(Option<String>, Option<String>, Option<String>)> {
    let store = engine.state::<Ec2State>();
    let store = store.lock();
    let interface = store.network_interfaces.get(network_interface_id)?;
    let attachment = interface.attachment.as_ref();
    Some((
        interface.status.clone(),
        attachment.and_then(|attachment| attachment.instance_id.clone()),
        attachment.and_then(|attachment| attachment.status.clone()),
    ))
}

/// One instance of `place`, launched over the wire so the attaches below name an instance the
/// account really holds, in the same Availability Zone as every seeded interface.
async fn launch_instance(router: &MultiServiceRouter, place: &Place) -> String {
    let (status, body) = call(
        router,
        REGION,
        "RunInstances",
        &[
            param("ImageId", AMI),
            param("InstanceType", INSTANCE_TYPE),
            param("MinCount", "1"),
            param("MaxCount", "1"),
            param("SubnetId", &place.subnet_id),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "the instance every attach names must launch, got {status} with body {body}"
    );
    element(&body, "instanceId").expect("a launch answers an instance id")
}

/// One interface created through the operation that creates one, which leaves it attached to
/// nothing at all — and, unlike a seeded record, with the primary private address the create
/// mints for it.
async fn create_interface(router: &MultiServiceRouter, place: &Place) -> String {
    let (status, body) = call(
        router,
        REGION,
        "CreateNetworkInterface",
        &[param("SubnetId", &place.subnet_id)],
    )
    .await;
    assert_eq!(
        status, 200,
        "the interface a launch names must be created, got {status} with body {body}"
    );
    element(&body, "networkInterfaceId").expect("the create answers an interface id")
}

/// Which operation asks something of an interface, and whether the request carries `DryRun`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// `DeleteNetworkInterface` — "You must detach the network interface before you can
    /// delete it" (`DeleteNetworkInterface`).
    Delete,
    /// `AttachNetworkInterface` — an interface already held is not given to another instance.
    Attach,
    /// `RunInstances` naming an EXISTING interface to attach at device index 0.
    Launch,
}

/// The request that asks it: the `Action` and the form fields, with the device index the
/// attach asks for (irrelevant to the rule, so each case may pick its own).
fn request(
    asked: Asked,
    network_interface_id: &str,
    instance_id: &str,
    device_index: u32,
    dry_run: bool,
) -> (&'static str, Vec<Param>) {
    let mut params = match asked {
        Asked::Delete => vec![param("NetworkInterfaceId", network_interface_id)],
        Asked::Attach => vec![
            param("NetworkInterfaceId", network_interface_id),
            param("InstanceId", instance_id),
            param("DeviceIndex", &device_index.to_string()),
        ],
        Asked::Launch => vec![
            param("ImageId", AMI),
            param("InstanceType", INSTANCE_TYPE),
            param("MinCount", "1"),
            param("MaxCount", "1"),
            param("NetworkInterface.1.DeviceIndex", "0"),
            param("NetworkInterface.1.NetworkInterfaceId", network_interface_id),
        ],
    };
    if dry_run {
        params.push(param("DryRun", "true"));
    }
    let action = match asked {
        Asked::Delete => "DeleteNetworkInterface",
        Asked::Attach => "AttachNetworkInterface",
        Asked::Launch => "RunInstances",
    };
    (action, params)
}

/// The rule: an action asked of an interface an attachment still holds is refused HTTP 400
/// `InvalidParameterValue` with the sentence `Network interface '<id>' is currently in use.`,
/// whichever operation asks it and whether or not the request carries `DryRun`, and the
/// refusal writes nothing.
#[tokio::test]
async fn an_interface_something_still_holds_is_refused_as_a_parameter_value() {
    let (router, engine) = super::ec2_query::emulator();
    let place = place(&engine);
    let instance_id = launch_instance(&router, &place).await;

    // Every non-terminal `AttachmentStatus`, plus an attachment that reports none at all.
    let statuses: [(&str, Option<&str>); 4] = [
        ("an attachment under way", Some(ATTACHMENT_STATUS_ATTACHING)),
        ("a finished attachment", Some(ATTACHMENT_STATUS_ATTACHED)),
        (
            "an attachment being taken away",
            Some(ATTACHMENT_STATUS_DETACHING),
        ),
        ("an attachment that reports no status", None),
    ];
    // Each operation that resolves a `NetworkInterfaceId`, with and without `DryRun`.
    let asks: [(Asked, bool); 5] = [
        (Asked::Delete, false),
        (Asked::Delete, true),
        (Asked::Attach, false),
        (Asked::Attach, true),
        (Asked::Launch, false),
    ];

    for (row, (status_case, attachment_status)) in statuses.into_iter().enumerate() {
        for (column, (asked, dry_run)) in asks.into_iter().enumerate() {
            let case = format!("{asked:?} (DryRun={dry_run}) on {status_case}");
            let network_interface_id = seed_held(
                &engine,
                &place,
                &format!("{:016x}", row * asks.len() + column),
                attachment_status,
            );
            let before = held_by(&engine, &network_interface_id);
            let (action, params) = request(
                asked,
                &network_interface_id,
                &instance_id,
                1,
                dry_run,
            );
            let (http_status, body) = call(&router, REGION, action, &params).await;
            assert_eq!(
                http_status, REFUSAL_STATUS,
                "case {case:?}: expected HTTP {REFUSAL_STATUS} from {action}, got \
                 {http_status} with body {body}"
            );
            let answered_code = error_code(&body);
            assert_eq!(
                answered_code, INVALID_PARAMETER_VALUE,
                "case {case:?}: expected the code {INVALID_PARAMETER_VALUE:?}, got \
                 {answered_code:?} in {body}"
            );
            let answered_message = error_message(&body);
            assert_eq!(
                answered_message,
                in_use_message(&network_interface_id),
                "case {case:?}: expected the message {:?}, got {answered_message:?}",
                in_use_message(&network_interface_id)
            );
            let after = held_by(&engine, &network_interface_id);
            assert_eq!(
                after, before,
                "case {case:?}: a refused call must leave the interface exactly as it was, \
                 was {before:?}, now {after:?}"
            );
        }
    }
}

/// How the interface a row names was made, which is what decides whether anything holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// An attachment record that has reached `detached`: the one `AttachmentStatus` that
    /// leaves the interface holding nothing.
    ByADetachedAttachment,
    /// An interface created through `CreateNetworkInterface`, which carries no attachment at
    /// all.
    ByNothing,
}

/// The other side of the same rule: an interface nothing holds — one whose attachment has
/// reached `detached`, or one that never had an attachment — is NOT refused, so the refusal
/// is computed from the attachment the store holds rather than from the presence of an
/// attachment record.
#[tokio::test]
async fn an_interface_nothing_holds_is_not_refused() {
    let (router, engine) = super::ec2_query::emulator();
    let place = place(&engine);
    let instance_id = launch_instance(&router, &place).await;

    // (case, how the interface is held, the operation asked, the device index it asks for,
    // whether DryRun is set, the status it must answer)
    let cases: [(&str, Held, Asked, u32, bool, u16); 4] = [
        (
            "the delete of an interface whose attachment is detached",
            Held::ByADetachedAttachment,
            Asked::Delete,
            0,
            false,
            200,
        ),
        (
            "the attach of an interface whose attachment is detached",
            Held::ByADetachedAttachment,
            Asked::Attach,
            1,
            false,
            200,
        ),
        (
            "a dry-run attach of an interface whose attachment is detached",
            Held::ByADetachedAttachment,
            Asked::Attach,
            2,
            true,
            DRY_RUN_STATUS,
        ),
        (
            "a launch naming an interface with no attachment",
            Held::ByNothing,
            Asked::Launch,
            0,
            false,
            200,
        ),
    ];

    for (index, (case, held, asked, device_index, dry_run, expected_status)) in
        cases.into_iter().enumerate()
    {
        let network_interface_id = match held {
            Held::ByADetachedAttachment => seed_held(
                &engine,
                &place,
                &format!("{:016x}", 0xd0 + index),
                Some(ATTACHMENT_STATUS_DETACHED),
            ),
            Held::ByNothing => create_interface(&router, &place).await,
        };
        let (action, params) = request(
            asked,
            &network_interface_id,
            &instance_id,
            device_index,
            dry_run,
        );
        let (http_status, body) = call(&router, REGION, action, &params).await;
        assert_eq!(
            http_status, expected_status,
            "case {case:?}: expected HTTP {expected_status} from {action}, got {http_status} \
             with body {body}"
        );
        assert!(
            !body.contains("is currently in use"),
            "case {case:?}: an interface nothing holds must not be refused as in use, got \
             {body}"
        );
    }
}
