// SPDX-License-Identifier: CC0-1.0

//! What every Lightsail record — a resource and the operation-log entry a
//! mutating call appends for it — reports in `location` and in
//! `operationDetails`, driven over the wire.
//!
//! Every case here goes through the same front door a client uses: `POST /` with
//! `X-Amz-Target: Lightsail_20161128.<Operation>` and an `awsJson1_1` body,
//! dispatched by the multi-service router, so the modelled-constraint walk, the
//! handlers and the awsJson error envelope are all exercised rather than
//! bypassed.
//!
//! The rules under test:
//!
//! * `ResourceLocation` reports an `availabilityZone` for every record, zonal or
//!   not: the one zone a zonal resource was created in, and `all` — every zone
//!   of the Region — where no single zone holds the resource. A caller reads the
//!   two members together as "the Amazon Web Services Region and Availability
//!   Zone" of the resource, so an absent zone would read as "no zone is known"
//!   rather than "the whole Region".
//! * `Operation$operationDetails` is "details about the operation", a member
//!   BESIDE the `resourceName` the entry already carries, so it never repeats
//!   that name: the entry of a call that took the resource it names AWAY reports
//!   an empty detail, because the record it would describe is the one the call
//!   removed, and every other entry reports none.
//!
//! The rows below span the class the rules generalise over: the KIND of resource
//! (whether one zone holds it or the Region as a whole does, and so which
//! `availabilityZone` its records name), and — for the detail — a call that
//! removes the resource its entry names, a call that creates one, and a
//! `Delete…` call whose named resource OUTLIVES it, so the detail follows what
//! the call did rather than what it is called.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::instance_lifecycle::{is_uuid_shaped, Emulator};
use crate::operations_for_resource::answered_entries;

/// The Region every row but the DNS zone is served in.
const REGION: &str = "us-west-2";

/// One Availability Zone of [`REGION`]: the zone the zonal rows create their
/// resource in, and therefore the one their records name.
const ZONE: &str = "us-west-2a";

/// The Region a certificate is reported in: Lightsail validates one for the
/// distributions it can be attached to, which live in `us-east-1` alone, so the
/// record is located there whatever Region the request was made in
/// (`crate::state::DISTRIBUTION_REGION_NAME`).
const CERTIFICATE_REGION: &str = "us-east-1";

/// The domain a certificate in this suite is requested for: it selects nothing
/// about a location or an operation detail.
const CERTIFICATE_DOMAIN: &str = "ops-detail.example";

/// The `availabilityZone` a record reports when no single zone holds the
/// resource: every zone of its Region
/// (`crate::state::AVAILABILITY_ZONE_ALL`).
const EVERY_ZONE: &str = "all";

/// A Linux/Unix blueprint and the smallest plan: neither selects anything about
/// a location or an operation detail.
const BLUEPRINT: &str = "amazon_linux_2023";
/// See [`BLUEPRINT`].
const BUNDLE: &str = "nano_3_0";

/// The smallest bucket plan: it selects nothing about a location or a detail.
const BUCKET_BUNDLE: &str = "small_1_0";

/// The smallest disk the service accepts (`crate::state::MIN_DISK_SIZE_IN_GB`).
const DISK_SIZE_IN_GB: i64 = 8;

/// What a row stands up, and the second call it then makes against it.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// An SSH key pair, held by the Region as a whole: `CreateKeyPair` then
    /// `DeleteKeyPair`, which removes it.
    KeyPair,
    /// A reserved public address, held by the Region: `AllocateStaticIp` then
    /// `ReleaseStaticIp`, which removes it.
    StaticIp,
    /// An object store bucket, held by the Region: `CreateBucket` then
    /// `DeleteBucket`, which removes it.
    Bucket,
    /// A certificate, held by the Region distributions live in:
    /// `CreateCertificate` then `DeleteCertificate`, which removes it.
    Certificate,
    /// A block storage disk, held by ONE zone: `CreateDisk` then `DeleteDisk`,
    /// which removes it.
    Disk,
    /// An instance, held by ONE zone, whose recorded host keys are forgotten:
    /// `CreateInstances` then `DeleteKnownHostKeys` — a `Delete…` call whose
    /// entry names the instance, which is still held afterwards.
    InstanceHostKeys,
}

impl Kind {
    /// The Region the row's calls are made in.
    fn region(self) -> &'static str {
        match self {
            // The certificate API is served in the Region every distribution a
            // certificate can be attached to lives in, and nowhere else.
            Self::Certificate => CERTIFICATE_REGION,
            _ => REGION,
        }
    }

    /// The `regionName` every record of the row reports.
    fn reported_region(self) -> &'static str {
        match self {
            Self::Certificate => CERTIFICATE_REGION,
            _ => REGION,
        }
    }

    /// The `availabilityZone` every record of the row reports: the zone a zonal
    /// resource was created in, and [`EVERY_ZONE`] for one no single zone holds.
    fn reported_zone(self) -> &'static str {
        match self {
            Self::Disk | Self::InstanceHostKeys => ZONE,
            _ => EVERY_ZONE,
        }
    }

    /// The modelled `ResourceType` every log entry of the row reports.
    fn resource_type(self) -> &'static str {
        match self {
            Self::KeyPair => "KeyPair",
            Self::StaticIp => "StaticIp",
            Self::Bucket => "Bucket",
            Self::Certificate => "Certificate",
            Self::Disk => "Disk",
            Self::InstanceHostKeys => "Instance",
        }
    }

    /// The `operationType` of the entry the row's FIRST call appends.
    fn create_type(self) -> &'static str {
        match self {
            Self::KeyPair => "CreateKeyPair",
            Self::StaticIp => "AllocateStaticIp",
            Self::Bucket => "CreateBucket",
            Self::Certificate => "CreateCertificate",
            Self::Disk => "CreateDisk",
            Self::InstanceHostKeys => "CreateInstance",
        }
    }

    /// The `operationType` of the entry the row's SECOND call appends.
    fn second_type(self) -> &'static str {
        match self {
            Self::KeyPair => "DeleteKeyPair",
            Self::StaticIp => "ReleaseStaticIp",
            Self::Bucket => "DeleteBucket",
            Self::Certificate => "DeleteCertificate",
            Self::Disk => "DeleteDisk",
            Self::InstanceHostKeys => "DeleteKnownHostKeys",
        }
    }

    /// Whether the row's second call takes the resource its entry NAMES away.
    fn second_removes_the_resource(self) -> bool {
        !matches!(self, Self::InstanceHostKeys)
    }

    /// The row's first call, as the operation name and the body it is sent.
    fn create_call(self, name: &str) -> (&'static str, Value) {
        match self {
            Self::KeyPair => ("CreateKeyPair", json!({"keyPairName": name})),
            Self::StaticIp => ("AllocateStaticIp", json!({"staticIpName": name})),
            Self::Bucket => (
                "CreateBucket",
                json!({"bucketName": name, "bundleId": BUCKET_BUNDLE}),
            ),
            Self::Certificate => (
                "CreateCertificate",
                json!({"certificateName": name, "domainName": CERTIFICATE_DOMAIN}),
            ),
            Self::Disk => (
                "CreateDisk",
                json!({
                    "diskName": name,
                    "availabilityZone": ZONE,
                    "sizeInGb": DISK_SIZE_IN_GB,
                }),
            ),
            Self::InstanceHostKeys => (
                "CreateInstances",
                json!({
                    "instanceNames": [name],
                    "availabilityZone": ZONE,
                    "blueprintId": BLUEPRINT,
                    "bundleId": BUNDLE,
                }),
            ),
        }
    }

    /// The row's second call, as the operation name and the body it is sent.
    fn second_call(self, name: &str) -> (&'static str, Value) {
        match self {
            Self::KeyPair => ("DeleteKeyPair", json!({"keyPairName": name})),
            Self::StaticIp => ("ReleaseStaticIp", json!({"staticIpName": name})),
            Self::Bucket => ("DeleteBucket", json!({"bucketName": name})),
            Self::Certificate => ("DeleteCertificate", json!({"certificateName": name})),
            Self::Disk => ("DeleteDisk", json!({"diskName": name})),
            Self::InstanceHostKeys => ("DeleteKnownHostKeys", json!({"instanceName": name})),
        }
    }

    /// The read that reports the resource itself, as the operation name, the
    /// body and the member the record is reported in — `None` for a resource
    /// whose own read this suite does not need, because its log entries carry
    /// the same location.
    fn read_call(self, name: &str) -> Option<(&'static str, Value, &'static str)> {
        match self {
            Self::KeyPair => Some(("GetKeyPair", json!({"keyPairName": name}), "keyPair")),
            Self::StaticIp => Some(("GetStaticIp", json!({"staticIpName": name}), "staticIp")),
            Self::Certificate => None,
            Self::Disk => Some(("GetDisk", json!({"diskName": name}), "disk")),
            Self::InstanceHostKeys => {
                Some(("GetInstance", json!({"instanceName": name}), "instance"))
            }
            // A bucket and a certificate are each reported by a LISTING, which
            // answers an array rather than one member.
            Self::Bucket => None,
        }
    }
}

/// One case: the kind of resource, and the name every record of it carries.
struct Row {
    case: &'static str,
    kind: Kind,
    name: &'static str,
}

const ROWS: &[Row] = &[
    Row {
        case: "an SSH key pair the Region holds",
        kind: Kind::KeyPair,
        name: "ops-detail-key-pair",
    },
    Row {
        case: "a static IP the Region reserves",
        kind: Kind::StaticIp,
        name: "ops_detail-static-ip",
    },
    Row {
        case: "a bucket the Region holds",
        kind: Kind::Bucket,
        name: "ops-detail-bucket",
    },
    Row {
        case: "a certificate the distribution Region holds",
        kind: Kind::Certificate,
        name: "ops-detail-certificate",
    },
    Row {
        case: "a block storage disk one zone holds",
        kind: Kind::Disk,
        name: "ops-detail-disk",
    },
    Row {
        case: "an instance one zone holds, whose known host keys are forgotten",
        kind: Kind::InstanceHostKeys,
        name: "ops_detail_instance",
    },
];

/// Stand `row`'s resource up and answer the log entries its create appended,
/// read back from the store through `GetOperationsForResource`.
async fn create(emulator: &Emulator, row: &Row) -> Vec<Value> {
    let (operation, body) = row.kind.create_call(row.name);
    emulator
        .ok_at(None, Some(row.kind.region()), operation, body)
        .await;
    // A disk is `creating` when its create returns, and a delete of a disk that
    // is not yet `available` is refused — so the row waits for the CONDITION the
    // second call needs, which the clock owes without anyone asking twice.
    if matches!(row.kind, Kind::Disk) {
        wait_for_disk_state(emulator, row, "available").await;
    }
    logged_entries(emulator, row).await
}

/// Poll the disk of `row` until it reports `want`.
async fn wait_for_disk_state(emulator: &Emulator, row: &Row, want: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let disk = emulator
            .ok_at(
                None,
                Some(row.kind.region()),
                "GetDisk",
                json!({"diskName": row.name}),
            )
            .await["disk"]
            .clone();
        if disk["state"].as_str() == Some(want) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "case {}: expected the disk to reach '{want}', got {:?}",
            row.case,
            disk["state"]
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Every log entry the store holds against `row`'s resource name, oldest first,
/// as `GetOperationsForResource` reports it.
async fn logged_entries(emulator: &Emulator, row: &Row) -> Vec<Value> {
    let body = emulator
        .ok_at(
            None,
            Some(row.kind.region()),
            "GetOperationsForResource",
            json!({"resourceName": row.name}),
        )
        .await;
    body["operations"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "case {}: GetOperationsForResource must report an operations list, got {body:?}",
                row.case
            )
        })
        .clone()
}

/// The one entry of `entries` whose `operationType` is `operation_type`.
fn entry_of_type(case: &str, entries: &[Value], operation_type: &str) -> Value {
    let found: Vec<&Value> = entries
        .iter()
        .filter(|entry| entry["operationType"].as_str() == Some(operation_type))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "case {case}: expected exactly one {operation_type} entry, got {entries:?}"
    );
    found[0].clone()
}

/// Assert the `location` of `record` is the one `row`'s resource lives at.
fn assert_location(case: &str, row: &Row, what: &str, record: &Value) {
    assert_eq!(
        record["location"]["regionName"].as_str(),
        Some(row.kind.reported_region()),
        "case {case}: expected {what} located in {}, got {:?}",
        row.kind.reported_region(),
        record["location"]
    );
    assert_eq!(
        record["location"]["availabilityZone"].as_str(),
        Some(row.kind.reported_zone()),
        "case {case}: expected {what} to name availability zone {:?}, got {:?}",
        row.kind.reported_zone(),
        record["location"]
    );
}

/// Assert `entry` reports the detail a log entry of `operation_type` reports:
/// empty where that call took the resource the entry names away, and none
/// otherwise — and in neither case the resource's own name.
fn assert_detail(case: &str, entry: &Value, removal: bool) {
    let detail = entry["operationDetails"].as_str();
    let expected = if removal { Some("") } else { None };
    assert_eq!(
        detail, expected,
        "case {case}: expected operationDetails {expected:?} on this entry, got {detail:?} \
         ({entry:?})"
    );
    assert_ne!(
        detail,
        entry["resourceName"].as_str(),
        "case {case}: operationDetails must not repeat the entry's own resourceName, got \
         {entry:?}"
    );
}

// ---------------------------------------------------------------------------
// The location table
// ---------------------------------------------------------------------------

/// RULE: every record reports an `availabilityZone` — the one zone a zonal
/// resource was created in, and `all` (every zone of the Region) where no single
/// zone holds the resource — on the resource itself and on every operation-log
/// entry recorded against it.
#[tokio::test]
async fn every_record_names_the_zones_its_resource_lives_in() {
    for row in ROWS {
        let emulator = Emulator::new();
        let case = row.case;
        let entries = create(&emulator, row).await;
        let created = entry_of_type(case, &entries, row.kind.create_type());
        assert_location(case, row, "the create's log entry", &created);
        assert_eq!(
            created["resourceType"].as_str(),
            Some(row.kind.resource_type()),
            "case {case}: expected the {} resource type, got {created:?}",
            row.kind.resource_type()
        );
        let id = created["id"].as_str().unwrap_or_default();
        assert!(
            is_uuid_shaped(id),
            "case {case}: expected a uuid-shaped operation id, got {id:?}"
        );

        // The resource's own read reports the same location as the entry
        // recorded against it: one record, one location.
        if let Some((operation, body, member)) = row.kind.read_call(row.name) {
            let read = emulator
                .ok_at(None, Some(row.kind.region()), operation, body)
                .await[member]
                .clone();
            assert_location(case, row, "the resource's own read", &read);
        }

        // And so does the entry the second call appends, whether or not that
        // call removed the resource.
        let (operation, body) = row.kind.second_call(row.name);
        let answered = emulator
            .ok_at(None, Some(row.kind.region()), operation, body)
            .await;
        for entry in answered_entries(case, &answered) {
            if entry["operationType"].as_str() == Some(row.kind.second_type()) {
                assert_location(case, row, "the second call's log entry", &entry);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The detail table
// ---------------------------------------------------------------------------

/// RULE: a log entry's `operationDetails` is never its own `resourceName`: the
/// entry of a call that took the resource it names away reports an empty detail,
/// and every other entry — including the one of a `Delete…` call whose named
/// resource outlives it — reports none.
#[tokio::test]
async fn only_a_removals_entry_reports_an_empty_detail_and_none_repeats_its_resource_name() {
    for row in ROWS {
        let emulator = Emulator::new();
        let case = row.case;
        let entries = create(&emulator, row).await;
        for entry in &entries {
            assert_detail(case, entry, false);
        }

        let (operation, body) = row.kind.second_call(row.name);
        let answered = emulator
            .ok_at(None, Some(row.kind.region()), operation, body)
            .await;
        let answered = answered_entries(case, &answered);
        let second = entry_of_type(case, &answered, row.kind.second_type());
        assert_detail(case, &second, row.kind.second_removes_the_resource());

        // The log HOLDS what the call answered: the same entry, read back by the
        // resource name it was recorded against, reports the same detail.
        let logged = logged_entries(&emulator, row).await;
        let read_back = entry_of_type(case, &logged, row.kind.second_type());
        assert_eq!(
            read_back["operationDetails"],
            second["operationDetails"],
            "case {case}: expected the log to hold the detail the call reported, got \
             {read_back:?}"
        );
        assert_eq!(
            read_back["id"], second["id"],
            "case {case}: expected the log to hold the entry the call reported, got \
             {read_back:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The key-pair lifecycle
// ---------------------------------------------------------------------------

/// The Regions a key pair is created and deleted in below: the lifecycle is the
/// same wherever the calls are made, and each Region is what its records report.
const KEY_PAIR_REGIONS: &[(&str, &str)] = &[
    ("a key pair created in us-west-2", "us-west-2"),
    ("a key pair created in eu-central-1", "eu-central-1"),
    ("a key pair created in ap-southeast-2", "ap-southeast-2"),
];

/// RULE: a key pair's whole lifecycle is reported by the log of that resource —
/// the create appends a terminal `CreateKeyPair` entry
/// `GetOperationsForResource` reports for the key pair's name, and the delete is
/// served with HTTP 200 and the `DeleteKeyPair` entry it appends beside it, so
/// the log still reports both once the public key is gone.
#[tokio::test]
async fn a_key_pairs_create_and_delete_are_both_reported_by_its_own_log() {
    for (index, (case, region)) in KEY_PAIR_REGIONS.iter().enumerate() {
        let emulator = Emulator::new();
        let name = format!("lifecycle-key-pair-{index}");
        emulator
            .ok_at(
                None,
                Some(region),
                "CreateKeyPair",
                json!({"keyPairName": name}),
            )
            .await;

        let logged = emulator
            .ok_at(
                None,
                Some(region),
                "GetOperationsForResource",
                json!({"resourceName": name}),
            )
            .await;
        let entries = logged["operations"]
            .as_array()
            .unwrap_or_else(|| panic!("case {case}: expected an operations list, got {logged:?}"))
            .clone();
        assert_eq!(
            entries.len(),
            1,
            "case {case}: expected the one entry the create appended, got {entries:?}"
        );
        let created = &entries[0];
        assert_eq!(
            (
                created["operationType"].as_str(),
                created["resourceType"].as_str(),
                created["resourceName"].as_str(),
                created["status"].as_str(),
                created["isTerminal"].as_bool(),
                created["location"]["regionName"].as_str(),
                created["location"]["availabilityZone"].as_str(),
                created["operationDetails"].as_str(),
            ),
            (
                Some("CreateKeyPair"),
                Some("KeyPair"),
                Some(name.as_str()),
                Some("Succeeded"),
                Some(true),
                Some(*region),
                Some(EVERY_ZONE),
                None,
            ),
            "case {case}: expected the terminal CreateKeyPair entry of {name}, got {created:?}"
        );
        assert!(
            created["createdAt"].as_f64().unwrap_or_default() > 0.0,
            "case {case}: expected a creation instant on the entry, got {created:?}"
        );

        let (status, body) = emulator
            .call_in(Some(region), "DeleteKeyPair", json!({"keyPairName": name}))
            .await;
        assert_eq!(
            status, 200,
            "case {case}: deleting the key pair the account holds must be served, got \
             {status} {body:?}"
        );
        let deleted = &body["operation"];
        assert_eq!(
            (
                deleted["operationType"].as_str(),
                deleted["resourceType"].as_str(),
                deleted["resourceName"].as_str(),
                deleted["status"].as_str(),
                deleted["isTerminal"].as_bool(),
                deleted["location"]["regionName"].as_str(),
                deleted["location"]["availabilityZone"].as_str(),
                deleted["operationDetails"].as_str(),
            ),
            (
                Some("DeleteKeyPair"),
                Some("KeyPair"),
                Some(name.as_str()),
                Some("Succeeded"),
                Some(true),
                Some(*region),
                Some(EVERY_ZONE),
                Some(""),
            ),
            "case {case}: expected the terminal DeleteKeyPair entry of {name}, got {body:?}"
        );

        // The log is append-only: both entries are still reported for a name the
        // account no longer holds a key pair under, oldest first.
        let logged = emulator
            .ok_at(
                None,
                Some(region),
                "GetOperationsForResource",
                json!({"resourceName": name}),
            )
            .await;
        let entries = logged["operations"]
            .as_array()
            .unwrap_or_else(|| panic!("case {case}: expected an operations list, got {logged:?}"))
            .clone();
        let types: Vec<Option<&str>> = entries
            .iter()
            .map(|entry| entry["operationType"].as_str())
            .collect();
        assert_eq!(
            types,
            vec![Some("CreateKeyPair"), Some("DeleteKeyPair")],
            "case {case}: expected both entries of {name} oldest first, got {entries:?}"
        );
        assert_eq!(
            entries[1]["id"].as_str(),
            deleted["id"].as_str(),
            "case {case}: expected the log to hold the entry the delete reported, got \
             {entries:?}"
        );
        let (status, body) = emulator
            .call_in(Some(region), "GetKeyPair", json!({"keyPairName": name}))
            .await;
        assert_eq!(
            status, 400,
            "case {case}: the public key is gone, so reading it back must be refused, got \
             {status} {body:?}"
        );
    }
}
