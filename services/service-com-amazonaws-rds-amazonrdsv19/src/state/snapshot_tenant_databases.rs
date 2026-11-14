// SPDX-License-Identifier: CC0-1.0

//! The tenant databases a DB SNAPSHOT captured, which is what
//! `DescribeDBSnapshotTenantDatabases` reports.
//!
//! A snapshot of a DB instance running one of the Oracle container database (CDB) engines
//! holds the pluggable databases that instance held when the snapshot was taken —
//! "`DescribeDBSnapshotTenantDatabases` ... Describes the tenant databases that exist in a
//! DB snapshot" and "If you restore a snapshot that was taken from DB instance using the
//! multi-tenant configuration, you restore all its tenant databases". So the records here
//! are COPIES taken at the instant the snapshot was ([`DbSnapshotRecord::from_instance`]),
//! exactly like every other instance setting a snapshot carries: a tenant database created,
//! renamed or deleted after the snapshot was taken does not rewrite what the snapshot holds.
//!
//! A snapshot of a single-tenant instance holds none, because such an instance holds no
//! tenant databases to copy.

use super::*;
use crate::ops::types::DBSnapshotTenantDatabase;

/// The ARN resource type of a tenant database INSIDE a snapshot, which
/// `DBSnapshotTenantDatabase$DBSnapshotTenantDatabaseARN` reports. Distinct from the
/// `tenant-database` of a live tenant database ([`TenantDatabaseRecord::arn`]): this one
/// names a database a snapshot holds, which cannot be interacted with directly.
const ARN_RESOURCE_TYPE: &str = "snapshot-tenant-database";

/// One tenant database as a DB snapshot captured it.
///
/// Only the tenant database's OWN facts are stored. Everything a
/// `DBSnapshotTenantDatabase` reports about the snapshot and the instance it was taken
/// from — the snapshot identifier, its type, the DB instance identifier, the instance's
/// `DbiResourceId` and engine — is read from the snapshot record that holds this one, so no
/// two copies of those values can disagree.
///
/// How many of these one snapshot holds is bounded by
/// [`TENANT_DATABASE_QUOTA_PER_INSTANCE`], the cap the live records of one DB instance are
/// held to: a snapshot costs no more than the instance it was taken from, and the number of
/// snapshots is bounded by the per-region snapshot quota like every other record here.
#[derive(Debug, Clone)]
pub struct SnapshotTenantDatabaseRecord {
    /// `TenantDBName`, as the tenant database carried it when the snapshot was taken.
    pub tenant_db_name: String,
    /// `TenantDatabaseResourceId`: the tenant database's own immutable resource id.
    pub resource_id: String,
    /// `MasterUsername` of the tenant database.
    pub master_username: String,
    /// `CharacterSetName`.
    pub character_set_name: Option<String>,
    /// `NcharCharacterSetName`.
    pub nchar_character_set_name: Option<String>,
    /// `TagList`: the tags the tenant database carried when the snapshot was taken.
    pub tags: Vec<Tag>,
}

impl SnapshotTenantDatabaseRecord {
    /// Capture the live tenant database `record`, as a snapshot of its DB instance does.
    pub fn from_tenant_database(record: &TenantDatabaseRecord) -> Self {
        Self {
            tenant_db_name: record.tenant_db_name.clone(),
            resource_id: record.resource_id.clone(),
            master_username: record.master_username.clone(),
            character_set_name: record.character_set_name.clone(),
            nchar_character_set_name: record.nchar_character_set_name.clone(),
            tags: record.tags.clone(),
        }
    }
}

impl DbSnapshotRecord {
    /// `DBSnapshotTenantDatabaseARN` for the tenant database `tenant` this snapshot holds.
    ///
    /// The resource is addressed by the snapshot that holds it and the tenant database's own
    /// name within it: a snapshot is immutable, so that pair cannot change, and a tenant
    /// database in a snapshot is reachable only through the snapshot ("You can't directly
    /// interact with the tenant databases in a DB snapshot").
    pub fn snapshot_tenant_database_arn(&self, tenant: &SnapshotTenantDatabaseRecord) -> String {
        emulator_server::emulator_arn(
            ARN_NAMESPACE,
            &self.region,
            &format!(
                "{ARN_RESOURCE_TYPE}:{}:{}",
                self.snapshot_identifier, tenant.tenant_db_name
            ),
        )
    }

    /// Project one captured tenant database onto the modelled `DBSnapshotTenantDatabase`
    /// shape, reading everything about the snapshot and its source instance from this
    /// record.
    ///
    /// `TenantDatabaseCreateTime` is the snapshot's own creation time: the member documents
    /// "The time the DB snapshot was taken, specified in Coordinated Universal Time (UTC).
    /// If you copy the snapshot, the creation time changes", so it follows the snapshot
    /// rather than the live tenant database the capture came from.
    pub fn tenant_database_to_wire(
        &self,
        tenant: &SnapshotTenantDatabaseRecord,
    ) -> DBSnapshotTenantDatabase {
        DBSnapshotTenantDatabase {
            db_snapshot_identifier: Some(self.snapshot_identifier.clone()),
            db_instance_identifier: Some(self.db_instance_identifier.clone()),
            dbi_resource_id: Some(self.dbi_resource_id.clone()),
            engine_name: Some(self.engine.clone()),
            snapshot_type: Some(self.snapshot_type.clone()),
            tenant_database_create_time: Some(self.snapshot_create_time),
            tenant_db_name: Some(tenant.tenant_db_name.clone()),
            master_username: Some(tenant.master_username.clone()),
            tenant_database_resource_id: Some(tenant.resource_id.clone()),
            character_set_name: tenant.character_set_name.clone(),
            nchar_character_set_name: tenant.nchar_character_set_name.clone(),
            db_snapshot_tenant_database_arn: Some(self.snapshot_tenant_database_arn(tenant)),
            tag_list: Some(tenant.tags.clone()),
        }
    }
}

impl ComAmazonawsRdsAmazonrdsv19State {
    /// The tenant databases a snapshot of the DB instance `db_instance_identifier` in
    /// `region` captures: a copy of every tenant database that instance holds at this
    /// instant, in tenant-name order.
    ///
    /// Empty for a single-tenant instance, which holds none. The one capture every operation
    /// that takes a DB snapshot uses, so no two of them differ about what a snapshot holds.
    pub fn capture_tenant_databases(
        &self,
        region: &str,
        db_instance_identifier: &str,
    ) -> Vec<SnapshotTenantDatabaseRecord> {
        self.tenant_databases_of(region, db_instance_identifier)
            .into_iter()
            .map(SnapshotTenantDatabaseRecord::from_tenant_database)
            .collect()
    }
}
