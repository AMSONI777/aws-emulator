// SPDX-License-Identifier: CC0-1.0

//! Whether Lake Formation lets the caller READ a Data Catalog table through a query, and
//! WHICH cells of it.
//!
//! Athena reads tables of the AWS Glue Data Catalog, and those tables are Lake Formation
//! resources: a principal reads one only while Lake Formation resolves a `SELECT`
//! permission for it there — in its own name, through the `IAM_ALLOWED_PRINCIPALS` group,
//! or as an administrator of the data lake — and then only the columns and the rows that
//! grant covers. A table no `SELECT` of the caller's reaches is not refused with an
//! authorization error: it is NOT THERE for that caller, which is the same answer a table
//! the catalog does not hold gets ([`super::catalog_sql::Failure::table_not_found`]).
//!
//! WHAT the caller holds is not decided here. Lake Formation owns those grants and the
//! Data Catalog owns the resources they name, so the decision is the Data Catalog's own
//! ([`::service_com_amazonaws_glue_awsglue::state::lake_formation`]) — the single place in
//! this tree that asks Lake Formation which permissions a request's caller holds in a
//! catalog, which is also what Glue's own metadata reads are answered from. This module is
//! only the Athena end of it: which catalogs one statement needs the answer for, and what
//! the answer means to a relation the statement reads.
//!
//! It is ASYNC and belongs in the handler, before the statement is planned: the question
//! is put to Lake Formation over the framework's in-process callback, while the resolution
//! that consults the answer runs on a blocking thread with no context to call anything
//! from. So one submission asks once, per Data Catalog it addresses, and carries the answer
//! into the run.
//!
//! An emulator with no Lake Formation mounted beside this service, or one whose Lake
//! Formation could not answer, governs nothing: [`DataLakeAccess`] then holds no entry for
//! that catalog and every relation in it reads unnarrowed. A refusal has to be grounded in
//! what Lake Formation said.

use std::collections::BTreeMap;

use ::service_com_amazonaws_glue_awsglue::state::lake_formation as catalog_governance;

pub use catalog_governance::ReadScope;

/// What the caller may read in each Data Catalog one statement addresses.
///
/// Keyed by `CatalogId` — the identifier Lake Formation holds its grants under — because
/// that is what a relation's catalog NAME resolves to, and two names may resolve to one
/// catalog.
#[derive(Debug, Clone, Default)]
pub struct DataLakeAccess {
    /// Catalog id -> what Lake Formation said the caller holds there. A catalog with no
    /// entry is one Lake Formation said nothing about.
    held: BTreeMap<String, catalog_governance::CatalogPermissions>,
}

/// What a reader may do with one table of the catalog.
#[derive(Debug, Clone)]
pub enum TableAccess {
    /// Lake Formation said nothing about this table's catalog, so nothing narrows the read.
    Ungoverned,
    /// The table is readable, within this scope.
    Readable(ReadScope),
    /// No `SELECT` of the caller's reaches the table, so the table is not there for it.
    Hidden,
}

impl DataLakeAccess {
    /// What the caller may read of the table `table` of `database` in the Data Catalog
    /// `catalog_id`.
    #[must_use]
    pub fn table_access(&self, catalog_id: &str, database: &str, table: &str) -> TableAccess {
        let Some(held) = self.held.get(catalog_id) else {
            return TableAccess::Ungoverned;
        };
        match held.table_read_scope(database, table) {
            Some(scope) => TableAccess::Readable(scope),
            None => TableAccess::Hidden,
        }
    }
}

/// What the caller holds in each Data Catalog `catalogs` names, asked of Lake Formation
/// once per catalog the statement addresses.
///
/// `catalogs` are catalog NAMES as a statement writes them (`AwsDataCatalog`, or a data
/// catalog this account registered); each is resolved to the `CatalogId` whose metadata it
/// serves the same way the statement's own resolution resolves it
/// ([`super::catalog_sql::catalog_id`]), and a name that resolves to no catalog of this
/// emulator is left out — nothing is known about such a catalog, so nothing in it is
/// refused.
///
/// Call this with no guard on any store held: the decision reads both this service's
/// registry and, through Lake Formation, the Data Catalog's own store.
pub async fn resolved<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    catalogs: impl IntoIterator<Item = String>,
) -> DataLakeAccess {
    let region = crate::state::authorization::region_from_request(ctx.parts());
    let mut held = BTreeMap::new();
    for catalog in catalogs {
        let Some(catalog_id) = super::catalog_sql::catalog_id(engine, &catalog) else {
            continue;
        };
        if held.contains_key(&catalog_id) {
            continue;
        }
        if let Some(permissions) =
            catalog_governance::catalog_permissions(engine, ctx, &region, &catalog_id).await
        {
            held.insert(catalog_id, permissions);
        }
    }
    DataLakeAccess { held }
}
