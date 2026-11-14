// SPDX-License-Identifier: CC0-1.0

//! Whether the caller holds the Lake Formation permission a Data Catalog METADATA READ
//! needs, and WHICH CELLS of a table it may read.
//!
//! A Data Catalog resource is governed by Lake Formation: a principal may read a
//! database's metadata only while it holds at least one Lake Formation permission on that
//! database — in its own name, through the `IAM_ALLOWED_PRINCIPALS` group every IAM user
//! and role belongs to, or on a resource INSIDE it, since a grant on a table makes the
//! table's parent database describable. A TABLE's metadata needs a permission on that table
//! itself — on the table, on named columns of it, on a filter over its cells, or on every
//! table of its database through a table wildcard — because a database's own permissions are
//! granted over the database resource; and the DATA behind it is readable only to a
//! principal holding `SELECT` there, then only the columns and rows that grant covers
//! ([`ReadScope`]). A data lake administrator holds every permission of its catalog
//! implicitly. A read by a principal none of those cover is refused.
//!
//! Lake Formation OWNS those grants, so they are read from Lake Formation rather than kept
//! a second time here: this module asks the Lake Formation service in this same emulator
//! over the framework's in-process callback, exactly as the catalog asks KMS about a key
//! ([`super::catalog_encryption`]). The permission state consulted is therefore the very
//! state `GrantPermissions`, `RevokePermissions` and `PutDataLakeSettings` wrote, and this
//! crate holds no copy of it that could drift. Lake Formation also renders the grants a
//! resource was CREATED carrying (a catalog's `CreateDatabaseDefaultPermissions`, a
//! database's `CreateTableDefaultPermissions`, a table creator's own), which is why they
//! are not computed here either.
//!
//! An emulator with no Lake Formation mounted beside this service, or one whose Lake
//! Formation could not answer, governs nothing that can be read: [`catalog_permissions`]
//! answers `None` there, and a reader treats that as "no decision", never as a refusal —
//! a refusal has to be grounded in what Lake Formation said.
//!
//! Nothing here writes: the question is put with reads only, and the answer is used to
//! decide whether a read is served. The call is made with NO guard on this service's own
//! store held, because Lake Formation reads the Data Catalog (the databases and tables a
//! grant names) out of that same store.

use std::collections::BTreeSet;
use std::time::SystemTime;

use ::aws_sdk_lakeformation::types::{DataLakePrincipal, Resource};
use ::service_com_amazonaws_iam_awsidentitymanagementv20100508::state as iam_store;
use ::service_com_amazonaws_sts_awssecuritytokenservicev20110615::state as sts_store;

/// The most entries one `ListPermissions` page is asked for: `MaxResults` is modelled
/// `range 1..1000`, so this is that ceiling and the fewest pages a decision has to walk.
const PERMISSIONS_PAGE_SIZE: i32 = 1000;

/// The permission a read of a table's DATA needs: "Supported permissions are SELECT"
/// is what `TableWithColumnsResource` exists to narrow, and `SELECT` is the value of the
/// modelled `Permission` enum that names it
/// (`smithy_query(query="shape",shape="Permission")`, Lake Formation's model).
const SELECT_PERMISSION: &str = "SELECT";

/// The most data cells filters one decision resolves the definition of.
///
/// A grant on a data cells filter names the filter; what it lets the holder see is the
/// filter's own definition, which is read back from Lake Formation one call per filter. A
/// principal may hold grants on many, so the number of those calls needs an end: a decision
/// resolves this many and treats the rest as granting nothing, exactly as it treats a filter
/// Lake Formation does not answer for.
const MAX_RESOLVED_CELL_FILTERS: usize = 64;

/// The most `ListPermissions` pages one decision walks for one principal.
///
/// A loop over a service-supplied continuation token needs an end of its own. Lake
/// Formation bounds the records it holds (its own `MAX_PERMISSION_GRANTS` ceiling, plus
/// one rendered default per database and per table of the catalog), so this many pages of
/// [`PERMISSIONS_PAGE_SIZE`] is far past anything a store that size can answer: the cap is
/// what makes the walk terminate, not a limit a real listing reaches. A listing still
/// going at the cap is an INCOMPLETE answer, and [`catalog_permissions`] treats it like a
/// failed call — no read is refused on it.
const MAX_PERMISSION_PAGES: usize = 64;

/// What the caller holds in ONE Data Catalog, as far as reading metadata out of it goes.
///
/// Built by [`catalog_permissions`] from what Lake Formation answered, and asked by the
/// catalog's read paths. Deliberately NOT a copy of the grants: only the questions those
/// paths put to them — which databases are describable, which tables are, and which cells
/// of a table may be read — are kept.
#[derive(Debug, Clone, Default)]
pub struct CatalogPermissions {
    /// Whether the caller is an administrator of this catalog's data lake, who holds every
    /// permission on every one of its resources implicitly.
    admin: bool,
    /// The stored (folded) names of the databases the caller holds a Lake Formation
    /// permission on, either on the database itself or on a resource inside it.
    databases: BTreeSet<String>,
    /// What the caller holds on the catalog's TABLES, one entry per grant that names a
    /// table, that table's columns, every table of a database, or a data cells filter over
    /// one.
    tables: Vec<TableGrant>,
}

/// One grant the caller holds on a table of this catalog, as the decisions below read it.
#[derive(Debug, Clone)]
struct TableGrant {
    /// The database the table is in, as the catalog stores its name.
    database: String,
    /// The table, as the catalog stores its name, or `None` for a grant on every table of
    /// the database (`TableResource$TableWildcard`, "every table under a database").
    table: Option<String>,
    /// Whether this grant lets its holder read the table's DATA: it carries `SELECT`, or
    /// the `ALL` ("Super") that is every permission on the resource.
    selects: bool,
    /// Which columns of the table it covers.
    columns: Columns,
    /// Which rows of the table it covers.
    rows: Rows,
}

/// The columns one grant covers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Columns {
    /// Every column of the table: a grant on the table itself, or a column wildcard with
    /// nothing excluded.
    Every,
    /// Every column but these: a `ColumnWildcard` carrying `ExcludedColumnNames`.
    Except(BTreeSet<String>),
    /// Exactly these: a `ColumnNames` list.
    Only(BTreeSet<String>),
}

impl Columns {
    /// Whether this scope covers the column `name`.
    ///
    /// Matched on the catalog's own fold of both names, so the casing a grant was written
    /// with cannot decide the answer.
    fn admits(&self, name: &str) -> bool {
        let folded = super::fold_name(name);
        match self {
            Self::Every => true,
            Self::Except(excluded) => !excluded.contains(&folded),
            Self::Only(named) => named.contains(&folded),
        }
    }
}

/// The rows one grant covers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rows {
    /// Every row of the table: a grant that carries no row filter, or one whose filter is
    /// the `AllRowsWildcard`.
    Every,
    /// The rows a predicate keeps (`RowFilter$FilterExpression`).
    Matching(String),
}

/// What the caller may read of ONE table: the columns its `SELECT` grants cover and the
/// rows they keep.
///
/// A principal may hold several grants on one table, so each axis is the UNION of what its
/// grants allow: a column is readable when ANY of them covers it, and a row when ANY of
/// them keeps it.
#[derive(Debug, Clone)]
pub struct ReadScope {
    /// The column scopes of the grants in force.
    columns: Vec<Columns>,
    /// Their row scopes.
    rows: Vec<Rows>,
}

impl ReadScope {
    /// Whether this scope hides nothing, so the table reads exactly as it would with no
    /// Lake Formation governing it.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.columns.contains(&Columns::Every) && self.rows.contains(&Rows::Every)
    }

    /// Whether the column `name` is readable.
    #[must_use]
    pub fn admits_column(&self, name: &str) -> bool {
        self.columns.iter().any(|columns| columns.admits(name))
    }

    /// The predicate the rows this scope keeps satisfy, as an SQL boolean expression, or
    /// `None` when every row is readable.
    ///
    /// The expression is the grant's own (`RowFilter$FilterExpression`, "a filter
    /// expression"), parenthesised so the disjunction of two of them means what each one
    /// says; the engine that reads the table is what evaluates it.
    #[must_use]
    pub fn row_predicate(&self) -> Option<String> {
        if self.rows.contains(&Rows::Every) {
            return None;
        }
        let predicates: Vec<String> = self
            .rows
            .iter()
            .filter_map(|rows| match rows {
                Rows::Every => None,
                Rows::Matching(expression) => Some(format!("({expression})")),
            })
            .collect();
        (!predicates.is_empty()).then(|| predicates.join(" OR "))
    }
}

/// `table` as a caller whose grants cover `scope` is told about it: its column list, and
/// its partition keys, narrowed to the columns that scope covers.
///
/// Lake Formation answers a metadata read of a column-scoped table with the columns the
/// reader's grant covers, so a column outside it is not reported at all — the same column
/// the reader's queries cannot address. A scope covering every column leaves the definition
/// exactly as the catalog holds it.
#[must_use]
pub fn narrowed_table(mut table: crate::ops::types::Table, scope: &ReadScope) -> crate::ops::types::Table {
    if scope.columns.contains(&Columns::Every) {
        return table;
    }
    let narrow = |columns: Vec<crate::ops::types::Column>| -> Vec<crate::ops::types::Column> {
        columns
            .into_iter()
            .filter(|column| scope.admits_column(&column.name))
            .collect()
    };
    if let Some(storage) = table.storage_descriptor.as_mut() {
        storage.columns = storage.columns.take().map(narrow);
    }
    table.partition_keys = table.partition_keys.take().map(narrow);
    table
}

impl CatalogPermissions {
    /// Whether the caller may read `name`'s metadata: it is a data lake administrator, or
    /// it holds a permission on that database or on a resource inside it.
    ///
    /// `name` is matched as the catalog STORES it ([`super::fold_name`]), so the spelling a
    /// request used cannot decide the answer.
    #[must_use]
    pub fn may_describe_database(&self, name: &str) -> bool {
        self.admin || self.databases.contains(&super::fold_name(name))
    }

    /// Whether the caller may read the metadata of the table `table` of the database
    /// `database`: it is a data lake administrator, or it holds a Lake Formation permission
    /// on that table — on the table itself, on named columns of it, on a filter over its
    /// cells, or on every table of its database through a table wildcard.
    ///
    /// A permission on the DATABASE is not one of them: Lake Formation grants a database's
    /// permissions over the database resource, and the metadata of a table inside it is
    /// answered to a principal that holds a permission on that table.
    ///
    /// Both names are matched as the catalog STORES them ([`super::fold_name`]), so the
    /// spelling a request used cannot decide the answer.
    #[must_use]
    pub fn may_describe_table(&self, database: &str, table: &str) -> bool {
        self.admin || self.grants_on(database, table).next().is_some()
    }

    /// What the caller may read of the DATA behind the table `table` of `database`, or
    /// `None` when no `SELECT` of its reaches it — in which case the table is not readable
    /// at all.
    #[must_use]
    pub fn table_read_scope(&self, database: &str, table: &str) -> Option<ReadScope> {
        self.scope_of(database, table, true)
    }

    /// What of the table `table` of `database` the caller may see the METADATA of: the
    /// columns its grants cover, whichever permission each carries — `None` when it holds no
    /// grant on the table at all.
    ///
    /// A metadata read is answered PROJECTED to those columns: Lake Formation holds a
    /// `SELECT` on named columns as a grant on THOSE columns
    /// (`TableWithColumnsResource`), so a principal whose only grant on a table is such a
    /// one is told about the columns it covers and not about the rest. A grant on the table
    /// itself covers every column, so a reader holding one sees the whole definition.
    #[must_use]
    pub fn table_metadata_scope(&self, database: &str, table: &str) -> Option<ReadScope> {
        self.scope_of(database, table, false)
    }

    /// The union of what the caller's grants on the table `table` of `database` cover, taken
    /// over every grant in force on it or, when `selecting_only`, over the ones that carry a
    /// permission to read its data.
    fn scope_of(&self, database: &str, table: &str, selecting_only: bool) -> Option<ReadScope> {
        if self.admin {
            return Some(ReadScope {
                columns: vec![Columns::Every],
                rows: vec![Rows::Every],
            });
        }
        let in_force: Vec<&TableGrant> = self
            .grants_on(database, table)
            .filter(|grant| grant.selects || !selecting_only)
            .collect();
        if in_force.is_empty() {
            return None;
        }
        Some(ReadScope {
            columns: in_force.iter().map(|grant| grant.columns.clone()).collect(),
            // A grant that is not about reading data says nothing about rows, so what it
            // contributes is every row of the table.
            rows: in_force
                .iter()
                .map(|grant| {
                    if grant.selects {
                        grant.rows.clone()
                    } else {
                        Rows::Every
                    }
                })
                .collect(),
        })
    }

    /// The grants in force on the table `table` of `database`: the ones naming that table
    /// and the ones naming every table of its database.
    fn grants_on<'held>(
        &'held self,
        database: &str,
        table: &str,
    ) -> impl Iterator<Item = &'held TableGrant> {
        let database = super::fold_name(database);
        let table = super::fold_name(table);
        self.tables.iter().filter(move |grant| {
            grant.database == database
                && grant
                    .table
                    .as_ref()
                    .is_none_or(|granted| *granted == table)
        })
    }
}

/// What the caller holds in the Data Catalog `catalog_id`, or `None` when Lake Formation
/// said nothing at all (none is mounted beside this service, or it could not answer) — in
/// which case nothing it governs has been read and no read may be refused on its behalf.
///
/// Call this with no guard on this service's store held: Lake Formation resolves the
/// databases and tables a grant names in the Data Catalog, which is that same store.
pub async fn catalog_permissions<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    region: &str,
    catalog_id: &str,
) -> Option<CatalogPermissions> {
    let client = lake_formation_client(ctx, region);

    // The catalog's data lake settings, which name its administrators. This is also what
    // says whether Lake Formation is there to answer at all: every catalog HAS settings
    // ("by default, the account ID", and a catalog nothing configured reads back the
    // defaults), so a failure here is about the service and not about the catalog.
    let settings = match client
        .get_data_lake_settings()
        .catalog_id(catalog_id)
        .send()
        .await
    {
        Ok(answer) => answer.data_lake_settings,
        Err(error) => {
            ::tracing::debug!(
                catalog = %catalog_id,
                reason = %::aws_smithy_types::error::display::DisplayErrorContext(&error),
                "Lake Formation answered nothing about this Data Catalog, so no catalog \
                 read is refused on its behalf"
            );
            return None;
        }
    };

    let principals = caller_data_lake_principals(engine, ctx);
    // "A list of Lake Formation principals" — an administrator of the data lake, and a
    // read-only administrator, hold every permission of the catalog implicitly, so a read
    // by one needs no grant of its own.
    let admin = settings.iter().any(|settings| {
        settings
            .data_lake_admins()
            .iter()
            .chain(settings.read_only_admins())
            .filter_map(DataLakePrincipal::data_lake_principal_identifier)
            .any(|admin| principals.iter().any(|held| held == admin))
    });

    let mut databases = BTreeSet::new();
    let mut tables: Vec<TableGrant> = Vec::new();
    // The data cells filters the caller's grants name, whose definitions say what each one
    // lets it see. Collected here and resolved once the listing is over, so Lake Formation's
    // own answer about a filter is read with no listing in flight.
    let mut cell_filters: Vec<CellFilterGrant> = Vec::new();
    for principal in &principals {
        let mut next_token: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let page = match client
                .list_permissions()
                .catalog_id(catalog_id)
                .principal(
                    DataLakePrincipal::builder()
                        .data_lake_principal_identifier(principal.clone())
                        .build(),
                )
                .max_results(PERMISSIONS_PAGE_SIZE)
                .set_next_token(next_token.take())
                .send()
                .await
            {
                Ok(page) => page,
                // Lake Formation stopped answering part way through: what it holds is
                // then unknown, and an unknown is not a refusal.
                Err(error) => {
                    ::tracing::debug!(
                        catalog = %catalog_id,
                        reason = %::aws_smithy_types::error::display::DisplayErrorContext(&error),
                        "Lake Formation did not answer which permissions this principal \
                         holds, so no catalog read is refused on its behalf"
                    );
                    return None;
                }
            };
            for entry in page.principal_resource_permissions() {
                // An entry carrying no permission at all grants nothing, whichever
                // resource it names.
                let holds = !entry.permissions().is_empty()
                    || !entry.permissions_with_grant_option().is_empty();
                if !holds {
                    continue;
                }
                if let Some(database) = granted_database(entry.resource(), catalog_id) {
                    databases.insert(database);
                }
                // A permission on the resource AS A WHOLE ("Super") carries every
                // permission of it, so it selects the table's data as a `SELECT` does.
                let selects = entry
                    .permissions()
                    .iter()
                    .chain(entry.permissions_with_grant_option())
                    .any(|permission| {
                        permission.as_str() == SELECT_PERMISSION
                            || permission.as_str() == super::PERMISSION_ALL
                    });
                match granted_table(entry.resource(), catalog_id) {
                    Some(GrantedTable::Table(mut grant)) => {
                        grant.selects = selects;
                        tables.push(grant);
                    }
                    Some(GrantedTable::CellFilter(mut filter)) => {
                        filter.selects = selects;
                        cell_filters.push(filter);
                    }
                    None => {}
                }
            }
            next_token = page.next_token().map(str::to_string);
            if next_token.is_none() {
                break;
            }
            pages = pages.saturating_add(1);
            if pages >= MAX_PERMISSION_PAGES {
                // The listing is still going at the cap, so this walk has NOT seen
                // everything the principal holds — the same incomplete answer a failed
                // call is, and decided the same way: nothing is refused on it.
                ::tracing::debug!(
                    catalog = %catalog_id,
                    pages,
                    "Lake Formation listed more permission pages than one catalog read \
                     walks, so no catalog read is refused on its behalf"
                );
                return None;
            }
        }
    }

    // What each data cells filter grant lets its holder see is the filter's own definition,
    // which Lake Formation holds: the columns it names and the rows its predicate keeps. A
    // filter this cannot read grants nothing — the grant names a definition that is not
    // there to read — so it is left out rather than widened into a grant on the whole table.
    for filter in cell_filters.into_iter().take(MAX_RESOLVED_CELL_FILTERS) {
        match resolved_cell_filter(&client, &filter).await {
            Some(grant) => tables.push(grant),
            None => ::tracing::debug!(
                catalog = %catalog_id,
                database = %filter.database,
                table = %filter.table,
                "Lake Formation did not answer the definition of a data cells filter the \
                 caller holds a grant on, so that grant covers nothing"
            ),
        }
    }

    Some(CatalogPermissions {
        admin,
        databases,
        tables,
    })
}

/// A grant on a data cells filter, before its definition is read back.
#[derive(Debug, Clone)]
struct CellFilterGrant {
    /// The database the filtered table is in, as the grant spelled it.
    database: String,
    /// The filtered table, as the grant spelled it.
    table: String,
    /// The filter's name, as the grant spelled it: the name
    /// `GetDataCellsFilter$Name` addresses it by.
    name: String,
    /// The catalog id the grant named for the filtered table.
    table_catalog_id: String,
    /// Whether the grant lets its holder read data; see [`TableGrant::selects`].
    selects: bool,
}

/// What a grant names: a table of this catalog, or a data cells filter over one.
#[derive(Debug, Clone)]
enum GrantedTable {
    /// A grant whose scope the resource itself states.
    Table(TableGrant),
    /// A grant whose scope is the named filter's definition.
    CellFilter(CellFilterGrant),
}

/// The table a grant on `resource` is about, and the columns and rows it covers — `None`
/// for a resource that is not a table of `catalog_id`, not a column scope of one, and not a
/// data cells filter over one.
///
/// `selects` is left for the caller to fill in: which permissions the grant carries is on
/// the entry, not on the resource it names.
fn granted_table(resource: Option<&Resource>, catalog_id: &str) -> Option<GrantedTable> {
    let resource = resource?;
    if let Some(table) = resource.table() {
        if !in_catalog(table.catalog_id(), catalog_id) {
            return None;
        }
        return Some(GrantedTable::Table(TableGrant {
            database: super::fold_name(table.database_name()),
            // "At least one of TableResource$Name or TableResource$TableWildcard is
            // required": the wildcard is a grant on every table of the database.
            table: table
                .name()
                .filter(|name| !name.is_empty())
                .map(super::fold_name),
            selects: false,
            // A grant on the table itself is a grant on all of it.
            columns: Columns::Every,
            rows: Rows::Every,
        }));
    }
    if let Some(table) = resource.table_with_columns() {
        if !in_catalog(table.catalog_id(), catalog_id) {
            return None;
        }
        return Some(GrantedTable::Table(TableGrant {
            database: super::fold_name(table.database_name()),
            table: Some(super::fold_name(table.name())),
            selects: false,
            columns: column_scope(table.column_names(), table.column_wildcard()),
            rows: Rows::Every,
        }));
    }
    if let Some(filter) = resource.data_cells_filter() {
        if !in_catalog(filter.table_catalog_id(), catalog_id) {
            return None;
        }
        // Every member of the resource names part of the filter's identity, so a grant
        // naming only some of them addresses no filter whose definition could be read. The
        // names travel on AS THE GRANT WROTE THEM, because that is the filter Lake Formation
        // holds them under; the fold is applied to what the decision is matched by.
        return Some(GrantedTable::CellFilter(CellFilterGrant {
            database: filter.database_name()?.to_string(),
            table: filter.table_name()?.to_string(),
            name: filter.name()?.to_string(),
            table_catalog_id: filter
                .table_catalog_id()
                .filter(|id| !id.is_empty())
                .unwrap_or(catalog_id)
                .to_string(),
            selects: false,
        }));
    }
    None
}

/// The columns a `ColumnNames` list and a `ColumnWildcard` name, as the scope they are.
///
/// "At least one of ColumnNames or ColumnWildcard is required"
/// (`TableWithColumnsResource$ColumnNames`): a named list is exactly those columns, a
/// wildcard is every column but the ones it excludes, and a resource carrying neither
/// narrows nothing.
fn column_scope(
    column_names: &[String],
    wildcard: Option<&::aws_sdk_lakeformation::types::ColumnWildcard>,
) -> Columns {
    if !column_names.is_empty() {
        return Columns::Only(column_names.iter().map(|name| super::fold_name(name)).collect());
    }
    match wildcard {
        Some(wildcard) if !wildcard.excluded_column_names().is_empty() => Columns::Except(
            wildcard
                .excluded_column_names()
                .iter()
                .map(|name| super::fold_name(name))
                .collect(),
        ),
        _ => Columns::Every,
    }
}

/// The grant a data cells filter confers, read from the filter's own definition in Lake
/// Formation — `None` when Lake Formation holds no such filter or did not answer.
async fn resolved_cell_filter(
    client: &::aws_sdk_lakeformation::Client,
    grant: &CellFilterGrant,
) -> Option<TableGrant> {
    let answer = client
        .get_data_cells_filter()
        .table_catalog_id(grant.table_catalog_id.clone())
        .database_name(grant.database.clone())
        .table_name(grant.table.clone())
        .name(grant.name.clone())
        .send()
        .await
        .ok()?;
    let filter = answer.data_cells_filter?;
    // "A PartiQL predicate": the rows the filter keeps, unless it carries the wildcard for
    // all rows instead.
    let rows = match filter.row_filter() {
        Some(row_filter) if row_filter.all_rows_wildcard().is_some() => Rows::Every,
        Some(row_filter) => match row_filter
            .filter_expression()
            .map(str::trim)
            .filter(|expression| !expression.is_empty())
        {
            Some(expression) => Rows::Matching(expression.to_string()),
            None => Rows::Every,
        },
        None => Rows::Every,
    };
    Some(TableGrant {
        database: super::fold_name(&grant.database),
        table: Some(super::fold_name(&grant.table)),
        selects: grant.selects,
        columns: column_scope(filter.column_names(), filter.column_wildcard()),
        rows,
    })
}

/// The database a grant on `resource` makes describable, as the catalog stores its name:
/// the database itself, or the parent of the table, the column-scoped table or the data
/// cells filter the grant names — a permission on a resource inside a database is what
/// makes that database visible to its holder.
///
/// `None` for a resource that is not in `catalog_id` (a grant in this catalog may name a
/// database of another one) and for every resource that is not a database or a thing
/// inside one: a catalog-level, data-location, LF-tag or tag-policy grant names no one
/// database.
fn granted_database(resource: Option<&Resource>, catalog_id: &str) -> Option<String> {
    let resource = resource?;
    if let Some(database) = resource.database() {
        return in_catalog(database.catalog_id(), catalog_id)
            .then(|| super::fold_name(database.name()));
    }
    if let Some(table) = resource.table() {
        return in_catalog(table.catalog_id(), catalog_id)
            .then(|| super::fold_name(table.database_name()));
    }
    if let Some(table) = resource.table_with_columns() {
        return in_catalog(table.catalog_id(), catalog_id)
            .then(|| super::fold_name(table.database_name()));
    }
    if let Some(filter) = resource.data_cells_filter() {
        let database = filter.database_name()?;
        return in_catalog(filter.table_catalog_id(), catalog_id)
            .then(|| super::fold_name(database));
    }
    None
}

/// Whether a resource member that names `named` sits in `catalog_id`: the catalog it names,
/// else the one the request addressed ("The identifier for the Data Catalog. By default,
/// the account ID.").
fn in_catalog(named: Option<&str>, catalog_id: &str) -> bool {
    named.filter(|id| !id.is_empty()).unwrap_or(catalog_id) == catalog_id
}

/// Every Lake Formation principal whose grants this request's caller holds: the identity
/// its credential speaks for, the IAM role behind an assumed-role session, and the
/// `IAM_ALLOWED_PRINCIPALS` group when one of those is an IAM user or role.
///
/// WHO the caller is comes from STS's own resolution of the access key id the request
/// signed with — the same record `sts:GetCallerIdentity` answers from — and the role behind
/// a session is the ARN the account's IAM holds that role under, which is the form a Lake
/// Formation grant names a role by. A credential that has expired speaks for nobody and so
/// holds nothing.
fn caller_data_lake_principals<Eng: Send + Sync + 'static>(
    engine: &Eng,
    ctx: &::smithy_server_runtime::OperationContext<'_>,
) -> Vec<String> {
    let access_key_id = ::engine::extract_akid(&ctx.parts().headers);
    let iam = iam_store::service_state(engine);
    // A LONG-TERM access key speaks for the IAM user that holds it; a key IAM holds no
    // record of is this emulator's own published credential.
    let long_term = {
        let held = iam.as_ref().map(|state| state.lock());
        sts_store::long_term_identity(held.as_deref(), &access_key_id)
    };
    // The identity the credential speaks for, and the role of an assumed-role session.
    let resolved = match sts_store::service_state(engine) {
        Some(sts) => sts_store::resolve_request_caller(
            &mut sts.lock(),
            &access_key_id,
            SystemTime::now(),
            ctx.credential_store(),
            long_term.clone(),
        )
        .map(|caller| (caller.identity.arn, caller.role_arn)),
        // No STS store on this engine: the only identity a request can present is the
        // long-term one resolved above.
        None => Ok((long_term.arn.clone(), None)),
    };
    let Ok((identity_arn, session_role_arn)) = resolved else {
        // The session credential has expired, so it speaks for nobody and holds nothing.
        return Vec::new();
    };

    let mut principals = vec![identity_arn.clone()];
    // The permissions in force on an assumed-role session are the ROLE's, and a grant
    // names the role by the ARN the account holds it under — which carries its PATH,
    // where the session ARN does not.
    if let Some(role_arn) = session_role_arn {
        push_once(&mut principals, role_arn);
    }
    let session_role =
        ::service_common::iam_role::assumed_role_session_role_name(&identity_arn);
    if let Some(role_name) = session_role {
        if let Some(held) = iam.as_ref().and_then(|state| {
            state
                .lock()
                .roles
                .get(&iam_store::name_key(role_name))
                .map(|role| role.arn.clone())
        }) {
            push_once(&mut principals, held);
        }
    }
    // "IAM_ALLOWED_PRINCIPALS" stands for every principal IAM itself allows, so an IAM
    // user or role holds what that group holds.
    if principals.iter().any(|principal| is_iam_principal(principal)) {
        push_once(&mut principals, super::IAM_ALLOWED_PRINCIPALS.to_string());
    }
    principals
}

/// Append `value` unless `values` already carries it, so one identity asked about twice is
/// one listing.
fn push_once(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// Whether `identifier` names an IAM principal, i.e. an IAM user or an IAM role of this
/// account — the two entities Lake Formation documents as supported principals ("Supported
/// principals are IAM users or IAM roles"), and so the two the
/// `IAM_ALLOWED_PRINCIPALS` group covers.
///
/// The ARN reading itself is the tree's shared one ([`::service_common::iam_role`]), so
/// what counts as a role or a user ARN here is what every other service reads.
fn is_iam_principal(identifier: &str) -> bool {
    ::service_common::iam_role::role_name(identifier).is_some()
        || ::service_common::iam_role::user_name(identifier).is_some()
}

/// A Lake Formation client over the in-process callback into this same emulator.
///
/// The callback is the framework's documented seam for calling another emulated service: it
/// routes in process, so no network client is configured here and no socket is opened.
/// `region` is the request's own signing region, so the permissions consulted are the ones
/// of the Region whose catalog is being read.
///
/// The transport is in-process, so there is nothing to retry, time out or watch for a
/// stalled stream, and the credentials the callback hands over are used directly.
fn lake_formation_client(
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    region: &str,
) -> ::aws_sdk_lakeformation::Client {
    let config = ::aws_sdk_lakeformation::Config::builder()
        .behavior_version(::aws_sdk_lakeformation::config::BehaviorVersion::latest())
        .region(::aws_sdk_lakeformation::config::Region::new(region.to_string()))
        .endpoint_url(format!("https://lakeformation.{region}.amazonaws.com"))
        .credentials_provider(ctx.callback().aws_credentials_provider())
        .http_client(ctx.callback().http_client())
        .retry_config(::aws_sdk_lakeformation::config::retry::RetryConfig::disabled())
        .timeout_config(::aws_sdk_lakeformation::config::timeout::TimeoutConfig::disabled())
        .identity_cache(::aws_sdk_lakeformation::config::IdentityCache::no_cache())
        .stalled_stream_protection(
            ::aws_sdk_lakeformation::config::StalledStreamProtectionConfig::disabled(),
        )
        .build();
    ::aws_sdk_lakeformation::Client::from_conf(config)
}
