// SPDX-License-Identifier: CC0-1.0

//! The AWS-managed dashboard catalog every account already holds.
//!
//! These dashboards are the SERVICE's own published data rather than the account's: an
//! account that has created nothing still enumerates them, every account enumerates the
//! same ones, and each is reachable by the ARN the catalog publishes for it. So the
//! catalog is a fixed table here, seeded into the one dashboard store
//! ([`super::ComAmazonawsBcmdashboardsAwsbcmdashboardsserviceState::default`]) and read
//! back through the same map, the same projection and the same pagination as a dashboard a
//! caller created — no handler branches on whether a dashboard is managed, and nothing
//! about the catalog is derived from a request.
//!
//! # Where the table comes from
//!
//! The model says nothing about the catalog's CONTENTS: `DashboardType` enumerates the
//! custom case alone (`smithy_query(query="shape",shape="DashboardType")`), so what the
//! catalog holds is observed behaviour. The published values below are the ones the wire
//! record of a brand-new account shows — each entry's resource id, name and description
//! ([`PUBLISHED_CATALOG`]), the publication and revision instants the entries carry
//! ([`MANAGED_CATALOG_CREATED_AT`], [`MANAGED_CATALOG_REVISED_AT`]), and the whole
//! `WidgetId` list of the one entry whose detail read is recorded, including the
//! configuration of the panels that record spells out.
//!
//! Everything else is the model's. `Widget` fixes a widget's members and their bounds — a
//! 32-hexadecimal-character `id`, a 2..50 `title`, a 1..200 `description`, 1..2 `configs`,
//! and a `width`/`height`/`horizontalOffset` layout inside the declared ranges (2..6, 4..10),
//! which here is the one grid tile the recorded detail read shows
//! ([`WIDGET_WIDTH`], [`WIDGET_HEIGHT`], [`WIDGET_HORIZONTAL_OFFSET`]). `QueryParameters`
//! fixes which queries a panel may run (`costAndUsage`, `savingsPlansCoverage`,
//! `savingsPlansUtilization`, `reservationCoverage`, `reservationUtilization`), with the
//! valid `metrics` of each stated in that member's own documentation, and `Dimension` fixes
//! the keys a query groups and filters by
//! (`smithy_query(query="shape",shape="Widget,QueryParameters,CostAndUsageQuery,Dimension")`).
//!
//! # What is NOT published data
//!
//! The four entries whose detail read is not recorded ([`compute_widgets`],
//! [`database_widgets`], [`reservation_widgets`], [`savings_plans_widgets`]) carry panels
//! this module SYNTHESIZES from each entry's own published description, under ids
//! [`synthesized_widget_id`] derives from the entry and the panel. Their titles,
//! descriptions, queries and ids are not recorded values and must not be read as the
//! catalog's own: a panel carries an id because a scheduled report names the widgets it
//! reports by id, and the entry is served with panels rather than an empty list because the
//! recorded reads of these entries carry one.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime};

use crate::ops::types::{
    CostAndUsageQuery, DateTimeRange, DateTimeValue, DimensionValues, DisplayConfig, Expression,
    GraphDisplayConfig, GroupDefinition, QueryParameters, ReservationCoverageQuery,
    ReservationUtilizationQuery, SavingsPlansCoverageQuery, SavingsPlansUtilizationQuery,
    TableDisplayConfigStruct, Widget, WidgetConfig,
};

use super::{
    Dashboard, ARN_NAMESPACE, DASHBOARD_RESOURCE_TYPE, DASHBOARD_TYPE_AWS_MANAGED,
    DATE_TIME_TYPE_RELATIVE,
};

/// The resource-id prefix of every AWS-managed dashboard's ARN, which is what tells one
/// apart from a dashboard a caller created: the catalog's ARNs are
/// `arn:aws:bcm-dashboards::<account>:dashboard/managed-<32 hex>`, while
/// [`super::ComAmazonawsBcmdashboardsAwsbcmdashboardsserviceState::mint_dashboard_arn`]
/// mints a bare 32-hex resource id. Both spellings satisfy `DashboardArn`'s `[-a-z0-9]+`
/// resource segment.
const MANAGED_DASHBOARD_ID_PREFIX: &str = "managed-";

/// When the AWS-managed catalog was published, and when it was last revised, as seconds
/// since the Unix epoch.
///
/// The catalog is Amazon Web Services' own data, not the account's: its dashboards exist
/// before a caller writes anything, so their `createdAt`/`updatedAt` are the instants the
/// catalog was published and last revised rather than anything this emulator's clock
/// produced — which is why they are stored constants and are stable across reads and
/// across restarts. A dashboard a CALLER creates is stamped from the clock
/// (`CreateDashboard`), as its own record's instants.
///
/// A revision is per ENTRY: an entry revised since the catalog was published carries the
/// revision instant, and one that has not been revised reads its publication instant back
/// as its `updatedAt` ([`PUBLISHED_CATALOG`] states which).
const MANAGED_CATALOG_CREATED_AT: u64 = 1_786_644_000;
const MANAGED_CATALOG_REVISED_AT: u64 = 1_787_079_600;

/// The `width`, `height` and `horizontalOffset` every catalog panel carries.
///
/// The catalog publishes its panels on one grid tile — the width and height the recorded
/// detail read shows for the panels it discloses — and at offset 0, which is also
/// `Widget$horizontalOffset`'s modelled `@default`. All three sit inside the model's
/// declared ranges (`width` 2..6, `height` 4..10).
const WIDGET_WIDTH: i32 = 2;
const WIDGET_HEIGHT: i32 = 4;
const WIDGET_HORIZONTAL_OFFSET: i32 = 0;

/// The `Granularity` (`GRANULARITY_VALUES`) most panels in the catalog aggregate at: a
/// month, which is the period a bill covers.
const GRANULARITY_MONTHLY: &str = "MONTHLY";

/// The `Granularity` a panel charting the latest month day by day aggregates at.
const GRANULARITY_DAILY: &str = "DAILY";

/// The `GroupDefinitionType` (`GROUP_DEFINITION_TYPE_VALUES`) a grouping by a cost
/// dimension carries — also the member's modelled `@default`.
const GROUP_DEFINITION_TYPE_DIMENSION: &str = "DIMENSION";

/// The `MetricName`s the catalog's `costAndUsage` panels report, from the valid values
/// `CostAndUsageQuery$metrics` documents.
const METRIC_UNBLENDED_COST: &str = "UnblendedCost";
const METRIC_AMORTIZED_COST: &str = "AmortizedCost";

/// The only metric `SavingsPlansCoverageQuery$metrics` documents as valid.
const METRIC_SPEND_COVERED_BY_SAVINGS_PLANS: &str = "SpendCoveredBySavingsPlans";

/// One of the metrics `ReservationCoverageQuery$metrics` documents as valid (`Hour`,
/// `Unit`, `Cost`): what the reservation-coverage panels report coverage in.
const METRIC_COST: &str = "Cost";

/// The `VisualType`s (`VISUAL_TYPE_VALUES`) the catalog's graph panels draw with.
const VISUAL_TYPE_LINE: &str = "LINE";
const VISUAL_TYPE_STACK: &str = "STACK";

/// The `Dimension`s (`DIMENSION_VALUES`) the catalog's panels group and filter by.
const DIMENSION_SERVICE: &str = "SERVICE";
const DIMENSION_LINKED_ACCOUNT: &str = "LINKED_ACCOUNT";
const DIMENSION_REGION: &str = "REGION";
const DIMENSION_PURCHASE_TYPE: &str = "PURCHASE_TYPE";
const DIMENSION_DATABASE_ENGINE: &str = "DATABASE_ENGINE";

/// The `PURCHASE_TYPE` dimension values the commitment panels narrow to, as a bill spells
/// them.
const PURCHASE_TYPE_RESERVED_INSTANCES: &str = "Reserved Instances";
const PURCHASE_TYPE_SAVINGS_PLANS: &str = "Savings Plans";

/// The resource ids of the published catalog's entries, each the 32-hex id the catalog
/// publishes for that dashboard (the `managed-` prefix is added when the ARN is built).
const COST_OVERVIEW_ID: &str = "4dc5619130f2463687fc45e003e4b930";
const COMPUTE_ID: &str = "b0e4f3ab71454cf48a7d148287222f9d";
const DATABASE_ID: &str = "d2effbcc2dfd44eeb8ebec3f6e83382a";
const RESERVATIONS_ID: &str = "a8f4e2b1c3d6490ea1b7f5c8d2e94a03";
const SAVINGS_PLANS_ID: &str = "7b3c91d4e5f2a0186c4d8e9f1a2b3c4d";

/// One entry of the published catalog: the resource id, name and description a listing
/// reports for it, the instant it was last revised, and the panels a detail read of it
/// serves.
struct PublishedEntry {
    resource_id: &'static str,
    name: &'static str,
    description: &'static str,
    revised_at: u64,
    /// The builder is handed its entry's resource id, which is what an entry whose panels
    /// are synthesized derives their ids from; an entry whose panels carry published ids of
    /// their own ignores it.
    panels: fn(&str) -> Vec<Widget>,
}

/// The published catalog's entries, in the order the catalog publishes them.
///
/// Each row carries its own panel builder, so an entry added here serves ITS panels and no
/// other entry's.
const PUBLISHED_CATALOG: [PublishedEntry; 5] = [
    PublishedEntry {
        resource_id: COST_OVERVIEW_ID,
        name: "Cost Overview and Trends",
        description: "High-level view of your AWS costs, usage trends, and forecasts",
        revised_at: MANAGED_CATALOG_REVISED_AT,
        panels: cost_overview_widgets,
    },
    PublishedEntry {
        resource_id: COMPUTE_ID,
        name: "Compute",
        description: "Compute spend, efficiency, and commitment health across your compute \
                      services",
        revised_at: MANAGED_CATALOG_REVISED_AT,
        panels: compute_widgets,
    },
    PublishedEntry {
        resource_id: DATABASE_ID,
        name: "Database",
        description: "Database spend, efficiency, and commitment health across your database \
                      services",
        revised_at: MANAGED_CATALOG_REVISED_AT,
        panels: database_widgets,
    },
    PublishedEntry {
        resource_id: RESERVATIONS_ID,
        name: "Reservations",
        description: "Reserved Instance cost, utilization, and coverage health",
        // Not revised since the catalog was published, so its `updatedAt` is its
        // `createdAt`.
        revised_at: MANAGED_CATALOG_CREATED_AT,
        panels: reservation_widgets,
    },
    PublishedEntry {
        resource_id: SAVINGS_PLANS_ID,
        name: "Savings Plans",
        description: "Savings Plans utilization and coverage health",
        revised_at: MANAGED_CATALOG_REVISED_AT,
        panels: savings_plans_widgets,
    },
];

/// The `WidgetId` of each published panel of the `Cost Overview and Trends` entry.
///
/// The ids are the catalog's own, from that entry's recorded detail read. Which panel each
/// one carries is what the record shows for the panels it spells out — the cost grouped by
/// service and by Region, the committed-versus-flexible split and the budget reading — and
/// the remaining ids carry the entry's other published panels.
const WIDGET_ID_COST_PER_REGION: &str = "35d71261755663fa7f5aa289556472ef";
const WIDGET_ID_COST_PER_SERVICE: &str = "2a7e51a22e1c00af3843c5cccb82b046";
const WIDGET_ID_COMMITTED_VS_FLEXIBLE: &str = "48381c58fdf60999c778deb93fc9284a";
const WIDGET_ID_TOTAL_AND_FORECAST: &str = "a15901be3f2d2c9f07f2c90938ca73d3";
const WIDGET_ID_COST_PER_ACCOUNT: &str = "a7a5c864d98bfa0bcb1359bd4e3529f3";
const WIDGET_ID_DAILY_COST: &str = "a80cc87050b1e60b97c65e38be2876ae";
const WIDGET_ID_SAVINGS_PLANS_UTILIZATION: &str = "b8fe9c2e86f1737da142b62be6e865a8";
const WIDGET_ID_RESERVATION_UTILIZATION: &str = "ce2a10fcd1ab3961dc32b6a3c595166c";
const WIDGET_ID_BUDGET_HEALTH: &str = "d771f500c22cacaa952f1bba40260445";

/// A stable `WidgetId` for a panel this module synthesizes for the catalog entry
/// `entry_id`, derived from that entry and the panel's own title.
///
/// A synthesized panel still has to carry an id — a scheduled report names the widgets it
/// reports by id, and `Widget$id` is documented as the widget's unique identifier — and
/// `WidgetId`'s `@pattern` fixes its form at 32 lowercase hexadecimal characters
/// (`smithy_query(query="shape",shape="Widget")`), which is exactly the width of an MD5
/// digest. Deriving the id means it is stable across reads and restarts (a client may store
/// it), distinct per entry and per panel, and written in exactly one place rather than typed
/// out per panel. It is NOT a published id: see this module's header.
fn synthesized_widget_id(entry_id: &str, title: &str) -> String {
    let mut digest = <::md5::Md5 as ::md5::Digest>::new();
    ::md5::Digest::update(&mut digest, entry_id.as_bytes());
    ::md5::Digest::update(&mut digest, b":");
    ::md5::Digest::update(&mut digest, title.as_bytes());
    ::hex::encode(::md5::Digest::finalize(digest))
}

/// A widget time range running from `start` to `end`, both relative offsets (ISO 8601
/// durations, as `DateTimeValue$value` carries them for a `RELATIVE` bound).
fn relative_range(start: &str, end: &str) -> DateTimeRange {
    DateTimeRange {
        start_time: DateTimeValue {
            r#type: DATE_TIME_TYPE_RELATIVE.to_string(),
            value: start.to_string(),
        },
        end_time: DateTimeValue {
            r#type: DATE_TIME_TYPE_RELATIVE.to_string(),
            value: end.to_string(),
        },
    }
}

/// A `DisplayConfig` drawing one metric as `visual_type` (a `VisualType`:
/// `VISUAL_TYPE_VALUES` are `LINE`, `BAR`, `STACK`).
fn graph_display(metric: &str, visual_type: &str) -> DisplayConfig {
    DisplayConfig::Graph(HashMap::from([(
        metric.to_string(),
        GraphDisplayConfig {
            visual_type: visual_type.to_string(),
        },
    )]))
}

/// A `DisplayConfig` drawing the query's result as a table.
fn table_display() -> DisplayConfig {
    DisplayConfig::Table(TableDisplayConfigStruct {})
}

/// The `GroupDefinition`s grouping a query by each `Dimension` in `dimensions`, or an empty
/// list when the query is ungrouped.
fn group_by_dimensions(dimensions: &[&str]) -> Vec<GroupDefinition> {
    dimensions
        .iter()
        .map(|dimension| GroupDefinition {
            key: dimension.to_string(),
            r#type: GROUP_DEFINITION_TYPE_DIMENSION.to_string(),
        })
        .collect()
}

/// An `Expression` narrowing a query to the `values` of one `Dimension` — how a panel
/// scoped to part of the bill (one family of services, one purchase type) states that
/// scope.
fn dimension_filter(dimension: &str, values: &[&str]) -> Expression {
    Expression {
        dimensions: Some(DimensionValues {
            key: dimension.to_string(),
            values: values.iter().map(|value| value.to_string()).collect(),
            match_options: None,
        }),
        ..Expression::default()
    }
}

/// A `costAndUsage` query of one metric at one granularity over `range`, grouped by the
/// dimensions in `group_by` and narrowed to `filter`.
///
/// A panel that groups by nothing carries no `groupBy` at all, which is how an ungrouped
/// query reads back: `CostAndUsageQuery$groupBy` is optional and absent rather than empty.
fn cost_and_usage(
    metric: &str,
    granularity: &str,
    range: DateTimeRange,
    group_by: &[&str],
    filter: Option<Expression>,
) -> QueryParameters {
    QueryParameters::costAndUsage(CostAndUsageQuery {
        metrics: vec![metric.to_string()],
        time_range: range,
        granularity: granularity.to_string(),
        group_by: (!group_by.is_empty()).then(|| group_by_dimensions(group_by)),
        filter,
    })
}

/// A `savingsPlansCoverage` query over `range`, narrowed to `filter`.
fn savings_plans_coverage(range: DateTimeRange, filter: Option<Expression>) -> QueryParameters {
    QueryParameters::savingsPlansCoverage(SavingsPlansCoverageQuery {
        time_range: range,
        metrics: Some(vec![METRIC_SPEND_COVERED_BY_SAVINGS_PLANS.to_string()]),
        granularity: Some(GRANULARITY_MONTHLY.to_string()),
        group_by: None,
        filter,
    })
}

/// A `savingsPlansUtilization` query over `range`.
fn savings_plans_utilization(range: DateTimeRange) -> QueryParameters {
    QueryParameters::savingsPlansUtilization(SavingsPlansUtilizationQuery {
        time_range: range,
        granularity: Some(GRANULARITY_MONTHLY.to_string()),
        filter: None,
    })
}

/// A `reservationUtilization` query over `range`, narrowed to `filter`.
fn reservation_utilization(range: DateTimeRange, filter: Option<Expression>) -> QueryParameters {
    QueryParameters::reservationUtilization(ReservationUtilizationQuery {
        time_range: range,
        group_by: None,
        granularity: Some(GRANULARITY_MONTHLY.to_string()),
        filter,
    })
}

/// A `reservationCoverage` query over `range`, narrowed to `filter`.
fn reservation_coverage(range: DateTimeRange, filter: Option<Expression>) -> QueryParameters {
    QueryParameters::reservationCoverage(ReservationCoverageQuery {
        time_range: range,
        group_by: None,
        granularity: Some(GRANULARITY_MONTHLY.to_string()),
        filter,
        metrics: Some(vec![METRIC_COST.to_string()]),
    })
}

/// One published panel: the modelled [`Widget`] a reader projects, carrying `query` drawn
/// as `display` and the layout defaults `Widget` declares.
fn panel(
    id: &str,
    title: &str,
    description: &str,
    query: QueryParameters,
    display: DisplayConfig,
) -> Widget {
    Widget {
        id: Some(id.to_string()),
        title: title.to_string(),
        description: Some(description.to_string()),
        width: WIDGET_WIDTH,
        height: WIDGET_HEIGHT,
        horizontal_offset: WIDGET_HORIZONTAL_OFFSET,
        configs: vec![WidgetConfig {
            query_parameters: query,
            display_config: display,
        }],
    }
}

/// The panels of the `Cost Overview and Trends` entry: the nine its recorded detail read
/// carries, each under its own published id, which is why this builder needs nothing from
/// the entry it belongs to.
fn cost_overview_widgets(_entry_id: &str) -> Vec<Widget> {
    vec![
        panel(
            WIDGET_ID_TOTAL_AND_FORECAST,
            "Total Current And Forecasted Cost",
            "Monthly unblended cost to date, with the forecast for the coming months.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P4M"),
                &[],
                None,
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            WIDGET_ID_COST_PER_SERVICE,
            "Cost Per Service",
            "Monthly unblended cost of the account, grouped by service.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_SERVICE],
                None,
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            WIDGET_ID_COMMITTED_VS_FLEXIBLE,
            "Committed vs Flexible Spend",
            "Monthly amortized cost split into committed and flexible spend.",
            cost_and_usage(
                METRIC_AMORTIZED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_PURCHASE_TYPE],
                None,
            ),
            graph_display(METRIC_AMORTIZED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            WIDGET_ID_COST_PER_ACCOUNT,
            "Cost Per Account",
            "Monthly unblended cost grouped by the accounts in your organization.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_LINKED_ACCOUNT],
                None,
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            WIDGET_ID_COST_PER_REGION,
            "Cost Per Region",
            "Monthly unblended cost grouped by Region.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_REGION],
                None,
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            WIDGET_ID_DAILY_COST,
            "Daily Cost Trend",
            "Daily unblended cost over the latest month.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_DAILY,
                relative_range("-P1M", "P0M"),
                &[],
                None,
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_LINE),
        ),
        panel(
            WIDGET_ID_SAVINGS_PLANS_UTILIZATION,
            "Savings Plans Utilization",
            "Monthly utilization of the Savings Plans your account holds.",
            savings_plans_utilization(relative_range("-P6M", "P0M")),
            table_display(),
        ),
        panel(
            WIDGET_ID_RESERVATION_UTILIZATION,
            "Reservation Utilization",
            "Monthly utilization of the Reserved Instances your account holds.",
            reservation_utilization(relative_range("-P6M", "P0M"), None),
            table_display(),
        ),
        // `Budget Health` reports the spend a budget is measured against. The recorded
        // panel states that spend with a query member this service's model does not
        // declare — `QueryParameters` carries no budget query
        // (`smithy_query(query="shape",shape="QueryParameters")`) — so the panel carries
        // the month-to-date cost itself, the representable half of the same reading, as the
        // table the record shows.
        panel(
            WIDGET_ID_BUDGET_HEALTH,
            "Budget Health",
            "Month-to-date unblended cost of the account, against which your budgets are \
             tracked.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P1M", "P0M"),
                &[],
                None,
            ),
            table_display(),
        ),
    ]
}

/// The panels of the `Compute` entry, SYNTHESIZED from the three readings its published
/// description names (what the compute services cost, and how healthy the commitments
/// covering them are): this entry's recorded detail read does not disclose its panels, so
/// neither these titles and queries nor their [`synthesized_widget_id`] ids are the
/// catalog's own published values.
fn compute_widgets(entry_id: &str) -> Vec<Widget> {
    let compute_services = dimension_filter(
        DIMENSION_SERVICE,
        &[
            "Amazon Elastic Compute Cloud - Compute",
            "AWS Lambda",
            "AWS Fargate",
        ],
    );
    vec![
        panel(
            &synthesized_widget_id(entry_id, "Cost Per Compute Service"),
            "Cost Per Compute Service",
            "Monthly unblended cost of your compute services, grouped by service.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_SERVICE],
                Some(compute_services.clone()),
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Compute Savings Plans Coverage"),
            "Compute Savings Plans Coverage",
            "Monthly share of your eligible compute spend covered by Savings Plans.",
            savings_plans_coverage(relative_range("-P6M", "P0M"), Some(compute_services.clone())),
            table_display(),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Compute Reservation Coverage"),
            "Compute Reservation Coverage",
            "Monthly share of your eligible compute usage covered by Reserved Instances.",
            reservation_coverage(relative_range("-P6M", "P0M"), Some(compute_services)),
            table_display(),
        ),
    ]
}

/// The panels of the `Database` entry, SYNTHESIZED the same way [`compute_widgets`] is and
/// no more published than those, taken over the database services and their engines.
fn database_widgets(entry_id: &str) -> Vec<Widget> {
    let database_services = dimension_filter(
        DIMENSION_SERVICE,
        &[
            "Amazon Relational Database Service",
            "Amazon DynamoDB",
            "Amazon ElastiCache",
        ],
    );
    vec![
        panel(
            &synthesized_widget_id(entry_id, "Cost Per Database Service"),
            "Cost Per Database Service",
            "Monthly unblended cost of your database services, grouped by service.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_SERVICE],
                Some(database_services.clone()),
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Cost Per Database Engine"),
            "Cost Per Database Engine",
            "Monthly unblended cost of your database usage, grouped by database engine.",
            cost_and_usage(
                METRIC_UNBLENDED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_DATABASE_ENGINE],
                Some(database_services.clone()),
            ),
            graph_display(METRIC_UNBLENDED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Database Reservation Coverage"),
            "Database Reservation Coverage",
            "Monthly share of your eligible database usage covered by Reserved Instances.",
            reservation_coverage(relative_range("-P6M", "P0M"), Some(database_services)),
            table_display(),
        ),
    ]
}

/// The panels of the `Reservations` entry, SYNTHESIZED from the three readings its
/// published description names (what the Reserved Instances cost, how far they are used,
/// and how much of the eligible usage they cover) the same way [`compute_widgets`] is, and
/// no more published than those.
fn reservation_widgets(entry_id: &str) -> Vec<Widget> {
    vec![
        panel(
            &synthesized_widget_id(entry_id, "Reserved Instance Cost"),
            "Reserved Instance Cost",
            "Monthly amortized cost of your Reserved Instances, grouped by service.",
            cost_and_usage(
                METRIC_AMORTIZED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_SERVICE],
                Some(dimension_filter(
                    DIMENSION_PURCHASE_TYPE,
                    &[PURCHASE_TYPE_RESERVED_INSTANCES],
                )),
            ),
            graph_display(METRIC_AMORTIZED_COST, VISUAL_TYPE_STACK),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Reservation Utilization"),
            "Reservation Utilization",
            "Monthly utilization of the Reserved Instances your account holds.",
            reservation_utilization(relative_range("-P6M", "P0M"), None),
            table_display(),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Reservation Coverage"),
            "Reservation Coverage",
            "Monthly share of your eligible instance usage covered by Reserved Instances.",
            reservation_coverage(relative_range("-P6M", "P0M"), None),
            table_display(),
        ),
    ]
}

/// The panels of the `Savings Plans` entry, SYNTHESIZED from the readings its published
/// description names (how far the Savings Plans the account holds are used, how much of the
/// eligible spend they cover, and what they cost) the same way [`compute_widgets`] is, and
/// no more published than those.
fn savings_plans_widgets(entry_id: &str) -> Vec<Widget> {
    vec![
        panel(
            &synthesized_widget_id(entry_id, "Savings Plans Utilization"),
            "Savings Plans Utilization",
            "Monthly utilization of the Savings Plans your account holds.",
            savings_plans_utilization(relative_range("-P6M", "P0M")),
            table_display(),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Savings Plans Coverage"),
            "Savings Plans Coverage",
            "Monthly share of your eligible spend covered by your Savings Plans.",
            savings_plans_coverage(relative_range("-P6M", "P0M"), None),
            table_display(),
        ),
        panel(
            &synthesized_widget_id(entry_id, "Savings Plans Cost"),
            "Savings Plans Cost",
            "Monthly amortized cost of the Savings Plans your account holds.",
            cost_and_usage(
                METRIC_AMORTIZED_COST,
                GRANULARITY_MONTHLY,
                relative_range("-P12M", "P0M"),
                &[DIMENSION_SERVICE],
                Some(dimension_filter(
                    DIMENSION_PURCHASE_TYPE,
                    &[PURCHASE_TYPE_SAVINGS_PLANS],
                )),
            ),
            graph_display(METRIC_AMORTIZED_COST, VISUAL_TYPE_STACK),
        ),
    ]
}

/// One stored dashboard of the AWS-managed catalog, built the same way a created one is:
/// the record carries its own ARN, name, description, type and widgets, and every reader
/// projects it from the store.
fn managed_dashboard(entry: &PublishedEntry) -> Dashboard {
    Dashboard {
        arn: published_dashboard_arn(entry.resource_id),
        name: entry.name.to_string(),
        description: Some(entry.description.to_string()),
        dashboard_type: DASHBOARD_TYPE_AWS_MANAGED.to_string(),
        widgets: (entry.panels)(entry.resource_id),
        created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(MANAGED_CATALOG_CREATED_AT),
        updated_at: SystemTime::UNIX_EPOCH + Duration::from_secs(entry.revised_at),
        // The catalog carries no tags and no resource-based policy: a tag is an account's
        // own metadata, and this model declares no operation that attaches a policy at all.
        resource_tags: Vec::new(),
        resource_policy: None,
    }
}

/// The AWS-managed dashboard catalog every account already holds, keyed by ARN exactly as
/// a created dashboard is.
///
/// `pub` so a test can state the catalog a listing must report alongside its own
/// dashboards from the one place that defines it.
pub fn managed_dashboard_catalog() -> BTreeMap<String, Dashboard> {
    PUBLISHED_CATALOG
        .iter()
        .map(|entry| {
            let dashboard = managed_dashboard(entry);
            (dashboard.arn.clone(), dashboard)
        })
        .collect()
}

/// The ARN the catalog publishes for the entry under `resource_id`.
fn published_dashboard_arn(resource_id: &str) -> String {
    ::engine::emulator_arn(
        ARN_NAMESPACE,
        "",
        &format!("{DASHBOARD_RESOURCE_TYPE}/{MANAGED_DASHBOARD_ID_PREFIX}{resource_id}"),
    )
}
