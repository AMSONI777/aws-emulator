// SPDX-License-Identifier: CC0-1.0

//! The ONE query an execution of a log alarm's managed scheduled query runs, and the aggregated
//! values its rows carry.
//!
//! "The expression that defines how to aggregate query results into one or more scalar values for
//! alarm evaluation. For example, `count(*)` or `avg(latency) by host | sort desc`."
//! (`ScheduledQueryConfiguration$AggregationExpression`) — that expression is written in the
//! aggregation language of CloudWatch Logs Insights, the `stats` command's own, and the service
//! that holds the log events is the one that reads and computes it. So nothing here parses it: the
//! expression is appended to the alarm's query string as the `stats` command it is
//! ([`aggregated_query`]) and the run's rows come back ALREADY aggregated by that engine, which is
//! what keeps one reader of that language in this emulator.
//!
//! What is left is reading the engine's own result shape ([`aggregated_values`]): an aggregation
//! reports "the grouped fields and then the aggregates, each named by its `as` clause or by the
//! text that computes it", so each row carries its contributor group first and the aggregated
//! value last.

use super::MAX_CONTRIBUTOR_GROUPS;

/// One row of a query's results: the fields that row carries, in the order
/// `GetQueryResults` reports them.
pub type QueryRow = Vec<(String, String)>;

/// The `stats` command the aggregation of a log alarm is computed by, as a query stage.
const STATS_COMMAND: &str = "stats";

/// The query ONE execution of a log alarm's managed scheduled query runs: the alarm's own
/// `QueryString` with its `AggregationExpression` appended as the `stats` command that computes
/// it.
///
/// "Each scheduled query execution returns one or more aggregated values determined by the
/// AggregationExpression" (`PutLogAlarm`) — so the run is the alarm's query AND its aggregation,
/// one query for the engine that holds the events to compile, run and bound. An expression that
/// already opens with the command word is not given a second one, and an expression carrying a
/// pipeline of its own (`avg(latency) by host | sort desc`) keeps it: the stages after the
/// aggregate are stages of the same query.
#[must_use]
pub fn aggregated_query(query_string: &str, aggregation_expression: &str) -> String {
    let aggregation = aggregation_expression.trim();
    let aggregation = aggregation
        .strip_prefix(STATS_COMMAND)
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .unwrap_or(aggregation)
        .trim();
    // A query string that ends on the pipe already expects a stage after it, so the composition
    // does not add a second separator.
    let query = query_string.trim().trim_end_matches('|').trim_end();
    if query.is_empty() {
        return format!("{STATS_COMMAND} {aggregation}");
    }
    format!("{query} | {STATS_COMMAND} {aggregation}")
}

/// The aggregated values the rows of one execution carry: one per row, with the contributor group
/// the row belongs to; `true` beside them when there were more rows than
/// [`MAX_CONTRIBUTOR_GROUPS`].
///
/// An aggregation's result "columns are the grouped fields and then the aggregates", so the LAST
/// field of a row is the value the alarm compares and whatever precedes it identifies the group
/// that value was computed over — one group per row, as the engine folded them. A row whose value
/// is not a number is no scalar to compare against a threshold and contributes nothing, which is
/// what an aggregate over records that carried no number answers.
#[must_use]
pub fn aggregated_values(rows: &[QueryRow]) -> (Vec<(Option<String>, f64)>, bool) {
    let partial = rows.len() > MAX_CONTRIBUTOR_GROUPS;
    let values = rows
        .iter()
        .take(MAX_CONTRIBUTOR_GROUPS)
        .filter_map(|row| {
            let (aggregate, group) = row.split_last()?;
            let value = aggregate.1.trim().parse::<f64>().ok()?;
            let label = (!group.is_empty()).then(|| {
                group
                    .iter()
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            });
            Some((label, value))
        })
        .collect();
    (values, partial)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row of a result set, from its field/value pairs.
    fn row(fields: &[(&str, &str)]) -> QueryRow {
        fields
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn the_run_query_is_the_alarms_own_query_followed_by_its_aggregation() {
        for (case, query, aggregation, expected) in [
            (
                "a filter and a count",
                "fields @timestamp, @message | filter @message like /BREACH/",
                "count(*)",
                "fields @timestamp, @message | filter @message like /BREACH/ | stats count(*)",
            ),
            (
                "an aggregation carrying a pipeline of its own",
                "fields latency, host",
                "avg(latency) by host | sort desc",
                "fields latency, host | stats avg(latency) by host | sort desc",
            ),
            (
                "an expression that already opens with the command word",
                "fields latency",
                "stats max(latency)",
                "fields latency | stats max(latency)",
            ),
            (
                "a query string left open on the pipe",
                "fields latency |",
                "sum(latency)",
                "fields latency | stats sum(latency)",
            ),
            (
                "an alarm that states no query of its own",
                "",
                "count(*)",
                "stats count(*)",
            ),
            (
                "an expression whose function name only starts with the command word",
                "fields statsValue",
                "statsd(statsValue)",
                "fields statsValue | stats statsd(statsValue)",
            ),
        ] {
            let composed = aggregated_query(query, aggregation);
            assert_eq!(
                composed, expected,
                "case {case:?}: expected {expected:?}, got {composed:?}"
            );
        }
    }

    #[test]
    fn an_ungrouped_aggregation_carries_one_value_and_no_group() {
        let (values, partial) = aggregated_values(&[row(&[("count(*)", "7")])]);
        assert!(!partial, "one row is no partial result, got {partial}");
        assert_eq!(
            values,
            vec![(None, 7.0)],
            "expected the one aggregated value, got {values:?}"
        );
    }

    #[test]
    fn a_grouped_aggregation_carries_one_value_per_group_in_the_order_it_reports_them() {
        let (values, _) = aggregated_values(&[
            row(&[("host", "two"), ("avg(latency)", "30")]),
            row(&[("host", "one"), ("avg(latency)", "10.5")]),
        ]);
        assert_eq!(
            values,
            vec![
                (Some("two".to_string()), 30.0),
                (Some("one".to_string()), 10.5),
            ],
            "expected one value per group, got {values:?}"
        );
    }

    #[test]
    fn a_row_whose_aggregate_is_no_number_carries_no_value() {
        // An aggregate over records that carried no number answers no scalar, and a row with no
        // field at all carries nothing to read.
        let (values, _) = aggregated_values(&[
            row(&[("max(latency)", "")]),
            row(&[("max(latency)", "not a number")]),
            row(&[]),
        ]);
        assert!(
            values.is_empty(),
            "expected no value at all, got {values:?}"
        );
    }

    #[test]
    fn more_groups_than_the_ceiling_are_evaluated_up_to_it_and_reported_as_partial() {
        let rows: Vec<QueryRow> = (0..=MAX_CONTRIBUTOR_GROUPS)
            .map(|index| {
                vec![
                    ("host".to_string(), format!("host-{index}")),
                    ("count(*)".to_string(), "1".to_string()),
                ]
            })
            .collect();
        let (values, partial) = aggregated_values(&rows);
        assert!(
            partial,
            "more groups than the ceiling is a partial result, got {partial}"
        );
        assert_eq!(
            values.len(),
            MAX_CONTRIBUTOR_GROUPS,
            "expected the ceiling's worth of values, got {}",
            values.len()
        );
    }
}
