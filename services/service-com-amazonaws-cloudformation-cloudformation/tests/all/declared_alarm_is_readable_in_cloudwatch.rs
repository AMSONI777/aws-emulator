// SPDX-License-Identifier: CC0-1.0

//! The alarm a stack declares beside the CloudWatch Logs resources whose metric it watches,
//! read back through the two services that own them.
//!
//! RULE under test: **every resource a stack reports created is created in the service that
//! OWNS it before the stack reaches `CREATE_COMPLETE`, under the identifier the stack
//! publishes for it** — so an `AWS::CloudWatch::Alarm` whose name a completed stack publishes
//! with `Ref` is one Amazon CloudWatch holds: `DescribeAlarms(AlarmNames=[<that name>])`,
//! paged to the end, reports EXACTLY ONE `MetricAlarms` entry for it, carrying the
//! declaration's namespace, metric, statistic, period, evaluation periods, threshold,
//! comparison operator and missing-data treatment, and a `StateValue` its own evaluation
//! reached.
//!
//! The reported case deployed a diagnosis estate — a log group, a metric filter over its
//! `ERROR` lines and an alarm over the metric that filter publishes — whose stack reached
//! `CREATE_COMPLETE` and published the alarm's name, while CloudWatch held no alarm of that
//! name at all: the Logs half of the same template was real and the alarm was not, so the
//! first read of the deploy-then-observe flow found nothing and could not tell an alarm that
//! does not exist from one that has no data.
//!
//! The rows differ along what the rule generalises over rather than restating that template:
//!
//! * where the alarm's NAME comes from — a template parameter resolved by `Ref`, a literal in
//!   the declaration, and no `AlarmName` at all, which CloudFormation names itself;
//! * WHICH state the alarm's own evaluation reaches with no datapoint published, over every
//!   value of `StateValue` ([`settled_state`]);
//! * the configuration itself — four of the five modelled statistics, four comparison
//!   operators, one and several evaluation periods with and without an "M out of N" count, a
//!   period of a minute and of five, and a threshold spelled as an integer and as a fraction;
//! * how much else of the SAME template belongs to another service — a log group alone, and a
//!   log group with the metric filter that publishes the metric the alarm watches.
//!
//! Nothing is waited out: the stack is polled to its terminal status and the alarm's state is
//! polled until the evaluation the clock owes has been materialised.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::cloudwatch_alarm_and_ecs_service_resources::cloudwatch;
use crate::dynamodb_table_resources::failure_reasons;
use crate::elbv2_resource_provisioning::poll_to_terminal;
use crate::logs_and_iot_resources::described_group;
use crate::stack_lifecycle::{
    acknowledging_iam, create_stack, member, output_value, router, xml_text,
};

/// The logical id of the template parameter a row may take the alarm's name from, which is
/// also the key `CreateStack` passes its value under.
const ALARM_NAME_PARAMETER: &str = "AlarmName";

/// The metric the filter publishes and the alarm watches, and the namespace it is published
/// in: one metric for every row, so a row's own configuration is the only thing that differs.
const METRIC_NAME: &str = "SftpErrors";
const METRIC_NAMESPACE: &str = "Sftp/Diagnostics";

/// The values `StateValue` publishes
/// (`smithy_query(query="shape",shape="StateValue")`) — the three states a readable alarm can
/// report, each one reached by a row below.
const STATE_VALUE_VALUES: [&str; 3] = ["OK", "ALARM", "INSUFFICIENT_DATA"];

/// How many pages a read of ONE alarm may take before the paging is judged not to terminate.
const PAGE_LIMIT: usize = 8;

/// How many times, and how far apart, the alarm's state is re-read while waiting for the
/// evaluation the clock owes it: a generous budget for a transition that is due promptly, so
/// the outcome does not depend on how fast the host runs.
const STATE_POLL_ATTEMPTS: usize = 120;
const STATE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Where the alarm's name comes from.
#[derive(Debug, Clone, Copy)]
enum Naming {
    /// The declaration's `AlarmName` is `Ref` of a template parameter carrying this value.
    FromParameter(&'static str),
    /// The declaration states this name outright.
    Literal(&'static str),
    /// The declaration states no name, so CloudFormation names the resource itself.
    Generated,
}

/// One row: the estate a template declares, and what the two owning services must then hold.
struct Row {
    case: &'static str,
    stack: &'static str,
    /// The log group the template declares, and the retention CloudWatch Logs must report.
    group: &'static str,
    retention: i64,
    /// Whether the template also declares the metric filter that publishes the metric.
    metric_filter: bool,
    naming: Naming,
    statistic: &'static str,
    comparison_operator: &'static str,
    period: i64,
    evaluation_periods: i64,
    /// The "M out of N" count the declaration states, or `None` where it states none.
    datapoints_to_alarm: Option<i64>,
    /// The threshold exactly as the template spells it — an integer or a fraction, both of
    /// which CloudWatch holds as one `Double` (`PutMetricAlarmInput$Threshold`).
    threshold: Value,
    /// The `TreatMissingData` the declaration states, or `None` where it states none.
    treat_missing_data: Option<&'static str>,
}

/// The state an alarm no datapoint has been published for settles in, decided by its
/// missing-data treatment alone.
///
/// "Sets how this alarm is to handle missing data points. If `TreatMissingData` is omitted,
/// the default behavior of `missing` is used. […] Valid Values: `breaching | notBreaching |
/// ignore | missing`"
/// (`smithy_query(query="doc",shape="PutMetricAlarmInput",member="TreatMissingData")`):
/// `notBreaching` substitutes a non-breaching datapoint for every empty window, so the
/// evaluation reaches `OK`; `breaching` substitutes a breaching one, so it reaches `ALARM`;
/// `missing` substitutes nothing, which leaves the window short of the datapoints either
/// direction needs; and `ignore` keeps the state the alarm is in, which for an alarm nothing
/// has evaluated yet is the `INSUFFICIENT_DATA` its creation set
/// ("When this operation creates an alarm, the alarm state is immediately set to
/// INSUFFICIENT_DATA", `PutMetricAlarm`).
fn settled_state(treat_missing_data: Option<&str>) -> &'static str {
    match treat_missing_data {
        Some("notBreaching") => "OK",
        Some("breaching") => "ALARM",
        _ => "INSUFFICIENT_DATA",
    }
}

/// The rows, spanning the class the rule covers.
///
/// The statistics and comparison operators are the model's own
/// (`smithy_query(query="shape",shape="Statistic")`,
/// `smithy_query(query="shape",shape="ComparisonOperator")`), and the retentions are values
/// `AWS::Logs::LogGroup`'s `RetentionInDays` publishes.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "an alarm named by a template parameter, over the metric the filter in the \
                   same template publishes",
            stack: "sftp-diagnosis-parameterised",
            group: "/sim/sftp/parameterised",
            retention: 30,
            metric_filter: true,
            naming: Naming::FromParameter("sftp-error-alarm-parameterised"),
            statistic: "Sum",
            comparison_operator: "GreaterThanOrEqualToThreshold",
            period: 60,
            evaluation_periods: 1,
            datapoints_to_alarm: None,
            threshold: json!(1),
            treat_missing_data: Some("notBreaching"),
        },
        Row {
            case: "an alarm the template names outright, over an average above a fractional \
                   threshold, whose missing data breaches",
            stack: "sftp-diagnosis-named",
            group: "/sim/sftp/named",
            retention: 7,
            metric_filter: false,
            naming: Naming::Literal("sftp-latency-alarm-named"),
            statistic: "Average",
            comparison_operator: "GreaterThanThreshold",
            period: 300,
            evaluation_periods: 2,
            datapoints_to_alarm: None,
            threshold: json!(12.5),
            treat_missing_data: Some("breaching"),
        },
        Row {
            case: "an alarm CloudFormation names itself, an M out of N window and no \
                   missing-data treatment of its own",
            stack: "sftp-diagnosis-generated",
            group: "/sim/sftp/generated",
            retention: 1,
            metric_filter: true,
            naming: Naming::Generated,
            statistic: "Minimum",
            comparison_operator: "LessThanOrEqualToThreshold",
            period: 60,
            evaluation_periods: 3,
            datapoints_to_alarm: Some(2),
            threshold: json!(0),
            treat_missing_data: None,
        },
        Row {
            case: "an alarm that ignores missing data, so it keeps the state it was created in",
            stack: "sftp-diagnosis-ignored",
            group: "/sim/sftp/ignored",
            retention: 90,
            metric_filter: false,
            naming: Naming::Literal("sftp-session-alarm-ignored"),
            statistic: "Maximum",
            comparison_operator: "LessThanThreshold",
            period: 60,
            evaluation_periods: 1,
            datapoints_to_alarm: None,
            threshold: json!(100),
            treat_missing_data: Some("ignore"),
        },
    ]
}

/// The template one row deploys: its log group, its metric filter where it declares one, the
/// alarm, and the two outputs the stack publishes the identifiers under.
fn template_of(row: &Row) -> String {
    let mut alarm = json!({
        "Namespace": METRIC_NAMESPACE,
        "MetricName": METRIC_NAME,
        "Statistic": row.statistic,
        "ComparisonOperator": row.comparison_operator,
        "Period": row.period,
        "EvaluationPeriods": row.evaluation_periods,
        "Threshold": row.threshold,
    });
    if let Some(count) = row.datapoints_to_alarm {
        alarm["DatapointsToAlarm"] = json!(count);
    }
    if let Some(treatment) = row.treat_missing_data {
        alarm["TreatMissingData"] = json!(treatment);
    }
    match row.naming {
        Naming::FromParameter(_) => alarm["AlarmName"] = json!({"Ref": ALARM_NAME_PARAMETER}),
        Naming::Literal(name) => alarm["AlarmName"] = json!(name),
        Naming::Generated => {}
    }
    let mut resources = json!({
        "Group": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {"LogGroupName": row.group, "RetentionInDays": row.retention},
        },
        "Alarm": {"Type": "AWS::CloudWatch::Alarm", "Properties": alarm},
    });
    if row.metric_filter {
        resources["Filter"] = json!({
            "Type": "AWS::Logs::MetricFilter",
            "Properties": {
                "FilterName": format!("{}-errors", row.stack),
                "LogGroupName": {"Ref": "Group"},
                "FilterPattern": "ERROR",
                "MetricTransformations": [{
                    "MetricName": METRIC_NAME,
                    "MetricNamespace": METRIC_NAMESPACE,
                    "MetricValue": "1",
                }],
            },
        });
    }
    let mut template = json!({
        "Resources": resources,
        "Outputs": {
            "AlarmName": {"Value": {"Ref": "Alarm"}},
            "LogGroupName": {"Value": {"Ref": "Group"}},
        },
    });
    if let Naming::FromParameter(_) = row.naming {
        template["Parameters"] = json!({"AlarmName": {"Type": "String"}});
    }
    template.to_string()
}

/// Every `MetricAlarms` entry `DescribeAlarms` reports for `name`, read to the END of the
/// paging — the read a client makes, so "no entry on any page" is what the absence of the
/// alarm looks like.
///
/// `MaxRecords` is one, so a name the store held more than one entry for would really be
/// paged rather than reported in a single answer.
async fn alarms_named(router: &MultiServiceRouter, case: &str, name: &str) -> Vec<Value> {
    let mut found: Vec<Value> = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..PAGE_LIMIT {
        let mut request = json!({"AlarmNames": [name], "MaxRecords": 1});
        if let Some(cursor) = &token {
            request["NextToken"] = json!(cursor);
        }
        let (status, document) = cloudwatch(router, "DescribeAlarms", &request).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from DescribeAlarms for {name:?}, got {status} \
             with {document}"
        );
        if let Some(page) = document.get("MetricAlarms").and_then(Value::as_array) {
            found.extend(page.iter().cloned());
        }
        token = document
            .get("NextToken")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        if token.is_none() {
            break;
        }
    }
    assert!(
        token.is_none(),
        "case {case:?}: expected the read of {name:?} to reach the end of the paging within \
         {PAGE_LIMIT} pages, got a further NextToken"
    );
    found
}

/// The one alarm `DescribeAlarms` reports for `name`, once it reports the state `expected`.
///
/// An alarm's state is EVALUATED rather than written by the caller, and the first evaluation
/// is due a span after the write that configured it, so the state is polled for until it holds
/// — never waited out for a fixed time.
async fn settled_alarm(
    router: &MultiServiceRouter,
    case: &str,
    name: &str,
    expected: &str,
) -> Value {
    let mut last = Value::Null;
    for _ in 0..STATE_POLL_ATTEMPTS {
        let reported = alarms_named(router, case, name).await;
        let mine: Vec<Value> = reported
            .into_iter()
            .filter(|alarm| alarm.get("AlarmName").and_then(Value::as_str) == Some(name))
            .collect();
        assert_eq!(
            mine.len(),
            1,
            "case {case:?}: expected Amazon CloudWatch to report exactly one alarm named \
             {name:?} — the one the stack reports created — got {mine:?}"
        );
        last = mine.into_iter().next().unwrap_or(Value::Null);
        if last.get("StateValue").and_then(Value::as_str) == Some(expected) {
            break;
        }
        tokio::time::sleep(STATE_POLL_INTERVAL).await;
    }
    last
}

#[tokio::test]
async fn an_alarm_a_stack_declares_is_readable_in_cloudwatch_by_the_name_it_publishes() {
    for row in rows() {
        let case = row.case;
        let router = router();

        let mut extra = acknowledging_iam(&[]);
        if let Naming::FromParameter(value) = row.naming {
            extra.push(member(
                "Parameters.member.1.ParameterKey",
                ALARM_NAME_PARAMETER,
            ));
            extra.push(member("Parameters.member.1.ParameterValue", value));
        }
        let (status, body) = create_stack(&router, row.stack, &template_of(&row), &extra).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from CreateStack, got {status} with {body}"
        );
        let described = poll_to_terminal(&router, case, row.stack).await;
        let reported = xml_text(&described, "StackStatus");
        assert_eq!(
            reported.as_deref(),
            Some("CREATE_COMPLETE"),
            "case {case:?}: expected the create to complete, got {reported:?} because {:?}",
            failure_reasons(&router, row.stack).await
        );

        // The identifier the stack PUBLISHES for the alarm is the handle every later
        // CloudWatch call about it takes, so it is the name the read below addresses.
        let name = output_value(&described, "AlarmName").unwrap_or_default();
        match row.naming {
            Naming::FromParameter(value) | Naming::Literal(value) => assert_eq!(
                name, value,
                "case {case:?}: expected the stack to publish the declared alarm name \
                 {value:?}, got {name:?}"
            ),
            Naming::Generated => {
                let prefix = format!("{}-Alarm-", row.stack);
                assert!(
                    name.starts_with(&prefix),
                    "case {case:?}: expected a generated name under {prefix:?}, got {name:?}"
                );
            }
        }

        // The Logs half of the SAME template, which the reported case already had: the group
        // exists with the retention it declared, and reports the filter declared on it.
        let published_group = output_value(&described, "LogGroupName").unwrap_or_default();
        assert_eq!(
            published_group, row.group,
            "case {case:?}: expected the stack to publish the declared log group name, got \
             {published_group:?}"
        );
        let group = described_group(&router, &published_group)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "case {case:?}: expected CloudWatch Logs to hold the group \
                     {published_group:?} the stack reports created, got no group at all"
                )
            });
        assert_eq!(
            group.get("retentionInDays").and_then(Value::as_i64),
            Some(row.retention),
            "case {case:?}: expected the group to carry the declared retention {}, got {group}",
            row.retention
        );
        let expected_filters = i64::from(row.metric_filter);
        assert_eq!(
            group.get("metricFilterCount").and_then(Value::as_i64),
            Some(expected_filters),
            "case {case:?}: expected the group to report {expected_filters} metric filter(s), \
             got {group}"
        );

        // The alarm itself, by the name the stack published: one entry, the declaration's
        // configuration, and a state its own evaluation reached.
        let expected_state = settled_state(row.treat_missing_data);
        let alarm = settled_alarm(&router, case, &name, expected_state).await;

        for (member_name, expected) in [
            ("Namespace", METRIC_NAMESPACE),
            ("MetricName", METRIC_NAME),
            ("Statistic", row.statistic),
            ("ComparisonOperator", row.comparison_operator),
        ] {
            let held = alarm.get(member_name).and_then(Value::as_str);
            assert_eq!(
                held,
                Some(expected),
                "case {case:?}: expected CloudWatch to report {member_name} as {expected:?}, \
                 got {held:?}"
            );
        }
        for (member_name, expected) in [
            ("Period", Some(row.period)),
            ("EvaluationPeriods", Some(row.evaluation_periods)),
            ("DatapointsToAlarm", row.datapoints_to_alarm),
        ] {
            let held = alarm.get(member_name).and_then(Value::as_i64);
            assert_eq!(
                held, expected,
                "case {case:?}: expected CloudWatch to report {member_name} as {expected:?}, \
                 got {held:?}"
            );
        }
        let held_threshold = alarm.get("Threshold").and_then(Value::as_f64);
        assert_eq!(
            held_threshold,
            row.threshold.as_f64(),
            "case {case:?}: expected CloudWatch to report the declared threshold {}, got \
             {held_threshold:?}",
            row.threshold
        );
        let held_treatment = alarm.get("TreatMissingData").and_then(Value::as_str);
        assert_eq!(
            held_treatment,
            row.treat_missing_data,
            "case {case:?}: expected CloudWatch to report TreatMissingData as {:?}, got \
             {held_treatment:?}",
            row.treat_missing_data
        );

        let state = alarm.get("StateValue").and_then(Value::as_str);
        assert!(
            state.is_some_and(|value| STATE_VALUE_VALUES.contains(&value)),
            "case {case:?}: expected a readable StateValue, one of {STATE_VALUE_VALUES:?}, got \
             {state:?}"
        );
        assert_eq!(
            state,
            Some(expected_state),
            "case {case:?}: expected the alarm's own evaluation to reach {expected_state:?} \
             with no datapoint published, got {state:?} ({:?})",
            alarm.get("StateReason")
        );
    }
}
