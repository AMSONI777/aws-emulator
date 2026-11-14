// SPDX-License-Identifier: CC0-1.0

//! When a STARTED canary leaves `RUNNING` by itself, end to end over the wire (the same
//! `MultiServiceRouter` the emulator boots, through the harness in `canary_lifecycle`).
//!
//! The ONE rule pinned here: a started canary leaves `RUNNING` on its own exactly when its
//! own schedule bounds how long it keeps running, and only once the run it opened has
//! finished — a run-once expression as soon as that single run is done, a non-zero
//! `DurationInSeconds` once that duration has passed — while a schedule that bounds nothing
//! holds `RUNNING` until `StopCanary`. A canary that stopped itself carries the instant it
//! stopped at, still serves its run history, and can be started again.
//!
//! Both members the rule reads are the model's own
//! (`smithy_query(query="shape",shape="CanaryScheduleInput",model_path="services/service-com-amazonaws-synthetics-synthetics/smithy-model/com-amazonaws-synthetics-synthetics.json")`):
//!
//! * `Expression`: "Specifying `rate(0 minute)` or `rate(0 hour)` is a special value that
//!   causes the canary to run only once when it is started."
//! * `DurationInSeconds` (`@range 0..31622400`): "How long, in seconds, for the canary to
//!   continue making regular runs according to the schedule in the `Expression` value. If
//!   you specify 0, the canary continues making runs until you stop it. If you omit this
//!   field, the default of 0 is used."
//!
//! `tests/all/canary_run_outcomes.rs` asserts the same rule over the two run-once spellings
//! against the services that own a run's resources; this suite spans the OTHER half of what
//! the rule generalises over — the `DurationInSeconds` bound, including both published
//! bounds of its range — and the readings a settled canary must still answer.

use serde_json::{json, Value};

use crate::canary_lifecycle::{poll_until, Synthetics};
use crate::group_membership::ok;

/// The Region every call in this suite is signed for.
const REGION: &str = "us-west-2";

/// `MaxOneYearInSeconds`, the target of `CanaryScheduleInput$DurationInSeconds`, is
/// `@range 0..31622400`: the published maximum, used by the row that proves a run-once
/// expression bounds the canary however large the duration beside it is.
const MAX_DURATION_IN_SECONDS: i64 = 31_622_400;

/// The smallest non-zero `DurationInSeconds` the published range admits, used by the rows
/// whose bound is the DURATION rather than the expression. Kept at the floor so the suite
/// waits for the shortest bound the model allows.
const SHORTEST_BOUND_IN_SECONDS: i64 = 1;

/// One row: a schedule, and whether that schedule bounds how long the canary runs.
struct Row {
    case: &'static str,
    name: &'static str,
    expression: &'static str,
    /// `None` leaves the member out, which takes its documented default of 0.
    duration: Option<i64>,
    /// Whether the clock owes this canary the move out of `RUNNING`.
    self_stops: bool,
}

/// The rows differ along what the rule generalises over: the form of the expression (both
/// rate units, both run-once spellings, cron) and the value of `DurationInSeconds` (omitted,
/// the published minimum of 0, the smallest non-zero value, and the published maximum).
fn rows() -> Vec<Row> {
    vec![
        // Bounded by the EXPRESSION: run-once, in either unit, whatever duration sits
        // beside it.
        Row {
            case: "run once, minutes, no duration",
            name: "bound-once-minute",
            expression: "rate(0 minute)",
            duration: None,
            self_stops: true,
        },
        Row {
            case: "run once, hours, the duration's documented default",
            name: "bound-once-hour",
            expression: "rate(0 hour)",
            duration: Some(0),
            self_stops: true,
        },
        Row {
            case: "run once, with the published maximum duration beside it",
            name: "bound-once-max-duration",
            expression: "rate(0 minute)",
            duration: Some(MAX_DURATION_IN_SECONDS),
            self_stops: true,
        },
        // Bounded by the DURATION: a recurring expression that stops making runs once the
        // duration has passed.
        Row {
            case: "every minute, for the shortest bound the range admits",
            name: "bound-rate-duration",
            expression: "rate(1 minute)",
            duration: Some(SHORTEST_BOUND_IN_SECONDS),
            self_stops: true,
        },
        Row {
            case: "a cron schedule, for the shortest bound the range admits",
            name: "bound-cron-duration",
            expression: "cron(0/10 * * * ? *)",
            duration: Some(SHORTEST_BOUND_IN_SECONDS),
            self_stops: true,
        },
        // Bounded by NOTHING: a recurring expression with no duration holds RUNNING.
        Row {
            case: "every minute, no duration",
            name: "unbound-rate-minute",
            expression: "rate(1 minute)",
            duration: None,
            self_stops: false,
        },
        Row {
            case: "every hour, the duration's published minimum",
            name: "unbound-rate-hour",
            expression: "rate(1 hour)",
            duration: Some(0),
            self_stops: false,
        },
        Row {
            case: "a cron schedule, no duration",
            name: "unbound-cron",
            expression: "cron(0/10 * * * ? *)",
            duration: None,
            self_stops: false,
        },
    ]
}

/// A `CreateCanary` body carrying the row's schedule and nothing else unusual.
fn canary_body(row: &Row) -> Value {
    let mut schedule = json!({ "Expression": row.expression });
    if let Some(seconds) = row.duration {
        schedule["DurationInSeconds"] = json!(seconds);
    }
    json!({
        "Name": row.name,
        "Code": { "Handler": "index.handler", "S3Bucket": "scripts", "S3Key": "canary.zip" },
        "ArtifactS3Location": format!("s3://artifacts/{}", row.name),
        "ExecutionRoleArn": "arn:aws:iam::123456789012:role/CanaryRole",
        "Schedule": schedule,
        "RuntimeVersion": "syn-nodejs-puppeteer-9.0",
    })
}

/// Every run the canary's history holds, newest first.
async fn runs_of(aws: &Synthetics, case: &str, name: &str) -> Vec<Value> {
    let answer = ok(&format!("{case}/runs"), aws.runs(name, json!({})).await);
    answer
        .at("CanaryRuns")
        .as_array()
        .unwrap_or_else(|| panic!("case {case}: expected a run list, got {:?}", answer.body))
        .clone()
}

/// Create the canary, wait out the provisioning transition the clock owes it, and start it.
async fn create_ready_and_start(aws: &Synthetics, row: &Row) {
    ok(&format!("{}/create", row.case), aws.create(canary_body(row)).await);
    let ready = poll_until(
        &format!("{}/ready", row.case),
        || aws.get(row.name),
        |answer| answer.string_at("Canary.Status.State") == "READY",
    )
    .await;
    assert_eq!(
        ready.at("Canary.Schedule.Expression").as_str(),
        Some(row.expression),
        "case {}: the schedule must round-trip, got {:?}",
        row.case,
        ready.at("Canary.Schedule")
    );
    assert_eq!(
        ready.at("Canary.Schedule.DurationInSeconds").as_i64(),
        Some(row.duration.unwrap_or(0)),
        "case {}: the duration must round-trip (0 when omitted), got {:?}",
        row.case,
        ready.at("Canary.Schedule")
    );
    ok(&format!("{}/start", row.case), aws.start(row.name).await);
}

/// Wait until the canary's newest run is no longer `RUNNING`, and answer it.
async fn finished_run(aws: &Synthetics, case: &str, name: &str) -> Value {
    let answer = poll_until(
        &format!("{case}/run-finished"),
        || aws.runs(name, json!({})),
        |answer| {
            answer.at("CanaryRuns")[0]["Status"]["State"]
                .as_str()
                .is_some_and(|state| state != "RUNNING")
        },
    )
    .await;
    answer.at("CanaryRuns")[0].clone()
}

#[tokio::test]
async fn a_started_canary_leaves_running_by_itself_only_when_its_schedule_bounds_it() {
    let aws = Synthetics::new(REGION);
    let rows = rows();

    // The canaries whose schedule bounds NOTHING are started FIRST, so that by the time the
    // bounded ones have stopped themselves below, every unbounded one has been `RUNNING` at
    // least as long — no assertion in this suite waits for a span to pass, it waits for a
    // bounded canary to prove the span passed.
    for row in rows.iter().filter(|row| !row.self_stops) {
        create_ready_and_start(&aws, row).await;
    }
    for row in rows.iter().filter(|row| row.self_stops) {
        create_ready_and_start(&aws, row).await;
    }

    // The run a start opens has to be finished before the canary can be: a canary with an
    // open run of its own schedule is still working, whatever its bound says.
    for row in &rows {
        let run = finished_run(&aws, row.case, row.name).await;
        assert!(
            run["Timeline"]["Completed"].is_number(),
            "case {}: a finished run carries the instant it completed, got {run}",
            row.case
        );
    }

    // A bounded canary settles out of RUNNING with no StopCanary call, keeps the instant it
    // stopped at, and still serves the run it made.
    for row in rows.iter().filter(|row| row.self_stops) {
        let canary = poll_until(
            &format!("{}/stopped", row.case),
            || aws.get(row.name),
            |answer| answer.string_at("Canary.Status.State") == "STOPPED",
        )
        .await;
        assert_eq!(
            canary.string_at("Canary.Status.State"),
            "STOPPED",
            "case {}: expected a bounded canary to settle to STOPPED on its own, got {:?}",
            row.case,
            canary.at("Canary.Status")
        );
        assert!(
            canary.at("Canary.Timeline.LastStopped").is_number(),
            "case {}: expected LastStopped on a canary that stopped itself, got {:?}",
            row.case,
            canary.at("Canary.Timeline")
        );
        let history = runs_of(&aws, row.case, row.name).await;
        assert_eq!(
            history.len(),
            1,
            "case {}: expected the one run the start made to be readable, got {history:?}",
            row.case
        );
        assert_ne!(
            history[0]["Status"]["State"].as_str(),
            Some("RUNNING"),
            "case {}: expected the recorded run to have reached a verdict, got {:?}",
            row.case,
            history[0]["Status"]
        );
    }

    // Every bounded canary above has now stopped itself, including the one bounded by the
    // shortest duration the range admits — which was started LAST. A canary whose schedule
    // bounds nothing is therefore still RUNNING at an instant past that bound, and only
    // StopCanary moves it.
    for row in rows.iter().filter(|row| !row.self_stops) {
        let canary = ok(&format!("{}/still-running", row.case), aws.get(row.name).await);
        assert_eq!(
            canary.string_at("Canary.Status.State"),
            "RUNNING",
            "case {}: expected an unbounded schedule to hold RUNNING until it is stopped, \
             got {:?}",
            row.case,
            canary.at("Canary.Status")
        );
        assert!(
            canary.at("Canary.Timeline.LastStopped").is_null(),
            "case {}: a canary that never stopped carries no LastStopped, got {:?}",
            row.case,
            canary.at("Canary.Timeline")
        );
        ok(&format!("{}/stop", row.case), aws.stop(row.name).await);
        let stopped = poll_until(
            &format!("{}/stopped-on-request", row.case),
            || aws.get(row.name),
            |answer| answer.string_at("Canary.Status.State") == "STOPPED",
        )
        .await;
        assert_eq!(
            stopped.string_at("Canary.Status.State"),
            "STOPPED",
            "case {}: expected StopCanary to stop it, got {:?}",
            row.case,
            stopped.at("Canary.Status")
        );
    }
}

#[tokio::test]
async fn a_canary_that_stopped_itself_can_be_started_again() {
    let aws = Synthetics::new(REGION);

    for row in rows().into_iter().filter(|row| row.self_stops) {
        create_ready_and_start(&aws, &row).await;
        poll_until(
            &format!("{}/first-stop", row.case),
            || aws.get(row.name),
            |answer| answer.string_at("Canary.Status.State") == "STOPPED",
        )
        .await;

        // Nothing about having stopped itself blocks a second start: the conflict a start is
        // refused for is a canary that is RUNNING or has an operation in flight.
        ok(&format!("{}/restart", row.case), aws.start(row.name).await);
        let history = poll_until(
            &format!("{}/second-run", row.case),
            || aws.runs(row.name, json!({})),
            |answer| answer.at("CanaryRuns").as_array().is_some_and(|runs| runs.len() == 2),
        )
        .await;
        let runs = history
            .at("CanaryRuns")
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            runs.len(),
            2,
            "case {}: expected a second start to record a second run, got {runs:?}",
            row.case
        );
        assert_ne!(
            runs[0]["Id"].as_str(),
            runs[1]["Id"].as_str(),
            "case {}: expected the two runs to be distinct records, got {runs:?}",
            row.case
        );
        // And the second run brings the canary back out of RUNNING the same way the first
        // did, because the bound is the schedule's and the schedule did not change.
        let settled = poll_until(
            &format!("{}/second-stop", row.case),
            || aws.get(row.name),
            |answer| answer.string_at("Canary.Status.State") == "STOPPED",
        )
        .await;
        assert_eq!(
            settled.string_at("Canary.Status.State"),
            "STOPPED",
            "case {}: expected the restarted canary to settle again, got {:?}",
            row.case,
            settled.at("Canary.Status")
        );
    }
}
