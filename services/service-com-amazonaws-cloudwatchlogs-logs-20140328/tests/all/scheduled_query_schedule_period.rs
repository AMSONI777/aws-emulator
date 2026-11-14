// SPDX-License-Identifier: CC0-1.0

//! The PERIOD of a scheduled query's `scheduleExpression`: the span a run that states no
//! `startTimeOffset` of its own reads back over.
//!
//! The rule under test: a schedule's period is a property of the SCHEDULE, not of the instant
//! it is asked about — the gap between two consecutive instants the expression names, the same
//! answer wherever in the cycle the question falls. A query that states no lookback therefore
//! reads one whole period back on every run, rather than the shrinking remainder of the time
//! still to run until the next instant (which, asked a minute before a daily cron's hour,
//! would read one minute of log data instead of a day's).
//!
//! The table spans what the rule generalises over: each form of expression the service accepts
//! (a `rate(...)` in each published unit, a cron naming an hour of the day, a cron naming a
//! minute of the hour), each asked at several instants of its own cycle — a whole cycle before
//! the next instant, well inside it, and a millisecond either side of it — so an answer that
//! depends on where in the cycle it was asked cannot pass. The cycle is located from the
//! schedule itself rather than from a calendar literal, so the assertions hold at every wall
//! clock the suite runs at.

use std::time::{SystemTime, UNIX_EPOCH};

use service_com_amazonaws_cloudwatchlogs_logs_20140328::state::{schedule_of, Schedule};

/// The milliseconds in a second, a minute, an hour and a day, for stating a period.
const SECOND_MS: i64 = 1_000;
const MINUTE_MS: i64 = 60 * SECOND_MS;
const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;

/// An arbitrary instant to locate each schedule's cycle from: now, so no case depends on a
/// calendar literal. Epoch milliseconds, the unit a stored schedule's instants carry.
fn anchor_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after the Unix epoch")
            .as_millis(),
    )
    .expect("the epoch milliseconds fit in an i64")
}

/// One row of the table: an expression and the period one of its cycles lasts.
struct Period {
    case: &'static str,
    expression: &'static str,
    expected_ms: i64,
}

/// Every expression form the service accepts, with the period its own cycle lasts. The rate
/// units are the ones `scheduled_query_schedule_expressions.rs` pins as accepted; the cron
/// forms name an hour of the day and a minute of the hour, the two cycle lengths a six-field
/// cron expression takes here.
fn rows() -> Vec<Period> {
    vec![
        Period {
            case: "a rate in minutes",
            expression: "rate(5 minutes)",
            expected_ms: 5 * MINUTE_MS,
        },
        Period {
            case: "a rate of one hour",
            expression: "rate(1 hour)",
            expected_ms: HOUR_MS,
        },
        Period {
            case: "a rate in hours",
            expression: "rate(6 hours)",
            expected_ms: 6 * HOUR_MS,
        },
        Period {
            case: "a rate of one day",
            expression: "rate(1 day)",
            expected_ms: DAY_MS,
        },
        Period {
            case: "a cron naming one hour of the day",
            expression: "cron(0 3 * * ? *)",
            expected_ms: DAY_MS,
        },
        Period {
            case: "a cron naming another hour and minute of the day",
            expression: "cron(37 18 * * ? *)",
            expected_ms: DAY_MS,
        },
        Period {
            case: "a cron naming one minute of every hour",
            expression: "cron(0 * * * ? *)",
            expected_ms: HOUR_MS,
        },
    ]
}

/// The instants one period is asked at, as offsets from the next instant the schedule names
/// after the anchor: a whole cycle before it (the previous instant, for a schedule at regular
/// intervals), two points inside the cycle, the millisecond before it and the millisecond
/// after it. The old defect — answering the time still to run until the next instant — shows
/// at the probes close to it.
fn probe_offsets_ms(period_ms: i64) -> Vec<(&'static str, i64)> {
    vec![
        ("a whole cycle before the next instant", -period_ms),
        ("half a cycle before the next instant", -period_ms / 2),
        ("a tenth of a cycle before the next instant", -period_ms / 10),
        ("one millisecond before the next instant", -1),
        ("one millisecond after the next instant", 1),
    ]
}

/// A schedule's period is the same span wherever in its cycle it is asked.
#[test]
fn a_schedules_period_is_the_gap_between_its_instants_wherever_it_is_asked() {
    let anchor = anchor_ms();
    for Period {
        case,
        expression,
        expected_ms,
    } in rows()
    {
        let schedule: Schedule = schedule_of(expression)
            .unwrap_or_else(|| panic!("case {case:?}: {expression:?} must parse as a schedule"));
        let next = schedule
            .next_after(anchor, None)
            .unwrap_or_else(|| panic!("case {case:?}: {expression:?} names a further instant"));

        for (probe, offset) in probe_offsets_ms(expected_ms) {
            let asked_at = next + offset;
            let period = schedule.interval_after(asked_at, None);
            assert_eq!(
                period,
                Some(expected_ms),
                "case {case:?} / {probe}: the period of {expression:?} is {expected_ms} ms \
                 wherever it is asked, got {period:?}"
            );
        }
    }
}

/// A cron evaluated in a named timezone keeps a cycle of the same length: a day there is a day,
/// bar the two days a year the zone's offset moves, when it is an hour shorter or longer.
#[test]
fn a_cron_in_a_named_timezone_keeps_a_daily_cycle() {
    let anchor = anchor_ms();
    let case = "a daily cron evaluated in America/New_York";
    let expression = "cron(0 3 * * ? *)";
    let zone = Some("America/New_York");
    let schedule = schedule_of(expression)
        .unwrap_or_else(|| panic!("case {case:?}: {expression:?} must parse as a schedule"));
    let next = schedule
        .next_after(anchor, zone)
        .unwrap_or_else(|| panic!("case {case:?}: {expression:?} names a further instant"));

    for (probe, offset) in probe_offsets_ms(DAY_MS) {
        let asked_at = next + offset;
        let period = schedule
            .interval_after(asked_at, zone)
            .unwrap_or_else(|| panic!("case {case:?} / {probe}: the schedule has a period"));
        assert!(
            (DAY_MS - HOUR_MS..=DAY_MS + HOUR_MS).contains(&period),
            "case {case:?} / {probe}: a daily cycle in a named zone lasts a day, an hour \
             either side across a change of offset, got {period} ms"
        );
    }
}
