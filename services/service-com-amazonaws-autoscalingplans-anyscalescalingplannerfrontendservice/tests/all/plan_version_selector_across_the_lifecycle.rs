// SPDX-License-Identifier: CC0-1.0

//! The `ScalingPlanVersion` selector across a plan's whole LIFECYCLE — the dimension the
//! version table in [`crate::plan_version_selects_a_plan`] does not span.
//!
//! One rule is pinned here: a request member the model constrains to no set of values
//! (`smithy_query(query="operation",operation="DescribeScalingPlanResources")` — member
//! `ScalingPlanVersion`, type `long`, no `@range` and no enum) SELECTS the resource the
//! request addresses, so what a coordinate selecting nothing is answered with is decided
//! by the operation's own error set and never by the phase the plan beside it is in. The
//! reads that bind no not-found error report their collection empty with HTTP 200 in every
//! phase, and the two mutating operations that DO bind `ObjectNotFoundException` refuse
//! the very same coordinate in every phase — including the phases where those operations
//! refuse the plan's OWN version as a concurrent update, which is what makes the refusal
//! about the coordinate rather than about what the plan is doing.
//!
//! This is the poll primitive the plan lifecycle is walked with: a caller probing a
//! version while a plan is being created, updated or drained has to be answered, not
//! refused, and the probe must leave the lifecycle where it found it.
//!
//! Rows differ along the lifecycle phase (a plan being created, settled, being updated,
//! being drained, and one already gone), along the version's magnitude and sign across the
//! whole `long` the member is modelled as, and along which operation carries the member.
//!
//! A phase is reached by moving the STORED instant a transition is due at
//! (`hold_pending` / `make_all_due`), never by waiting for a clock.
//!
//! The harness (router, dispatch, error-body readers) is reused from
//! [`crate::scaling_plan_lifecycle`], the version table from
//! [`crate::plan_version_member_validation`], the two read requests from
//! [`crate::absent_plan_reads`] and the not-found sentence from
//! [`crate::plan_version_selects_a_plan`]; nothing here builds a second one.

use serde_json::{json, Value};

use service_com_amazonaws_autoscalingplans_anyscalescalingplannerfrontendservice::state::{
    wire_refusals, ONLY_VERSION,
};

use crate::absent_plan_reads::{read_request, READS};
use crate::plan_version_member_validation::unheld_versions;
use crate::plan_version_selects_a_plan::expected_not_found;
use crate::scaling_plan_lifecycle::{
    error_code, error_message, simple_instructions, stack_source, Emulator,
};

/// The one plan these tests hold, so a row probes the VERSION half of the coordinate
/// against a plan the service really has.
const PLAN: &str = "held plan";

/// The modelled not-found shape the two mutating operations bind
/// (`smithy_query(query="operation",operation="DeleteScalingPlan,UpdateScalingPlan")`).
const NOT_FOUND: &str = "ObjectNotFoundException";

/// What a mutating operation answers the plan's OWN version with in a phase — the
/// boundary beside the rule, which the phase DOES decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnVersion {
    /// The plan is settled, so the mutation it addresses is served.
    Served,
    /// The plan still has a transition in flight, so the mutation is refused as a
    /// concurrent update.
    InProgress,
    /// The plan is no longer stored, so its own version selects nothing either.
    Gone,
}

/// Every phase a stored plan passes through: its label, the `StatusCode`
/// `DescribeScalingPlans` reports it as (`None` once the plan is gone), and what a
/// mutation at the plan's own version is answered with there.
const PHASES: [(&str, Option<&str>, OwnVersion); 5] = [
    (
        "being created",
        Some("CreationInProgress"),
        OwnVersion::InProgress,
    ),
    ("settled", Some("Active"), OwnVersion::Served),
    (
        "being updated",
        Some("UpdateInProgress"),
        OwnVersion::InProgress,
    ),
    (
        "being deleted",
        Some("DeletionInProgress"),
        OwnVersion::InProgress,
    ),
    ("gone", None, OwnVersion::Gone),
];

/// An emulator holding (or, for the last phase, having held) one plan in `phase`.
async fn emulator_in_phase(phase: &str) -> Emulator {
    let emulator = Emulator::new();
    emulator
        .ok(
            "CreateScalingPlan",
            json!({
                "ScalingPlanName": PLAN,
                "ApplicationSource": stack_source(1),
                "ScalingInstructions": simple_instructions(),
            }),
        )
        .await;
    let own = json!({ "ScalingPlanName": PLAN, "ScalingPlanVersion": ONLY_VERSION });
    match phase {
        "being created" => emulator.hold_pending(PLAN),
        "settled" => emulator.make_all_due(),
        "being updated" => {
            emulator.make_all_due();
            emulator.ok("UpdateScalingPlan", own).await;
            emulator.hold_pending(PLAN);
        }
        "being deleted" => {
            emulator.make_all_due();
            emulator.ok("DeleteScalingPlan", own).await;
            emulator.hold_pending(PLAN);
        }
        "gone" => {
            emulator.make_all_due();
            emulator.ok("DeleteScalingPlan", own).await;
            emulator.make_all_due();
            // The removal the clock owes is applied by the next call, whichever it is.
            emulator.ok("DescribeScalingPlans", json!({})).await;
        }
        other => panic!("case {other:?}: not a lifecycle phase this suite builds"),
    }
    emulator
}

/// The `StatusCode` the collection read reports [`PLAN`] as, or `None` when no plan is
/// reported at all.
async fn reported_status(emulator: &Emulator) -> Option<String> {
    let described = emulator.ok("DescribeScalingPlans", json!({})).await;
    described["ScalingPlans"]
        .as_array()
        .and_then(|plans| plans.first())
        .map(|plan| plan["StatusCode"].as_str().unwrap_or_default().to_string())
}

#[tokio::test]
async fn a_read_at_a_version_the_plan_does_not_carry_is_empty_in_every_lifecycle_phase() {
    for (phase, status, own) in PHASES {
        let emulator = emulator_in_phase(phase).await;
        let reached = reported_status(&emulator).await;
        assert_eq!(
            reached.as_deref(),
            status,
            "case a plan {phase}: the phase the rest of the case needs was not reached"
        );

        for (label, version) in unheld_versions() {
            for (operation, member) in READS {
                let request = read_request(operation, PLAN, version);
                let case = format!("{operation}/{label} ({version}) on a plan {phase}");
                let (http, body) = emulator.call(operation, &request).await;
                assert_eq!(
                    http, 200,
                    "case {case:?}: expected HTTP 200, got {http} with {body}"
                );
                assert_eq!(
                    body[member],
                    json!([]),
                    "case {case:?}: expected an empty {member} list, got {body}"
                );
                assert!(
                    body.get("NextToken").is_none_or(Value::is_null),
                    "case {case:?}: an empty answer continues nowhere, got {body}"
                );
            }
        }

        // The control at the plan's OWN version: a read of the coordinate that DOES select
        // the plan is served what the plan holds in this phase, so the empty answers above
        // come from the coordinate missing and not from the phase.
        let described = emulator
            .ok(
                "DescribeScalingPlanResources",
                read_request("DescribeScalingPlanResources", PLAN, ONLY_VERSION),
            )
            .await;
        let expected_resources = if own == OwnVersion::Gone { 0 } else { 1 };
        assert_eq!(
            described["ScalingPlanResources"]
                .as_array()
                .map(Vec::len),
            Some(expected_resources),
            "case the own version of a plan {phase}: expected {expected_resources} \
             resource(s), got {described}"
        );
        let forecast = emulator
            .ok(
                "GetScalingPlanResourceForecastData",
                read_request("GetScalingPlanResourceForecastData", PLAN, ONLY_VERSION),
            )
            .await;
        assert!(
            forecast["Datapoints"].is_array(),
            "case the own version of a plan {phase}: expected the required Datapoints \
             list, got {forecast}"
        );

        // And the probes above left the lifecycle where they found it: a read is not a
        // nudge to the next phase.
        let after = reported_status(&emulator).await;
        assert_eq!(
            after, reached,
            "case the reads on a plan {phase}: the phase must be as it was, got {after:?} \
             after {reached:?}"
        );
    }
}

#[tokio::test]
async fn the_writes_refuse_a_version_the_plan_does_not_carry_in_every_lifecycle_phase() {
    for (phase, _, own) in PHASES {
        for operation in ["DeleteScalingPlan", "UpdateScalingPlan"] {
            // One emulator per operation, so the served control at the end of a phase's
            // run cannot decide what the next operation sees.
            let emulator = emulator_in_phase(phase).await;

            for (label, version) in unheld_versions() {
                let request = json!({ "ScalingPlanName": PLAN, "ScalingPlanVersion": version });
                let case = format!("{operation}/{label} ({version}) on a plan {phase}");
                let (http, body) = emulator.call(operation, &request).await;
                assert_eq!(
                    (http, error_code(&body)),
                    (400, NOT_FOUND),
                    "case {case:?}: expected a 400 {NOT_FOUND}, got {http} with {body}"
                );
                let expected = expected_not_found(PLAN, version);
                let actual = error_message(&body);
                assert_eq!(
                    actual, expected,
                    "case {case:?}: expected {expected:?}, got {actual:?}"
                );
            }

            // The boundary: at the plan's OWN version the same request is answered about
            // what the plan is doing — served when it is settled, refused as a concurrent
            // update while a transition is in flight, not found once it is gone.
            let request = json!({ "ScalingPlanName": PLAN, "ScalingPlanVersion": ONLY_VERSION });
            let case = format!("{operation} at the own version of a plan {phase}");
            let (http, body) = emulator.call(operation, &request).await;
            let refusal: Option<(u16, &str, String)> = match own {
                OwnVersion::Served => None,
                OwnVersion::InProgress => Some((
                    wire_refusals::CONCURRENT_UPDATE_STATUS,
                    wire_refusals::CONCURRENT_UPDATE_CODE,
                    wire_refusals::CONCURRENT_UPDATE_MESSAGE.to_string(),
                )),
                OwnVersion::Gone => Some((
                    400,
                    NOT_FOUND,
                    expected_not_found(PLAN, ONLY_VERSION),
                )),
            };
            match refusal {
                None => assert_eq!(
                    http, 200,
                    "case {case:?}: expected HTTP 200, got {http} with {body}"
                ),
                Some((status, code, message)) => assert_eq!(
                    (http, error_code(&body), error_message(&body)),
                    (status, code, message.as_str()),
                    "case {case:?}: expected {status} {code} {message:?}, got {http} with \
                     {body}"
                ),
            }
        }
    }
}
