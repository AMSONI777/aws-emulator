// SPDX-License-Identifier: CC0-1.0

//! The sentence ARC states for each class of refusal a zonal-shift mutation answers,
//! driven end to end over the same `MultiServiceRouter` the emulator boots.
//!
//! The rule under test: a refusal `StartZonalShift`, `UpdateZonalShift` or
//! `CancelZonalShift` takes on its own — one the model does not express as a constraint —
//! is stated as ONE sentence that is a property of the refusal CLASS, so it is the same
//! words for every shift, resource, zone, caller and operation that reaches the class and
//! carries nothing of the request or of the store: no shift id, no resource ARN, no
//! status token, no rejected value. What identifies the refusal to a client is the
//! modelled member that carries it — `ConflictException$reason`,
//! `ConflictException$zonalShiftId`, `ValidationException$reason`
//! (`smithy_query(query="shape", shape="ConflictException,ValidationException")`) — and
//! those are asserted beside the sentence here.
//!
//! Each class is a TABLE whose rows differ along what the rule generalises over — which
//! operation ran into it, how the shift stopped being active, which resource and zone the
//! request named, which value it carried — and the sentence is pinned as a literal, so a
//! row that reverts to prose composed from the request fails.
//!
//! The framework's own constraint refusals (an `expiresIn` outside its `@pattern`) are
//! the other half: their envelope and clause are the framework's, and the value the
//! request carried stays out of a clause about a member of the operation's input shape.
//! The table over members and constraint classes lives in `refusal_message_rules.rs` and
//! the one over values in `refusal_disclosure.rs`; the rows below are an `expiresIn` of
//! the modelled length that no row there carries.

use std::time::{Duration, SystemTime};

use super::zonal_shift_lifecycle::{call, emulator, encoded, error_code, seeded, start_body};
use service_com_amazonaws_arczonalshift_percdataplane::ComAmazonawsArczonalshiftPercdataplaneState as ZonalShiftStore;

/// The sentence ARC states when the shift a call names is no longer running, for both the
/// cancel and the update that run into it. No variable part at all.
const NOT_ACTIVE: &str = "You can't update this zonal shift because it's no longer active";

/// The sentence ARC states when a resource already has an active customer-initiated zonal
/// shift and another is asked for. No variable part at all, trailing period included.
const ALREADY_ACTIVE: &str = "There's already an active zonal shift for that resource.";

/// The sentence ARC states when `awayFrom` names no Availability Zone the resource is
/// deployed in. No variable part at all.
const INVALID_AZ: &str = "Invalid availability zone.";

/// `expiresIn`'s `@pattern` as a refusal of the framework's reports it: `^([1-9][0-9]*)(m|h)$`
/// without the anchors that make the match total
/// (`smithy_query(query="shape", shape="ExpiresIn")`).
const EXPIRES_IN_PATTERN_CLAUSE: &str = "1 validation error detected: Value at 'expiresIn' \
     failed to satisfy constraint: Member must satisfy regular expression pattern: \
     ([1-9][0-9]*)(m|h)";

/// A refused call's message, with its status and error code checked first.
fn refusal_message(
    case: &str,
    status: u16,
    body: &serde_json::Value,
    expected_status: u16,
    expected_code: &str,
) -> String {
    assert_eq!(
        status, expected_status,
        "case {case:?}: expected HTTP {expected_status}, got {status} {body}"
    );
    let code = error_code(body);
    assert_eq!(
        code, expected_code,
        "case {case:?}: expected {expected_code}, got {code:?} in {body}"
    );
    body["message"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: a refusal states a message, got {body}"))
        .to_string()
}

/// Assert `message` carries none of the values the request or the store held, which is
/// what makes the sentence the class's rather than this request's.
fn states_nothing_of(case: &str, message: &str, values: &[&str]) {
    for value in values {
        assert!(
            !message.contains(value),
            "case {case:?}: the sentence must not carry {value:?}, got {message:?}"
        );
    }
}

#[tokio::test]
async fn the_status_precondition_states_one_sentence_for_every_operation_and_status() {
    // Rows differ along the two axes the rule generalises over: HOW the shift stopped
    // being active (a caller canceled it, or the clock passed its expiry), and WHICH
    // operation then ran into the precondition — each with a different body, so the
    // sentence cannot be coming from what the request asked to change.
    let stopped: [(&str, bool); 2] = [
        ("canceled by a caller", true),
        ("expired by the clock", false),
    ];
    let operations: [(&str, &str, &str); 4] = [
        ("cancel again", "DELETE", ""),
        ("update a comment", "PATCH", r#"{"comment":"too late"}"#),
        ("update an expiry", "PATCH", r#"{"expiresIn":"2h"}"#),
        (
            "update both",
            "PATCH",
            r#"{"comment":"too late","expiresIn":"30m"}"#,
        ),
    ];
    for (stop, by_cancel) in stopped {
        for (op, method, payload) in operations {
            let case = format!("{op} on a shift {stop}");
            let (router, engine) = emulator();
            let (resource, zones) = seeded(&engine)[0].clone();
            let (status, started) = call(
                &router,
                "POST",
                "/zonalshifts",
                &start_body(&resource, &zones[0], "1h", "a shift to end"),
            )
            .await;
            assert_eq!(status, 201, "case {case:?}: the shift starts, got {started}");
            let shift_id = started["zonalShiftId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let reached = if by_cancel {
                let (status, body) =
                    call(&router, "DELETE", &format!("/zonalshifts/{shift_id}"), "").await;
                assert_eq!(status, 200, "case {case:?}: the cancel succeeds, got {body}");
                "CANCELED"
            } else {
                // The one thing no modeled operation can do: backdate the stored expiry,
                // so the next call finds the shift EXPIRED.
                let store = engine.state::<ZonalShiftStore>();
                let mut store = store.lock();
                let shift = store
                    .zonal_shifts
                    .get_mut(&shift_id)
                    .expect("the started shift is in the store");
                shift.expiry_time = SystemTime::now() - Duration::from_secs(1);
                "EXPIRED"
            };

            let (status, body) =
                call(&router, method, &format!("/zonalshifts/{shift_id}"), payload).await;
            let message = refusal_message(&case, status, &body, 409, "ConflictException");
            assert_eq!(
                message, NOT_ACTIVE,
                "case {case:?}: expected {NOT_ACTIVE:?}, got {message:?}"
            );
            assert_eq!(
                body["reason"], "ZonalShiftStatusNotActive",
                "case {case:?}: expected reason ZonalShiftStatusNotActive, got {body}"
            );
            assert_eq!(
                body["zonalShiftId"], shift_id,
                "case {case:?}: the modelled member names the shift, got {body}"
            );
            states_nothing_of(&case, &message, &[&shift_id, &resource, reached, &zones[0]]);
        }
    }
}

#[tokio::test]
async fn a_second_shift_for_a_resource_states_one_sentence() {
    let (router, engine) = emulator();
    let resources = seeded(&engine);
    // One row per resource (each deployed in a different number of zones) crossed with
    // every zone it is deployed in and a length of time of its own: the conflict is the
    // resource's, so none of that reaches the sentence.
    for (resource, zones) in resources {
        let (status, first) = call(
            &router,
            "POST",
            "/zonalshifts",
            &start_body(&resource, &zones[0], "1h", "the shift already held"),
        )
        .await;
        assert_eq!(status, 201, "the first shift starts, got {status} {first}");
        let held_id = first["zonalShiftId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        for away_from in &zones {
            for expires_in in ["1h", "30m", "72h"] {
                let case =
                    format!("second shift for {resource} away from {away_from} for {expires_in}");
                let (status, body) = call(
                    &router,
                    "POST",
                    "/zonalshifts",
                    &start_body(&resource, away_from, expires_in, "the second shift"),
                )
                .await;
                let message = refusal_message(&case, status, &body, 409, "ConflictException");
                assert_eq!(
                    message, ALREADY_ACTIVE,
                    "case {case:?}: expected {ALREADY_ACTIVE:?}, got {message:?}"
                );
                assert_eq!(
                    body["reason"], "ZonalShiftAlreadyExists",
                    "case {case:?}: expected reason ZonalShiftAlreadyExists, got {body}"
                );
                assert_eq!(
                    body["zonalShiftId"], held_id,
                    "case {case:?}: the modelled member names the shift already held, \
                     got {body}"
                );
                states_nothing_of(
                    &case,
                    &message,
                    &[&held_id, &resource, away_from, expires_in],
                );
            }
        }
    }
}

#[tokio::test]
async fn an_away_from_outside_the_resources_zones_states_one_sentence() {
    let (router, engine) = emulator();
    let resources = seeded(&engine);
    for (resource, zones) in &resources {
        // A zone ANOTHER managed resource is deployed in — a real Availability Zone ID,
        // just not one of this resource's — beside values that name no zone at all and
        // one at `AvailabilityZone`'s `@length` maximum of 20
        // (`smithy_query(query="shape", shape="AvailabilityZone")`), so the rows span
        // what the rule generalises over rather than one rejected spelling.
        let mut rows: Vec<String> = vec![
            "usw2-az1".to_string(),
            "nope".to_string(),
            "z".repeat(20),
        ];
        rows.extend(
            resources
                .iter()
                .flat_map(|(_, other_zones)| other_zones.iter())
                .find(|zone| !zones.contains(zone))
                .cloned(),
        );
        for away_from in rows.iter().map(String::as_str) {
            let case = format!("{resource} away from {away_from}");
            let (status, body) = call(
                &router,
                "POST",
                "/zonalshifts",
                &start_body(resource, away_from, "1h", "a zone the resource is not in"),
            )
            .await;
            let message = refusal_message(&case, status, &body, 400, "ValidationException");
            assert_eq!(
                message, INVALID_AZ,
                "case {case:?}: expected {INVALID_AZ:?}, got {message:?}"
            );
            assert_eq!(
                body["reason"], "UnsupportedAz",
                "case {case:?}: expected reason UnsupportedAz, got {body}"
            );
            let mut withheld: Vec<&str> = vec![away_from, resource.as_str()];
            withheld.extend(zones.iter().map(String::as_str));
            states_nothing_of(&case, &message, &withheld);
        }
    }
}

#[tokio::test]
async fn an_expires_in_past_the_documented_maximum_states_the_rule_without_the_value() {
    // The documented bound is "up to three days (72 hours)"
    // (`smithy_query(query="doc", shape="StartZonalShiftRequest", member="expiresIn")`),
    // so each published end — in hours and in minutes — is accepted and one step past it
    // is refused, in both units and well beyond.
    let (router, engine) = emulator();
    let (resource, zones) = seeded(&engine)[0].clone();
    for expires_in in ["72h", "4320m"] {
        let (status, body) = call(
            &router,
            "POST",
            "/zonalshifts",
            &start_body(&resource, &zones[0], expires_in, "at the maximum"),
        )
        .await;
        assert_eq!(
            status, 201,
            "case expiresIn={expires_in}: the published maximum is accepted, got {status} {body}"
        );
        let shift_id = body["zonalShiftId"].as_str().unwrap_or_default().to_string();
        let (status, body) = call(&router, "DELETE", &format!("/zonalshifts/{shift_id}"), "").await;
        assert_eq!(
            status, 200,
            "case expiresIn={expires_in}: the shift cancels so the next row is not a \
             conflict, got {status} {body}"
        );
    }

    // A shift to update, so the same class is reached from the operation that re-expires
    // a running shift as well as from the one that starts it.
    let (status, running) = call(
        &router,
        "POST",
        "/zonalshifts",
        &start_body(&resource, &zones[0], "1h", "a running shift"),
    )
    .await;
    assert_eq!(status, 201, "the shift to update starts, got {running}");
    let running_id = running["zonalShiftId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    for expires_in in ["73h", "99h", "4321m", "9999h"] {
        for (op, method, uri, payload) in [
            (
                "start",
                "POST",
                "/zonalshifts".to_string(),
                start_body(&resource, &zones[0], expires_in, "past the maximum"),
            ),
            (
                "update",
                "PATCH",
                format!("/zonalshifts/{running_id}"),
                serde_json::json!({ "expiresIn": expires_in }).to_string(),
            ),
        ] {
            let case = format!("{op} with expiresIn={expires_in}");
            let (status, body) = call(&router, method, &uri, &payload).await;
            let message = refusal_message(&case, status, &body, 400, "ValidationException");
            assert_eq!(
                body["reason"], "InvalidExpiresIn",
                "case {case:?}: expected reason InvalidExpiresIn, got {body}"
            );
            states_nothing_of(&case, &message, &[expires_in, &resource, &running_id]);
        }
    }

    // The refused rows left the running shift exactly as it was, so nothing about the
    // store followed from a refusal.
    let (status, read_back) = call(
        &router,
        "GET",
        &format!("/zonalshifts?resourceIdentifier={}", encoded(&resource)),
        "",
    )
    .await;
    assert_eq!(status, 200, "the shifts list reads back, got {read_back}");
    let items = read_back["items"]
        .as_array()
        .expect("items is a list")
        .iter()
        .filter(|item| item["zonalShiftId"] == serde_json::json!(running_id))
        .count();
    assert_eq!(
        items, 1,
        "the shift the refused updates named is still the one shift held, got {read_back}"
    );
}

#[tokio::test]
async fn an_expires_in_outside_its_pattern_states_the_member_and_the_pattern_only() {
    // The other half: a value the framework's constraint walk refuses. The member sits in
    // the operation's own input shape, so the clause states its position and the pattern
    // the model declares, and the value the caller sent stays out. Rows inside
    // `ExpiresIn`'s `@length` 2..5 so each breaks exactly one constraint.
    let (router, engine) = emulator();
    let (resource, zones) = seeded(&engine)[0].clone();
    for expires_in in ["1H", "0h", "12d", "1 h", "01h"] {
        let case = format!("start with expiresIn={expires_in}");
        let (status, body) = call(
            &router,
            "POST",
            "/zonalshifts",
            &start_body(&resource, &zones[0], expires_in, "outside the pattern"),
        )
        .await;
        let message = refusal_message(&case, status, &body, 400, "ValidationException");
        assert_eq!(
            message, EXPIRES_IN_PATTERN_CLAUSE,
            "case {case:?}: expected {EXPIRES_IN_PATTERN_CLAUSE:?}, got {message:?}"
        );
        states_nothing_of(&case, &message, &[expires_in, &resource]);
    }
}
