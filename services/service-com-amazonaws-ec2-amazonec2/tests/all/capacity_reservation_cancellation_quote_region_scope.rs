// SPDX-License-Identifier: CC0-1.0

//! The Region a Capacity Reservation cancellation quote is generated in.
//!
//! `CreateCapacityReservationCancellationQuote` names the reservation it quotes by id, and a
//! Capacity Reservation reserves capacity in ONE Availability Zone
//! (`CreateCapacityReservationRequest$AvailabilityZone`), so it belongs to the one Region
//! that zone is in. The rule under test: the generate resolves the id it is given among the
//! reservations of the REGION the request was signed for — it quotes one of that Region out
//! of the commitment and capacity the store holds for it, and reports an id held only by a
//! reservation of another Region as a reservation that does not exist
//! (`InvalidCapacityReservationId.NotFound`, the sentence EC2 words for a
//! capacity-reservation id it cannot resolve), writing nothing.
//!
//! Driven over the wire the service speaks: ec2Query — an
//! `application/x-www-form-urlencoded` POST whose body carries `Action=…`, answered with XML
//! (README.md / OPERATIONS.md "Wire protocol"). The Region of a call is the one in its SigV4
//! credential scope, which is what the harness varies per row.
//!
//! The table's rows differ along what the rule generalises over: which Region holds the
//! reservation, which Availability Zone of it the capacity sits in, which instance family
//! and how much capacity is reserved, how far ahead the reservation starts and how long it
//! committed for. Every row is then quoted from its own Region AND from every other row's,
//! so no single Region is the specification.

use std::time::Duration;

use ec2::state::{
    CAPACITY_RESERVATION_CANCELLATION_QUOTE_ID_PREFIX, CAPACITY_RESERVATION_STATE_SCHEDULED,
    INVALID_CAPACITY_RESERVATION_ID_NOT_FOUND, iso8601_utc,
};
use service_com_amazonaws_ec2_amazonec2 as ec2;
use smithy_server_runtime::MultiServiceRouter;

// The readings of this operation's wire shape, and the store count behind it, are the sibling
// suite's: that module compiles into the SAME test binary, so the quote parser and the start
// date live in one place rather than in two copies that can drift.
use super::capacity_reservation_cancellation_quotes::{
    ReportedQuote, reported_quote, start_date, stored_count,
};
use super::ec2_query::{element, error_code, error_message};
use super::wire::{child, child_text, document, is_long_id};

/// The platform every reservation here reserves capacity for: a member of
/// `CapacityReservationInstancePlatform`
/// (`smithy_query(query="shape",shape="CapacityReservationInstancePlatform")`).
const INSTANCE_PLATFORM: &str = "Linux/UNIX";

/// "If you are requesting a future-dated Capacity Reservation, you must specify `targeted`"
/// (`CreateCapacityReservationRequest$InstanceMatchCriteria`).
const INSTANCE_MATCH_CRITERIA_TARGETED: &str = "targeted";

/// "The only supported value is `incremental`"
/// (`CreateCapacityReservationRequest$DeliveryPreference`).
const DELIVERY_PREFERENCE: &str = "incremental";

/// One row: a Region, and the future-dated Capacity Reservation created in it.
struct RegionCase {
    /// The Region the row's reservation lives in — also what the row is called in an
    /// assertion.
    region: &'static str,
    /// The Availability Zone the capacity is reserved in. Every Region of this emulator has
    /// the zones `<region>a`, `<region>b` and `<region>c`
    /// (`ec2::state::availability_zones_in_region`), so the rows reserve in different ones.
    zone: &'static str,
    /// A member of the modelled `InstanceType` catalog, in one of the families a
    /// future-dated reservation may reserve ("the C, M, R, I, T, and G instance families
    /// only", `CreateCapacityReservationRequest$InstanceType`).
    instance_type: &'static str,
    /// "The number of instances for which to reserve capacity" (`InstanceCount`).
    instance_count: i32,
    /// How far ahead the reservation starts: "between 5 and 120 days in advance"
    /// (`StartDate`).
    lead_days: u64,
    /// "Specify a commitment duration, in seconds" (`CommitmentDuration`).
    commitment_seconds: u64,
}

/// The Regions the rule is asserted over.
fn region_cases() -> Vec<RegionCase> {
    vec![
        RegionCase {
            region: "us-east-1",
            zone: "us-east-1a",
            instance_type: "c5.xlarge",
            instance_count: 2,
            lead_days: 5,
            commitment_seconds: 24 * 60 * 60,
        },
        RegionCase {
            region: "us-west-2",
            zone: "us-west-2b",
            instance_type: "m5.large",
            instance_count: 11,
            // A commitment that is not a whole number of hours, so the row also spans the
            // part hour the charge is published in whole hours of.
            lead_days: 30,
            commitment_seconds: 3 * 24 * 60 * 60 + 30 * 60,
        },
        RegionCase {
            region: "eu-central-1",
            zone: "eu-central-1c",
            instance_type: "r5.large",
            instance_count: 1,
            lead_days: 119,
            commitment_seconds: 365 * 24 * 60 * 60,
        },
    ]
}

/// The form fields that create the future-dated reservation of `case`.
fn reservation_params(case: &RegionCase) -> Vec<(String, String)> {
    vec![
        ("InstanceType".to_string(), case.instance_type.to_string()),
        ("InstancePlatform".to_string(), INSTANCE_PLATFORM.to_string()),
        ("InstanceCount".to_string(), case.instance_count.to_string()),
        ("AvailabilityZone".to_string(), case.zone.to_string()),
        (
            "InstanceMatchCriteria".to_string(),
            INSTANCE_MATCH_CRITERIA_TARGETED.to_string(),
        ),
        (
            "StartDate".to_string(),
            iso8601_utc(start_date(case.lead_days)),
        ),
        (
            "CommitmentDuration".to_string(),
            case.commitment_seconds.to_string(),
        ),
        (
            "DeliveryPreference".to_string(),
            DELIVERY_PREFERENCE.to_string(),
        ),
    ]
}

/// Create the future-dated Capacity Reservation of `case` in its own Region and answer its
/// id.
async fn create_future_dated(router: &MultiServiceRouter, case: &RegionCase) -> String {
    let (status, body) = super::ec2_query::call(
        router,
        case.region,
        "CreateCapacityReservation",
        &reservation_params(case),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {:?}: expected the reservation to be created, got {status} with body {body}",
        case.region
    );
    element(&body, "capacityReservationId")
        .unwrap_or_else(|| panic!("case {:?}: expected a reservation id in {body}", case.region))
}

/// Look again at the reservation `reservation_id` names, in its own Region, until it reports
/// the `scheduled` state the clock owes a future-dated request once its assessment falls
/// due, as a client's readiness waiter does. The deadline is generous: all it bounds is a
/// hang.
async fn poll_until_scheduled(
    router: &MultiServiceRouter,
    case: &RegionCase,
    reservation_id: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let (status, body) = super::ec2_query::call(
            router,
            case.region,
            "DescribeCapacityReservations",
            &[(
                "CapacityReservationId.1".to_string(),
                reservation_id.to_string(),
            )],
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: expected HTTP 200 describing {reservation_id}, got {status} with \
             body {body}",
            case.region
        );
        let reported = described_state(case.region, &body);
        if reported == CAPACITY_RESERVATION_STATE_SCHEDULED {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "case {:?}: waited for {reservation_id} to report \
             {CAPACITY_RESERVATION_STATE_SCHEDULED}, it reports {reported:?}",
            case.region
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The `state` of the one reservation a `DescribeCapacityReservations` response carries: the
/// element that has a `capacityReservationId` child, read through the XML tree so a nested
/// member of the same name is never taken for the reservation's own.
fn described_state(case: &str, body: &str) -> String {
    let parsed = document(case, body);
    parsed
        .descendants()
        .find(|node| node.is_element() && child(*node, "capacityReservationId").is_some())
        .and_then(|node| child_text(node, "state"))
        .unwrap_or_default()
}

/// One `CreateCapacityReservationCancellationQuote` call signed for `region`, naming
/// `reservation_id`.
async fn generate(
    router: &MultiServiceRouter,
    region: &str,
    reservation_id: &str,
) -> (u16, String) {
    super::ec2_query::call(
        router,
        region,
        "CreateCapacityReservationCancellationQuote",
        &[(
            "CapacityReservationId".to_string(),
            reservation_id.to_string(),
        )],
    )
    .await
}

/// One `DescribeCapacityReservationCancellationQuotes` call signed for `region`, narrowed to
/// `quote_id`.
async fn describe_quote(
    router: &MultiServiceRouter,
    region: &str,
    quote_id: &str,
) -> (u16, String) {
    super::ec2_query::call(
        router,
        region,
        "DescribeCapacityReservationCancellationQuotes",
        &[(
            "CapacityReservationCancellationQuoteId.1".to_string(),
            quote_id.to_string(),
        )],
    )
    .await
}

/// The whole rule: a reservation is quoted in its own Region and reported absent in every
/// other, and only the quotes the successful generates minted are stored.
#[tokio::test]
async fn a_reservation_is_quoted_only_in_the_region_that_holds_it() {
    let (router, engine) = super::ec2_query::emulator();
    let cases = region_cases();

    // Every reservation is created first, so the three assessments the clock owes run
    // together rather than one after another.
    let mut reservations = Vec::new();
    for case in &cases {
        reservations.push(create_future_dated(&router, case).await);
    }
    for (case, reservation_id) in cases.iter().zip(&reservations) {
        poll_until_scheduled(&router, case, reservation_id).await;
    }

    let mut quoted = 0usize;
    for (case, reservation_id) in cases.iter().zip(&reservations) {
        let region = case.region;

        // The Region that holds the reservation quotes it, out of what the store holds for
        // it.
        let (status, body) = generate(&router, region, reservation_id).await;
        assert_eq!(
            status, 200,
            "case {region:?}: expected the reservation's own Region to quote it, got \
             {status} with body {body}"
        );
        let quote = reported_quote(region, &body);
        assert!(
            is_long_id(
                CAPACITY_RESERVATION_CANCELLATION_QUOTE_ID_PREFIX,
                &quote.id
            ),
            "case {region:?}: expected a \
             {CAPACITY_RESERVATION_CANCELLATION_QUOTE_ID_PREFIX}-<17 hex digits> quote id, \
             got {:?}",
            quote.id
        );
        assert_eq!(
            quote.capacity_reservation_id, *reservation_id,
            "case {region:?}: expected the quote to name the reservation it quotes, got {:?}",
            quote.capacity_reservation_id
        );
        assert_eq!(
            quote.configuration_instance_count,
            case.instance_count.to_string(),
            "case {region:?}: expected the configuration to report the capacity reserved in \
             this Region, got {:?}",
            quote.configuration_instance_count
        );
        assert_eq!(
            quote.configuration_reservation_state, CAPACITY_RESERVATION_STATE_SCHEDULED,
            "case {region:?}: expected the configuration to report the state the \
             reservation is in, got {:?}",
            quote.configuration_reservation_state
        );
        let committed: Vec<String> = quote
            .terms
            .iter()
            .map(|terms| terms.committed_instance_count.clone())
            .collect();
        assert_eq!(
            committed,
            vec![case.instance_count.to_string()],
            "case {region:?}: expected the terms to carry the capacity that stays under \
             commitment, got {:?}",
            quote.terms
        );
        quoted += 1;
        assert_eq!(
            stored_count(&engine),
            quoted,
            "case {region:?}: expected the generate to store the one quote it reported, so \
             the store holds {quoted}, got {}",
            stored_count(&engine)
        );

        // The quote the generate stored is the quote a read reports, so the answer came out
        // of the store rather than out of the request.
        let (status, body) = describe_quote(&router, region, &quote.id).await;
        assert_eq!(
            status, 200,
            "case {region:?}: expected HTTP 200 reading the quote back, got {status} with \
             body {body}"
        );
        let read_back = reported_quote(region, &body);
        // Everything but the quote's own state, which the clock may have moved from `pending`
        // to `active` between the two reads and which the sibling suite is what pins.
        assert_eq!(
            ReportedQuote {
                quote_state: quote.quote_state.clone(),
                ..read_back.clone()
            },
            quote,
            "case {region:?}: expected the read to report the quote the generate stored, \
             got {read_back:?}"
        );

        // Every OTHER Region holds no reservation under that id, so it reports one that
        // does not exist — and stores nothing.
        let expected_message =
            format!("The capacity-reservation ID '{reservation_id}' does not exist");
        for other in cases.iter().filter(|other| other.region != region) {
            let label = format!("{} asked for in {}", region, other.region);
            let (status, body) = generate(&router, other.region, reservation_id).await;
            assert_eq!(
                status, 400,
                "case {label:?}: expected HTTP 400 for a reservation of another Region, got \
                 {status} with body {body}"
            );
            assert_eq!(
                error_code(&body),
                INVALID_CAPACITY_RESERVATION_ID_NOT_FOUND,
                "case {label:?}: expected {INVALID_CAPACITY_RESERVATION_ID_NOT_FOUND}, got \
                 {:?}",
                error_code(&body)
            );
            assert_eq!(
                error_message(&body),
                expected_message,
                "case {label:?}: expected the not-found sentence for the id the request \
                 sent, got {:?}",
                error_message(&body)
            );
            assert_eq!(
                stored_count(&engine),
                quoted,
                "case {label:?}: expected the refusal to store nothing, so the store still \
                 holds {quoted}, got {}",
                stored_count(&engine)
            );
        }
    }

    assert_eq!(
        stored_count(&engine),
        cases.len(),
        "expected one stored quote per Region that holds a reservation, got {}",
        stored_count(&engine)
    );
}
