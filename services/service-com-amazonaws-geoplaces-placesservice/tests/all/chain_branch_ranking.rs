// SPDX-License-Identifier: CC0-1.0

//! A result item describes ONE place: the `Address` the catalog record carries, the
//! WGS 84 `Position` of that address, and the `Distance` between the queried
//! position and that `Position` — which is also the key the ranked list is ordered
//! by.
//!
//! The class the rule generalises over is the chain whose branches stand at varied
//! distances around one locality: the ranked list is read at several query
//! positions and several page sizes, and the order, the addresses and the distances
//! are all checked against an INDEPENDENT oracle computed in this file from the
//! branch table below, so no row of the table can be satisfied by a list that
//! merely has the right length.
//!
//! The same item is then read back by `PlaceId` through GetPlace, so the record a
//! ranked list named is the record the handle resolves to.

use serde_json::{json, Value};

use crate::places_catalog::{distance, items, position, text, Emulator};
use crate::result_item_composition::address;

const SEARCH_TEXT: &str = "/v2/search-text";
const SEARCH_NEARBY: &str = "/v2/search-nearby";

/// Mean Earth radius in metres (IUGG), the sphere a great-circle distance in
/// `Distance` — "the distance in meters from the QueryPosition" — is measured on.
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// Metres a reported `Distance` may differ from this file's own oracle: the
/// service reports whole metres, so only the rounding of the last one is free.
const DISTANCE_TOLERANCE_M: f64 = 1.0;

/// One branch of the business chain the catalog seeds around Seattle, as the
/// catalog's own record holds it (`seed_catalog` in `src/state.rs`): the brand
/// title the place data writes, the branch's street address, and the WGS 84
/// position of that address.
///
/// Every record the catalog holds for the chain is a row here, including the ones
/// a distance-ranked page never reaches from the anchors below, so the table is
/// the chain and not a result set.
#[derive(Debug, Clone, Copy)]
struct Branch {
    title: &'static str,
    address_number: &'static str,
    street: &'static str,
    postal_code: &'static str,
    district: &'static str,
    /// `[longitude, latitude]`, the order every modeled `Position` carries.
    position: [f64; 2],
}

/// The chain's branches in the catalog, listed north to south. The chain is the
/// one `BusinessChains.Name` the catalog seeds several stores for.
const BRANCHES: [Branch; 7] = [
    Branch {
        title: "STARBUCKS",
        address_number: "500",
        street: "Mercer St",
        postal_code: "98109-4654",
        district: "Lower Queen Anne",
        position: [-122.347_26, 47.624_72],
    },
    Branch {
        title: "STARBUCKS",
        address_number: "442",
        street: "Terry Ave N",
        postal_code: "98109-5210",
        district: "South Lake Union",
        position: [-122.336_95, 47.622_87],
    },
    Branch {
        title: "STARBUCKS",
        address_number: "2011",
        street: "7th Ave",
        postal_code: "98121-2601",
        district: "Belltown",
        position: [-122.338_22, 47.615_23],
    },
    Branch {
        title: "STARBUCKS RESERVE ROASTERY",
        address_number: "1124",
        street: "Pike St",
        postal_code: "98101",
        district: "Capitol Hill",
        position: [-122.327_29, 47.614_04],
    },
    Branch {
        title: "STARBUCKS",
        address_number: "1912",
        street: "Pike Pl",
        postal_code: "98101",
        district: "Downtown",
        position: [-122.340_62, 47.610_10],
    },
    Branch {
        title: "STARBUCKS",
        address_number: "102",
        street: "Pike St",
        postal_code: "98101",
        district: "Downtown",
        position: [-122.339_50, 47.608_20],
    },
    Branch {
        title: "STARBUCKS",
        address_number: "701",
        street: "5th Ave",
        postal_code: "98104",
        district: "Downtown",
        position: [-122.330_60, 47.604_40],
    },
];

/// The free-form text that names the chain, so every row of [`BRANCHES`] is a
/// match and nothing else is.
const CHAIN_QUERY: &str = "Starbucks";

/// A position a query is asked from: a landmark, a neighbourhood centre, and one
/// well outside the locality, so the branch order the oracle computes differs from
/// row to row instead of being the table's own order.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    case: &'static str,
    position: [f64; 2],
}

const ANCHORS: [Anchor; 6] = [
    Anchor {
        case: "seattle-center",
        position: [-122.3493, 47.6205],
    },
    Anchor {
        case: "pike-place-market",
        position: [-122.340_81, 47.608_849],
    },
    Anchor {
        case: "pioneer-square",
        position: [-122.3343, 47.6016],
    },
    Anchor {
        case: "south-lake-union",
        position: [-122.3370, 47.6260],
    },
    Anchor {
        case: "capitol-hill",
        position: [-122.3125, 47.6150],
    },
    Anchor {
        case: "bellevue",
        position: [-122.2015, 47.6101],
    },
];

/// The great-circle distance in whole metres between two WGS 84 positions: this
/// file's own oracle for `Distance`, written from the haversine formula rather than
/// borrowed from the service.
fn metres_apart(from: [f64; 2], to: [f64; 2]) -> f64 {
    let (lon1, lat1) = (from[0].to_radians(), from[1].to_radians());
    let (lon2, lat2) = (to[0].to_radians(), to[1].to_radians());
    let half_lat = ((lat2 - lat1) / 2.0).sin();
    let half_lon = ((lon2 - lon1) / 2.0).sin();
    let chord = half_lat * half_lat + lat1.cos() * lat2.cos() * half_lon * half_lon;
    2.0 * EARTH_RADIUS_M * chord.clamp(0.0, 1.0).sqrt().asin()
}

/// [`BRANCHES`] ordered as a query from `anchor` must rank them: nearest first.
///
/// The ordering is strict — the assertion below checks that no two branches are at
/// the same distance from an anchor, so the expected order is the only one.
fn ranked_from(anchor: [f64; 2]) -> Vec<(Branch, f64)> {
    let mut ranked: Vec<(Branch, f64)> = BRANCHES
        .iter()
        .map(|branch| (*branch, metres_apart(anchor, branch.position)))
        .collect();
    ranked.sort_by(|left, right| left.1.total_cmp(&right.1));
    ranked
}

/// A member of one item's `Address`.
fn address_member(item: &Value, member: &str) -> String {
    text(&address(item), member)
}

/// The first `StreetComponents` entry of one item's address, or `Value::Null`.
fn street_component(item: &Value) -> Value {
    address(item)
        .get("StreetComponents")
        .and_then(Value::as_array)
        .and_then(|components| components.first().cloned())
        .unwrap_or(Value::Null)
}

/// Every reported branch names its own address and its own position, whichever
/// slot of the ranked list it lands in: `Address`, `Position` and `Distance` are
/// read together and all three are checked against the row of [`BRANCHES`] the
/// oracle puts in that slot.
/// `expected_metres` is `None` where the request named no position to measure from:
/// there the item must carry NO `Distance` member at all, rather than the modeled
/// default of zero.
fn assert_item_is(case: &str, item: &Value, branch: &Branch, expected_metres: Option<f64>) {
    assert_eq!(
        text(item, "Title"),
        branch.title,
        "case {case}: expected the branch at {:?}, got {:?}",
        branch.position,
        item
    );
    assert_eq!(
        (
            address_member(item, "AddressNumber"),
            address_member(item, "Street"),
            address_member(item, "PostalCode"),
            address_member(item, "District"),
        ),
        (
            branch.address_number.to_string(),
            branch.street.to_string(),
            branch.postal_code.to_string(),
            branch.district.to_string(),
        ),
        "case {case}: expected the address of {branch:?}, got {:?}",
        address(item)
    );
    let label = address_member(item, "Label");
    for part in [branch.address_number, branch.street, branch.postal_code] {
        assert!(
            label.contains(part),
            "case {case}: expected the assembled label to carry {part:?}, got {label:?}"
        );
    }
    // The street as its components: the directional words, the base name and the
    // type word reassemble into the street the address reports.
    let component = street_component(item);
    let (prefix, base_name, kind, suffix, placement) = (
        text(&component, "Prefix"),
        text(&component, "BaseName"),
        text(&component, "Type"),
        text(&component, "Suffix"),
        text(&component, "TypePlacement"),
    );
    // `TypePlacement` says which side of the base name the type word sits on.
    let named = if placement == "BeforeBaseName" {
        [prefix, kind, base_name, suffix]
    } else {
        [prefix, base_name, kind, suffix]
    };
    let reassembled = named
        .iter()
        .filter(|word| !word.is_empty())
        .cloned()
        .collect::<Vec<String>>()
        .join(" ");
    assert_eq!(
        reassembled, branch.street,
        "case {case}: expected the street components of {:?}, got {component:?}",
        branch.street
    );
    assert_eq!(
        position(item),
        vec![branch.position[0], branch.position[1]],
        "case {case}: expected the position of {branch:?}, got {:?}",
        position(item)
    );
    match expected_metres {
        Some(expected) => {
            let reported = distance(item) as f64;
            assert!(
                (reported - expected).abs() <= DISTANCE_TOLERANCE_M,
                "case {case}: expected Distance {expected:.1} m from the queried position \
                 to {:?}, got {reported} m",
                branch.position
            );
        }
        None => assert!(
            item.get("Distance").is_none(),
            "case {case}: expected no Distance member with no position to measure from, \
             got {:?}",
            item.get("Distance")
        ),
    }
}

/// A ranked search returns the branches NEAREST the position it was asked from, in
/// distance order, each reporting its own address, its own position and the
/// distance between the two positions.
///
/// The rows differ along the position asked from (four points inside the locality
/// and one outside it, each putting the branches in a different order) and along
/// the page size (one branch, a few, every branch, more than there are), so the
/// rule is read off the whole ladder rather than one result set.
#[tokio::test]
async fn search_text_ranks_the_chain_branches_by_distance_from_the_queried_position() {
    let emulator = Emulator::new();
    for anchor in ANCHORS {
        let ranked = ranked_from(anchor.position);
        for pair in ranked.windows(2) {
            assert!(
                pair[1].1 - pair[0].1 > DISTANCE_TOLERANCE_M,
                "case {}: the anchors must rank the branches strictly, got {:?} and {:?} \
                 at {:.1} m and {:.1} m",
                anchor.case,
                pair[0].0.position,
                pair[1].0.position,
                pair[0].1,
                pair[1].1
            );
        }

        for page_size in [1_usize, 3, BRANCHES.len(), BRANCHES.len() + 5] {
            let case = format!("{}-max-results-{page_size}", anchor.case);
            let body = emulator
                .post_ok(
                    &case,
                    SEARCH_TEXT,
                    &json!({
                        "QueryText": CHAIN_QUERY,
                        "BiasPosition": [anchor.position[0], anchor.position[1]],
                        "MaxResults": page_size,
                    }),
                )
                .await;
            let returned = items(&body);
            let expected = page_size.min(BRANCHES.len());
            assert_eq!(
                returned.len(),
                expected,
                "case {case}: expected {expected} of the {} branches, got {:?}",
                BRANCHES.len(),
                returned
                    .iter()
                    .map(|item| address_member(item, "Label"))
                    .collect::<Vec<_>>()
            );
            for (slot, item) in returned.iter().enumerate() {
                let (branch, metres) = ranked[slot];
                assert_item_is(&format!("{case}-slot-{slot}"), item, &branch, Some(metres));
            }
        }
    }
}

/// The handle a ranked item hands out resolves to the record that item described:
/// GetPlace answers with the same title, the same address and the same position,
/// so a client that keeps a `PlaceId` keeps the place and not the slot.
#[tokio::test]
async fn a_ranked_branch_resolves_through_get_place_to_the_same_record() {
    let emulator = Emulator::new();
    let anchor = ANCHORS[0];
    let ranked = ranked_from(anchor.position);
    let body = emulator
        .post_ok(
            anchor.case,
            SEARCH_TEXT,
            &json!({
                "QueryText": CHAIN_QUERY,
                "BiasPosition": [anchor.position[0], anchor.position[1]],
                "MaxResults": BRANCHES.len(),
            }),
        )
        .await;
    let returned = items(&body);
    assert_eq!(
        returned.len(),
        BRANCHES.len(),
        "case {}: expected every branch, got {returned:?}",
        anchor.case
    );
    for (slot, item) in returned.iter().enumerate() {
        let (branch, _) = ranked[slot];
        let place_id = text(item, "PlaceId");
        let case = format!("{}-get-place-{slot}", anchor.case);
        let place = emulator
            .get_ok(&case, &format!("/v2/place/{place_id}"))
            .await;
        // GetPlace reports no `Distance`: there is no queried position to measure
        // from, so the read-back is checked against the record alone.
        assert_item_is(&case, &place, &branch, None);
    }
}

/// `SearchNearby` ranks and bounds the same records by the same distance: every
/// branch inside the radius, in distance order, and none outside it — so the rule
/// is not one operation's own arrangement of the catalog.
///
/// The rows differ along the radius, which is what the bound generalises over:
/// one that reaches no branch, ones that reach part of the chain, and one that
/// reaches all of it.
#[tokio::test]
async fn search_nearby_bounds_and_ranks_the_same_branches_by_the_same_distance() {
    let emulator = Emulator::new();
    let anchor = ANCHORS[0];
    let ranked = ranked_from(anchor.position);
    // `QueryRadius` is `DistanceMeters`, `@range 1..21000000`.
    for radius in [1_i64, 600, 1_100, 2_000, 5_000] {
        let case = format!("{}-radius-{radius}", anchor.case);
        let body = emulator
            .post_ok(
                &case,
                SEARCH_NEARBY,
                &json!({
                    "QueryPosition": [anchor.position[0], anchor.position[1]],
                    "QueryRadius": radius,
                    "MaxResults": 100,
                }),
            )
            .await;
        let inside: Vec<&(Branch, f64)> = ranked
            .iter()
            .filter(|(_, metres)| metres.round() as i64 <= radius)
            .collect();
        let branches: Vec<Value> = items(&body)
            .into_iter()
            .filter(|item| text(item, "Title").starts_with("STARBUCKS"))
            .collect();
        assert_eq!(
            branches.len(),
            inside.len(),
            "case {case}: expected the {} branch(es) within {radius} m, got {:?}",
            inside.len(),
            branches
                .iter()
                .map(|item| address_member(item, "Label"))
                .collect::<Vec<_>>()
        );
        for (slot, item) in branches.iter().enumerate() {
            let (branch, metres) = inside[slot];
            assert_item_is(&format!("{case}-slot-{slot}"), item, branch, Some(*metres));
        }
    }
}
