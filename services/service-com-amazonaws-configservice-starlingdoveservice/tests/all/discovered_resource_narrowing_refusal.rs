// SPDX-License-Identifier: CC0-1.0

//! How a discovered-resource listing words the refusal of a request that asked to be
//! narrowed two ways at once, over the wire.
//!
//! The rule pinned here: a `ListDiscoveredResources` request carrying BOTH resource ids
//! and a resource name is refused 400 `ValidationException` worded as Config words that
//! mutual exclusion — "Both Resource ID and Resource Name cannot be specified in the
//! request" — fixed text that is the same for every such request: it names neither the
//! operation nor the wire member spellings, carries no part of the request (no resource
//! type, no resource id, no resource name, no limit, no count) and appends no
//! remediation step. A request that narrows ONE way is served, so the refusal is about
//! the pair rather than about either narrowing.
//!
//! An HTTP status and an error code are not the whole contract of a refusal: the
//! `message` is what a client surfaces, logs and branches on, so this refusal class has
//! ONE sentence and it is the sentence AWS words for it.
//!
//! Every case drives the emulator the way a client does — an `awsJson1_1` `POST /`
//! through the same `MultiServiceRouter` the production router builds — over the
//! inventory the `discovered_resources` suite seeds its own reads with.

use serde_json::{json, Value};

use crate::config_setup_and_rule_loop::Emulator;
use crate::discovered_resources::{
    emulator_discovering, live, named, reported_ids, Discovered, DYNAMODB_TABLE, EC2_VOLUME,
    MAX_RESOURCE_IDS, S3_BUCKET,
};

/// The sentence Config words this refusal with. RECORDED behaviour: the model states no
/// text for `ValidationException`, and the message is entirely fixed — it interpolates
/// nothing from the request.
const EXPECTED_MESSAGE: &str =
    "Both Resource ID and Resource Name cannot be specified in the request";

/// The inventory every case here reads: two named resources of different types and two
/// unnamed ones, so a narrowing by name and a narrowing by id each match something.
fn inventory() -> Vec<Discovered> {
    vec![
        named(EC2_VOLUME, "vol-0001", "data-volume"),
        live(EC2_VOLUME, "vol-0002"),
        named(DYNAMODB_TABLE, "orders", "orders-table"),
        live(S3_BUCKET, "config-bucket"),
    ]
}

/// Call `ListDiscoveredResources` with `request`, require a 400 `ValidationException`,
/// and answer the message the refusal was worded with.
async fn refusal_message(case: &str, emulator: &Emulator, request: &Value) -> String {
    let (status, parsed) = emulator.call("ListDiscoveredResources", request).await;
    assert_eq!(
        status, 400,
        "case {case:?}: expected HTTP 400, got {status} with {parsed}"
    );
    let code = parsed["__type"]
        .as_str()
        .map(|wire| wire.rsplit('#').next().unwrap_or(wire))
        .unwrap_or("<none>");
    assert_eq!(
        code, "ValidationException",
        "case {case:?}: expected the error code ValidationException, got {code:?} in {parsed}"
    );
    parsed["message"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: expected a message in {parsed}"))
        .to_string()
}

#[tokio::test]
async fn narrowing_by_ids_and_by_name_at_once_is_refused_with_configs_own_sentence() {
    let twenty_ids: Vec<String> = (0..MAX_RESOURCE_IDS)
        .map(|index| format!("vol-{index:04}"))
        .collect();

    // Rows differ along everything the sentence could have interpolated and does not:
    // the resource type asked about (including one nothing was discovered for), how many
    // resource ids the request narrows by (one, several, the published maximum of 20),
    // whether those ids and that name match anything in the inventory, and the other
    // members a listing may carry (`limit`, `includeDeletedResources`, `nextToken`).
    let cases: [(&str, Value); 8] = [
        (
            "one id and a name both matching a resource",
            json!({
                "resourceType": EC2_VOLUME,
                "resourceIds": ["vol-0001"],
                "resourceName": "data-volume",
            }),
        ),
        (
            "one id and a name matching nothing",
            json!({
                "resourceType": EC2_VOLUME,
                "resourceIds": ["vol-0404"],
                "resourceName": "no-such-name",
            }),
        ),
        (
            "several ids and a name",
            json!({
                "resourceType": EC2_VOLUME,
                "resourceIds": ["vol-0001", "vol-0002"],
                "resourceName": "data-volume",
            }),
        ),
        (
            "the maximum number of ids and a name",
            json!({
                "resourceType": EC2_VOLUME,
                "resourceIds": twenty_ids,
                "resourceName": "data-volume",
            }),
        ),
        (
            "another resource type entirely",
            json!({
                "resourceType": DYNAMODB_TABLE,
                "resourceIds": ["orders"],
                "resourceName": "orders-table",
            }),
        ),
        (
            "a resource type nothing was discovered for",
            json!({
                "resourceType": "AWS::IAM::Role",
                "resourceIds": ["AROAEXAMPLEID"],
                "resourceName": "config-role",
            }),
        ),
        (
            "a page size and deleted resources asked for as well",
            json!({
                "resourceType": S3_BUCKET,
                "resourceIds": ["config-bucket"],
                "resourceName": "config-bucket",
                "limit": 7,
                "includeDeletedResources": true,
            }),
        ),
        (
            "a nextToken that is not one this operation issued",
            json!({
                "resourceType": EC2_VOLUME,
                "resourceIds": ["vol-0002"],
                "resourceName": "data-volume",
                "nextToken": "!!! not a token !!!",
            }),
        ),
    ];

    let emulator = emulator_discovering(&inventory()).await;
    for (case, request) in cases {
        let message = refusal_message(case, &emulator, &request).await;
        assert_eq!(
            message, EXPECTED_MESSAGE,
            "case {case:?}: expected the refusal to be worded {EXPECTED_MESSAGE:?}, got \
             {message:?}"
        );
        // The sentence is fixed, so nothing the request carried can appear in it: not the
        // type, not an id, not the name, not the operation, not a member spelling.
        for quoted in [
            request["resourceType"].as_str().unwrap_or_default(),
            request["resourceName"].as_str().unwrap_or_default(),
            request["resourceIds"][0].as_str().unwrap_or_default(),
            "ListDiscoveredResources",
            "resourceIds",
            "resourceName",
        ] {
            assert!(
                !quoted.is_empty(),
                "case {case:?}: every row states the type, the ids and the name it was \
                 refused for, got {request}"
            );
            assert!(
                !message.contains(quoted),
                "case {case:?}: the refusal must carry no part of the request, found \
                 {quoted:?} in {message:?}"
            );
        }
    }
}

#[tokio::test]
async fn narrowing_one_way_is_served_so_the_refusal_is_about_the_pair() {
    let emulator = emulator_discovering(&inventory()).await;

    // Each half of the refused request on its own: the ids, then the name.
    for (case, request, expected) in [
        (
            "the resource ids alone",
            json!({ "resourceType": EC2_VOLUME, "resourceIds": ["vol-0001"] }),
            ["vol-0001"],
        ),
        (
            "the resource name alone",
            json!({ "resourceType": EC2_VOLUME, "resourceName": "data-volume" }),
            ["vol-0001"],
        ),
    ] {
        let body = emulator.ok("ListDiscoveredResources", &request).await;
        assert_eq!(
            reported_ids(case, &body),
            expected,
            "case {case:?}: expected the resource ids {expected:?}, got {body}"
        );
    }
}
