// SPDX-License-Identifier: CC0-1.0

//! The NOTIFICATIONS plugin's channel-configuration API on a domain's data plane, driven
//! over the real wire path: `/_plugins/_notifications/configs`, the route a client creates
//! the channel an alerting monitor's action sends through on.
//!
//! One rule, over a SET of inputs rather than one recorded call:
//!
//! * **a domain's published data plane SERVES the notifications plugin's channel
//!   configuration resource**: a create persists the `config` object the request carries
//!   under the `config_id` it named, or under one the plugin mints for a request naming
//!   none, and the plugin's own get, list, update and delete are each computed from those
//!   persisted records alone — so a channel nobody created is reported by none of them.
//!
//! The rows differ along the CHANNEL KIND (the plugin's own `config_type` values, an SNS
//! channel among them), whether the caller named the id or the plugin minted it, whether
//! the channel carries the enabled flag, and the shape of the kind's own members (a nested
//! object, a header map, a list of recipients) — because the plugin's record is the
//! caller's object, kept as written.
//!
//! Three more suites pin what the route does with a request it will not store (the missing
//! members, the duplicate id, the method the route does not take) and the bound the cluster
//! holds these records to.
//!
//! Everything here goes through the plugin's own HTTP API: nothing reaches into the store to
//! arrange what it then asserts. The harness is this crate's own
//! ([`super::domain_lifecycle`], [`super::domain_rest_data_plane`]). What a channel then
//! DELIVERS — a monitor's trigger publishing its rendered message to the configured SNS
//! topic, and withholding it when the condition is false — is [`super::alerting_monitors`].

use serde_json::{json, Value};
use service_com_amazonaws_opensearch_amazonopensearchservice::state::notifications::NOTIFICATION_CONFIG_QUOTA;

use super::data_source_registry::created_domain;
use super::domain_lifecycle::{Answer, Emulator, DEFAULT_ACCESS_KEY_ID};
use super::domain_rest_data_plane::{endpoint_of, rest, rest_prefixed};

/// The route the plugin's channel configurations live under.
const CONFIGS: &str = "/_plugins/_notifications/configs";

/// One row of the table below: a case name, the id the caller named (`None` to let the
/// plugin mint one), and the `config` object the create carries.
struct Row {
    case: &'static str,
    named_id: Option<&'static str>,
    config: Value,
}

/// The channel kinds a create is exercised over.
///
/// The `config_type` of each is one of the notifications plugin's own channel kinds — the
/// plugin holds a configuration of any of them, and only an Amazon SNS channel is one this
/// process can really deliver through, as this crate's `state::notifications` module
/// documents. The members under the kind's own key are that kind's, so they span the shapes
/// a configuration carries: a nested object of ARNs, a URL, a header map, a list.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "an SNS channel under the id the caller named",
            named_id: Some("sns-ops-channel"),
            config: json!({
                "name": "ops-channel",
                "description": "the topic the monitor alerts on",
                "config_type": "sns",
                "is_enabled": true,
                "sns": {
                    "topic_arn": format!(
                        "arn:aws:sns:us-east-1:{}:alerting-topic",
                        ::engine::emulator_account_id()
                    ),
                    "role_arn": format!(
                        "arn:aws:iam::{}:role/alerting-publisher",
                        ::engine::emulator_account_id()
                    ),
                },
            }),
        },
        Row {
            case: "a Chime channel whose id the plugin mints",
            named_id: None,
            config: json!({
                "name": "chime-room",
                "config_type": "chime",
                "chime": { "url": "https://hooks.chime.aws/incomingwebhooks/room" },
            }),
        },
        Row {
            case: "a Slack channel switched off",
            named_id: Some("slack-quiet"),
            config: json!({
                "name": "slack-quiet",
                "config_type": "slack",
                "is_enabled": false,
                "slack": { "url": "https://hooks.slack.com/services/quiet" },
            }),
        },
        Row {
            case: "a custom webhook carrying a header map",
            named_id: Some("hook-with-headers"),
            config: json!({
                "name": "custom-hook",
                "config_type": "webhook",
                "webhook": {
                    "url": "https://alerts.example.invalid/ingest",
                    "header_params": { "X-Channel": "alerting", "X-Tier": "2" },
                },
            }),
        },
        Row {
            case: "an email group naming a list of recipients",
            named_id: None,
            config: json!({
                "name": "oncall",
                "config_type": "email_group",
                "email_group": {
                    "recipient_list": [
                        { "recipient": "primary@example.invalid" },
                        { "recipient": "secondary@example.invalid" },
                    ],
                },
            }),
        },
    ]
}

/// `POST CONFIGS` with `body`, over the PREFIXED addressing.
async fn create(emulator: &Emulator, domain: &str, body: Value) -> Answer {
    rest_prefixed(emulator, domain, "POST", CONFIGS, Some(body)).await
}

/// The `config_id` an answer carries, or a panic naming the case.
fn created_id(answer: &Answer, case: &str) -> String {
    answer.body["config_id"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: expected the answer to name config_id, got {:?}",
                answer.body
            )
        })
        .to_string()
}

/// The `config_list` an answer carries.
fn config_list(answer: &Answer, case: &str) -> Vec<Value> {
    answer.body["config_list"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: expected the answer to carry config_list, got {:?}",
                answer.body
            )
        })
        .clone()
}

/// The one configuration a read of a single id reports.
fn only_config(answer: &Answer, case: &str) -> Value {
    let listed = config_list(answer, case);
    assert_eq!(
        listed.len(),
        1,
        "case {case:?}: expected exactly one configuration, got {listed:?}"
    );
    listed[0].clone()
}

/// The `error.reason` a refused answer carries.
fn reason(answer: &Answer) -> String {
    answer.body["error"]["reason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The `error.type` a refused answer carries.
fn error_type(answer: &Answer) -> String {
    answer.body["error"]["type"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// RULE: a domain's published data plane serves the notifications plugin's channel
/// configuration resource — a create persists the `config` object the request carries under
/// the id it named or one the plugin minted, and the plugin's own get and list are computed
/// from those persisted records alone.
#[tokio::test]
async fn every_created_channel_configuration_is_persisted_and_read_back_by_the_plugin() {
    let emulator = Emulator::new();
    let domain = "notifications-domain";
    created_domain(&emulator, domain).await;

    // A domain nobody gave a channel holds none: the list is the EMPTY page, not a
    // refusal and not somebody else's records.
    let empty = rest_prefixed(&emulator, domain, "GET", CONFIGS, None).await;
    assert_eq!(
        empty.status, 200,
        "case list(empty): expected 200, got {} with {:?}",
        empty.status, empty.body
    );
    assert_eq!(
        empty.body["total_hits"],
        json!(0),
        "case list(empty): expected no configuration, got {:?}",
        empty.body
    );

    let mut created: Vec<(&'static str, String, Value)> = Vec::new();
    for row in rows() {
        let mut body = json!({ "config": row.config.clone() });
        if let Some(named) = row.named_id {
            body["config_id"] = json!(named);
        }
        let answer = create(&emulator, domain, body).await;
        // The recorded service answers a create either way; what matters is that the
        // create is SERVED and the record it made is readable.
        assert!(
            matches!(answer.status, 200 | 201),
            "case {:?}: expected 200 or 201 from the create, got {} with {:?}",
            row.case,
            answer.status,
            answer.body
        );
        let id = created_id(&answer, row.case);
        match row.named_id {
            Some(named) => assert_eq!(
                id, named,
                "case {:?}: expected the create to keep the id the caller named, got {id:?}",
                row.case
            ),
            None => assert!(
                !id.is_empty(),
                "case {:?}: expected the plugin to mint a config_id, got {id:?}",
                row.case
            ),
        }
        assert!(
            created.iter().all(|(_, held, _)| held != &id),
            "case {:?}: expected a config_id no other configuration holds, got {id:?}",
            row.case
        );
        created.push((row.case, id, row.config));
    }

    // Every record reads back under its own id, with the configuration AS WRITTEN and the
    // two instants the plugin stamps.
    for (case, id, config) in &created {
        let read = rest_prefixed(&emulator, domain, "GET", &format!("{CONFIGS}/{id}"), None).await;
        assert_eq!(
            read.status, 200,
            "case {case:?}: expected 200 reading {id:?} back, got {} with {:?}",
            read.status, read.body
        );
        let held = only_config(&read, case);
        assert_eq!(
            held["config_id"],
            json!(id),
            "case {case:?}: expected the read to report config_id {id:?}, got {held:?}"
        );
        assert_eq!(
            &held["config"], config,
            "case {case:?}: expected the configuration as written, got {:?}",
            held["config"]
        );
        let created_ms = held["created_time_ms"].as_u64().unwrap_or_default();
        let updated_ms = held["last_updated_time_ms"].as_u64().unwrap_or_default();
        assert!(
            created_ms > 0,
            "case {case:?}: expected a created_time_ms the create stamped, got {:?}",
            held["created_time_ms"]
        );
        assert_eq!(
            updated_ms, created_ms,
            "case {case:?}: expected a configuration nobody updated to report its create \
             instant as its last update, got {updated_ms} against {created_ms}"
        );
    }

    // The list reports every record the domain holds — as a SET, since the page's order is
    // the store's and not a promise of this API.
    let listed = rest_prefixed(&emulator, domain, "GET", CONFIGS, None).await;
    assert_eq!(
        listed.status, 200,
        "case list(all): expected 200, got {} with {:?}",
        listed.status, listed.body
    );
    assert_eq!(
        listed.body["total_hits"],
        json!(created.len()),
        "case list(all): expected {} configurations, got {:?}",
        created.len(),
        listed.body
    );
    let listed_ids: Vec<String> = config_list(&listed, "list(all)")
        .iter()
        .map(|held| held["config_id"].as_str().unwrap_or_default().to_string())
        .collect();
    for (case, id, _) in &created {
        assert!(
            listed_ids.contains(id),
            "case {case:?}: expected the list to report {id:?}, got {listed_ids:?}"
        );
    }

    // The list takes the plugin's own `config_id` filter, one id or several.
    let first = created[0].1.clone();
    let third = created[2].1.clone();
    for (case, filter, expected) in [
        ("one id", first.clone(), vec![first.clone()]),
        (
            "two ids",
            format!("{first},{third}"),
            vec![first.clone(), third.clone()],
        ),
        (
            "an id the cluster does not hold",
            "no-such-config".to_string(),
            Vec::new(),
        ),
    ] {
        let filtered = rest_prefixed(
            &emulator,
            domain,
            "GET",
            &format!("{CONFIGS}?config_id={filter}"),
            None,
        )
        .await;
        assert_eq!(
            filtered.status, 200,
            "case filter({case:?}): expected 200, got {} with {:?}",
            filtered.status, filtered.body
        );
        let mut got: Vec<String> = config_list(&filtered, case)
            .iter()
            .map(|held| held["config_id"].as_str().unwrap_or_default().to_string())
            .collect();
        got.sort();
        let mut want = expected;
        want.sort();
        assert_eq!(
            got, want,
            "case filter({case:?}): expected exactly {want:?}, got {got:?}"
        );
        assert_eq!(
            filtered.body["total_hits"],
            json!(got.len()),
            "case filter({case:?}): expected total_hits to count the page, got {:?}",
            filtered.body
        );
    }

    // The SAME route on the HOST the domain published — the addressing
    // `DomainStatus$Endpoint` hands a client — serves the same resource.
    let host = endpoint_of(&emulator, domain);
    let on_host = rest(
        &emulator,
        DEFAULT_ACCESS_KEY_ID,
        &host,
        "GET",
        &format!("{CONFIGS}/{first}"),
        None,
    )
    .await;
    assert_eq!(
        on_host.status, 200,
        "case published endpoint: expected 200 on the host the domain published, got {} \
         with {:?}",
        on_host.status, on_host.body
    );
    assert_eq!(
        only_config(&on_host, "published endpoint")["config_id"],
        json!(first),
        "case published endpoint: expected the same record the prefixed addressing reports, \
         got {:?}",
        on_host.body
    );
}

/// RULE (the same one, on the writes that change a record): an update replaces the stored
/// configuration and restamps only its update instant, a delete removes it, and every read
/// of an id the cluster does not hold is refused where the plugin refuses one.
#[tokio::test]
async fn an_updated_channel_configuration_is_replaced_and_a_deleted_one_is_gone() {
    let emulator = Emulator::new();
    let domain = "notifications-writes";
    created_domain(&emulator, domain).await;

    let topic = format!(
        "arn:aws:sns:us-east-1:{}:first-topic",
        ::engine::emulator_account_id()
    );
    let created = create(
        &emulator,
        domain,
        json!({
            "config_id": "replaced-channel",
            "config": {
                "name": "first",
                "config_type": "sns",
                "sns": { "topic_arn": topic },
            },
        }),
    )
    .await;
    assert!(
        matches!(created.status, 200 | 201),
        "case create: expected 200 or 201, got {} with {:?}",
        created.status,
        created.body
    );
    let id = created_id(&created, "create");
    let first_read =
        rest_prefixed(&emulator, domain, "GET", &format!("{CONFIGS}/{id}"), None).await;
    let created_ms = only_config(&first_read, "create")["created_time_ms"]
        .as_u64()
        .unwrap_or_default();

    // The rows an update is driven over: a changed member of the same kind, a changed
    // enabled flag, and a changed KIND — the plugin's record is the caller's object, so a
    // replacement is whatever object the caller sent.
    let replacements = [
        (
            "a changed topic",
            json!({
                "name": "second",
                "config_type": "sns",
                "sns": {
                    "topic_arn": format!(
                        "arn:aws:sns:us-east-1:{}:second-topic",
                        ::engine::emulator_account_id()
                    ),
                },
            }),
        ),
        (
            "a channel switched off",
            json!({
                "name": "second",
                "config_type": "sns",
                "is_enabled": false,
                "sns": { "topic_arn": topic.clone() },
            }),
        ),
        (
            "a changed channel kind",
            json!({
                "name": "second",
                "config_type": "slack",
                "slack": { "url": "https://hooks.slack.com/services/replaced" },
            }),
        ),
    ];
    for (case, replacement) in replacements {
        let updated = rest_prefixed(
            &emulator,
            domain,
            "PUT",
            &format!("{CONFIGS}/{id}"),
            Some(json!({ "config": replacement.clone() })),
        )
        .await;
        assert_eq!(
            updated.status, 200,
            "case update({case:?}): expected 200, got {} with {:?}",
            updated.status, updated.body
        );
        assert_eq!(
            created_id(&updated, case),
            id,
            "case update({case:?}): expected the update to answer the same id"
        );
        let read = rest_prefixed(&emulator, domain, "GET", &format!("{CONFIGS}/{id}"), None).await;
        let held = only_config(&read, case);
        assert_eq!(
            &held["config"], &replacement,
            "case update({case:?}): expected the stored configuration to BE the replacement, \
             got {:?}",
            held["config"]
        );
        assert_eq!(
            held["created_time_ms"].as_u64().unwrap_or_default(),
            created_ms,
            "case update({case:?}): expected the create instant to be left alone, got {:?}",
            held["created_time_ms"]
        );
        assert!(
            held["last_updated_time_ms"].as_u64().unwrap_or_default() >= created_ms,
            "case update({case:?}): expected the update instant to be at or after the create \
             instant, got {:?} against {created_ms}",
            held["last_updated_time_ms"]
        );
        // The update replaced one record rather than adding another.
        let listed = rest_prefixed(&emulator, domain, "GET", CONFIGS, None).await;
        assert_eq!(
            listed.body["total_hits"],
            json!(1),
            "case update({case:?}): expected the domain to still hold one configuration, got \
             {:?}",
            listed.body
        );
    }

    let deleted =
        rest_prefixed(&emulator, domain, "DELETE", &format!("{CONFIGS}/{id}"), None).await;
    assert_eq!(
        deleted.status, 200,
        "case delete: expected 200, got {} with {:?}",
        deleted.status, deleted.body
    );
    assert_eq!(
        deleted.body["delete_response_list"][&id],
        json!("OK"),
        "case delete: expected the delete to report the id it removed, got {:?}",
        deleted.body
    );
    let after = rest_prefixed(&emulator, domain, "GET", CONFIGS, None).await;
    assert_eq!(
        after.body["total_hits"],
        json!(0),
        "case delete: expected the domain to hold no configuration, got {:?}",
        after.body
    );

    // Every read and write of an id the cluster does not hold is refused the same way,
    // including the one just deleted.
    for (case, method) in [
        ("get", "GET"),
        ("put", "PUT"),
        ("delete", "DELETE"),
        ("get an id nobody created", "GET"),
    ] {
        let target = if case.contains("nobody") {
            "never-created".to_string()
        } else {
            id.clone()
        };
        let body = (method == "PUT")
            .then(|| json!({ "config": { "name": "x", "config_type": "sns" } }));
        let answer = rest_prefixed(
            &emulator,
            domain,
            method,
            &format!("{CONFIGS}/{target}"),
            body,
        )
        .await;
        assert_eq!(
            answer.status, 404,
            "case missing({case:?}): expected 404, got {} with {:?}",
            answer.status, answer.body
        );
        assert_eq!(
            reason(&answer),
            format!("NotificationConfig {target} not found"),
            "case missing({case:?}): unexpected reason in {:?}",
            answer.body
        );
    }
}

/// RULE (the refusals the same route owes): a request the plugin cannot store a record from
/// is refused on what is wrong with it — a missing member, an id the cluster already holds,
/// or a method the route does not take — and leaves the records the domain holds alone.
#[tokio::test]
async fn a_channel_configuration_the_plugin_cannot_store_is_refused() {
    let emulator = Emulator::new();
    let domain = "notifications-refusals";
    created_domain(&emulator, domain).await;

    let held = create(
        &emulator,
        domain,
        json!({
            "config_id": "held-channel",
            "config": { "name": "held", "config_type": "sns", "sns": { "topic_arn": "arn" } },
        }),
    )
    .await;
    assert!(
        matches!(held.status, 200 | 201),
        "case create(held): expected 200 or 201, got {} with {:?}",
        held.status,
        held.body
    );

    // The rows span what can be wrong with a create: no `config` at all, a `config` that is
    // not an object (two spellings), a `config` naming no kind, a kind named as the empty
    // string, and an id the cluster already holds.
    let rows: [(&str, Value, u16, &str); 7] = [
        (
            "no config member",
            json!({ "config_id": "no-config" }),
            400,
            "[config] required property is missing",
        ),
        (
            "an empty body",
            Value::Null,
            400,
            "[config] required property is missing",
        ),
        (
            "a config that is a string",
            json!({ "config": "sns" }),
            400,
            "[config] required property is missing",
        ),
        (
            "a config that is a list",
            json!({ "config": [{ "config_type": "sns" }] }),
            400,
            "[config] required property is missing",
        ),
        (
            "a config naming no kind",
            json!({ "config": { "name": "kindless" } }),
            400,
            "[config_type] required property is missing",
        ),
        (
            "a kind named as the empty string",
            json!({ "config": { "name": "empty-kind", "config_type": "" } }),
            400,
            "[config_type] required property is missing",
        ),
        (
            "an id the cluster already holds",
            json!({
                "config_id": "held-channel",
                "config": { "name": "again", "config_type": "chime" },
            }),
            409,
            "A config with config_id held-channel already exists",
        ),
    ];
    for (case, body, status, expected_reason) in rows {
        let body = if body.is_null() { None } else { Some(body) };
        let answer = rest_prefixed(&emulator, domain, "POST", CONFIGS, body).await;
        assert_eq!(
            answer.status, status,
            "case refusal({case:?}): expected {status}, got {} with {:?}",
            answer.status, answer.body
        );
        assert_eq!(
            reason(&answer),
            expected_reason,
            "case refusal({case:?}): unexpected reason in {:?}",
            answer.body
        );
        let expected_type = if status == 409 {
            "status_exception"
        } else {
            "illegal_argument_exception"
        };
        assert_eq!(
            error_type(&answer),
            expected_type,
            "case refusal({case:?}): unexpected error type in {:?}",
            answer.body
        );
    }

    // A method the route does not take is a different class of failure from a path the
    // surface serves nothing for: it names the methods the route DOES take.
    for (case, method, path, allowed) in [
        ("delete the collection", "DELETE", CONFIGS, "POST, GET"),
        ("put the collection", "PUT", CONFIGS, "POST, GET"),
        (
            "post one configuration",
            "POST",
            "/_plugins/_notifications/configs/held-channel",
            "GET, PUT, DELETE",
        ),
    ] {
        let answer = rest_prefixed(&emulator, domain, method, path, None).await;
        assert_eq!(
            answer.status, 405,
            "case method({case:?}): expected 405, got {} with {:?}",
            answer.status, answer.body
        );
        assert_eq!(
            answer.body["error"],
            json!(format!(
                "Incorrect HTTP method for uri [{path}] and method [{method}], allowed: \
                 [{allowed}]"
            )),
            "case method({case:?}): unexpected answer {:?}",
            answer.body
        );
    }

    // None of the refusals touched the record the domain holds.
    let listed = rest_prefixed(&emulator, domain, "GET", CONFIGS, None).await;
    assert_eq!(
        listed.body["total_hits"],
        json!(1),
        "case refusals: expected the held configuration to be untouched, got {:?}",
        listed.body
    );
    assert_eq!(
        only_config(&listed, "refusals")["config"]["name"],
        json!("held"),
        "case refusals: expected the held configuration as written, got {:?}",
        listed.body
    );
}

/// RULE (the bound on the same records): one domain holds at most
/// [`NOTIFICATION_CONFIG_QUOTA`] channel configurations, so the create at the bound serves
/// and the one past it is refused — and a delete makes room again.
#[tokio::test]
async fn a_domain_holds_at_most_the_bounded_number_of_channel_configurations() {
    let emulator = Emulator::new();
    let domain = "notifications-bound";
    created_domain(&emulator, domain).await;

    for index in 0..NOTIFICATION_CONFIG_QUOTA {
        let answer = create(
            &emulator,
            domain,
            json!({
                "config_id": format!("channel-{index:03}"),
                "config": { "name": format!("channel-{index:03}"), "config_type": "chime" },
            }),
        )
        .await;
        assert!(
            matches!(answer.status, 200 | 201),
            "case create({index}) at or under the bound: expected 200 or 201, got {} with {:?}",
            answer.status,
            answer.body
        );
    }

    let past = create(
        &emulator,
        domain,
        json!({
            "config_id": "channel-past-the-bound",
            "config": { "name": "past", "config_type": "chime" },
        }),
    )
    .await;
    assert_eq!(
        past.status, 400,
        "case create past the bound: expected 400, got {} with {:?}",
        past.status, past.body
    );
    assert!(
        reason(&past).contains(&format!("maximum of {NOTIFICATION_CONFIG_QUOTA}")),
        "case create past the bound: expected the refusal to name the bound, got {:?}",
        past.body
    );

    // The bound is on what the domain HOLDS, not on how many creates it has seen.
    let removed = rest_prefixed(
        &emulator,
        domain,
        "DELETE",
        &format!("{CONFIGS}/channel-000"),
        None,
    )
    .await;
    assert_eq!(
        removed.status, 200,
        "case delete to make room: expected 200, got {} with {:?}",
        removed.status, removed.body
    );
    let again = create(
        &emulator,
        domain,
        json!({
            "config_id": "channel-past-the-bound",
            "config": { "name": "past", "config_type": "chime" },
        }),
    )
    .await;
    assert!(
        matches!(again.status, 200 | 201),
        "case create after a delete made room: expected 200 or 201, got {} with {:?}",
        again.status,
        again.body
    );
}
