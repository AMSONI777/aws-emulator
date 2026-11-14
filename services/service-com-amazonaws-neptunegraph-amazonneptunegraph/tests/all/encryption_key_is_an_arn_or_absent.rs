// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for the ONE value every projection of a graph — and of a snapshot
//! taken of it, and of a graph restored from that snapshot — reports at
//! `kmsKeyIdentifier`.
//!
//! The rule under test: the member reports the key the request that minted the resource
//! named, and is ABSENT when it named none. A resource whose create request named no key
//! is encrypted with a key the service owns, which has no ARN a caller may name, and the
//! member is modelled as a KMS key ARN on every projection but the `ListGraphs` summary
//! (`GetGraphOutput$kmsKeyIdentifier` and the rest target `KmsKeyArn`, constrained to
//! [`KMS_KEY_ARN_PATTERN`] — `smithy_query(query="shape",shape="KmsKeyArn")`), so there
//! is no value to report there and nothing is reported.
//!
//! So every assertion here is one of two: a reported value equals the key the request
//! supplied AND satisfies the modelled pattern, or no value is reported at all. The rows
//! differ along what the rule generalises over — whether a key was supplied, and, when
//! one was, the partition, the Region and the form of the 36-character key id the
//! pattern leaves open — and each row is driven through the whole surface the stored
//! value travels to: the graph record (`CreateGraph`, `GetGraph`, `UpdateGraph`,
//! `ResetGraph`, `DeleteGraph`), the `ListGraphs` summary, the snapshot record
//! (`CreateGraphSnapshot`, `GetGraphSnapshot`, `DeleteGraphSnapshot`), the
//! `ListGraphSnapshots` summary, and `RestoreGraphFromSnapshot` with the `GetGraph` of
//! what it restored.

use std::sync::Arc;

use regex::Regex;
use serde_json::{json, Value};
use service_com_amazonaws_neptunegraph_amazonneptunegraph::state::PROVISIONING_SPAN;
use service_com_amazonaws_neptunegraph_amazonneptunegraph::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The region the test's SigV4 credential scope names.
const REGION: &str = "us-east-1";

/// The modelled `KmsKeyArn` pattern, exactly as the model spells it
/// (`smithy_query(query="shape",shape="KmsKeyArn")`): the expression every reported
/// `kmsKeyIdentifier` of a `KmsKeyArn` member has to satisfy.
const KMS_KEY_ARN_PATTERN: &str =
    "^arn:aws[^:]*:kms:[a-zA-Z0-9-]*:[0-9]{12}:key/[a-zA-Z0-9-]{36}$";

/// The smallest `provisionedMemory` the model allows (`range 16..24576`), which is all
/// this suite needs from a graph.
const MIN_PROVISIONED_MEMORY: i64 = 16;

/// One row: the case name and the `kmsKeyIdentifier` the create request supplies, if
/// any.
struct Row {
    case: &'static str,
    supplied: Option<&'static str>,
}

/// The rows: no key, and one key per clause the modelled pattern leaves open — the
/// partition suffix (none, GovCloud, China), the Region, and whether the 36-character
/// key id is hyphen-grouped.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "no key supplied: a service-owned key, which has no ARN to report",
            supplied: None,
        },
        Row {
            case: "a key in the default partition",
            supplied: Some(
                "arn:aws:kms:us-east-1:000000000000:key/12345678-1234-1234-1234-123456789012",
            ),
        },
        Row {
            case: "a key in the GovCloud partition and one of its Regions",
            supplied: Some(
                "arn:aws-us-gov:kms:us-gov-west-1:000000000000:key/\
                 87654321-4321-4321-4321-210987654321",
            ),
        },
        Row {
            case: "a key in the China partition whose id carries no hyphens",
            supplied: Some(
                "arn:aws-cn:kms:cn-north-1:000000000000:key/\
                 abcdefABCDEF0123456789abcdefABCDEF01",
            ),
        },
    ]
}

/// An emulator holding only this service, on its own engine, so each test starts from
/// an empty store.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.register_service(EmulatedService::new(engine));
    router
}

/// Dispatch one `restJson1` request and return its status and parsed JSON body.
async fn call(
    router: &MultiServiceRouter,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let payload = body.map_or_else(Vec::new, |value| {
        serde_json::to_vec(&value).expect("a JSON request body serializes")
    });
    let request = http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/{REGION}/neptune-graph/\
                 aws4_request, SignedHeaders=host, Signature=deadbeef"
            ),
        )
        .body(bytes::Bytes::from(payload))
        .expect("a well-formed test request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let parsed = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// Poll one resource until it reports `expected`. No handler ever sleeps; only this test
/// waits, because it is asking about a state the clock reaches on its own.
async fn wait_for_status(
    router: &MultiServiceRouter,
    case: &str,
    path: &str,
    expected: &str,
) -> Value {
    for _ in 0..200 {
        let (status, body) = call(router, "GET", path, None).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected 200 from GET {path}, got {status}: {body}"
        );
        if body["status"] == json!(expected) {
            return body;
        }
        tokio::time::sleep(PROVISIONING_SPAN / 4).await;
    }
    let (_, body) = call(router, "GET", path, None).await;
    panic!(
        "case {case:?}: GET {path} never reported {expected}, last status {}",
        body["status"]
    );
}

/// Assert `record` reports exactly the row's key at `kmsKeyIdentifier`: the supplied ARN
/// (which the modelled pattern has to accept), or nothing at all.
fn assert_reported_key(row: &Row, pattern: &Regex, step: &str, record: &Value) {
    let reported = &record["kmsKeyIdentifier"];
    match row.supplied {
        Some(key) => {
            assert_eq!(
                reported,
                &json!(key),
                "case {:?} ({step}): expected kmsKeyIdentifier {key:?}, got {reported}",
                row.case
            );
            let reported = reported.as_str().unwrap_or_default();
            assert!(
                pattern.is_match(reported),
                "case {:?} ({step}): expected a kmsKeyIdentifier matching \
                 {KMS_KEY_ARN_PATTERN}, got {reported:?}",
                row.case
            );
        }
        None => assert!(
            record.get("kmsKeyIdentifier").is_none_or(Value::is_null),
            "case {:?} ({step}): a service-owned key has no ARN, so the member the model \
             constrains to {KMS_KEY_ARN_PATTERN} carries nothing, got {reported}",
            row.case
        ),
    }
}

/// The entry of `list` (`graphs` or `graphSnapshots`) whose `id` is `id`.
async fn listed(
    router: &MultiServiceRouter,
    case: &str,
    path: &str,
    member: &str,
    id: &str,
) -> Value {
    let (status, body) = call(router, "GET", path, None).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected 200 from GET {path}, got {status}: {body}"
    );
    body[member]
        .as_array()
        .unwrap_or_else(|| panic!("case {case:?}: GET {path} reports a list, got {body}"))
        .iter()
        .find(|entry| entry["id"] == json!(id))
        .cloned()
        .unwrap_or_else(|| panic!("case {case:?}: no {member} entry for {id} in {body}"))
}

/// Create a graph for `row` and return its id and the `CreateGraph` response.
async fn create_graph(router: &MultiServiceRouter, row: &Row, name: &str) -> (String, Value) {
    let mut body = json!({"graphName": name, "provisionedMemory": MIN_PROVISIONED_MEMORY});
    if let Some(key) = row.supplied {
        body["kmsKeyIdentifier"] = json!(key);
    }
    let (status, created) = call(router, "POST", "/graphs", Some(body)).await;
    assert_eq!(
        status, 201,
        "case {:?}: expected 201 from CreateGraph, got {status}: {created}",
        row.case
    );
    let id = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("case {:?}: no id in {created}", row.case))
        .to_string();
    (id, created)
}

#[tokio::test]
async fn a_graph_reports_its_own_key_or_none_through_every_graph_projection() {
    let router = emulator();
    let pattern = Regex::new(KMS_KEY_ARN_PATTERN).expect("the modelled pattern compiles");

    for (index, row) in rows().iter().enumerate() {
        let (id, created) = create_graph(&router, row, &format!("key-graph-{index}")).await;
        assert_reported_key(row, &pattern, "CreateGraph", &created);

        // The read reports the record that was stored, not the response that was
        // rendered.
        let (status, fetched) = call(&router, "GET", &format!("/graphs/{id}"), None).await;
        assert_eq!(
            status, 200,
            "case {:?}: expected 200 from GetGraph, got {status}: {fetched}",
            row.case
        );
        assert_reported_key(row, &pattern, "GetGraph", &fetched);

        // `GraphSummary$kmsKeyIdentifier` targets the prelude `String` rather than
        // `KmsKeyArn`, and still answers about the same stored record: one resource, one
        // answer.
        let summary = listed(
            &router,
            row.case,
            "/graphs?maxResults=100",
            "graphs",
            &id,
        )
        .await;
        assert_reported_key(row, &pattern, "ListGraphs", &summary);

        wait_for_status(&router, row.case, &format!("/graphs/{id}"), "AVAILABLE").await;

        // A reconfiguration and a reset report the record they left behind: neither
        // touches the key the data is encrypted with.
        let (status, updated) = call(
            &router,
            "PATCH",
            &format!("/graphs/{id}"),
            Some(json!({"provisionedMemory": 32})),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: expected 200 from UpdateGraph, got {status}: {updated}",
            row.case
        );
        assert_reported_key(row, &pattern, "UpdateGraph", &updated);
        wait_for_status(&router, row.case, &format!("/graphs/{id}"), "AVAILABLE").await;

        let (status, reset) = call(
            &router,
            "PUT",
            &format!("/graphs/{id}"),
            Some(json!({"skipSnapshot": true})),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: expected 200 from ResetGraph, got {status}: {reset}",
            row.case
        );
        assert_reported_key(row, &pattern, "ResetGraph", &reset);
        wait_for_status(&router, row.case, &format!("/graphs/{id}"), "AVAILABLE").await;

        let (status, deleted) = call(
            &router,
            "DELETE",
            &format!("/graphs/{id}?skipSnapshot=true"),
            None,
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: expected 200 from DeleteGraph, got {status}: {deleted}",
            row.case
        );
        assert_reported_key(row, &pattern, "DeleteGraph", &deleted);
    }
}

#[tokio::test]
async fn a_snapshot_and_a_restore_carry_the_source_graph_key_or_none() {
    let router = emulator();
    let pattern = Regex::new(KMS_KEY_ARN_PATTERN).expect("the modelled pattern compiles");

    for (index, row) in rows().iter().enumerate() {
        let (graph_id, _) = create_graph(&router, row, &format!("snap-graph-{index}")).await;
        wait_for_status(
            &router,
            row.case,
            &format!("/graphs/{graph_id}"),
            "AVAILABLE",
        )
        .await;

        let snapshot_name = format!("snap-{index}");
        let (status, snapshot) = call(
            &router,
            "POST",
            "/snapshots",
            Some(json!({"graphIdentifier": graph_id, "snapshotName": snapshot_name})),
        )
        .await;
        assert_eq!(
            status, 201,
            "case {:?}: expected 201 from CreateGraphSnapshot, got {status}: {snapshot}",
            row.case
        );
        assert_reported_key(row, &pattern, "CreateGraphSnapshot", &snapshot);
        let snapshot_id = snapshot["id"]
            .as_str()
            .unwrap_or_else(|| panic!("case {:?}: no id in {snapshot}", row.case))
            .to_string();

        let read = wait_for_status(
            &router,
            row.case,
            &format!("/snapshots/{snapshot_id}"),
            "AVAILABLE",
        )
        .await;
        assert_reported_key(row, &pattern, "GetGraphSnapshot", &read);

        let entry = listed(
            &router,
            row.case,
            "/snapshots?maxResults=100",
            "graphSnapshots",
            &snapshot_id,
        )
        .await;
        assert_reported_key(row, &pattern, "ListGraphSnapshots", &entry);

        // The restored graph's data is the snapshotted data, so it is encrypted with the
        // same key — or, for the row that named none, with a service-owned key that has
        // no ARN either.
        let restored_name = format!("restored-graph-{index}");
        let (status, restored) = call(
            &router,
            "POST",
            &format!("/snapshots/{snapshot_id}/restore"),
            Some(json!({"graphName": restored_name})),
        )
        .await;
        assert_eq!(
            status, 201,
            "case {:?}: expected 201 from RestoreGraphFromSnapshot, got {status}: {restored}",
            row.case
        );
        assert_reported_key(row, &pattern, "RestoreGraphFromSnapshot", &restored);
        let restored_id = restored["id"]
            .as_str()
            .unwrap_or_else(|| panic!("case {:?}: no id in {restored}", row.case))
            .to_string();
        let (status, fetched) = call(&router, "GET", &format!("/graphs/{restored_id}"), None).await;
        assert_eq!(
            status, 200,
            "case {:?}: expected 200 from GetGraph of the restored graph, got {status}: {fetched}",
            row.case
        );
        assert_reported_key(row, &pattern, "GetGraph (restored)", &fetched);

        let (status, removed) = call(
            &router,
            "DELETE",
            &format!("/snapshots/{snapshot_id}"),
            None,
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: expected 200 from DeleteGraphSnapshot, got {status}: {removed}",
            row.case
        );
        assert_reported_key(row, &pattern, "DeleteGraphSnapshot", &removed);
    }
}
