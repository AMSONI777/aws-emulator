// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of the FLEET INDEX's MANAGED fields and of the bucket
//! aggregation computed over them: `CreateFleetMetric` / `UpdateFleetMetric` over a
//! managed field, and `GetBucketsAggregation` over the things a query selects.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` over a
//! restJson1 request signed for the `iot` signing name — so what is asserted is what an
//! AWS SDK client would see, not an internal function's return value.
//!
//! The rules under test:
//!
//! * a field the fleet-indexing service MANAGES is aggregatable as soon as the index
//!   that holds it exists: only a field whose values a CALLER supplies
//!   (`attributes.<name>`) has to be declared through `UpdateIndexingConfiguration`
//!   before an aggregation may name it;
//! * a bucket aggregation is COMPUTED over the account's own registry: the query selects
//!   the things, `totalCount` counts them and each bucket counts the things that carry
//!   one value of the aggregated field, ranked by that count;
//! * an aggregation over an index the account does not have is
//!   `ResourceNotFoundException` (404) and one over an index still building is
//!   `IndexNotReadyException` (400);
//! * what ONE aggregation may cost is bounded in both dimensions a request chooses —
//!   how many documents the scan examines and how much character matching the query
//!   performs over them — and past either bound the request is REFUSED rather than
//!   answered from a partial scan.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use serde_json::{json, Value};
use service_com_amazonaws_iot_awsiotservice::state::{
    documents_matching, fleet_metrics::MANAGED_THING_FIELDS, ComAmazonawsIotAwsiotserviceState,
    IndexedDocument, ScanRefusal, INDEX_BUILD_SPAN, MAX_SCANNED_DOCUMENTS, MAX_WALK_DEPTH,
    THING_INDEX_NAME,
};
use service_com_amazonaws_iot_awsiotservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The region this suite signs for.
const REGION: &str = "eu-north-1";

/// A custom field of type `String` the account declares, so a case can show that a
/// CALLER-supplied field still needs the declaration a managed one does not.
const DECLARED_ATTRIBUTE_FIELD: &str = "attributes.zone";

/// An attribute field the account declares nothing for.
const UNDECLARED_ATTRIBUTE_FIELD: &str = "attributes.undeclared";

/// One emulator: the shared engine plus a router with this service mounted.
struct Emulator {
    engine: Arc<engine::InMemoryEngine>,
    router: MultiServiceRouter,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        router.set_request_authentication(false);
        router.register_service(EmulatedService::new(Arc::clone(&engine)));
        Self { engine, router }
    }

    async fn dispatch(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let host = format!("iot.{REGION}.amazonaws.com");
        let payload = body.map_or_else(Bytes::new, |value| Bytes::from(value.to_string()));
        let request = http::Request::builder()
            .method(method)
            .uri(format!("https://{host}{path}"))
            .header("host", host)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/iot/aws4_request, \
                     SignedHeaders=host, Signature=0123456789abcdef"
                ),
            )
            .body(payload)
            .expect("the fleet-indexing request is well formed");
        Reply::of(self.router.dispatch(request).await)
    }

    /// Turn REGISTRY thing indexing on, declaring one custom attribute field.
    async fn enable_thing_index(&self, case: &str) {
        let reply = self
            .dispatch(
                "POST",
                "/indexing/config",
                Some(&json!({
                    "thingIndexingConfiguration": {
                        "thingIndexingMode": "REGISTRY",
                        "customFields": [{ "name": DECLARED_ATTRIBUTE_FIELD, "type": "String" }],
                    }
                })),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected UpdateIndexingConfiguration to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
    }

    /// Finish the build the clock owes the thing index, by moving the recorded due
    /// instant into the past — the state a caller that waited out [`INDEX_BUILD_SPAN`]
    /// would find, without the test waiting for it.
    fn finish_index_build(&self) {
        let state = self.engine.state::<ComAmazonawsIotAwsiotserviceState>();
        let mut store = state.lock();
        let build = store
            .index_builds
            .get_mut(THING_INDEX_NAME)
            .expect("enabling the index records a build");
        build.active_at = SystemTime::now() - INDEX_BUILD_SPAN;
    }

    /// An emulator whose thing index exists and is ACTIVE.
    async fn with_active_index(case: &str) -> Self {
        let emulator = Self::new();
        emulator.enable_thing_index(case).await;
        emulator.finish_index_build();
        emulator
    }

    async fn create_thing_type(&self, case: &str, thing_type_name: &str) {
        let reply = self
            .dispatch(
                "POST",
                &format!("/thing-types/{thing_type_name}"),
                Some(&json!({})),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected CreateThingType to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
    }

    /// Register one thing of the type given, carrying the attributes given.
    async fn create_thing(
        &self,
        case: &str,
        thing_name: &str,
        thing_type_name: Option<&str>,
        zone: Option<&str>,
    ) {
        let mut body = json!({});
        if let Some(thing_type_name) = thing_type_name {
            body["thingTypeName"] = json!(thing_type_name);
        }
        if let Some(zone) = zone {
            body["attributePayload"] = json!({ "attributes": { "zone": zone } });
        }
        let reply = self
            .dispatch("POST", &format!("/things/{thing_name}"), Some(&body))
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected CreateThing to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
    }

    async fn create_metric(&self, metric_name: &str, body: &Value) -> Reply {
        self.dispatch("PUT", &format!("/fleet-metric/{metric_name}"), Some(body))
            .await
    }

    async fn update_metric(&self, metric_name: &str, body: &Value) -> Reply {
        self.dispatch("PATCH", &format!("/fleet-metric/{metric_name}"), Some(body))
            .await
    }

    async fn describe_metric(&self, metric_name: &str) -> Reply {
        self.dispatch("GET", &format!("/fleet-metric/{metric_name}"), None)
            .await
    }

    async fn buckets(&self, body: &Value) -> Reply {
        self.dispatch("POST", "/indices/buckets", Some(body)).await
    }

    async fn list_metrics(&self, query: &str) -> Reply {
        self.dispatch("GET", &format!("/fleet-metrics?{query}"), None)
            .await
    }
}

/// A dispatched response, reduced to what the assertions read.
struct Reply {
    status: u16,
    body: Bytes,
}

impl Reply {
    fn of(response: http::Response<Bytes>) -> Self {
        Self {
            status: response.status().as_u16(),
            body: response.into_body(),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("response body is not JSON ({e}): {}", self.text()))
    }

    fn error_code(&self) -> String {
        self.json()["__type"]
            .as_str()
            .unwrap_or_else(|| panic!("no __type in {}", self.text()))
            .to_string()
    }

    /// The `(metricName, metricArn)` pairs a `ListFleetMetrics` page carries.
    fn fleet_metrics(&self) -> Vec<(String, String)> {
        self.json()["fleetMetrics"]
            .as_array()
            .unwrap_or_else(|| panic!("no fleetMetrics in {}", self.text()))
            .iter()
            .map(|metric| {
                (
                    metric["metricName"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    metric["metricArn"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }

    /// The `(keyValue, count)` pairs a bucket aggregation answered with, in the order it
    /// ranked them.
    fn buckets(&self) -> Vec<(String, i64)> {
        self.json()["buckets"]
            .as_array()
            .unwrap_or_else(|| panic!("no buckets in {}", self.text()))
            .iter()
            .map(|bucket| {
                (
                    bucket["keyValue"].as_str().unwrap_or_default().to_string(),
                    bucket["count"].as_i64().unwrap_or_default(),
                )
            })
            .collect()
    }
}

/// RULE: every field the fleet-indexing service manages is aggregatable without the
/// account declaring anything, and only a caller-supplied `attributes.<name>` field
/// needs a `customFields` declaration.
#[tokio::test]
async fn a_managed_index_field_is_aggregatable_without_being_declared() {
    let emulator = Emulator::with_active_index("managed fields").await;

    // The rows are the index's OWN managed-field catalog
    // (`service_com_amazonaws_iot_awsiotservice::state::fleet_metrics::MANAGED_THING_FIELDS`,
    // the managed-field table AWS IoT fleet indexing publishes), so a field added to or
    // dropped from it is covered here without this table being rewritten. The `count`
    // statistic is the one aggregation every field type admits — the arithmetic
    // summaries are of numbers and a cardinality is not asked of a flag — so what each
    // row varies is the FIELD and nothing else.
    for (index, (field, _field_type)) in MANAGED_THING_FIELDS.iter().enumerate() {
        let metric_name = format!("managed-{index}");
        let created = emulator
            .create_metric(
                &metric_name,
                &json!({
                    "queryString": "thingName:*",
                    "aggregationType": { "name": "Statistics", "values": ["count"] },
                    "aggregationField": field,
                    "period": 300,
                }),
            )
            .await;
        assert_eq!(
            created.status,
            200,
            "case managed field {field}: expected 200, got {} body {}",
            created.status,
            created.text()
        );
        // The created metric reads back with the field it aggregates, so the accept is
        // backed by a record and not by a bare 200.
        let read = emulator.describe_metric(&metric_name).await;
        assert_eq!(
            read.json()["aggregationField"],
            json!(field),
            "case managed field {field}: the read must report the stored field, got {}",
            read.text()
        );
    }

    // A field the account DECLARED is aggregatable too...
    let declared = emulator
        .create_metric(
            "declared",
            &json!({
                "queryString": "thingName:*",
                "aggregationType": { "name": "Cardinality" },
                "aggregationField": DECLARED_ATTRIBUTE_FIELD,
                "period": 300,
            }),
        )
        .await;
    assert_eq!(
        declared.status,
        200,
        "case a declared custom field: expected 200, got {} body {}",
        declared.status,
        declared.text()
    );
    // ...and one it declared nothing for is refused, which is what makes the accepts
    // above about the managed catalog rather than about every field being allowed.
    let undeclared = emulator
        .create_metric(
            "undeclared",
            &json!({
                "queryString": "thingName:*",
                "aggregationType": { "name": "Cardinality" },
                "aggregationField": UNDECLARED_ATTRIBUTE_FIELD,
                "period": 300,
            }),
        )
        .await;
    assert_eq!(
        undeclared.status,
        400,
        "case an undeclared attribute field: expected 400, got {} body {}",
        undeclared.status,
        undeclared.text()
    );
    assert_eq!(
        undeclared.error_code(),
        "InvalidRequestException",
        "case an undeclared attribute field: got {}",
        undeclared.text()
    );

    // The same rule holds for an UPDATE of a metric's aggregation: the managed field is
    // accepted and the undeclared one refused, with the record left at what it was.
    let updated = emulator
        .update_metric(
            "managed-0",
            &json!({
                "indexName": THING_INDEX_NAME,
                "aggregationField": "registry.thingTypeName",
                "aggregationType": { "name": "Cardinality" },
            }),
        )
        .await;
    assert_eq!(
        updated.status,
        200,
        "case an update to a managed field: expected 200, got {} body {}",
        updated.status,
        updated.text()
    );
    let read = emulator.describe_metric("managed-0").await;
    assert_eq!(
        read.json()["aggregationField"],
        json!("registry.thingTypeName"),
        "case an update to a managed field: the read must report it, got {}",
        read.text()
    );
    let refused = emulator
        .update_metric(
            "managed-0",
            &json!({
                "indexName": THING_INDEX_NAME,
                "aggregationField": UNDECLARED_ATTRIBUTE_FIELD,
                "aggregationType": { "name": "Cardinality" },
            }),
        )
        .await;
    assert_eq!(
        refused.status,
        400,
        "case an update to an undeclared attribute field: expected 400, got {} body {}",
        refused.status,
        refused.text()
    );
    let read = emulator.describe_metric("managed-0").await;
    assert_eq!(
        read.json()["aggregationField"],
        json!("registry.thingTypeName"),
        "case an update to an undeclared attribute field: the record must be unchanged, got {}",
        read.text()
    );

    // Every metric the creates above recorded is reported by the listing, with the ARN
    // its own create minted — and the listing pages over them, a page at a time.
    let listed = emulator.list_metrics("").await;
    assert_eq!(
        listed.status,
        200,
        "case the listing: expected 200, got {} body {}",
        listed.status,
        listed.text()
    );
    let expected_count = MANAGED_THING_FIELDS.len() + 1;
    assert_eq!(
        listed.fleet_metrics().len(),
        expected_count,
        "case the listing: expected {expected_count} metrics, got {:?}",
        listed.fleet_metrics()
    );
    for (metric_name, metric_arn) in listed.fleet_metrics() {
        let read = emulator.describe_metric(&metric_name).await;
        assert_eq!(
            read.json()["metricArn"],
            json!(metric_arn),
            "case the listing: expected the ARN the create minted for {metric_name}, got {}",
            read.text()
        );
    }
    let mut paged: Vec<String> = Vec::new();
    let mut query = "maxResults=2".to_string();
    loop {
        let page = emulator.list_metrics(&query).await;
        let names: Vec<String> = page
            .fleet_metrics()
            .into_iter()
            .map(|(metric_name, _arn)| metric_name)
            .collect();
        assert!(
            names.len() <= 2,
            "case the paged listing: a page must hold at most 2, got {names:?}"
        );
        paged.extend(names);
        match page.json()["nextToken"].as_str() {
            Some(token) => query = format!("maxResults=2&nextToken={token}"),
            None => break,
        }
    }
    assert_eq!(
        paged.len(),
        expected_count,
        "case the paged listing: expected every metric once, got {paged:?}"
    );
}

/// RULE: a bucket aggregation is computed over the things the query selects, counting
/// the things that carry each value of the aggregated field.
#[tokio::test]
async fn a_bucket_aggregation_counts_the_registry_the_query_selects() {
    let emulator = Emulator::with_active_index("buckets").await;
    for thing_type_name in ["sensor", "gateway"] {
        emulator.create_thing_type("buckets", thing_type_name).await;
    }
    // Three things of one type, two of another and one of none: the counts the
    // aggregation has to report are a property of this registry.
    emulator
        .create_thing("buckets", "sensor-1", Some("sensor"), Some("north"))
        .await;
    emulator
        .create_thing("buckets", "sensor-2", Some("sensor"), Some("north"))
        .await;
    emulator
        .create_thing("buckets", "sensor-3", Some("sensor"), Some("south"))
        .await;
    emulator
        .create_thing("buckets", "gateway-1", Some("gateway"), Some("south"))
        .await;
    emulator
        .create_thing("buckets", "gateway-2", Some("gateway"), None)
        .await;
    emulator.create_thing("buckets", "spare-1", None, None).await;

    // The rows span what the rule generalises over: which field is aggregated (a managed
    // registry field and a declared attribute field), which things the query selects
    // (all of them, a wildcard over the name, a value match, and one that selects
    // none), and how many buckets the request asks for.
    struct Case {
        label: &'static str,
        query: &'static str,
        field: &'static str,
        max_buckets: Option<i64>,
        total: i64,
        buckets: Vec<(&'static str, i64)>,
    }
    let cases = vec![
        Case {
            label: "the type of every thing",
            query: "thingName:*",
            field: "registry.thingTypeName",
            max_buckets: None,
            total: 6,
            buckets: vec![("sensor", 3), ("gateway", 2)],
        },
        Case {
            label: "the type of the things one name wildcard selects",
            query: "thingName:sensor-*",
            field: "registry.thingTypeName",
            max_buckets: None,
            total: 3,
            buckets: vec![("sensor", 3)],
        },
        Case {
            label: "a declared attribute field over every thing",
            query: "thingName:*",
            field: DECLARED_ATTRIBUTE_FIELD,
            max_buckets: None,
            total: 6,
            buckets: vec![("north", 2), ("south", 2)],
        },
        Case {
            label: "the type of the things one attribute value selects",
            query: "attributes.zone:south",
            field: "registry.thingTypeName",
            max_buckets: None,
            total: 2,
            buckets: vec![("gateway", 1), ("sensor", 1)],
        },
        Case {
            label: "only the highest-ranked bucket",
            query: "thingName:*",
            field: "registry.thingTypeName",
            max_buckets: Some(1),
            total: 6,
            buckets: vec![("sensor", 3)],
        },
        Case {
            label: "a query that selects no thing at all",
            query: "thingName:absent-*",
            field: "registry.thingTypeName",
            max_buckets: None,
            total: 0,
            buckets: vec![],
        },
        Case {
            label: "the name of every thing, one bucket each",
            query: "thingName:* AND NOT thingName:spare-1",
            field: "thingName",
            max_buckets: Some(10),
            total: 5,
            buckets: vec![
                ("gateway-1", 1),
                ("gateway-2", 1),
                ("sensor-1", 1),
                ("sensor-2", 1),
                ("sensor-3", 1),
            ],
        },
    ];

    for case in &cases {
        let mut terms = json!({});
        if let Some(max_buckets) = case.max_buckets {
            terms["maxBuckets"] = json!(max_buckets);
        }
        let answer = emulator
            .buckets(&json!({
                "queryString": case.query,
                "aggregationField": case.field,
                "bucketsAggregationType": { "termsAggregation": terms },
            }))
            .await;
        assert_eq!(
            answer.status,
            200,
            "case {}: expected 200, got {} body {}",
            case.label,
            answer.status,
            answer.text()
        );
        assert_eq!(
            answer.json()["totalCount"],
            json!(case.total),
            "case {}: expected {} things selected, got {}",
            case.label,
            case.total,
            answer.text()
        );
        let expected: Vec<(String, i64)> = case
            .buckets
            .iter()
            .map(|(value, count)| ((*value).to_string(), *count))
            .collect();
        assert_eq!(
            answer.buckets(),
            expected,
            "case {}: expected the buckets {expected:?}, got {:?}",
            case.label,
            answer.buckets()
        );
    }
}

/// RULE: an aggregation is answered out of the INDEX, so an account that has none is a
/// 404 and an index still building is a 400 — and the same calls succeed once it is
/// ACTIVE.
#[tokio::test]
async fn an_aggregation_over_an_absent_or_building_index_is_refused() {
    let request = json!({
        "queryString": "thingName:*",
        "aggregationField": "registry.version",
        "bucketsAggregationType": { "termsAggregation": { "maxBuckets": 5 } },
    });

    // No indexing configured at all: the index does not exist, so there is nothing to
    // aggregate.
    let emulator = Emulator::new();
    let refused = emulator.buckets(&request).await;
    assert_eq!(
        refused.status,
        404,
        "case thing indexing OFF: expected 404, got {} body {}",
        refused.status,
        refused.text()
    );
    assert_eq!(
        refused.error_code(),
        "ResourceNotFoundException",
        "case thing indexing OFF: got {}",
        refused.text()
    );

    // Turned on, the index exists but is still building until the clock makes it active.
    emulator.enable_thing_index("building").await;
    let building = emulator.buckets(&request).await;
    assert_eq!(
        building.status,
        400,
        "case the index still building: expected 400, got {} body {}",
        building.status,
        building.text()
    );
    assert_eq!(
        building.error_code(),
        "IndexNotReadyException",
        "case the index still building: got {}",
        building.text()
    );

    // Once the build the clock owed is due, the same request is answered.
    emulator.finish_index_build();
    let answered = emulator.buckets(&request).await;
    assert_eq!(
        answered.status,
        200,
        "case the index ACTIVE: expected 200, got {} body {}",
        answered.status,
        answered.text()
    );

    // The index that is no fleet index of this service at all, and a request naming no
    // bucket aggregation, are each refused on their own terms.
    let unknown_index = emulator
        .buckets(&json!({
            "indexName": "AWS_Nothing",
            "queryString": "thingName:*",
            "aggregationField": "registry.version",
            "bucketsAggregationType": { "termsAggregation": { "maxBuckets": 5 } },
        }))
        .await;
    assert_eq!(
        unknown_index.error_code(),
        "InvalidRequestException",
        "case an index name this service does not serve: got {}",
        unknown_index.text()
    );
    let no_aggregation = emulator
        .buckets(&json!({
            "queryString": "thingName:*",
            "aggregationField": "registry.version",
            "bucketsAggregationType": {},
        }))
        .await;
    assert_eq!(
        no_aggregation.error_code(),
        "InvalidAggregationException",
        "case a request naming no bucket aggregation: got {}",
        no_aggregation.text()
    );
    let bad_query = emulator
        .buckets(&json!({
            "queryString": "thingName:(",
            "aggregationField": "registry.version",
            "bucketsAggregationType": { "termsAggregation": { "maxBuckets": 5 } },
        }))
        .await;
    assert_eq!(
        bad_query.error_code(),
        "InvalidQueryException",
        "case a query string that is not a query: got {}",
        bad_query.text()
    );
}

/// RULE: what ONE aggregation may cost is bounded in both dimensions a request chooses,
/// and past either bound the scan is refused rather than answered from a partial read.
///
/// The bounds are exercised on the scan itself: an index holding more documents than one
/// scan examines, and a query whose matching costs more than one aggregation evaluates,
/// are each far too large to drive through the registry's own API in a test.
#[test]
fn an_aggregation_past_either_bound_is_refused() {
    /// One document carrying a long value, which is what a wildcard term is matched
    /// against character by character.
    fn document(index: usize) -> IndexedDocument {
        let mut document = IndexedDocument::new();
        document.insert(
            "thingName".to_string(),
            vec![format!("thing-{index}-{}", "v".repeat(800))],
        );
        document
    }

    // One document past the number a scan examines is refused naming how many there are.
    let too_many: Vec<IndexedDocument> = (0..=MAX_SCANNED_DOCUMENTS)
        .map(|index| {
            let mut document = IndexedDocument::new();
            document.insert("thingName".to_string(), vec![format!("thing-{index}")]);
            document
        })
        .collect();
    let refused = documents_matching(too_many, "thingName:*");
    assert_eq!(
        refused.err(),
        Some(ScanRefusal::TooManyDocuments(MAX_SCANNED_DOCUMENTS + 1)),
        "case one document past the scan's ceiling: expected the documents refusal"
    );

    // A query whose matching costs more than one aggregation evaluates is refused too: a
    // wildcard pattern of the length the query reader admits, against long values.
    let wide: Vec<IndexedDocument> = (0..200).map(document).collect();
    let pattern = format!("thingName:{}*", "a".repeat(2_000));
    let refused = documents_matching(wide.clone(), &pattern);
    assert_eq!(
        refused.err(),
        Some(ScanRefusal::TooMuchMatching),
        "case a long wildcard term over many documents: expected the matching refusal"
    );

    // The same documents under an ordinary query are scanned, so the bound above is
    // about the cost the request chose and not about the store's size.
    let selected = documents_matching(wide.clone(), "thingName:thing-7-*");
    assert_eq!(
        selected.map(|selected| selected.len()),
        Ok(1),
        "case an ordinary query over the same documents: expected the one thing it selects"
    );

    // A query that nests deeper than the walk descends is refused before any document is
    // examined, so the recursion cannot run the scan thread's stack out. A run of
    // negations is the form that reaches the walk's ceiling: the query reader caps how
    // deeply PARENTHESES nest, well below it, so that form never gets this far.
    let negations = format!("{}thingName:*", "NOT ".repeat(MAX_WALK_DEPTH as usize + 2));
    let refused = documents_matching(wide.clone(), &negations);
    assert_eq!(
        refused.err(),
        Some(ScanRefusal::TooDeeplyNested),
        "case a run of negations past the walk's ceiling: expected the nesting refusal"
    );
    // The parenthesised form is not a query this service reads at all, so it selects
    // nothing rather than descending: every caller refuses it before the scan.
    let groups = format!(
        "{}thingName:*{}",
        "(".repeat(MAX_WALK_DEPTH as usize + 2),
        ")".repeat(MAX_WALK_DEPTH as usize + 2)
    );
    assert_eq!(
        documents_matching(wide.clone(), &groups).map(|selected| selected.len()),
        Ok(0),
        "case parentheses past the query reader's ceiling: expected nothing selected"
    );

    // A query that nests within the ceiling is evaluated, so the bound is on the depth
    // the request chose rather than on nesting at all.
    let nested = documents_matching(wide, "NOT (NOT (thingName:thing-7-*))");
    assert_eq!(
        nested.map(|selected| selected.len()),
        Ok(1),
        "case a query nesting within the ceiling: expected the one thing it selects"
    );
}
