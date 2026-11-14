// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP tests for the two refusals of the dataset surface that are about the
//! resource the request names rather than about the shape of its members.
//!
//! Every test drives the service the way the router does: an `http::Request` through
//! [`MultiServiceRouter::dispatch`], so the wire protocol (`restJson1`), the boundary
//! constraint validation and the handlers are all exercised. The suite that exercises an
//! Amazon S3 source mounts object storage beside this service on ONE engine — what the
//! assembled emulator does — so the objects a source is resolved against are the ones
//! object storage really holds.
//!
//! Two rules are under test, each asserted over a SET of inputs rather than over one
//! request:
//!
//! 1. A `datasetId` this account holds no dataset for is refused with the operation's
//!    modelled `ResourceNotFoundException` (HTTP 404, `smithy_query(query="operation",
//!    operation="GetDataset")`) in the dataset resource's own fixed sentence. The sentence
//!    never varies: not with the asking operation, and not with the identifier, which it
//!    does not quote at all. The rows differ along the operation asked (read, update,
//!    version listing, publish), along the form of the absent identifier, and along
//!    whether a `datasetVersion` was asked for.
//! 2. A `CreateDataset` whose `source` names an Amazon S3 object that does not resolve to
//!    something readable is refused with the modelled `ValidationException` (HTTP 400)
//!    naming the URI the request carried, and persists nothing — a dataset is never
//!    reported for a source that could never populate it. The rows differ along HOW the
//!    URI misses: a key the bucket holds nothing at, a bucket object storage does not
//!    hold, the stored key with a suffix, the stored key under another prefix, and a key
//!    differing from the stored one only in case. The last row is the URI that DOES
//!    resolve, which is accepted and ingested.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use service_com_amazonaws_bedrockagentcorecontrol_amazonbedrockagentcorecontrol as agentcore;

/// The region every request here is signed for, which is what the router routes on and
/// what the handlers read the ARN Region from.
const REGION: &str = "us-west-2";

/// How long a poll waits for a status the clock owes before giving up. Generous: it bounds
/// a transition the emulator makes in seconds, so a loaded host still passes.
const POLL_DEADLINE: Duration = Duration::from_secs(120);

/// How long a poll waits between looks. Short enough that the loop is cheap, and never
/// asserted on: the test waits for the CONDITION.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// One `DatasetSchemaType` value, from `smithy_query shape=DatasetSchemaType`.
const SCHEMA_TYPE: &str = "AGENTCORE_EVALUATION_PREDEFINED_V1";

/// The whole sentence the dataset resource words a `datasetId` it holds nothing for in. It
/// carries no variable part: what the caller has to check is the member it sent, not a
/// value this service could quote back.
const DATASET_NOT_FOUND: &str =
    "The specified dataset does not exist. Please verify the datasetId and try again.";

/// The bucket the resolvable JSONL file lives in, inside `S3Uri`'s pattern
/// `^s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]/.{1,1024}$` (`smithy_query shape=S3Source`).
const BUCKET: &str = "dataset-source-probe";

/// The key that bucket really holds a JSONL file at.
const PRESENT_KEY: &str = "present/examples.jsonl";

/// This emulator: the control plane, optionally with object storage mounted beside it on
/// the one shared engine.
struct Emulator {
    router: MultiServiceRouter,
    object_storage: bool,
}

impl Emulator {
    /// Only the control plane, which the dataset reads need nothing beside.
    fn new() -> Self {
        Self::over_engine(false)
    }

    /// The control plane with object storage answering, which is what the assembled
    /// emulator is.
    fn with_object_storage() -> Self {
        Self::over_engine(true)
    }

    fn over_engine(object_storage: bool) -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        // `default()` registers no authenticator, so the suite exercises routing and the
        // handlers rather than this process's SigV4 keys.
        let mut router = MultiServiceRouter::default();
        router.register_service(agentcore::EmulatedService::new(Arc::clone(&engine)));
        if object_storage {
            router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
                Arc::clone(&engine),
            ));
        }
        Self {
            router,
            object_storage,
        }
    }

    /// One `restJson1` request to the control plane, signed for [`REGION`].
    async fn call(&self, method: &str, uri: &str, body: Option<&Value>) -> Answer {
        let payload = body.map_or_else(Bytes::new, |value| {
            Bytes::from(serde_json::to_vec(value).expect("the request body serializes"))
        });
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261029/{REGION}/bedrock-agentcore/\
             aws4_request, SignedHeaders=host, Signature=abc"
        );
        let mut request = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", authorization)
            .header("host", "bedrock-agentcore-control.amazonaws.com");
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let request = request.body(payload).expect("a well-formed request");
        Answer::of(self.router.dispatch(request).await)
    }

    /// `CreateDataset`: `POST /datasets` (`smithy_query operation=CreateDataset`).
    async fn create_dataset(&self, body: &Value) -> Answer {
        self.call("POST", "/datasets", Some(body)).await
    }

    /// `GetDataset`: `GET /datasets/{datasetId}`.
    async fn get_dataset(&self, dataset_id: &str) -> Answer {
        self.call("GET", &format!("/datasets/{dataset_id}"), None)
            .await
    }

    /// `ListDatasets`: `GET /datasets`.
    async fn list_datasets(&self) -> Answer {
        self.call("GET", "/datasets", None).await
    }

    /// Look at the dataset until it reports a status the clock has SETTLED it in — any
    /// status other than the transient `CREATING` — and answer that read. Waits for the
    /// CONDITION: it polls until the status holds or [`POLL_DEADLINE`] passes, so it never
    /// depends on how fast the host runs.
    async fn poll_until_settled(&self, case: &str, dataset_id: &str) -> Answer {
        let started = Instant::now();
        loop {
            let read = self.get_dataset(dataset_id).await;
            if read.text("status") != "CREATING" {
                return read;
            }
            assert!(
                started.elapsed() < POLL_DEADLINE,
                "case {case:?}: dataset {dataset_id} never left CREATING, last read was status \
                 {:?} and body {}",
                read.text("status"),
                read.body
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// One path-style request to object storage's front door. Object storage is a REST
    /// service: the bucket and the key live in the URI and the body is the object's own
    /// bytes, so this is a raw request. The credential scope names `s3`, which is what the
    /// router claims on.
    async fn s3(&self, method: &str, path: &str, body: &[u8]) -> u16 {
        assert!(
            self.object_storage,
            "an emulator built without object storage cannot be seeded with objects"
        );
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261029/{REGION}/s3/aws4_request, \
             SignedHeaders=host, Signature=abc"
        );
        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", authorization)
            .body(Bytes::copy_from_slice(body))
            .expect("a well-formed request");
        self.router.dispatch(request).await.status().as_u16()
    }

    /// Store `body` at `key` in `bucket`, creating the bucket first, so a source that
    /// names that location resolves to a file that is really there.
    async fn put_object(&self, bucket: &str, key: &str, body: &[u8]) {
        let created = self
            .s3(
                "PUT",
                &format!("/{bucket}"),
                format!(
                    "<CreateBucketConfiguration \
                     xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <LocationConstraint>{REGION}</LocationConstraint>\
                     </CreateBucketConfiguration>"
                )
                .as_bytes(),
            )
            .await;
        assert!(
            created == 200 || created == 409,
            "seeding s3://{bucket}: expected 200 or 409 from CreateBucket, got {created}"
        );
        let stored = self.s3("PUT", &format!("/{bucket}/{key}"), body).await;
        assert_eq!(
            stored, 200,
            "seeding s3://{bucket}/{key}: expected 200 from PutObject, got {stored}"
        );
    }
}

/// One answer from the emulator: its status, the error shape `x-amzn-errortype` names and
/// its JSON body.
struct Answer {
    status: u16,
    error_type: String,
    body: Value,
}

impl Answer {
    fn of(response: http::Response<Bytes>) -> Self {
        let status = response.status().as_u16();
        let error_type = response
            .headers()
            .get("x-amzn-errortype")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .rsplit('#')
            .next()
            .unwrap_or_default()
            .to_string();
        let body = if response.body().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(response.body()).unwrap_or(Value::Null)
        };
        Self {
            status,
            error_type,
            body,
        }
    }

    /// The error code `restJson1` puts in the body's `__type`.
    fn error_code(&self) -> String {
        self.body
            .get("__type")
            .and_then(Value::as_str)
            .unwrap_or("<no __type>")
            .rsplit('#')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn text(&self, member: &str) -> String {
        self.body
            .get(member)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
}

/// A `source` carrying `count` inline examples, each carrying the fields the AgentCore
/// evaluation schemas require of one (`crate::state::required_example_fields`).
fn inline_source(count: usize) -> Value {
    let examples: Vec<Value> = (0..count)
        .map(|index| {
            json!({
                "scenario_id": format!("scenario-{index}"),
                "input": format!("turn {index}"),
            })
        })
        .collect();
    json!({"inlineExamples": {"examples": examples}})
}

/// A JSONL file holding `count` examples, one JSON value per line.
fn jsonl(count: usize) -> String {
    (0..count)
        .map(|index| format!("{{\"scenario_id\":\"s{index}\",\"input\":\"turn {index}\"}}\n"))
        .collect()
}

/// One dataset route that resolves a `datasetId`: how it is addressed, and the body it
/// needs to reach the lookup rather than the boundary's own validation.
struct Route {
    operation: &'static str,
    method: &'static str,
    /// The path the route takes for `dataset_id`, suffixed after `/datasets/{id}`.
    suffix: &'static str,
    body: Option<Value>,
}

/// RULE 1: every dataset route that resolves a `datasetId` reports an id this account
/// holds no dataset for in the dataset resource's one fixed sentence, and quotes no part
/// of the identifier it was given.
#[tokio::test]
async fn a_missing_dataset_id_is_refused_in_the_dataset_resources_own_words() {
    let emulator = Emulator::new();

    // A dataset really held, so every refusal below is about the identifier and not about
    // the account holding no dataset at all.
    let created = emulator
        .create_dataset(&json!({
            "datasetName": "Present",
            "schemaType": SCHEMA_TYPE,
            "source": inline_source(2),
        }))
        .await;
    assert_eq!(
        created.status, 202,
        "the dataset the refusals are measured against is created, got {} and body {}",
        created.status, created.body
    );
    let present = created.text("datasetId");

    // Each is a well-formed `DatasetId` (`^[a-zA-Z0-9_-]{1,110}$`, `smithy_query
    // operation=GetDataset`), so every refusal is the handler's and not the boundary's.
    let absent: [(&str, String); 5] = [
        ("an id nothing was created under", "Absent-0123456789".to_string()),
        ("a single-character id", "a".to_string()),
        ("an id of underscores and hyphens", "_-_-_-".to_string()),
        (
            "the stored id with a character prepended",
            format!("z{present}"),
        ),
        // The longest id the member admits: `^[a-zA-Z0-9_-]{1,110}$`.
        ("an id of the maximum modelled length", "d".repeat(110)),
    ];

    let routes: [Route; 5] = [
        Route {
            operation: "GetDataset",
            method: "GET",
            suffix: "",
            body: None,
        },
        Route {
            operation: "GetDataset for one datasetVersion",
            method: "GET",
            suffix: "?datasetVersion=1",
            body: None,
        },
        Route {
            operation: "UpdateDataset",
            method: "PUT",
            suffix: "",
            body: Some(json!({"description": "a change nothing can take"})),
        },
        Route {
            operation: "ListDatasetVersions",
            method: "GET",
            suffix: "/versions",
            body: None,
        },
        Route {
            operation: "CreateDatasetVersion",
            method: "POST",
            suffix: "/versions",
            body: Some(json!({})),
        },
    ];

    for (case, dataset_id) in &absent {
        // An identifier short enough to occur inside ordinary English is not evidence
        // either way, so the "echoes nothing" check below is made with the distinctive
        // ones.
        let distinctive = dataset_id.len() > 6;
        for route in &routes {
            let operation = route.operation;
            let uri = format!("/datasets/{dataset_id}{}", route.suffix);
            let refused = emulator
                .call(route.method, &uri, route.body.as_ref())
                .await;
            assert_eq!(
                (refused.status, refused.error_code().as_str()),
                (404, "ResourceNotFoundException"),
                "case {case:?} ({operation}): expected HTTP 404 ResourceNotFoundException, got \
                 {} {} and body {}",
                refused.status,
                refused.error_code(),
                refused.body
            );
            assert_eq!(
                refused.error_type, "ResourceNotFoundException",
                "case {case:?} ({operation}): expected x-amzn-errortype to name the modelled \
                 error shape, got {:?}",
                refused.error_type
            );
            assert_eq!(
                refused.text("message"),
                DATASET_NOT_FOUND,
                "case {case:?} ({operation}): expected the dataset resource's sentence \
                 {DATASET_NOT_FOUND:?}, got {:?}",
                refused.text("message")
            );
            assert!(
                !distinctive || !refused.text("message").contains(dataset_id.as_str()),
                "case {case:?} ({operation}): the refusal quotes none of the caller's \
                 identifier, got {:?}",
                refused.text("message")
            );
        }
    }

    // The dataset the account DOES hold is still readable, so the sentence above reports a
    // missing dataset rather than a broken lookup.
    let read = emulator.get_dataset(&present).await;
    assert_eq!(
        read.status, 200,
        "the stored dataset is still readable, got {} and body {}",
        read.status, read.body
    );
}

/// One create whose `source` names an Amazon S3 object: the URI it carries, and whether
/// that URI resolves to the file object storage holds.
struct SourceRow {
    case: &'static str,
    name: &'static str,
    uri: String,
    resolves: bool,
}

/// RULE 2: `CreateDataset` resolves an Amazon S3 source before it creates anything — a URI
/// naming no readable object is refused 400 `ValidationException` naming that URI, and
/// leaves no dataset behind; the URI that does resolve is accepted and ingested.
#[tokio::test]
async fn create_dataset_resolves_its_s3_source_before_creating_anything() {
    let emulator = Emulator::with_object_storage();
    // The one object that is really there. Every other row's URI misses it in a different
    // way.
    emulator
        .put_object(BUCKET, PRESENT_KEY, jsonl(2).as_bytes())
        .await;

    let rows: [SourceRow; 6] = [
        SourceRow {
            case: "a key the bucket holds nothing at",
            name: "absent_key",
            uri: format!("s3://{BUCKET}/missing/examples.jsonl"),
            resolves: false,
        },
        SourceRow {
            case: "a bucket object storage does not hold",
            name: "absent_bucket",
            uri: "s3://dataset-source-nowhere/present/examples.jsonl".to_string(),
            resolves: false,
        },
        SourceRow {
            case: "the stored key with a suffix",
            name: "suffixed_key",
            uri: format!("s3://{BUCKET}/{PRESENT_KEY}.bak"),
            resolves: false,
        },
        SourceRow {
            case: "the stored key under another prefix",
            name: "other_prefix",
            uri: format!("s3://{BUCKET}/other/examples.jsonl"),
            resolves: false,
        },
        SourceRow {
            case: "a key differing from the stored one only in case",
            name: "other_case",
            uri: format!("s3://{BUCKET}/Present/examples.jsonl"),
            resolves: false,
        },
        SourceRow {
            case: "the key the bucket really holds",
            name: "resolvable",
            uri: format!("s3://{BUCKET}/{PRESENT_KEY}"),
            resolves: true,
        },
    ];

    let mut accepted: Vec<(&str, String)> = Vec::new();
    for row in &rows {
        let case = row.case;
        let answered = emulator
            .create_dataset(&json!({
                "datasetName": row.name,
                "schemaType": SCHEMA_TYPE,
                "source": {"s3Source": {"s3Uri": row.uri}},
            }))
            .await;
        if row.resolves {
            assert_eq!(
                answered.status, 202,
                "case {case:?}: a source that resolves is accepted, got {} and body {}",
                answered.status, answered.body
            );
            accepted.push((case, answered.text("datasetId")));
            continue;
        }
        assert_eq!(
            (answered.status, answered.error_code().as_str()),
            (400, "ValidationException"),
            "case {case:?}: expected HTTP 400 ValidationException from CreateDataset, got {} {} \
             and body {}",
            answered.status,
            answered.error_code(),
            answered.body
        );
        assert_eq!(
            answered.error_type, "ValidationException",
            "case {case:?}: expected x-amzn-errortype to name the modelled error shape, got {:?}",
            answered.error_type
        );
        assert_eq!(
            answered.text("message"),
            format!(
                "The specified S3 URI does not exist or is not accessible: {}",
                row.uri
            ),
            "case {case:?}: expected the refusal to name the URI the request carried, got {:?}",
            answered.text("message")
        );
        assert!(
            answered.body.get("datasetId").is_none()
                && answered.body.get("datasetArn").is_none(),
            "case {case:?}: a refused create reports no dataset, got {}",
            answered.body
        );
    }

    // Nothing the refused creates carried was persisted: the account holds exactly the one
    // dataset whose source resolved.
    let listed = emulator.list_datasets().await;
    let names: Vec<String> = listed.body["datasets"]
        .as_array()
        .map(|datasets| {
            datasets
                .iter()
                .map(|dataset| {
                    dataset["datasetName"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        names,
        vec!["resolvable".to_string()],
        "only the create whose source resolved left a dataset behind, got {}",
        listed.body
    );

    // And that dataset really ingested the file: the examples it reports are the ones the
    // object holds, once the clock has settled its status.
    for (case, dataset_id) in accepted {
        let settled = emulator.poll_until_settled(case, &dataset_id).await;
        assert_eq!(
            settled.text("status"),
            "ACTIVE",
            "case {case:?}: a resolved source settles ACTIVE, got {} and body {}",
            settled.text("status"),
            settled.body
        );
        assert_eq!(
            settled.body["exampleCount"],
            json!(2),
            "case {case:?}: expected the examples the object holds, got {}",
            settled.body["exampleCount"]
        );
    }
}
