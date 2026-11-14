// SPDX-License-Identifier: CC0-1.0

//! An ingestion job's `IngestionJobStatistics` measure THAT job's run over THAT
//! data source.
//!
//! `StartIngestionJob` "begins a data ingestion job. Data sources are ingested
//! into your knowledge base", and the counters the job carries are the service's
//! own accounting of what that run did: `numberOfDocumentsScanned` is "the total
//! number of source documents that were scanned. Includes new, updated, and
//! unchanged documents" and `numberOfNewDocumentsIndexed` "the number of new
//! source documents in the data source that were successfully indexed", beside
//! the modified, deleted, failed and skipped counts
//! (`smithy_query(query="shape",shape="IngestionJobStatistics")`). Every member
//! is a `PrimitiveLong` defaulting to 0, so a zero means "this run did none of
//! that" rather than "this emulator did not count".
//!
//! What this suite pins is the part of that rule that is about WHOSE run a
//! counter reports, which no other suite drives:
//!
//! * a job accounts for the source documents of its OWN data source — a sibling
//!   data source of the same knowledge base, ingested from the same bucket under
//!   its own inclusion prefix, is not in its counters;
//! * the counters scale with the number of documents that data source holds;
//! * a job that has completed keeps the accounting it measured: a LATER run over
//!   the same data source reports its own counters and does not restate the
//!   earlier job's;
//! * reading a job reports the same counters however often it is read, so a
//!   polling client cannot move them.
//!
//! The rows differ along what the rule generalises over: how many source
//! documents the data source holds (none, one, two, several) and which of the
//! knowledge base's data sources holds them.
//!
//! Every assertion here goes through the router, so it exercises the real wire
//! path (route matching, model constraint validation, serialization) rather than
//! calling a handler directly, and every wait is a poll for the CONDITION — the
//! job's terminal status — under a deadline generous enough for any host.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{json, Value};
use service_com_amazonaws_bedrockagent_amazonbedrockagentbuildtimelambda::EmulatedService;
use service_com_amazonaws_s3_amazons3::state::{service_state as s3_state, Object};
use smithy_server_runtime::MultiServiceRouter;

use crate::vector_store_fixture::{index_vector_keys, seed_index, EMBEDDING_DIMENSION};

/// A SigV4 `Authorization` header scoped to the `bedrock` signing name: the
/// routing key this service claims on.
const AUTHORIZATION: &str = "AWS4-HMAC-SHA256 \
     Credential=AKIDEXAMPLE/20260101/eu-west-1/bedrock/aws4_request, \
     SignedHeaders=host;x-amz-date, Signature=0123456789abcdef";

/// The region the data source's bucket is held in.
const REGION: &str = "eu-west-1";

/// A role ARN matching the modelled `KnowledgeBaseRoleArn` pattern.
const KB_ROLE: &str =
    "arn:aws:iam::000000000000:role/service-role/AmazonBedrockExecutionRoleForKnowledgeBase";

/// An embedding model ARN matching the modelled `BedrockEmbeddingModelArn`.
const EMBEDDING_MODEL: &str =
    "arn:aws:bedrock:eu-west-1::foundation-model/amazon.titan-embed-text-v2:0";

/// The vector bucket the knowledge bases here bind to.
const VECTOR_BUCKET: &str = "arn:aws:s3vectors:::bucket/own-run-vectors";

/// The index of [`VECTOR_BUCKET`] the ingested vectors are written into.
const INDEX: &str = "own-run-index";

/// The S3 bucket every data source here is crawled from.
const SOURCE_BUCKET: &str = "own-run-source-documents";

/// How long a poll waits for the clock to complete a started job: many times the
/// spans the service owes it, so a loaded machine still converges, and bounded
/// so a hung poll fails this test rather than hanging the suite.
const COMPLETION_POLL_CAP: Duration = Duration::from_secs(30);

/// How long one poll attempt waits before reading the job again.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Every member of the modelled `IngestionJobStatistics`
/// (`smithy_query(query="shape",shape="IngestionJobStatistics")`), which is what
/// makes "the counters this job reports" a complete reading rather than the few
/// an assertion happens to name.
const STATISTICS_MEMBERS: [&str; 8] = [
    "numberOfDocumentsScanned",
    "numberOfMetadataDocumentsScanned",
    "numberOfNewDocumentsIndexed",
    "numberOfModifiedDocumentsIndexed",
    "numberOfMetadataDocumentsModified",
    "numberOfDocumentsDeleted",
    "numberOfDocumentsFailed",
    "numberOfDocumentsSkipped",
];

/// One HTTP answer from the emulator, parsed.
#[derive(Debug)]
struct Answer {
    status: u16,
    body: Value,
}

impl Answer {
    fn member(&self, path: &[&str]) -> &Value {
        let mut at = &self.body;
        for key in path {
            at = &at[*key];
        }
        at
    }

    fn string(&self, path: &[&str]) -> String {
        self.member(path)
            .as_str()
            .unwrap_or_else(|| panic!("{path:?} is not a string in {:?}", self.body))
            .to_string()
    }

    /// Every counter of the job's statistics, as a client reads them.
    fn statistics(&self) -> BTreeMap<&'static str, i64> {
        STATISTICS_MEMBERS
            .into_iter()
            .map(|member| {
                let value = self
                    .member(&["ingestionJob", "statistics", member])
                    .as_i64()
                    .unwrap_or_else(|| {
                        panic!("statistics.{member} is not a number in {:?}", self.body)
                    });
                (member, value)
            })
            .collect()
    }
}

/// The counters a run over `new` previously-unseen documents, `modified`
/// rewritten ones and `deleted` departed ones must report, with everything else
/// at the modelled zero.
fn expected_statistics(
    scanned: i64,
    new: i64,
    modified: i64,
    deleted: i64,
) -> BTreeMap<&'static str, i64> {
    let mut expected: BTreeMap<&'static str, i64> =
        STATISTICS_MEMBERS.into_iter().map(|member| (member, 0)).collect();
    expected.insert("numberOfDocumentsScanned", scanned);
    expected.insert("numberOfNewDocumentsIndexed", new);
    expected.insert("numberOfModifiedDocumentsIndexed", modified);
    expected.insert("numberOfDocumentsDeleted", deleted);
    expected
}

/// The emulator under test: one router over one shared engine, exactly as the
/// production router mounts this service.
struct Emulator {
    router: MultiServiceRouter,
    engine: Arc<engine::InMemoryEngine>,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        // The vector store the knowledge base binds to, and the bucket its data
        // sources are crawled from: both set up before anything names them, as a
        // caller sets them up against AWS.
        seed_index(&engine, VECTOR_BUCKET, INDEX, EMBEDDING_DIMENSION);
        {
            let state = s3_state(&*engine).expect("the object store on this engine");
            state.lock().create_bucket(SOURCE_BUCKET, REGION);
        }
        let mut router = MultiServiceRouter::new();
        router.set_request_authentication(false);
        router.register_service(EmulatedService::new(Arc::clone(&engine)));
        Self { router, engine }
    }

    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> Answer {
        let bytes = body
            .map(|value| Bytes::from(serde_json::to_vec(&value).expect("serialize request body")))
            .unwrap_or_default();
        let request = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "bedrock-agent.eu-west-1.amazonaws.com")
            .header("authorization", AUTHORIZATION)
            .header("content-type", "application/json")
            .body(bytes)
            .expect("build the request");

        let response = self.router.dispatch(request).await;
        let status = response.status().as_u16();
        let raw = response.into_body();
        let body: Value = if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw).unwrap_or_else(|error| {
                panic!(
                    "{method} {uri} -> {status} body is not JSON ({error}): {}",
                    String::from_utf8_lossy(&raw)
                )
            })
        };
        Answer { status, body }
    }

    /// Store `body` at `key` of the source bucket, through Amazon S3's own store
    /// — the one map its `PutObject` writes and its `GetObject` reads.
    fn hold_object(&self, key: &str, body: &str) {
        let state = s3_state(&*self.engine).expect("the object store on this engine");
        let mut store = state.lock();
        let written = store.put_object(
            SOURCE_BUCKET,
            key,
            Object::stored(body.as_bytes().to_vec(), Some("text/plain".to_string())),
        );
        assert!(
            written.is_some(),
            "the harness must be able to store the source document at {key:?}"
        );
    }

    /// Create a knowledge base bound to [`INDEX`] and answer its minted id.
    async fn knowledge_base(&self, name: &str) -> String {
        let created = self
            .call(
                "PUT",
                "/knowledgebases/",
                Some(json!({
                    "name": name,
                    "roleArn": KB_ROLE,
                    "knowledgeBaseConfiguration": {
                        "type": "VECTOR",
                        "vectorKnowledgeBaseConfiguration": {
                            "embeddingModelArn": EMBEDDING_MODEL,
                        },
                    },
                    "storageConfiguration": {
                        "type": "S3_VECTORS",
                        "s3VectorsConfiguration": {
                            "vectorBucketArn": VECTOR_BUCKET,
                            "indexName": INDEX,
                        },
                    },
                })),
            )
            .await;
        assert_eq!(
            created.status, 202,
            "case setup: expected CreateKnowledgeBase -> 202, got {created:?}"
        );
        created.string(&["knowledgeBase", "knowledgeBaseId"])
    }

    /// Attach an S3 data source over `prefix` of the source bucket and answer
    /// its minted id.
    async fn data_source(&self, knowledge_base_id: &str, name: &str, prefix: &str) -> String {
        let created = self
            .call(
                "PUT",
                &format!("/knowledgebases/{knowledge_base_id}/datasources/"),
                Some(json!({
                    "name": name,
                    "dataSourceConfiguration": {
                        "type": "S3",
                        "s3Configuration": {
                            "bucketArn": format!("arn:aws:s3:::{SOURCE_BUCKET}"),
                            "inclusionPrefixes": [prefix],
                        },
                    },
                })),
            )
            .await;
        assert_eq!(
            created.status, 200,
            "case setup: expected CreateDataSource -> 200, got {created:?}"
        );
        created.string(&["dataSource", "dataSourceId"])
    }

    /// `GetIngestionJob` for one job of one data source.
    async fn get_ingestion_job(
        &self,
        knowledge_base_id: &str,
        data_source_id: &str,
        ingestion_job_id: &str,
    ) -> Answer {
        self.call(
            "GET",
            &format!(
                "/knowledgebases/{knowledge_base_id}/datasources/{data_source_id}\
                 /ingestionjobs/{ingestion_job_id}"
            ),
            None,
        )
        .await
    }

    /// Start an ingestion job and answer the `ingestionJobId` it minted.
    async fn start_ingestion_job(&self, knowledge_base_id: &str, data_source_id: &str) -> String {
        let started = self
            .call(
                "PUT",
                &format!(
                    "/knowledgebases/{knowledge_base_id}/datasources/{data_source_id}\
                     /ingestionjobs/"
                ),
                Some(json!({})),
            )
            .await;
        assert_eq!(
            started.status, 202,
            "case setup: expected StartIngestionJob -> 202, got {started:?}"
        );
        started.string(&["ingestionJob", "ingestionJobId"])
    }

    /// Start a job and POLL `GetIngestionJob` until the clock has completed it,
    /// answering the completed job and its id.
    async fn run_ingestion_job(
        &self,
        knowledge_base_id: &str,
        data_source_id: &str,
    ) -> (String, Answer) {
        let ingestion_job_id = self
            .start_ingestion_job(knowledge_base_id, data_source_id)
            .await;
        let deadline = Instant::now() + COMPLETION_POLL_CAP;
        loop {
            let read = self
                .get_ingestion_job(knowledge_base_id, data_source_id, &ingestion_job_id)
                .await;
            assert_eq!(
                read.status, 200,
                "case setup: expected GetIngestionJob -> 200, got {read:?}"
            );
            if read.string(&["ingestionJob", "status"]) == "COMPLETE" {
                return (ingestion_job_id, read);
            }
            assert!(
                Instant::now() < deadline,
                "case setup: the clock must complete job {ingestion_job_id}, last read {read:?}"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// The keys of the vectors the bound index holds.
    fn index_keys(&self) -> Vec<String> {
        index_vector_keys(&self.engine, VECTOR_BUCKET, INDEX)
    }
}

/// The `s3://` URI of one source document, as a knowledge-base document and the
/// vector written for it name it.
fn uri(key: &str) -> String {
    format!("s3://{SOURCE_BUCKET}/{key}")
}

/// One data source of the shared knowledge base, and how many documents it
/// holds.
struct SiblingRow {
    case: &'static str,
    /// The data source's single `inclusionPrefixes` entry, which is what makes
    /// its documents its own.
    prefix: &'static str,
    /// How many source documents sit under that prefix.
    documents: usize,
}

/// Each data source of one knowledge base is ingested on its own account: a
/// job's counters report the documents of ITS data source, however many
/// documents its siblings hold, and the bound index ends up holding a vector for
/// every document of every one of them.
#[tokio::test]
async fn each_job_accounts_for_the_documents_of_its_own_data_source() {
    let rows = [
        SiblingRow {
            case: "a prefix holding nothing",
            prefix: "empty/",
            documents: 0,
        },
        SiblingRow {
            case: "a prefix holding one document",
            prefix: "single/",
            documents: 1,
        },
        SiblingRow {
            case: "a prefix holding two documents",
            prefix: "pair/",
            documents: 2,
        },
        SiblingRow {
            case: "a prefix holding five documents",
            prefix: "five/",
            documents: 5,
        },
    ];

    let emulator = Emulator::new();
    let mut every_uri: Vec<String> = Vec::new();
    for row in &rows {
        for index in 0..row.documents {
            let key = format!("{}document-{index}.txt", row.prefix);
            emulator.hold_object(&key, &format!("the text of {key}"));
            every_uri.push(uri(&key));
        }
    }
    every_uri.sort();

    // One knowledge base, one bucket, one data source per row: so a counter that
    // reported the BUCKET's documents rather than the data source's own would be
    // wrong on every row but the widest.
    let knowledge_base_id = emulator.knowledge_base("own-run-siblings-kb").await;
    let mut jobs: Vec<(&SiblingRow, String, String, BTreeMap<&'static str, i64>)> = Vec::new();
    for (position, row) in rows.iter().enumerate() {
        let data_source_id = emulator
            .data_source(
                &knowledge_base_id,
                &format!("own-run-ds-{position}"),
                row.prefix,
            )
            .await;
        let (ingestion_job_id, completed) = emulator
            .run_ingestion_job(&knowledge_base_id, &data_source_id)
            .await;
        let counted = i64::try_from(row.documents).expect("a small count");
        let expected = expected_statistics(counted, counted, 0, 0);
        let measured = completed.statistics();
        assert_eq!(
            measured, expected,
            "case {}: expected the job over {} documents to report {expected:?}, got {measured:?}",
            row.case, row.documents
        );
        jobs.push((row, data_source_id, ingestion_job_id, measured));
    }

    // Every document of every data source really has a vector in the bound
    // index, so the counters above are statements about work that happened.
    assert_eq!(
        emulator.index_keys(),
        every_uri,
        "case every data source: expected the bound index to hold one vector per indexed \
         document of every data source"
    );

    // And reading a completed job again — after every sibling has run — reports
    // the counters IT measured, unchanged.
    for (row, data_source_id, ingestion_job_id, measured) in &jobs {
        let reread = emulator
            .get_ingestion_job(&knowledge_base_id, data_source_id, ingestion_job_id)
            .await;
        assert_eq!(
            reread.status, 200,
            "case {}: expected GetIngestionJob -> 200, got {reread:?}",
            row.case
        );
        assert_eq!(
            &reread.statistics(),
            measured,
            "case {}: expected re-reading the job to report {measured:?}, got {:?}",
            row.case,
            reread.statistics()
        );
    }
}

/// A completed job keeps the accounting of its own run: a second job over the
/// same data source reports what IT found, and the first still reports what it
/// found — however often either is read.
#[tokio::test]
async fn a_completed_job_keeps_the_accounting_of_its_own_run() {
    let emulator = Emulator::new();
    emulator.hold_object("docs/kept.txt", "unchanged between the two runs");
    emulator.hold_object("docs/rewritten.txt", "the first revision");
    let knowledge_base_id = emulator.knowledge_base("own-run-history-kb").await;
    let data_source_id = emulator
        .data_source(&knowledge_base_id, "own-run-history-ds", "docs/")
        .await;

    let (first_id, first) = emulator
        .run_ingestion_job(&knowledge_base_id, &data_source_id)
        .await;
    let first_statistics = expected_statistics(2, 2, 0, 0);
    assert_eq!(
        first.statistics(),
        first_statistics,
        "case the first run: expected {first_statistics:?}, got {:?}",
        first.statistics()
    );

    // The source changes under the data source: one document is rewritten and
    // one is added, so the second run has its own, different accounting.
    emulator.hold_object("docs/rewritten.txt", "the second revision, longer than the first");
    emulator.hold_object("docs/added.txt", "written between the two runs");

    let (second_id, second) = emulator
        .run_ingestion_job(&knowledge_base_id, &data_source_id)
        .await;
    let second_statistics = expected_statistics(3, 1, 1, 0);
    assert_eq!(
        second.statistics(),
        second_statistics,
        "case the second run: expected {second_statistics:?}, got {:?}",
        second.statistics()
    );

    // Two reads of each job, after both runs: a job's counters are its run's,
    // and reading one neither restates it from the latest run nor moves it.
    for attempt in 0..2 {
        for (case, ingestion_job_id, expected) in [
            ("the first run", &first_id, &first_statistics),
            ("the second run", &second_id, &second_statistics),
        ] {
            let reread = emulator
                .get_ingestion_job(&knowledge_base_id, &data_source_id, ingestion_job_id)
                .await;
            assert_eq!(
                reread.status, 200,
                "case {case} (read {attempt}): expected GetIngestionJob -> 200, got {reread:?}"
            );
            assert_eq!(
                &reread.statistics(),
                expected,
                "case {case} (read {attempt}): expected {expected:?}, got {:?}",
                reread.statistics()
            );
        }
    }

    // The documents of both runs are in the bound index: the second run added
    // the new document's vector and replaced the rewritten one's rather than
    // leaving the index behind what the counters claim.
    assert_eq!(
        emulator.index_keys(),
        vec![
            uri("docs/added.txt"),
            uri("docs/kept.txt"),
            uri("docs/rewritten.txt")
        ],
        "case after both runs: expected the bound index to hold one vector per document the \
         data source now holds"
    );
}
