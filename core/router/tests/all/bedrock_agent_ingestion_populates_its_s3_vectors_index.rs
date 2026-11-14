// SPDX-License-Identifier: CC0-1.0

//! A Bedrock Agent ingestion job over an S3 data source really populates the S3
//! Vectors index its knowledge base is bound to, as that service's own
//! `ListVectors` reports it — and the data source's `dataDeletionPolicy` decides
//! what becomes of those vectors when the data source is deleted.
//!
//! The rule under test: **an ingestion job's `IngestionJobStatistics` measure the
//! run — a job that completes over a data source holding N previously-unseen
//! source documents reports N newly indexed — and every document it reports
//! indexed is backed by a vector the OWNING vector store returns from its own
//! read**; a `DELETE` data-deletion policy then removes exactly that data
//! source's vectors on its deletion, and `RETAIN` leaves them. Three crates have
//! to agree for that to hold (Amazon S3 holds the source documents, Amazon
//! Bedrock Agent runs the job, Amazon S3 Vectors holds the vectors and answers
//! for them), so the suite lives here rather than in any one of them.
//!
//! The rows differ along what the rule generalises over: how many source
//! documents the ingested data source holds, and which `dataDeletionPolicy`
//! value it declares (`RETAIN` and `DELETE`, the two the modelled
//! `DataDeletionPolicy` admits). Every row also runs a SIBLING data source of the
//! same knowledge base into the same index, so a delete that removed more than
//! the deleted data source's own vectors fails the row.
//!
//! Every call goes over the wire of the service that owns it, and the one wait —
//! for the clock to complete a started job — is a poll for that condition under a
//! deadline generous enough for any host.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

/// The Region every call here is signed for.
const REGION: &str = "us-east-1";

/// The account id every ARN this emulator mints carries.
const ACCOUNT: &str = "000000000000";

/// A role ARN matching the modelled `KnowledgeBaseRoleArn` pattern.
const KB_ROLE: &str =
    "arn:aws:iam::000000000000:role/service-role/AmazonBedrockExecutionRoleForKnowledgeBase";

/// The embedding model each knowledge base here declares, and how many values
/// its vectors carry: Titan Text Embeddings V2 produces 1024, so the index the
/// knowledge base writes into holds vectors of exactly that length.
const EMBEDDING_MODEL: &str =
    "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0";
const EMBEDDING_DIMENSION: u32 = 1024;

/// The metadata key a Bedrock knowledge base records a chunk's source location
/// under in its vector store, as the published knowledge-base metadata fields
/// name it.
const SOURCE_URI_METADATA_KEY: &str = "x-amz-bedrock-kb-source-uri";

/// How long a poll waits for the clock to complete a started ingestion job: many
/// times the spans the owning service owes it, so a loaded machine still
/// converges, and bounded so a hung poll fails this test rather than hanging the
/// suite.
const COMPLETION_POLL_CAP: Duration = Duration::from_secs(30);

/// How long one poll attempt waits before reading the job again.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The emulator with the three services this suite exercises, mounted on ONE
/// engine exactly as `core/router/src/lib.rs` mounts them.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
        Arc::clone(&engine),
    ));
    router.register_service(
        service_com_amazonaws_s3vectors_s3vectors::EmulatedService::new(Arc::clone(&engine)),
    );
    router.register_service(
        service_com_amazonaws_bedrockagent_amazonbedrockagentbuildtimelambda::EmulatedService::new(
            engine,
        ),
    );
    router
}

/// A SigV4 `Authorization` header whose credential scope names `service` in
/// [`REGION`], which is what routes the request and what each handler reads its
/// Region from.
fn authorization(service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/{REGION}/{service}/\
         aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000\
         000000000000000000000000"
    )
}

/// One request against Amazon S3's REST surface, path-style.
async fn s3(router: &MultiServiceRouter, method: &str, path: &str, body: &str) -> (u16, String) {
    let host = format!("s3.{REGION}.amazonaws.com");
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("host", host)
        .header("authorization", authorization("s3"))
        .header("content-type", "application/octet-stream")
        .body(Bytes::from(body.to_owned()))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    (
        response.status().as_u16(),
        String::from_utf8_lossy(response.body()).into_owned(),
    )
}

/// `PUT /<bucket>` — S3's `CreateBucket`.
async fn create_bucket(router: &MultiServiceRouter, case: &str, bucket: &str) {
    let (status, answered) = s3(router, "PUT", &format!("/{bucket}"), "").await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateBucket({bucket:?}) must succeed, got {status} with {answered}"
    );
}

/// `PUT /<bucket>/<key>` — S3's `PutObject`, the write that puts a source
/// document where a data source's crawl finds it.
async fn put_object(router: &MultiServiceRouter, case: &str, bucket: &str, key: &str, body: &str) {
    let (status, answered) = s3(router, "PUT", &format!("/{bucket}/{key}"), body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: PutObject({bucket:?}, {key:?}) must succeed, got {status} with {answered}"
    );
}

/// One Amazon S3 Vectors operation over its restJson1 wire: a POST to the
/// operation's own URI, which is how that model binds every one of them.
async fn s3vectors(router: &MultiServiceRouter, operation: &str, body: &Value) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("/{operation}"))
        .header("host", format!("s3vectors.{REGION}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("s3vectors"))
        .body(Bytes::from(
            serde_json::to_vec(body).expect("the request body serializes"),
        ))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, payload)
}

/// One Amazon Bedrock Agent operation over the `restJson1` wire its model
/// declares, on the method and URI that operation's own `@http` binding names,
/// signed for `bedrock` — the signing name every Bedrock-family model declares.
async fn bedrock_agent(
    router: &MultiServiceRouter,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let payload = body
        .map(|value| Bytes::from(serde_json::to_vec(&value).expect("the request body serializes")))
        .unwrap_or_default();
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", format!("bedrock.{REGION}.amazonaws.com"))
        .header("content-type", "application/json")
        .header("authorization", authorization("bedrock"))
        .body(payload)
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let answered: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, answered)
}

/// A string member of an answer, by path.
fn string_at(document: &Value, path: &[&str]) -> String {
    let mut at = document;
    for key in path {
        at = &at[*key];
    }
    at.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string in {document:?}"))
        .to_string()
}

/// One counter of an ingestion job's statistics.
fn counter(job: &Value, member: &str) -> i64 {
    job["ingestionJob"]["statistics"][member]
        .as_i64()
        .unwrap_or_else(|| panic!("statistics.{member} is not a number in {job:?}"))
}

/// The `s3://` URI of one source document, as `S3Location$uri` spells it and as
/// the vector written for it is keyed by.
fn uri(bucket: &str, key: &str) -> String {
    format!("s3://{bucket}/{key}")
}

/// Create the vector bucket and the index a knowledge base binds to, answering
/// the bucket's ARN as the owning service minted it.
async fn vector_store(
    router: &MultiServiceRouter,
    case: &str,
    bucket: &str,
    index: &str,
) -> String {
    let (status, created) =
        s3vectors(router, "CreateVectorBucket", &json!({ "vectorBucketName": bucket })).await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateVectorBucket({bucket:?}) must succeed, got {status} with {created:?}"
    );
    let vector_bucket_arn = string_at(&created, &["vectorBucketArn"]);
    assert_eq!(
        vector_bucket_arn,
        format!("arn:aws:s3vectors:{REGION}:{ACCOUNT}:bucket/{bucket}"),
        "case {case:?}: expected the minted vector bucket ARN to name the bucket in {REGION}"
    );
    let (status, index_created) = s3vectors(
        router,
        "CreateIndex",
        &json!({
            "vectorBucketName": bucket,
            "indexName": index,
            "dataType": "float32",
            "dimension": EMBEDDING_DIMENSION,
            "distanceMetric": "cosine",
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateIndex({index:?}) must succeed, got {status} with {index_created:?}"
    );
    vector_bucket_arn
}

/// `ListVectors` over the bound index, with each vector's metadata: the keys it
/// reports, in key order, each paired with the source URI the knowledge base
/// recorded for it.
async fn listed_vectors(
    router: &MultiServiceRouter,
    case: &str,
    bucket: &str,
    index: &str,
) -> Vec<(String, String)> {
    let (status, listed) = s3vectors(
        router,
        "ListVectors",
        &json!({
            "vectorBucketName": bucket,
            "indexName": index,
            "returnMetadata": true,
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: ListVectors({index:?}) must succeed, got {status} with {listed:?}"
    );
    let mut reported: Vec<(String, String)> = listed["vectors"]
        .as_array()
        .unwrap_or_else(|| panic!("case {case:?}: vectors is a list in {listed:?}"))
        .iter()
        .map(|vector| {
            (
                string_at(vector, &["key"]),
                vector["metadata"][SOURCE_URI_METADATA_KEY]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    reported.sort();
    reported
}

/// Create a knowledge base over the index `(vector_bucket_arn, index)` and
/// answer its minted id.
async fn knowledge_base(
    router: &MultiServiceRouter,
    case: &str,
    name: &str,
    vector_bucket_arn: &str,
    index: &str,
) -> String {
    let (status, created) = bedrock_agent(
        router,
        "PUT",
        "/knowledgebases/",
        Some(json!({
            "name": name,
            "roleArn": KB_ROLE,
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": { "embeddingModelArn": EMBEDDING_MODEL },
            },
            "storageConfiguration": {
                "type": "S3_VECTORS",
                "s3VectorsConfiguration": {
                    "vectorBucketArn": vector_bucket_arn,
                    "indexName": index,
                },
            },
        })),
    )
    .await;
    assert_eq!(
        status, 202,
        "case {case:?}: CreateKnowledgeBase({name:?}) must succeed, got {status} with {created:?}"
    );
    string_at(&created, &["knowledgeBase", "knowledgeBaseId"])
}

/// Create an S3 data source over `prefix` of `bucket` under `policy`, answering
/// its minted id.
async fn data_source(
    router: &MultiServiceRouter,
    case: &str,
    knowledge_base_id: &str,
    name: &str,
    bucket: &str,
    prefix: &str,
    policy: &str,
) -> String {
    let (status, created) = bedrock_agent(
        router,
        "PUT",
        &format!("/knowledgebases/{knowledge_base_id}/datasources/"),
        Some(json!({
            "name": name,
            "dataDeletionPolicy": policy,
            "dataSourceConfiguration": {
                "type": "S3",
                "s3Configuration": {
                    "bucketArn": format!("arn:aws:s3:::{bucket}"),
                    "inclusionPrefixes": [prefix],
                },
            },
        })),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: CreateDataSource({name:?}) must succeed, got {status} with {created:?}"
    );
    string_at(&created, &["dataSource", "dataSourceId"])
}

/// Start an ingestion job for one data source and POLL `GetIngestionJob` until
/// the clock has completed it, answering the completed job.
async fn run_ingestion_job(
    router: &MultiServiceRouter,
    case: &str,
    knowledge_base_id: &str,
    data_source_id: &str,
) -> Value {
    let jobs = format!("/knowledgebases/{knowledge_base_id}/datasources/{data_source_id}/ingestionjobs");
    let (status, started) = bedrock_agent(router, "PUT", &format!("{jobs}/"), Some(json!({}))).await;
    assert_eq!(
        status, 202,
        "case {case:?}: StartIngestionJob must succeed, got {status} with {started:?}"
    );
    let ingestion_job_id = string_at(&started, &["ingestionJob", "ingestionJobId"]);
    let deadline = Instant::now() + COMPLETION_POLL_CAP;
    loop {
        let (status, read) =
            bedrock_agent(router, "GET", &format!("{jobs}/{ingestion_job_id}"), None).await;
        assert_eq!(
            status, 200,
            "case {case:?}: GetIngestionJob({ingestion_job_id}) must succeed, got {status} with \
             {read:?}"
        );
        if string_at(&read, &["ingestionJob", "status"]) == "COMPLETE" {
            return read;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the clock must complete job {ingestion_job_id}, last read {read:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// One ingestion, with the data-deletion policy its data source declares.
struct Row {
    case: &'static str,
    /// How many source documents the ingested data source holds.
    documents: usize,
    /// The data source's `dataDeletionPolicy` — one of the two values the
    /// modelled `DataDeletionPolicy` admits
    /// (`smithy_query(query="shape",shape="DataDeletionPolicy")`).
    policy: &'static str,
    /// Whether the vectors of that data source's documents are still in the
    /// index once it is deleted, which is what the policy decides.
    survives_deletion: bool,
}

/// An ingestion job accounts for the documents it indexed, those vectors are in
/// the bound index as S3 Vectors itself reports them, and the data source's
/// `dataDeletionPolicy` decides whether they outlive the data source.
#[tokio::test]
async fn an_ingestion_job_populates_the_bound_s3_vectors_index() {
    let rows = [
        Row {
            case: "two documents, RETAIN",
            documents: 2,
            policy: "RETAIN",
            survives_deletion: true,
        },
        Row {
            case: "three documents, DELETE",
            documents: 3,
            policy: "DELETE",
            survives_deletion: false,
        },
        Row {
            case: "one document, DELETE",
            documents: 1,
            policy: "DELETE",
            survives_deletion: false,
        },
    ];

    for (position, row) in rows.iter().enumerate() {
        let case = row.case;
        let router = build_router();
        let vectors_bucket = format!("kb-ingest-vectors-{position}");
        let index = format!("kb-ingest-index-{position}");
        let source_bucket = format!("kb-ingest-source-{position}");
        let vector_bucket_arn = vector_store(&router, case, &vectors_bucket, &index).await;

        // The source documents, written through Amazon S3's own PutObject: the
        // ingested data source's under one prefix, and one more under a second
        // prefix that a SIBLING data source of the same knowledge base ingests.
        create_bucket(&router, case, &source_bucket).await;
        let mut ingested: Vec<String> = Vec::new();
        for document in 0..row.documents {
            let key = format!("ingested/document-{document}.txt");
            put_object(
                &router,
                case,
                &source_bucket,
                &key,
                &format!("the text of document {document} of {case}"),
            )
            .await;
            ingested.push(uri(&source_bucket, &key));
        }
        let sibling_key = "retained/sibling.txt";
        put_object(
            &router,
            case,
            &source_bucket,
            sibling_key,
            "the sibling data source's own document",
        )
        .await;
        let sibling_uri = uri(&source_bucket, sibling_key);

        let knowledge_base_id = knowledge_base(
            &router,
            case,
            &format!("kb-ingest-{position}"),
            &vector_bucket_arn,
            &index,
        )
        .await;
        let subject = data_source(
            &router,
            case,
            &knowledge_base_id,
            &format!("kb-ingest-subject-{position}"),
            &source_bucket,
            "ingested/",
            row.policy,
        )
        .await;
        let sibling = data_source(
            &router,
            case,
            &knowledge_base_id,
            &format!("kb-ingest-sibling-{position}"),
            &source_bucket,
            "retained/",
            "RETAIN",
        )
        .await;

        // The job's own accounting of what it did.
        let job = run_ingestion_job(&router, case, &knowledge_base_id, &subject).await;
        let counted = i64::try_from(row.documents).expect("a small count");
        for (member, expected) in [
            ("numberOfDocumentsScanned", counted),
            ("numberOfNewDocumentsIndexed", counted),
            ("numberOfModifiedDocumentsIndexed", 0),
            ("numberOfDocumentsDeleted", 0),
            ("numberOfDocumentsFailed", 0),
            ("numberOfDocumentsSkipped", 0),
        ] {
            assert_eq!(
                counter(&job, member),
                expected,
                "case {case:?}: expected statistics.{member} to be {expected}, got {:?}",
                job["ingestionJob"]["statistics"]
            );
        }
        let sibling_job = run_ingestion_job(&router, case, &knowledge_base_id, &sibling).await;
        assert_eq!(
            counter(&sibling_job, "numberOfNewDocumentsIndexed"),
            1,
            "case {case:?}: expected the sibling data source's one document indexed as new, got \
             {:?}",
            sibling_job["ingestionJob"]["statistics"]
        );

        // Every document either job reported indexed is backed by a vector the
        // vector store itself answers for, recorded against the source document
        // it was built from.
        let mut expected: Vec<(String, String)> = ingested
            .iter()
            .chain(std::iter::once(&sibling_uri))
            .map(|uri| (uri.clone(), uri.clone()))
            .collect();
        expected.sort();
        let listed = listed_vectors(&router, case, &vectors_bucket, &index).await;
        assert_eq!(
            listed, expected,
            "case {case:?}: expected ListVectors to report one vector per indexed document, each \
             carrying its source URI, got {listed:?}"
        );

        // The data source's policy then decides what becomes of its vectors — and
        // of its sibling's, which are never this delete's to take.
        let (status, deleted) = bedrock_agent(
            &router,
            "DELETE",
            &format!("/knowledgebases/{knowledge_base_id}/datasources/{subject}"),
            None,
        )
        .await;
        assert_eq!(
            status, 202,
            "case {case:?}: DeleteDataSource must be accepted, got {status} with {deleted:?}"
        );
        let mut after: Vec<(String, String)> = vec![(sibling_uri.clone(), sibling_uri.clone())];
        if row.survives_deletion {
            for uri in &ingested {
                after.push((uri.clone(), uri.clone()));
            }
        }
        after.sort();
        let remaining = listed_vectors(&router, case, &vectors_bucket, &index).await;
        assert_eq!(
            remaining, after,
            "case {case:?}: under dataDeletionPolicy {} expected ListVectors to report \
             {after:?} after the delete, got {remaining:?}",
            row.policy
        );
    }
}
