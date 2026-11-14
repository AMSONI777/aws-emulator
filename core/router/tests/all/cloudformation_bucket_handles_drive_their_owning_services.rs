// SPDX-License-Identifier: CC0-1.0

//! The handle a CloudFormation stack publishes for each S3 bucket variant is the identifier
//! its OWNING service takes — and for the Amazon S3 Tables table bucket that means EVERY
//! operation of that service keyed by it, not one read.
//!
//! The rule under test: **a resource type's physical resource id — the value a resource row
//! reports and the value `Ref` of its logical id resolves to, which are the same value — is
//! the identifier the owning service's own API accepts for the resource, so a client holding
//! only that value can pass it to any operation of that service keyed by it.** Amazon S3
//! keys a bucket by `Bucket=<name>`, so `AWS::S3::Bucket` publishes the bare name; Amazon S3
//! Tables keys a table bucket by `tableBucketARN` and Amazon S3 Vectors a vector bucket by
//! `vectorBucketArn`, so those two types publish the resource's own ARN. Four crates have to
//! agree for that to hold (CloudFormation makes the creates, the three S3 services serve
//! them), so the suite lives here rather than in any one of them.
//!
//! `cloudformation_provisions_s3tables_table_buckets.rs` pins the SHAPE of the table bucket's
//! handle against one read (`GetTableBucket`). What this suite adds is the rest of the rule:
//! the published handle is accepted wherever the owning service's model keys an operation by
//! it. The rows span the operations S3 Tables binds `tableBucketARN` as an `@httpLabel` of
//! (`GetTableBucket`, `CreateNamespace`, `GetNamespace`, `ListNamespaces`, `CreateTable`,
//! `ListTables`) plus the one listing that reports the bucket without taking it
//! (`ListTableBuckets`), each on the value the stack published; and the stacks span what the
//! rule generalises over besides — the Region deployed in, and whether each bucket is NAMED
//! by the template or left for CloudFormation to generate a name — with the two sibling
//! variants deployed beside the table bucket in every stack, since the rule is that the three
//! publish the identifier SHAPE of three different services from one stack.
//!
//! The rows are read through `ListStackResources` (drained through its `NextToken`) and
//! through the stack's `Ref` outputs, and the two must agree: a client reads the handle either
//! way.
//!
//! Every expected value is computed here from what the template declares, never read back out
//! of the answer being checked — except a GENERATED bucket name, which is CloudFormation's to
//! compute: what is checked about one is that the handle is that name's ARN (or, for the plain
//! bucket, that name itself) and that the owning service resolves it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

// The XML element readers this crate writes ONCE (`tests/all/query_wire.rs`).
use super::query_wire::{opt_element, outputs_of, physical_ids_of};
// The four-service router, the three wire callers, the handle writer, the two ARN forms and
// the published table bucket name form the sibling provisioning suite for these types already
// writes: both suites drive the SAME emulator through the same calls, and compute a handle —
// and hold a name to the form its service publishes — the same way.
use super::cloudformation_provisions_s3tables_table_buckets::{
    build_router, cloudformation, get_bucket_location, is_s3tables_name, label, s3tables,
    s3vectors, table_bucket_arn, vector_bucket_arn,
};

/// How long a poll waits for a stack to reach a terminal status. The create's clock-owed span
/// falls due one transition delay after the call that opened it; this bound is generous enough
/// that a loaded machine never reads a status that is merely not due yet.
const TERMINAL_WAIT: Duration = Duration::from_secs(20);

/// How often that poll asks, which is how a client watches a stack.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How many pages of a listing this suite drains. These stacks declare a handful of
/// resources, so every listing is one page; the bound only stops a token the service failed to
/// retire from looping forever.
const MAX_PAGES: usize = 16;

/// The statuses a `CreateStack` can settle at, as `StackStatus` spells them.
const TERMINAL_STATUSES: &[&str] = &[
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
];

/// The logical ids every stack here gives its three buckets, and the output keys its `Ref`s
/// are published under — the same names, so one map compares against the other.
const PLAIN: &str = "Plain";
const VECTORS: &str = "Vectors";
const TABLES: &str = "Tables";

/// The namespace and the table this suite creates UNDER the published handle: both inside the
/// form their members publish (`NamespaceName` and `TableName`, pattern `^[0-9a-z_]*$`).
const NAMESPACE: &str = "analytics";
const TABLE: &str = "events";

/// The one open table format `CreateTable.format` admits (`OpenTableFormat`, whose only value
/// is `ICEBERG`).
const TABLE_FORMAT: &str = "ICEBERG";

/// The name a bucket ARN carries: the segment after its `bucket/`, which is how both ARN-keyed
/// services spell the resource part of one.
fn name_in(arn: &str) -> String {
    arn.rsplit_once("bucket/")
        .map(|(_, name)| name.to_string())
        .unwrap_or_default()
}

/// One stack of the table: the Region it deploys in, and the name it declares for each of the
/// three buckets — `None` for a bucket the template does not name, whose name CloudFormation
/// generates.
struct Stack {
    case: &'static str,
    region: &'static str,
    plain: Option<&'static str>,
    vectors: Option<&'static str>,
    tables: Option<&'static str>,
}

/// One declared resource: its type, and the name property where the stack names it. A stack
/// that names it nowhere declares no properties at all, which is how a template leaves the
/// name to CloudFormation.
fn declared(resource_type: &str, property: &str, name: Option<&str>) -> Value {
    match name {
        Some(name) => json!({ "Type": resource_type, "Properties": { property: name } }),
        None => json!({ "Type": resource_type }),
    }
}

impl Stack {
    /// The template this stack deploys: the three bucket variants, and one output per resource
    /// carrying `Ref` of its logical id — the way a client reads a handle out of a stack
    /// without reading its resource rows.
    fn template(&self) -> String {
        json!({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "the three S3 bucket variants, each read with Ref",
            "Resources": {
                PLAIN: declared("AWS::S3::Bucket", "BucketName", self.plain),
                VECTORS: declared(
                    "AWS::S3Vectors::VectorBucket",
                    "VectorBucketName",
                    self.vectors
                ),
                TABLES: declared(
                    "AWS::S3Tables::TableBucket",
                    "TableBucketName",
                    self.tables
                )
            },
            "Outputs": {
                PLAIN: { "Value": { "Ref": PLAIN } },
                VECTORS: { "Value": { "Ref": VECTORS } },
                TABLES: { "Value": { "Ref": TABLES } }
            }
        })
        .to_string()
    }
}

const STACKS: &[Stack] = &[
    Stack {
        // The recorded shape: three named bucket variants in one stack, each output a `Ref`.
        case: "three named bucket variants in one stack",
        region: "us-west-2",
        plain: Some("sim2real-handles-plain"),
        vectors: Some("sim2real-handles-v"),
        tables: Some("sim2real-handles-t"),
    },
    Stack {
        // The same rule where CloudFormation decides every name, in another Region.
        case: "three bucket variants the template does not name",
        region: "eu-central-1",
        plain: None,
        vectors: None,
        tables: None,
    },
];

/// What the answer of one S3 Tables operation keyed by the published handle must carry.
enum Expect {
    /// The read reports the bucket the handle names: its `arn` IS the handle, and its `name`
    /// the bucket's own name.
    Bucket,
    /// The answer echoes the handle back in its own `tableBucketARN` member, and reports the
    /// namespace it was given.
    NamespaceUnderIt,
    /// The answer reports the namespace, which is what the read was for.
    Namespace,
    /// The namespace is among the ones listed for the handle.
    NamespaceListed,
    /// The created table's own ARN NESTS inside the handle (`<handle>/table/<identifier>`,
    /// whose last segment is the identifier S3 Tables minted for the table).
    TableUnderIt,
    /// The table is among the ones listed for the handle, under an ARN nested in it.
    TableListed,
    /// The bucket is among the table buckets the service lists, under the handle as its `arn`.
    BucketListed,
}

/// One Amazon S3 Tables operation driven with the handle a stack published: the method and URI
/// its own `@http` binding declares, with `{handle}` standing for the handle as one
/// percent-encoded `@httpLabel` segment, and the request body where the operation takes one.
///
/// Source for each binding: `smithy_query(query="operation", operation="…")` on that service's
/// model — `GetTableBucket` `GET /buckets/{tableBucketARN}`, `CreateNamespace`
/// `PUT /namespaces/{tableBucketARN}`, `GetNamespace` `GET /namespaces/{tableBucketARN}/{namespace}`,
/// `ListNamespaces` `GET /namespaces/{tableBucketARN}`, `CreateTable`
/// `PUT /tables/{tableBucketARN}/{namespace}`, `ListTables` `GET /tables/{tableBucketARN}` and
/// `ListTableBuckets` `GET /buckets`.
struct Keyed {
    operation: &'static str,
    method: &'static str,
    uri: &'static str,
    body: Option<Value>,
    expect: Expect,
}

/// The operations above, in the order a client runs them: a namespace exists before a table is
/// created in it, so the creates come before the reads that must find them.
fn keyed_operations() -> Vec<Keyed> {
    vec![
        Keyed {
            operation: "GetTableBucket",
            method: "GET",
            uri: "/buckets/{handle}",
            body: None,
            expect: Expect::Bucket,
        },
        Keyed {
            operation: "CreateNamespace",
            method: "PUT",
            uri: "/namespaces/{handle}",
            body: Some(json!({ "namespace": [NAMESPACE] })),
            expect: Expect::NamespaceUnderIt,
        },
        Keyed {
            operation: "GetNamespace",
            method: "GET",
            uri: "/namespaces/{handle}/analytics",
            body: None,
            expect: Expect::Namespace,
        },
        Keyed {
            operation: "ListNamespaces",
            method: "GET",
            uri: "/namespaces/{handle}",
            body: None,
            expect: Expect::NamespaceListed,
        },
        Keyed {
            operation: "CreateTable",
            method: "PUT",
            uri: "/tables/{handle}/analytics",
            body: Some(json!({ "name": TABLE, "format": TABLE_FORMAT })),
            expect: Expect::TableUnderIt,
        },
        Keyed {
            operation: "ListTables",
            method: "GET",
            uri: "/tables/{handle}",
            body: None,
            expect: Expect::TableListed,
        },
        Keyed {
            operation: "ListTableBuckets",
            method: "GET",
            uri: "/buckets",
            body: None,
            expect: Expect::BucketListed,
        },
    ]
}

/// The text of one member of a JSON answer, or `None` where the answer carries no such member.
fn text(answer: &Value, member: &str) -> Option<String> {
    answer.get(member).and_then(Value::as_str).map(str::to_string)
}

/// Every string in one member of a JSON answer that is a LIST of strings — a `namespace`,
/// which S3 Tables models as a `NamespaceList`.
fn strings(answer: &Value, member: &str) -> Vec<String> {
    answer
        .get(member)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Every entry of one member of a JSON answer that is a list of STRUCTURES (the `namespaces`,
/// `tables` and `tableBuckets` a listing reports).
fn entries(answer: &Value, member: &str) -> Vec<Value> {
    answer
        .get(member)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Poll `DescribeStacks` until the stack SETTLES, and answer the terminal status it settled at
/// beside the answer it was read from — which is how a client waits for a stack.
async fn settled_stack(
    router: &MultiServiceRouter,
    case: &str,
    region: &str,
    stack_name: &str,
) -> (String, String) {
    let deadline = Instant::now() + TERMINAL_WAIT;
    loop {
        let (status, described) =
            cloudformation(router, region, "DescribeStacks", &[("StackName", stack_name)]).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from DescribeStacks on {stack_name:?}, got \
             {status} with body {described}"
        );
        let reached = opt_element(&described, "StackStatus").unwrap_or_default();
        if TERMINAL_STATUSES.contains(&reached.as_str()) {
            return (reached, described);
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected {stack_name:?} to settle at a terminal status within \
             {TERMINAL_WAIT:?}, it is still {reached:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The stack's resource rows as a client reads them: `ListStackResources` drained through its
/// `NextToken`, so a row is never missed because it fell on a later page.
async fn resource_rows(
    router: &MultiServiceRouter,
    case: &str,
    region: &str,
    stack_name: &str,
) -> BTreeMap<String, String> {
    let mut rows = BTreeMap::new();
    let mut next_token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let token = next_token.take();
        let mut members: Vec<(&str, &str)> = vec![("StackName", stack_name)];
        if let Some(token) = token.as_deref() {
            members.push(("NextToken", token));
        }
        let (status, listed) = cloudformation(router, region, "ListStackResources", &members).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from ListStackResources, got {status} with body \
             {listed}"
        );
        rows.extend(physical_ids_of(&listed));
        next_token = opt_element(&listed, "NextToken");
        if next_token.is_none() {
            return rows;
        }
    }
    panic!(
        "case {case:?}: ListStackResources did not retire its NextToken within {MAX_PAGES} pages"
    );
}

/// The row one logical id reports, or a panic quoting the rows that were read.
fn row<'a>(case: &str, rows: &'a BTreeMap<String, String>, logical_id: &str) -> &'a String {
    rows.get(logical_id).unwrap_or_else(|| {
        panic!(
            "case {case:?}: expected a physical id for {logical_id:?}, got the rows {:?}",
            rows
        )
    })
}

/// Every stack of the table: the handle each bucket variant publishes is the identifier its
/// owning service accepts, the resource rows and the `Ref` outputs carry the same value, and
/// every Amazon S3 Tables operation keyed by the table bucket's handle takes it.
#[tokio::test]
async fn each_bucket_variants_published_handle_is_what_its_owning_service_accepts() {
    let router = build_router();

    for (index, stack) in STACKS.iter().enumerate() {
        let case = stack.case;
        let region = stack.region;
        let stack_name = format!("bucket-handles-{index}");

        let (status, body) = cloudformation(
            &router,
            region,
            "CreateStack",
            &[
                ("StackName", &stack_name),
                ("TemplateBody", &stack.template()),
            ],
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from CreateStack, got {status} with body {body}"
        );

        let (reached, described) = settled_stack(&router, case, region, &stack_name).await;
        assert_eq!(
            reached, "CREATE_COMPLETE",
            "case {case:?}: expected the stack to reach CREATE_COMPLETE, got {reached:?} in \
             {described}"
        );

        let rows = resource_rows(&router, case, region, &stack_name).await;
        let outputs = outputs_of(&described);
        for logical_id in [PLAIN, VECTORS, TABLES] {
            let reported = row(case, &rows, logical_id);
            assert_eq!(
                outputs.get(logical_id),
                Some(reported),
                "case {case:?}: expected the Ref output {logical_id:?} to carry the row's own \
                 physical id {reported:?}, got {:?}",
                outputs.get(logical_id)
            );
        }

        // The plain bucket is published under its bare NAME — never an ARN — and Amazon S3
        // resolves it by that name.
        let plain = row(case, &rows, PLAIN);
        if let Some(declared) = stack.plain {
            assert_eq!(
                plain, declared,
                "case {case:?}: expected the S3 bucket's handle to be the declared name \
                 {declared:?}, got {plain:?}"
            );
        }
        assert!(
            !plain.starts_with("arn:"),
            "case {case:?}: expected the S3 bucket's handle to be a bare bucket name, got \
             {plain:?}"
        );
        let (status, located) = get_bucket_location(&router, region, plain).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetBucketLocation on the handle the stack \
             published, got {status} with body {located}"
        );

        // The vector bucket is published under its own ARN, and Amazon S3 Vectors resolves it
        // by that ARN.
        let vectors = row(case, &rows, VECTORS);
        let vectors_name = stack.vectors.map_or_else(|| name_in(vectors), str::to_string);
        assert_eq!(
            vectors,
            &vector_bucket_arn(region, &vectors_name),
            "case {case:?}: expected the vector bucket's handle to be the ARN \
             {:?}, got {vectors:?}",
            vector_bucket_arn(region, &vectors_name)
        );
        let (status, vector_bucket) = s3vectors(
            &router,
            region,
            "GetVectorBucket",
            &json!({ "vectorBucketArn": vectors }),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetVectorBucket on the handle the stack \
             published, got {status} with body {vector_bucket}"
        );

        // The table bucket is published under its own ARN too, and that ARN is a name S3
        // Tables could have created the bucket under at all.
        let tables = row(case, &rows, TABLES).clone();
        let tables_name = stack.tables.map_or_else(|| name_in(&tables), str::to_string);
        let handle = table_bucket_arn(region, &tables_name);
        assert_eq!(
            tables, handle,
            "case {case:?}: expected the table bucket's handle to be the ARN {handle:?}, got \
             {tables:?}"
        );
        assert!(
            tables.ends_with(&format!(":bucket/{tables_name}")),
            "case {case:?}: expected a handle ending in :bucket/{tables_name}, got {tables:?}"
        );
        assert!(
            is_s3tables_name(&tables_name),
            "case {case:?}: expected a bucket name inside the published name form, got \
             {tables_name:?}"
        );

        // ...and every operation that service keys by that handle takes it.
        for keyed in keyed_operations() {
            let operation = keyed.operation;
            let case = format!("{case}, {operation} on the published handle");
            let uri = keyed.uri.replace("{handle}", &label(&handle));
            let (status, answered) =
                s3tables(&router, region, keyed.method, &uri, keyed.body.as_ref()).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected HTTP 200 from {operation} on the handle the stack \
                 published, got {status} with body {answered}"
            );
            match keyed.expect {
                Expect::Bucket => {
                    assert_eq!(
                        text(&answered, "arn").as_deref(),
                        Some(handle.as_str()),
                        "case {case:?}: expected the read to report the handle {handle:?}, got \
                         {answered}"
                    );
                    assert_eq!(
                        text(&answered, "name").as_deref(),
                        Some(tables_name.as_str()),
                        "case {case:?}: expected the read to report the bucket name \
                         {tables_name:?}, got {answered}"
                    );
                }
                Expect::NamespaceUnderIt => {
                    assert_eq!(
                        text(&answered, "tableBucketARN").as_deref(),
                        Some(handle.as_str()),
                        "case {case:?}: expected the answer to carry the handle {handle:?}, got \
                         {answered}"
                    );
                    assert_eq!(
                        strings(&answered, "namespace"),
                        vec![NAMESPACE.to_string()],
                        "case {case:?}: expected the namespace {NAMESPACE:?}, got {answered}"
                    );
                }
                Expect::Namespace => {
                    assert_eq!(
                        strings(&answered, "namespace"),
                        vec![NAMESPACE.to_string()],
                        "case {case:?}: expected the namespace {NAMESPACE:?}, got {answered}"
                    );
                }
                Expect::NamespaceListed => {
                    let listed: Vec<Vec<String>> = entries(&answered, "namespaces")
                        .iter()
                        .map(|entry| strings(entry, "namespace"))
                        .collect();
                    assert!(
                        listed.contains(&vec![NAMESPACE.to_string()]),
                        "case {case:?}: expected {NAMESPACE:?} among the namespaces of the \
                         handle, got {listed:?}"
                    );
                }
                Expect::TableUnderIt => {
                    let table_arn = text(&answered, "tableARN").unwrap_or_default();
                    let nested = format!("{handle}/table/");
                    assert!(
                        table_arn
                            .strip_prefix(&nested)
                            .is_some_and(|identifier| !identifier.is_empty()),
                        "case {case:?}: expected the table's ARN to nest inside the handle \
                         ({nested}<table identifier>), got {table_arn:?}"
                    );
                }
                Expect::TableListed => {
                    let nested = format!("{handle}/table/");
                    let listed: Vec<(String, String)> = entries(&answered, "tables")
                        .iter()
                        .map(|entry| {
                            (
                                text(entry, "name").unwrap_or_default(),
                                text(entry, "tableARN").unwrap_or_default(),
                            )
                        })
                        .collect();
                    assert!(
                        listed.iter().any(|(name, table_arn)| {
                            name == TABLE && table_arn.starts_with(&nested)
                        }),
                        "case {case:?}: expected the table {TABLE:?} under the handle among the \
                         listed tables, got {listed:?}"
                    );
                }
                Expect::BucketListed => {
                    let listed: Vec<(String, String)> = entries(&answered, "tableBuckets")
                        .iter()
                        .map(|entry| {
                            (
                                text(entry, "name").unwrap_or_default(),
                                text(entry, "arn").unwrap_or_default(),
                            )
                        })
                        .collect();
                    assert!(
                        listed.contains(&(tables_name.clone(), handle.clone())),
                        "case {case:?}: expected the bucket {tables_name:?} under the handle \
                         {handle:?} among the listed table buckets, got {listed:?}"
                    );
                }
            }
        }
    }
}
