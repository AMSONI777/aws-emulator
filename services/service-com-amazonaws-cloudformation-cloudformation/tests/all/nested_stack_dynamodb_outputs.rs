// SPDX-License-Identifier: CC0-1.0

//! What a stack publishes for a resource its owning service reports READY AS THE CREATE
//! ANSWERS, end to end over the awsQuery wire.
//!
//! RULE: the `Fn::GetAtt` return values of a resource are the values the service that owns it
//! publishes for it ONCE IT IS UP — for an `AWS::CloudFormation::Stack` those are the child
//! stack's own `Outputs`, addressed as `Outputs.<OutputKey>` — and they are read when that
//! service reports the resource up, whether that is at the instant the create answered or
//! when the wait the create opened releases. So whether the resource happened to be up
//! already when its create was accepted is not what decides which of its values a template
//! can read: a parent's declared output over a child's output carries the value the child
//! published either way.
//!
//! `nested_stack_output_values.rs` holds the same reading for a child whose own resources come
//! up while the parent is still waiting for it. What this suite adds is the other side of that
//! fork — a child CloudFormation can report settled by the time the parent's resource asks —
//! which is what a child carrying a resource of a type whose create takes longer produces, and
//! which no other suite reaches.
//!
//! The rows differ along what the rule generalises over: the resource TYPE the child declares
//! (an `AWS::DynamoDB::Table` and an `AWS::S3::Bucket`, whose creates settle differently) and
//! how the PARENT's own template reached CloudFormation (inline, and staged in Amazon S3 as a
//! `TemplateURL`). Every expected value is the one the CHILD's own `DescribeStacks` reports
//! for that output, read back through the wire, so no row restates the naming or ARN form of
//! any resource type.

use serde_json::json;

use crate::change_set_lifecycle::settle_the_store;
use crate::harness::{call, create_stack, member, router_with_engine};
use crate::nested_stacks::{staged_url, STACK_RESOURCE_TYPE};
use crate::stack_lifecycle::describe_stack;
use crate::stack_outputs::{output_for, wire_outputs, WireOutput};
use crate::template_by_reference::{create_staging_bucket, stage};
use smithy_server_runtime::MultiServiceRouter;

/// The logical id the parent declares its nested stack under.
const CHILD: &str = "Child";

/// The two outputs every child template publishes: the resource's own identifier, and one
/// attribute of it. Declared under the SAME keys for every row, so the parent's template is
/// the same whichever type the child carries.
const CHILD_OUTPUTS: &[&str] = &["ThingName", "ThingArn"];

/// A child template declaring one `AWS::DynamoDB::Table` and publishing [`CHILD_OUTPUTS`] off
/// it.
fn dynamodb_child() -> String {
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Thing": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}]
                }
            }
        },
        "Outputs": {
            "ThingName": {"Value": {"Ref": "Thing"}},
            "ThingArn": {"Value": {"Fn::GetAtt": ["Thing", "Arn"]}}
        }
    })
    .to_string()
}

/// A child template declaring one `AWS::S3::Bucket` and publishing the same pair.
fn bucket_child(bucket: &str) -> String {
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Thing": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}}
        },
        "Outputs": {
            "ThingName": {"Value": {"Ref": "Thing"}},
            "ThingArn": {"Value": {"Fn::GetAtt": ["Thing", "Arn"]}}
        }
    })
    .to_string()
}

/// The parent's template: the nested stack, its stack id, and one declared output per entry of
/// [`CHILD_OUTPUTS`] reading the child's own.
fn parent_template(child_key: &str) -> String {
    let mut outputs = serde_json::Map::new();
    outputs.insert(
        "ChildStackId".to_string(),
        json!({"Value": {"Ref": CHILD}}),
    );
    for key in CHILD_OUTPUTS {
        outputs.insert(
            (*key).to_string(),
            json!({"Value": {"Fn::GetAtt": [CHILD, format!("Outputs.{key}")]}}),
        );
    }
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            CHILD: {
                "Type": STACK_RESOURCE_TYPE,
                "Properties": {"TemplateURL": staged_url(child_key)}
            }
        },
        "Outputs": outputs
    })
    .to_string()
}

/// How the parent's own template reached CloudFormation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Submitted {
    /// As the request's own `TemplateBody`.
    Inline,
    /// As a `TemplateURL` naming an object staged in Amazon S3.
    ByReference,
}

/// One row: a child template, and how its parent was submitted.
struct Row {
    case: &'static str,
    /// The key the child's template is staged under; the parent's is derived from it.
    child_key: &'static str,
    child: String,
    stack: &'static str,
    submitted: Submitted,
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "a child declaring a DynamoDB table, the parent submitted inline",
            child_key: "ready-at-create-ddb-inline.json",
            child: dynamodb_child(),
            stack: "ready-ddb-inline",
            submitted: Submitted::Inline,
        },
        Row {
            case: "a child declaring a DynamoDB table, the parent staged in Amazon S3",
            child_key: "ready-at-create-ddb-staged.json",
            child: dynamodb_child(),
            stack: "ready-ddb-staged",
            submitted: Submitted::ByReference,
        },
        Row {
            case: "a child declaring an Amazon S3 bucket, the parent submitted inline",
            child_key: "ready-at-create-bucket-inline.json",
            child: bucket_child("ready-at-create-bucket-inline-data"),
            stack: "ready-bucket-inline",
            submitted: Submitted::Inline,
        },
        Row {
            case: "a child declaring an Amazon S3 bucket, the parent staged in Amazon S3",
            child_key: "ready-at-create-bucket-staged.json",
            child: bucket_child("ready-at-create-bucket-staged-data"),
            stack: "ready-bucket-staged",
            submitted: Submitted::ByReference,
        },
    ]
}

/// The `Outputs` a settled stack reports, read through `DescribeStacks`.
async fn settled_outputs(
    case: &str,
    router: &MultiServiceRouter,
    stack: &str,
) -> Vec<WireOutput> {
    let (code, body) = describe_stack(router, stack).await;
    assert_eq!(
        code, 200,
        "case {case:?}: DescribeStacks({stack}) must answer, got {code} {body}"
    );
    wire_outputs(&body)
}

/// RULE: a parent's output over one of its nested stack's outputs carries the value the CHILD
/// published for it — whichever type the child's own resources are, and however the parent's
/// template was submitted.
#[tokio::test]
async fn a_parents_outputs_carry_the_childs_published_values() {
    let (router, engine) = router_with_engine();
    create_staging_bucket(&router).await;
    for row in rows() {
        stage(&router, row.child_key, &row.child).await;
        let parent = parent_template(row.child_key);
        let (code, body) = match row.submitted {
            Submitted::Inline => create_stack(&router, row.stack, &parent, &[]).await,
            Submitted::ByReference => {
                let parent_key = format!("{}-parent.json", row.child_key);
                stage(&router, &parent_key, &parent).await;
                call(
                    &router,
                    "CreateStack",
                    &[
                        member("StackName", row.stack),
                        member("TemplateURL", &staged_url(&parent_key)),
                    ],
                )
                .await
            }
        };
        assert_eq!(
            code, 200,
            "case {:?}: the parent must be created, got {code} {body}",
            row.case
        );
        // Each level of nesting is one span of the clock, and the parent's own output over the
        // child is only resolved by the pass that runs once the child has settled.
        for _ in 0..8 {
            settle_the_store(&router, &engine).await;
        }

        let parent_outputs = settled_outputs(row.case, &router, row.stack).await;
        let child_id = output_for(&parent_outputs, "ChildStackId")
            .and_then(|output| output.value.clone())
            .unwrap_or_else(|| {
                panic!(
                    "case {:?}: expected the parent to report the child's stack id, got \
                     {parent_outputs:?}",
                    row.case
                )
            });
        let child_outputs = settled_outputs(row.case, &router, &child_id).await;
        for key in CHILD_OUTPUTS {
            let published = output_for(&child_outputs, key)
                .and_then(|output| output.value.clone())
                .unwrap_or_else(|| {
                    panic!(
                        "case {:?}: the child must publish a value for {key:?}, got \
                         {child_outputs:?}",
                        row.case
                    )
                });
            assert!(
                !published.is_empty(),
                "case {:?}: the child's own output {key:?} must carry a value, got \
                 {published:?}",
                row.case
            );
            let reported = output_for(&parent_outputs, key).unwrap_or_else(|| {
                panic!(
                    "case {:?}: expected the parent to report an output {key:?}, got \
                     {parent_outputs:?}",
                    row.case
                )
            });
            assert_eq!(
                reported.value.as_deref(),
                Some(published.as_str()),
                "case {:?}: expected the parent's OutputValue for {key:?} to be the child's, \
                 got {:?}",
                row.case,
                reported.value
            );
        }
    }
}
