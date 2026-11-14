// SPDX-License-Identifier: CC0-1.0

//! Where a `CreateChangeSet` template comes FROM, and what the hierarchy below it is planned
//! as — end to end over the awsQuery wire.
//!
//! RULE 1: the ceiling a submitted template is held to belongs to the SOURCE that carried it.
//! The documented 51,200-byte maximum is a constraint on the request's own `TemplateBody`
//! member, so only a body the request carried inline is held to it — and refused with the
//! constraint report that quotes the member's leading characters and the length it holds in
//! all. A body resolved from a `TemplateURL` was never that member: "the URL must point to a
//! template (max size: 1 MB)", so it is held to the 1,000,000 bytes a template may weigh and
//! refused for the TEMPLATE being larger than CloudFormation reads.
//!
//! RULE 2: a reference is refused for what is wrong with it. Text carrying no `https` location
//! is refused for the scheme the documentation fixes; an `https` URL naming no Amazon S3
//! location is an unsupported url; an Amazon S3 endpoint carrying no object references none;
//! and a read Amazon S3 refused is reported as Amazon S3 answered it, with only a key the
//! bucket does not hold reported as the object's absence — a read that addressed one VERSION
//! of an object is answered by the permission to read versions, so it is reported as that
//! refusal rather than as a missing version.
//!
//! RULE 3: with `IncludeNestedStacks`, the change set is created "for the entire stack
//! hierarchy": a change on a child stack that exists carries
//! `ResourceChange$ChangeSetId` — "the change set ID of the nested change set" — which names a
//! change set this service really holds, reporting the child's own plan, its parent change set
//! and the root of the hierarchy. Deleting the root discards the hierarchy with it.
//!
//! The rows differ along what each rule generalises over: the SIZE of the body and the SOURCE
//! that carried it, which way a reference fails to address a readable object, and whether the
//! request asks for the hierarchy at all.

use serde_json::json;

use crate::change_set_lifecycle::{create_change_set, describe_change_set, settle_the_store};
use crate::harness::{
    call, create_stack, member, refusal, router_with_engine, xml_blocks, xml_text, xml_texts,
    REGION,
};
use crate::nested_stacks::{staged_url, STACK_RESOURCE_TYPE};
use crate::template_by_reference::{create_staging_bucket, stage, STAGING_BUCKET};
use service_com_amazonaws_cloudformation_cloudformation::state::{
    change_action, change_set_status, status, QUOTED_TEMPLATE_PREFIX, TEMPLATE_BODY_MAX_BYTES,
    TEMPLATE_MAX_BYTES,
};
use smithy_server_runtime::MultiServiceRouter;

/// A JSON template of exactly `bytes` characters declaring one resource, padded in
/// `Metadata` — a section whose content the template format bounds by nothing, unlike
/// `Description`, which a template may carry only 1024 bytes of.
fn template_of_size(bytes: usize) -> String {
    const SKELETON: &str = concat!(
        r#"{"Metadata":{"Pad":"PAD"},"#,
        r#""Resources":{"Topic":{"Type":"AWS::SNS::Topic","Properties":{}}}}"#
    );
    let padding = bytes - (SKELETON.len() - "PAD".len());
    SKELETON.replace("PAD", &"d".repeat(padding))
}

/// The constraint report an INLINE body past its documented maximum is refused with, written
/// out from the rule rather than taken from the handler: the fixed sentence, the member's own
/// value quoted — its leading [`QUOTED_TEMPLATE_PREFIX`] characters followed by the marker
/// naming how many it holds in all — and the ceiling it failed.
fn inline_too_long(body: &str) -> String {
    let quoted: String = body.chars().take(QUOTED_TEMPLATE_PREFIX).collect();
    let characters = body.chars().count();
    format!(
        "1 validation error detected: Value '{quoted}...<{characters} chars total>' at \
         'templateBody' failed to satisfy constraint: Member must have length less than or \
         equal to {TEMPLATE_BODY_MAX_BYTES}"
    )
}

/// Where the template of one row came from.
#[derive(Clone, Copy, Debug)]
enum Source {
    /// The request's own `TemplateBody` member.
    Inline,
    /// A `TemplateURL` naming the staged object that holds it.
    Reference,
}

/// One row of the size table: a body of one size, carried by one source.
struct Sized {
    case: &'static str,
    bytes: usize,
    source: Source,
    /// `None` where the change set must be created; the `ValidationError` message otherwise.
    refused_with: Option<String>,
}

fn sized_rows() -> Vec<Sized> {
    vec![
        Sized {
            case: "an inline body at the documented inline maximum",
            bytes: TEMPLATE_BODY_MAX_BYTES,
            source: Source::Inline,
            refused_with: None,
        },
        Sized {
            case: "an inline body one byte past it",
            bytes: TEMPLATE_BODY_MAX_BYTES + 1,
            source: Source::Inline,
            refused_with: Some(inline_too_long(&template_of_size(
                TEMPLATE_BODY_MAX_BYTES + 1,
            ))),
        },
        Sized {
            case: "an inline body far past it",
            bytes: TEMPLATE_BODY_MAX_BYTES * 2,
            source: Source::Inline,
            refused_with: Some(inline_too_long(&template_of_size(
                TEMPLATE_BODY_MAX_BYTES * 2,
            ))),
        },
        Sized {
            case: "the same body one byte past the inline maximum, read from an object",
            bytes: TEMPLATE_BODY_MAX_BYTES + 1,
            source: Source::Reference,
            refused_with: None,
        },
        Sized {
            case: "a staged template well past the inline maximum",
            bytes: 250_000,
            source: Source::Reference,
            refused_with: None,
        },
        Sized {
            case: "a staged template at the size a template may weigh",
            bytes: TEMPLATE_MAX_BYTES,
            source: Source::Reference,
            refused_with: None,
        },
        Sized {
            case: "a staged template one byte past that size",
            bytes: TEMPLATE_MAX_BYTES + 1,
            source: Source::Reference,
            refused_with: Some(format!(
                "Template may not exceed {TEMPLATE_MAX_BYTES} bytes in size."
            )),
        },
    ]
}

#[tokio::test]
async fn the_ceiling_a_template_is_held_to_is_the_one_its_source_carries() {
    let (router, engine) = router_with_engine();
    create_staging_bucket(&router).await;

    for (index, row) in sized_rows().into_iter().enumerate() {
        let case = row.case;
        let body_text = template_of_size(row.bytes);
        assert_eq!(
            body_text.len(),
            row.bytes,
            "case {case:?}: the row's body must be exactly {} bytes, got {}",
            row.bytes,
            body_text.len()
        );
        let stack = format!("sized-source-{index}");
        let change_set = format!("sized-source-{index}-set");
        let source_member = match row.source {
            Source::Inline => member("TemplateBody", &body_text),
            Source::Reference => {
                let key = format!("sized/{index}.template.json");
                stage(&router, &key, &body_text).await;
                member("TemplateURL", &staged_url(&key))
            }
        };
        let (code, body) = create_change_set(
            &router,
            &stack,
            &change_set,
            &[member("ChangeSetType", "CREATE"), source_member],
        )
        .await;

        let Some(expected) = row.refused_with else {
            assert_eq!(
                code, 200,
                "case {case:?}: a {}-byte body from {:?} must be accepted, got {code} {body}",
                row.bytes, row.source
            );
            // ...and the plan really is over the template that was carried: the change set
            // completes with the one resource the body declares.
            settle_the_store(&router, &engine).await;
            let (code, body) = describe_change_set(&router, &change_set, Some(&stack)).await;
            assert_eq!(
                code, 200,
                "case {case:?}: the change set must be describable, got {code} {body}"
            );
            assert_eq!(
                xml_text(&body, "Status").as_deref(),
                Some(change_set_status::CREATE_COMPLETE),
                "case {case:?}: expected the change set to complete, got {body}"
            );
            assert_eq!(
                xml_texts(&body, "LogicalResourceId"),
                vec!["Topic".to_string()],
                "case {case:?}: expected the plan over the carried template's one resource, \
                 got {body}"
            );
            continue;
        };
        assert_eq!(
            code, 400,
            "case {case:?}: a {}-byte body from {:?} must be refused, got {code} {body}",
            row.bytes, row.source
        );
        let (reported_code, reported_message) = refusal(&body);
        assert_eq!(
            reported_code, "ValidationError",
            "case {case:?}: expected a ValidationError, got {body}"
        );
        assert_eq!(
            reported_message, expected,
            "case {case:?}: expected {expected:?}, got {reported_message:?}"
        );
    }
}

/// The `ValidationError` message CloudFormation answers for a read Amazon S3 refused without
/// establishing that the object is absent: what Amazon S3 said, then the line that error is
/// documented on.
fn s3_error(message: &str) -> String {
    format!(
        "S3 error: {message}\nFor more information check \
         http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html"
    )
}

#[tokio::test]
async fn a_template_url_is_refused_for_what_is_wrong_with_the_reference() {
    let (router, _engine) = router_with_engine();
    create_staging_bucket(&router).await;
    let key = "refusals/present.template.json";
    stage(
        &router,
        key,
        &json!({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}).to_string(),
    )
    .await;

    // The rows differ along WHICH way the reference fails to address a readable object.
    let rows: Vec<(&str, String, String)> = vec![
        (
            "text no URL reader will read at all",
            "not a url".to_string(),
            "The location for an Amazon S3 bucket must start with https://".to_string(),
        ),
        (
            "a scheme the documentation does not allow",
            format!("s3://{STAGING_BUCKET}/{key}"),
            "The location for an Amazon S3 bucket must start with https://".to_string(),
        ),
        (
            "an https host that is no Amazon S3 location",
            "https://templates.example.com/stack.json".to_string(),
            "TemplateURL must be a supported URL.".to_string(),
        ),
        (
            "an Amazon S3 endpoint carrying no object",
            format!("https://{STAGING_BUCKET}.s3.{REGION}.amazonaws.com/"),
            "TemplateURL must reference a valid S3 object to which you have access."
                .to_string(),
        ),
        (
            "a key the staging bucket does not hold",
            staged_url("refusals/absent.template.json"),
            format!(
                "S3 object does not exist. Bucket: {STAGING_BUCKET}, Key: \
                 refusals/absent.template.json. Error: NoSuchKey"
            ),
        ),
        (
            "a version of an object the bucket holds no such version of",
            format!("{}?versionId=3HL4kqtJlcpXroDTDmJ1rmSpXd3dIbrH", staged_url(key)),
            s3_error("Access Denied"),
        ),
        (
            "a bucket nothing created",
            format!("https://absent-staging-bucket.s3.{REGION}.amazonaws.com/{key}"),
            s3_error("The specified bucket does not exist"),
        ),
    ];

    for (index, (case, url, expected)) in rows.into_iter().enumerate() {
        let stack = format!("refused-reference-{index}");
        let (code, body) = create_change_set(
            &router,
            &stack,
            &format!("refused-reference-{index}-set"),
            &[
                member("ChangeSetType", "CREATE"),
                member("TemplateURL", &url),
            ],
        )
        .await;
        assert_eq!(
            code, 400,
            "case {case:?}: expected the reference refused, got {code} {body}"
        );
        let (reported_code, reported_message) = refusal(&body);
        assert_eq!(
            reported_code, "ValidationError",
            "case {case:?}: expected a ValidationError, got {body}"
        );
        assert_eq!(
            reported_message, expected,
            "case {case:?}: expected {expected:?}, got {reported_message:?}"
        );
        // A refused reference writes nothing: no stack was brought into review.
        let (code, body) = call(&router, "DescribeStacks", &[member("StackName", &stack)]).await;
        assert_eq!(
            code, 400,
            "case {case:?}: expected no stack to exist, got {code} {body}"
        );
    }
}

#[tokio::test]
async fn a_change_set_states_exactly_one_template_source() {
    let (router, _engine) = router_with_engine();
    let stack = "one-source";
    let (code, body) = create_stack(
        &router,
        stack,
        &json!({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}).to_string(),
        &[],
    )
    .await;
    assert_eq!(code, 200, "the stack must be created first, got {code} {body}");

    let url = staged_url("never-read.json");
    let body_text = json!({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}).to_string();
    // The rows differ along WHICH way the request fails to state one source: none at all,
    // two submitted ones, and the stack's own template beside a submitted one (by value and
    // by reference, since either is a submitted template).
    /// One row: the case, the template members the request states, and the sentence it is
    /// refused with.
    type SourceRow = (&'static str, Vec<(String, String)>, &'static str);
    let rows: Vec<SourceRow> = vec![
        (
            "no source at all",
            Vec::new(),
            "Either Template URL or Template Body must be specified.",
        ),
        (
            "both a body and a reference",
            vec![
                member("TemplateBody", &body_text),
                member("TemplateURL", &url),
            ],
            "You cannot specify both Template URL and Template Body.",
        ),
        (
            "the stack's own template beside a submitted body",
            vec![
                member("UsePreviousTemplate", "true"),
                member("TemplateBody", &body_text),
            ],
            "You cannot specify both usePreviousTemplate and Template Body/Template URL.",
        ),
        (
            "the stack's own template beside a submitted reference",
            vec![
                member("UsePreviousTemplate", "true"),
                member("TemplateURL", &url),
            ],
            "You cannot specify both usePreviousTemplate and Template Body/Template URL.",
        ),
    ];
    for (index, (case, members, expected)) in rows.into_iter().enumerate() {
        let (code, body) =
            create_change_set(&router, stack, &format!("sources-{index}"), &members).await;
        assert_eq!(
            code, 400,
            "case {case:?}: expected the request refused, got {code} {body}"
        );
        let (reported_code, reported_message) = refusal(&body);
        assert_eq!(
            reported_code, "ValidationError",
            "case {case:?}: expected a ValidationError, got {body}"
        );
        assert_eq!(
            reported_message, expected,
            "case {case:?}: expected {expected:?}, got {reported_message:?}"
        );
    }
}

/// A child template declaring one bucket under the name it is given.
fn child_template(bucket: &str) -> String {
    json!({
        "Resources": {
            "Data": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}}
        }
    })
    .to_string()
}

/// A parent template whose one nested stack addresses `key`.
fn parent_template(key: &str) -> String {
    json!({
        "Resources": {
            "Child": {
                "Type": STACK_RESOURCE_TYPE,
                "Properties": {"TemplateURL": staged_url(key)}
            }
        }
    })
    .to_string()
}

/// The `ResourceChange` block one change set reports for `logical_id`.
fn resource_change(xml: &str, logical_id: &str) -> String {
    xml_blocks(xml, "ResourceChange")
        .into_iter()
        .find(|change| xml_text(change, "LogicalResourceId").as_deref() == Some(logical_id))
        .unwrap_or_default()
}

/// Settle the store until `stack` reports a status that is not in flight, or the deadline
/// passes: a nested hierarchy settles one level per transition, so the test waits for the
/// CONDITION rather than for a span of the clock.
async fn settled_stack(
    case: &str,
    router: &MultiServiceRouter,
    engine: &::std::sync::Arc<engine::InMemoryEngine>,
    stack: &str,
) -> String {
    for _ in 0..64 {
        settle_the_store(router, engine).await;
        let (code, body) = call(router, "DescribeStacks", &[member("StackName", stack)]).await;
        assert_eq!(
            code, 200,
            "case {case:?}: DescribeStacks({stack}) must answer, got {code} {body}"
        );
        let reported = xml_text(&body, "StackStatus").unwrap_or_default();
        if !reported.ends_with("_IN_PROGRESS") {
            return reported;
        }
    }
    panic!("case {case:?}: the stack {stack} never settled");
}

#[tokio::test]
async fn a_change_set_for_a_hierarchy_gives_each_child_stacks_change_a_change_set_of_its_own() {
    let (router, engine) = router_with_engine();
    create_staging_bucket(&router).await;
    let deployed_key = "hierarchy/child-deployed.json";
    let revised_key = "hierarchy/child-revised.json";
    stage(&router, deployed_key, &child_template("hierarchy-deployed")).await;
    stage(&router, revised_key, &child_template("hierarchy-revised")).await;

    let stack = "hierarchy-parent";
    let (code, body) = create_stack(&router, stack, &parent_template(deployed_key), &[]).await;
    assert_eq!(
        code, 200,
        "the parent stack must be created first, got {code} {body}"
    );
    let settled = settled_stack("the deployed hierarchy", &router, &engine, stack).await;
    assert_eq!(
        settled,
        status::CREATE_COMPLETE,
        "the parent and its child must deploy, got {settled}"
    );

    // The rows differ along whether the request asks for the hierarchy: the same revision,
    // planned for the stack alone and planned for the whole hierarchy.
    let rows: &[(&str, &str, bool)] = &[
        ("the stack alone", "hierarchy-alone", false),
        ("the whole hierarchy", "hierarchy-included", true),
    ];
    for (case, change_set, included) in rows {
        let mut members = vec![member("TemplateBody", &parent_template(revised_key))];
        if *included {
            members.push(member("IncludeNestedStacks", "true"));
        }
        let (code, body) = create_change_set(&router, stack, change_set, &members).await;
        assert_eq!(
            code, 200,
            "case {case:?}: CreateChangeSet must create the change set, got {code} {body}"
        );
        let parent_change_set_id = xml_text(&body, "Id").unwrap_or_default();
        settle_the_store(&router, &engine).await;
        let (code, body) = describe_change_set(&router, change_set, Some(stack)).await;
        assert_eq!(
            code, 200,
            "case {case:?}: DescribeChangeSet must answer, got {code} {body}"
        );
        assert_eq!(
            xml_text(&body, "Status").as_deref(),
            Some(change_set_status::CREATE_COMPLETE),
            "case {case:?}: the change set must complete, got {body}"
        );
        // The parent's own plan is the same either way: the child's declaration changed, so
        // the nested stack is modified.
        let child_change = resource_change(&body, "Child");
        assert_eq!(
            xml_text(&child_change, "Action").as_deref(),
            Some(change_action::MODIFY),
            "case {case:?}: expected the child stack modified, got {body}"
        );
        assert_eq!(
            xml_text(&child_change, "ResourceType").as_deref(),
            Some(STACK_RESOURCE_TYPE),
            "case {case:?}: expected the change on the nested-stack resource, got {body}"
        );
        let child_stack_id = xml_text(&child_change, "PhysicalResourceId").unwrap_or_default();
        let nested_id = xml_text(&child_change, "ChangeSetId");
        if !*included {
            assert_eq!(
                nested_id, None,
                "case {case:?}: a change set for the stack alone plans no nested change set, \
                 got {nested_id:?}"
            );
            continue;
        }
        let nested_id = nested_id.unwrap_or_default();
        assert!(
            !nested_id.is_empty(),
            "case {case:?}: expected the child's change to name a nested change set, got \
             {body}"
        );

        // The id names a change set this service really holds: it reports the CHILD's stack,
        // the child's own plan, and the hierarchy it belongs to.
        let (code, nested) = describe_change_set(&router, &nested_id, None).await;
        assert_eq!(
            code, 200,
            "case {case:?}: the nested change set must be describable by its id, got {code} \
             {nested}"
        );
        assert_eq!(
            xml_text(&nested, "StackId").as_deref(),
            Some(child_stack_id.as_str()),
            "case {case:?}: expected the nested change set on the child stack, got {nested}"
        );
        assert_eq!(
            xml_text(&nested, "ParentChangeSetId").as_deref(),
            Some(parent_change_set_id.as_str()),
            "case {case:?}: expected the parent change set named, got {nested}"
        );
        assert_eq!(
            xml_text(&nested, "RootChangeSetId").as_deref(),
            Some(parent_change_set_id.as_str()),
            "case {case:?}: expected the root of the hierarchy named, got {nested}"
        );
        assert_eq!(
            xml_text(&nested, "Status").as_deref(),
            Some(change_set_status::CREATE_COMPLETE),
            "case {case:?}: the nested change set must complete, got {nested}"
        );
        // The child's plan is over the child's own template: the revised body renames the
        // bucket its one resource declares, which is a modification of that resource.
        let data_change = resource_change(&nested, "Data");
        assert_eq!(
            xml_text(&data_change, "Action").as_deref(),
            Some(change_action::MODIFY),
            "case {case:?}: expected the child's own resource modified, got {nested}"
        );
        assert_eq!(
            xml_text(&data_change, "ResourceType").as_deref(),
            Some("AWS::S3::Bucket"),
            "case {case:?}: expected the child's own resource type, got {nested}"
        );

        // "DeleteChangeSet will delete all change sets that belong to the stacks hierarchy":
        // discarding the root discards the nested change set with it.
        let (code, deleted) = call(
            &router,
            "DeleteChangeSet",
            &[
                member("ChangeSetName", change_set),
                member("StackName", stack),
            ],
        )
        .await;
        assert_eq!(
            code, 200,
            "case {case:?}: DeleteChangeSet must succeed, got {code} {deleted}"
        );
        let (code, gone) = describe_change_set(&router, &nested_id, None).await;
        assert_eq!(
            code, 404,
            "case {case:?}: the nested change set must go with its root, got {code} {gone}"
        );
    }
}
