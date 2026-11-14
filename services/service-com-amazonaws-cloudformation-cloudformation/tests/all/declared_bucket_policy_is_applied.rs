// SPDX-License-Identifier: CC0-1.0

//! The POLICY a stack declares for a bucket it creates, read back through Amazon S3's own
//! wire once the stack has completed.
//!
//! **The rule.** A resource whose type is a SUB-RESOURCE of another service's resource is
//! created by the call that service publishes for it, with every intrinsic function in its
//! declaration resolved first — so once the stack reports `CREATE_COMPLETE`, the owning
//! service reports the declared configuration, and `GetBucketPolicy`'s `NoSuchBucketPolicy`
//! ("the bucket policy does not exist") is the answer only for a bucket no stack put a policy
//! on. An `AWS::S3::BucketPolicy` is such a resource: it is "the policy of the bucket it
//! names", written by `PutBucketPolicy` ("applies an Amazon S3 bucket policy to an Amazon S3
//! bucket") and read by `GetBucketPolicy`. The mirror of the rule is that a declaration the
//! owning service REFUSES fails the resource, so the stack rolls back rather than reporting a
//! success with the declared posture absent.
//!
//! The rows of the first table differ along what the rule generalises over: how the document
//! composes the bucket's ARN (`Fn::GetAtt`, `Fn::Join` around one, `Fn::Sub` reading one, and
//! a literal string that needs no resolution at all), how many statements it carries and with
//! which effects (one `Deny`, one `Allow`, both), whether the bucket's name came from a
//! template PARAMETER or a literal, whether the bucket blocks public policies (the declared
//! Block Public Access configuration, which does not hold back a document that grants nobody
//! anything), and whether the policy is declared BEFORE the bucket it depends on.
//!
//! `bucket_policy_update_and_rename_rollback.rs` pins what an UPDATE of such a policy does;
//! this suite pins the CREATE, which is where the declared posture either reaches the bucket
//! or silently does not.

use serde_json::{json, Value};

use crate::harness::{
    call_in, create_stack, member, router, settled_stack_status, stack_event_reasons, xml_text,
    xml_texts, REGION,
};
use crate::stack_resource_provisioning::s3;
use service_com_amazonaws_cloudformation_cloudformation::state::status;
use smithy_server_runtime::MultiServiceRouter;

/// The template parameter the rows that name their bucket indirectly take its name from.
const BUCKET_NAME_PARAMETER: &str = "BucketName";

/// The output every template publishes the bucket's own name under, so each row reads the
/// name it then calls Amazon S3 with back out of the stack.
const BUCKET_OUTPUT: &str = "SourceBucketName";

/// The bucket each row deploys, named once so a row's declaration and the document it
/// expects in force cannot drift apart.
const DENY_BUCKET: &str = "declared-bucket-policy-deny-source";
/// See [`DENY_BUCKET`].
const ALLOW_BUCKET: &str = "declared-bucket-policy-allow-source";
/// See [`DENY_BUCKET`].
const BOTH_BUCKET: &str = "declared-bucket-policy-both-source";
/// See [`DENY_BUCKET`].
const ORDERING_BUCKET: &str = "declared-bucket-policy-ordering-source";
/// See [`DENY_BUCKET`].
const REFUSED_BUCKET: &str = "declared-bucket-policy-refused-source";

/// The value the settled stack publishes under [`BUCKET_OUTPUT`] — the bucket name a client
/// goes on to call Amazon S3 with.
async fn published_bucket(case: &str, router: &MultiServiceRouter, stack: &str) -> String {
    let (code, body) =
        call_in(router, REGION, "DescribeStacks", &[member("StackName", stack)]).await;
    assert_eq!(
        code, 200,
        "case {case:?}: DescribeStacks must answer 200, got {code} {body}"
    );
    let keys = xml_texts(&body, "OutputKey");
    let values = xml_texts(&body, "OutputValue");
    keys.into_iter()
        .zip(values)
        .find(|(key, _)| key == BUCKET_OUTPUT)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("case {case:?}: no {BUCKET_OUTPUT} output in {body}"))
}

/// The bucket's declared properties: its name — a literal, or a reference to
/// [`BUCKET_NAME_PARAMETER`] — the versioning state every template here asks for, and, where
/// `block_public_access` says so, the four Block Public Access settings.
fn bucket_properties(bucket: &str, by_parameter: bool, block_public_access: bool) -> Value {
    let name: Value = if by_parameter {
        json!({ "Ref": BUCKET_NAME_PARAMETER })
    } else {
        json!(bucket)
    };
    let mut properties = json!({
        "BucketName": name,
        "VersioningConfiguration": { "Status": "Enabled" },
    });
    if block_public_access {
        let members = properties
            .as_object_mut()
            .expect("the bucket's properties are an object");
        members.insert(
            "PublicAccessBlockConfiguration".to_string(),
            json!({
                "BlockPublicAcls": true,
                "BlockPublicPolicy": true,
                "IgnorePublicAcls": true,
                "RestrictPublicBuckets": true,
            }),
        );
    }
    properties
}

/// The whole template a case deploys: the bucket under `bucket_logical_id`, the
/// `AWS::S3::BucketPolicy` that owns its policy under `policy_logical_id`, and the output
/// publishing the bucket's own name.
fn template(
    bucket: &str,
    bucket_logical_id: &str,
    policy_logical_id: &str,
    by_parameter: bool,
    block_public_access: bool,
    declared: &Value,
) -> String {
    let mut document = json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            bucket_logical_id: {
                "Type": "AWS::S3::Bucket",
                "Properties": bucket_properties(bucket, by_parameter, block_public_access),
            },
            policy_logical_id: {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": { "Ref": bucket_logical_id },
                    "PolicyDocument": declared.clone(),
                },
            },
        },
        "Outputs": {
            BUCKET_OUTPUT: { "Value": { "Ref": bucket_logical_id } },
        },
    });
    if by_parameter {
        document
            .as_object_mut()
            .expect("the template is an object")
            .insert(
                "Parameters".to_string(),
                json!({ BUCKET_NAME_PARAMETER: { "Type": "String" } }),
            );
    }
    document.to_string()
}

/// The ARN of a bucket, as Amazon S3 spells it and as `Fn::GetAtt … Arn` answers it for an
/// `AWS::S3::Bucket`.
fn bucket_arn(bucket: &str) -> String {
    format!("arn:aws:s3:::{bucket}")
}

/// The ARN of every object in a bucket — the second resource a bucket-wide statement names.
fn objects_arn(bucket: &str) -> String {
    format!("{}/*", bucket_arn(bucket))
}

/// A `Deny` of every S3 action over an insecure connection — the posture a template states
/// for a bucket that must only be reached over TLS, which grants nobody anything.
fn deny_insecure_transport(resource: Value) -> Value {
    json!({
        "Sid": "DenyInsecureTransport",
        "Effect": "Deny",
        "Principal": { "AWS": "*" },
        "Action": "s3:*",
        "Resource": resource,
        "Condition": { "Bool": { "aws:SecureTransport": "false" } },
    })
}

/// An `Allow` of one action to the account that owns the bucket — a grant whose principal this
/// emulator's IAM resolves, and which is not a public one.
fn allow_account(resource: Value, action: &str) -> Value {
    json!({
        "Sid": "AccountReadsObjects",
        "Effect": "Allow",
        "Principal": { "AWS": format!("arn:aws:iam::{}:root", engine::emulator_account_id()) },
        "Action": action,
        "Resource": resource,
    })
}

/// A policy document around `statements`.
fn policy(statements: Vec<Value>) -> Value {
    json!({ "Version": "2012-10-17", "Statement": statements })
}

/// One row of the applied-policy table.
struct Applied {
    case: &'static str,
    stack: &'static str,
    bucket: &'static str,
    /// The logical id the bucket is declared under, and the one its policy is. The pair of a
    /// row whose policy sorts BEFORE its bucket is what pins that the implicit dependency the
    /// `Ref` creates — not the declaration order — is what orders the two creates.
    bucket_logical_id: &'static str,
    /// See [`Applied::bucket_logical_id`].
    policy_logical_id: &'static str,
    /// Whether the bucket's name is declared as a reference to [`BUCKET_NAME_PARAMETER`]
    /// rather than as a literal.
    by_parameter: bool,
    /// Whether the bucket declares the four Block Public Access settings.
    block_public_access: bool,
    /// The `PolicyDocument` the template declares, intrinsics and all.
    declared: Value,
    /// The document that must be in force on the bucket once the stack has completed.
    expected: Value,
}

fn applied_rows() -> Vec<Applied> {
    vec![
        // The class the issue cited: the bucket's name comes from a parameter, the bucket
        // blocks public policies, and the one Deny statement reads the bucket's ARN with an
        // `Fn::GetAtt` and composes the objects' ARN with an `Fn::Join` around another.
        Applied {
            case: "a deny of insecure transport, ARNs read with Fn::GetAtt and Fn::Join",
            stack: "declared-bucket-policy-deny",
            bucket: DENY_BUCKET,
            bucket_logical_id: "FrontendSourceBucket",
            policy_logical_id: "FrontendSourceBucketPolicy",
            by_parameter: true,
            block_public_access: true,
            declared: policy(vec![deny_insecure_transport(json!([
                { "Fn::GetAtt": ["FrontendSourceBucket", "Arn"] },
                { "Fn::Join": ["", [{ "Fn::GetAtt": ["FrontendSourceBucket", "Arn"] }, "/*"]] },
            ]))]),
            expected: policy(vec![deny_insecure_transport(json!([
                bucket_arn(DENY_BUCKET),
                objects_arn(DENY_BUCKET),
            ]))]),
        },
        // A document with nothing to resolve at all, on a bucket declared by a literal name
        // and carrying no Block Public Access configuration: one Allow, one string Resource.
        Applied {
            case: "an allow to the account, with a literal resource and a literal bucket name",
            stack: "declared-bucket-policy-allow",
            bucket: ALLOW_BUCKET,
            bucket_logical_id: "Store",
            policy_logical_id: "StorePolicy",
            by_parameter: false,
            block_public_access: false,
            declared: policy(vec![allow_account(
                json!(objects_arn(ALLOW_BUCKET)),
                "s3:GetObject",
            )]),
            expected: policy(vec![allow_account(
                json!(objects_arn(ALLOW_BUCKET)),
                "s3:GetObject",
            )]),
        },
        // TWO statements, of both effects, with the objects' ARN composed by an `Fn::Sub`
        // reading the bucket's `Arn` attribute — the other spelling of the same read.
        Applied {
            case: "two statements, the objects' ARN composed with Fn::Sub",
            stack: "declared-bucket-policy-both",
            bucket: BOTH_BUCKET,
            bucket_logical_id: "Assets",
            policy_logical_id: "AssetsPolicy",
            by_parameter: false,
            block_public_access: true,
            declared: policy(vec![
                deny_insecure_transport(json!({ "Fn::Sub": "${Assets.Arn}/*" })),
                allow_account(
                    json!({ "Fn::GetAtt": ["Assets", "Arn"] }),
                    "s3:ListBucket",
                ),
            ]),
            expected: policy(vec![
                deny_insecure_transport(json!(objects_arn(BOTH_BUCKET))),
                allow_account(json!(bucket_arn(BOTH_BUCKET)), "s3:ListBucket"),
            ]),
        },
        // The policy declared BEFORE the bucket it names: the `Ref` is what orders the two
        // creates, so the policy still reaches a bucket that exists.
        Applied {
            case: "the policy declared before the bucket it names",
            stack: "declared-bucket-policy-ordering",
            bucket: ORDERING_BUCKET,
            bucket_logical_id: "ZSourceBucket",
            policy_logical_id: "ASourceBucketPolicy",
            by_parameter: true,
            block_public_access: false,
            declared: policy(vec![deny_insecure_transport(json!({
                "Fn::GetAtt": ["ZSourceBucket", "Arn"]
            }))]),
            expected: policy(vec![deny_insecure_transport(json!(bucket_arn(
                ORDERING_BUCKET
            )))]),
        },
    ]
}

/// THE RULE: see the module header — the declared policy is in force on the bucket the stack
/// created, resolved, once the stack reports `CREATE_COMPLETE`.
#[tokio::test]
async fn a_declared_bucket_policy_is_in_force_once_the_stack_completes() {
    for row in applied_rows() {
        let case = row.case;
        let router = router();
        let parameters = if row.by_parameter {
            vec![
                member("Parameters.member.1.ParameterKey", BUCKET_NAME_PARAMETER),
                member("Parameters.member.1.ParameterValue", row.bucket),
            ]
        } else {
            Vec::new()
        };
        let body = template(
            row.bucket,
            row.bucket_logical_id,
            row.policy_logical_id,
            row.by_parameter,
            row.block_public_access,
            &row.declared,
        );
        let (code, answered) = create_stack(&router, row.stack, &body, &parameters).await;
        assert_eq!(
            code, 200,
            "case {case:?}: the create must be accepted, got {code} {answered}"
        );
        let settled = settled_stack_status(case, &router, REGION, row.stack).await;
        assert_eq!(
            settled,
            status::CREATE_COMPLETE,
            "case {case:?}: expected the create to complete, got {settled:?}; the stack reports \
             {:?}",
            stack_event_reasons(&router, REGION, row.stack).await
        );

        // The name a client reads out of the stack is the bucket the stack created...
        let published = published_bucket(case, &router, row.stack).await;
        assert_eq!(
            published, row.bucket,
            "case {case:?}: expected the stack to publish {:?} as its bucket, got {published:?}",
            row.bucket
        );
        // ...the bucket's other declared properties took effect...
        let versioning = s3(&router, "GET", &format!("/{published}?versioning"), b"").await;
        assert_eq!(
            versioning.status, 200,
            "case {case:?}: GetBucketVersioning must be served, got {} {}",
            versioning.status, versioning.body
        );
        assert_eq!(
            xml_text(&versioning.body, "Status").as_deref(),
            Some("Enabled"),
            "case {case:?}: expected the declared versioning state in force, got {}",
            versioning.body
        );
        // ...and so did its POLICY: the declared document, with every intrinsic resolved.
        let answered = s3(&router, "GET", &format!("/{published}?policy"), b"").await;
        assert_eq!(
            answered.status, 200,
            "case {case:?}: the bucket must carry the declared policy, got {} {}",
            answered.status, answered.body
        );
        let in_force: Value = serde_json::from_str(&answered.body).unwrap_or_else(|error| {
            panic!(
                "case {case:?}: GetBucketPolicy must answer a JSON document, got {} ({error})",
                answered.body
            )
        });
        assert_eq!(
            in_force, row.expected,
            "case {case:?}: expected the declared document {} in force, got {}",
            row.expected, in_force
        );
        assert!(
            !answered.body.contains("Fn::"),
            "case {case:?}: no intrinsic function may survive into the stored document, got {}",
            answered.body
        );
    }
}

/// THE MIRROR OF THE RULE: a document the owning service refuses fails the resource, so the
/// stack rolls back instead of reporting a success with no policy on the bucket.
///
/// The refusal is the one Amazon S3 answers a document naming an identity its account cannot
/// resolve as a grantee (`MalformedPolicy`, `Invalid principal in policy`): the role the
/// statement grants to does not exist, so the grant would be a grant to nobody.
#[tokio::test]
async fn a_policy_the_owning_service_refuses_rolls_the_stack_back() {
    let case = "a grant to a role the account does not hold";
    let stack = "declared-bucket-policy-refused";
    let router = router();
    let declared = policy(vec![json!({
        "Sid": "GrantToNobody",
        "Effect": "Allow",
        "Principal": {
            "AWS": format!(
                "arn:aws:iam::{}:role/a-role-this-account-does-not-hold",
                engine::emulator_account_id()
            )
        },
        "Action": "s3:GetObject",
        "Resource": { "Fn::Join": ["", [{ "Fn::GetAtt": ["Store", "Arn"] }, "/*"]] },
    })]);
    let body = template(
        REFUSED_BUCKET,
        "Store",
        "StorePolicy",
        false,
        false,
        &declared,
    );

    let (code, answered) = create_stack(&router, stack, &body, &[]).await;
    assert_eq!(
        code, 200,
        "case {case:?}: the create must be accepted, got {code} {answered}"
    );
    let settled = settled_stack_status(case, &router, REGION, stack).await;
    let reasons = stack_event_reasons(&router, REGION, stack).await;
    assert_eq!(
        settled,
        status::ROLLBACK_COMPLETE,
        "case {case:?}: a refused policy must not complete the stack, got {settled:?}; the stack \
         reports {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("Invalid principal in policy")),
        "case {case:?}: expected the owning service's refusal in the stack's events, got \
         {reasons:?}"
    );
}
