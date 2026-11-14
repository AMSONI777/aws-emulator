// SPDX-License-Identifier: CC0-1.0

//! What a bucket's OWN TAGS decide about a call addressed to it, while attribute-based
//! access control is enabled on the bucket.
//!
//! The rule under test: while a general purpose bucket's ABAC status is `Enabled` — "if ABAC
//! is enabled on your bucket, you can use tags on the bucket for access control"
//! (`GetBucketAbac`'s own documentation) — the request context of every call addressed to
//! that bucket, or to an object it holds, answers `aws:ResourceTag/<key>` from that bucket's
//! tag set, and the family is answered in full, so a clause over a tag key the bucket does
//! not carry is decided as absent. A statement conditioned on one of those keys is therefore
//! decided by the pair (the bucket's tag, the request's value), and a value written as a
//! policy VARIABLE — IAM's `${<condition key>}` grammar, "a placeholder for the value of the
//! condition key", the `${aws:PrincipalTag/<key>}` form an ABAC design is written in — is
//! substituted from that same context before it is compared. A bucket NOT under ABAC answers
//! the family not at all, so such a grant reaches nothing there: an `Allow` whose condition
//! cannot be decided grants nothing.
//!
//! Every assertion drives real HTTP requests through a router holding S3 beside IAM and STS
//! over ONE shared engine: the role, its inline policy and the tagged session are made with
//! those services' own operations (`CreateRole` + `PutRolePolicy` + `AssumeRole` with
//! `Tags`), the bucket's tags with `PutBucketTagging` and its ABAC status with
//! `PutBucketAbac`, read back through `GetBucketAbac`. Nothing reaches into a store to plant
//! a tag, a policy or a decision.
//!
//! The tables span what the rule generalises over rather than one recorded call:
//!
//! * the PAIR — the bucket's tag and the request's value equal, different, the bucket
//!   carrying no tag under the condition's key, the session carrying none, both carrying the
//!   value under ANOTHER key, and the pair sitting among several other tags;
//! * the condition VALUE — the policy variable naming the principal's tag, and a literal
//!   value, which is decided by the bucket's tag alone;
//! * the bucket's ABAC STATUS — `Enabled`, `Disabled`, and a bucket no put has touched;
//! * the OPERATION — the object read, its HEAD, the bucket listing, the object write and the
//!   object delete, each judged under its own IAM action and over the resource it addresses.

use std::sync::Arc;

use serde_json::json;
use smithy_server_runtime::MultiServiceRouter;

use super::bucket_lifecycle::Answer;
// The encoder and the policy/ARN/refusal spellings the role-session suites of this test
// binary already state: reused rather than copied again, so two suites cannot word the same
// thing differently.
use super::identity_authorization::form_encode;
use super::role_session_object_authorization::{
    denial_message, identity_document, object_arn, xml_element,
};

/// The Region every request in this suite is signed for.
const REGION: &str = "us-east-1";

/// The access-key id standing for the account's own published credential: neither STS nor IAM
/// holds a record of it, so it resolves to the account's ambient identity. It writes every
/// fixture here.
const ACCOUNT_KEY: &str = "AKIDEMULATOR";

/// The bytes every object in this suite holds. A tag decides who may reach an object, not
/// what is in it, so one payload serves every row.
const BODY: &[u8] = b"abac-tag-authorized-subject";

/// The bytes a WRITE row stores, told apart from the fixture's so a served write is seen to
/// have replaced them.
const WRITTEN_BODY: &[u8] = b"abac-tag-authorized-write";

/// The code S3 answers an authorization refusal with, and the status it carries (Amazon S3
/// "Error responses": `AccessDenied`, HTTP 403).
const ACCESS_DENIED: &str = "AccessDenied";

/// The IAM action a read of the current version of an object is authorized under ("to use
/// `GetObject`, you must have the `READ` access to the object", `GetObject`'s own
/// documentation of its general purpose bucket permissions), which a HEAD of the same object
/// asks for too.
const GET_OBJECT: &str = "s3:GetObject";

/// The IAM action an object write is authorized under ("you must have the `s3:PutObject`
/// permission", `PutObject`).
const PUT_OBJECT: &str = "s3:PutObject";

/// The IAM action a delete that names no version is authorized under ("`s3:DeleteObject` — to
/// delete an object (or add a delete marker)", `DeleteObject`).
const DELETE_OBJECT: &str = "s3:DeleteObject";

/// The IAM action a listing of a bucket's objects is authorized under ("you must have READ
/// access to the bucket" — `s3:ListBucket`, `ListObjectsV2`'s own documentation).
const LIST_BUCKET: &str = "s3:ListBucket";

/// The tag KEY the attribute-based grants in this suite are written over.
const TEAM_TAG: &str = "Team";

/// The tag key no condition here reads, for the rows that carry the admitted value under a
/// DIFFERENT key.
const OTHER_TAG: &str = "Squad";

/// The two tag values the rows pair and mis-pair.
const FINANCE: &str = "Finance";
const MARKETING: &str = "Marketing";

/// The two values `BucketAbacStatus` publishes
/// (`smithy_query(query="shape",shape="BucketAbacStatus")`).
const ABAC_ENABLED: &str = "Enabled";
const ABAC_DISABLED: &str = "Disabled";

/// The condition value that names the CALLING principal's own tag — IAM's policy-variable
/// grammar, which is what makes one document decide differently for two sessions.
fn principal_tag_variable(key: &str) -> String {
    format!("${{aws:PrincipalTag/{key}}}")
}

/// The condition key naming the tag `key` of the resource the request addressed.
fn resource_tag_key(key: &str) -> String {
    format!("aws:ResourceTag/{key}")
}

/// An emulator holding S3 beside the two services a decision about a session's call reads
/// from: IAM (the role and its identity policies) and STS (the session a role is assumed
/// into, with the tags its mint attached).
struct Emulator {
    router: MultiServiceRouter,
}

/// One role session a row calls as.
struct Session {
    /// The session's access key id, which is where this emulator reads WHO is calling.
    access_key_id: String,
    /// The assumed-role session ARN `sts:GetCallerIdentity` reports, which a refusal names.
    session_arn: String,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        // The suite signs nothing: the `Authorization` header carries only the credential
        // scope, which is where a service reads the Region and the caller's access key id.
        router.set_request_authentication(false);
        router.register_service(service_com_amazonaws_s3_amazons3::EmulatedService::new(
            Arc::clone(&engine),
        ));
        router.register_service(
            service_com_amazonaws_iam_awsidentitymanagementv20100508::EmulatedService::new(
                Arc::clone(&engine),
            ),
        );
        router.register_service(
            service_com_amazonaws_sts_awssecuritytokenservicev20110615::EmulatedService::new(
                engine,
            ),
        );
        Self { router }
    }

    /// One S3 request signed with `access_key_id` in its SigV4 credential scope.
    async fn s3(&self, access_key_id: &str, method: &str, uri: &str, body: &[u8]) -> Answer {
        let host = format!("s3.{REGION}.amazonaws.com");
        let request = http::Request::builder()
            .method(method)
            .uri(format!("https://{host}{uri}"))
            .header("host", host.clone())
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={access_key_id}/20260101/{REGION}/s3/\
                     aws4_request, SignedHeaders=host, Signature=0000"
                ),
            )
            .body(bytes::Bytes::copy_from_slice(body))
            .expect("the test request must build");
        let response = self.router.dispatch(request).await;
        let (parts, body) = response.into_parts();
        Answer {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        }
    }

    /// One awsQuery call to IAM or STS, as the account's own credential.
    async fn query(
        &self,
        signing_name: &str,
        version: &str,
        action: &str,
        params: &[(String, String)],
    ) -> (u16, String) {
        let mut body = format!("Action={action}&Version={version}");
        for (name, value) in params {
            body.push('&');
            body.push_str(name);
            body.push('=');
            body.push_str(&form_encode(value));
        }
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{signing_name}.amazonaws.com/"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={ACCOUNT_KEY}/20260101/{REGION}/\
                     {signing_name}/aws4_request, SignedHeaders=host, Signature=0000"
                ),
            )
            .body(bytes::Bytes::from(body))
            .expect("a well-formed awsQuery request");
        let response = self.router.dispatch(request).await;
        (
            response.status().as_u16(),
            String::from_utf8_lossy(response.body()).to_string(),
        )
    }

    /// Create an IAM role trusted by this account's root and carrying `policy` as its inline
    /// policy, and answer its ARN.
    async fn create_role(&self, case: &str, role_name: &str, policy: &str) -> String {
        let account = engine::emulator_account_id();
        let role_arn = format!("arn:aws:iam::{account}:role/{role_name}");
        let trust = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": format!("arn:aws:iam::{account}:root")},
                // `sts:TagSession` beside the assume: "to pass session tags, the principal
                // must have the `sts:TagSession` permission" (`AssumeRole$Tags`), so a role
                // whose sessions carry tags admits both actions.
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }],
        })
        .to_string();
        let (status, body) = self
            .query(
                "iam",
                "2010-05-08",
                "CreateRole",
                &[
                    ("RoleName".to_string(), role_name.to_string()),
                    ("AssumeRolePolicyDocument".to_string(), trust),
                ],
            )
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: creating the role {role_name:?} must succeed, got {status} {body}"
        );
        let (status, body) = self
            .query(
                "iam",
                "2010-05-08",
                "PutRolePolicy",
                &[
                    ("RoleName".to_string(), role_name.to_string()),
                    ("PolicyName".to_string(), "inline".to_string()),
                    ("PolicyDocument".to_string(), policy.to_string()),
                ],
            )
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: putting the inline policy of {role_name:?} must succeed, got \
             {status} {body}"
        );
        role_arn
    }

    /// Assume `role_arn` through STS's own `AssumeRole`, attaching the session tags `tags`.
    async fn assume(
        &self,
        case: &str,
        role_arn: &str,
        session_name: &str,
        tags: &[(&str, &str)],
    ) -> Session {
        let mut params = vec![
            ("RoleArn".to_string(), role_arn.to_string()),
            ("RoleSessionName".to_string(), session_name.to_string()),
        ];
        // The `Tags` member of `AssumeRole`, as awsQuery flattens a list of structures.
        for (index, (key, value)) in tags.iter().enumerate() {
            params.push((
                format!("Tags.member.{}.Key", index + 1),
                (*key).to_string(),
            ));
            params.push((
                format!("Tags.member.{}.Value", index + 1),
                (*value).to_string(),
            ));
        }
        let (status, body) = self.query("sts", "2011-06-15", "AssumeRole", &params).await;
        assert_eq!(
            status, 200,
            "case {case:?}: assuming {role_arn:?} must succeed, got {status} {body}"
        );
        Session {
            access_key_id: xml_element(&body, "AccessKeyId").unwrap_or_else(|| {
                panic!("case {case:?}: AssumeRole must answer an AccessKeyId, got {body}")
            }),
            session_arn: xml_element(&body, "Arn").unwrap_or_else(|| {
                panic!("case {case:?}: AssumeRole must answer the session Arn, got {body}")
            }),
        }
    }

    /// `PUT /<bucket>` as the account.
    async fn create_bucket(&self, case: &str, bucket: &str) {
        let created = self.s3(ACCOUNT_KEY, "PUT", &format!("/{bucket}"), b"").await;
        assert_eq!(
            created.status,
            200,
            "case {case:?}: the bucket {bucket:?} must be created first, got {} with {}",
            created.status,
            body_text(&created)
        );
    }

    /// `PUT /<bucket>?tagging` as the account — the tag set the ABAC decision is taken over.
    async fn tag_bucket(&self, case: &str, bucket: &str, tags: &[(&str, &str)]) {
        let tag_elements: String = tags
            .iter()
            .map(|(key, value)| format!("<Tag><Key>{key}</Key><Value>{value}</Value></Tag>"))
            .collect();
        let document = format!(
            "<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet>{tag_elements}\
             </TagSet></Tagging>"
        );
        let tagged = self
            .s3(
                ACCOUNT_KEY,
                "PUT",
                &format!("/{bucket}?tagging"),
                document.as_bytes(),
            )
            .await;
        assert_eq!(
            tagged.status,
            204,
            "case {case:?}: the tag set {tags:?} must be stored on {bucket:?}, got {} with {}",
            tagged.status,
            body_text(&tagged)
        );
    }

    /// `PUT /<bucket>?abac` as the account, read back through `GetBucketAbac` so the status a
    /// row is decided under is the one the bucket really carries.
    async fn set_abac(&self, case: &str, bucket: &str, status: &str) {
        let put = self
            .s3(
                ACCOUNT_KEY,
                "PUT",
                &format!("/{bucket}?abac"),
                format!(
                    "<AbacStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Status>{status}</Status></AbacStatus>"
                )
                .as_bytes(),
            )
            .await;
        assert_eq!(
            put.status,
            200,
            "case {case:?}: PutBucketAbac {status:?} on {bucket:?} must be accepted, got {} \
             with {}",
            put.status,
            body_text(&put)
        );
        self.assert_abac(case, bucket, status).await;
    }

    /// `GET /<bucket>?abac` as the account — what the bucket's ABAC status reads back as.
    async fn assert_abac(&self, case: &str, bucket: &str, expected: &str) {
        let read = self
            .s3(ACCOUNT_KEY, "GET", &format!("/{bucket}?abac"), b"")
            .await;
        let text = body_text(&read);
        assert_eq!(
            read.status, 200,
            "case {case:?}: GetBucketAbac on {bucket:?} must report the status, got {} with \
             {text}",
            read.status
        );
        assert_eq!(
            xml_element(&text, "Status").as_deref(),
            Some(expected),
            "case {case:?}: expected the ABAC status {expected:?} on {bucket:?}, got {text}"
        );
    }

    /// `PUT /<bucket>/<key>` as the account — the fixture every read, delete and overwrite
    /// row addresses. Written before any policy or tag is installed, so no row's document can
    /// decide another row's setup.
    async fn write_fixture(&self, case: &str, bucket: &str, key: &str) {
        let written = self
            .s3(ACCOUNT_KEY, "PUT", &format!("/{bucket}/{key}"), BODY)
            .await;
        assert_eq!(
            written.status,
            200,
            "case {case:?}: the fixture {key:?} must be stored first, got {} with {}",
            written.status,
            body_text(&written)
        );
    }

    /// `GET /<bucket>/<key>` as the ACCOUNT — what is at the key, whatever any row's session
    /// may reach.
    async fn fixture_bytes(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
        let read = self
            .s3(ACCOUNT_KEY, "GET", &format!("/{bucket}/{key}"), b"")
            .await;
        (read.status == 200).then(|| read.body.to_vec())
    }
}

/// An answer's body as text, with the XML entities S3 escapes a message's quotes as read
/// back, so an expected sentence can be compared as it was worded.
fn body_text(answer: &Answer) -> String {
    String::from_utf8_lossy(&answer.body)
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

/// The clause IAM publishes for a call no readable identity-based grant reaches at all —
/// which is what a grant whose condition does not hold leaves behind.
fn no_identity_grant(action: &str) -> String {
    format!("because no identity-based policy allows the {action} action")
}

/// Assert an S3 answer is the implicit-deny refusal, in S3's own `AccessDenied` envelope:
/// HTTP 403, the code, and IAM's sentence naming the principal, the action and the resource.
fn assert_refused(case: &str, answer: &Answer, principal: &str, action: &str, resource: &str) {
    let text = body_text(answer);
    assert_eq!(
        answer.status, 403,
        "case {case:?}: expected HTTP 403, got {} with {text}",
        answer.status
    );
    assert!(
        text.contains(ACCESS_DENIED),
        "case {case:?}: expected the {ACCESS_DENIED} code, got {text}"
    );
    let expected = denial_message(principal, action, resource, &no_identity_grant(action));
    assert!(
        text.contains(&expected),
        "case {case:?}: expected the message {expected:?}, got {text}"
    );
}

/// The ARN of a general purpose bucket — S3's own form, which carries neither a Region nor an
/// account.
fn bucket_arn(bucket: &str) -> String {
    format!("arn:aws:s3:::{bucket}")
}

/// An identity-based document whose ONLY statement allows `actions` over `bucket` and
/// everything in it, conditioned on the bucket's `Team` tag equalling `expected`.
///
/// `expected` is either a literal value or IAM's policy-variable spelling of the calling
/// principal's own tag, which is the difference the first table is written over.
fn conditioned_document(bucket: &str, actions: &[&str], expected: &str) -> String {
    identity_document(vec![json!({
        "Effect": "Allow",
        "Action": actions,
        "Resource": [bucket_arn(bucket), format!("{}/*", bucket_arn(bucket))],
        "Condition": {
            "StringEquals": { resource_tag_key(TEAM_TAG): expected },
        },
    })])
}

/// An identity-based document whose only statement allows `actions` over `bucket` and
/// everything in it with NO condition at all — the control a row uses to show a refusal is
/// the condition's doing and not the bucket's ABAC status breaking the call.
fn unconditioned_document(bucket: &str, actions: &[&str]) -> String {
    identity_document(vec![json!({
        "Effect": "Allow",
        "Action": actions,
        "Resource": [bucket_arn(bucket), format!("{}/*", bucket_arn(bucket))],
    })])
}

/// The key every object row of this suite addresses.
const KEY: &str = "tagged-object.txt";

// ---------------------------------------------------------------------------
// RULE: while ABAC is enabled on a bucket, a statement conditioned on
// `aws:ResourceTag/<key>` is decided by the bucket's own tag set — and a condition value
// written as a policy variable is substituted from the request's context first.
// ---------------------------------------------------------------------------

/// One row of the pair table: the tags the bucket carries, the tags the session carries, the
/// condition value the grant is written with, and whether the read is then served.
struct PairRow {
    label: &'static str,
    bucket_tags: &'static [(&'static str, &'static str)],
    session_tags: &'static [(&'static str, &'static str)],
    /// `None` is the policy-variable form naming the principal's own `Team` tag; `Some` a
    /// literal value the bucket's tag is compared against directly.
    literal: Option<&'static str>,
    allowed: bool,
}

#[tokio::test]
async fn a_grant_conditioned_on_the_buckets_tags_is_decided_by_them() {
    let emulator = Emulator::new();

    // The rows differ along what the rule generalises over: whether the bucket's tag and the
    // value the condition resolves to are equal, where each of them comes from (the bucket's
    // tag set, the session's tags, a literal in the document), which KEY carries them, and
    // how many other tags sit beside the pair.
    let rows = [
        PairRow {
            label: "the policy variable, and the two tags pair",
            bucket_tags: &[(TEAM_TAG, FINANCE)],
            session_tags: &[(TEAM_TAG, FINANCE)],
            literal: None,
            allowed: true,
        },
        PairRow {
            label: "the policy variable, and the session's tag is another value",
            bucket_tags: &[(TEAM_TAG, FINANCE)],
            session_tags: &[(TEAM_TAG, MARKETING)],
            literal: None,
            allowed: false,
        },
        PairRow {
            label: "the policy variable, and the bucket carries no tag under that key",
            bucket_tags: &[(OTHER_TAG, FINANCE)],
            session_tags: &[(TEAM_TAG, FINANCE)],
            literal: None,
            allowed: false,
        },
        PairRow {
            label: "the policy variable, and the session carries no tag at all",
            bucket_tags: &[(TEAM_TAG, FINANCE)],
            session_tags: &[],
            literal: None,
            allowed: false,
        },
        PairRow {
            label: "the policy variable, and both carry the value under another key",
            bucket_tags: &[(OTHER_TAG, FINANCE)],
            session_tags: &[(OTHER_TAG, FINANCE)],
            literal: None,
            allowed: false,
        },
        PairRow {
            label: "a literal value the bucket's tag equals",
            bucket_tags: &[(TEAM_TAG, FINANCE)],
            session_tags: &[],
            literal: Some(FINANCE),
            allowed: true,
        },
        PairRow {
            label: "a literal value the bucket's tag does not equal",
            bucket_tags: &[(TEAM_TAG, MARKETING)],
            session_tags: &[(TEAM_TAG, FINANCE)],
            literal: Some(FINANCE),
            allowed: false,
        },
        PairRow {
            label: "the policy variable, and the pair sits among several tags",
            bucket_tags: &[(OTHER_TAG, MARKETING), (TEAM_TAG, FINANCE)],
            session_tags: &[(OTHER_TAG, "logistics"), (TEAM_TAG, FINANCE)],
            literal: None,
            allowed: true,
        },
    ];

    for (index, row) in rows.iter().enumerate() {
        let label = row.label;
        let bucket = format!("abac-pair-bucket-{index}");
        emulator.create_bucket(label, &bucket).await;
        emulator.write_fixture(label, &bucket, KEY).await;
        emulator.tag_bucket(label, &bucket, row.bucket_tags).await;
        emulator.set_abac(label, &bucket, ABAC_ENABLED).await;

        let expected = row
            .literal
            .map_or_else(|| principal_tag_variable(TEAM_TAG), str::to_string);
        let policy = conditioned_document(&bucket, &[GET_OBJECT], &expected);
        let role_arn = emulator
            .create_role(label, &format!("abac-pair-role-{index}"), &policy)
            .await;
        let session = emulator
            .assume(
                label,
                &role_arn,
                &format!("abac-pair-session-{index}"),
                row.session_tags,
            )
            .await;

        let answer = emulator
            .s3(
                &session.access_key_id,
                "GET",
                &format!("/{bucket}/{KEY}"),
                b"",
            )
            .await;
        if row.allowed {
            assert_eq!(
                answer.status,
                200,
                "case {label:?}: the grant's condition holds, so the read must be served, got \
                 {} with {}",
                answer.status,
                body_text(&answer)
            );
            assert_eq!(
                answer.body.as_ref(),
                BODY,
                "case {label:?}: expected the stored bytes, got {}",
                body_text(&answer)
            );
        } else {
            assert_refused(
                label,
                &answer,
                &session.session_arn,
                GET_OBJECT,
                &object_arn(&bucket, KEY),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// RULE: the bucket's tags decide only while ABAC is ENABLED on it; a bucket outside ABAC
// answers the resource-tag family not at all, so a grant conditioned on it reaches nothing —
// while a grant that is not so conditioned is untouched by the status.
// ---------------------------------------------------------------------------

/// One row of the ABAC-status table: the status the bucket carries, and whether the grant
/// conditioned on its tags then reaches the read.
struct StatusRow {
    label: &'static str,
    /// Whether the bucket is put to `Enabled` FIRST, so the status under test is one it was
    /// moved back into rather than one it never left.
    enabled_first: bool,
    /// `None` is a bucket no `PutBucketAbac` has touched, which carries the status the
    /// property defaults to.
    put: Option<&'static str>,
    /// What `GetBucketAbac` must then report.
    reads_as: &'static str,
    allowed: bool,
}

#[tokio::test]
async fn the_buckets_tags_decide_only_while_abac_is_enabled() {
    let emulator = Emulator::new();

    // Every row's bucket carries the same tag and every row's session the same matching tag,
    // so the ABAC status is the only thing that differs between them.
    let rows = [
        StatusRow {
            label: "a bucket no PutBucketAbac has touched",
            enabled_first: false,
            put: None,
            reads_as: ABAC_DISABLED,
            allowed: false,
        },
        StatusRow {
            label: "a bucket whose ABAC was put to Disabled",
            enabled_first: false,
            put: Some(ABAC_DISABLED),
            reads_as: ABAC_DISABLED,
            allowed: false,
        },
        StatusRow {
            label: "a bucket whose ABAC was put to Enabled",
            enabled_first: false,
            put: Some(ABAC_ENABLED),
            reads_as: ABAC_ENABLED,
            allowed: true,
        },
        StatusRow {
            label: "a bucket put to Enabled and then back to Disabled",
            enabled_first: true,
            put: Some(ABAC_DISABLED),
            reads_as: ABAC_DISABLED,
            allowed: false,
        },
    ];

    for (index, row) in rows.iter().enumerate() {
        let label = row.label;
        let bucket = format!("abac-status-bucket-{index}");
        emulator.create_bucket(label, &bucket).await;
        emulator.write_fixture(label, &bucket, KEY).await;
        emulator
            .tag_bucket(label, &bucket, &[(TEAM_TAG, FINANCE)])
            .await;
        // A row that is put to Enabled first reaches its status by being moved back INTO it
        // rather than by never leaving it.
        if row.enabled_first {
            emulator.set_abac(label, &bucket, ABAC_ENABLED).await;
        }
        match row.put {
            Some(status) => emulator.set_abac(label, &bucket, status).await,
            None => emulator.assert_abac(label, &bucket, row.reads_as).await,
        }

        // The grant conditioned on the bucket's tag: served only where the bucket answers
        // the resource-tag family at all.
        let conditioned = conditioned_document(
            &bucket,
            &[GET_OBJECT],
            &principal_tag_variable(TEAM_TAG),
        );
        let conditioned_role = emulator
            .create_role(label, &format!("abac-status-role-{index}"), &conditioned)
            .await;
        let session = emulator
            .assume(
                label,
                &conditioned_role,
                &format!("abac-status-session-{index}"),
                &[(TEAM_TAG, FINANCE)],
            )
            .await;
        let answer = emulator
            .s3(
                &session.access_key_id,
                "GET",
                &format!("/{bucket}/{KEY}"),
                b"",
            )
            .await;
        if row.allowed {
            assert_eq!(
                answer.status,
                200,
                "case {label:?}: the bucket's tags are in force, so the read must be served, \
                 got {} with {}",
                answer.status,
                body_text(&answer)
            );
            assert_eq!(
                answer.body.as_ref(),
                BODY,
                "case {label:?}: expected the stored bytes, got {}",
                body_text(&answer)
            );
        } else {
            assert_refused(
                label,
                &answer,
                &session.session_arn,
                GET_OBJECT,
                &object_arn(&bucket, KEY),
            );
        }

        // The control: an UNCONDITIONED grant over the same bucket reaches the same read
        // whatever the ABAC status, so every refusal above is the condition's doing.
        let plain = unconditioned_document(&bucket, &[GET_OBJECT]);
        let plain_role = emulator
            .create_role(label, &format!("abac-status-plain-role-{index}"), &plain)
            .await;
        let plain_session = emulator
            .assume(
                label,
                &plain_role,
                &format!("abac-status-plain-session-{index}"),
                &[(TEAM_TAG, MARKETING)],
            )
            .await;
        let served = emulator
            .s3(
                &plain_session.access_key_id,
                "GET",
                &format!("/{bucket}/{KEY}"),
                b"",
            )
            .await;
        assert_eq!(
            served.status,
            200,
            "case {label:?}: an unconditioned grant must serve the read whatever the ABAC \
             status, got {} with {}",
            served.status,
            body_text(&served)
        );
    }
}

// ---------------------------------------------------------------------------
// RULE: the bucket's tags are answered for EVERY action authorized over the bucket or over
// an object it holds — not only the object read — each judged under its own IAM action and
// over the resource it addresses.
// ---------------------------------------------------------------------------

/// Which operation a row of the action table drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// `GetObject`, which answers the stored bytes.
    Get,
    /// `HeadObject`, which carries no body, so its status is the whole answer.
    Head,
    /// `ListObjectsV2`, which addresses the BUCKET rather than an object.
    List,
    /// `PutObject`, which must leave what was at the key alone when it is refused.
    Put,
    /// `DeleteObject`, which must leave the object readable when it is refused.
    Delete,
}

impl Call {
    /// The IAM action this call is authorized under.
    fn action(self) -> &'static str {
        match self {
            Self::Get | Self::Head => GET_OBJECT,
            Self::List => LIST_BUCKET,
            Self::Put => PUT_OBJECT,
            Self::Delete => DELETE_OBJECT,
        }
    }

    /// The HTTP method, request target and body this call is made with.
    fn request(self, bucket: &str) -> (&'static str, String, &'static [u8]) {
        match self {
            Self::Get => ("GET", format!("/{bucket}/{KEY}"), b""),
            Self::Head => ("HEAD", format!("/{bucket}/{KEY}"), b""),
            Self::List => ("GET", format!("/{bucket}?list-type=2"), b""),
            Self::Put => ("PUT", format!("/{bucket}/{KEY}"), WRITTEN_BODY),
            Self::Delete => ("DELETE", format!("/{bucket}/{KEY}"), b""),
        }
    }

    /// The ARN the decision about this call is taken over: the object it addresses, or the
    /// bucket itself for the listing.
    fn resource(self, bucket: &str) -> String {
        match self {
            Self::List => bucket_arn(bucket),
            _ => object_arn(bucket, KEY),
        }
    }

    /// The status a SERVED call answers with: "the request succeeded with no content" for the
    /// delete (HTTP 204), and 200 for the rest.
    fn served_status(self) -> u16 {
        match self {
            Self::Delete => 204,
            _ => 200,
        }
    }
}

#[tokio::test]
async fn the_buckets_tags_decide_every_action_authorized_over_it() {
    let emulator = Emulator::new();

    // One row per operation, each judged under its own IAM action and over its own resource.
    let calls = [Call::Get, Call::Head, Call::List, Call::Put, Call::Delete];

    for (index, call) in calls.iter().copied().enumerate() {
        let label = format!("{call:?}");
        let case = label.as_str();
        let bucket = format!("abac-action-bucket-{index}");
        emulator.create_bucket(case, &bucket).await;
        emulator.write_fixture(case, &bucket, KEY).await;
        emulator
            .tag_bucket(case, &bucket, &[(TEAM_TAG, FINANCE)])
            .await;
        emulator.set_abac(case, &bucket, ABAC_ENABLED).await;

        // ONE role, whose only grant is conditioned on the pair, and two sessions off it: the
        // mismatched one first, so the call it is refused is seen to have changed nothing
        // before the matching one is served.
        let policy = conditioned_document(
            &bucket,
            &[call.action()],
            &principal_tag_variable(TEAM_TAG),
        );
        let role_arn = emulator
            .create_role(case, &format!("abac-action-role-{index}"), &policy)
            .await;
        let (method, target, body) = call.request(&bucket);

        let mismatched = emulator
            .assume(
                case,
                &role_arn,
                &format!("abac-action-mismatched-{index}"),
                &[(TEAM_TAG, MARKETING)],
            )
            .await;
        let refused = emulator
            .s3(&mismatched.access_key_id, method, &target, body)
            .await;
        if call == Call::Head {
            // A HEAD carries no body, so its status is the whole of what tells a caller it
            // was refused.
            assert_eq!(
                refused.status,
                403,
                "case {case:?} with a mismatched session tag: expected HTTP 403, got {}",
                refused.status
            );
        } else {
            assert_refused(
                case,
                &refused,
                &mismatched.session_arn,
                call.action(),
                &call.resource(&bucket),
            );
        }
        // A refused call is a call that did not happen: whatever the fixture held is still
        // there, byte for byte.
        assert_eq!(
            emulator.fixture_bytes(&bucket, KEY).await.as_deref(),
            Some(BODY),
            "case {case:?}: a refused call must leave the stored object exactly as it was"
        );

        let matching = emulator
            .assume(
                case,
                &role_arn,
                &format!("abac-action-matching-{index}"),
                &[(TEAM_TAG, FINANCE)],
            )
            .await;
        let served = emulator
            .s3(&matching.access_key_id, method, &target, body)
            .await;
        assert_eq!(
            served.status,
            call.served_status(),
            "case {case:?} with the matching session tag: expected HTTP {}, got {} with {}",
            call.served_status(),
            served.status,
            body_text(&served)
        );
        // And the served call really did what it says: the read answers the stored bytes, the
        // write replaces them, the delete takes the object away.
        match call {
            Call::Get => assert_eq!(
                served.body.as_ref(),
                BODY,
                "case {case:?}: expected the stored bytes, got {}",
                body_text(&served)
            ),
            Call::Put => assert_eq!(
                emulator.fixture_bytes(&bucket, KEY).await.as_deref(),
                Some(WRITTEN_BODY),
                "case {case:?}: the served write must have replaced the stored bytes"
            ),
            Call::Delete => assert_eq!(
                emulator.fixture_bytes(&bucket, KEY).await,
                None,
                "case {case:?}: the served delete must have removed the object"
            ),
            Call::List => assert!(
                body_text(&served).contains(&format!("<Key>{KEY}</Key>")),
                "case {case:?}: the served listing must report the stored key, got {}",
                body_text(&served)
            ),
            Call::Head => assert!(
                served.body.is_empty(),
                "case {case:?}: a HEAD answers no body, got {}",
                body_text(&served)
            ),
        }
    }
}
