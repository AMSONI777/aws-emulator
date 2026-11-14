// SPDX-License-Identifier: CC0-1.0

//! A CloudFormation-deployed delivery stream MOVES DATA: a `PutRecord` a client makes against
//! the stream a stack provisioned becomes an object in the Amazon S3 location that stack's
//! template declared.
//!
//! The rule under test: **a resource CloudFormation provisions is created through its owning
//! service's own API, so it is the SAME resource that API's own create makes — it carries no
//! reduced data plane.** For an `AWS::KinesisFirehose::DeliveryStream` whose properties are
//! `CreateDeliveryStream`'s own members, that means every rule the stream's destination
//! configuration states holds for the deployed stream exactly as it does for one a client
//! created directly: the records a put accepted are held until the destination's own
//! `BufferingHints` are met ("Buffer incoming data for the specified period of time, in
//! seconds, before delivering it to the destination" / "Buffer incoming data to the specified
//! size, in MiBs"), the flushed buffer is written under the declared `Prefix` with the
//! automatic `YYYY/MM/DD/HH` segments ("The \"YYYY/MM/DD/HH\" time format prefix is
//! automatically used for delivered Amazon S3 files"), and the write is made under the
//! declared `RoleARN` ("the Amazon Resource Name (ARN) of the Amazon Web Services
//! credentials"), so it happens only where the permissions in force on that role allow Amazon
//! S3's own write of the object.
//!
//! Only a cross-service suite can ask this: the flow spans CloudFormation (which deploys),
//! IAM (which holds the delivery role and decides the write), Firehose (which buffers and
//! delivers) and Amazon S3 (which holds the bucket and the delivered object), mounted on ONE
//! engine exactly as `core/router/src/lib.rs` mounts them. The sibling suite
//! `cloudformation_firehose_stream_stabilisation` pins that such a put is ACCEPTED once the
//! stack completes; this one pins what becomes of the record afterwards, which is the half a
//! client's pipeline actually consumes.
//!
//! The rows differ along what the rule generalises over: the template language (JSON, YAML
//! with its short-form intrinsics), the member the stream declares its Amazon S3 destination
//! under (`ExtendedS3DestinationConfiguration`, the deprecated `S3DestinationConfiguration`),
//! whether the template NAMES the stream or leaves the name to CloudFormation, whether the
//! destination declares a key `Prefix`, the `BufferingHints` it declares (the shortest wait
//! the hints admit, and the longest), and what the declared delivery role is allowed to write
//! (the destination's own bucket, or only another one). Nothing is asserted about how fast the
//! host ran: a destination that is due is polled until it holds its object, and a destination
//! that must hold nothing is re-read at every one of those readings.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

// The router, the request builder and the awsQuery caller the cross-service CloudFormation
// suites share, so this suite mounts the same services over the same wire as the metric-stream
// export pipeline beside it rather than building a second emulator of its own.
use crate::cloudformation_metric_stream_exports_to_s3::{cloudformation, emulator, send};
use crate::query_wire::{element, elements, outputs_of};

/// How long a stack is given to report itself settled, and how often it is asked. The spans
/// the services behind a stack choose take the time they take, so the bound is a generous
/// wall-clock deadline whose only job is that the wait TERMINATES.
const DEPLOY_DEADLINE: Duration = Duration::from_secs(90);

/// How long a delivery that IS due is waited for before a row fails: far longer than the
/// emulator's own delivery span, so a loaded machine does not fail a row the clock would have
/// served.
const DELIVERY_DEADLINE: Duration = Duration::from_secs(60);

/// How long the destinations that must hold NOTHING go on being re-read once every due
/// destination holds its object — spent re-reading them rather than sleeping once, so what the
/// assertion judges is the latest reading.
const SILENCE_WINDOW: Duration = Duration::from_secs(2);

/// How often a stack, or a destination, is read while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The `StackStatus` a deployment the template declares correctly settles in.
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";

/// The trust policy every row's delivery role carries: Firehose assumes the role a
/// destination names, so the service principal has to be able to.
const TRUST_POLICY: &str = concat!(
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"#,
    r#"{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#
);

/// What a row's delivery role is allowed to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// Amazon S3's own write of an object of the destination's OWN bucket, which is the
    /// permission a delivery to it needs.
    DestinationObjects,
    /// The same write, scoped to another bucket altogether — a least-privilege mistake, so
    /// the delivery to this row's destination is not a write this role may make.
    ObjectsElsewhere,
}

/// Which language a row's template is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Json,
    /// YAML with the short-form intrinsic tags (`!GetAtt`, `!Ref`).
    Yaml,
}

/// What the row's destination must hold once the records are put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// One object, carrying the record that was put.
    Delivered,
    /// Nothing at all: the destination's buffering window has not elapsed, or the declared
    /// role may not make the write.
    HoldsNothing,
}

/// One deployed stream: the template that declares it, and what its destination then holds.
struct Row {
    case: &'static str,
    /// The stack this row deploys, which every other name it uses is derived from.
    stack: &'static str,
    /// The `CreateDeliveryStream` member the template declares the Amazon S3 destination
    /// under.
    member: &'static str,
    /// `BufferingHints` as `(SizeInMBs, IntervalInSeconds)`.
    hints: (i64, i64),
    /// The `Prefix` the destination declares, or `None` where it declares none at all.
    prefix: Option<&'static str>,
    /// Whether the template declares `DeliveryStreamName`, or leaves the name to
    /// CloudFormation.
    named: bool,
    grant: Grant,
    language: Language,
    /// The record bytes the client puts on the deployed stream.
    record: &'static [u8],
    outcome: Outcome,
}

impl Row {
    /// The bucket the template declares, and the one its objects are read back from.
    fn bucket(&self) -> String {
        format!("{}-data", self.stack)
    }

    /// The role the template declares the delivery under.
    fn role(&self) -> String {
        format!("{}-role", self.stack)
    }

    /// The `DeliveryStreamName` the template declares, for a row that names its stream.
    fn declared_stream(&self) -> String {
        format!("{}-stream", self.stack)
    }

    /// The bucket ARN pattern this row's role is granted the object write on.
    fn granted_objects(&self) -> String {
        match self.grant {
            Grant::DestinationObjects => format!("arn:aws:s3:::{}/*", self.bucket()),
            Grant::ObjectsElsewhere => format!("arn:aws:s3:::{}-elsewhere/*", self.stack),
        }
    }

    /// The identity policy the template puts on that role: Amazon S3's own write of an
    /// object, on whichever objects this row grants it.
    fn role_policy(&self) -> String {
        format!(
            concat!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","#,
                r#""Action":"s3:PutObject","Resource":"{}"}}]}}"#
            ),
            self.granted_objects()
        )
    }

    /// The body of the row's template, in the language it is written in.
    fn template(&self) -> String {
        match self.language {
            Language::Json => self.json_template(),
            Language::Yaml => self.yaml_template(),
        }
    }

    /// The row's template as JSON: the delivery role, the destination bucket, and the stream
    /// delivering into it, with the stream's name published as an output.
    fn json_template(&self) -> String {
        let mut destination = json!({
            "BucketARN": { "Fn::GetAtt": ["Bucket", "Arn"] },
            "RoleARN": { "Fn::GetAtt": ["Role", "Arn"] },
            "CompressionFormat": "UNCOMPRESSED",
            "BufferingHints": {
                "SizeInMBs": self.hints.0,
                "IntervalInSeconds": self.hints.1,
            },
        });
        if let Some(prefix) = self.prefix {
            destination["Prefix"] = json!(prefix);
        }
        let mut stream = json!({ "DeliveryStreamType": "DirectPut" });
        stream[self.member] = destination;
        if self.named {
            stream["DeliveryStreamName"] = json!(self.declared_stream());
        }
        json!({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "a Firehose stream delivering a direct put to a declared bucket",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": self.role(),
                        "AssumeRolePolicyDocument": TRUST_POLICY,
                        "Policies": [{
                            "PolicyName": "delivery",
                            "PolicyDocument": self.role_policy(),
                        }],
                    },
                },
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": { "BucketName": self.bucket() },
                },
                "Stream": {
                    "Type": "AWS::KinesisFirehose::DeliveryStream",
                    "Properties": stream,
                },
            },
            "Outputs": {
                "StreamName": { "Value": { "Ref": "Stream" } },
            },
        })
        .to_string()
    }

    /// The same template written in YAML, with the short-form intrinsic tags a client writes
    /// it with.
    fn yaml_template(&self) -> String {
        let mut lines = vec![
            "AWSTemplateFormatVersion: '2010-09-09'".to_string(),
            "Resources:".to_string(),
            "  Role:".to_string(),
            "    Type: AWS::IAM::Role".to_string(),
            "    Properties:".to_string(),
            format!("      RoleName: {}", self.role()),
            format!("      AssumeRolePolicyDocument: '{TRUST_POLICY}'"),
            "      Policies:".to_string(),
            "        - PolicyName: delivery".to_string(),
            format!("          PolicyDocument: '{}'", self.role_policy()),
            "  Bucket:".to_string(),
            "    Type: AWS::S3::Bucket".to_string(),
            "    Properties:".to_string(),
            format!("      BucketName: {}", self.bucket()),
            "  Stream:".to_string(),
            "    Type: AWS::KinesisFirehose::DeliveryStream".to_string(),
            "    Properties:".to_string(),
            "      DeliveryStreamType: DirectPut".to_string(),
        ];
        if self.named {
            lines.push(format!(
                "      DeliveryStreamName: {}",
                self.declared_stream()
            ));
        }
        lines.push(format!("      {}:", self.member));
        lines.push("        BucketARN: !GetAtt Bucket.Arn".to_string());
        lines.push("        RoleARN: !GetAtt Role.Arn".to_string());
        lines.push("        CompressionFormat: UNCOMPRESSED".to_string());
        if let Some(prefix) = self.prefix {
            lines.push(format!("        Prefix: {prefix}"));
        }
        lines.push("        BufferingHints:".to_string());
        lines.push(format!("          SizeInMBs: {}", self.hints.0));
        lines.push(format!("          IntervalInSeconds: {}", self.hints.1));
        lines.push("Outputs:".to_string());
        lines.push("  StreamName:".to_string());
        lines.push("    Value: !Ref Stream".to_string());
        lines.push(String::new());
        lines.join("\n")
    }
}

/// The deployed streams under test.
///
/// Three rows must deliver and two must not, so neither answer can be had by a store that
/// never delivers anything or by one that writes everything it is given.
const ROWS: &[Row] = &[
    Row {
        case: "a named JSON stream with an extended S3 destination under a declared prefix",
        stack: "cfn-firehose-put-json",
        member: "ExtendedS3DestinationConfiguration",
        // The shortest wait `IntervalInSeconds` admits (published range 0..900), so the row
        // is about the delivery and not about an interval it would wait out.
        hints: (1, 0),
        prefix: Some("raw/events/"),
        named: true,
        grant: Grant::DestinationObjects,
        language: Language::Json,
        record: b"cfn-deployed-json-record\n",
        outcome: Outcome::Delivered,
    },
    Row {
        case: "a named JSON stream with the deprecated S3 destination spelling and no prefix",
        stack: "cfn-firehose-put-legacy",
        member: "S3DestinationConfiguration",
        hints: (1, 0),
        prefix: None,
        named: true,
        grant: Grant::DestinationObjects,
        language: Language::Json,
        record: b"cfn-deployed-legacy-record\n",
        outcome: Outcome::Delivered,
    },
    Row {
        case: "a YAML stream whose name CloudFormation generates, delivering under a prefix",
        stack: "cfn-firehose-put-yaml",
        member: "ExtendedS3DestinationConfiguration",
        hints: (1, 0),
        prefix: Some("yaml/landing/"),
        named: false,
        grant: Grant::DestinationObjects,
        language: Language::Yaml,
        record: b"cfn-deployed-yaml-record\n",
        outcome: Outcome::Delivered,
    },
    Row {
        case: "a named JSON stream whose buffering interval is the longest the hint admits",
        stack: "cfn-firehose-put-buffered",
        // The published maxima of both hints (`SizeInMBs` 1..128, `IntervalInSeconds`
        // 0..900), with one small record: neither condition is met while this suite runs.
        member: "ExtendedS3DestinationConfiguration",
        hints: (128, 900),
        prefix: Some("buffered/"),
        named: true,
        grant: Grant::DestinationObjects,
        language: Language::Json,
        record: b"cfn-deployed-buffered-record\n",
        outcome: Outcome::HoldsNothing,
    },
    Row {
        case: "a named JSON stream whose delivery role may only write another bucket",
        stack: "cfn-firehose-put-denied",
        member: "ExtendedS3DestinationConfiguration",
        hints: (1, 0),
        prefix: Some("denied/"),
        named: true,
        grant: Grant::ObjectsElsewhere,
        language: Language::Json,
        record: b"cfn-deployed-denied-record\n",
        outcome: Outcome::HoldsNothing,
    },
];

/// One deployed row: the stream the stack created, under the name it published.
struct Leg<'a> {
    row: &'a Row,
    stream: String,
}

#[tokio::test]
async fn a_put_on_a_stack_deployed_stream_is_delivered_to_its_declared_destination() {
    let router = emulator();

    // Every stack is created before any of them is awaited, so the suite spends ONE
    // provisioning span rather than one per row.
    for row in ROWS {
        let (status, body) = cloudformation(
            &router,
            "CreateStack",
            &[
                ("StackName", row.stack),
                ("TemplateBody", &row.template()),
                // Every template declares the IAM role its stream delivers under, by name.
                ("Capabilities.member.1", "CAPABILITY_NAMED_IAM"),
            ],
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: expected HTTP 200 from CreateStack, got {status} with body {body}",
            row.case
        );
    }

    let mut legs: Vec<Leg<'_>> = Vec::new();
    for row in ROWS {
        let described = await_complete(&router, row).await;
        let status = element(&described, "StackStatus");
        assert_eq!(
            status, CREATE_COMPLETE,
            "case {:?}: expected the stack to reach {CREATE_COMPLETE}, got {status} in \
             {described}",
            row.case
        );
        let stream = outputs_of(&described)
            .get("StreamName")
            .cloned()
            .unwrap_or_default();
        if row.named {
            assert_eq!(
                stream,
                row.declared_stream(),
                "case {:?}: expected the stack to publish the declared stream name, got \
                 {stream:?} in {described}",
                row.case
            );
        } else {
            // A name CloudFormation generated carries the stack's name, so what is checked is
            // the SHAPE of a generated name rather than a value this suite could compute.
            assert!(
                stream
                    .to_lowercase()
                    .starts_with(&format!("{}-", row.stack).to_lowercase())
                    && stream.len() > row.stack.len() + 1,
                "case {:?}: expected a generated name carrying the stack name, got {stream:?} \
                 in {described}",
                row.case
            );
        }
        legs.push(Leg { row, stream });
    }

    // Each record is put right after its own stack completed, through Firehose's own wire:
    // the stream a stack deployed takes data like any other.
    for leg in &legs {
        let (status, body) = firehose(
            &router,
            "PutRecord",
            &json!({
                "DeliveryStreamName": &leg.stream,
                "Record": { "Data": ::aws_smithy_types::base64::encode(leg.row.record) },
            }),
        )
        .await;
        assert_eq!(
            status, 200,
            "case {:?}: expected PutRecord against {:?} to be accepted, got {status} with \
             {body}",
            leg.row.case, leg.stream
        );
        assert!(
            body["RecordId"].as_str().is_some_and(|id| !id.is_empty()),
            "case {:?}: expected PutRecord against {:?} to answer a RecordId, got {body}",
            leg.row.case,
            leg.stream
        );
    }

    // The destinations whose buffering condition the put met, and whose role allows the
    // write, hold their object; the others hold nothing at every reading taken meanwhile.
    await_delivered(&router, &legs).await;
    // And they still hold nothing after as long a wait again, re-read throughout it.
    let until = Instant::now() + SILENCE_WINDOW;
    while Instant::now() < until {
        assert_holding_nothing(&router, &legs).await;
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    assert_holding_nothing(&router, &legs).await;

    // Each delivered object is the record its client put, under the destination's declared
    // prefix and the automatic time segments.
    for leg in &legs {
        if leg.row.outcome != Outcome::Delivered {
            continue;
        }
        let keys = keys_of(&router, leg.row).await;
        assert_eq!(
            keys.len(),
            1,
            "case {:?}: one flushed buffer is one object, got {keys:?}",
            leg.row.case
        );
        assert_key_layout(leg, &keys[0]);
        let body = object(&router, leg.row, &keys[0]).await;
        assert!(
            body == leg.row.record,
            "case {:?}: expected the object to hold the record that was put ({:?}), got {:?}",
            leg.row.case,
            String::from_utf8_lossy(leg.row.record),
            String::from_utf8_lossy(&body)
        );
    }
}

/// Poll `row`'s stack until it first reports a settled status, and answer the `DescribeStacks`
/// body that status was read from.
async fn await_complete(router: &MultiServiceRouter, row: &Row) -> String {
    let deadline = Instant::now() + DEPLOY_DEADLINE;
    loop {
        let (status, body) =
            cloudformation(router, "DescribeStacks", &[("StackName", row.stack)]).await;
        assert_eq!(
            status, 200,
            "case {:?}: expected HTTP 200 from DescribeStacks, got {status} with body {body}",
            row.case
        );
        let reported = element(&body, "StackStatus");
        if reported.ends_with("_COMPLETE") || reported.ends_with("_FAILED") {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "case {:?}: expected the stack to settle, last saw {reported:?} in {body}",
            row.case
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Wait until every destination that must be delivered to holds an object, requiring every
/// destination that must hold nothing to be empty at each reading taken meanwhile.
async fn await_delivered(router: &MultiServiceRouter, legs: &[Leg<'_>]) {
    let deadline = Instant::now() + DELIVERY_DEADLINE;
    loop {
        assert_holding_nothing(router, legs).await;
        let mut pending: Vec<&str> = Vec::new();
        for leg in legs {
            if leg.row.outcome == Outcome::Delivered && keys_of(router, leg.row).await.is_empty() {
                pending.push(leg.row.case);
            }
        }
        if pending.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected a delivered object for each of {pending:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Require every destination that must hold nothing to be empty right now.
async fn assert_holding_nothing(router: &MultiServiceRouter, legs: &[Leg<'_>]) {
    for leg in legs {
        if leg.row.outcome != Outcome::HoldsNothing {
            continue;
        }
        let keys = keys_of(router, leg.row).await;
        assert!(
            keys.is_empty(),
            "case {:?}: nothing may be written to this destination, got {keys:?}",
            leg.row.case
        );
    }
}

/// Every key `row`'s bucket holds, read through Amazon S3's own `ListObjectsV2`.
///
/// Each row delivers at most one object, so the listing is read in one page; a row that
/// delivered more than one page would fail the assertions above rather than pass on a short
/// read.
async fn keys_of(router: &MultiServiceRouter, row: &Row) -> Vec<String> {
    let (status, body) = send(
        router,
        "s3",
        "GET",
        &format!("/{}?list-type=2", row.bucket()),
        &[],
        Vec::new(),
    )
    .await;
    let text = String::from_utf8_lossy(&body).to_string();
    assert_eq!(
        status,
        200,
        "case {:?}: expected HTTP 200 from ListObjectsV2 on {}, got {status} with {text}",
        row.case,
        row.bucket()
    );
    let mut keys = elements(&text, "Key");
    keys.sort();
    keys
}

/// The bytes one delivered object holds, read through `GetObject`.
async fn object(router: &MultiServiceRouter, row: &Row, key: &str) -> Vec<u8> {
    let (status, body) = send(
        router,
        "s3",
        "GET",
        &format!("/{}/{key}", row.bucket()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(
        status,
        200,
        "case {:?}: expected HTTP 200 from GetObject for {key:?}, got {status} with {}",
        row.case,
        String::from_utf8_lossy(&body)
    );
    body
}

/// Require `key` to be the destination's declared `Prefix`, then the automatic
/// `YYYY/MM/DD/HH` segments, then a name beginning with the stream's own.
fn assert_key_layout(leg: &Leg<'_>, key: &str) {
    let case = leg.row.case;
    let declared = leg.row.prefix.unwrap_or_default();
    let rest = key.strip_prefix(declared).unwrap_or_else(|| {
        panic!(
            "case {case:?}: the key must begin with the declared prefix {declared:?}, got \
             {key:?}"
        )
    });
    let segments: Vec<&str> = rest.split('/').collect();
    assert!(
        segments.len() == 5,
        "case {case:?}: the automatic YYYY/MM/DD/HH segments and the object's own name follow \
         the declared prefix, got {rest:?} in key {key:?}"
    );
    // The widths of those four segments, as the documented `YYYY/MM/DD/HH` format spells them.
    for (width, segment) in [4, 2, 2, 2].iter().zip(&segments) {
        assert!(
            segment.len() == *width && segment.bytes().all(|byte| byte.is_ascii_digit()),
            "case {case:?}: expected a {width}-digit time segment, got {segment:?} in key \
             {key:?}"
        );
    }
    assert!(
        segments[4].starts_with(&format!("{}-", leg.stream)),
        "case {case:?}: the object's name begins with its stream, got {:?} in key {key:?}",
        segments[4]
    );
}

/// One Firehose operation over its `awsJson1_1` wire.
async fn firehose(router: &MultiServiceRouter, operation: &str, request: &Value) -> (u16, Value) {
    let (status, body) = send(
        router,
        "firehose",
        "POST",
        "/",
        &[
            ("content-type", "application/x-amz-json-1.1"),
            ("x-amz-target", &format!("Firehose_20150804.{operation}")),
        ],
        request.to_string().into_bytes(),
    )
    .await;
    let parsed = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    };
    (status, parsed)
}
