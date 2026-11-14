// SPDX-License-Identifier: CC0-1.0

//! A CloudFormation-deployed alarm's SNS action is decided by the topic policy the SAME stack
//! declared — through the whole mounted service set, the one `core/router/src/lib.rs` assembles
//! for the binary.
//!
//! The RULE under test: **an alarm publishes its notification to the SNS topic its
//! `AlarmActions` names only where that topic's own access policy ALLOWS `SNS:Publish` for the
//! `cloudwatch.amazonaws.com` service principal; a policy that states no such grant withholds
//! the publish, so the queue subscribed to the topic receives nothing — whoever wrote that
//! policy, including an `AWS::SNS::TopicPolicy` a stack declared.**
//!
//! Four services have to agree for that to hold: CloudFormation provisions the alarm, the topic
//! and the topic's policy, CloudWatch evaluates the grant and publishes, SNS fans out, SQS holds
//! what arrived. An `AWS::SNS::TopicPolicy` REPLACES the policy a topic came up with, so a stack
//! that declares a least-privilege document is the one shape in which a deployed estate is
//! silently mute in a real account — which is why the deployed path is pinned here beside the
//! crate-local tables
//! (`services/service-com-amazonaws-cloudwatch-graniteserviceversion20100801/tests/all/sns_action_topic_policy.rs`
//! and `.../sns_action_publish_grant.rs`), where the policy forms and the key policy of an
//! encrypted topic are tabled.
//!
//! The rows differ along the grant the declared document makes: the publish granted to this
//! service principal, granted to it only for another topic, granted to another principal, and a
//! stack declaring no topic policy at all (so the policy the topic came up with stands).

use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::query_wire::{form_encode, opt_element};

/// The Region the whole wiring lives in, and so the Region the stack belongs to.
const REGION: &str = "us-west-2";

/// CloudWatch's `X-Amz-Target` prefix and its signing name (`sigv4Name: monitoring`).
const CLOUDWATCH_TARGET_PREFIX: &str = "GraniteServiceVersion20100801";
const CLOUDWATCH_SIGNING_NAME: &str = "monitoring";

/// The service principal CloudWatch executes an alarm action as, which a topic policy names
/// under `Principal` as `{"Service": …}`.
const CLOUDWATCH_PRINCIPAL: &str = "cloudwatch.amazonaws.com";

/// The service principal SNS performs its delivery to a subscribed queue as, which is what that
/// queue's own policy has to allow.
const SNS_PRINCIPAL: &str = "sns.amazonaws.com";

/// How long a row waits for the stack to settle and for an asynchronous delivery, and how often
/// it looks again. Generous only so a failure is a failure rather than a hang: every row waits
/// for the CONDITION it is about rather than for a span of the clock.
const DEADLINE: Duration = Duration::from_secs(30);
const LOOK_AGAIN: Duration = Duration::from_millis(100);

/// The whole emulator over one engine, exactly as the binary assembles it.
fn router() -> MultiServiceRouter {
    let engine = aws_emulator_router::new_engine();
    let mut router = aws_emulator_router::build_router(engine);
    // Signature verification is the front door's concern, not this suite's.
    router.set_request_authentication(false);
    router
}

/// A SigV4 `Authorization` whose credential scope names `service` in [`REGION`], which is what
/// routes the request.
fn authorization(service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/{service}/aws4_request, \
         SignedHeaders=host, Signature=0000"
    )
}

/// One `awsQuery` form call, answering the HTTP status and the body.
async fn query(
    router: &MultiServiceRouter,
    signing_name: &str,
    version: &str,
    action: &str,
    members: &[(&str, &str)],
) -> (u16, String) {
    let mut body = format!("Action={action}&Version={version}");
    for (key, value) in members {
        body.push('&');
        body.push_str(&form_encode(key));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("{signing_name}.{REGION}.amazonaws.com"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", authorization(signing_name))
        .body(Bytes::from(body))
        .expect("the test request is well formed");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    (status, String::from_utf8_lossy(response.body()).to_string())
}

/// One CloudFormation call, which must answer 200.
async fn cfn(
    router: &MultiServiceRouter,
    case: &str,
    action: &str,
    members: &[(&str, &str)],
) -> String {
    let (status, body) = query(router, "cloudformation", "2010-05-15", action, members).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from CloudFormation {action}, got {status} with {body}"
    );
    body
}

/// One `X-Amz-Target` RPC call, which must answer 200.
async fn rpc(
    router: &MultiServiceRouter,
    case: &str,
    signing_name: &str,
    target_prefix: &str,
    operation: &str,
    body: &Value,
) -> Value {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("{signing_name}.{REGION}.amazonaws.com"))
        .header("content-type", "application/x-amz-json-1.0")
        .header("x-amz-target", format!("{target_prefix}.{operation}"))
        .header("authorization", authorization(signing_name))
        .body(Bytes::from(body.to_string()))
        .expect("the test request is well formed");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let parsed: Value = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or(Value::Null)
    };
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from {signing_name} {operation}, got {status} with \
         {parsed}"
    );
    parsed
}

/// One CloudWatch call (`awsJson1_0`).
async fn cw(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    rpc(
        router,
        case,
        CLOUDWATCH_SIGNING_NAME,
        CLOUDWATCH_TARGET_PREFIX,
        operation,
        body,
    )
    .await
}

/// One Amazon SQS call (`awsJson1_0`).
async fn sqs(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    rpc(router, case, "sqs", "AmazonSQS", operation, body).await
}

/// The policy statement a row's `AWS::SNS::TopicPolicy` declares: an allow of `sns:Publish` for
/// `principal` on `resource`, which is how such a grant is written.
fn publish_grant(principal: Value, resource: Value) -> Value {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowPublish",
            "Effect": "Allow",
            "Principal": principal,
            "Action": "sns:Publish",
            "Resource": resource,
        }],
    })
}

/// The template a row deploys: a topic, a queue subscribed to it (granting SNS the send), an
/// alarm whose `AlarmActions` is that topic, and — for a row that declares one — the topic
/// policy that decides the alarm's publish.
fn template(names: &Names, topic_policy: Option<Value>) -> String {
    let mut resources = json!({
        "Topic": {
            "Type": "AWS::SNS::Topic",
            "Properties": {"TopicName": names.topic},
        },
        "Queue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": names.queue},
        },
        "QueuePolicy": {
            "Type": "AWS::SQS::QueuePolicy",
            "Properties": {
                "Queues": [{"Ref": "Queue"}],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AllowSNSDelivery",
                        "Effect": "Allow",
                        "Principal": {"Service": SNS_PRINCIPAL},
                        "Action": "sqs:SendMessage",
                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                    }],
                },
            },
        },
        "Subscription": {
            "Type": "AWS::SNS::Subscription",
            "Properties": {
                "TopicArn": {"Ref": "Topic"},
                "Protocol": "sqs",
                "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
            },
        },
        "Alarm": {
            "Type": "AWS::CloudWatch::Alarm",
            "Properties": {
                "AlarmName": names.alarm,
                "Namespace": "Custom/Deployed",
                "MetricName": "Backlog",
                "Statistic": "Average",
                "Period": 60,
                "EvaluationPeriods": 1,
                "Threshold": 1.0,
                "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                "AlarmActions": [{"Ref": "Topic"}],
            },
        },
    });
    if let Some(document) = topic_policy {
        resources["TopicPolicy"] = json!({
            "Type": "AWS::SNS::TopicPolicy",
            "Properties": {"Topics": [{"Ref": "Topic"}], "PolicyDocument": document},
        });
    }
    json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "an alarm, its topic and the policy that decides its action",
        "Resources": resources,
    })
    .to_string()
}

/// The names one row's stack declares, each carrying the row's own index so two rows never
/// share a resource.
struct Names {
    stack: String,
    topic: String,
    queue: String,
    alarm: String,
}

impl Names {
    fn of(index: usize) -> Self {
        Self {
            stack: format!("cw-alarm-topic-policy-{index}"),
            topic: format!("cw-alarm-topic-{index}"),
            queue: format!("cw-alarm-queue-{index}"),
            alarm: format!("cw-alarm-{index}"),
        }
    }
}

/// Deploy the stack and wait until it reports a terminal status, which must be
/// `CREATE_COMPLETE`.
async fn deploy(router: &MultiServiceRouter, case: &str, names: &Names, template: &str) {
    cfn(
        router,
        case,
        "CreateStack",
        &[("StackName", &names.stack), ("TemplateBody", template)],
    )
    .await;
    let deadline = Instant::now() + DEADLINE;
    let mut status = String::new();
    while Instant::now() < deadline {
        let described = cfn(router, case, "DescribeStacks", &[("StackName", &names.stack)]).await;
        status = opt_element(&described, "StackStatus").unwrap_or_default();
        if status != "CREATE_IN_PROGRESS" {
            break;
        }
        tokio::time::sleep(LOOK_AGAIN).await;
    }
    assert_eq!(
        status, "CREATE_COMPLETE",
        "case {case:?}: the stack must reach CREATE_COMPLETE, got {status:?}"
    );
}

/// The url of the queue the stack declared, as Amazon SQS reports it for that name.
async fn queue_url(router: &MultiServiceRouter, case: &str, names: &Names) -> String {
    let answered = sqs(
        router,
        case,
        "GetQueueUrl",
        &json!({"QueueName": names.queue}),
    )
    .await;
    answered["QueueUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: GetQueueUrl reported no url: {answered}"))
        .to_string()
}

/// Every alarm notification waiting on the queue at `url`, as the body SNS enveloped.
async fn arrived(router: &MultiServiceRouter, case: &str, url: &str) -> Vec<Value> {
    let received = sqs(
        router,
        case,
        "ReceiveMessage",
        &json!({"QueueUrl": url, "MaxNumberOfMessages": 10}),
    )
    .await;
    received["Messages"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|message| {
            let body = message["Body"].as_str().unwrap_or_default();
            let envelope: Value = serde_json::from_str(body).unwrap_or_else(|error| {
                panic!("case {case:?}: the body is not the SNS envelope ({error}): {body}")
            });
            let inner = envelope["Message"].as_str().unwrap_or_default();
            serde_json::from_str(inner).unwrap_or_else(|error| {
                panic!("case {case:?}: the message is not an alarm notification ({error}): {inner}")
            })
        })
        .collect()
}

/// Poll the queue until `wanted` notifications have arrived or the deadline passes, reading it
/// at least once — so a row expecting NOTHING reads the queue rather than asserting about a
/// queue nobody looked at.
async fn arrived_until(
    router: &MultiServiceRouter,
    case: &str,
    url: &str,
    wanted: usize,
) -> Vec<Value> {
    let deadline = Instant::now() + DEADLINE;
    let mut held: Vec<Value> = Vec::new();
    held.extend(arrived(router, case, url).await);
    while held.len() < wanted && Instant::now() < deadline {
        held.extend(arrived(router, case, url).await);
        if held.len() >= wanted {
            break;
        }
        tokio::time::sleep(LOOK_AGAIN).await;
    }
    held
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deployed_alarms_action_is_decided_by_the_topic_policy_the_stack_declared() {
    // (case, the policy document the stack declares for the topic, how many notifications the
    // subscribed queue is owed)
    let rows: Vec<(&str, Option<Value>, usize)> = vec![
        (
            "a stack declaring no topic policy, so the one the topic came up with stands",
            None,
            1,
        ),
        (
            "a declared grant of the publish to this service principal",
            Some(publish_grant(
                json!({"Service": CLOUDWATCH_PRINCIPAL}),
                json!({"Ref": "Topic"}),
            )),
            1,
        ),
        (
            "a declared policy granting the publish to another principal only",
            Some(publish_grant(
                json!({"Service": "events.amazonaws.com"}),
                json!({"Ref": "Topic"}),
            )),
            0,
        ),
        (
            "a declared grant of the publish to this principal on another topic only",
            Some(publish_grant(
                json!({"Service": CLOUDWATCH_PRINCIPAL}),
                json!("arn:aws:sns:us-west-2:000000000000:cw-alarm-topic-elsewhere"),
            )),
            0,
        ),
    ];

    for (index, (case, document, wanted)) in rows.into_iter().enumerate() {
        let router = router();
        let names = Names::of(index);
        deploy(&router, case, &names, &template(&names, document)).await;

        // The alarm the stack declared really exists in CloudWatch: the action below is fired
        // on the resource that service holds, not on anything the stack reports for itself.
        let described = cw(
            &router,
            case,
            "DescribeAlarms",
            &json!({"AlarmNames": [names.alarm]}),
        )
        .await;
        assert_eq!(
            described["MetricAlarms"][0]["AlarmName"].as_str(),
            Some(names.alarm.as_str()),
            "case {case:?}: CloudWatch must hold the alarm the stack declared, got {described}"
        );
        let topic_arn = described["MetricAlarms"][0]["AlarmActions"][0]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            topic_arn.ends_with(&names.topic),
            "case {case:?}: the alarm's action must name the topic the stack declared, got \
             {topic_arn:?}"
        );

        let url = queue_url(&router, case, &names).await;
        cw(
            &router,
            case,
            "SetAlarmState",
            &json!({
                "AlarmName": names.alarm,
                "StateValue": "ALARM",
                "StateReason": "driven by the test",
            }),
        )
        .await;

        let notifications = arrived_until(&router, case, &url, wanted).await;
        assert_eq!(
            notifications.len(),
            wanted,
            "case {case:?}: expected {wanted} notification(s) on the subscribed queue, got \
             {notifications:?}"
        );
        if wanted > 0 {
            assert_eq!(
                notifications[0]["AlarmName"].as_str(),
                Some(names.alarm.as_str()),
                "case {case:?}: the notification must name the alarm, got {}",
                notifications[0]
            );
            assert_eq!(
                notifications[0]["NewStateValue"].as_str(),
                Some("ALARM"),
                "case {case:?}: the notification must carry the state moved to, got {}",
                notifications[0]
            );
            continue;
        }
        // The alarm's own history accounts for the publish that was withheld, which is where a
        // client sees WHY nothing arrived.
        let history = cw(
            &router,
            case,
            "DescribeAlarmHistory",
            &json!({"AlarmName": names.alarm, "HistoryItemType": "Action"}),
        )
        .await;
        let data = history["AlarmHistoryItems"][0]["HistoryData"]
            .as_str()
            .unwrap_or_default();
        let recorded: Value = serde_json::from_str(data).unwrap_or(Value::Null);
        assert_eq!(
            recorded["actionState"].as_str(),
            Some("Failed"),
            "case {case:?}: the withheld action must be recorded as Failed, got {history}"
        );
        let error = recorded["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("not authorized to perform: SNS:Publish")
                && error.contains(&topic_arn),
            "case {case:?}: the recorded error must name the refused publish and the topic \
             {topic_arn:?}, got {error:?}"
        );
    }
}
