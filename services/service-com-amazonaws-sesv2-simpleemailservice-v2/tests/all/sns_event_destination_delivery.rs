// SPDX-License-Identifier: CC0-1.0

//! What a configuration set's Amazon SNS event destination DELIVERS: the email events one
//! accepted send publishes to the topic, end to end over HTTP.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` with this service,
//! Amazon SNS and Amazon SQS mounted on ONE engine, which is what makes the topic a send
//! publishes to the topic SNS fans out — and asserts each event where a client observes one:
//! on the queue subscribed to that topic, read through `sqs:ReceiveMessage`. The subscription
//! asks for raw delivery, so the body the queue holds is the published document itself.
//!
//! The RULE these cases pin: for each event an accepted send produces, every event
//! destination of the configuration set the message named that is `Enabled` and whose
//! `MatchingEventTypes` names that event's type receives one notification of it — for an
//! `SnsDestination`, as one message published to the topic its `TopicArn` names, carrying the
//! event's own `eventType` and, under `mail`, the message the event is about (the `MessageId`
//! the send answered, the sender, the recipients, the headers and the set's own message tag);
//! and every other destination receives nothing.
//!
//! The table spans what the rule generalises over: which events the send's recipients produce
//! (acceptance only, a delivery, a failure, a complaint, several at once), how many recipients
//! one send has and whether they react differently, which event types the destination matches
//! (one, two, every value of `EventType`, only types this send never produces), and whether
//! the destination is on at all. A row that expects NOTHING is read against a positive control
//! of its own — a second set whose destination is on, publishing to a topic of its own — so an
//! absence cannot pass by timing. The recorded case — a destination matching `SEND` and
//! `DELIVERY` that is first off and then switched on — is two rows of it plus the case that
//! flips the same destination with `UpdateConfigurationSetEventDestination` and reads the
//! NEXT send's own `MessageId` off the event.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use service_com_amazonaws_sesv2_simpleemailservice_v2::state::ComAmazonawsSesv2SimpleemailserviceV2State;
use service_com_amazonaws_sesv2_simpleemailservice_v2::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The Region every call below is signed for, and so the Region of the topic and the queue.
const REGION: &str = "us-east-1";

/// The sender every send is from, and the domain identity that authorises it.
const SENDER: &str = "sender@senders.example.com";
const SENDER_DOMAIN: &str = "senders.example.com";

/// The subject every send carries.
const SUBJECT: &str = "a message under test";

/// The message tag SES applies to every send made through a configuration set, which the
/// published document reports under `mail.tags`.
const CONFIGURATION_SET_TAG: &str = "ses:configuration-set";

/// The service principal Amazon SNS delivers to a subscribed queue as, which is what the
/// queue's own policy grants the send.
const SNS_PRINCIPAL: &str = "sns.amazonaws.com";

/// The `x-amz-target` prefix and JSON version Amazon SQS serves (that crate's
/// `OPERATIONS.md` "Wire protocol").
const SQS_TARGET_PREFIX: &str = "AmazonSQS";

/// Every value of the `EventType` enum
/// (`smithy_query(query="shape",shape="EventType",model_path="services/service-com-amazonaws-sesv2-simpleemailservice-v2/smithy-model/com-amazonaws-sesv2-simpleemailservice-v2.json")`).
const EVERY_EVENT_TYPE: &[&str] = &[
    "BOUNCE",
    "CLICK",
    "COMPLAINT",
    "DELIVERY",
    "DELIVERY_DELAY",
    "OPEN",
    "REJECT",
    "RENDERING_FAILURE",
    "SEND",
    "SUBSCRIPTION",
];

/// The mailbox-simulator addresses a send below is addressed to, and what each does with the
/// message (`state::event_publication::outcome`): `success` takes it, `bounce` is an unknown
/// user, `complaint` takes it and reports it.
const SUCCESS: &str = "success@simulator.amazonses.com";
const BOUNCING: &str = "bounce@simulator.amazonses.com";
const COMPLAINING: &str = "complaint@simulator.amazonses.com";
const ALSO_SUCCESS: &str = "ooto@simulator.amazonses.com";

/// How many times the queue is read while waiting for the events a row expects.
///
/// An email event is published ASYNCHRONOUSLY — the message is accepted and answered before
/// any event of it exists — so the events arrive on a task of their own. Each pass reads the
/// queue again and yields to the runtime; nothing here waits for a SPAN, and the loop stops
/// as soon as what it is waiting for is there.
const READS_WHILE_PUBLISHING: usize = 2_000;

/// How many further reads confirm that what the queue holds has settled — so a row that
/// expects fewer events than the topic ends up carrying, or none at all, fails on the
/// comparison rather than on a race.
const SETTLED_READS: usize = 64;

/// The name every destination below is attached under: one destination per set, so the name
/// is not what a row varies.
const DESTINATION_NAME: &str = "sns-gate";

/// The configuration set a row expecting NO event is read against: its own destination is on
/// and matches the acceptance, so the events of a send made through it are the proof that the
/// publishing path ran at all.
const ANCHOR_SET: &str = "positive-control-sns-set";

/// One event a row expects on the queue: the `eventType` the published document is of, and
/// the addresses the document itself names.
#[derive(Clone, Copy)]
struct Expected {
    /// The `eventType` of the published document.
    event_type: &'static str,
    /// The recipients the event's own list is about, in the order the send addressed them.
    addresses: &'static [&'static str],
    /// `(bounceType, bounceSubType)` for a failure, `None` for every other event.
    bounce: Option<(&'static str, &'static str)>,
}

/// One row of the table.
struct Row {
    case: &'static str,
    /// The configuration set the row creates and sends through.
    set: &'static str,
    /// `EventDestinationDefinition$Enabled`.
    enabled: bool,
    /// The event types the destination matches, as the definition names them.
    matching: &'static [&'static str],
    /// The recipients of the one send, in the order the request lists them.
    recipients: &'static [&'static str],
    /// The events the topic must have published afterwards, and nothing besides.
    expected: &'static [Expected],
}

const ROWS: &[Row] = &[
    Row {
        case: "a bouncing recipient under a destination matching every event type",
        set: "bounce-sns-set",
        enabled: true,
        matching: EVERY_EVENT_TYPE,
        recipients: &[BOUNCING],
        expected: &[
            Expected {
                event_type: "Send",
                addresses: &[BOUNCING],
                bounce: None,
            },
            Expected {
                event_type: "Bounce",
                addresses: &[BOUNCING],
                bounce: Some(("Permanent", "General")),
            },
        ],
    },
    Row {
        case: "a deliverable recipient under a destination matching every event type",
        set: "delivery-sns-set",
        enabled: true,
        matching: EVERY_EVENT_TYPE,
        recipients: &[SUCCESS],
        expected: &[
            Expected {
                event_type: "Send",
                addresses: &[SUCCESS],
                bounce: None,
            },
            Expected {
                event_type: "Delivery",
                addresses: &[SUCCESS],
                bounce: None,
            },
        ],
    },
    Row {
        case: "a recipient that reports the message",
        set: "complaint-sns-set",
        enabled: true,
        matching: EVERY_EVENT_TYPE,
        recipients: &[COMPLAINING],
        expected: &[
            Expected {
                event_type: "Send",
                addresses: &[COMPLAINING],
                bounce: None,
            },
            Expected {
                event_type: "Delivery",
                addresses: &[COMPLAINING],
                bounce: None,
            },
            Expected {
                event_type: "Complaint",
                addresses: &[COMPLAINING],
                bounce: None,
            },
        ],
    },
    Row {
        case: "two recipients of one send that react differently",
        set: "mixed-sns-set",
        enabled: true,
        matching: EVERY_EVENT_TYPE,
        recipients: &[BOUNCING, SUCCESS],
        expected: &[
            Expected {
                event_type: "Send",
                addresses: &[BOUNCING, SUCCESS],
                bounce: None,
            },
            Expected {
                event_type: "Bounce",
                addresses: &[BOUNCING],
                bounce: Some(("Permanent", "General")),
            },
            Expected {
                event_type: "Delivery",
                addresses: &[SUCCESS],
                bounce: None,
            },
        ],
    },
    Row {
        case: "two recipients that both take the message are reported together",
        set: "two-deliveries-sns-set",
        enabled: true,
        matching: &["DELIVERY"],
        recipients: &[SUCCESS, ALSO_SUCCESS],
        expected: &[Expected {
            event_type: "Delivery",
            addresses: &[SUCCESS, ALSO_SUCCESS],
            bounce: None,
        }],
    },
    Row {
        case: "a destination matching one event type publishes only that one",
        set: "bounce-only-sns-set",
        enabled: true,
        matching: &["BOUNCE"],
        recipients: &[BOUNCING],
        expected: &[Expected {
            event_type: "Bounce",
            addresses: &[BOUNCING],
            bounce: Some(("Permanent", "General")),
        }],
    },
    Row {
        case: "a destination matching the acceptance and the delivery publishes both",
        set: "send-and-delivery-sns-set",
        enabled: true,
        matching: &["SEND", "DELIVERY"],
        recipients: &[SUCCESS],
        expected: &[
            Expected {
                event_type: "Send",
                addresses: &[SUCCESS],
                bounce: None,
            },
            Expected {
                event_type: "Delivery",
                addresses: &[SUCCESS],
                bounce: None,
            },
        ],
    },
    Row {
        case: "a destination that is off publishes nothing",
        set: "switched-off-sns-set",
        enabled: false,
        matching: EVERY_EVENT_TYPE,
        recipients: &[BOUNCING],
        expected: &[],
    },
    Row {
        case: "a destination that is off publishes nothing for the types the recorded case \
               matches either",
        set: "switched-off-pair-sns-set",
        enabled: false,
        matching: &["SEND", "DELIVERY"],
        recipients: &[SUCCESS],
        expected: &[],
    },
    Row {
        case: "a destination matching only event types this send never produces publishes \
               nothing",
        set: "unmatched-type-sns-set",
        enabled: true,
        matching: &["OPEN", "CLICK", "RENDERING_FAILURE"],
        recipients: &[SUCCESS],
        expected: &[],
    },
];

/// One answered request: its status and parsed body.
struct Reply {
    status: u16,
    body: Value,
}

impl Reply {
    /// A string at `pointer`, or `""` when the body carries nothing there.
    fn text(&self, pointer: &str) -> String {
        self.body
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
}

/// The emulator under test: this service, Amazon SNS and Amazon SQS on ONE engine, the shape
/// `core/router/src/lib.rs` mounts every service in.
struct Emulator {
    router: MultiServiceRouter,
    engine: Arc<engine::InMemoryEngine>,
}

impl Emulator {
    fn new() -> Self {
        let engine = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        // These cases exercise handler behaviour, not SigV4.
        router.set_request_authentication(false);
        router.register_service(EmulatedService::new(Arc::clone(&engine)));
        router.register_service(
            service_com_amazonaws_sns_amazonsimplenotificationservice::EmulatedService::new(
                Arc::clone(&engine),
            ),
        );
        router.register_service(
            service_com_amazonaws_sqs_amazonsqs::EmulatedService::new(Arc::clone(&engine)),
        );
        Emulator { router, engine }
    }

    /// An Amazon SNS client over the in-process callback into this emulator — the same seam
    /// the handler publishes an email event through, so the setup reaches SNS the way it does.
    fn sns(&self) -> ::aws_sdk_sns::Client {
        let callback = ::smithy_server_runtime::EmbeddedEmulator::from_router(self.router.clone());
        let config = ::aws_sdk_sns::Config::builder()
            .behavior_version(::aws_sdk_sns::config::BehaviorVersion::latest())
            .region(::aws_sdk_sns::config::Region::new(REGION.to_string()))
            .endpoint_url(format!("https://sns.{REGION}.amazonaws.com"))
            .credentials_provider(callback.aws_credentials_provider())
            .http_client(callback.http_client())
            .retry_config(::aws_sdk_sns::config::retry::RetryConfig::disabled())
            .timeout_config(::aws_sdk_sns::config::timeout::TimeoutConfig::disabled())
            .identity_cache(::aws_sdk_sns::config::IdentityCache::no_cache())
            .stalled_stream_protection(
                ::aws_sdk_sns::config::StalledStreamProtectionConfig::disabled(),
            )
            .build();
        ::aws_sdk_sns::Client::from_conf(config)
    }

    /// One call on this service's restJson1 surface.
    async fn ses(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let payload = match &body {
            Some(value) => bytes::Bytes::from(serde_json::to_vec(value).expect("serialize body")),
            None => bytes::Bytes::new(),
        };
        let request = http::Request::builder()
            .method(method)
            .uri(format!("https://email.{REGION}.amazonaws.com{path}"))
            .header("host", format!("email.{REGION}.amazonaws.com"))
            .header("content-type", "application/json")
            .header("authorization", authorization("ses"))
            .body(payload)
            .expect("build request");
        self.answered(request).await
    }

    /// The same call, requiring the 200 the operation's output shape declares.
    async fn ses_ok(&self, case: &str, method: &str, path: &str, body: Option<Value>) -> Reply {
        let reply = self.ses(method, path, body).await;
        assert_eq!(
            reply.status, 200,
            "case {case:?}: {method} {path} must be served, got {} {}",
            reply.status, reply.body
        );
        reply
    }

    /// One `awsJson1_0` call against Amazon SQS.
    async fn sqs(&self, case: &str, operation: &str, body: &Value) -> Value {
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", format!("sqs.{REGION}.amazonaws.com"))
            .header("content-type", "application/x-amz-json-1.0")
            .header("x-amz-target", format!("{SQS_TARGET_PREFIX}.{operation}"))
            .header("authorization", authorization("sqs"))
            .body(bytes::Bytes::from(body.to_string()))
            .expect("build request");
        let reply = self.answered(request).await;
        assert_eq!(
            reply.status, 200,
            "case {case:?}: sqs:{operation} must be served, got {} {}",
            reply.status, reply.body
        );
        reply.body
    }

    async fn answered(&self, request: http::Request<bytes::Bytes>) -> Reply {
        let response = self.router.dispatch(request).await;
        let status = response.status().as_u16();
        let payload = response.into_body();
        let body = if payload.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&payload).unwrap_or(Value::Null)
        };
        Reply { status, body }
    }

    /// The account with a verified sending domain, so every send below is authorised.
    async fn given_verified_sender(&self, case: &str) {
        self.ses_ok(
            case,
            "POST",
            "/v2/email/identities",
            Some(json!({"EmailIdentity": SENDER_DOMAIN})),
        )
        .await;
        // Bring the verification transition the clock owes the identity into the past, so a
        // send does not race the span.
        let state = self
            .engine
            .state::<ComAmazonawsSesv2SimpleemailserviceV2State>();
        let mut store = state.lock();
        let past = SystemTime::now()
            .checked_sub(Duration::from_secs(1))
            .expect("an instant before now");
        for record in store.identities.values_mut() {
            record.verification_due_at = past;
        }
        store.settle(SystemTime::now());
    }

    /// The topic `name`, created through the SNS API; answers the ARN SNS minted for it.
    async fn given_topic(&self, case: &str, name: &str) -> String {
        let created = self
            .sns()
            .create_topic()
            .name(name)
            .send()
            .await
            .unwrap_or_else(|error| panic!("case {case:?}: CreateTopic({name}) failed: {error:?}"));
        created
            .topic_arn()
            .unwrap_or_else(|| panic!("case {case:?}: CreateTopic({name}) reported no TopicArn"))
            .to_string()
    }

    /// A queue called `name` that the topic at `topic_arn` may deliver to, subscribed to that
    /// topic with raw delivery; answers the queue's url.
    async fn given_subscribed_queue(&self, case: &str, name: &str, topic_arn: &str) -> String {
        let created = self
            .sqs(case, "CreateQueue", &json!({"QueueName": name}))
            .await;
        let url = created["QueueUrl"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: CreateQueue reported no QueueUrl: {created}"))
            .to_string();
        let attributes = self
            .sqs(
                case,
                "GetQueueAttributes",
                &json!({"QueueUrl": url, "AttributeNames": ["QueueArn"]}),
            )
            .await;
        let arn = attributes["Attributes"]["QueueArn"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("case {case:?}: GetQueueAttributes reported no QueueArn: {attributes}")
            })
            .to_string();
        self.sqs(
            case,
            "SetQueueAttributes",
            &json!({"QueueUrl": url, "Attributes": {"Policy": grant_to_sns(&arn, topic_arn)}}),
        )
        .await;
        // "RawMessageDelivery – When set to true, enables raw message delivery to Amazon SQS
        // […] endpoints" (`SetSubscriptionAttributes`), so the queue holds the published
        // document itself rather than an SNS envelope around it.
        self.sns()
            .subscribe()
            .topic_arn(topic_arn)
            .protocol("sqs")
            .endpoint(&arn)
            .attributes("RawMessageDelivery", "true")
            .send()
            .await
            .unwrap_or_else(|error| panic!("case {case:?}: Subscribe({arn}) failed: {error:?}"));
        url
    }

    /// A configuration set carrying one SNS event destination, publishing to `topic_arn`.
    async fn given_destination(
        &self,
        case: &str,
        set: &str,
        enabled: bool,
        matching: &[&str],
        topic_arn: &str,
    ) {
        self.ses_ok(
            case,
            "POST",
            "/v2/email/configuration-sets",
            Some(json!({"ConfigurationSetName": set})),
        )
        .await;
        self.ses_ok(
            case,
            "POST",
            &format!("/v2/email/configuration-sets/{set}/event-destinations"),
            Some(json!({
                "EventDestinationName": DESTINATION_NAME,
                "EventDestination": definition(enabled, matching, topic_arn),
            })),
        )
        .await;
    }

    /// `UpdateConfigurationSetEventDestination` over the SAME destination of `set`.
    async fn update_destination(
        &self,
        case: &str,
        set: &str,
        enabled: bool,
        matching: &[&str],
        topic_arn: &str,
    ) {
        self.ses_ok(
            case,
            "PUT",
            &format!("/v2/email/configuration-sets/{set}/event-destinations/{DESTINATION_NAME}"),
            Some(json!({"EventDestination": definition(enabled, matching, topic_arn)})),
        )
        .await;
    }

    /// `SendEmail` through `set` to `recipients`, answering the `MessageId` it minted.
    async fn send(&self, case: &str, set: &str, recipients: &[&str]) -> String {
        let request = json!({
            "FromEmailAddress": SENDER,
            "Destination": {"ToAddresses": recipients},
            "ConfigurationSetName": set,
            "Content": {"Simple": {
                "Subject": {"Data": SUBJECT},
                "Body": {"Text": {"Data": "hello"}},
            }},
        });
        let reply = self
            .ses_ok(case, "POST", "/v2/email/outbound-emails", Some(request))
            .await;
        let message_id = reply.text("/MessageId");
        assert!(
            !message_id.is_empty(),
            "case {case:?}: an accepted send must answer a MessageId, got {}",
            reply.body
        );
        message_id
    }

    /// Every message waiting on the queue at `url` right now, as the document each body
    /// carries.
    async fn received(&self, case: &str, url: &str) -> Vec<Value> {
        let answered = self
            .sqs(
                case,
                "ReceiveMessage",
                &json!({"QueueUrl": url, "MaxNumberOfMessages": 10}),
            )
            .await;
        answered["Messages"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|message| {
                let body = message["Body"].as_str().unwrap_or_default();
                serde_json::from_str::<Value>(body).unwrap_or_else(|error| {
                    panic!("case {case:?}: a published event is not JSON ({error}): {body:?}")
                })
            })
            .collect()
    }
}

/// The `authorization` header a call signed for `signing_name` carries: the credential scope
/// is what routes the request to the service that serves it.
fn authorization(signing_name: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAEMULATOR0000000/20260101/{REGION}/{signing_name}/\
         aws4_request, SignedHeaders=host, Signature=00"
    )
}

/// The `EventDestinationDefinition` a row attaches: the switch, the types it matches and the
/// topic it publishes to.
fn definition(enabled: bool, matching: &[&str], topic_arn: &str) -> Value {
    json!({
        "Enabled": enabled,
        "MatchingEventTypes": matching,
        "SnsDestination": {"TopicArn": topic_arn},
    })
}

/// The queue policy AWS documents for an SQS queue subscribed to an SNS topic: the service
/// principal `sns.amazonaws.com`, allowed `sqs:SendMessage` on that queue, for deliveries
/// coming from that one topic.
fn grant_to_sns(queue_arn: &str, topic_arn: &str) -> String {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowSNSDelivery",
            "Effect": "Allow",
            "Principal": {"Service": SNS_PRINCIPAL},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })
    .to_string()
}

/// The addresses a `Send`/`Bounce`/`Delivery`/`Complaint` document names, read from the
/// member that event's own document carries them in.
fn addresses_of(event_type: &str, document: &Value) -> Vec<String> {
    let listed = |pointer: &str, member: Option<&str>| -> Vec<String> {
        document
            .pointer(pointer)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|entry| match member {
                Some(member) => entry
                    .get(member)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                None => entry.as_str().unwrap_or_default().to_string(),
            })
            .collect()
    };
    match event_type {
        // The acceptance is about the message, so the addresses it names are the ones the
        // message was accepted for.
        "Send" => listed("/mail/destination", None),
        "Bounce" => listed("/bounce/bouncedRecipients", Some("emailAddress")),
        "Delivery" => listed("/delivery/recipients", None),
        "Complaint" => listed("/complaint/complainedRecipients", Some("emailAddress")),
        other => panic!("no event of this suite is of type {other:?}"),
    }
}

/// Assert ONE published document against the event `expected` describes, for the send that
/// minted `message_id` through `set`.
fn assert_event(case: &str, expected: &Expected, document: &Value, set: &str, message_id: &str) {
    assert_eq!(
        document["eventType"],
        json!(expected.event_type),
        "case {case:?}: expected eventType {:?}, got {:?}",
        expected.event_type,
        document["eventType"]
    );
    assert_eq!(
        document["mail"]["messageId"],
        json!(message_id),
        "case {case:?}: expected mail.messageId {message_id:?}, got {:?}",
        document["mail"]["messageId"]
    );
    assert_eq!(
        document["mail"]["source"],
        json!(SENDER),
        "case {case:?}: expected mail.source {SENDER:?}, got {:?}",
        document["mail"]["source"]
    );
    assert_eq!(
        document["mail"]["commonHeaders"]["subject"],
        json!(SUBJECT),
        "case {case:?}: expected mail.commonHeaders.subject {SUBJECT:?}, got {:?}",
        document["mail"]["commonHeaders"]["subject"]
    );
    assert_eq!(
        document["mail"]["tags"][CONFIGURATION_SET_TAG],
        json!([set]),
        "case {case:?}: expected mail.tags[{CONFIGURATION_SET_TAG:?}] to name {set:?}, got {:?}",
        document["mail"]["tags"]
    );
    let actual = addresses_of(expected.event_type, document);
    let wanted: Vec<String> = expected.addresses.iter().map(|at| at.to_string()).collect();
    assert_eq!(
        actual, wanted,
        "case {case:?}: expected the {:?} event to name {wanted:?}, got {actual:?}",
        expected.event_type
    );
    if let Some((bounce_type, sub_type)) = expected.bounce {
        assert_eq!(
            document["bounce"]["bounceType"],
            json!(bounce_type),
            "case {case:?}: expected bounce.bounceType {bounce_type:?}, got {:?}",
            document["bounce"]["bounceType"]
        );
        assert_eq!(
            document["bounce"]["bounceSubType"],
            json!(sub_type),
            "case {case:?}: expected bounce.bounceSubType {sub_type:?}, got {:?}",
            document["bounce"]["bounceSubType"]
        );
    }
}

/// The documents the queue holds once `wanted` many are all there, and then once what it
/// holds has settled.
async fn settled_documents(
    emulator: &Emulator,
    case: &str,
    url: &str,
    wanted: usize,
) -> Vec<Value> {
    let mut held: Vec<Value> = Vec::new();
    for _ in 0..READS_WHILE_PUBLISHING {
        if held.len() >= wanted {
            break;
        }
        held.extend(emulator.received(case, url).await);
        ::tokio::task::yield_now().await;
    }
    for _ in 0..SETTLED_READS {
        ::tokio::task::yield_now().await;
        let again = emulator.received(case, url).await;
        assert!(
            again.is_empty(),
            "case {case:?}: the topic kept publishing events: {again:?} on top of {held:?}"
        );
    }
    held
}

/// The one document of `held` that is of `event_type`.
fn of_type<'a>(case: &str, held: &'a [Value], event_type: &str) -> &'a Value {
    held.iter()
        .find(|document| document["eventType"] == json!(event_type))
        .unwrap_or_else(|| panic!("case {case:?}: no {event_type:?} event among {held:?}"))
}

#[tokio::test]
async fn a_send_publishes_one_topic_message_per_matched_email_event() {
    for row in ROWS {
        let case = row.case;
        let emulator = Emulator::new();
        emulator.given_verified_sender(case).await;
        let topic = emulator.given_topic(case, "ses-events").await;
        let url = emulator
            .given_subscribed_queue(case, "ses-events-queue", &topic)
            .await;
        emulator
            .given_destination(case, row.set, row.enabled, row.matching, &topic)
            .await;
        // The positive control a row expecting nothing is read against, on a topic and a
        // queue of its own: a set whose destination is ON and matches the acceptance.
        let anchor_url = if row.expected.is_empty() {
            let anchor_topic = emulator.given_topic(case, "control-events").await;
            let anchor_url = emulator
                .given_subscribed_queue(case, "control-events-queue", &anchor_topic)
                .await;
            emulator
                .given_destination(case, ANCHOR_SET, true, &["SEND"], &anchor_topic)
                .await;
            anchor_url
        } else {
            String::new()
        };

        // Nothing is published before the send: attaching a destination publishes no event.
        let before = emulator.received(case, &url).await;
        assert!(
            before.is_empty(),
            "case {case:?}: attaching a destination must publish no event, got {before:?}"
        );

        let message_id = emulator.send(case, row.set, row.recipients).await;
        // A row that expects NOTHING needs a positive control, because an absence is only
        // meaningful once the publishing path is known to have run: a second set whose own
        // destination is on publishes the acceptance of a send made AFTER this row's, so
        // waiting for that event is what proves this row's send had its chance before the
        // row's own queue is asserted empty.
        if row.expected.is_empty() {
            let anchor = emulator.send(case, ANCHOR_SET, &[SUCCESS]).await;
            let published = settled_documents(&emulator, case, &anchor_url, 1).await;
            assert_eq!(
                published.len(),
                1,
                "case {case:?}: the positive control's destination is on and matches the \
                 acceptance, got {published:?}"
            );
            assert_event(
                case,
                &Expected {
                    event_type: "Send",
                    addresses: &[SUCCESS],
                    bounce: None,
                },
                &published[0],
                ANCHOR_SET,
                &anchor,
            );
        }
        let held = settled_documents(&emulator, case, &url, row.expected.len()).await;
        assert_eq!(
            held.len(),
            row.expected.len(),
            "case {case:?}: expected {} event(s) on the topic, got {held:?}",
            row.expected.len()
        );
        // One message per expectation, matched by its own `eventType`: separate publications
        // carry no order of their own.
        for expected in row.expected {
            let document = of_type(case, &held, expected.event_type);
            assert_event(case, expected, document, row.set, &message_id);
        }
    }
}

#[tokio::test]
async fn switching_a_destination_on_publishes_the_next_send_and_not_the_earlier_one() {
    // The switch is read at the moment the events are published, so the SAME destination
    // flipped from off to on publishes nothing for the send made while it was off — those
    // events are not delivered late either — and the next send's events name that send's own
    // MessageId.
    let case = "a destination switched on between two sends";
    let set = "re-enabled-sns-set";
    let matching: &[&str] = &["SEND", "DELIVERY"];
    let emulator = Emulator::new();
    emulator.given_verified_sender(case).await;
    let topic = emulator.given_topic(case, "gate-events").await;
    let url = emulator
        .given_subscribed_queue(case, "gate-events-queue", &topic)
        .await;
    emulator
        .given_destination(case, set, false, matching, &topic)
        .await;

    let while_off = emulator.send(case, set, &[SUCCESS]).await;
    for _ in 0..SETTLED_READS {
        let held = emulator.received(case, &url).await;
        assert!(
            held.is_empty(),
            "case {case:?}: a destination that is off must publish nothing, got {held:?}"
        );
        ::tokio::task::yield_now().await;
    }

    emulator
        .update_destination(case, set, true, matching, &topic)
        .await;
    let while_on = emulator.send(case, set, &[SUCCESS]).await;
    assert_ne!(
        while_off, while_on,
        "case {case:?}: two sends must mint two MessageIds, got {while_off:?} twice"
    );
    let held = settled_documents(&emulator, case, &url, 2).await;
    assert_eq!(
        held.len(),
        2,
        "case {case:?}: expected the acceptance and the delivery of the second send, got \
         {held:?}"
    );
    for event_type in ["Send", "Delivery"] {
        let document = of_type(case, &held, event_type);
        assert_event(
            case,
            &Expected {
                event_type,
                addresses: &[SUCCESS],
                bounce: None,
            },
            document,
            set,
            &while_on,
        );
    }
    for document in &held {
        assert_ne!(
            document["mail"]["messageId"],
            json!(while_off),
            "case {case:?}: an event of the re-enabled destination must name the second \
             send's MessageId, got the first one in {document:?}"
        );
    }
}

#[tokio::test]
async fn only_the_enabled_destination_of_a_set_receives_the_events() {
    // `Enabled` is read per DESTINATION, so two destinations of one set that name two topics
    // part ways on it: one publishes every event it matches, the other nothing at all.
    let case = "one set, one destination on and one off";
    let set = "two-destinations-sns-set";
    let emulator = Emulator::new();
    emulator.given_verified_sender(case).await;
    let live_topic = emulator.given_topic(case, "live-events").await;
    let quiet_topic = emulator.given_topic(case, "quiet-events").await;
    let live_url = emulator
        .given_subscribed_queue(case, "live-events-queue", &live_topic)
        .await;
    let quiet_url = emulator
        .given_subscribed_queue(case, "quiet-events-queue", &quiet_topic)
        .await;
    emulator
        .given_destination(case, set, true, &["SEND"], &live_topic)
        .await;
    emulator
        .ses_ok(
            case,
            "POST",
            &format!("/v2/email/configuration-sets/{set}/event-destinations"),
            Some(json!({
                "EventDestinationName": "sns-gate-off",
                "EventDestination": definition(false, EVERY_EVENT_TYPE, &quiet_topic),
            })),
        )
        .await;

    let message_id = emulator.send(case, set, &[SUCCESS]).await;
    let held = settled_documents(&emulator, case, &live_url, 1).await;
    assert_eq!(
        held.len(),
        1,
        "case {case:?}: the destination that is on matches only the acceptance, got {held:?}"
    );
    assert_event(
        case,
        &Expected {
            event_type: "Send",
            addresses: &[SUCCESS],
            bounce: None,
        },
        &held[0],
        set,
        &message_id,
    );
    for _ in 0..SETTLED_READS {
        let quiet = emulator.received(case, &quiet_url).await;
        assert!(
            quiet.is_empty(),
            "case {case:?}: the destination that is off must publish nothing, got {quiet:?}"
        );
        ::tokio::task::yield_now().await;
    }
}
