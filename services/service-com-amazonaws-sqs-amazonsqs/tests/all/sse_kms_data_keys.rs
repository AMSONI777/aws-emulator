// SPDX-License-Identifier: CC0-1.0

//! The KMS calls a queue encrypted with a CUSTOMER MANAGED key makes, and what bounds
//! them: the data key reuse period.
//!
//! RULE: a queue on a customer managed KMS key is server-side encrypted with envelope
//! encryption, so Amazon SQS obtains a data key from that key for the queue's messages and
//! reuses it for the length of the queue's own `KmsDataKeyReusePeriodSeconds` before
//! calling KMS again — "the length of time, in seconds, for which Amazon SQS can reuse a
//! data key to encrypt or decrypt messages before calling KMS again ... A shorter time
//! period provides better security but results in more calls to KMS" (the
//! `KmsDataKeyReusePeriodSeconds` entry of the `CreateQueue` `Attributes` documentation).
//! Each such call is an API call of the account made ON THE CALLER'S BEHALF: event history
//! records it under the service that was called (`eventSource` `kms.amazonaws.com`,
//! `eventName` `GenerateDataKey` / `Decrypt`) with the caller's own identity and
//! `invokedBy` naming Amazon SQS, and every call carries the encryption context entry
//! `aws:sqs:arn` naming the queue the data key is for.
//!
//! So the count is one-sided and per queue: every send inside one queue's window shares one
//! data key however many sends there are, and the first send after the window asks again.
//!
//! The tables span the classes the rule generalises over rather than one example:
//!
//! * the reuse period: the documented default (no attribute at all), both published bounds
//!   (60 and 86,400 seconds) and a value between them, each driven just inside its own
//!   window and just past it;
//! * how the sends are made: one at a time, and as a batch;
//! * which queue a data key belongs to: two queues on the SAME key get one data key each;
//! * which encryption a queue is on: a queue on the Amazon SQS owned key asks KMS nothing.
//!
//! Driven over the wire through the same `MultiServiceRouter` the emulator's front doors
//! use, with KMS mounted beside Amazon SQS on one engine, so every key here is one KMS
//! itself created. A reuse period is a documented duration measured in minutes at the
//! shortest, so no test sleeps for one: the instant the stored data key was obtained is
//! moved into the past through the engine seam, exactly as the retention suite moves a
//! message's instants, and everything asserted then goes over the wire.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Value};
use service_com_amazonaws_sqs_amazonsqs::state::{
    data_keys, ComAmazonawsSqsAmazonsqsState,
};
use smithy_server_runtime::MultiServiceRouter;

use super::support::{
    create_ok, emulator_with_kms, expected_arn, kms_ok, messages, ok, REGION,
};

/// The `eventSource` of the service these calls are made TO.
const KMS_EVENT_SOURCE: &str = "kms.amazonaws.com";

/// The `userIdentity.invokedBy` of a call Amazon SQS made for a caller.
const INVOKED_BY: &str = "sqs.amazonaws.com";

/// The access-key id every request these suites make is signed with
/// (`support::authorization_in`), which is the credential each record must name.
const ACCOUNT_KEY: &str = "AKIDTEST";

/// The data key spec Amazon SQS asks for, from KMS's own `DataKeySpec` value set
/// (`smithy_query(query="shape",shape="DataKeySpec")`: `AES_128 | AES_256`).
const DATA_KEY_SPEC: &str = "AES_256";

/// Every record the account's event history holds, as the CloudTrail event document each is
/// reported as — the same log CloudTrail's `LookupEvents` reads.
fn recorded(engine: &engine::InMemoryEngine) -> Vec<Value> {
    let log = service_com_amazonaws_sqs_amazonsqs::service::management_events::management_event_log(
        engine,
    )
    .expect("the shared engine carries the account's management-event log");
    let held = log.lock();
    held.iter()
        .map(|event| event.to_cloudtrail_event_json())
        .collect()
}

/// The records of calls to `event_name` made against KMS, in the order they were recorded.
fn kms_records(engine: &engine::InMemoryEngine, event_name: &str) -> Vec<Value> {
    recorded(engine)
        .into_iter()
        .filter(|record| {
            record["eventSource"] == json!(KMS_EVENT_SOURCE)
                && record["eventName"] == json!(event_name)
        })
        .collect()
}

/// The `aws:sqs:arn` entry of a record's encryption context: the queue the call was made
/// for.
fn context_queue(record: &Value) -> String {
    record["requestParameters"]["encryptionContext"]["aws:sqs:arn"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Move the instant the queue's stored data key was obtained `by` into the past, so the
/// window it may be reused in has run that much further out when the next send asks.
///
/// This is how a span the clock owes is reached without sleeping for it.
fn age_data_key(engine: &engine::InMemoryEngine, queue_name: &str, by: Duration) {
    let store = engine.state::<ComAmazonawsSqsAmazonsqsState>();
    let mut store = store.lock();
    let held = store
        .data_keys
        .get_mut(&(REGION.to_string(), queue_name.to_string()))
        .unwrap_or_else(|| panic!("case ageing {queue_name}: the queue holds no data key"));
    held.obtained_at = held
        .obtained_at
        .checked_sub(by)
        .unwrap_or(held.obtained_at);
}

/// Create a symmetric KMS key and answer `(key id, key ARN)`.
async fn create_key(router: &MultiServiceRouter) -> (String, String) {
    let created = kms_ok(router, "CreateKey", json!({})).await;
    let metadata = &created["KeyMetadata"];
    (
        metadata["KeyId"]
            .as_str()
            .unwrap_or_else(|| panic!("CreateKey reports a KeyId, got {created}"))
            .to_string(),
        metadata["Arn"]
            .as_str()
            .unwrap_or_else(|| panic!("CreateKey reports an Arn, got {created}"))
            .to_string(),
    )
}

/// Send `count` messages to the queue at `url`, one call each.
async fn send_each(router: &MultiServiceRouter, url: &str, count: usize) {
    for index in 0..count {
        ok(
            router,
            "SendMessage",
            json!({"QueueUrl": url, "MessageBody": format!("message {index}")}),
        )
        .await;
    }
}

/// Send `count` messages to the queue at `url` as ONE batch.
async fn send_batch(router: &MultiServiceRouter, url: &str, count: usize) {
    let entries: Vec<Value> = (0..count)
        .map(|index| json!({"Id": format!("e{index}"), "MessageBody": format!("entry {index}")}))
        .collect();
    let answer = ok(
        router,
        "SendMessageBatch",
        json!({"QueueUrl": url, "Entries": entries}),
    )
    .await;
    assert!(
        answer["Failed"]
            .as_array()
            .is_none_or(|failed| failed.is_empty()),
        "case a batch of {count} sends: every entry must be accepted, got {answer}"
    );
}

/// One row of the reuse-period table.
struct ReuseRow {
    case: &'static str,
    /// The `KmsDataKeyReusePeriodSeconds` the queue is created with, or `None` for a queue
    /// that names none and so is on the documented default of 300 seconds.
    period: Option<&'static str>,
    /// The window the row expects the queue to reuse one data key in.
    window: Duration,
    /// How many sends the burst makes.
    sends: usize,
    /// Whether the burst is made as one batch rather than one call per message.
    batched: bool,
}

/// A burst of sends inside one window makes exactly ONE `GenerateDataKey` call, and the
/// first send past that window makes a second — over the published range of the period, and
/// whichever way the sends are made.
#[tokio::test]
async fn one_data_key_per_reuse_window_however_many_sends_the_burst_makes() {
    let rows: &[ReuseRow] = &[
        ReuseRow {
            case: "the documented default: no attribute at all",
            period: None,
            window: Duration::from_secs(300),
            sends: 6,
            batched: false,
        },
        ReuseRow {
            case: "the published minimum, 60 seconds",
            period: Some("60"),
            window: Duration::from_secs(60),
            sends: 6,
            batched: false,
        },
        ReuseRow {
            case: "an hour, as a send burst makes it",
            period: Some("3600"),
            window: Duration::from_secs(3600),
            sends: 6,
            batched: false,
        },
        ReuseRow {
            case: "the published maximum, 86,400 seconds",
            period: Some("86400"),
            window: Duration::from_secs(86_400),
            sends: 3,
            batched: false,
        },
        ReuseRow {
            case: "one batch of sends inside one window",
            period: Some("600"),
            window: Duration::from_secs(600),
            sends: 6,
            batched: true,
        },
    ];

    for (index, row) in rows.iter().enumerate() {
        let (router, engine) = emulator_with_kms();
        let (key_id, key_arn) = create_key(&router).await;
        let name = format!("reuse-{index}");
        let mut attributes = BTreeMap::from([("KmsMasterKeyId", key_id.clone())]);
        if let Some(period) = row.period {
            attributes.insert("KmsDataKeyReusePeriodSeconds", period.to_string());
        }
        let url = create_ok(&router, &name, &json!(attributes)).await;
        let arn = expected_arn(&name);

        if row.batched {
            send_batch(&router, &url, row.sends).await;
        } else {
            send_each(&router, &url, row.sends).await;
        }
        let made = kms_records(&engine, "GenerateDataKey");
        assert_eq!(
            made.len(),
            1,
            "case {:?}: {} sends inside one window must make exactly one GenerateDataKey \
             call, got {made:?}",
            row.case,
            row.sends
        );
        let record = &made[0];
        for (member, expected) in [
            ("eventSource", json!(KMS_EVENT_SOURCE)),
            ("eventName", json!("GenerateDataKey")),
            ("awsRegion", json!(REGION)),
            // A cryptographic operation changes nothing the account holds.
            ("readOnly", json!(true)),
        ] {
            assert_eq!(
                record[member], expected,
                "case {:?}: expected {member} {expected}, got {record}",
                row.case
            );
        }
        assert_eq!(
            record["userIdentity"]["invokedBy"],
            json!(INVOKED_BY),
            "case {:?}: the call was made by Amazon SQS for the caller, got {record}",
            row.case
        );
        assert_eq!(
            record["userIdentity"]["accessKeyId"],
            json!(ACCOUNT_KEY),
            "case {:?}: the record names the CALLER's own credential, got {record}",
            row.case
        );
        assert_eq!(
            context_queue(record),
            arn,
            "case {:?}: the encryption context must name the queue, got {record}",
            row.case
        );
        assert_eq!(
            record["requestParameters"]["keyId"],
            json!(key_arn),
            "case {:?}: the call names the queue's own key, got {record}",
            row.case
        );
        assert_eq!(
            record["requestParameters"]["keySpec"],
            json!(DATA_KEY_SPEC),
            "case {:?}: expected keySpec {DATA_KEY_SPEC:?}, got {record}",
            row.case
        );
        assert!(
            record["responseElements"].is_null(),
            "case {:?}: no record carries key material, got {record}",
            row.case
        );

        // Just INSIDE the window: the data key is still the queue's, so the send makes no
        // further call.
        age_data_key(&engine, &name, row.window - Duration::from_secs(1));
        send_each(&router, &url, 1).await;
        let inside = kms_records(&engine, "GenerateDataKey");
        assert_eq!(
            inside.len(),
            1,
            "case {:?}: a send one second inside the window reuses the data key, got \
             {inside:?}",
            row.case
        );

        // Just PAST it: the window has run out, so the next send asks KMS again.
        age_data_key(&engine, &name, Duration::from_secs(2));
        send_each(&router, &url, 1).await;
        let past = kms_records(&engine, "GenerateDataKey");
        assert_eq!(
            past.len(),
            2,
            "case {:?}: the first send past the window must call KMS again, got {past:?}",
            row.case
        );
        assert_eq!(
            context_queue(&past[1]),
            arn,
            "case {:?}: the second call is for the same queue, got {:?}",
            row.case,
            past[1]
        );
    }
}

/// A data key belongs to ONE queue: two queues on the same customer managed key each obtain
/// their own, so a burst on one makes no call for the other.
#[tokio::test]
async fn each_queue_obtains_its_own_data_key_from_a_shared_key() {
    let (router, engine) = emulator_with_kms();
    let (key_id, _) = create_key(&router).await;
    let long = create_ok(
        &router,
        "shared-key-long",
        &json!({"KmsMasterKeyId": key_id, "KmsDataKeyReusePeriodSeconds": "3600"}),
    )
    .await;
    let short = create_ok(
        &router,
        "shared-key-short",
        &json!({"KmsMasterKeyId": key_id, "KmsDataKeyReusePeriodSeconds": "60"}),
    )
    .await;

    send_each(&router, &long, 6).await;
    send_each(&router, &short, 3).await;
    // The short queue's window runs out; the long one's does not.
    age_data_key(&engine, "shared-key-short", Duration::from_secs(150));
    send_each(&router, &short, 3).await;

    let made = kms_records(&engine, "GenerateDataKey");
    let for_long = made
        .iter()
        .filter(|record| context_queue(record) == expected_arn("shared-key-long"))
        .count();
    let for_short = made
        .iter()
        .filter(|record| context_queue(record) == expected_arn("shared-key-short"))
        .count();
    assert_eq!(
        (for_long, for_short),
        (1, 2),
        "case two queues on one key: expected one call for the 3600 s queue and two for \
         the 60 s one, got {made:?}"
    );
}

/// What a queue's encryption decides: only a queue on a CUSTOMER MANAGED key asks KMS for a
/// data key at all. The rows span the encryption a queue can be on.
#[tokio::test]
async fn only_a_queue_on_a_customer_managed_key_calls_kms_for_a_data_key() {
    let (router, engine) = emulator_with_kms();
    let (key_id, _) = create_key(&router).await;
    type Row = (&'static str, &'static str, Value, usize);
    let rows: Vec<Row> = vec![
        (
            "a queue naming no encryption attribute at all",
            "sse-default",
            json!({}),
            0,
        ),
        (
            "a queue on the Amazon SQS owned key",
            "sse-sqs",
            json!({"SqsManagedSseEnabled": "true"}),
            0,
        ),
        (
            "a queue on a customer managed key",
            "sse-kms",
            json!({"KmsMasterKeyId": key_id}),
            1,
        ),
    ];
    for (case, name, attributes, expected) in rows {
        let before = kms_records(&engine, "GenerateDataKey").len();
        let url = create_ok(&router, name, &attributes).await;
        send_each(&router, &url, 2).await;
        let made = kms_records(&engine, "GenerateDataKey").len() - before;
        assert_eq!(
            made, expected,
            "case {case:?}: expected {expected} GenerateDataKey call(s), got {made}"
        );
    }
}

/// The other leg of the same window: a receive reuses the data key inside it and has KMS
/// open the message's own sealed data key past it — a `Decrypt` call recorded exactly like
/// the generation, and made once however many messages share the data key.
///
/// The `Decrypt` record is only written when KMS actually opened the sealed copy the queue
/// stored, so it is also what proves that copy is a real ciphertext of the queue's key under
/// the documented encryption context.
#[tokio::test]
async fn a_receive_reuses_the_data_key_inside_the_window_and_has_kms_open_it_past_it() {
    let (router, engine) = emulator_with_kms();
    let (key_id, key_arn) = create_key(&router).await;
    let name = "receive-window";
    let url = create_ok(
        &router,
        name,
        &json!({"KmsMasterKeyId": key_id, "KmsDataKeyReusePeriodSeconds": "60"}),
    )
    .await;
    send_each(&router, &url, 3).await;

    // Inside the window: the queue's own data key serves the receive, so KMS is asked
    // nothing.
    let delivered = messages(
        &ok(
            &router,
            "ReceiveMessage",
            json!({"QueueUrl": url, "MaxNumberOfMessages": 10, "VisibilityTimeout": 0}),
        )
        .await,
    );
    assert_eq!(
        delivered.len(),
        3,
        "case a receive inside the window: the three messages must come over, got \
         {delivered:?}"
    );
    assert_eq!(
        delivered[0]["Body"],
        json!("message 0"),
        "case a receive inside the window: the body sent must come back, got {delivered:?}"
    );
    let inside = kms_records(&engine, "Decrypt");
    assert!(
        inside.is_empty(),
        "case a receive inside the window: the data key is reused, so KMS is asked \
         nothing, got {inside:?}"
    );

    // Past it: the data key the messages were sealed under is opened by KMS, once for the
    // whole batch, because all three messages share it.
    age_data_key(&engine, name, Duration::from_secs(61));
    let delivered = messages(
        &ok(
            &router,
            "ReceiveMessage",
            json!({"QueueUrl": url, "MaxNumberOfMessages": 10, "VisibilityTimeout": 0}),
        )
        .await,
    );
    assert_eq!(
        delivered.len(),
        3,
        "case a receive past the window: the messages must still come over, got \
         {delivered:?}"
    );
    let past = kms_records(&engine, "Decrypt");
    assert_eq!(
        past.len(),
        1,
        "case a receive past the window: one Decrypt for the one data key the messages \
         share, got {past:?}"
    );
    let record = &past[0];
    assert_eq!(
        (
            record["eventSource"].clone(),
            record["userIdentity"]["invokedBy"].clone(),
            record["requestParameters"]["keyId"].clone(),
        ),
        (json!(KMS_EVENT_SOURCE), json!(INVOKED_BY), json!(key_arn)),
        "case a receive past the window: the record must name KMS, Amazon SQS and the \
         queue's key, got {record}"
    );
    assert_eq!(
        context_queue(record),
        expected_arn(name),
        "case a receive past the window: the encryption context must name the queue, got \
         {record}"
    );
}

/// The window is read off the queue at the instant the question is asked, and it is the
/// documented default for a queue that names none — so a value the attribute accepts is the
/// window, and nothing outside the published range ever is.
#[test]
fn the_reuse_period_is_the_queue_s_own_value_inside_the_published_range() {
    // The published range, from the `KmsDataKeyReusePeriodSeconds` entry of the
    // `CreateQueue` `Attributes` documentation: "between 60 seconds (1 minute) and 86,400
    // seconds (24 hours). Default: 300 (5 minutes)".
    let rows = [
        ("a queue naming no value", None, 300),
        ("the published minimum", Some("60"), 60),
        ("a value inside the range", Some("3600"), 3600),
        ("the published maximum", Some("86400"), 86_400),
        ("one second under the minimum", Some("59"), 60),
        ("one second over the maximum", Some("86401"), 86_400),
        ("a value that is not a number", Some("later"), 300),
    ];
    for (case, carried, expected) in rows {
        let mut attributes: BTreeMap<String, String> = BTreeMap::new();
        if let Some(carried) = carried {
            attributes.insert(
                "KmsDataKeyReusePeriodSeconds".to_string(),
                carried.to_string(),
            );
        }
        let window = data_keys::reuse_period(&attributes);
        assert_eq!(
            window,
            Duration::from_secs(expected),
            "case {case:?}: expected a window of {expected} s, got {window:?}"
        );
    }
}

/// The encryption context of every call on a queue's key names that queue, under the key
/// the SQS Developer Guide's server-side-encryption page states: `aws:sqs:arn`.
#[test]
fn the_encryption_context_names_the_queue_under_the_documented_key() {
    for name in ["probe", "probe.fifo", "a-queue-with-a-longer-name"] {
        let arn = expected_arn(name);
        let context = data_keys::encryption_context(&arn);
        assert_eq!(
            context.get(data_keys::QUEUE_ENCRYPTION_CONTEXT_NAME),
            Some(&arn),
            "case {name:?}: expected the queue's ARN under \
             {:?}, got {context:?}",
            data_keys::QUEUE_ENCRYPTION_CONTEXT_NAME
        );
        assert_eq!(
            context.len(),
            1,
            "case {name:?}: the context carries that one entry, got {context:?}"
        );
    }
}

/// A send that never happened asks nothing: the data key is obtained for the message a send
/// accepts, so a send refused before it reaches the queue leaves event history empty.
#[tokio::test]
async fn a_send_refused_before_the_queue_makes_no_kms_call() {
    let (router, engine) = emulator_with_kms();
    let (key_id, _) = create_key(&router).await;
    let url = create_ok(
        &router,
        "refused-sends",
        &json!({"KmsMasterKeyId": key_id}),
    )
    .await;
    // A body no message may carry: refused before the store is touched.
    let (status, answer) = super::support::call(
        &router,
        "SendMessage",
        &json!({"QueueUrl": url, "MessageBody": ""}),
    )
    .await;
    assert_eq!(
        status, 400,
        "case an empty body: the send must be refused, got {status} with {answer}"
    );
    let made = kms_records(&engine, "GenerateDataKey");
    assert!(
        made.is_empty(),
        "case an empty body: a refused send makes no KMS call, got {made:?}"
    );
    // And the queue's own data key was not obtained either, so the store holds none.
    let store = engine.state::<ComAmazonawsSqsAmazonsqsState>();
    let held = store.lock().data_keys.len();
    assert_eq!(
        held, 0,
        "case an empty body: no data key is held for a queue nothing was sent to, got \
         {held}"
    );
}
