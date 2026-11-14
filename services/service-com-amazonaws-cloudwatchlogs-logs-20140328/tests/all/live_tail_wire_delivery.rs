// SPDX-License-Identifier: CC0-1.0

//! `StartLiveTail` over a real socket: the events a `PutLogEvents` on ANOTHER connection
//! ingests while the session is open are the ones the session delivers.
//!
//! RULE: a Live Tail session is a subscription to what its log groups ingest while it is
//! open, so the ingestion that fills it is a SEPARATE request — made by another client, on
//! another connection, while the session's own request is still in flight — and the session
//! answers with the events that ingestion stored.
//!
//! The sibling suite (`live_tail_sessions`) drives the same rule through the service in
//! process. This one drives it over HTTP on a loopback port, because that is the arrangement
//! a live tail is actually used in: one connection holds the session open while another
//! writes, and nothing of that can be observed by dispatching one request at a time.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use service_com_amazonaws_cloudwatchlogs_logs_20140328::state::ComAmazonawsCloudwatchlogsLogs20140328State;

use crate::live_tail_sessions::{decode_frames, delivered_by};

/// The log group and stream the session below tails.
const GROUP: &str = "/aws/emulator/live-tail-wire";
const STREAM: &str = "wire-one";

/// The authorization header every request below carries. Request authentication is off on
/// this router, so the header only has to name the credential scope the handlers read the
/// Region out of.
const AUTHORIZATION: &str = "AWS4-HMAC-SHA256 \
     Credential=AKIDEXAMPLE/20260101/eu-west-2/logs/aws4_request, \
     SignedHeaders=host;x-amz-target, Signature=0123456789abcdef";

/// How long a wait for a condition may take before the test gives up on it. Generous on
/// purpose: nothing here is timed, so a loaded host only has to reach the condition
/// eventually.
const CONDITION_DEADLINE: Duration = Duration::from_secs(120);

/// One operation written straight onto its OWN socket, with the response head and body read
/// back to EOF.
///
/// `connection: close` so the server closes the socket after answering and the read
/// terminates on EOF: this suite is about two requests in flight at once, so each one gets
/// its own connection rather than sharing one and serialising itself.
fn call(port: u16, operation: &str, body: &Value) -> (String, Vec<u8>) {
    let payload = body.to_string();
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to the served port");
    let request = format!(
        "POST / HTTP/1.1\r\n\
         host: logs.eu-west-2.amazonaws.com\r\n\
         authorization: {AUTHORIZATION}\r\n\
         x-amz-target: Logs_20140328.{operation}\r\n\
         content-type: application/x-amz-json-1.1\r\n\
         content-length: {}\r\n\
         connection: close\r\n\
         \r\n{payload}",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("write the request");
    stream.flush().expect("flush the request");
    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .expect("read the whole answer");
    let split = answer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("{operation}: a response head and body"));
    let head = String::from_utf8_lossy(&answer[..split]).to_string();
    (head, answer[split + 4..].to_vec())
}

/// How many Live Tail sessions the store holds as OPEN.
fn open_sessions(engine: &Arc<engine::InMemoryEngine>) -> usize {
    let state = engine.state::<ComAmazonawsCloudwatchlogsLogs20140328State>();
    let store = state.lock();
    store.live_tail_sessions.len()
}

/// A session served over the wire delivers the events another connection ingested while it
/// was open, and nothing the group held before it opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_on_the_wire_carries_what_another_connection_ingests() {
    let case = "a session held open while another connection writes";
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = smithy_server_runtime::MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_cloudwatchlogs_logs_20140328::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    let (endpoint, _served) = emulator_server::serve_on_ephemeral_port(router).await;
    let port: u16 = endpoint
        .rsplit(':')
        .next()
        .and_then(|port| port.parse().ok())
        .unwrap_or_else(|| panic!("an endpoint with a port, got {endpoint:?}"));

    // The group, its stream, and one event the group holds BEFORE any session opens.
    let at = crate::harness::now_ms() - 60 * 60 * 1_000;
    let setup = |operation: &'static str, body: Value| async move {
        let (head, answer) = tokio::task::spawn_blocking(move || call(port, operation, &body))
            .await
            .expect("the socket exchange runs to completion");
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "case {operation}: expected a 200 on the wire, got {head:?} {:?}",
            String::from_utf8_lossy(&answer)
        );
    };
    setup("CreateLogGroup", json!({"logGroupName": GROUP})).await;
    setup(
        "CreateLogStream",
        json!({"logGroupName": GROUP, "logStreamName": STREAM}),
    )
    .await;
    setup(
        "PutLogEvents",
        json!({
            "logGroupName": GROUP,
            "logStreamName": STREAM,
            "logEvents": [{"timestamp": at, "message": "BEFORE the session"}],
        }),
    )
    .await;

    // The session's own request, on its own connection, held open while the write below is
    // made on another.
    let session = tokio::task::spawn_blocking(move || {
        call(
            port,
            "StartLiveTail",
            &json!({"logGroupIdentifiers": [GROUP]}),
        )
    });

    // Only what is ingested while the session is open is delivered, so the write waits for
    // it to be open — polling for that condition, never sleeping a fixed span.
    let give_up_at = Instant::now() + CONDITION_DEADLINE;
    while open_sessions(&engine) == 0 {
        assert!(
            Instant::now() < give_up_at,
            "case {case:?}: the session's request never opened a session"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    setup(
        "PutLogEvents",
        json!({
            "logGroupName": GROUP,
            "logStreamName": STREAM,
            "logEvents": [{"timestamp": at + 1, "message": "DURING the session"}],
        }),
    )
    .await;

    let (head, body) = session
        .await
        .expect("the session's socket exchange runs to completion");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "case {case:?}: expected a 200 on the wire, got {head:?}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("application/vnd.amazon.eventstream"),
        "case {case:?}: expected an event-stream body, got {head:?}"
    );
    let delivered: Vec<String> = decode_frames(case, &body)
        .iter()
        .filter(|frame| frame.event_type == "sessionUpdate")
        .flat_map(|frame| delivered_by(case, &frame.payload))
        .map(|(message, _, _)| message)
        .collect();
    assert_eq!(
        delivered,
        vec!["DURING the session".to_string()],
        "case {case:?}: expected the event the other connection ingested while the session \
         was open, got {delivered:?}"
    );
}
