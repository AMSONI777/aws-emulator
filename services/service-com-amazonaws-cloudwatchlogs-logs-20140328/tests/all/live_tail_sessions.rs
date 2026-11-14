// SPDX-License-Identifier: CC0-1.0

//! `StartLiveTail` sessions over the log events ingested while they are open, end to end
//! over the wire.
//!
//! RULE: a Live Tail session is a SUBSCRIPTION to what the log groups it names ingest while
//! it is open — "a stream of log events that have been recently ingested in the log groups"
//! — served as HTTP 200 whose body is an AWS event stream that OPENS with the frame a client
//! reads the output shape itself out of (`:event-type` `initial-response`) — a client that
//! does not find it there reads none of the frames behind it — then carries "A single
//! LiveTailSessionStart object […] at the start of the session", and then, "every second, a
//! LiveTailSessionUpdate object […] contain[ing] an array of the actual log events" ingested
//! in that second that every selector of the request admits (`logStreamNames` "only log
//! events in the log streams that you specify here", `logStreamNamePrefixes`,
//! `logEventFilterPattern` "include only log events that match the pattern"), bounded by the
//! 500 events an update may carry and reporting `sampled` exactly when the match exceeded
//! what it carried. An event a group already held when the session opened is not delivered,
//! and a session over a log group the account does not hold is refused, like every modelled
//! error of this operation, as a client error at HTTP 400.
//!
//! The rows of the tables below differ along what the rule generalises over: which selector
//! the request carries and in which FORM (a name or an ARN, named streams or prefixed ones, a
//! term pattern, a JSON pattern, a space-delimited pattern), how many log groups the session
//! spans, how many events the selection admits relative to the update's ceiling, and which
//! modelled constraint a refused request broke.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_smithy_eventstream::frame::read_message_from;
use aws_smithy_types::event_stream::HeaderValue;
use serde_json::{json, Value};

use service_com_amazonaws_cloudwatchlogs_logs_20140328::state::live_tail::{
    MAX_BUFFERED_BYTES, MAX_BUFFERED_UPDATES,
};
use service_com_amazonaws_cloudwatchlogs_logs_20140328::state::ComAmazonawsCloudwatchlogsLogs20140328State;

use crate::harness::{base_ms, batch, messages, Logs};

/// The two log groups the sessions below tail. Two groups rather than one, because a
/// session spans "up to 10 log groups" and interleaves their events.
const GROUP_A: &str = "/aws/emulator/live-tail-a";
const GROUP_B: &str = "/aws/emulator/live-tail-b";

/// `GROUP_A`'s streams: two share a prefix, so a prefix selects a proper subset.
const APP_ONE: &str = "app-one";
const APP_TWO: &str = "app-two";
/// `GROUP_B`'s one stream.
const SYS_ONE: &str = "sys-one";

/// The media type an event-stream body carries.
const EVENT_STREAM: &str = "application/vnd.amazon.eventstream";

/// The `:event-type` of the frame an event-stream response opens with, which carries the
/// output's non-stream members (source:
/// `service_common::event_stream::INITIAL_RESPONSE_EVENT`).
const INITIAL_RESPONSE: &str = "initial-response";

/// The documented event ceiling of one update, as `StartLiveTail` states it ("The array of
/// log events contained in a LiveTailSessionUpdate can include as many as 500 log events").
const MAX_EVENTS_PER_UPDATE: usize = 500;

/// How long a wait for a condition may take before the test gives up on it. Generous on
/// purpose: nothing here is timed, so a loaded host only has to reach the condition
/// eventually.
const CONDITION_DEADLINE: Duration = Duration::from_secs(120);

/// How often a wait re-reads the condition it is waiting for.
const CONDITION_POLL: Duration = Duration::from_millis(5);

/// One stored event: the group and stream it is written to, its offset from the suite's
/// base instant and its message. The offsets are distinct across BOTH groups, so the
/// chronological order of the writes is total.
struct Stored {
    group: &'static str,
    stream: &'static str,
    offset: i64,
    message: &'static str,
}

/// The events every selection row tails over.
static STORED: [Stored; 5] = [
    Stored {
        group: GROUP_A,
        stream: APP_ONE,
        offset: 0,
        message: "ERROR disk full",
    },
    Stored {
        group: GROUP_A,
        stream: APP_TWO,
        offset: 10,
        message: "{\"level\":\"WARN\",\"code\":500}",
    },
    Stored {
        group: GROUP_A,
        stream: APP_ONE,
        offset: 20,
        message: "INFO disk fine",
    },
    Stored {
        group: GROUP_B,
        stream: SYS_ONE,
        offset: 30,
        message: "ERROR kernel panic",
    },
    Stored {
        group: GROUP_A,
        stream: APP_TWO,
        offset: 40,
        message: "ERROR 404 while handling orders",
    },
];

/// The `(group, stream)` pairs [`STORED`] is written through, in the order the writes are
/// made: a session is handed the events in the order the groups ingested them, so this is
/// also the order it delivers them in.
const INGESTED_THROUGH: [(&str, &str); 3] = [
    (GROUP_A, APP_ONE),
    (GROUP_A, APP_TWO),
    (GROUP_B, SYS_ONE),
];

/// The two groups and their three streams, created and empty.
async fn given_groups_and_streams(logs: &Logs) {
    for group in GROUPS {
        logs.ok("CreateLogGroup", &json!({"logGroupName": group}))
            .await;
    }
    for (group, stream) in INGESTED_THROUGH {
        logs.ok(
            "CreateLogStream",
            &json!({"logGroupName": group, "logStreamName": stream}),
        )
        .await;
    }
}

/// Write [`STORED`] — one batch per stream, in [`INGESTED_THROUGH`] order — stamped from
/// `at`.
async fn ingest_stored_events(logs: &Logs, at: i64) {
    for (group, stream) in INGESTED_THROUGH {
        let events: Vec<(i64, &str)> = STORED
            .iter()
            .filter(|stored| stored.group == group && stored.stream == stream)
            .map(|stored| (at + stored.offset, stored.message))
            .collect();
        logs.ok(
            "PutLogEvents",
            &json!({
                "logGroupName": group,
                "logStreamName": stream,
                "logEvents": batch(&events),
            }),
        )
        .await;
    }
}

/// One decoded event-stream frame: the `:event-type` the union member is framed under,
/// and its payload.
///
/// `pub(crate)` because the wire suite beside this one reads the same frames off a socket
/// and so decodes them the same way.
pub(crate) struct Frame {
    pub(crate) event_type: String,
    pub(crate) payload: Value,
}

/// Decode an event-stream body, asserting the frame headers an SDK decoder requires.
pub(crate) fn decode_frames(case: &str, body: &[u8]) -> Vec<Frame> {
    let mut buffer = bytes::Bytes::copy_from_slice(body);
    let mut frames = Vec::new();
    while !buffer.is_empty() {
        let message = read_message_from(&mut buffer).unwrap_or_else(|error| {
            panic!("case {case:?}: the body must decode as event-stream frames: {error}")
        });
        let header = |name: &str| {
            message
                .headers()
                .iter()
                .find(|header| header.name().as_str() == name)
                .map(|header| match header.value() {
                    HeaderValue::String(value) => value.as_str().to_string(),
                    other => format!("{other:?}"),
                })
        };
        assert_eq!(
            header(":message-type").as_deref(),
            Some("event"),
            "case {case:?}: a session frame must be an event, got {:?}",
            header(":message-type")
        );
        let event_type = header(":event-type")
            .unwrap_or_else(|| panic!("case {case:?}: a session frame named no :event-type"));
        let payload: Value = serde_json::from_slice(message.payload()).unwrap_or_else(|error| {
            panic!("case {case:?}: the {event_type} payload must be JSON: {error}")
        });
        frames.push(Frame {
            event_type,
            payload,
        });
    }
    frames
}

/// One session that was served: its `sessionStart` and the `sessionUpdate`s that followed.
struct Session {
    start: Value,
    updates: Vec<Value>,
}

impl Session {
    /// The `(message, logStreamName, logGroupIdentifier)` triples the session delivered,
    /// across its updates, in the order it delivered them.
    fn delivered(&self, case: &str) -> Vec<(String, String, String)> {
        self.updates
            .iter()
            .flat_map(|update| delivered_by(case, update))
            .collect()
    }

    /// Whether any update of this session reported itself sampled.
    fn sampled_any(&self, case: &str) -> bool {
        self.updates.iter().any(|update| sampled(case, update))
    }
}

/// The triples one update delivered, in order.
pub(crate) fn delivered_by(case: &str, update: &Value) -> Vec<(String, String, String)> {
    update["sessionResults"]
        .as_array()
        .unwrap_or_else(|| panic!("case {case:?}: an update carries sessionResults, got {update}"))
        .iter()
        .map(|event| {
            let member = |key: &str| {
                event[key]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("case {case:?}: a delivered event carries {key}, got {event}")
                    })
                    .to_string()
            };
            (
                member("message"),
                member("logStreamName"),
                member("logGroupIdentifier"),
            )
        })
        .collect()
}

/// Whether one update reports itself sampled.
fn sampled(case: &str, update: &Value) -> bool {
    update["sessionMetadata"]["sampled"]
        .as_bool()
        .unwrap_or_else(|| panic!("case {case:?}: an update reports sampled, got {update}"))
}

/// How many Live Tail sessions the store holds as OPEN.
fn open_sessions(logs: &Logs) -> usize {
    let state = logs
        .engine()
        .state::<ComAmazonawsCloudwatchlogsLogs20140328State>();
    let store = state.lock();
    store.live_tail_sessions.len()
}

/// Wait until the store holds `open` open sessions — which is what says a session has
/// SUBSCRIBED, since only what is ingested after that reaches it.
///
/// Waits for the CONDITION rather than for a span of the clock: it looks again until the
/// count is reached or [`CONDITION_DEADLINE`] passes.
async fn await_open_sessions(case: &str, logs: &Logs, open: usize) {
    let give_up_at = Instant::now() + CONDITION_DEADLINE;
    loop {
        let registered = open_sessions(logs);
        if registered >= open {
            return;
        }
        assert!(
            Instant::now() < give_up_at,
            "case {case:?}: expected {open} open Live Tail session(s), got {registered}"
        );
        tokio::time::sleep(CONDITION_POLL).await;
    }
}

/// Wait until no session is open any more, which is what says every handle was given back.
async fn await_no_open_session(case: &str, logs: &Logs) {
    let give_up_at = Instant::now() + CONDITION_DEADLINE;
    loop {
        let registered = open_sessions(logs);
        if registered == 0 {
            return;
        }
        assert!(
            Instant::now() < give_up_at,
            "case {case:?}: expected every session to be given back, got {registered} open"
        );
        tokio::time::sleep(CONDITION_POLL).await;
    }
}

/// Start a session that must be served, run `while_open` once it has subscribed, and answer
/// its frames after asserting the whole wire shape around them.
async fn tail<F, Fut>(case: &str, logs: &Arc<Logs>, request: &Value, while_open: F) -> Session
where
    F: FnOnce(Arc<Logs>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let serving = {
        let logs = Arc::clone(logs);
        let request = request.clone();
        tokio::spawn(async move { logs.call_raw("StartLiveTail", &request).await })
    };
    // Only the events ingested while the session is open are delivered, so the writes wait
    // for it to be open.
    await_open_sessions(case, logs, 1).await;
    while_open(Arc::clone(logs)).await;

    let (status, headers, body) = serving
        .await
        .unwrap_or_else(|error| panic!("case {case:?}: the session task panicked: {error}"));
    assert_eq!(
        status,
        200,
        "case {case:?}: expected HTTP 200 from StartLiveTail, got {status} with {:?}",
        String::from_utf8_lossy(&body)
    );
    let media_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    assert_eq!(
        media_type, EVENT_STREAM,
        "case {case:?}: expected an event-stream body, got {media_type:?}"
    );
    let frames = decode_frames(case, &body);
    let types: Vec<&str> = frames
        .iter()
        .map(|frame| frame.event_type.as_str())
        .collect();
    let expected_types: Vec<&str> = std::iter::once(INITIAL_RESPONSE)
        .chain(std::iter::once("sessionStart"))
        .chain(std::iter::repeat_n("sessionUpdate", types.len().saturating_sub(2)))
        .collect();
    assert_eq!(
        types, expected_types,
        "case {case:?}: a session opens with the frame the output shape arrives in, then \
         sends one sessionStart and its updates, got {types:?}"
    );
    let updates = types.len().saturating_sub(2);
    assert!(
        (1..=MAX_BUFFERED_UPDATES).contains(&updates),
        "case {case:?}: a session sends one update per second, up to the \
         {MAX_BUFFERED_UPDATES} its buffer holds, got {updates}"
    );
    let mut frames = frames.into_iter();
    let initial = frames
        .next()
        .unwrap_or_else(|| panic!("case {case:?}: the session sent no initial response"))
        .payload;
    assert_eq!(
        initial,
        json!({}),
        "case {case:?}: StartLiveTailResponse's only member is the stream, so the initial \
         response carries none, got {initial}"
    );
    let start = frames
        .next()
        .unwrap_or_else(|| panic!("case {case:?}: the session sent no sessionStart"))
        .payload;
    Session {
        start,
        updates: frames.map(|frame| frame.payload).collect(),
    }
}

/// One row of the selection table.
struct Row {
    /// What the row varies, named in every assertion it makes.
    case: &'static str,
    /// Which stored groups the session names, by index into [`GROUPS`].
    groups: &'static [usize],
    /// Whether the row names its groups by ARN rather than by name.
    by_arn: bool,
    stream_names: Option<&'static [&'static str]>,
    stream_prefixes: Option<&'static [&'static str]>,
    filter_pattern: Option<&'static str>,
    /// The offsets of the ingested events the row must be delivered.
    delivered: &'static [i64],
}

/// The groups a row's indexes address.
const GROUPS: [&str; 2] = [GROUP_A, GROUP_B];

/// The selection table.
static ROWS: [Row; 10] = [
    Row {
        case: "one group by name and no selector, so every event it ingests",
        groups: &[0],
        by_arn: false,
        stream_names: None,
        stream_prefixes: None,
        filter_pattern: None,
        delivered: &[0, 10, 20, 40],
    },
    Row {
        case: "one group by ARN, which names the same group",
        groups: &[0],
        by_arn: true,
        stream_names: None,
        stream_prefixes: None,
        filter_pattern: None,
        delivered: &[0, 10, 20, 40],
    },
    Row {
        case: "two groups, both of whose events the session carries",
        groups: &[0, 1],
        by_arn: false,
        stream_names: None,
        stream_prefixes: None,
        filter_pattern: None,
        delivered: &[0, 10, 20, 30, 40],
    },
    Row {
        case: "two groups by ARN",
        groups: &[0, 1],
        by_arn: true,
        stream_names: None,
        stream_prefixes: None,
        filter_pattern: None,
        delivered: &[0, 10, 20, 30, 40],
    },
    Row {
        case: "the log streams named, which is one of the group's two",
        groups: &[0],
        by_arn: false,
        stream_names: Some(&[APP_ONE]),
        stream_prefixes: None,
        filter_pattern: None,
        delivered: &[0, 20],
    },
    Row {
        case: "a log stream prefix both the group's streams carry",
        groups: &[0],
        by_arn: false,
        stream_names: None,
        stream_prefixes: Some(&["app-"]),
        filter_pattern: None,
        delivered: &[0, 10, 20, 40],
    },
    Row {
        case: "a log stream prefix no stream carries",
        groups: &[0],
        by_arn: false,
        stream_names: None,
        stream_prefixes: Some(&["nothing-"]),
        filter_pattern: None,
        delivered: &[],
    },
    Row {
        case: "an unstructured term carried by three of the five events",
        groups: &[0, 1],
        by_arn: false,
        stream_names: None,
        stream_prefixes: None,
        filter_pattern: Some("ERROR"),
        delivered: &[0, 30, 40],
    },
    Row {
        case: "a JSON condition selecting one event",
        groups: &[0, 1],
        by_arn: false,
        stream_names: None,
        stream_prefixes: None,
        filter_pattern: Some("{$.level = \"WARN\"}"),
        delivered: &[10],
    },
    Row {
        case: "a space-delimited pattern on the first field",
        groups: &[0, 1],
        by_arn: false,
        stream_names: None,
        stream_prefixes: None,
        filter_pattern: Some("[level = ERROR, ...]"),
        delivered: &[0, 30, 40],
    },
];

/// A session delivers exactly the events its selection admits of what the groups ingested
/// while it was open, each naming the stream it was ingested into and the identifier its
/// group was named by — and its `sessionStart` echoes the selection it was started with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_delivers_the_events_its_selection_admits() {
    // Each row tails its OWN emulator, so every row's session runs at the same time: a
    // session stays open for the seconds its buffer holds updates for, which running the
    // table one row at a time would wait out once per row.
    let mut running = Vec::new();
    for row in &ROWS {
        running.push(tokio::spawn(check_selection(row)));
    }
    for row in running {
        row.await.expect("a selection row's task did not panic");
    }
}

/// One row of [`ROWS`]: open the session, ingest [`STORED`] while it is open, and assert
/// what it delivered.
async fn check_selection(row: &'static Row) {
    let logs = Arc::new(Logs::new());
    let at = base_ms();
    given_groups_and_streams(&logs).await;

    // The ARN form of each group, read back off the group itself rather than built here,
    // so a row that names a group by ARN names the same group the name form does.
    let mut arns = Vec::new();
    for group in GROUPS {
        let (_wildcard, log_group_arn) = logs.group_arns(group).await;
        arns.push(log_group_arn);
    }
    let identifiers: Vec<String> = row
        .groups
        .iter()
        .map(|index| {
            if row.by_arn {
                arns[*index].clone()
            } else {
                GROUPS[*index].to_string()
            }
        })
        .collect();
    let mut request = json!({"logGroupIdentifiers": identifiers});
    if let Some(names) = row.stream_names {
        request["logStreamNames"] = json!(names);
    }
    if let Some(prefixes) = row.stream_prefixes {
        request["logStreamNamePrefixes"] = json!(prefixes);
    }
    if let Some(pattern) = row.filter_pattern {
        request["logEventFilterPattern"] = json!(pattern);
    }

    let session = tail(row.case, &logs, &request, move |logs| async move {
        ingest_stored_events(&logs, at).await;
    })
    .await;

    // The session names itself and echoes the selection: "A single LiveTailSessionStart
    // object is sent at the start of the session."
    let start = &session.start;
    assert_eq!(
        start["logGroupIdentifiers"],
        json!(identifiers),
        "case {:?}: sessionStart echoes the log groups the session tails, got {start}",
        row.case
    );
    assert_eq!(
        start["logStreamNames"],
        row.stream_names.map_or(Value::Null, |names| json!(names)),
        "case {:?}: sessionStart echoes logStreamNames, got {start}",
        row.case
    );
    assert_eq!(
        start["logStreamNamePrefixes"],
        row.stream_prefixes
            .map_or(Value::Null, |prefixes| json!(prefixes)),
        "case {:?}: sessionStart echoes logStreamNamePrefixes, got {start}",
        row.case
    );
    assert_eq!(
        start["logEventFilterPattern"],
        row.filter_pattern
            .map_or(Value::Null, |pattern| json!(pattern)),
        "case {:?}: sessionStart echoes logEventFilterPattern, got {start}",
        row.case
    );
    for member in ["requestId", "sessionId"] {
        let value = start[member].as_str().unwrap_or_else(|| {
            panic!(
                "case {:?}: sessionStart names the session's {member}, got {start}",
                row.case
            )
        });
        assert!(
            !value.is_empty(),
            "case {:?}: the session's {member} is not empty, got {value:?}",
            row.case
        );
    }

    // The order is the order the groups ingested the events in, which is the order the
    // session was handed them: one batch per stream, in `INGESTED_THROUGH` order.
    let expected: Vec<(String, String, String)> = INGESTED_THROUGH
        .iter()
        .flat_map(|(group, stream)| {
            STORED
                .iter()
                .filter(move |stored| stored.group == *group && stored.stream == *stream)
                .filter(|stored| row.delivered.contains(&stored.offset))
        })
        .map(|stored| {
            let index = GROUPS
                .iter()
                .position(|group| *group == stored.group)
                .unwrap_or_else(|| panic!("case {:?}: {} is a row group", row.case, stored.group));
            let identifier = if row.by_arn {
                arns[index].clone()
            } else {
                stored.group.to_string()
            };
            (
                stored.message.to_string(),
                stored.stream.to_string(),
                identifier,
            )
        })
        .collect();
    let actual = session.delivered(row.case);
    assert_eq!(
        actual, expected,
        "case {:?}: expected the session to deliver {expected:?}, got {actual:?}",
        row.case
    );
    assert!(
        !session.sampled_any(row.case),
        "case {:?}: {} events is under the update's ceiling, so no update is sampled",
        row.case,
        expected.len()
    );
}

/// A session carries only what was ingested while it was open: "A Live Tail session returns
/// a stream of log events that have been recently ingested in the log groups", so the events
/// a group already held are not delivered — and they are still there for a later reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_delivers_nothing_a_group_held_before_it_opened() {
    let case = "events written before the session opened";
    let logs = Arc::new(Logs::new());
    let at = base_ms();
    given_groups_and_streams(&logs).await;
    // Rows: one batch written BEFORE the session opens, one WHILE it is open.
    let before = ["BEFORE one", "BEFORE two"];
    let during = ["DURING one", "DURING two"];
    let written = |messages: &[&str], from: i64| -> Vec<(i64, String)> {
        messages
            .iter()
            .enumerate()
            .map(|(index, message)| {
                (
                    at + from + i64::try_from(index).unwrap_or_default(),
                    (*message).to_string(),
                )
            })
            .collect()
    };
    let earlier = written(&before, 0);
    let later = written(&during, 100);
    let put = |logs: Arc<Logs>, events: Vec<(i64, String)>| async move {
        let pairs: Vec<(i64, &str)> = events
            .iter()
            .map(|(timestamp, message)| (*timestamp, message.as_str()))
            .collect();
        logs.ok(
            "PutLogEvents",
            &json!({
                "logGroupName": GROUP_A,
                "logStreamName": APP_ONE,
                "logEvents": batch(&pairs),
            }),
        )
        .await;
    };
    put(Arc::clone(&logs), earlier.clone()).await;

    let session = tail(
        case,
        &logs,
        &json!({"logGroupIdentifiers": [GROUP_A]}),
        {
            let later = later.clone();
            move |logs| async move { put(logs, later).await }
        },
    )
    .await;

    let delivered: Vec<String> = session
        .delivered(case)
        .into_iter()
        .map(|(message, _, _)| message)
        .collect();
    let expected: Vec<String> = during.iter().map(|message| (*message).to_string()).collect();
    assert_eq!(
        delivered, expected,
        "case {case:?}: expected only the events ingested while the session was open, got \
         {delivered:?}"
    );

    // The session consumed nothing: both batches are still readable.
    let page = logs
        .ok(
            "GetLogEvents",
            &json!({"logGroupName": GROUP_A, "logStreamName": APP_ONE}),
        )
        .await;
    let stored = messages(&page);
    let all: Vec<String> = earlier
        .iter()
        .chain(later.iter())
        .map(|(_, message)| message.clone())
        .collect();
    assert_eq!(
        stored, all,
        "case {case:?}: a session changes no event a later reader sees, got {stored:?}"
    );
    await_no_open_session(case, &logs).await;
}

/// Two sessions open at once on one store each get what its OWN selection admits of the
/// same ingestion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_open_sessions_each_get_what_their_own_selection_admits() {
    let case = "two sessions over one ingestion";
    let logs = Arc::new(Logs::new());
    let at = base_ms();
    given_groups_and_streams(&logs).await;

    // One session narrowed to a single stream, one narrowed by a filter pattern over both
    // groups: the same events reach both and each keeps only its own.
    let named = json!({"logGroupIdentifiers": [GROUP_A], "logStreamNames": [APP_ONE]});
    let filtered = json!({"logGroupIdentifiers": [GROUP_A, GROUP_B], "logEventFilterPattern": "ERROR"});
    let first = {
        let logs = Arc::clone(&logs);
        tokio::spawn(async move { logs.call_raw("StartLiveTail", &named).await })
    };
    let second = {
        let logs = Arc::clone(&logs);
        tokio::spawn(async move { logs.call_raw("StartLiveTail", &filtered).await })
    };
    await_open_sessions(case, &logs, 2).await;
    ingest_stored_events(&logs, at).await;

    let mut delivered = Vec::new();
    for (label, serving) in [("named streams", first), ("filtered", second)] {
        let (status, _headers, body) = serving
            .await
            .unwrap_or_else(|error| panic!("case {case:?}: the {label} session panicked: {error}"));
        assert_eq!(
            status, 200,
            "case {case:?}: the {label} session is served, got {status}"
        );
        let messages: Vec<String> = decode_frames(case, &body)
            .iter()
            .filter(|frame| frame.event_type == "sessionUpdate")
            .flat_map(|frame| delivered_by(case, &frame.payload))
            .map(|(message, _, _)| message)
            .collect();
        delivered.push((label, messages));
    }

    let expected = [
        // `APP_ONE`'s two events, in the order they were ingested.
        ("named streams", vec!["ERROR disk full", "INFO disk fine"]),
        // Every event carrying the term, across both groups.
        (
            "filtered",
            vec![
                "ERROR disk full",
                "ERROR 404 while handling orders",
                "ERROR kernel panic",
            ],
        ),
    ];
    for (label, expected) in expected {
        let actual = delivered
            .iter()
            .find(|(delivered_label, _)| *delivered_label == label)
            .map(|(_, messages)| messages.clone())
            .unwrap_or_default();
        assert_eq!(
            actual, expected,
            "case {case:?}: the {label} session delivers its own selection, got {actual:?}"
        );
    }
    await_no_open_session(case, &logs).await;
}

/// An update carries at most the 500 events the model allows it: past that it delivers the
/// most recent events that fit and reports itself sampled, and within it delivers every
/// matching event and reports itself unsampled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_is_bounded_by_the_events_one_update_may_carry() {
    // Rows: how many events one batch ingests while the session is open, against the
    // update's documented event ceiling (under it, at it, past it). One batch, so every
    // event of a row is ingested in the same instant and lands in the same update.
    let rows: [(&str, usize, usize); 3] = [
        ("one event under the event ceiling", MAX_EVENTS_PER_UPDATE - 1, MAX_EVENTS_PER_UPDATE - 1),
        ("exactly the event ceiling", MAX_EVENTS_PER_UPDATE, MAX_EVENTS_PER_UPDATE),
        ("seven events past the event ceiling", MAX_EVENTS_PER_UPDATE + 7, MAX_EVENTS_PER_UPDATE),
    ];
    let mut running = Vec::new();
    for (case, ingested, delivered) in rows {
        running.push(tokio::spawn(check_event_ceiling(case, ingested, delivered)));
    }
    for row in running {
        row.await.expect("a sampling row's task did not panic");
    }
}

/// One row of the event-ceiling table.
async fn check_event_ceiling(case: &'static str, ingested: usize, expected: usize) {
    let logs = Arc::new(Logs::new());
    let at = base_ms();
    let group = format!("/aws/emulator/live-tail-{ingested}");
    logs.ok("CreateLogGroup", &json!({"logGroupName": group}))
        .await;
    logs.ok(
        "CreateLogStream",
        &json!({"logGroupName": group, "logStreamName": APP_ONE}),
    )
    .await;
    // Each message is distinct, so which events the update carried is visible.
    let written: Vec<String> = (0..ingested)
        .map(|index| format!("event {index}"))
        .collect();
    let request = json!({"logGroupIdentifiers": [group.clone()]});
    let session = tail(case, &logs, &request, {
        let group = group.clone();
        let written = written.clone();
        move |logs| async move {
            let events: Vec<(i64, &str)> = written
                .iter()
                .enumerate()
                .map(|(index, message)| {
                    (at + i64::try_from(index).unwrap_or_default(), message.as_str())
                })
                .collect();
            logs.ok(
                "PutLogEvents",
                &json!({
                    "logGroupName": group,
                    "logStreamName": APP_ONE,
                    "logEvents": batch(&events),
                }),
            )
            .await;
        }
    })
    .await;

    let delivered: Vec<String> = session
        .delivered(case)
        .into_iter()
        .map(|(message, _, _)| message)
        .collect();
    assert_eq!(
        delivered.len(),
        expected,
        "case {case:?}: expected {expected} delivered events, got {}",
        delivered.len()
    );
    // The sample is the most recent events, which is what a tail is watching.
    let newest: Vec<String> = written.iter().skip(ingested - expected).cloned().collect();
    assert_eq!(
        delivered, newest,
        "case {case:?}: expected the most recent {expected} events, got {} of them",
        delivered.len()
    );
    assert_eq!(
        session.sampled_any(case),
        ingested > expected,
        "case {case:?}: an update reports itself sampled exactly when it left a matching \
         event out"
    );
}

/// A session is also bounded by the BYTES of messages it holds between two updates (an
/// emulator bound): the newest events are the ones it keeps, an update that left one out
/// says so, and one event larger than the whole bound is still delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_is_bounded_by_the_bytes_it_buffers() {
    let case = "three events whose messages do not fit one buffer";
    let logs = Arc::new(Logs::new());
    let at = base_ms();
    let group = "/aws/emulator/live-tail-bytes";
    logs.ok("CreateLogGroup", &json!({"logGroupName": group}))
        .await;
    logs.ok(
        "CreateLogStream",
        &json!({"logGroupName": group, "logStreamName": APP_ONE}),
    )
    .await;
    // Three messages of which two fit the buffer's byte bound: each needs its own batch,
    // since the bound is larger than one `PutLogEvents` may carry.
    let message_bytes = MAX_BUFFERED_BYTES / 2 + 1;
    let written: Vec<String> = (0..3)
        .map(|index| {
            let label = format!("event {index} ");
            format!(
                "{label}{}",
                "x".repeat(message_bytes.saturating_sub(label.len()))
            )
        })
        .collect();
    let session = tail(case, &logs, &json!({"logGroupIdentifiers": [group]}), {
        let written = written.clone();
        move |logs| async move {
            for (index, message) in written.iter().enumerate() {
                logs.ok(
                    "PutLogEvents",
                    &json!({
                        "logGroupName": group,
                        "logStreamName": APP_ONE,
                        "logEvents": batch(&[(
                            at + i64::try_from(index).unwrap_or_default(),
                            message.as_str(),
                        )]),
                    }),
                )
                .await;
            }
        }
    })
    .await;

    let delivered: Vec<String> = session
        .delivered(case)
        .into_iter()
        .map(|(message, _, _)| message)
        .collect();
    // No update carries more than the buffer's bytes, unless it carries a single event:
    // the newest event is always delivered, whatever its size.
    for (index, update) in session.updates.iter().enumerate() {
        let carried = delivered_by(case, update);
        let bytes: usize = carried.iter().map(|(message, _, _)| message.len()).sum();
        assert!(
            carried.len() <= 1 || bytes <= MAX_BUFFERED_BYTES,
            "case {case:?}: update {index} carries {} events of {bytes} bytes, past the \
             {MAX_BUFFERED_BYTES} one buffer holds",
            carried.len()
        );
    }
    assert_eq!(
        delivered.last(),
        written.last(),
        "case {case:?}: the newest event is always delivered, got {:?}",
        delivered.last()
    );
    assert!(
        delivered.len() == written.len() || session.sampled_any(case),
        "case {case:?}: {} of {} events were delivered, so an update reports itself sampled",
        delivered.len(),
        written.len()
    );
    // Whatever the buffer dropped, the log group still holds every event.
    let page = logs
        .ok(
            "GetLogEvents",
            &json!({"logGroupName": group, "logStreamName": APP_ONE}),
        )
        .await;
    assert_eq!(
        messages(&page),
        written,
        "case {case:?}: a session changes no event a later reader sees"
    );
}

/// One refusal row: the request that is refused, and the error code and message it is
/// refused with.
struct Refusal {
    case: &'static str,
    /// The request body, built against the stored groups.
    request: fn(&str) -> Value,
    code: &'static str,
    message: &'static str,
}

/// The refusal table. Every modelled error of this operation is a client error at HTTP
/// 400, which [`Logs::refusal`] asserts for each row.
const REFUSALS: [Refusal; 11] = [
    Refusal {
        case: "a log group name the account does not hold",
        request: |_| json!({"logGroupIdentifiers": ["/aws/emulator/never-created"]}),
        code: "ResourceNotFoundException",
        message: "Provided LogGroup doesn't exist.",
    },
    Refusal {
        case: "a log group ARN the account does not hold",
        request: |_| json!({
            "logGroupIdentifiers": [
                "arn:aws:logs:eu-west-2:000000000000:log-group:/aws/emulator/never-created"
            ]
        }),
        code: "ResourceNotFoundException",
        message: "Provided LogGroup doesn't exist.",
    },
    Refusal {
        case: "one unknown log group among two the account holds",
        request: |deleted| {
            json!({"logGroupIdentifiers": [GROUP_A, deleted, GROUP_B]})
        },
        code: "ResourceNotFoundException",
        message: "Provided LogGroup doesn't exist.",
    },
    Refusal {
        case: "a log group that was deleted after it was created",
        request: |deleted| json!({"logGroupIdentifiers": [deleted]}),
        code: "ResourceNotFoundException",
        message: "Provided LogGroup doesn't exist.",
    },
    Refusal {
        case: "both log stream selectors at once",
        request: |_| json!({
            "logGroupIdentifiers": [GROUP_A],
            "logStreamNames": [APP_ONE],
            "logStreamNamePrefixes": ["app-"],
        }),
        code: "InvalidParameterException",
        message: "LogStreamNames provided with LogStreamPrefixes. LogStreamPrefixes is \
                  disabled if log stream names is provided.",
    },
    Refusal {
        case: "named log streams across two log groups",
        request: |_| json!({
            "logGroupIdentifiers": [GROUP_A, GROUP_B],
            "logStreamNames": [APP_ONE],
        }),
        code: "InvalidParameterException",
        message: "LogStreamNames provided with more than one LogGroupIdentifier. \
                  LogStreamNames is disabled if more than one LogGroupIdentifier is provided.",
    },
    Refusal {
        case: "log stream prefixes across two log groups",
        request: |_| json!({
            "logGroupIdentifiers": [GROUP_A, GROUP_B],
            "logStreamNamePrefixes": ["app-"],
        }),
        code: "InvalidParameterException",
        message: "LogStreamPrefixes provided with more than one LogGroupIdentifier. \
                  LogStreamPrefixes is disabled if more than one LogGroupIdentifier is \
                  provided.",
    },
    Refusal {
        case: "no logGroupIdentifiers at all, which the model requires",
        request: |_| json!({}),
        code: "InvalidParameterException",
        message: "1 validation error detected: Value at 'logGroupIdentifiers' failed to satisfy \
                  constraint: Member must not be null",
    },
    Refusal {
        case: "an empty logGroupIdentifiers, which is under the modelled minimum of 1",
        request: |_| json!({"logGroupIdentifiers": []}),
        code: "InvalidParameterException",
        message: "1 validation error detected: Value at 'logGroupIdentifiers' failed to satisfy \
                  constraint: Member must have length greater than or equal to 1",
    },
    Refusal {
        case: "an asterisk-suffixed log group ARN, which the identifier pattern excludes",
        request: |_| json!({
            "logGroupIdentifiers": [
                "arn:aws:logs:eu-west-2:000000000000:log-group:/aws/emulator/live-tail-a:*"
            ]
        }),
        code: "InvalidParameterException",
        message: "1 validation error detected: Value at 'logGroupIdentifiers.1.member' failed to \
                  satisfy constraint: Member must satisfy regular expression pattern: \
                  [\\w#+=/:,.@-]*",
    },
    Refusal {
        case: "a filter pattern that opens a bracketed form it does not close",
        request: |_| json!({
            "logGroupIdentifiers": [GROUP_A],
            "logEventFilterPattern": "{$.level = \"WARN\"",
        }),
        code: "InvalidParameterException",
        message: "If a filter pattern starts with '{' it must end with '}'",
    },
];

/// The log group each refusal row that needs one names: created, then deleted, so a row
/// that must be refused for a group the account does not hold is refused for a group the
/// store once held rather than for a name no request ever created.
const DELETED_GROUP: &str = "/aws/emulator/live-tail-deleted";

/// Every refused session is refused with the modelled error the condition names, at the
/// HTTP 400 every modelled error of this operation carries — never with a 501, which an
/// SDK classifies as a retryable server fault. A refused request opens no session.
#[tokio::test]
async fn a_refused_session_answers_the_modelled_client_error() {
    let logs = Logs::new();
    given_groups_and_streams(&logs).await;
    logs.ok("CreateLogGroup", &json!({"logGroupName": DELETED_GROUP}))
        .await;
    logs.ok("DeleteLogGroup", &json!({"logGroupName": DELETED_GROUP}))
        .await;

    for row in &REFUSALS {
        let request = (row.request)(DELETED_GROUP);
        let (code, message) = logs.refusal("StartLiveTail", &request).await;
        assert_eq!(
            code, row.code,
            "case {:?}: expected {}, got {code} with {message:?}",
            row.case, row.code
        );
        assert_eq!(
            message, row.message,
            "case {:?}: expected the message {:?}, got {message:?}",
            row.case, row.message
        );
        assert_eq!(
            open_sessions(&logs),
            0,
            "case {:?}: a refused request leaves no session open",
            row.case
        );
    }
}
