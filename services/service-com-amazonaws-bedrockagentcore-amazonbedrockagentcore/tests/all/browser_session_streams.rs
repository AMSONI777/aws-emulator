// SPDX-License-Identifier: CC0-1.0

//! What a browser session's record-and-report path owes a client: its streams, its
//! effective time-to-live, and the termination a stop writes.
//!
//! THE RULES under test, each asserted over a SET of inputs rather than one:
//!
//! * A started session HAS streams, and every operation that reports a session reports
//!   the ones its start materialised: `automationStream` with a non-empty endpoint inside
//!   `BrowserStreamEndpoint`'s `@length 10..512` and a `streamStatus` from
//!   `AutomationStreamStatus`, plus a `liveViewStream` endpoint. A start and a read of the
//!   same session report the same streams, and a read never changes them.
//! * A session runs under the time-to-live its start asked for, and under the service's
//!   own default when the start asked for none — which is the value every read reports.
//! * A stop terminates the session: from then on a read reports `TERMINATED`, a replayed
//!   `clientToken` answers with the stop it already performed, and a second stop is a
//!   conflict because a stopped session cannot be restarted.
//! * `UpdateBrowserStream` moves the automation stream's status, and that status is what
//!   every later read reports; the endpoints stay the session's own.
//!
//! Every case drives real HTTP through the same `MultiServiceRouter` the emulator serves
//! with, so what is asserted is the wire behaviour a client sees.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;
use std::sync::Arc;

use aws_smithy_types::date_time::{DateTime, Format};
use service_com_amazonaws_bedrockagentcore_amazonbedrockagentcore as agentcore;
use service_com_amazonaws_bedrockagentcorecontrol_amazonbedrockagentcorecontrol as agentcorecontrol;

/// The browser tool the service itself provides, held by every account without anything
/// creating it (source: smithy_query query="shape" shape="BrowserId" on the control
/// plane's model, whose pattern reserves this id as its first alternative).
const SYSTEM_BROWSER: &str = "aws.browser.v1";

/// The `name` a case creates its own browser under. `CreateBrowser$name` is
/// `SandboxName`, pattern ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ (source: smithy_query
/// query="operation" operation="CreateBrowser" on the control plane's model).
const CUSTOM_BROWSER_NAME: &str = "stream_browser";

/// A `BrowserSessionId`-shaped identifier nothing ever started (pattern
/// ^[0-9a-zA-Z]{1,40}$).
const MISSING_SESSION: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";

/// `BrowserStreamEndpoint`'s published bounds, which both stream endpoints target
/// (source: smithy_query query="shape" shape="BrowserStreamEndpoint", length 10..512).
const ENDPOINT_MIN_LEN: usize = 10;
const ENDPOINT_MAX_LEN: usize = 512;

/// The values `AutomationStreamStatus` accepts (source: smithy_query query="shape"
/// shape="AutomationStreamStatus").
const ENABLED: &str = "ENABLED";
const DISABLED: &str = "DISABLED";

/// The time-to-live a session runs under when its start asks for none, and the `@default`
/// the request member declares — which the protocol binds for an absent member, so a
/// request naming it is the same request on the wire as one naming no timeout at all
/// (source: smithy_query query="operation" operation="StartBrowserSession").
const SERVICE_DEFAULT_TIMEOUT: i64 = 900;
const MODELLED_DEFAULT_TIMEOUT: i64 = 3_600;

/// The emulator, with request authentication off so a test signs nothing. The AgentCore
/// CONTROL plane is mounted beside this service because it owns the browsers a session
/// runs on.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(agentcore::EmulatedService::new(Arc::clone(&engine)));
    router.register_service(agentcorecontrol::EmulatedService::new(engine));
    router
}

/// Send one request and return its status and parsed JSON body (`Value::Null` for an
/// empty body). The SigV4 credential scope is what routes the request to this service.
async fn send(
    router: &MultiServiceRouter,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let payload = body.map_or_else(bytes::Bytes::new, |v| bytes::Bytes::from(v.to_string()));
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://bedrock-agentcore.us-east-1.amazonaws.com{path}"))
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/bedrock-agentcore/aws4_request, \
             SignedHeaders=host, Signature=0",
        )
        .header("content-type", "application/json")
        .body(payload)
        .expect("build the request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let parsed = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, parsed)
}

/// Create one custom browser through the control plane and return the `browserId` it
/// minted. `CreateBrowser` is `PUT /browsers`, answering 202 (source: smithy_query
/// query="operation" operation="CreateBrowser" on the control plane's model).
async fn create_browser(router: &MultiServiceRouter, name: &str) -> String {
    let (status, created) = send(
        router,
        "PUT",
        "/browsers",
        Some(json!({"name": name, "networkConfiguration": {"networkMode": "PUBLIC"}})),
    )
    .await;
    assert_eq!(
        status, 202,
        "the fixture browser must be created, got {status} with {created:?}"
    );
    created["browserId"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// `StartBrowserSession`: `PUT /browsers/{browserIdentifier}/sessions/start`.
async fn start_session(router: &MultiServiceRouter, browser: &str, body: Value) -> (u16, Value) {
    send(
        router,
        "PUT",
        &format!("/browsers/{browser}/sessions/start"),
        Some(body),
    )
    .await
}

/// `GetBrowserSession`: `GET /browsers/{browserIdentifier}/sessions/get?sessionId=…`.
async fn get_session(router: &MultiServiceRouter, browser: &str, session_id: &str) -> (u16, Value) {
    send(
        router,
        "GET",
        &format!("/browsers/{browser}/sessions/get?sessionId={session_id}"),
        None,
    )
    .await
}

/// `StopBrowserSession`: `PUT /browsers/{browserIdentifier}/sessions/stop?sessionId=…`.
async fn stop_session(
    router: &MultiServiceRouter,
    browser: &str,
    session_id: &str,
    body: Value,
) -> (u16, Value) {
    send(
        router,
        "PUT",
        &format!("/browsers/{browser}/sessions/stop?sessionId={session_id}"),
        Some(body),
    )
    .await
}

/// `UpdateBrowserStream`: `PUT /browsers/{browserIdentifier}/sessions/streams/update?sessionId=…`.
async fn update_stream(
    router: &MultiServiceRouter,
    browser: &str,
    session_id: &str,
    body: Value,
) -> (u16, Value) {
    send(
        router,
        "PUT",
        &format!("/browsers/{browser}/sessions/streams/update?sessionId={session_id}"),
        Some(body),
    )
    .await
}

fn member<'a>(body: &'a Value, name: &str) -> &'a Value {
    body.get(name).unwrap_or(&Value::Null)
}

fn text<'a>(body: &'a Value, name: &str) -> &'a str {
    member(body, name).as_str().unwrap_or("")
}

fn error_code(body: &Value) -> &str {
    body.get("__type").and_then(Value::as_str).unwrap_or("")
}

fn message(body: &Value) -> &str {
    body.get("message").and_then(Value::as_str).unwrap_or("")
}

/// The automation stream's endpoint and status, and the live view stream's endpoint, from
/// a response that carries `streams`.
fn automation_endpoint(body: &Value) -> &str {
    body.pointer("/streams/automationStream/streamEndpoint")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn automation_status(body: &Value) -> &str {
    body.pointer("/streams/automationStream/streamStatus")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn live_view_endpoint(body: &Value) -> &str {
    body.pointer("/streams/liveViewStream/streamEndpoint")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// A `DateTimestamp` member carries `@timestampFormat("date-time")`, so on this service's
/// restJson1 wire it is an RFC 3339 string (source: smithy_query query="shape"
/// shape="DateTimestamp").
fn date_time(case: &str, member_name: &str, body: &Value) -> DateTime {
    let value = member(body, member_name);
    let rendered = value.as_str().unwrap_or_else(|| {
        panic!("case {case:?}: expected {member_name} as a date-time string, got {value:?}")
    });
    DateTime::from_str(rendered, Format::DateTime).unwrap_or_else(|error| {
        panic!("case {case:?}: expected {member_name} in RFC 3339, got {rendered:?} ({error})")
    })
}

/// Both endpoints of one session name that session and sit inside the published length
/// bounds, and the automation stream carries `expected_status`.
fn assert_streams(case: &str, body: &Value, session_id: &str, expected_status: &str) {
    for (stream, endpoint) in [
        ("automationStream", automation_endpoint(body)),
        ("liveViewStream", live_view_endpoint(body)),
    ] {
        assert!(
            (ENDPOINT_MIN_LEN..=ENDPOINT_MAX_LEN).contains(&endpoint.len()),
            "case {case:?}: expected {stream} endpoint within {ENDPOINT_MIN_LEN}..{ENDPOINT_MAX_LEN} characters, got {endpoint:?}"
        );
        assert!(
            endpoint.contains(session_id),
            "case {case:?}: expected {stream} endpoint to address session {session_id}, got {endpoint:?}"
        );
    }
    assert_ne!(
        automation_endpoint(body),
        live_view_endpoint(body),
        "case {case:?}: expected the two streams to be addressed apart, got {body:?}"
    );
    assert_eq!(
        automation_status(body),
        expected_status,
        "case {case:?}: expected automation streamStatus {expected_status}, got {body:?}"
    );
}

/// A start materialises the session's streams, and a read reports the SAME ones — for
/// rows that differ along the browser the session runs on, which optional members the
/// start carried, and the time-to-live it asked for.
#[tokio::test]
async fn a_started_session_reports_streams_a_read_reports_identically() {
    let router = emulator();
    let custom = create_browser(&router, CUSTOM_BROWSER_NAME).await;

    let cases: Vec<(&str, String, Value)> = vec![
        (
            "system-browser-with-no-optional-members",
            SYSTEM_BROWSER.to_string(),
            json!({}),
        ),
        (
            "system-browser-named-with-a-viewport",
            SYSTEM_BROWSER.to_string(),
            json!({"name": "shopping", "sessionTimeoutSeconds": 60, "viewPort": {"width": 1_280, "height": 720}}),
        ),
        (
            "custom-browser-at-the-lowest-timeout",
            custom.clone(),
            json!({"sessionTimeoutSeconds": 1}),
        ),
        (
            "custom-browser-at-the-highest-timeout-with-a-profile",
            custom.clone(),
            json!({
                "sessionTimeoutSeconds": 28_800,
                "name": "n".repeat(100),
                // `BrowserProfileId`'s pattern is ^[a-zA-Z][a-zA-Z0-9_]{0,47}-[a-zA-Z0-9]{10}$
                // (source: smithy_query query="shape" shape="BrowserProfileConfiguration").
                "profileConfiguration": {"profileIdentifier": "shopping_profile-0a1b2c3d4e"},
            }),
        ),
    ];

    for (case, browser, body) in cases {
        let (status, started) = start_session(&router, &browser, body).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from StartBrowserSession, got {status} with {started:?}"
        );
        let session_id = text(&started, "sessionId").to_string();
        assert_streams(case, &started, &session_id, ENABLED);
        assert!(
            automation_endpoint(&started).contains(&browser),
            "case {case:?}: expected the automation endpoint to address browser {browser}, got {started:?}"
        );

        // The read reports the streams the start materialised, member for member, and
        // reading twice reports them again: a read changes nothing.
        for round in ["first-read", "second-read"] {
            let (status, read) = get_session(&router, &browser, &session_id).await;
            assert_eq!(
                status, 200,
                "case {case:?}/{round}: expected HTTP 200 from GetBrowserSession, got {status} with {read:?}"
            );
            assert_eq!(
                member(&read, "streams"),
                member(&started, "streams"),
                "case {case:?}/{round}: expected the streams the start reported, got {read:?}"
            );
            assert_streams(case, &read, &session_id, ENABLED);
        }
    }
}

/// The time-to-live a read reports is the one the session RUNS under: the requested
/// value, or the service's own default when the start requested none. The row naming the
/// request member's `@default` is the same request on the wire as the row naming nothing,
/// because the protocol binds that default server-side for an absent member.
#[tokio::test]
async fn a_read_reports_the_timeout_the_session_runs_under() {
    let router = emulator();
    let custom = create_browser(&router, CUSTOM_BROWSER_NAME).await;

    // `BrowserSessionTimeout` is range 1..28800 (source: smithy_query query="operation"
    // operation="StartBrowserSession"): both published bounds, the documented recommended
    // minimum, the service default itself, and one value in between.
    let cases: Vec<(&str, String, Value, i64)> = vec![
        (
            "no-timeout-requested",
            SYSTEM_BROWSER.to_string(),
            json!({}),
            SERVICE_DEFAULT_TIMEOUT,
        ),
        (
            "no-timeout-requested-on-a-custom-browser",
            custom.clone(),
            json!({"name": "unbounded"}),
            SERVICE_DEFAULT_TIMEOUT,
        ),
        (
            "the-request-members-schema-default-is-no-request-at-all",
            SYSTEM_BROWSER.to_string(),
            json!({"sessionTimeoutSeconds": MODELLED_DEFAULT_TIMEOUT}),
            SERVICE_DEFAULT_TIMEOUT,
        ),
        (
            "lowest-timeout-in-range",
            SYSTEM_BROWSER.to_string(),
            json!({"sessionTimeoutSeconds": 1}),
            1,
        ),
        (
            "recommended-minimum-timeout",
            custom.clone(),
            json!({"sessionTimeoutSeconds": 60}),
            60,
        ),
        (
            "the-service-default-asked-for-explicitly",
            SYSTEM_BROWSER.to_string(),
            json!({"sessionTimeoutSeconds": SERVICE_DEFAULT_TIMEOUT}),
            SERVICE_DEFAULT_TIMEOUT,
        ),
        (
            "an-hour-and-a-half",
            custom.clone(),
            json!({"sessionTimeoutSeconds": 5_400}),
            5_400,
        ),
        (
            "highest-timeout-in-range",
            SYSTEM_BROWSER.to_string(),
            json!({"sessionTimeoutSeconds": 28_800}),
            28_800,
        ),
    ];

    for (case, browser, body, expected) in cases {
        let (status, started) = start_session(&router, &browser, body).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from StartBrowserSession, got {status} with {started:?}"
        );
        let session_id = text(&started, "sessionId").to_string();
        let (status, read) = get_session(&router, &browser, &session_id).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetBrowserSession, got {status} with {read:?}"
        );
        assert_eq!(
            member(&read, "sessionTimeoutSeconds").as_i64(),
            Some(expected),
            "case {case:?}: expected the session to run under {expected} seconds, got {read:?}"
        );
    }
}

/// A stop terminates the session it names: the read reports `TERMINATED` from then on, a
/// replayed `clientToken` answers with the stop it already performed, and a second stop
/// is refused because a stopped session cannot be restarted. Rows differ along the
/// browser and along whether the stop carries a token and how long that token is.
#[tokio::test]
async fn a_stop_terminates_the_session_every_later_read_reports() {
    let router = emulator();
    let custom = create_browser(&router, CUSTOM_BROWSER_NAME).await;

    // `ClientToken` is len 33..256 (source: smithy_query query="operation"
    // operation="StopBrowserSession"): no token, the shortest, and the longest.
    let cases: Vec<(&str, String, Option<String>)> = vec![
        ("system-browser-no-client-token", SYSTEM_BROWSER.to_string(), None),
        (
            "custom-browser-shortest-client-token",
            custom.clone(),
            Some("a".repeat(33)),
        ),
        (
            "system-browser-longest-client-token",
            SYSTEM_BROWSER.to_string(),
            Some("z".repeat(256)),
        ),
    ];

    for (case, browser, token) in cases {
        let (status, started) =
            start_session(&router, &browser, json!({"sessionTimeoutSeconds": 28_800})).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from StartBrowserSession, got {status} with {started:?}"
        );
        let session_id = text(&started, "sessionId").to_string();
        let created_at = date_time(case, "createdAt", &started);

        let (status, read) = get_session(&router, &browser, &session_id).await;
        assert_eq!(
            (status, text(&read, "status")),
            (200, "READY"),
            "case {case:?}: expected a started session to read back READY, got {status} with {read:?}"
        );

        let stop_body = token
            .as_ref()
            .map_or_else(|| json!({}), |value| json!({"clientToken": value}));
        let (status, stopped) =
            stop_session(&router, &browser, &session_id, stop_body.clone()).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from StopBrowserSession, got {status} with {stopped:?}"
        );
        assert_eq!(
            (text(&stopped, "browserIdentifier"), text(&stopped, "sessionId")),
            (browser.as_str(), session_id.as_str()),
            "case {case:?}: expected the stop to answer for the session it stopped, got {stopped:?}"
        );
        let stopped_at = date_time(case, "lastUpdatedAt", &stopped);
        assert!(
            stopped_at.secs() >= created_at.secs(),
            "case {case:?}: expected the stop's lastUpdatedAt at or after the session's createdAt, got {stopped:?} for {started:?}"
        );

        // The termination is what every later read reports, with the session's streams
        // still addressed as its start materialised them.
        let (status, read) = get_session(&router, &browser, &session_id).await;
        assert_eq!(
            (status, text(&read, "status")),
            (200, "TERMINATED"),
            "case {case:?}: expected a stopped session to read back TERMINATED, got {status} with {read:?}"
        );
        assert_eq!(
            member(&read, "streams"),
            member(&started, "streams"),
            "case {case:?}: expected a stopped session to keep the streams it was started with, got {read:?}"
        );
        assert_eq!(
            member(&read, "lastUpdatedAt"),
            member(&stopped, "lastUpdatedAt"),
            "case {case:?}: expected the read to report the instant of the stop, got {read:?}"
        );

        // A replayed token answers with the stop it already performed; a stop that
        // carries no such token conflicts with the termination instead.
        let (status, again) = stop_session(&router, &browser, &session_id, stop_body).await;
        if token.is_some() {
            assert_eq!(
                (status, member(&again, "lastUpdatedAt")),
                (200, member(&stopped, "lastUpdatedAt")),
                "case {case:?}: expected the replayed token to answer with the stop it already performed, got {status} with {again:?}"
            );
        } else {
            assert_eq!(
                (status, error_code(&again)),
                (409, "ConflictException"),
                "case {case:?}: expected a second stop to conflict, got {status} with {again:?}"
            );
        }
        let (status, fresh_token) = stop_session(
            &router,
            &browser,
            &session_id,
            json!({"clientToken": "second-stop-token-0123456789-abcdefghij"}),
        )
        .await;
        assert_eq!(
            (status, error_code(&fresh_token)),
            (409, "ConflictException"),
            "case {case:?}: expected a stop under a new token to conflict with the termination, got {status} with {fresh_token:?}"
        );
        assert_eq!(
            message(&fresh_token),
            format!("Session already terminated: {session_id}"),
            "case {case:?}: expected the conflict to name the terminated session, got {fresh_token:?}"
        );
    }

    // A stop addressed to a session nothing started resolves no session.
    let (status, missing) =
        stop_session(&router, SYSTEM_BROWSER, MISSING_SESSION, json!({})).await;
    assert_eq!(
        (status, error_code(&missing)),
        (404, "ResourceNotFoundException"),
        "expected a stop of a session nothing started to be a 404, got {status} with {missing:?}"
    );
}

/// `UpdateBrowserStream` moves the automation stream's status and every later read
/// reports it, while the endpoints stay the session's own. Rows differ along the sequence
/// of statuses requested, including an update that requests none.
#[tokio::test]
async fn an_update_moves_the_automation_stream_status_a_read_reports() {
    let router = emulator();
    let custom = create_browser(&router, CUSTOM_BROWSER_NAME).await;

    let cases: Vec<(&str, String, Vec<Option<&str>>, &str)> = vec![
        (
            "disable-once",
            SYSTEM_BROWSER.to_string(),
            vec![Some(DISABLED)],
            DISABLED,
        ),
        (
            "disable-then-enable",
            custom.clone(),
            vec![Some(DISABLED), Some(ENABLED)],
            ENABLED,
        ),
        (
            "enable-an-already-enabled-stream",
            SYSTEM_BROWSER.to_string(),
            vec![Some(ENABLED)],
            ENABLED,
        ),
        (
            "an-update-that-requests-no-status-leaves-it-alone",
            custom.clone(),
            vec![Some(DISABLED), None],
            DISABLED,
        ),
    ];

    for (case, browser, updates, expected) in cases {
        let (status, started) =
            start_session(&router, &browser, json!({"sessionTimeoutSeconds": 28_800})).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from StartBrowserSession, got {status} with {started:?}"
        );
        let session_id = text(&started, "sessionId").to_string();

        for requested in &updates {
            let update = requested.map_or_else(
                || json!({"streamUpdate": {"automationStreamUpdate": {}}}),
                |value| json!({"streamUpdate": {"automationStreamUpdate": {"streamStatus": value}}}),
            );
            let (status, updated) = update_stream(&router, &browser, &session_id, update).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected HTTP 200 from UpdateBrowserStream, got {status} with {updated:?}"
            );
            assert_eq!(
                (text(&updated, "browserIdentifier"), text(&updated, "sessionId")),
                (browser.as_str(), session_id.as_str()),
                "case {case:?}: expected the update to answer for the session it updated, got {updated:?}"
            );
            // `updatedAt` is a `DateTimestamp`, so it is an RFC 3339 string on this wire.
            let _ = date_time(case, "updatedAt", &updated);
            assert_eq!(
                automation_endpoint(&updated),
                automation_endpoint(&started),
                "case {case:?}: expected the update to leave the automation endpoint alone, got {updated:?}"
            );
            assert_eq!(
                live_view_endpoint(&updated),
                live_view_endpoint(&started),
                "case {case:?}: expected the update to leave the live view endpoint alone, got {updated:?}"
            );
        }

        let (status, read) = get_session(&router, &browser, &session_id).await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from GetBrowserSession, got {status} with {read:?}"
        );
        assert_streams(case, &read, &session_id, expected);
        assert_eq!(
            automation_endpoint(&read),
            automation_endpoint(&started),
            "case {case:?}: expected the session's own automation endpoint, got {read:?}"
        );
    }

    // A session that has been stopped has no stream left to update, and a session nothing
    // started resolves nothing.
    let (_, started) = start_session(&router, SYSTEM_BROWSER, json!({})).await;
    let session_id = text(&started, "sessionId").to_string();
    let (status, _) = stop_session(&router, SYSTEM_BROWSER, &session_id, json!({})).await;
    assert_eq!(status, 200, "the fixture session must stop");
    let disable = json!({"streamUpdate": {"automationStreamUpdate": {"streamStatus": DISABLED}}});
    let (status, refused) =
        update_stream(&router, SYSTEM_BROWSER, &session_id, disable.clone()).await;
    assert_eq!(
        (status, error_code(&refused)),
        (409, "ConflictException"),
        "expected an update of a terminated session to conflict, got {status} with {refused:?}"
    );
    let (status, missing) = update_stream(&router, SYSTEM_BROWSER, MISSING_SESSION, disable).await;
    assert_eq!(
        (status, error_code(&missing)),
        (404, "ResourceNotFoundException"),
        "expected an update of a session nothing started to be a 404, got {status} with {missing:?}"
    );
}

/// A replayed `UpdateBrowserStream` `clientToken` answers with the update it already
/// applied rather than applying a second one.
#[tokio::test]
async fn a_replayed_stream_update_token_answers_with_the_update_it_applied() {
    let router = emulator();
    let (_, started) = start_session(&router, SYSTEM_BROWSER, json!({})).await;
    let session_id = text(&started, "sessionId").to_string();

    let token = "stream-update-token-0123456789-abcdefghij";
    let first = json!({
        "clientToken": token,
        "streamUpdate": {"automationStreamUpdate": {"streamStatus": DISABLED}},
    });
    let (status, applied) = update_stream(&router, SYSTEM_BROWSER, &session_id, first).await;
    assert_eq!(
        status, 200,
        "expected HTTP 200 from the first UpdateBrowserStream, got {status} with {applied:?}"
    );

    // The replay carries a different status: the service ignores a request whose token it
    // has already served.
    let replay = json!({
        "clientToken": token,
        "streamUpdate": {"automationStreamUpdate": {"streamStatus": ENABLED}},
    });
    let (status, replayed) = update_stream(&router, SYSTEM_BROWSER, &session_id, replay).await;
    assert_eq!(
        (status, &replayed),
        (200, &applied),
        "expected the replayed token to answer with the update it already applied, got {status} with {replayed:?}"
    );
    let (_, read) = get_session(&router, SYSTEM_BROWSER, &session_id).await;
    assert_eq!(
        automation_status(&read),
        DISABLED,
        "expected the replay to have applied nothing, got {read:?}"
    );
}
