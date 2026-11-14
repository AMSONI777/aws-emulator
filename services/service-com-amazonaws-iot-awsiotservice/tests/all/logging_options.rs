// SPDX-License-Identifier: CC0-1.0

//! The account's (v1) LOGGING OPTIONS, end to end over HTTP.
//!
//! Every test drives real requests through the `MultiServiceRouter` this crate's service
//! is mounted in, so routing, the restJson1 `GET /loggingOptions` and
//! `POST /loggingOptions` bindings, the handlers and the response serialization are all
//! exercised.
//!
//! The rules under test, none of them specific to one set of options:
//!
//! * `GetLoggingOptions` reports the options this service HOLDS — what the last
//!   `SetLoggingOptions` persisted, member for member;
//! * an account that has never set them holds NO options, so the read is refused with the
//!   modelled `InvalidRequestException` (400) and the fixed sentence AWS words that
//!   refusal with, rather than answered with options nobody configured;
//! * the read is a read: repeating it, with no set between, reports the same options and
//!   leaves the store alone — an unconfigured account stays unconfigured;
//! * a set replaces the account's options in FULL, so a member one request supplies and
//!   the next omits is gone from what the reader reports;
//! * a `logLevel` outside the `LogLevel` catalog the model declares is refused and
//!   records nothing;
//! * the v1 options and the V2 options are separate account settings: setting one leaves
//!   the other's reader answering exactly as it did before.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Map, Value};
use service_com_amazonaws_iot_awsiotservice::ops::types::LOG_LEVEL_VALUES;
use service_com_amazonaws_iot_awsiotservice::state::{
    ComAmazonawsIotAwsiotserviceState, LoggingOptions,
};
use service_com_amazonaws_iot_awsiotservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The region every request in this suite is signed for. The options are account-wide, so
/// no assertion depends on it.
const REGION: &str = "eu-west-2";

/// AWS's own sentence for a read of an account whose v1 logging options were never set,
/// written out here so the wording is pinned by the test and not only by the constant
/// under test. It is fixed text: nothing about the account or the request varies in it.
const EXPECTED_NO_OPTIONS_MESSAGE: &str = "No Logging Options found";

/// Role ARNs a caller may name as the one "that grants access". Nothing asserts on their
/// text — the member is an opaque `AwsArn` in the model
/// (`smithy_query(query="shape",shape="AwsArn")`) — so the rows differ in path, name and
/// partition to show the handler stores what it was given.
const ROLE_ARNS: &[&str] = &[
    "arn:aws:iam::000000000000:role/iot-logs",
    "arn:aws:iam::000000000000:role/service-role/AWSIoTLogging_v1",
    "arn:aws-us-gov:iam::000000000000:role/iot/logging/deeply/nested/role-name",
];

/// One emulator: the shared engine plus a router with this service mounted.
struct Emulator {
    engine: Arc<engine::InMemoryEngine>,
    router: MultiServiceRouter,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        router.set_request_authentication(false);
        router.register_service(EmulatedService::new(Arc::clone(&engine)));
        Self { engine, router }
    }

    /// This service's store, as the handlers reach it.
    fn state(&self) -> engine::ServiceState<ComAmazonawsIotAwsiotserviceState> {
        self.engine.state::<ComAmazonawsIotAwsiotserviceState>()
    }

    /// Overwrite the stored options, so a read can be tested against a record no request
    /// in the test wrote.
    fn seed(&self, options: LoggingOptions) {
        self.state().lock().logging_options = Some(options);
    }

    /// The options the store holds, as the handlers see them.
    fn stored(&self) -> Option<LoggingOptions> {
        self.state().lock().logging_options.clone()
    }

    async fn dispatch(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let host = format!("iot.{REGION}.amazonaws.com");
        let payload = body.map_or_else(Bytes::new, |value| Bytes::from(value.to_string()));
        let request = http::Request::builder()
            .method(method)
            .uri(format!("https://{host}{path}"))
            .header("host", host)
            .header("content-type", "application/json")
            // The credential scope names the `iot` signing name the model's
            // `aws.auth#sigv4` trait declares, which is what routes the request.
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/iot/aws4_request, \
                     SignedHeaders=host, Signature=0123456789abcdef"
                ),
            )
            .body(payload)
            .expect("the logging-options request is well formed");
        Reply::of(self.router.dispatch(request).await)
    }

    async fn get_logging_options(&self) -> Reply {
        self.dispatch("GET", "/loggingOptions", None).await
    }

    /// `SetLoggingOptions` binds `loggingOptionsPayload` as the `@httpPayload`, so the
    /// request body IS the payload document.
    async fn set_logging_options(&self, payload: &Value) -> Reply {
        self.dispatch("POST", "/loggingOptions", Some(payload)).await
    }

    /// Set options the service must accept, failing the case if it does not.
    async fn set_ok(&self, case: &str, payload: &Value) {
        let reply = self.set_logging_options(payload).await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected SetLoggingOptions to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
    }

    /// The options a successful read reports, as JSON.
    async fn reported(&self, case: &str) -> Value {
        let reply = self.get_logging_options().await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected GetLoggingOptions to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
        reply.json()
    }

    /// Assert the read is refused as "no options set", with the status, the error code and
    /// the sentence the model and AWS word that refusal with.
    async fn assert_no_options(&self, case: &str) {
        let reply = self.get_logging_options().await;
        assert_eq!(
            reply.status,
            400,
            "case {case}: expected GetLoggingOptions to answer 400, got {} body {}",
            reply.status,
            reply.text()
        );
        assert_eq!(
            reply.error_code(),
            "InvalidRequestException",
            "case {case}: expected InvalidRequestException, got {}",
            reply.text()
        );
        assert_eq!(
            reply.json()["message"].as_str(),
            Some(EXPECTED_NO_OPTIONS_MESSAGE),
            "case {case}: expected the refusal to state that no options are set, got {}",
            reply.text()
        );
    }

    /// `GetV2LoggingOptions`, so a test can show the two account settings are separate.
    async fn get_v2_logging_options(&self) -> Reply {
        self.dispatch("GET", "/v2LoggingOptions", None).await
    }

    async fn set_v2_logging_options(&self, body: &Value) -> Reply {
        self.dispatch("POST", "/v2LoggingOptions", Some(body)).await
    }
}

/// A dispatched response, reduced to what the assertions read.
struct Reply {
    status: u16,
    body: Bytes,
}

impl Reply {
    fn of(response: http::Response<Bytes>) -> Self {
        Self {
            status: response.status().as_u16(),
            body: response.into_body(),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("response body is not JSON ({e}): {}", self.text()))
    }

    /// The error code a restJson1 error response carries.
    fn error_code(&self) -> String {
        self.json()["__type"]
            .as_str()
            .unwrap_or_else(|| panic!("no __type in {}", self.text()))
            .to_string()
    }
}

/// One `LoggingOptionsPayload`, in the JSON form the model binds it to. `logLevel` left
/// `None` is left out of the object, which is how a caller omits it.
fn payload(role_arn: &str, log_level: Option<&str>) -> Value {
    let mut document = Map::new();
    document.insert("roleArn".to_string(), Value::String(role_arn.to_string()));
    if let Some(log_level) = log_level {
        document.insert("logLevel".to_string(), Value::String(log_level.to_string()));
    }
    Value::Object(document)
}

/// Assert that a read reports exactly what `payload` configured.
///
/// Every member is checked by NAME rather than by comparing whole documents, because a
/// serializer may leave an absent member out of the response object entirely.
async fn assert_reports(emulator: &Emulator, case: &str, payload: &Value) {
    let reported = emulator.reported(case).await;
    for member in ["roleArn", "logLevel"] {
        let expected = payload.get(member);
        assert_eq!(
            reported.get(member),
            expected,
            "case {case}: expected {member} {expected:?}, got {:?} in {reported}",
            reported.get(member)
        );
    }
}

/// One set of options that must round-trip through the reader.
struct RoundTripCase {
    name: String,
    payload: Value,
}

/// Options spanning what the rule generalises over: every log level the model declares,
/// a payload that omits the optional level, and role ARNs of different shapes.
fn round_trip_cases() -> Vec<RoundTripCase> {
    let mut cases = Vec::new();

    // Every value `LogLevel` declares, as the model's own catalog
    // (`smithy_query(query="shape",shape="LogLevel")`), so the rows cover levels the
    // issue never cited.
    for level in LOG_LEVEL_VALUES {
        cases.push(RoundTripCase {
            name: format!("log level {level}"),
            payload: payload(ROLE_ARNS[0], Some(level)),
        });
    }

    // `logLevel` is optional on `LoggingOptionsPayload`, so an account configured without
    // one holds none and the reader reports none.
    for role_arn in ROLE_ARNS {
        cases.push(RoundTripCase {
            name: format!("role {role_arn}, no level"),
            payload: payload(role_arn, None),
        });
        cases.push(RoundTripCase {
            name: format!("role {role_arn}, level INFO"),
            payload: payload(role_arn, Some("INFO")),
        });
    }

    cases
}

/// An account that has never set v1 logging options holds none, so the read is refused
/// with the modelled `InvalidRequestException` (400) — and reading it is a read: the
/// account is still unconfigured afterwards.
#[tokio::test]
async fn an_account_with_no_options_is_refused_as_having_none() {
    let emulator = Emulator::new();

    for round in 0..3 {
        let case = format!("round {round}");
        emulator.assert_no_options(&case).await;
        assert_eq!(
            emulator.stored(),
            None,
            "case {case}: expected the read to leave the account unconfigured, got {:?}",
            emulator.stored()
        );
    }
}

/// Every set of options a caller writes is reported back by the reader, member for
/// member.
#[tokio::test]
async fn every_set_of_options_a_caller_writes_is_reported_back() {
    for case in round_trip_cases() {
        // A fresh emulator per row, so each row is read against its own write and no row
        // can pass on another row's state.
        let emulator = Emulator::new();
        emulator.set_ok(&case.name, &case.payload).await;
        assert_reports(&emulator, &case.name, &case.payload).await;
    }
}

/// Reading configured options is a read: three calls with no set between them report the
/// same options and leave the record alone.
#[tokio::test]
async fn reading_configured_options_changes_nothing() {
    let emulator = Emulator::new();
    let configured = payload(ROLE_ARNS[1], Some("WARN"));
    emulator.set_ok("repeated read", &configured).await;
    let before = emulator.stored();

    for round in 0..3 {
        let case = format!("round {round}");
        assert_reports(&emulator, &case, &configured).await;
        assert_eq!(
            emulator.stored(),
            before,
            "case {case}: expected the read to leave the stored options alone, got {:?}",
            emulator.stored()
        );
    }
}

/// A set replaces the account's options in FULL: what the second payload omits is gone
/// from what the reader reports, and what it names replaces what the first named.
#[tokio::test]
async fn a_later_set_replaces_the_options_in_full() {
    let sequences: &[(&str, Value, Value)] = &[
        (
            "a level, then no level",
            payload(ROLE_ARNS[0], Some("DEBUG")),
            payload(ROLE_ARNS[0], None),
        ),
        (
            "no level, then a level",
            payload(ROLE_ARNS[0], None),
            payload(ROLE_ARNS[0], Some("ERROR")),
        ),
        (
            "another role and another level",
            payload(ROLE_ARNS[1], Some("INFO")),
            payload(ROLE_ARNS[2], Some("DISABLED")),
        ),
    ];

    for (case, first, second) in sequences {
        let emulator = Emulator::new();
        emulator.set_ok(case, first).await;
        assert_reports(&emulator, &format!("{case}: first set"), first).await;
        emulator.set_ok(case, second).await;
        assert_reports(&emulator, &format!("{case}: second set"), second).await;
    }
}

/// The reader reports what STATE holds, not a value compiled into it: a record seeded
/// straight into the store is what the next read answers with.
#[tokio::test]
async fn the_reader_reports_what_the_store_holds() {
    // Two seeded records, so no single hardcoded response can satisfy both rows.
    let seeds: Vec<(&str, LoggingOptions, Value)> = vec![
        (
            "a seeded role and level",
            LoggingOptions {
                role_arn: ROLE_ARNS[2].to_string(),
                log_level: Some("DISABLED".to_string()),
            },
            payload(ROLE_ARNS[2], Some("DISABLED")),
        ),
        (
            "a seeded role with no level",
            LoggingOptions {
                role_arn: ROLE_ARNS[0].to_string(),
                log_level: None,
            },
            payload(ROLE_ARNS[0], None),
        ),
    ];

    for (case, seed, expected) in seeds {
        let emulator = Emulator::new();
        emulator.seed(seed);
        assert_reports(&emulator, case, &expected).await;
    }
}

/// A `logLevel` outside the catalog the model declares is refused and changes nothing.
///
/// The value set is a MODELLED constraint, so no request carrying a value outside one ever
/// reaches the handler — which is why the status, and not the error code, is what this
/// asserts.
#[tokio::test]
async fn a_log_level_outside_the_modelled_enum_is_refused_and_changes_nothing() {
    let mut cases: Vec<(String, Value)> = Vec::new();
    // The lowercase spelling of each declared value is outside the enum, so each is
    // refused…
    for level in LOG_LEVEL_VALUES {
        cases.push((
            format!("logLevel {}", level.to_lowercase()),
            payload(ROLE_ARNS[0], Some(&level.to_lowercase())),
        ));
    }
    // …as is a level no catalog lists at all.
    cases.push((
        "a level no catalog lists".to_string(),
        payload(ROLE_ARNS[0], Some("TRACE")),
    ));

    for (case, request) in cases {
        let emulator = Emulator::new();
        let reply = emulator.set_logging_options(&request).await;
        assert_eq!(
            reply.status,
            400,
            "case {case}: expected SetLoggingOptions to refuse with 400, got {} body {}",
            reply.status,
            reply.text()
        );
        assert_eq!(
            emulator.stored(),
            None,
            "case {case}: expected the refusal to record nothing, got {:?}",
            emulator.stored()
        );
        // The account is still unconfigured, so its reader still refuses.
        emulator.assert_no_options(&case).await;
    }
}

/// The v1 options and the V2 options are SEPARATE account settings: configuring one
/// leaves the other's reader answering exactly as it did before, each with its own
/// modelled refusal for an account that never set it.
#[tokio::test]
async fn the_v1_and_v2_options_are_separate_settings() {
    // Setting the V2 options configures nothing for the v1 reader.
    let emulator = Emulator::new();
    let v2_reply = emulator
        .set_v2_logging_options(&json!({ "roleArn": ROLE_ARNS[0], "defaultLogLevel": "WARN" }))
        .await;
    assert_eq!(
        v2_reply.status,
        200,
        "case v2 set: expected SetV2LoggingOptions to answer 200, got {} body {}",
        v2_reply.status,
        v2_reply.text()
    );
    emulator.assert_no_options("after a v2 set").await;

    // And setting the v1 options configures nothing for the V2 reader, which refuses an
    // account that never set ITS options with its own modelled error class.
    let emulator = Emulator::new();
    let configured = payload(ROLE_ARNS[0], Some("WARN"));
    emulator.set_ok("v1 set", &configured).await;
    assert_reports(&emulator, "after a v1 set", &configured).await;
    let v2_reply = emulator.get_v2_logging_options().await;
    assert_eq!(
        v2_reply.status,
        404,
        "case after a v1 set: expected GetV2LoggingOptions to answer 404, got {} body {}",
        v2_reply.status,
        v2_reply.text()
    );
    assert_eq!(
        v2_reply.error_code(),
        "NotConfiguredException",
        "case after a v1 set: expected NotConfiguredException, got {}",
        v2_reply.text()
    );
}
