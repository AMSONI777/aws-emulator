// SPDX-License-Identifier: CC0-1.0

//! The account's (v1) LOGGING OPTIONS: the one record `SetLoggingOptions` writes and
//! `GetLoggingOptions` reports.
//!
//! Neither operation names a resource — `SetLoggingOptions` is "Sets the logging options"
//! and `GetLoggingOptions` "Gets the logging options"
//! (`smithy_query(query="operation",operation="GetLoggingOptions,SetLoggingOptions")`) —
//! so the account holds ONE such record, not a map of them, and the store keeps it as an
//! `Option`: an account nobody has set logging options for holds NOTHING, which is the
//! state the reader refuses with the modelled `InvalidRequestException` (HTTP 400) rather
//! than inventing options for.
//!
//! Every member of `GetLoggingOptionsResponse` has a `LoggingOptionsPayload` member of the
//! same name and shape (`roleArn`, `logLevel`), so the payload IS the whole options
//! document: the record below holds those members and the reader hands them straight back,
//! which is what keeps the writer and the reader from drifting.
//!
//! These are the SETTINGS the v2 operations supersede ("use of this command is not
//! recommended. Use GetV2LoggingOptions instead"), and they are a record of their own, not
//! a view over [`super::v2_logging`]: the two reads report different shapes, the v1 read
//! has no `disableAllLogs` or per-event-type override to report, and each refuses an
//! account that never set ITS options with its own modelled error class.

/// The message a reader of the account's v1 logging options refuses an account that has
/// never set them with.
///
/// The text is FIXED — nothing about the account, the request or the region varies in it —
/// which is how AWS IoT words this refusal.
pub fn missing_logging_options_message() -> String {
    "No Logging Options found".to_string()
}

/// The account's v1 logging options, as this service persists them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoggingOptions {
    /// "The ARN of the IAM role that grants access" — `@required` on
    /// `LoggingOptionsPayload`, so a stored record always carries one.
    pub role_arn: String,
    /// "The log level" — one of the values `LogLevel` declares; the boundary validator
    /// refuses anything else before a handler sees it. Optional on the payload, so an
    /// account configured without one holds none and the reader reports none.
    pub log_level: Option<String>,
}

impl LoggingOptions {
    /// The options a `SetLoggingOptions` request configures.
    ///
    /// A set replaces the account's options in full: every member of the response has a
    /// payload member of the same name, so the payload carries the whole document and a
    /// member a caller omits is one the configured options do not have.
    pub fn configured(role_arn: String, log_level: Option<String>) -> Self {
        Self {
            role_arn,
            log_level,
        }
    }
}
