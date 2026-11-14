// SPDX-License-Identifier: CC0-1.0

//! The OPEN Live Tail sessions of this account, and the publication of ingested log events
//! to them.
//!
//! `StartLiveTail` "returns a stream of log events that have been recently ingested in the
//! log groups", and what it streams is produced by the INGESTION path rather than read out
//! of what a group already holds: "Every second, a LiveTailSessionUpdate object is sent.
//! Each of these objects contains an array of the actual log events", and "if no new log
//! events were ingested in the past second, the LiveTailSessionUpdate object will contain an
//! empty array". So a session is a subscriber: it is REGISTERED here while it is open
//! ([`SessionHandle`]), every `PutLogEvents` offers the events it stores to the sessions
//! tailing that log group ([`publish`]), and each session keeps the ones its own selection
//! admits until the next update takes them ([`SessionRecord::take_update`]).
//!
//! That is also what makes a session carry only what was ingested while it was open: a
//! session's buffer starts empty, and the only thing that ever puts an event in it is an
//! ingestion that happened after it was registered. An event a log group already held when
//! the session opened was published to whatever sessions were open THEN, so it reaches this
//! one through nothing.
//!
//! # What one session buffers
//!
//! Three bounds decide what a session can hold, and the first two are the service's own:
//!
//! * `MAX_EVENTS_PER_UPDATE` — "The array of log events contained in a
//!   LiveTailSessionUpdate can include as many as 500 log events. If the number of log
//!   events matching the request exceeds 500 per second, the log events are sampled down to
//!   500 log events to be included in each LiveTailSessionUpdate object". The sample is the
//!   most recent events, which is what a tail is watching, and an update that left a
//!   matching event out reports itself `sampled`, as that member documents.
//! * [`MAX_BUFFERED_EVENTS`] — "If your client consumes the log events slower than the
//!   server produces them, CloudWatch Logs buffers up to 10 LiveTailSessionUpdate events or
//!   5000 log events, after which it starts dropping the oldest events". A session whose
//!   buffer is full therefore drops its OLDEST events rather than refusing the ingestion or
//!   growing without bound.
//! * [`MAX_BUFFERED_BYTES`] — an EMULATOR bound, on the bytes of log-event messages one
//!   session holds between two updates: a single event's message may be a megabyte
//!   ([`super::MAX_LOG_EVENT_BYTES`]), so the event bound above alone would let one session
//!   hold gigabytes. Accounted from the messages themselves, as this service's other bounded
//!   reads of stored events account their page, and enforced exactly like the documented one
//!   — the oldest events go first — so what a session keeps is always the most recent run of
//!   what it matched.
//!
//! Nothing here reads or writes a log group: a session's registration lives beside the
//! groups, and dropping its handle takes it away, so a tail leaves every group it tailed
//! exactly as a later reader finds it.
//!
//! What the registry can cost is bounded by those same two things: an entry exists only
//! while the request serving its session is in flight — the handle is given back however
//! that request ends, a caller that hung up included — and while it does it holds at most
//! [`MAX_BUFFERED_EVENTS`] events and [`MAX_BUFFERED_BYTES`] of message bytes between two
//! updates.

use std::collections::BTreeMap;

use super::filter_pattern::FilterPattern;
use super::{ComAmazonawsCloudwatchlogsLogs20140328State, StoredEvent};

/// How often an open session sends an update: "Every second, a LiveTailSessionUpdate object
/// is sent."
pub const UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// The most log events one update carries: "The array of log events contained in a
/// LiveTailSessionUpdate can include as many as 500 log events. If the number of log events
/// matching the request exceeds 500 per second, the log events are sampled down to 500 log
/// events to be included in each LiveTailSessionUpdate object" (`StartLiveTail`).
pub const MAX_EVENTS_PER_UPDATE: usize = 500;

/// The most updates one session's buffer holds for a client that has not consumed them:
/// CloudWatch Logs "buffers up to 10 LiveTailSessionUpdate events or 5000 log events, after
/// which it starts dropping the oldest events" (`StartLiveTail`).
pub const MAX_BUFFERED_UPDATES: usize = 10;

/// The most log events one session's buffer holds for a client that has not consumed them.
/// See [`MAX_BUFFERED_UPDATES`], which states the same sentence's other half.
pub const MAX_BUFFERED_EVENTS: usize = 5_000;

/// The most bytes of log-event messages one session holds between two updates — an EMULATOR
/// bound, see the module docs. Past it the OLDEST buffered events are dropped, exactly as the
/// documented event bound drops them.
pub const MAX_BUFFERED_BYTES: usize = 1_048_576;

/// One log event a session delivers, with the log group identifier the request named its
/// group by and the stream it was ingested into — the two positions the modelled
/// `LiveTailSessionLogEvent` reports beside the event itself.
#[derive(Debug, Clone)]
pub struct DeliveredEvent {
    /// The log group identifier as the SESSION's request spelled it (a name or an ARN), not
    /// the group's name: the member reports the group the way the caller named it.
    pub log_group_identifier: String,
    pub log_stream_name: String,
    pub message: String,
    pub timestamp: i64,
    pub ingestion_time: i64,
}

impl DeliveredEvent {
    /// What this event costs the session's byte budget: its message, which is the only
    /// caller-sized part of it.
    fn message_bytes(&self) -> usize {
        self.message.len()
    }
}

/// The update one session owes for the second that just ended.
#[derive(Debug, Default)]
pub struct Update {
    /// The log events of that second the session's selection admitted, oldest first, bounded
    /// by [`MAX_EVENTS_PER_UPDATE`]. Empty when none were ingested, which is what the
    /// operation documents for a quiet second.
    pub events: Vec<DeliveredEvent>,
    /// Whether a matching event was left out of this update — because more than
    /// [`MAX_EVENTS_PER_UPDATE`] matched in that second, or because the session's buffer
    /// dropped its oldest to stay inside its bounds.
    pub sampled: bool,
}

/// One OPEN Live Tail session: the selection it was started with, and the matching events
/// ingested since its last update.
#[derive(Debug)]
pub struct SessionRecord {
    /// The log groups this session tails: the group's NAME, which is what an ingestion names
    /// it by, mapped to the identifier the request spelled it as. A request that names one
    /// group twice (by name and by ARN) keeps the first spelling, since one event is
    /// delivered once.
    groups: BTreeMap<String, String>,
    /// "If you specify this field, only the log events in the log streams that you specify
    /// here are included in the Live Tail session" — `None` when the request named none.
    log_stream_names: Option<Vec<String>>,
    /// "If you specify this field, only the log events in the log streams that have names
    /// that start with the prefixes that you specify here are included" — `None` when the
    /// request named none.
    log_stream_name_prefixes: Option<Vec<String>>,
    /// "An optional pattern to use to filter the results to include only log events that
    /// match the pattern", parsed when the session was started.
    pattern: FilterPattern,
    /// The admitted events ingested since the last update, oldest first.
    pending: Vec<DeliveredEvent>,
    /// The bytes of messages `pending` holds, so the byte bound is enforced without
    /// re-summing it on every ingestion.
    pending_bytes: usize,
    /// How many admitted events of the same span the buffer DROPPED to stay inside its
    /// bounds. It is what makes the next update report itself sampled, since those events
    /// matched the session's request and the update does not carry them.
    dropped: usize,
}

impl SessionRecord {
    /// A session over `groups` (group name -> the identifier the request named it by) with
    /// the request's own stream selection and filter pattern, buffering nothing yet.
    #[must_use]
    pub fn new(
        groups: BTreeMap<String, String>,
        log_stream_names: Option<Vec<String>>,
        log_stream_name_prefixes: Option<Vec<String>>,
        pattern: FilterPattern,
    ) -> Self {
        Self {
            groups,
            log_stream_names,
            log_stream_name_prefixes,
            pattern,
            pending: Vec::new(),
            pending_bytes: 0,
            dropped: 0,
        }
    }

    /// The identifier this session would deliver an event of `log_group_name` /
    /// `log_stream_name` carrying `message` under, or `None` when its selection admits no
    /// such event.
    fn admits(&self, log_group_name: &str, log_stream_name: &str, message: &str) -> Option<&str> {
        let identifier = self.groups.get(log_group_name)?;
        if !self.covers_stream(log_stream_name) {
            return None;
        }
        self.pattern
            .match_message(message)
            .map(|_| identifier.as_str())
    }

    /// Whether one log stream is in this session's selection: the named streams when the
    /// request named any, the streams whose name starts with one of the prefixes when it
    /// gave prefixes, and every stream of the group when it gave neither (the two selectors
    /// are refused together before a session is opened).
    fn covers_stream(&self, log_stream_name: &str) -> bool {
        if let Some(names) = &self.log_stream_names {
            return names.iter().any(|name| name == log_stream_name);
        }
        if let Some(prefixes) = &self.log_stream_name_prefixes {
            return prefixes
                .iter()
                .any(|prefix| log_stream_name.starts_with(prefix.as_str()));
        }
        true
    }

    /// Buffer one ingested event this session admitted, dropping the OLDEST buffered events
    /// where that takes the buffer past either of its bounds.
    fn buffer(&mut self, delivered: DeliveredEvent) {
        self.pending_bytes = self
            .pending_bytes
            .saturating_add(delivered.message_bytes());
        self.pending.push(delivered);
        while self.pending.len() > MAX_BUFFERED_EVENTS
            || (self.pending.len() > 1 && self.pending_bytes > MAX_BUFFERED_BYTES)
        {
            let oldest = self.pending.remove(0);
            self.pending_bytes = self.pending_bytes.saturating_sub(oldest.message_bytes());
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// Take the update this session owes for the span that just ended, leaving its buffer
    /// empty.
    ///
    /// Past [`MAX_EVENTS_PER_UPDATE`] the update carries the most recent events — "the log
    /// events are sampled down to 500 log events" — and reports itself sampled, which it also
    /// does when the buffer dropped one of the events it had matched.
    pub fn take_update(&mut self) -> Update {
        let dropped = std::mem::take(&mut self.dropped);
        let mut events = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        let matched = events.len().saturating_add(dropped);
        if events.len() > MAX_EVENTS_PER_UPDATE {
            events.drain(..events.len() - MAX_EVENTS_PER_UPDATE);
        }
        Update {
            sampled: events.len() < matched,
            events,
        }
    }
}

/// Offer the events a `PutLogEvents` is storing on `log_group_name` / `log_stream_name` to
/// every OPEN session, so each one buffers the ones its own selection admits.
///
/// Called under the store's own guard, from the ingestion itself: the sessions an event
/// reaches are the ones that were open when it was ingested, and an event ingested before a
/// session opened reaches it through nothing.
pub fn publish(
    store: &mut ComAmazonawsCloudwatchlogsLogs20140328State,
    log_group_name: &str,
    log_stream_name: &str,
    events: &[StoredEvent],
) {
    if store.live_tail_sessions.is_empty() || events.is_empty() {
        return;
    }
    for session in store.live_tail_sessions.values_mut() {
        for event in events {
            let Some(identifier) = session.admits(log_group_name, log_stream_name, &event.message)
            else {
                continue;
            };
            let delivered = DeliveredEvent {
                log_group_identifier: identifier.to_string(),
                log_stream_name: log_stream_name.to_string(),
                message: event.message.clone(),
                timestamp: event.timestamp,
                ingestion_time: event.ingestion_time,
            };
            session.buffer(delivered);
        }
    }
}

/// The registration one OPEN session holds.
///
/// Dropping it takes the session out of the store, so a session that ends — with its last
/// update, or because the caller hung up and the handler's future was cancelled — never
/// leaves a subscriber behind that an ingestion would go on buffering events for. The handle
/// keeps its own handle on the store for that, so it does not borrow the guard the session
/// was registered under.
///
/// NEVER drop one while holding the state lock: the drop takes that same lock to remove the
/// session.
pub struct SessionHandle {
    state: ::engine::ServiceState<ComAmazonawsCloudwatchlogsLogs20140328State>,
    session_id: String,
}

impl SessionHandle {
    /// Register `session` under `session_id` through the already-held `guard`.
    #[must_use]
    pub fn open(
        state: &::engine::ServiceState<ComAmazonawsCloudwatchlogsLogs20140328State>,
        guard: &mut ComAmazonawsCloudwatchlogsLogs20140328State,
        session_id: &str,
        session: SessionRecord,
    ) -> Self {
        guard
            .live_tail_sessions
            .insert(session_id.to_string(), session);
        Self {
            state: state.clone(),
            session_id: session_id.to_string(),
        }
    }

    /// The update this session owes for the span that just ended. An empty update for a
    /// session that is no longer registered, which nothing but its own handle can do.
    #[must_use]
    pub fn take_update(&self) -> Update {
        let mut guard = self.state.lock();
        guard
            .live_tail_sessions
            .get_mut(&self.session_id)
            .map(SessionRecord::take_update)
            .unwrap_or_default()
    }
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        let mut guard = self.state.lock();
        guard.live_tail_sessions.remove(&self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DeliveredEvent, SessionRecord, MAX_BUFFERED_BYTES, MAX_BUFFERED_EVENTS,
        MAX_EVENTS_PER_UPDATE,
    };
    use std::collections::BTreeMap;

    /// A session over one group named by its own name, admitting every stream and message.
    fn tailing() -> SessionRecord {
        let mut groups = BTreeMap::new();
        groups.insert("group".to_string(), "group".to_string());
        SessionRecord::new(
            groups,
            None,
            None,
            super::FilterPattern::parse("").expect("the empty pattern parses"),
        )
    }

    /// One buffered event of `bytes` message bytes, labelled `index`.
    fn event(index: usize, bytes: usize) -> DeliveredEvent {
        let label = format!("event {index} ");
        DeliveredEvent {
            log_group_identifier: "group".to_string(),
            log_stream_name: "stream".to_string(),
            message: format!("{label}{}", "x".repeat(bytes.saturating_sub(label.len()))),
            timestamp: 0,
            ingestion_time: 0,
        }
    }

    /// An update carries the events of its own span, bounded by the 500 one update may
    /// carry, and reports itself sampled exactly when it left a matching event out.
    #[test]
    fn an_update_carries_at_most_the_events_one_update_may_carry() {
        // Rows: how many events one span buffered, against the update's event ceiling.
        for buffered in [0, 1, MAX_EVENTS_PER_UPDATE - 1, MAX_EVENTS_PER_UPDATE] {
            let mut session = tailing();
            for index in 0..buffered {
                session.buffer(event(index, 16));
            }
            let update = session.take_update();
            assert_eq!(
                update.events.len(),
                buffered,
                "case {buffered} buffered: every matching event fits one update, got {}",
                update.events.len()
            );
            assert!(
                !update.sampled,
                "case {buffered} buffered: nothing was left out, so the update is not sampled"
            );
        }

        let mut session = tailing();
        for index in 0..MAX_EVENTS_PER_UPDATE + 7 {
            session.buffer(event(index, 16));
        }
        let update = session.take_update();
        assert_eq!(
            update.events.len(),
            MAX_EVENTS_PER_UPDATE,
            "case \"past the ceiling\": expected {MAX_EVENTS_PER_UPDATE} events, got {}",
            update.events.len()
        );
        assert!(
            update.sampled,
            "case \"past the ceiling\": an update that left a matching event out is sampled"
        );
        assert_eq!(
            update.events.first().map(|first| first.message.clone()),
            Some(event(7, 16).message),
            "case \"past the ceiling\": the sample is the most recent events, got {:?}",
            update.events.first().map(|first| first.message.clone())
        );

        // The span after one that was sampled starts clean: an update reports what its own
        // span buffered.
        let after = session.take_update();
        assert!(
            after.events.is_empty() && !after.sampled,
            "case \"the next span\": a quiet span carries an empty, unsampled update, got {after:?}"
        );
    }

    /// The buffer holds the most recent run of what it matched: past either of its bounds the
    /// OLDEST events go, and the update that follows says it was sampled.
    #[test]
    fn the_buffer_drops_its_oldest_events_past_either_bound() {
        // One event per megabyte-ish message: two of them do not fit the byte bound.
        let mut session = tailing();
        let large = MAX_BUFFERED_BYTES / 2 + 1;
        for index in 0..3 {
            session.buffer(event(index, large));
        }
        let update = session.take_update();
        assert_eq!(
            update.events.len(),
            1,
            "case \"past the byte bound\": expected the newest event alone, got {}",
            update.events.len()
        );
        assert_eq!(
            update.events.first().map(|first| first.message.clone()),
            Some(event(2, large).message),
            "case \"past the byte bound\": the newest event is the one kept"
        );
        assert!(
            update.sampled,
            "case \"past the byte bound\": the update left a matching event out"
        );

        // A single event larger than the whole bound is still delivered rather than dropped.
        let mut session = tailing();
        session.buffer(event(0, MAX_BUFFERED_BYTES * 2));
        let update = session.take_update();
        assert_eq!(
            update.events.len(),
            1,
            "case \"one oversized event\": the newest event is always carried, got {}",
            update.events.len()
        );
        assert!(
            !update.sampled,
            "case \"one oversized event\": nothing was left out, so the update is not sampled"
        );

        // The documented event bound, counted on small messages so the byte bound is not the
        // one that bites.
        let mut session = tailing();
        for index in 0..MAX_BUFFERED_EVENTS + 3 {
            session.buffer(event(index, 16));
        }
        let update = session.take_update();
        assert_eq!(
            (update.events.len(), update.sampled),
            (MAX_EVENTS_PER_UPDATE, true),
            "case \"past the buffered-event bound\": expected a sampled {MAX_EVENTS_PER_UPDATE}-event \
             update, got {} events",
            update.events.len()
        );
    }

    /// A session buffers an event only where its own selection admits it: the group it
    /// tails, the streams it selected, and the pattern it filters by.
    #[test]
    fn a_session_admits_only_what_its_selection_covers() {
        let mut groups = BTreeMap::new();
        groups.insert("group".to_string(), "arn-of-group".to_string());
        let named = SessionRecord::new(
            groups.clone(),
            Some(vec!["app-one".to_string()]),
            None,
            super::FilterPattern::parse("ERROR").expect("a term pattern parses"),
        );
        // Rows: the group, stream and message of one ingestion, and the identifier the
        // session would deliver it under.
        let rows = [
            ("group", "app-one", "ERROR disk full", Some("arn-of-group")),
            ("group", "app-one", "INFO disk fine", None),
            ("group", "app-two", "ERROR disk full", None),
            ("other", "app-one", "ERROR disk full", None),
        ];
        for (group, stream, message, expected) in rows {
            let actual = named.admits(group, stream, message);
            assert_eq!(
                actual, expected,
                "case {group}/{stream}/{message:?}: expected {expected:?}, got {actual:?}"
            );
        }

        let prefixed = SessionRecord::new(
            groups,
            None,
            Some(vec!["app-".to_string()]),
            super::FilterPattern::parse("").expect("the empty pattern parses"),
        );
        for (stream, expected) in [("app-two", Some("arn-of-group")), ("sys-one", None)] {
            let actual = prefixed.admits("group", stream, "anything");
            assert_eq!(
                actual, expected,
                "case prefix/{stream}: expected {expected:?}, got {actual:?}"
            );
        }
    }
}
