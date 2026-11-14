// SPDX-License-Identifier: CC0-1.0

//! The MESSAGE BROKER behind a RabbitMQ broker's AMQP endpoint: its exchanges, its
//! queues, and what becomes of a message between the publish that routes it and the
//! acknowledgement that drops it.
//!
//! RULE: a published message is routed by the EXCHANGE it names — a direct exchange to
//! every queue bound under the message's routing key, a fanout exchange to every queue
//! bound to it, a topic exchange to every queue whose binding pattern matches the
//! routing key word by word, a headers exchange to every queue whose binding arguments
//! match the message's headers — and the message then waits in each queue it reached, in
//! publication order, until a consumer acknowledges it. A message a consumer REJECTS
//! without requeueing, or that outlives its expiration, leaves the queue for that
//! queue's dead-letter exchange carrying the reason it died; a message that outlives the
//! queue's length bound does the same.
//!
//! The arguments a queue is declared with are RabbitMQ's documented optional arguments
//! (`x-message-ttl`, `x-dead-letter-exchange`, `x-dead-letter-routing-key`,
//! `x-max-length`), and the record a dead-lettered message carries is RabbitMQ's own
//! `x-death` entry (count, reason, queue, time, exchange, routing-keys and, when the
//! message carried one, its original expiration).
//!
//! Nothing here speaks the wire: [`super::amqp_session`] parses frames and calls this.
//! One of these lives per BROKER, in that broker's data-plane record, so what a client
//! publishes on one connection is what another consumes.
//!
//! # Bounds
//!
//! The store is in memory and shared by every session on the broker's socket, so each
//! dimension it can grow in is capped: [`MAX_EXCHANGES`], [`MAX_QUEUES`],
//! [`MAX_MESSAGES_PER_QUEUE`], [`MAX_BINDINGS_PER_EXCHANGE`], [`MAX_MESSAGE_BYTES`] and
//! [`MAX_BROKER_BYTES`] — which is enforced where a body is STORED, so a message that
//! fans out to many queues is accounted for every copy it leaves behind, and refused its
//! whole cost before the first one is made. Past a cap a publish is REFUSED with the
//! engine's own error rather than silently dropped; a copy an expiry or a length bound
//! produces, which has no caller left to refuse, is dropped. A dead-letter chain is
//! bounded by [`MAX_PLACEMENT_STEPS`] and [`MAX_PENDING_PLACEMENTS`] within one publish
//! and by [`MAX_DEATH_HOPS`] across the message's own history, so a cycle of dead-letter
//! exchanges cannot spin.
//!
//! The WORK a request can ask for is bounded too: a topic match walks each side once
//! ([`topic_matches`], bounded by [`MAX_TOPIC_WORDS`]) rather than searching every way a
//! `#` could be split, and a time to live a client chooses is held to
//! [`MAX_MESSAGE_TTL`] and turned into an instant only where the clock can represent
//! one.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::amq_protocol::protocol::basic::AMQPProperties;
use ::amq_protocol::types::{AMQPValue, FieldArray, FieldTable, LongString, ShortString};

/// How many exchanges one broker may hold.
pub const MAX_EXCHANGES: usize = 256;

/// How many queues one broker may hold.
pub const MAX_QUEUES: usize = 256;

/// How many bindings one exchange may hold.
pub const MAX_BINDINGS_PER_EXCHANGE: usize = 256;

/// How many messages one queue may hold before a publish into it is refused.
pub const MAX_MESSAGES_PER_QUEUE: usize = 10_000;

/// The largest message body this broker accepts.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// How many bytes of message bodies one broker holds across every queue.
pub const MAX_BROKER_BYTES: usize = 64 * 1024 * 1024;

/// How many placements one publish may cause: the message itself plus the dead-letter
/// hops it may set off. A dead-letter exchange that routes back into a queue the message
/// came from would otherwise cycle forever.
pub const MAX_PLACEMENT_STEPS: usize = 32;

/// How many times one message may be dead-lettered before it is dropped instead of
/// republished again.
///
/// RabbitMQ drops a message whose dead-lettering would cycle; this is that bound, read
/// off the message's own history, so a chain of dead-letter exchanges that leads back to
/// a queue the message has already died in ends rather than running on every tick of the
/// clock.
pub const MAX_DEATH_HOPS: usize = 8;

/// How many placements may be waiting at once inside one publish or one expiry pass.
///
/// A placement waiting to happen holds its own copy of the message, so this bounds the
/// copies in flight the way [`MAX_BROKER_BYTES`] bounds the ones stored; a copy past it
/// is dropped rather than staged.
pub const MAX_PENDING_PLACEMENTS: usize = 64;

/// How many `.`-separated words a topic pattern or a routing key may carry.
///
/// Both arrive as AMQP short strings, which are 255 bytes at most, and a word takes at
/// least its separator and a character — so no valid value reaches this bound, and one
/// that somehow did is refused by the match rather than walked.
pub const MAX_TOPIC_WORDS: usize = 128;

/// The longest time to live this broker gives a message.
///
/// A time to live arrives as a number of milliseconds a client chooses, and an instant
/// that far ahead may not be representable on the platform's clock at all; a value past
/// this bound is held to it, which keeps "practically never" from becoming an instant
/// nothing can compute. RabbitMQ's own `x-message-ttl` is a 32-bit millisecond count,
/// whose largest value is just under 25 days — this is that ceiling.
pub const MAX_MESSAGE_TTL: Duration = Duration::from_millis(i32::MAX as u64);

/// The argument that gives a queue's messages a time to live, in milliseconds.
const ARG_MESSAGE_TTL: &str = "x-message-ttl";

/// The argument naming the exchange a queue dead-letters to.
const ARG_DEAD_LETTER_EXCHANGE: &str = "x-dead-letter-exchange";

/// The argument naming the routing key a dead-lettered message is republished under.
const ARG_DEAD_LETTER_ROUTING_KEY: &str = "x-dead-letter-routing-key";

/// The argument bounding how many messages a queue holds.
const ARG_MAX_LENGTH: &str = "x-max-length";

/// The binding argument that decides whether a headers exchange needs ALL of a
/// binding's arguments to match or ANY of them.
const ARG_MATCH: &str = "x-match";

/// The header carrying one entry per queue a message has died in, newest first.
const HEADER_DEATH: &str = "x-death";

/// The header carrying the reason of the FIRST death in a message's history.
const HEADER_FIRST_DEATH_REASON: &str = "x-first-death-reason";

/// The header carrying the queue of the first death.
const HEADER_FIRST_DEATH_QUEUE: &str = "x-first-death-queue";

/// The header carrying the exchange of the first death.
const HEADER_FIRST_DEATH_EXCHANGE: &str = "x-first-death-exchange";

/// `x-death`'s reason for a message a consumer rejected without requeueing it.
pub const REASON_REJECTED: &str = "rejected";

/// `x-death`'s reason for a message that outlived its expiration.
pub const REASON_EXPIRED: &str = "expired";

/// `x-death`'s reason for a message dropped because its queue was full.
pub const REASON_MAXLEN: &str = "maxlen";

/// The exchange every broker has and no client declares: the default exchange, which
/// routes a message to the queue its routing key names.
pub const DEFAULT_EXCHANGE: &str = "";

/// What a client is answered when its request cannot be served, and at which level the
/// protocol closes.
///
/// The codes and the wording are the AMQP reply codes RabbitMQ answers with, so a client
/// library that branches on them behaves as it does against the real broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// The CHANNEL is closed with this reply code and text; the connection stays open.
    Channel { code: u16, text: String },
    /// The CONNECTION is closed with this reply code and text.
    Connection { code: u16, text: String },
}

impl BrokerError {
    /// 404: the exchange or queue the request names does not exist.
    fn not_found(text: String) -> Self {
        Self::Channel { code: 404, text }
    }

    /// 406: the request contradicts the state the resource is in.
    fn precondition_failed(text: String) -> Self {
        Self::Channel { code: 406, text }
    }

    /// 503: the request itself is not a command this broker can carry out.
    fn command_invalid(text: String) -> Self {
        Self::Connection { code: 503, text }
    }

    /// 506: the broker has no room left for what the request asks it to hold.
    fn resource_error(text: String) -> Self {
        Self::Connection { code: 506, text }
    }

    /// 311: the message body is larger than this broker accepts.
    fn content_too_large(text: String) -> Self {
        Self::Channel { code: 311, text }
    }
}

/// How an exchange routes: the four types AMQP 0-9-1 defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeKind {
    Direct,
    Fanout,
    Topic,
    Headers,
}

impl ExchangeKind {
    /// The type name a client declares this kind under, which is also the name reported
    /// back when a redeclaration disagrees.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Fanout => "fanout",
            Self::Topic => "topic",
            Self::Headers => "headers",
        }
    }

    /// The kind a declared type name means, or `None` for a type this broker does not
    /// serve — RabbitMQ's own types beyond the four are plugins, and a broker without
    /// the plugin refuses the declaration rather than routing the exchange some other
    /// way.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "direct" => Some(Self::Direct),
            "fanout" => Some(Self::Fanout),
            "topic" => Some(Self::Topic),
            // RabbitMQ's headers exchange answers to both names.
            "headers" | "match" => Some(Self::Headers),
            _ => None,
        }
    }
}

/// One binding of a queue to an exchange.
#[derive(Debug, Clone)]
struct Binding {
    queue: String,
    routing_key: String,
    arguments: FieldTable,
}

/// One exchange, as a declaration left it.
#[derive(Debug, Clone)]
struct Exchange {
    kind: ExchangeKind,
    durable: bool,
    auto_delete: bool,
    internal: bool,
    bindings: Vec<Binding>,
}

/// One message, as a queue holds it.
#[derive(Debug, Clone)]
pub struct Message {
    /// The exchange the publish named.
    pub exchange: String,
    /// The routing key the publish named.
    pub routing_key: String,
    pub properties: AMQPProperties,
    pub body: Vec<u8>,
    /// Whether this message has already been delivered to a consumer once.
    pub redelivered: bool,
    /// The instant the clock makes this message's expiration due, when it has one.
    expires_at: Option<SystemTime>,
    /// How many times this message has been dead-lettered, which bounds a cycle.
    deaths: usize,
}

impl Message {
    /// A message as a publish hands it over: nothing has happened to it yet.
    pub fn published(
        exchange: &str,
        routing_key: &str,
        properties: AMQPProperties,
        body: Vec<u8>,
    ) -> Self {
        Self {
            exchange: exchange.to_string(),
            routing_key: routing_key.to_string(),
            properties,
            body,
            redelivered: false,
            expires_at: None,
            deaths: 0,
        }
    }

    /// The per-message time to live the publisher set (`expiration`, in milliseconds),
    /// when it set one that is a number of milliseconds — held to
    /// [`MAX_MESSAGE_TTL`], the longest span this broker computes an instant for.
    fn published_ttl(&self) -> Option<Duration> {
        let raw = self.properties.expiration().as_ref()?;
        raw.as_str()
            .parse::<u64>()
            .ok()
            .map(|millis| Duration::from_millis(millis).min(MAX_MESSAGE_TTL))
    }
}

/// One queue, as a declaration left it, plus what it holds.
#[derive(Debug, Clone)]
struct Queue {
    durable: bool,
    exclusive: bool,
    auto_delete: bool,
    arguments: FieldTable,
    /// The messages waiting, oldest first.
    messages: VecDeque<Message>,
    /// How many consumers are reading this queue right now, across every session.
    consumers: usize,
}

impl Queue {
    /// The exchange this queue dead-letters to, when it was declared with one.
    fn dead_letter_exchange(&self) -> Option<String> {
        argument_text(&self.arguments, ARG_DEAD_LETTER_EXCHANGE)
    }

    /// The routing key a dead-lettered message is republished under, when the queue was
    /// declared with one; otherwise the message keeps its own routing key.
    fn dead_letter_routing_key(&self) -> Option<String> {
        argument_text(&self.arguments, ARG_DEAD_LETTER_ROUTING_KEY)
    }

    /// The time to live this queue gives every message in it, held to
    /// [`MAX_MESSAGE_TTL`] — see [`Message::published_ttl`].
    fn message_ttl(&self) -> Option<Duration> {
        argument_number(&self.arguments, ARG_MESSAGE_TTL)
            .and_then(|millis| u64::try_from(millis).ok())
            .map(|millis| Duration::from_millis(millis).min(MAX_MESSAGE_TTL))
    }

    /// How many messages this queue may hold, when it was declared with a bound.
    fn max_length(&self) -> Option<usize> {
        argument_number(&self.arguments, ARG_MAX_LENGTH)
            .and_then(|count| usize::try_from(count).ok())
    }
}

/// What a declaration asks of a queue: everything `queue.declare` carries about one.
///
/// A struct rather than a parameter list because a queue is declared by six values and a
/// caller that mixed two of them up would be declaring a different queue.
#[derive(Debug, Clone, Copy)]
pub struct QueueDeclaration<'a> {
    /// The name asked for, or the empty name for a queue the broker names itself.
    pub name: &'a str,
    /// Whether the declaration only CHECKS that the queue exists.
    pub passive: bool,
    pub durable: bool,
    pub exclusive: bool,
    pub auto_delete: bool,
    pub arguments: &'a FieldTable,
}

/// What a declaration reports back about a queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueState {
    pub name: String,
    pub message_count: u32,
    pub consumer_count: u32,
}

/// One broker's exchanges and queues: the whole of its virtual host.
#[derive(Debug)]
pub struct MessageBroker {
    exchanges: BTreeMap<String, Exchange>,
    queues: BTreeMap<String, Queue>,
    /// The bytes of message bodies held across every queue.
    held_bytes: usize,
    /// The sequence the next server-generated queue name is built from.
    next_generated_name: u64,
}

impl Default for MessageBroker {
    /// A broker as RabbitMQ starts one: the default exchange plus the predeclared
    /// `amq.*` exchanges, and no queues.
    fn default() -> Self {
        let mut exchanges = BTreeMap::new();
        for (name, kind) in [
            (DEFAULT_EXCHANGE, ExchangeKind::Direct),
            ("amq.direct", ExchangeKind::Direct),
            ("amq.fanout", ExchangeKind::Fanout),
            ("amq.topic", ExchangeKind::Topic),
            ("amq.headers", ExchangeKind::Headers),
            ("amq.match", ExchangeKind::Headers),
        ] {
            exchanges.insert(
                name.to_string(),
                Exchange {
                    kind,
                    durable: true,
                    auto_delete: false,
                    internal: false,
                    bindings: Vec::new(),
                },
            );
        }
        Self {
            exchanges,
            queues: BTreeMap::new(),
            held_bytes: 0,
            next_generated_name: 1,
        }
    }
}

impl MessageBroker {
    /// Declare an exchange, or check that one exists (`passive`).
    pub fn declare_exchange(
        &mut self,
        name: &str,
        kind: &str,
        passive: bool,
        durable: bool,
        auto_delete: bool,
        internal: bool,
    ) -> Result<(), BrokerError> {
        if passive {
            return self.exchange(name).map(|_| ());
        }
        let Some(kind) = ExchangeKind::parse(kind) else {
            return Err(BrokerError::command_invalid(format!(
                "COMMAND_INVALID - unknown exchange type '{kind}'"
            )));
        };
        if let Some(existing) = self.exchanges.get(name) {
            if existing.kind != kind {
                return Err(BrokerError::precondition_failed(format!(
                    "PRECONDITION_FAILED - inequivalent arg 'type' for exchange '{name}' in \
                     vhost '/': received '{}' but current is '{}'",
                    kind.as_str(),
                    existing.kind.as_str()
                )));
            }
            if existing.durable != durable {
                return Err(BrokerError::precondition_failed(format!(
                    "PRECONDITION_FAILED - inequivalent arg 'durable' for exchange '{name}' in \
                     vhost '/': received '{durable}' but current is '{}'",
                    existing.durable
                )));
            }
            return Ok(());
        }
        if self.exchanges.len() >= MAX_EXCHANGES {
            return Err(BrokerError::resource_error(format!(
                "RESOURCE_ERROR - this broker already holds its limit of {MAX_EXCHANGES} \
                 exchanges"
            )));
        }
        self.exchanges.insert(
            name.to_string(),
            Exchange {
                kind,
                durable,
                auto_delete,
                internal,
                bindings: Vec::new(),
            },
        );
        Ok(())
    }

    /// Delete an exchange, refusing when `if_unused` and something is bound to it.
    pub fn delete_exchange(&mut self, name: &str, if_unused: bool) -> Result<(), BrokerError> {
        let exchange = self.exchange(name)?;
        if if_unused && !exchange.bindings.is_empty() {
            return Err(BrokerError::precondition_failed(format!(
                "PRECONDITION_FAILED - exchange '{name}' in vhost '/' in use"
            )));
        }
        if is_predeclared(name) {
            return Err(BrokerError::precondition_failed(format!(
                "PRECONDITION_FAILED - cannot delete the predeclared exchange '{name}' in vhost \
                 '/'"
            )));
        }
        self.exchanges.remove(name);
        Ok(())
    }

    /// Declare a queue, or check that one exists (`passive`), reporting what it holds.
    ///
    /// A declaration that names no queue is given a server-generated name, which is what
    /// a client asking for an exclusive queue of its own relies on.
    pub fn declare_queue(
        &mut self,
        declaration: &QueueDeclaration<'_>,
        now: SystemTime,
    ) -> Result<QueueState, BrokerError> {
        let QueueDeclaration {
            name,
            passive,
            durable,
            exclusive,
            auto_delete,
            arguments,
        } = *declaration;
        if passive {
            self.expire_due(now);
            return self.queue_state(name);
        }
        let name = if name.is_empty() {
            self.generate_queue_name(now)
        } else {
            name.to_string()
        };
        if let Some(existing) = self.queues.get(&name) {
            for (argument, received, current) in [
                ("durable", durable, existing.durable),
                ("exclusive", exclusive, existing.exclusive),
                ("auto_delete", auto_delete, existing.auto_delete),
            ] {
                if received != current {
                    return Err(BrokerError::precondition_failed(format!(
                        "PRECONDITION_FAILED - inequivalent arg '{argument}' for queue '{name}' \
                         in vhost '/': received '{received}' but current is '{current}'"
                    )));
                }
            }
            if existing.arguments != *arguments {
                return Err(BrokerError::precondition_failed(format!(
                    "PRECONDITION_FAILED - inequivalent args for queue '{name}' in vhost '/'"
                )));
            }
            self.expire_due(now);
            return self.queue_state(&name);
        }
        if self.queues.len() >= MAX_QUEUES {
            return Err(BrokerError::resource_error(format!(
                "RESOURCE_ERROR - this broker already holds its limit of {MAX_QUEUES} queues"
            )));
        }
        if let Some(exchange) = argument_text(arguments, ARG_DEAD_LETTER_EXCHANGE) {
            // The exchange a queue dead-letters to need not exist yet (RabbitMQ accepts
            // the argument either way), but its name has to be a name.
            if exchange.len() > u8::MAX as usize {
                return Err(BrokerError::precondition_failed(format!(
                    "PRECONDITION_FAILED - invalid arg '{ARG_DEAD_LETTER_EXCHANGE}' for queue \
                     '{name}' in vhost '/'"
                )));
            }
        }
        self.queues.insert(
            name.clone(),
            Queue {
                durable,
                exclusive,
                auto_delete,
                arguments: arguments.clone(),
                messages: VecDeque::new(),
                consumers: 0,
            },
        );
        // Every queue is bound to the default exchange under its own name, which is what
        // makes a publish to `""` reach the queue the routing key names.
        self.queue_state(&name)
    }

    /// Bind a queue to an exchange under `routing_key`.
    pub fn bind_queue(
        &mut self,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    ) -> Result<(), BrokerError> {
        self.queue(queue)?;
        self.exchange(exchange)?;
        let binding = Binding {
            queue: queue.to_string(),
            routing_key: routing_key.to_string(),
            arguments: arguments.clone(),
        };
        let held = self
            .exchanges
            .get(exchange)
            .map_or(0, |exchange| exchange.bindings.len());
        if held >= MAX_BINDINGS_PER_EXCHANGE {
            return Err(BrokerError::resource_error(format!(
                "RESOURCE_ERROR - exchange '{exchange}' in vhost '/' already holds its limit of \
                 {MAX_BINDINGS_PER_EXCHANGE} bindings"
            )));
        }
        if let Some(exchange) = self.exchanges.get_mut(exchange) {
            let already = exchange.bindings.iter().any(|existing| {
                existing.queue == binding.queue
                    && existing.routing_key == binding.routing_key
                    && existing.arguments == binding.arguments
            });
            if !already {
                exchange.bindings.push(binding);
            }
        }
        Ok(())
    }

    /// Drop a binding. A binding that is not there is not an error: AMQP's unbind is
    /// idempotent on the state, and RabbitMQ answers it with `unbind-ok`.
    ///
    /// An exchange declared `auto_delete` that has just lost its last binding goes with
    /// it, which is what that flag means.
    pub fn unbind_queue(
        &mut self,
        queue: &str,
        exchange: &str,
        routing_key: &str,
    ) -> Result<(), BrokerError> {
        self.queue(queue)?;
        self.exchange(exchange)?;
        if let Some(record) = self.exchanges.get_mut(exchange) {
            record
                .bindings
                .retain(|binding| !(binding.queue == queue && binding.routing_key == routing_key));
        }
        self.collect_auto_deleted_exchange(exchange);
        Ok(())
    }

    /// Delete an exchange declared `auto_delete` that holds no binding any more. Every
    /// path that can drop a binding goes through here, so such an exchange cannot
    /// outlive its last binding on one path and not on another.
    fn collect_auto_deleted_exchange(&mut self, exchange: &str) {
        let orphaned = self.exchanges.get(exchange).is_some_and(|record| {
            record.auto_delete && record.bindings.is_empty() && !is_predeclared(exchange)
        });
        if orphaned {
            self.exchanges.remove(exchange);
        }
    }

    /// Delete a queue, reporting how many messages went with it.
    pub fn delete_queue(
        &mut self,
        name: &str,
        if_unused: bool,
        if_empty: bool,
    ) -> Result<u32, BrokerError> {
        let queue = self.queue(name)?;
        if if_unused && queue.consumers > 0 {
            return Err(BrokerError::precondition_failed(format!(
                "PRECONDITION_FAILED - queue '{name}' in vhost '/' in use"
            )));
        }
        if if_empty && !queue.messages.is_empty() {
            return Err(BrokerError::precondition_failed(format!(
                "PRECONDITION_FAILED - queue '{name}' in vhost '/' not empty"
            )));
        }
        let removed = match self.queues.remove(name) {
            None => 0,
            Some(queue) => {
                let bytes: usize = queue.messages.iter().map(|message| message.body.len()).sum();
                self.held_bytes = self.held_bytes.saturating_sub(bytes);
                queue.messages.len()
            }
        };
        for exchange in self.exchanges.values_mut() {
            exchange.bindings.retain(|binding| binding.queue != name);
        }
        let bound: Vec<String> = self.exchanges.keys().cloned().collect();
        for exchange in bound {
            self.collect_auto_deleted_exchange(&exchange);
        }
        Ok(u32::try_from(removed).unwrap_or(u32::MAX))
    }

    /// Drop every message waiting in a queue, reporting how many there were.
    pub fn purge_queue(&mut self, name: &str) -> Result<u32, BrokerError> {
        self.queue(name)?;
        let mut purged = 0;
        let mut bytes = 0usize;
        if let Some(queue) = self.queues.get_mut(name) {
            purged = queue.messages.len();
            bytes = queue.messages.iter().map(|message| message.body.len()).sum();
            queue.messages.clear();
        }
        self.held_bytes = self.held_bytes.saturating_sub(bytes);
        Ok(u32::try_from(purged).unwrap_or(u32::MAX))
    }

    /// Route a published message to every queue the exchange sends it to, reporting
    /// whether it reached any — which is what a `mandatory` publish is returned for when
    /// it reached none.
    pub fn publish(
        &mut self,
        exchange: &str,
        routing_key: &str,
        properties: AMQPProperties,
        body: Vec<u8>,
        now: SystemTime,
    ) -> Result<bool, BrokerError> {
        if body.len() > MAX_MESSAGE_BYTES {
            return Err(BrokerError::content_too_large(format!(
                "CONTENT_TOO_LARGE - message body of {} bytes is larger than the {MAX_MESSAGE_BYTES} \
                 bytes this broker accepts",
                body.len()
            )));
        }
        if self.held_bytes.saturating_add(body.len()) > MAX_BROKER_BYTES {
            return Err(BrokerError::resource_error(format!(
                "RESOURCE_ERROR - this broker already holds its limit of {MAX_BROKER_BYTES} bytes \
                 of messages"
            )));
        }
        // The cost of the message in every queue it reaches is checked once the routing
        // is known, below.
        let message = Message::published(exchange, routing_key, properties, body);
        let targets = self.route(exchange, routing_key, &message)?;
        if targets.is_empty() {
            return Ok(false);
        }
        // Every queue the message reached holds its OWN copy, so what a publish costs is
        // the body once per target — checked here, before a copy is made, so a fan-out
        // past the broker's room is refused rather than half stored.
        let cost = message.body.len().saturating_mul(targets.len());
        if self.held_bytes.saturating_add(cost) > MAX_BROKER_BYTES {
            return Err(BrokerError::resource_error(format!(
                "RESOURCE_ERROR - this broker holds {} of its limit of {MAX_BROKER_BYTES} bytes \
                 of messages, and this publish needs {cost} more",
                self.held_bytes
            )));
        }
        self.place(targets, message, now)?;
        Ok(true)
    }

    /// The next message a consumer on `queue` is handed, or `None` when the queue is
    /// empty. The message LEAVES the queue: it is the session's until it acknowledges it
    /// or hands it back ([`Self::requeue`], [`Self::dead_letter`]).
    pub fn take_next(&mut self, queue: &str, now: SystemTime) -> Option<Message> {
        self.expire_queue(queue, now);
        let message = self.queues.get_mut(queue)?.messages.pop_front()?;
        self.held_bytes = self.held_bytes.saturating_sub(message.body.len());
        Some(message)
    }

    /// The next message on `queue` plus how many are left behind it, for a `basic.get`.
    pub fn get(
        &mut self,
        queue: &str,
        now: SystemTime,
    ) -> Result<Option<(Message, u32)>, BrokerError> {
        self.queue(queue)?;
        let Some(message) = self.take_next(queue, now) else {
            return Ok(None);
        };
        let left = self
            .queues
            .get(queue)
            .map_or(0, |queue| queue.messages.len());
        Ok(Some((message, u32::try_from(left).unwrap_or(u32::MAX))))
    }

    /// Hand a message back to the head of its queue, as a consumer that rejects it with
    /// `requeue` does, so the next read sees it again marked redelivered.
    ///
    /// A queue that filled up, or a broker with no room left, drops it rather than
    /// growing past either bound.
    pub fn requeue(&mut self, queue: &str, mut message: Message) {
        message.redelivered = true;
        let len = self.queues.get(queue).map_or(0, |q| q.messages.len());
        if len >= MAX_MESSAGES_PER_QUEUE
            || self
                .held_bytes
                .saturating_add(message.body.len())
                > MAX_BROKER_BYTES
        {
            // The queue filled up while the message was out; it is dropped rather than
            // taking the broker past its bound.
            return;
        }
        let body_len = message.body.len();
        let mut held = false;
        if let Some(target) = self.queues.get_mut(queue) {
            target.messages.push_front(message);
            held = true;
        }
        if held {
            self.held_bytes = self.held_bytes.saturating_add(body_len);
        }
    }

    /// Send a message to its queue's dead-letter exchange, carrying `reason`.
    ///
    /// A queue with no dead-letter exchange drops it, which is what RabbitMQ does.
    pub fn dead_letter(&mut self, queue: &str, message: Message, reason: &str, now: SystemTime) {
        if message.deaths >= MAX_DEATH_HOPS {
            return;
        }
        let Some(record) = self.queues.get(queue) else {
            return;
        };
        let Some(exchange) = record.dead_letter_exchange() else {
            return;
        };
        let routing_key = record
            .dead_letter_routing_key()
            .unwrap_or_else(|| message.routing_key.clone());
        let dead = self.mark_dead(message, queue, reason, now);
        let Ok(targets) = self.route(&exchange, &routing_key, &dead) else {
            return;
        };
        if targets.is_empty() {
            return;
        }
        let mut republished = dead;
        republished.exchange = exchange;
        republished.routing_key = routing_key;
        let _ = self.place(targets, republished, now);
    }

    /// Materialise every expiration the clock has made due: a message at the head of its
    /// queue that has outlived its time to live leaves for the queue's dead-letter
    /// exchange with the reason `expired`.
    ///
    /// RabbitMQ expires a message when it reaches the head of its queue, so this walks
    /// each queue from the front and stops at the first message still alive.
    pub fn expire_due(&mut self, now: SystemTime) {
        let queues: Vec<String> = self.queues.keys().cloned().collect();
        for queue in queues {
            self.expire_queue(&queue, now);
        }
    }

    /// What a declaration reports about one queue.
    pub fn queue_state(&self, name: &str) -> Result<QueueState, BrokerError> {
        let queue = self.queue(name)?;
        Ok(QueueState {
            name: name.to_string(),
            message_count: u32::try_from(queue.messages.len()).unwrap_or(u32::MAX),
            consumer_count: u32::try_from(queue.consumers).unwrap_or(u32::MAX),
        })
    }

    /// How many messages a queue holds right now, for a session deciding whether to
    /// deliver. `None` when the queue is gone.
    pub fn queue_depth(&self, name: &str) -> Option<usize> {
        self.queues.get(name).map(|queue| queue.messages.len())
    }

    /// Record that a session started consuming from `queue`, which is what the queue's
    /// consumer count reports and what an `auto_delete` queue is kept alive by.
    pub fn add_consumer(&mut self, queue: &str) -> Result<(), BrokerError> {
        self.queue(queue)?;
        if let Some(queue) = self.queues.get_mut(queue) {
            queue.consumers = queue.consumers.saturating_add(1);
        }
        Ok(())
    }

    /// Record that a session stopped consuming from `queue`, deleting an `auto_delete`
    /// queue that has just lost its last consumer.
    pub fn remove_consumer(&mut self, queue: &str) {
        let mut orphaned = false;
        if let Some(record) = self.queues.get_mut(queue) {
            record.consumers = record.consumers.saturating_sub(1);
            orphaned = record.consumers == 0 && record.auto_delete;
        }
        if orphaned {
            let _ = self.delete_queue(queue, false, false);
        }
    }

    /// Whether this broker holds a queue under `name`.
    pub fn has_queue(&self, name: &str) -> bool {
        self.queues.contains_key(name)
    }

    /// Whether the queue under `name` was declared EXCLUSIVE, which is what makes it the
    /// property of the one connection that declared it.
    pub fn is_exclusive(&self, name: &str) -> bool {
        self.queues
            .get(name)
            .is_some_and(|queue| queue.exclusive)
    }

    /// Whether this broker holds an exchange under `name`.
    pub fn has_exchange(&self, name: &str) -> bool {
        self.exchanges.contains_key(name)
    }

    /// The queues an exchange routes a message with this routing key and these headers
    /// to, in binding order and without repeating a queue.
    fn route(
        &self,
        exchange: &str,
        routing_key: &str,
        message: &Message,
    ) -> Result<Vec<String>, BrokerError> {
        let record = self.exchange(exchange)?;
        // An INTERNAL exchange is not one a client publishes to: it exists to be the
        // target of other exchanges' bindings, and RabbitMQ refuses a publish to one.
        if record.internal {
            return Err(BrokerError::Channel {
                code: 403,
                text: format!(
                    "ACCESS_REFUSED - cannot publish to internal exchange '{exchange}' in vhost \
                     '/'"
                ),
            });
        }
        // The default exchange routes to the queue the routing key NAMES, which is the
        // binding every queue has to it by construction.
        if exchange == DEFAULT_EXCHANGE {
            return Ok(if self.queues.contains_key(routing_key) {
                vec![routing_key.to_string()]
            } else {
                Vec::new()
            });
        }
        let mut targets: Vec<String> = Vec::new();
        for binding in &record.bindings {
            let matches = match record.kind {
                ExchangeKind::Direct => binding.routing_key == routing_key,
                ExchangeKind::Fanout => true,
                ExchangeKind::Topic => topic_matches(&binding.routing_key, routing_key),
                ExchangeKind::Headers => {
                    headers_match(&binding.arguments, message.properties.headers())
                }
            };
            if matches && !targets.contains(&binding.queue) {
                targets.push(binding.queue.clone());
            }
        }
        targets.retain(|queue| self.queues.contains_key(queue));
        Ok(targets)
    }

    /// Put one message in every queue it was routed to, dead-lettering whatever the
    /// queues' length bounds push out, until nothing is left to place.
    ///
    /// Every copy is accounted against the broker's own room as it is stored, and a copy
    /// there is no room for — or one past [`MAX_PENDING_PLACEMENTS`] waiting copies — is
    /// DROPPED rather than stored: a publish is refused its whole cost up front
    /// ([`Self::publish`]), and what reaches here from an expiry or a length bound has no
    /// caller left to refuse.
    fn place(
        &mut self,
        targets: Vec<String>,
        message: Message,
        now: SystemTime,
    ) -> Result<(), BrokerError> {
        let mut pending: Vec<(String, Message)> = targets
            .into_iter()
            .take(MAX_PENDING_PLACEMENTS)
            .map(|queue| (queue, message.clone()))
            .collect();
        let mut steps = 0usize;
        while let Some((queue, message)) = pending.pop() {
            steps += 1;
            if steps > MAX_PLACEMENT_STEPS {
                return Ok(());
            }
            let Some(record) = self.queues.get(&queue) else {
                continue;
            };
            if record.messages.len() >= MAX_MESSAGES_PER_QUEUE {
                return Err(BrokerError::resource_error(format!(
                    "RESOURCE_ERROR - queue '{queue}' in vhost '/' already holds its limit of \
                     {MAX_MESSAGES_PER_QUEUE} messages"
                )));
            }
            let ttl = [record.message_ttl(), message.published_ttl()]
                .into_iter()
                .flatten()
                .min();
            let max_length = record.max_length();
            let body_len = message.body.len();
            // The room this copy needs, as it is stored: the budget is enforced here
            // because this is where a body is held, whichever path brought it.
            if self.held_bytes.saturating_add(body_len) > MAX_BROKER_BYTES {
                continue;
            }
            let mut held = false;
            if let Some(record) = self.queues.get_mut(&queue) {
                let mut stored = message;
                // An instant the platform's clock cannot represent is no deadline at
                // all: the message keeps waiting rather than the computation failing.
                stored.expires_at = ttl.and_then(|ttl| now.checked_add(ttl));
                record.messages.push_back(stored);
                held = true;
            }
            if held {
                self.held_bytes = self.held_bytes.saturating_add(body_len);
            }
            // A queue past its length bound drops from the FRONT, and what is dropped is
            // dead-lettered with the reason `maxlen`.
            if let Some(bound) = max_length {
                while self
                    .queues
                    .get(&queue)
                    .is_some_and(|record| record.messages.len() > bound.max(1))
                {
                    let Some(dropped) = self.take_front(&queue) else {
                        break;
                    };
                    self.enqueue_dead_letters(&queue, dropped, REASON_MAXLEN, now, &mut pending);
                }
            }
        }
        Ok(())
    }

    /// Take the message at the head of a queue without expiring anything.
    fn take_front(&mut self, queue: &str) -> Option<Message> {
        let message = self.queues.get_mut(queue)?.messages.pop_front()?;
        self.held_bytes = self.held_bytes.saturating_sub(message.body.len());
        Some(message)
    }

    /// Work out where a dead message goes and add it to `pending`, so the caller's own
    /// loop places it: a dead letter is a publish like any other.
    fn enqueue_dead_letters(
        &mut self,
        queue: &str,
        message: Message,
        reason: &str,
        now: SystemTime,
        pending: &mut Vec<(String, Message)>,
    ) {
        if message.deaths >= MAX_DEATH_HOPS {
            return;
        }
        let Some(record) = self.queues.get(queue) else {
            return;
        };
        let Some(exchange) = record.dead_letter_exchange() else {
            return;
        };
        let routing_key = record
            .dead_letter_routing_key()
            .unwrap_or_else(|| message.routing_key.clone());
        let mut dead = self.mark_dead(message, queue, reason, now);
        let Ok(targets) = self.route(&exchange, &routing_key, &dead) else {
            return;
        };
        dead.exchange = exchange;
        dead.routing_key = routing_key;
        for target in targets {
            // One copy per queue the dead letter reaches, and no more waiting at once
            // than the bound on copies in flight.
            if pending.len() >= MAX_PENDING_PLACEMENTS {
                return;
            }
            pending.push((target, dead.clone()));
        }
    }

    /// Expire the messages at the head of one queue that have outlived their time to
    /// live, sending each to the queue's dead-letter exchange.
    fn expire_queue(&mut self, queue: &str, now: SystemTime) {
        let mut pending: Vec<(String, Message)> = Vec::new();
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > MAX_PLACEMENT_STEPS {
                break;
            }
            let due = self.queues.get(queue).is_some_and(|record| {
                record
                    .messages
                    .front()
                    .and_then(|message| message.expires_at)
                    .is_some_and(|expires_at| expires_at <= now)
            });
            if !due {
                break;
            }
            let Some(expired) = self.take_front(queue) else {
                break;
            };
            self.enqueue_dead_letters(queue, expired, REASON_EXPIRED, now, &mut pending);
        }
        for (target, message) in pending {
            let _ = self.place(vec![target], message, now);
        }
    }

    /// The message as a dead-lettering leaves it: its `x-death` history extended with
    /// this death, and its own expiration moved into that record — which is what keeps a
    /// message that expired from expiring again the moment it lands in the dead-letter
    /// queue.
    fn mark_dead(
        &self,
        message: Message,
        queue: &str,
        reason: &str,
        now: SystemTime,
    ) -> Message {
        let mut headers = message.properties.headers().clone().unwrap_or_default();
        let original_expiration = message
            .properties
            .expiration()
            .as_ref()
            .map(|value| value.as_str().to_string());
        let mut entry = FieldTable::default();
        let previous = death_count(&headers, queue, reason);
        entry.insert(
            "count".into(),
            AMQPValue::LongLongInt(previous.saturating_add(1)),
        );
        entry.insert("reason".into(), text_value(reason));
        entry.insert("queue".into(), text_value(queue));
        entry.insert(
            "time".into(),
            AMQPValue::Timestamp(
                now.duration_since(UNIX_EPOCH)
                    .map(|since| since.as_secs())
                    .unwrap_or_default(),
            ),
        );
        entry.insert("exchange".into(), text_value(&message.exchange));
        let mut keys = FieldArray::default();
        keys.push(text_value(&message.routing_key));
        entry.insert("routing-keys".into(), AMQPValue::FieldArray(keys));
        if let Some(expiration) = &original_expiration {
            entry.insert("original-expiration".into(), text_value(expiration));
        }
        // Newest death first, which is the order RabbitMQ writes the history in, and the
        // entry a reader of `x-death[0]` expects to be the death it just caused.
        let mut history = FieldArray::default();
        history.push(AMQPValue::FieldTable(entry));
        if let Some(AMQPValue::FieldArray(existing)) = lookup(&headers, HEADER_DEATH) {
            for held in existing.as_slice() {
                history.push(held.clone());
            }
        }
        let first = history.len() == 1;
        headers.insert(HEADER_DEATH.into(), AMQPValue::FieldArray(history));
        if first {
            headers.insert(HEADER_FIRST_DEATH_REASON.into(), text_value(reason));
            headers.insert(HEADER_FIRST_DEATH_QUEUE.into(), text_value(queue));
            headers.insert(
                HEADER_FIRST_DEATH_EXCHANGE.into(),
                text_value(&message.exchange),
            );
        }
        let properties = properties_with_headers_and_no_expiration(&message.properties, headers);
        Message {
            properties,
            redelivered: false,
            expires_at: None,
            deaths: message.deaths.saturating_add(1),
            ..message
        }
    }

    /// The exchange under `name`, or the 404 a client is answered for one that is not
    /// there.
    fn exchange(&self, name: &str) -> Result<&Exchange, BrokerError> {
        self.exchanges.get(name).ok_or_else(|| {
            BrokerError::not_found(format!("NOT_FOUND - no exchange '{name}' in vhost '/'"))
        })
    }

    /// The queue under `name`, or the 404 a client is answered for one that is not there.
    fn queue(&self, name: &str) -> Result<&Queue, BrokerError> {
        self.queues.get(name).ok_or_else(|| {
            BrokerError::not_found(format!("NOT_FOUND - no queue '{name}' in vhost '/'"))
        })
    }

    /// The name a queue declared without one is given: `amq.gen-` and bits of this
    /// broker's own sequence, so two declarations on one broker cannot collide.
    fn generate_queue_name(&mut self, now: SystemTime) -> String {
        loop {
            let sequence = self.next_generated_name;
            self.next_generated_name = sequence.wrapping_add(1);
            let nanos = now
                .duration_since(UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default();
            let candidate = format!("amq.gen-{nanos:x}-{sequence:x}");
            if !self.queues.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

/// Whether an exchange is one every broker starts with, which no client may delete and
/// which no `auto_delete` collects.
fn is_predeclared(name: &str) -> bool {
    name == DEFAULT_EXCHANGE || name.starts_with("amq.")
}

/// How many times a message has already died in `queue` for `reason`, read off its own
/// `x-death` history — the count RabbitMQ increments rather than restarting.
///
/// The history travels with the message, so the count in it is whatever a publisher put
/// there: a value below zero is no count at all and is read as none.
fn death_count(headers: &FieldTable, queue: &str, reason: &str) -> i64 {
    let Some(AMQPValue::FieldArray(history)) = lookup(headers, HEADER_DEATH) else {
        return 0;
    };
    for entry in history.as_slice() {
        let AMQPValue::FieldTable(entry) = entry else {
            continue;
        };
        let same_queue = lookup(entry, "queue")
            .and_then(value_text)
            .is_some_and(|held| held == queue);
        let same_reason = lookup(entry, "reason")
            .and_then(value_text)
            .is_some_and(|held| held == reason);
        if same_queue && same_reason {
            if let Some(count) = lookup(entry, "count").and_then(value_number) {
                return count.max(0);
            }
        }
    }
    0
}

/// A text field value, in the long-string form RabbitMQ writes `x-death`'s own fields
/// in.
fn text_value(text: &str) -> AMQPValue {
    AMQPValue::LongString(LongString::from(text))
}

/// The text a field value carries, whichever string form it is in.
fn value_text(value: &AMQPValue) -> Option<String> {
    match value {
        AMQPValue::LongString(text) => Some(String::from_utf8_lossy(text.as_bytes()).to_string()),
        AMQPValue::ShortString(text) => Some(text.as_str().to_string()),
        AMQPValue::ByteArray(bytes) => {
            Some(String::from_utf8_lossy(bytes.as_slice()).to_string())
        }
        _ => None,
    }
}

/// The number a field value carries, whichever integer width it is in.
fn value_number(value: &AMQPValue) -> Option<i64> {
    match value {
        AMQPValue::ShortShortInt(number) => Some(i64::from(*number)),
        AMQPValue::ShortShortUInt(number) => Some(i64::from(*number)),
        AMQPValue::ShortInt(number) => Some(i64::from(*number)),
        AMQPValue::ShortUInt(number) => Some(i64::from(*number)),
        AMQPValue::LongInt(number) => Some(i64::from(*number)),
        AMQPValue::LongUInt(number) => Some(i64::from(*number)),
        AMQPValue::LongLongInt(number) => Some(*number),
        AMQPValue::Timestamp(number) => i64::try_from(*number).ok(),
        _ => None,
    }
}

/// The value a field table holds under `name`, looked up by the name's own text so a
/// caller needs no key type.
fn lookup<'a>(table: &'a FieldTable, name: &str) -> Option<&'a AMQPValue> {
    table
        .inner()
        .iter()
        .find(|(key, _)| key.as_str() == name)
        .map(|(_, value)| value)
}

/// The text an argument carries, when the table carries that argument at all.
fn argument_text(arguments: &FieldTable, name: &str) -> Option<String> {
    lookup(arguments, name).and_then(value_text)
}

/// The number an argument carries, when the table carries that argument at all.
fn argument_number(arguments: &FieldTable, name: &str) -> Option<i64> {
    lookup(arguments, name).and_then(value_number)
}

/// Whether a topic binding pattern matches a routing key: the words are separated by
/// `.`, `*` stands for exactly one word and `#` for zero or more.
///
/// The match is walked ONCE from each side, left to right: a `#` takes as few words as
/// it can and is only ever extended by one word when what follows it fails, so no
/// alternative is explored twice and the work is at most the product of the two word
/// counts — never the combinatorial search a pattern of several `#` segments would cost
/// a backtracking matcher. Both sides arrive as AMQP short strings (255 bytes at most),
/// so those counts are bounded by [`MAX_TOPIC_WORDS`], which a longer one is refused by
/// rather than matched.
fn topic_matches(pattern: &str, routing_key: &str) -> bool {
    let pattern = topic_words(pattern);
    let words = topic_words(routing_key);
    if pattern.len() > MAX_TOPIC_WORDS || words.len() > MAX_TOPIC_WORDS {
        return false;
    }
    // Where the pattern and the routing key have been walked to, plus the last `#` seen
    // and how many words it has been made to stand for — the one thing the walk goes
    // back to when a literal after a `#` does not match.
    let mut at_pattern = 0usize;
    let mut at_word = 0usize;
    let mut after_hash: Option<usize> = None;
    let mut hash_took = 0usize;
    while at_word < words.len() {
        let expected = pattern.get(at_pattern).copied();
        let word = words.get(at_word).copied().unwrap_or_default();
        match expected {
            // `#` stands for zero words to begin with; the arm below extends it.
            Some("#") => {
                at_pattern += 1;
                after_hash = Some(at_pattern);
                hash_took = at_word;
            }
            // `*` stands for exactly this one word.
            Some("*") => {
                at_pattern += 1;
                at_word += 1;
            }
            Some(literal) if literal == word => {
                at_pattern += 1;
                at_word += 1;
            }
            // This word does not match: let the last `#` stand for one word more, or
            // there is no match at all.
            _ => match after_hash {
                Some(resume) => {
                    at_pattern = resume;
                    hash_took += 1;
                    at_word = hash_took;
                }
                None => return false,
            },
        }
    }
    // Every word is accounted for: what is left of the pattern may only be `#`, which
    // stands for the empty remainder.
    while pattern.get(at_pattern) == Some(&"#") {
        at_pattern += 1;
    }
    at_pattern == pattern.len()
}

/// The words of a topic pattern or routing key: `.`-separated, and none at all for the
/// empty string.
fn topic_words(value: &str) -> Vec<&str> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split('.').collect()
    }
}

/// Whether a headers binding matches a message's headers: every argument of the binding
/// must match when `x-match` is `all` (the default), and one is enough when it is `any`.
fn headers_match(arguments: &FieldTable, headers: &Option<FieldTable>) -> bool {
    let empty = FieldTable::default();
    let headers = headers.as_ref().unwrap_or(&empty);
    let any = argument_text(arguments, ARG_MATCH)
        .is_some_and(|mode| mode.eq_ignore_ascii_case("any") || mode.eq_ignore_ascii_case("any-with-x"));
    let mut required = 0usize;
    let mut matched = 0usize;
    for (name, expected) in arguments.inner() {
        if name.as_str() == ARG_MATCH {
            continue;
        }
        required += 1;
        if lookup(headers, name.as_str()) == Some(expected) {
            matched += 1;
        }
    }
    if required == 0 {
        return true;
    }
    if any {
        matched > 0
    } else {
        matched == required
    }
}

/// The same properties with `headers` replaced and the `expiration` dropped, which is
/// what a dead-lettered message carries: its remaining time to live is not the new
/// queue's business, and the value it had is kept in `x-death`.
///
/// Written out member by member because the generated properties are opaque: there is a
/// setter per member and no way to clear one.
fn properties_with_headers_and_no_expiration(
    properties: &AMQPProperties,
    headers: FieldTable,
) -> AMQPProperties {
    let mut rebuilt = AMQPProperties::default().with_headers(headers);
    if let Some(value) = properties.content_type() {
        rebuilt = rebuilt.with_content_type(value.clone());
    }
    if let Some(value) = properties.content_encoding() {
        rebuilt = rebuilt.with_content_encoding(value.clone());
    }
    if let Some(value) = properties.delivery_mode() {
        rebuilt = rebuilt.with_delivery_mode(*value);
    }
    if let Some(value) = properties.priority() {
        rebuilt = rebuilt.with_priority(*value);
    }
    if let Some(value) = properties.correlation_id() {
        rebuilt = rebuilt.with_correlation_id(value.clone());
    }
    if let Some(value) = properties.reply_to() {
        rebuilt = rebuilt.with_reply_to(value.clone());
    }
    if let Some(value) = properties.message_id() {
        rebuilt = rebuilt.with_message_id(value.clone());
    }
    if let Some(value) = properties.timestamp() {
        rebuilt = rebuilt.with_timestamp(*value);
    }
    if let Some(value) = properties.kind() {
        rebuilt = rebuilt.with_type(value.clone());
    }
    if let Some(value) = properties.user_id() {
        rebuilt = rebuilt.with_user_id(value.clone());
    }
    if let Some(value) = properties.app_id() {
        rebuilt = rebuilt.with_app_id(value.clone());
    }
    if let Some(value) = properties.cluster_id() {
        rebuilt = rebuilt.with_cluster_id(value.clone());
    }
    rebuilt
}

/// A field table built from `(name, value)` pairs, which is how a declaration's
/// arguments are written where one is needed.
pub fn field_table(entries: &[(&str, AMQPValue)]) -> FieldTable {
    let mut table = FieldTable::default();
    for (name, value) in entries {
        table.insert(ShortString::from(*name), value.clone());
    }
    table
}
