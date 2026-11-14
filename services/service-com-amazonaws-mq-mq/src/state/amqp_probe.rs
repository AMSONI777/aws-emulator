// SPDX-License-Identifier: CC0-1.0

//! PROBES of the AMQP data plane, driven against the message broker directly rather
//! than over a socket: the readings a wire session cannot show whole because they are
//! the CLOCK's.
//!
//! A session on a broker's socket shows what a client sees; what it cannot show is a
//! reading at an instant the test chooses. These probes hand
//! [`super::rabbitmq_plane::message_broker::MessageBroker`] the instant each call
//! happens at, so an expiration coming due, the `x-death` history a message accumulates
//! as it dies in one queue after another, and the length bound that pushes a message out
//! are each read at a known instant instead of waited for.
//!
//! The suite that drives the same broker over its published `amqps://` endpoint, as a
//! client does, is the crate's `rabbitmq_data_plane` integration test.

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use ::amq_protocol::protocol::basic::AMQPProperties;
    use ::amq_protocol::types::{AMQPValue, FieldTable, LongString, ShortString};

    use crate::state::message_broker::{
        field_table, MessageBroker, QueueDeclaration, MAX_MESSAGES_PER_QUEUE, MAX_MESSAGE_TTL,
        REASON_EXPIRED, REASON_MAXLEN, REASON_REJECTED,
    };

    /// The instant every probe starts at: a fixed point, so what a reading depends on is
    /// the span the probe adds to it and never the host's own clock.
    fn start() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// The text a field value carries, as a client reads one.
    fn text(value: &AMQPValue) -> String {
        match value {
            AMQPValue::LongString(value) => String::from_utf8_lossy(value.as_bytes()).to_string(),
            AMQPValue::ShortString(value) => value.as_str().to_string(),
            other => panic!("expected a text field value, got {other:?}"),
        }
    }

    /// The newest `x-death` entry of a message's headers: the death it just suffered.
    fn newest_death(properties: &AMQPProperties) -> FieldTable {
        let headers = properties
            .headers()
            .clone()
            .expect("a dead-lettered message carries headers");
        let (_, death) = headers
            .inner()
            .iter()
            .find(|(name, _)| name.as_str() == "x-death")
            .expect("a dead-lettered message carries an x-death history");
        let AMQPValue::FieldArray(history) = death else {
            panic!("expected x-death to be an array, got {death:?}");
        };
        let AMQPValue::FieldTable(newest) = history
            .as_slice()
            .first()
            .expect("the history carries the death that just happened")
            .clone()
        else {
            panic!("expected an x-death entry to be a table");
        };
        newest
    }

    /// The value one `x-death` entry carries under `name`.
    fn death_field(entry: &FieldTable, name: &str) -> AMQPValue {
        entry
            .inner()
            .iter()
            .find(|(held, _)| held.as_str() == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("expected the x-death entry to carry {name:?}, got {entry:?}"))
    }

    /// A broker holding a queue that dead-letters to a fanout exchange, and the queue
    /// bound to that exchange: `(broker, live queue, dead-letter queue)`.
    fn broker_with_dead_letters(arguments: &[(&str, AMQPValue)]) -> (MessageBroker, String, String) {
        let mut broker = MessageBroker::default();
        broker
            .declare_exchange("probe.dlx", "fanout", false, true, false, false)
            .expect("the dead-letter exchange is declared");
        broker
            .declare_queue(
                &QueueDeclaration {
                    name: "probe.dead",
                    passive: false,
                    durable: true,
                    exclusive: false,
                    auto_delete: false,
                    arguments: &FieldTable::default(),
                },
                start(),
            )
            .expect("the dead-letter queue is declared");
        broker
            .bind_queue("probe.dead", "probe.dlx", "", &FieldTable::default())
            .expect("the dead-letter queue is bound");
        let mut declared: Vec<(&str, AMQPValue)> = vec![(
            "x-dead-letter-exchange",
            AMQPValue::LongString(LongString::from("probe.dlx")),
        )];
        declared.extend_from_slice(arguments);
        broker
            .declare_queue(
                &QueueDeclaration {
                    name: "probe.live",
                    passive: false,
                    durable: true,
                    exclusive: false,
                    auto_delete: false,
                    arguments: &field_table(&declared),
                },
                start(),
            )
            .expect("the live queue is declared");
        (broker, "probe.live".to_string(), "probe.dead".to_string())
    }

    /// RULE: a topic exchange routes a message to a queue when the binding's pattern
    /// matches the routing key word by word, with `*` standing for exactly one word and
    /// `#` for zero or more — and the match is decided by walking each side once, so a
    /// pattern built of many `#` segments is answered rather than searched.
    ///
    /// The rows span the pattern forms the match generalises over: a bare `#`, a `#` at
    /// either end and in the middle, `*` alone and mixed with literals, the empty
    /// pattern and the empty routing key, more `#` segments than words, and the
    /// adversarial shape a backtracking matcher cannot finish — many `#` segments and a
    /// literal that never matches, against a routing key of many words.
    #[test]
    fn a_topic_binding_matches_its_pattern_word_by_word() {
        // The pattern a backtracking matcher explodes on: `#.a` twenty times over,
        // ending in a literal the routing key does not carry.
        let adversarial_pattern = ["#.a"; 20].join(".") + ".z";
        let adversarial_key = ["a"; 60].join(".");
        let rows: &[(&str, &str, &str, bool)] = &[
            ("a bare hash", "#", "orders.new.eu", true),
            ("a hash at the end", "orders.#", "orders", true),
            ("a hash in the middle", "orders.#.eu", "orders.new.fast.eu", true),
            ("a hash at the start", "#.eu", "orders.new.eu", true),
            ("a star stands for one word", "*.eu", "orders.eu", true),
            ("a star does not stand for two", "*.eu", "orders.new.eu", false),
            ("a star between literals", "orders.*.eu", "orders.new.eu", true),
            ("a star needs its word", "orders.*.eu", "orders.eu", false),
            ("a literal that does not match", "orders.new", "orders.old", false),
            ("more hashes than words", "#.#.#", "orders.new", true),
            ("the empty pattern takes nothing", "", "orders", false),
            ("the empty routing key", "#", "", true),
            ("the empty routing key against a literal", "orders", "", false),
            (
                "many hashes and a literal that never matches",
                adversarial_pattern.as_str(),
                adversarial_key.as_str(),
                false,
            ),
        ];
        let now = start();
        for (case, pattern, routing_key, expected) in rows {
            let mut broker = MessageBroker::default();
            broker
                .declare_exchange("probe.topic", "topic", false, true, false, false)
                .expect("the topic exchange is declared");
            broker
                .declare_queue(
                    &QueueDeclaration {
                        name: "probe.topic.queue",
                        passive: false,
                        durable: true,
                        exclusive: false,
                        auto_delete: false,
                        arguments: &FieldTable::default(),
                    },
                    now,
                )
                .expect("the queue is declared");
            broker
                .bind_queue(
                    "probe.topic.queue",
                    "probe.topic",
                    pattern,
                    &FieldTable::default(),
                )
                .expect("the queue is bound");
            let routed = broker
                .publish(
                    "probe.topic",
                    routing_key,
                    AMQPProperties::default(),
                    b"topic".to_vec(),
                    now,
                )
                .expect("the publish is accepted");
            assert_eq!(
                routed, *expected,
                "case {case:?}: pattern {pattern:?} against {routing_key:?} expected \
                 {expected}, got {routed}"
            );
            let depth = broker.queue_depth("probe.topic.queue");
            assert_eq!(
                depth,
                Some(usize::from(*expected)),
                "case {case:?}: expected the queue to hold the matching message only, got \
                 {depth:?}"
            );
        }
    }

    /// RULE: a message that outlives its time to live leaves its queue for that queue's
    /// dead-letter exchange, and not a moment before — read at instants the probe
    /// chooses rather than waited for.
    ///
    /// The rows span where the time to live comes from (the queue's own argument, the
    /// publisher's expiration, both at once with the shorter one winning) and the instant
    /// it is read at (before it is due, at the instant it is due, well after).
    #[test]
    fn a_message_expires_exactly_when_the_clock_makes_it_due() {
        let rows: &[(&str, Option<i32>, Option<&str>, u64)] = &[
            ("the queue's own time to live", Some(5_000), None, 5),
            ("the publisher's expiration", None, Some("2000"), 2),
            (
                "both, the shorter one winning",
                Some(9_000),
                Some("3000"),
                3,
            ),
        ];
        for (case, queue_ttl, expiration, due_after_secs) in rows {
            let arguments: Vec<(&str, AMQPValue)> = queue_ttl
                .map(|ttl| vec![("x-message-ttl", AMQPValue::LongInt(ttl))])
                .unwrap_or_default();
            let (mut broker, live, dead) = broker_with_dead_letters(&arguments);
            let mut properties = AMQPProperties::default().with_delivery_mode(2);
            if let Some(expiration) = expiration {
                properties = properties.with_expiration(ShortString::from(*expiration));
            }
            broker
                .publish("", &live, properties, b"probe".to_vec(), start())
                .expect("the message is published");

            // A moment before it is due: still in its own queue, and nothing in the
            // dead-letter queue.
            let before = start() + Duration::from_secs(*due_after_secs) - Duration::from_millis(1);
            broker.expire_due(before);
            assert_eq!(
                broker.queue_depth(&live),
                Some(1),
                "case {case:?}: expected the message to still be in {live:?} before its time to \
                 live is due, got {:?}",
                broker.queue_depth(&live)
            );
            assert_eq!(
                broker.queue_depth(&dead),
                Some(0),
                "case {case:?}: expected nothing in {dead:?} before the time to live is due, got \
                 {:?}",
                broker.queue_depth(&dead)
            );

            // The instant it is due: the message is in the dead-letter queue, carrying
            // the reason and the queue it died in.
            let due = start() + Duration::from_secs(*due_after_secs);
            broker.expire_due(due);
            assert_eq!(
                broker.queue_depth(&live),
                Some(0),
                "case {case:?}: expected the message to leave {live:?} once its time to live is \
                 due, got {:?}",
                broker.queue_depth(&live)
            );
            let (message, left) = broker
                .get(&dead, due)
                .expect("the dead-letter queue is readable")
                .unwrap_or_else(|| {
                    panic!("case {case:?}: expected the expired message to reach {dead:?}")
                });
            assert_eq!(
                left, 0,
                "case {case:?}: expected the one expired message in {dead:?}, got {left} more"
            );
            let death = newest_death(&message.properties);
            assert_eq!(
                text(&death_field(&death, "reason")),
                REASON_EXPIRED,
                "case {case:?}: expected the reason an expiration gives, got {death:?}"
            );
            assert_eq!(
                text(&death_field(&death, "queue")),
                live,
                "case {case:?}: expected x-death to name the queue it died in, got {death:?}"
            );
            // The expiration itself does not travel with the message: it is recorded in
            // the death, so the message does not expire again the moment it lands.
            if let Some(expiration) = expiration {
                assert_eq!(
                    text(&death_field(&death, "original-expiration")),
                    *expiration,
                    "case {case:?}: expected the publisher's expiration to be kept in the death, \
                     got {death:?}"
                );
            }
            assert_eq!(
                message.properties.expiration(),
                &None,
                "case {case:?}: expected the dead message to carry no expiration of its own, got \
                 {:?}",
                message.properties
            );
            assert_eq!(
                broker.queue_depth(&dead),
                Some(0),
                "case {case:?}: expected the dead-letter queue to be empty once read, got {:?}",
                broker.queue_depth(&dead)
            );
        }
    }

    /// RULE: a time to live and a death count a CLIENT chooses are values the broker
    /// computes with, so neither may take it past what it can represent: a time to live
    /// is held to the longest span the broker computes an instant for, and a death count
    /// a message arrives carrying is counted on from where it is rather than overflowing.
    #[test]
    fn a_client_chosen_time_to_live_and_death_count_cannot_overflow_the_broker() {
        // The largest number of milliseconds a publisher can write into `expiration`.
        let (mut broker, live, dead) = broker_with_dead_letters(&[]);
        broker
            .publish(
                "",
                &live,
                AMQPProperties::default().with_expiration(ShortString::from(
                    u64::MAX.to_string().as_str(),
                )),
                b"forever".to_vec(),
                start(),
            )
            .expect("the message is published");
        // Held to the broker's own ceiling rather than to an instant nothing can
        // compute: well inside it the message is still waiting.
        broker.expire_due(start() + Duration::from_secs(60 * 60 * 24));
        assert_eq!(
            broker.queue_depth(&live),
            Some(1),
            "expected a message whose time to live was clamped to still be waiting a day \
             later, got {:?}",
            broker.queue_depth(&live)
        );
        // Past the ceiling it is due, and the clock makes it due exactly once.
        broker.expire_due(start() + MAX_MESSAGE_TTL + Duration::from_secs(1));
        assert_eq!(
            broker.queue_depth(&live),
            Some(0),
            "expected the clamped time to live to come due, got {:?}",
            broker.queue_depth(&live)
        );
        assert_eq!(
            broker.queue_depth(&dead),
            Some(1),
            "expected the expired message in the dead-letter queue, got {:?}",
            broker.queue_depth(&dead)
        );

        // A death count the message arrives carrying, at the largest value its field can
        // hold: the next death counts on from it rather than overflowing.
        let (mut broker, live, dead) = broker_with_dead_letters(&[]);
        let mut history = ::amq_protocol::types::FieldArray::default();
        let mut claimed = FieldTable::default();
        claimed.insert(
            "count".into(),
            AMQPValue::LongLongInt(i64::MAX),
        );
        claimed.insert(
            "reason".into(),
            AMQPValue::LongString(LongString::from(REASON_REJECTED)),
        );
        claimed.insert(
            "queue".into(),
            AMQPValue::LongString(LongString::from(live.as_str())),
        );
        history.push(AMQPValue::FieldTable(claimed));
        let mut headers = FieldTable::default();
        headers.insert("x-death".into(), AMQPValue::FieldArray(history));
        broker
            .publish(
                "",
                &live,
                AMQPProperties::default().with_headers(headers),
                b"claimed".to_vec(),
                start(),
            )
            .expect("the message is published");
        let taken = broker
            .take_next(&live, start())
            .expect("the message is in its queue");
        broker.dead_letter(&live, taken, REASON_REJECTED, start());
        let message = broker
            .take_next(&dead, start())
            .expect("the rejected message reached the dead-letter queue");
        let death = newest_death(&message.properties);
        assert_eq!(
            death_field(&death, "count"),
            AMQPValue::LongLongInt(i64::MAX),
            "expected the count to hold at what its field can carry, got {death:?}"
        );
    }

    /// RULE: every death a message suffers is recorded, newest first, and a second death
    /// in the same queue for the same reason raises that entry's count rather than
    /// starting a new history.
    #[test]
    fn a_death_is_counted_in_the_history_the_message_carries() {
        let (mut broker, live, dead) = broker_with_dead_letters(&[]);
        // The dead-letter queue dead-letters back to the same exchange, so a message
        // that dies twice has two entries in its history.
        let now = start();
        broker
            .publish(
                "",
                &live,
                AMQPProperties::default(),
                b"counted".to_vec(),
                now,
            )
            .expect("the message is published");
        let taken = broker
            .take_next(&live, now)
            .expect("the message is in its queue");
        broker.dead_letter(&live, taken, REASON_REJECTED, now);
        let first = broker
            .take_next(&dead, now)
            .expect("the rejected message reached the dead-letter queue");
        let death = newest_death(&first.properties);
        assert_eq!(
            text(&death_field(&death, "reason")),
            REASON_REJECTED,
            "expected the reason a rejection gives, got {death:?}"
        );
        assert_eq!(
            death_field(&death, "count"),
            AMQPValue::LongLongInt(1),
            "expected the first death to be counted once, got {death:?}"
        );
        assert_eq!(
            text(&death_field(&death, "exchange")),
            "",
            "expected x-death to name the exchange the message was published to, got {death:?}"
        );

        // The same message rejected again in the same queue: the history's own count
        // rises rather than restarting.
        broker
            .publish(
                "",
                &live,
                first.properties.clone(),
                b"counted".to_vec(),
                now,
            )
            .expect("the message is published again");
        let again = broker
            .take_next(&live, now)
            .expect("the message is in its queue");
        broker.dead_letter(&live, again, REASON_REJECTED, now);
        let second = broker
            .take_next(&dead, now)
            .expect("the rejected message reached the dead-letter queue");
        let death = newest_death(&second.properties);
        assert_eq!(
            death_field(&death, "count"),
            AMQPValue::LongLongInt(2),
            "expected the second death in the same queue to raise the count, got {death:?}"
        );
    }

    /// RULE: a queue holds no more than the length bound it was declared with, and what
    /// the bound pushes out is dead-lettered with the reason a full queue gives — while
    /// a queue with no bound of its own is held to the broker's own ceiling.
    #[test]
    fn a_full_queue_pushes_its_oldest_message_out_to_the_dead_letter_exchange() {
        let (mut broker, live, dead) = broker_with_dead_letters(&[(
            "x-max-length",
            AMQPValue::LongInt(2),
        )]);
        let now = start();
        for sequence in 0..4u8 {
            broker
                .publish(
                    "",
                    &live,
                    AMQPProperties::default(),
                    vec![b'a' + sequence],
                    now,
                )
                .expect("the message is published");
        }
        assert_eq!(
            broker.queue_depth(&live),
            Some(2),
            "expected the queue to hold no more than its bound, got {:?}",
            broker.queue_depth(&live)
        );
        assert_eq!(
            broker.queue_depth(&dead),
            Some(2),
            "expected everything the bound pushed out to be dead-lettered, got {:?}",
            broker.queue_depth(&dead)
        );
        // What is pushed out is the OLDEST message, and it carries the reason a full
        // queue gives.
        let (oldest, _) = broker
            .get(&dead, now)
            .expect("the dead-letter queue is readable")
            .expect("the pushed-out message is there");
        assert_eq!(
            oldest.body,
            b"a".to_vec(),
            "expected the oldest message to be the one pushed out, got {:?}",
            String::from_utf8_lossy(&oldest.body)
        );
        let death = newest_death(&oldest.properties);
        assert_eq!(
            text(&death_field(&death, "reason")),
            REASON_MAXLEN,
            "expected the reason a full queue gives, got {death:?}"
        );
        // What is left is the newest messages, in publication order.
        let (first, _) = broker
            .get(&live, now)
            .expect("the queue is readable")
            .expect("the queue holds its bound");
        assert_eq!(
            first.body,
            b"c".to_vec(),
            "expected the queue to hold the newest messages in order, got {:?}",
            String::from_utf8_lossy(&first.body)
        );

        // A queue with no bound of its own is still bounded: the broker's own ceiling is
        // what a publish past it is refused by, rather than growing without end.
        let mut broker = MessageBroker::default();
        broker
            .declare_queue(
                &QueueDeclaration {
                    name: "probe.unbounded",
                    passive: false,
                    durable: true,
                    exclusive: false,
                    auto_delete: false,
                    arguments: &FieldTable::default(),
                },
                now,
            )
            .expect("the queue is declared");
        for sequence in 0..MAX_MESSAGES_PER_QUEUE {
            broker
                .publish(
                    "",
                    "probe.unbounded",
                    AMQPProperties::default(),
                    b"filling".to_vec(),
                    now,
                )
                .unwrap_or_else(|error| {
                    panic!("message {sequence} must be accepted below the ceiling, got {error:?}")
                });
        }
        let refused = broker.publish(
            "",
            "probe.unbounded",
            AMQPProperties::default(),
            b"one too many".to_vec(),
            now,
        );
        assert!(
            refused.is_err(),
            "expected a publish past the broker's own ceiling to be refused, got {refused:?}"
        );
        assert_eq!(
            broker.queue_depth("probe.unbounded"),
            Some(MAX_MESSAGES_PER_QUEUE),
            "expected the queue to hold exactly the ceiling, got {:?}",
            broker.queue_depth("probe.unbounded")
        );
    }
}
