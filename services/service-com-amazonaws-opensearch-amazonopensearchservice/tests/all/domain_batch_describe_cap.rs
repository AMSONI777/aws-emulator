// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the per-request CAP the batch domain read applies to its
//! `DomainNames` list.
//!
//! Every case drives the real wire path — a `restJson1` HTTP request through the
//! multi-service router into the mounted service — so what is asserted is what a
//! client sees. The harness comes from [`super::domain_lifecycle`]; this suite adds
//! no second copy of it.
//!
//! The rule under test: `DescribeDomains` describes at most five domains in one
//! call, so a request whose `DomainNames` carries more ENTRIES than that is refused
//! as a whole with the service's 400 input-validation refusal, before any name is
//! resolved — while a request at or below the cap is answered. The rows therefore
//! span what the rule generalises over: how many entries the list carries (every
//! size up to the cap, the cap itself, one past it, and well past it), whether those
//! names name stored domains, and whether the entries are distinct — because the cap
//! counts the list's entries and not the domains they resolve to.

use serde_json::{json, Value};

use super::control_plane_refusal_wording::message;
use super::domain_lifecycle::{error_code, Answer, Emulator, PREFIX};

/// The cap, stated here rather than read from the implementation: the limit is the
/// requirement, so an expectation that imported the constant the handler states
/// would pass whatever that constant said.
const BATCH_LIMIT: usize = 5;

/// The sentence the refusal carries, likewise spelled out: whole fixed text, with
/// the cap as its only value.
const TOO_MANY_DOMAIN_NAMES: &str = "Please provide a maximum of 5 domain names to describe.";

/// `POST /2021-01-01/opensearch/domain-info` with `names` as its `DomainNames`.
async fn describe_domains(emulator: &Emulator, names: &[String]) -> Answer {
    emulator
        .call(
            "POST",
            &format!("{PREFIX}/opensearch/domain-info"),
            Some(json!({ "DomainNames": names })),
        )
        .await
}

/// `n` distinct domain names, each inside `DomainName`'s `@length(3, 28)` and
/// `^[a-z][a-z0-9\-]+$` (smithy_query query="shape" shape="DomainName").
fn names(prefix: &str, n: usize) -> Vec<String> {
    (0..n).map(|at| format!("{prefix}-{at}")).collect()
}

/// `CreateDomain` for `name`, asserting it was accepted.
async fn create(emulator: &Emulator, name: &str) {
    let answer = emulator.create(json!({ "DomainName": name })).await;
    assert_eq!(
        answer.status, 200,
        "case CreateDomain({name:?}): expected 200, got {} with {:?}",
        answer.status, answer.body
    );
}

/// The `DomainName` of every entry of an accepted answer, in the order reported.
fn reported_names(case: &str, answer: &Answer) -> Vec<String> {
    answer.body["DomainStatusList"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "case {case}: expected a DomainStatusList array, got {:?}",
                answer.body
            )
        })
        .iter()
        .map(|entry| {
            entry["DomainName"]
                .as_str()
                .unwrap_or_else(|| panic!("case {case}: expected a DomainName, got {entry:?}"))
                .to_owned()
        })
        .collect()
}

/// The domains these tests create, so the rows can mix stored and unknown names.
/// There are more of them than the cap, so a request may name only stored domains
/// and still be over it.
const STORED: [&str; 7] = [
    "cap-alpha",
    "cap-beta",
    "cap-gamma",
    "cap-delta",
    "cap-epsilon",
    "cap-zeta",
    "cap-eta",
];

async fn populated() -> Emulator {
    let emulator = Emulator::new();
    for name in STORED {
        create(&emulator, name).await;
    }
    emulator
}

#[tokio::test]
async fn a_batch_naming_more_than_the_cap_is_refused() {
    let emulator = populated().await;
    let stored: Vec<String> = STORED.iter().map(|name| (*name).to_owned()).collect();

    // (case, the DomainNames the request carries). Every row carries MORE than the
    // cap and differs in how: one name past it or far past it, all-stored,
    // all-unknown, mixed, repeats only, and names at the extremes of the member's
    // own length constraint — so the refusal is a property of the list's size.
    let rows: Vec<(&str, Vec<String>)> = vec![
        ("one name past the cap, none of them stored", names("cap-absent", BATCH_LIMIT + 1)),
        ("one name past the cap, every one stored", stored[..BATCH_LIMIT + 1].to_vec()),
        (
            "one name past the cap, stored and unknown mixed",
            vec![
                STORED[0].to_owned(),
                "cap-missing-a".to_owned(),
                STORED[1].to_owned(),
                "cap-missing-b".to_owned(),
                STORED[2].to_owned(),
                "cap-missing-c".to_owned(),
            ],
        ),
        (
            "one name past the cap, every entry the SAME stored domain",
            vec![STORED[0].to_owned(); BATCH_LIMIT + 1],
        ),
        (
            "one name past the cap, every entry the same unknown name",
            vec!["cap-missing-a".to_owned(); BATCH_LIMIT + 1],
        ),
        ("twice the cap", names("cap-absent", BATCH_LIMIT * 2)),
        ("far past the cap", names("cap-absent", 40)),
        (
            "past the cap with the shortest and longest names the member admits",
            vec![
                "abc".to_owned(),
                format!("a{}", "b".repeat(27)),
                "xyz".to_owned(),
                format!("c{}", "d".repeat(27)),
                "pqr".to_owned(),
                format!("e{}", "f".repeat(27)),
            ],
        ),
    ];

    for (case, requested) in rows {
        let answer = describe_domains(&emulator, &requested).await;
        assert_eq!(
            (answer.status, error_code(&answer).as_str()),
            (400, "ValidationException"),
            "case {case:?}: expected the modelled validation refusal for {} names, got {} with \
             {:?}",
            requested.len(),
            answer.status,
            answer.body
        );
        assert_eq!(
            message(&answer),
            TOO_MANY_DOMAIN_NAMES,
            "case {case:?}: expected {TOO_MANY_DOMAIN_NAMES:?}, got {:?}",
            answer.body
        );
        // The sentence carries nothing of the request: not a name it listed and not
        // how many it listed.
        let listed = requested.len().to_string();
        for value in requested
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(listed.as_str()))
        {
            assert!(
                !message(&answer).contains(value),
                "case {case:?}: expected the fixed sentence to carry no {value:?}, got {:?}",
                answer.body
            );
        }
        assert!(
            answer.body["DomainStatusList"].is_null(),
            "case {case:?}: a refused batch must report no domain at all, got {:?}",
            answer.body
        );
    }

    // The refusal is a refusal, not a side effect: the store holds exactly the
    // domains that were created.
    assert_eq!(
        emulator.store().lock().domains.len(),
        STORED.len(),
        "a refused batch must create and remove no domain"
    );
}

#[tokio::test]
async fn a_batch_at_or_below_the_cap_is_answered() {
    let emulator = populated().await;

    // (case, the DomainNames the request carries, the names expected in the answer).
    // Every size from none up to the cap itself, with stored, unknown and repeated
    // entries — so the accepted side of the bound is asserted at the bound and
    // everywhere below it.
    let rows: Vec<(&str, Vec<String>, Vec<String>)> = vec![
        ("no names at all", vec![], vec![]),
        (
            "one stored name",
            vec![STORED[1].to_owned()],
            vec![STORED[1].to_owned()],
        ),
        (
            "two stored names",
            vec![STORED[2].to_owned(), STORED[0].to_owned()],
            vec![STORED[2].to_owned(), STORED[0].to_owned()],
        ),
        (
            "three names, one of them unknown",
            vec![
                STORED[3].to_owned(),
                "cap-missing-a".to_owned(),
                STORED[4].to_owned(),
            ],
            vec![STORED[3].to_owned(), STORED[4].to_owned()],
        ),
        ("four unknown names", names("cap-absent", 4), vec![]),
        (
            "the cap exactly, every name stored",
            STORED[..BATCH_LIMIT]
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            STORED[..BATCH_LIMIT]
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        ),
        (
            "the cap exactly, every entry the same stored domain",
            vec![STORED[5].to_owned(); BATCH_LIMIT],
            vec![STORED[5].to_owned()],
        ),
    ];

    for (case, requested, expected) in rows {
        let answer = describe_domains(&emulator, &requested).await;
        assert_eq!(
            answer.status, 200,
            "case {case:?}: expected {} names to be answered, got {} with {:?}",
            requested.len(),
            answer.status,
            answer.body
        );
        let actual = reported_names(case, &answer);
        assert_eq!(
            actual, expected,
            "case {case:?}: expected {expected:?}, got {actual:?}"
        );
    }
}

#[tokio::test]
async fn the_cap_counts_the_lists_entries_rather_than_the_domains_they_name() {
    let emulator = populated().await;
    let one = STORED[0].to_owned();

    // The same single domain, named the cap's many times and then once more: the
    // first is answered — with ONE entry, because a domain has one status — and the
    // second is refused, so what the cap bounds is the list the request carried.
    let at_the_cap = describe_domains(&emulator, &vec![one.clone(); BATCH_LIMIT]).await;
    let case = "the cap's many entries, all one domain";
    assert_eq!(
        at_the_cap.status, 200,
        "case {case:?}: expected 200, got {} with {:?}",
        at_the_cap.status, at_the_cap.body
    );
    assert_eq!(
        reported_names(case, &at_the_cap),
        vec![one.clone()],
        "case {case:?}: expected the one domain reported once, got {:?}",
        at_the_cap.body
    );

    let past_the_cap = describe_domains(&emulator, &vec![one.clone(); BATCH_LIMIT + 1]).await;
    let case = "one entry past the cap, all one domain";
    assert_eq!(
        (past_the_cap.status, error_code(&past_the_cap).as_str()),
        (400, "ValidationException"),
        "case {case:?}: expected the modelled validation refusal, got {} with {:?}",
        past_the_cap.status,
        past_the_cap.body
    );
    assert_eq!(
        message(&past_the_cap),
        TOO_MANY_DOMAIN_NAMES,
        "case {case:?}: expected {TOO_MANY_DOMAIN_NAMES:?}, got {:?}",
        past_the_cap.body
    );

    // Refused before any name is resolved: a request over the cap naming only
    // domains that do not exist is refused exactly like one naming only stored
    // ones, so the refusal is decided on the request alone.
    let unknown = describe_domains(&emulator, &names("cap-nothing", BATCH_LIMIT + 1)).await;
    assert_eq!(
        (unknown.status, message(&unknown)),
        (past_the_cap.status, message(&past_the_cap)),
        "an over-cap batch of unknown names must be refused exactly like one of stored names, \
         got {} with {:?}",
        unknown.status,
        unknown.body
    );

    // And the refusal left the domains readable as they were.
    for name in STORED {
        let single = emulator.describe(name).await;
        assert_eq!(
            single.status, 200,
            "case {name:?}: expected the domain to still be readable, got {} with {:?}",
            single.status, single.body
        );
        assert_eq!(
            single.body["DomainStatus"]["DomainName"],
            Value::String(name.to_owned()),
            "case {name:?}: expected the stored record, got {:?}",
            single.body
        );
    }
}
