// SPDX-License-Identifier: CC0-1.0

//! The readings this service's front door makes about a request it refuses, driven
//! over the wire through an operation on each side of them (the shared harness is
//! `crate::wire`, the shared expectations `crate::support`).
//!
//! One rule, two halves, asserted over a table spanning the class:
//!
//! * a value outside a modelled member constraint is placed by the HTTP BINDING the
//!   model gives the violated member — a member the operation carries in the request
//!   body earns the front door's `BadRequestException` and its one member-free
//!   sentence, while a member bound to the request URI (`@httpQuery`, `@httpLabel`,
//!   `@httpHeader`) keeps the modelled `ValidationException` whose `fieldList` names
//!   it — and a violation path that descends INTO a member's value is placed by its
//!   first segment, the top-level member the whole subtree hangs off;
//! * a `@pattern` requirement is quoted as the expression a value has to satisfy,
//!   without the whole-value anchors Smithy wraps it in, while every other kind of
//!   requirement stays exactly as the framework states it.
//!
//! The two operations between them cover both halves: every input of
//! `UpdateAccountCustomizations` travels in the body, and both inputs of
//! `ListServices` are `@httpQuery`
//! (`smithy_query(query="operation", operation="UpdateAccountCustomizations")` and
//! `smithy_query(query="operation", operation="ListServices")`).
//!
//! WHICH bodies are refused is `body_validation_refusals`' rule and the pattern
//! rendering's own table is `pattern_refusal_rendering`'s; this suite asserts that
//! the one front door makes both readings for both operations, and that the requests
//! each operation SERVES are answered exactly as before.

use crate::support::{answer, prime, reported_owned, Answer, BODY_MEMBERS};
use crate::wire::{
    build_router, call, catalog_services, encode_query_value, get_customizations, legal_region,
    list_page, list_services_uri, update_customizations,
};
use serde_json::{json, Value};

/// The error code this service's model declares for an input that fails its
/// constraints (`smithy_query(query="operation", operation="ListServices")`), which
/// a value bound to the request URI keeps.
const VALIDATION_EXCEPTION: &str = "ValidationException";

/// The one sentence the front door states about a body it refused: the class of
/// failure, naming no member.
const INVALID_REQUEST_BODY: &str = "Invalid request body";

/// The marker a requirement clause states a pattern after.
const PATTERN_CLAUSE: &str = "Member must satisfy regular expression pattern: ";

/// The `NextToken` `@pattern` as the MODEL writes it, anchors included
/// (`smithy_query(query="shape", shape="NextToken")`).
const NEXT_TOKEN_PATTERN: &str = r"^[-A-Za-z0-9+/_]+=*$";

/// `NextToken`'s modelled `@length` bounds, so a row meant to break the pattern can
/// be checked to break nothing else
/// (`smithy_query(query="operation", operation="ListServices")`).
const NEXT_TOKEN_LENGTH: std::ops::RangeInclusive<usize> = 32..=512;

/// The expression a refusal must quote: [`NEXT_TOKEN_PATTERN`] with the whole-value
/// anchor pair dropped. Derived here rather than written out, so the row states the
/// rule and not one expected string.
fn advertised_pattern() -> String {
    NEXT_TOKEN_PATTERN
        .strip_prefix('^')
        .and_then(|body| body.strip_suffix('$'))
        .expect("the modelled pattern is a whole-value pattern")
        .to_string()
}

/// Where the value one row breaks a constraint with travelled, which is what the
/// front door reads to place the refusal.
enum Sent {
    /// A `ListServices` request carrying this raw query string, breaking the
    /// constraints of these members — and whether the broken requirement is a
    /// `@pattern`, which is quoted differently from every other kind.
    Uri {
        query: String,
        members: Vec<&'static str>,
        pattern: bool,
    },
    /// An `UpdateAccountCustomizations` request carrying this body.
    Body(Value),
}

/// One row of the table: a request outside a modelled constraint, and where its
/// value travelled.
struct Row {
    case: String,
    sent: Sent,
}

/// Every row the rule is asserted over. They differ along which operation is
/// called, where the refused value travelled, which KIND of constraint it broke,
/// how DEEP in the input the violated value sits (a top-level member, an element of
/// a member's list, the list member itself), and how many members one request
/// breaks at once.
fn rows() -> Vec<Row> {
    let over_bound_regions: Vec<String> = (0..101).map(legal_region).collect();
    let mut rows: Vec<Row> = Vec::new();

    // The BODY half. Bounds from
    // `smithy_query(query="shape", shape="AccountColor,ServiceList,RegionsList")`:
    // `AccountColor` is an enum of ten values, `Service` is `@length(1, 64)`
    // `@pattern ^[a-z0-9]+(-[a-z0-9]+)*$` in a list of at most 500, `Region` is
    // `@pattern ^[a-z]{2}(-[a-z]{1,10}){1,2}-[1-9]$` in a list of at most 100.
    for (name, document) in [
        (
            "a top-level member outside the modelled enum",
            json!({"accountColor": "chartreuse"}),
        ),
        (
            "the first element of a list outside its @pattern",
            json!({"visibleServices": ["Not_A_Service!"]}),
        ),
        (
            "a later element of a list outside its @pattern",
            json!({"visibleServices": ["s3", "Not_A_Service!", "ec2"]}),
        ),
        (
            "an element one character past its @length maximum",
            json!({"visibleServices": ["a".repeat(65)]}),
        ),
        (
            "an element of the other list outside its @pattern",
            json!({"visibleRegions": ["US-EAST-1"]}),
        ),
        (
            "a list member one element past its own @length maximum",
            json!({"visibleRegions": over_bound_regions.clone()}),
        ),
        (
            "two members broken by one body",
            json!({"accountColor": "chartreuse", "visibleServices": ["S3"]}),
        ),
    ] {
        rows.push(Row {
            case: format!("{name}, in the request body"),
            sent: Sent::Body(document),
        });
    }

    // The URI half: `maxResults` `@range(1, 1000)` and `nextToken`
    // `@length(32, 512)` / `@pattern`, each published bound crossed by one and far
    // past it, then the pattern broken inside the length bounds.
    for max_results in [0_i64, -1, 1001, 1_000_000] {
        rows.push(Row {
            case: format!("maxResults={max_results} outside its @range, in the request URI"),
            sent: Sent::Uri {
                query: format!("maxResults={max_results}"),
                members: vec!["maxResults"],
                pattern: false,
            },
        });
    }
    for length in [1_usize, 31, 513, 2048] {
        let token = "A".repeat(length);
        rows.push(Row {
            case: format!("a {length}-character nextToken outside its @length, in the request URI"),
            sent: Sent::Uri {
                query: format!("nextToken={}", encode_query_value(&token)),
                members: vec!["nextToken"],
                pattern: false,
            },
        });
    }
    for (name, token) in [
        ("a run of illegal characters", "#".repeat(32)),
        ("one illegal character at the head", format!(".{}", "A".repeat(39))),
        ("one illegal character at the tail", format!("{}.", "A".repeat(63))),
        ("one illegal character in the middle", format!("{} {}", "A".repeat(40), "B".repeat(40))),
    ] {
        assert!(
            NEXT_TOKEN_LENGTH.contains(&token.len()),
            "a pattern row must satisfy @length(32, 512) so only the pattern is broken, \
             got {} characters for {name:?}",
            token.len()
        );
        rows.push(Row {
            case: format!("nextToken with {name}, outside its @pattern, in the request URI"),
            sent: Sent::Uri {
                query: format!("nextToken={}", encode_query_value(&token)),
                members: vec!["nextToken"],
                pattern: true,
            },
        });
    }
    rows.push(Row {
        case: "maxResults and nextToken broken together, in the request URI".to_string(),
        sent: Sent::Uri {
            query: format!("maxResults=0&nextToken={}", encode_query_value("short")),
            members: vec!["maxResults", "nextToken"],
            pattern: false,
        },
    });

    rows
}

/// The member paths an answer's `fieldList` names, sorted, or `None` when it
/// carries none.
fn reported_members(case: &str, body: &Value) -> Option<Vec<String>> {
    let entries = body
        .get("fieldList")?
        .as_array()
        .unwrap_or_else(|| panic!("case {case:?}: fieldList must be an array, got {body}"));
    let mut paths: Vec<String> = entries
        .iter()
        .map(|entry| {
            entry
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_else(|| {
                    panic!("case {case:?}: a fieldList entry requires a path, got {entry}")
                })
                .to_string()
        })
        .collect();
    paths.sort();
    Some(paths)
}

/// The rule: the one front door places every refusal by the model's binding, and
/// quotes a `@pattern` as the expression a value has to satisfy.
#[tokio::test]
async fn every_refusal_is_placed_by_the_models_binding_and_quotes_the_advertised_pattern() {
    let advertised = advertised_pattern();

    for Row { case, sent } in rows() {
        let case = case.as_str();
        let router = build_router();
        // Primed before the request, so "the refusal wrote nothing" is an
        // observable claim about this row rather than the absence of one.
        let primed = prime(&router).await;

        let (status, error_type, body) = match &sent {
            Sent::Uri { query, .. } => {
                call(&router, "GET", &format!("/v1/services?{query}"), None).await
            }
            Sent::Body(document) => update_customizations(&router, document.clone()).await,
        };
        assert_eq!(
            status, 400,
            "case {case:?}: expected HTTP 400, got {status} ({body})"
        );

        match &sent {
            // A value bound to the request URI keeps the modelled exception, whose
            // `fieldList` names every member refused.
            Sent::Uri {
                members: refused,
                pattern,
                ..
            } => {
                assert_eq!(
                    error_type, VALIDATION_EXCEPTION,
                    "case {case:?}: a URI-bound refusal keeps {VALIDATION_EXCEPTION}, \
                     got {error_type:?} ({body})"
                );
                let mut expected: Vec<String> =
                    refused.iter().map(|member| (*member).to_string()).collect();
                expected.sort();
                let reported = reported_members(case, &body).unwrap_or_else(|| {
                    panic!(
                        "case {case:?}: a URI-bound refusal names its members in fieldList, \
                         got {body}"
                    )
                });
                assert_eq!(
                    reported, expected,
                    "case {case:?}: expected the refused members {expected:?} reported, \
                     got {reported:?} ({body})"
                );
                let stated = body
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("case {case:?}: a refusal must say something, got {body}"));
                if *pattern {
                    let quoted = stated
                        .rsplit_once(PATTERN_CLAUSE)
                        .map(|(_, quoted)| quoted)
                        .unwrap_or_else(|| {
                            panic!("case {case:?}: no pattern clause in {stated:?}")
                        });
                    assert_eq!(
                        quoted, advertised,
                        "case {case:?}: expected the advertised expression {advertised:?}, \
                         got {quoted:?}"
                    );
                } else {
                    assert!(
                        !stated.contains(PATTERN_CLAUSE),
                        "case {case:?}: a requirement that is not a @pattern must state no \
                         pattern, got {stated:?}"
                    );
                }
            }
            // A value the operation carries in the body earns the front door's own
            // code and its one sentence, in the header and in the body alike.
            Sent::Body(_) => {
                let stated: Answer = answer(status, &error_type, &body);
                assert_eq!(
                    stated,
                    (
                        400,
                        crate::support::BAD_REQUEST_EXCEPTION.to_string(),
                        crate::support::BAD_REQUEST_EXCEPTION.to_string(),
                        INVALID_REQUEST_BODY.to_string(),
                    ),
                    "case {case:?}: a body refusal is the front door's code in the header and \
                     the body with its one sentence, got {stated:?} ({body})"
                );
                assert!(
                    reported_members(case, &body).is_none(),
                    "case {case:?}: a body refusal names no member, got {body}"
                );
                for member in BODY_MEMBERS {
                    assert!(
                        !stated.3.contains(member),
                        "case {case:?}: a body refusal must name no member, got {:?}",
                        stated.3
                    );
                }
            }
        }

        let (_, _, fetched) = get_customizations(&router).await;
        assert_eq!(
            fetched, primed,
            "case {case:?}: a refused request must leave the record untouched, got {fetched:?}"
        );
    }
}

/// The other side of the same reading: what the front door places in the body is
/// what each operation still SERVES, so nothing about an accepted request moved.
///
/// `ListServices` pages every size its `@range` admits, `UpdateAccountCustomizations`
/// stores what a body supplies and reads it back through `GetAccountCustomizations`,
/// and a body member carried as an explicit `null` is still seen as the body member
/// it is — the reset documented at
/// `smithy_query(query="doc", shape="UpdateAccountCustomizations")` — which the same
/// reading of a member's binding is what finds.
#[tokio::test]
async fn the_requests_each_operation_serves_are_unchanged() {
    let router = build_router();

    // Every published bound of the one `@range`, and a value just inside each.
    for max_results in [1_i64, 2, 999, 1000] {
        let (services, _) = list_page(&router, Some(max_results), None).await;
        let asked = usize::try_from(max_results).expect("a bound inside @range(1, 1000) is positive");
        assert!(
            !services.is_empty() && services.len() <= asked,
            "case maxResults={max_results}: a page must hold between one entry and what it \
             asked for, got {} entries",
            services.len()
        );
    }

    // A token this service issued still resumes the listing: the pattern rendering
    // changes how a refusal reads, never which values are refused.
    let (_, issued) = list_page(&router, Some(1), None).await;
    let token = issued.expect("a first page of one entry must carry a nextToken");
    let uri = list_services_uri(Some(1), Some(&token));
    let (status, error_type, body) = call(&router, "GET", &uri, None).await;
    assert_eq!(
        status, 200,
        "an issued token must still resume the listing, got {status} {error_type:?} ({body})"
    );

    // The body half round-trips: what a legal body supplies is stored and read back.
    let chosen = catalog_services(&router, 3).await;
    let regions: Vec<String> = (0..3).map(legal_region).collect();
    let (status, _, updated) = update_customizations(
        &router,
        json!({
            "accountColor": "teal",
            "visibleServices": chosen.clone(),
            "visibleRegions": regions.clone(),
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "a body inside every modelled constraint must be served, got {status} ({updated})"
    );
    let (status, _, fetched) = get_customizations(&router).await;
    assert_eq!(
        status, 200,
        "the stored record must read back, got {status} ({fetched})"
    );
    assert_eq!(
        fetched, updated,
        "the reader must answer what the update stored, got {fetched:?} against {updated:?}"
    );
    assert_eq!(
        fetched.get("visibleServices"),
        Some(&reported_owned(&chosen)),
        "the stored services must read back as the supplied members, got {fetched:?}"
    );
    assert_eq!(
        fetched.get("visibleRegions"),
        Some(&reported_owned(&regions)),
        "the stored Regions must read back as the supplied members, got {fetched:?}"
    );

    // And a member carried as an explicit `null` is still read as a body member:
    // the setting goes back to unconfigured, which the reader reports as absent.
    let (status, _, reset) = update_customizations(
        &router,
        json!({"visibleServices": null, "visibleRegions": null}),
    )
    .await;
    assert_eq!(
        status, 200,
        "a nulled body member must be served, got {status} ({reset})"
    );
    assert_eq!(
        reset,
        json!({"accountColor": "teal"}),
        "a nulled list setting must read back as an absent member, got {reset:?}"
    );
}
