// SPDX-License-Identifier: CC0-1.0

//! The rule `CreateAnomalyDetector` and `PutAnomalyDetector` hold a Random Cut Forest
//! `query` to, end to end over HTTP: the query is accepted only when the ROOT of the whole
//! expression is one of the aggregation operators `RandomCutForestConfiguration$query`
//! publishes — the operator applied LAST, to everything the expression computes — and is
//! refused with the modelled `ValidationException` (400) for every other root, however
//! early in the text an aggregation is written.
//!
//! Each row of the table is a FORM an expression can take, so the suite spans what the
//! rule generalises over: which operator sits at the root (an aggregation, arithmetic, a
//! comparison, a set operation, a function call, a unary minus, a subquery, a
//! parenthesisation), which operand of a binary operator the aggregation is written as,
//! which of the published operators does the wrapping, which aggregation-modifier form is
//! used, how the expression is spaced, and text PromQL cannot parse at all.
//!
//! The harness (`Amp`, `Reply`, `text`) is the one `tests/all/workspace_lifecycle.rs`
//! builds, and the request helpers (`create_detector`, `put_detector`,
//! `describe_detector`, `Spec`) are the ones `tests/all/anomaly_detector_update.rs`
//! already drives these operations with.

use crate::anomaly_detector_update::{
    create_detector, describe_detector, put_detector, Spec, ABSENT_DETECTOR_ID,
};
use crate::workspace_lifecycle::{text, Amp, Reply};
use service_com_amazonaws_amp_amazonprometheusservice::state::{
    RANDOM_CUT_FOREST_AGGREGATION_OPERATORS, RANDOM_CUT_FOREST_QUERY_UNSUPPORTED_MESSAGE,
    STATUS_ACTIVE,
};

/// The PromQL form a published aggregation operator takes over `inner`.
///
/// `quantile` is the one operator in the published catalog that PromQL defines WITH a
/// parameter — `quantile(φ, expression)`, the aggregation-operators page
/// `RandomCutForestConfiguration$query` links to — so its call carries the scalar φ; every
/// other published operator aggregates the expression alone. Shared with the suites that
/// walk the catalog, so one definition says what a call to each operator looks like.
pub(crate) fn aggregation_call(operator: &str, inner: &str) -> String {
    match operator {
        "quantile" => format!("quantile(0.99, {inner})"),
        _ => format!("{operator}({inner})"),
    }
}

/// One expression, and whether a supported aggregation operator is its ROOT.
struct QueryCase {
    /// What this form is, named in every assertion this row makes.
    name: String,
    query: String,
    /// `true` when the whole expression is a call to one of the published operators, so
    /// the service must store it; `false` when it is not, so the service must refuse it.
    wrapped: bool,
}

fn case(name: &str, query: &str, wrapped: bool) -> QueryCase {
    QueryCase {
        name: name.to_string(),
        query: query.to_string(),
        wrapped,
    }
}

/// Every form under test. The catalog rows come from
/// `RANDOM_CUT_FOREST_AGGREGATION_OPERATORS` (the operators the model's member lists), and
/// the rest are written out: the forms PromQL's aggregation syntax allows, and the roots
/// that are not an aggregation at all.
fn query_cases() -> Vec<QueryCase> {
    let mut cases: Vec<QueryCase> = RANDOM_CUT_FOREST_AGGREGATION_OPERATORS
        .iter()
        .map(|operator| {
            QueryCase {
                name: format!("the published operator {operator} wrapping a selector"),
                query: aggregation_call(operator, "requests_total"),
                wrapped: true,
            }
        })
        .collect();
    cases.extend([
        // The aggregation forms PromQL's `<aggr-op> [by|without (<labels>)] (<expr>)`
        // syntax allows, each still an aggregation at the root.
        case(
            "a by modifier before the argument list",
            "sum by (job) (rate(requests_total[5m]))",
            true,
        ),
        case(
            "a without modifier before the argument list",
            "max without (instance) (up)",
            true,
        ),
        case("a modifier after the argument list", "sum(up) by (job)", true),
        case(
            "an operator and its argument list split over lines",
            "sum\n  by (job)\n  (up)",
            true,
        ),
        case(
            "an aggregation whose argument is itself an aggregation",
            "avg(sum by (job) (up))",
            true,
        ),
        case(
            "a close parenthesis inside a label matcher's quoted value",
            "sum(up{path=\"/a)b\"})",
            true,
        ),
        // Roots that are NOT an aggregation, with the aggregation written FIRST — the
        // forms a reading of the leading identifier alone cannot tell from a wrapped
        // query.
        case(
            "two aggregations divided by one another",
            "sum(rate(a[5m])) / sum(rate(b[5m]))",
            false,
        ),
        case(
            "an aggregation plus a scalar, the aggregation written first",
            "sum(rate(a[5m])) + 1",
            false,
        ),
        case(
            "a comparison whose left operand is an aggregation",
            "sum(up) > 0",
            false,
        ),
        case(
            "a set operation between two aggregations",
            "max(up) or min(down)",
            false,
        ),
        case(
            "an unless between two aggregations",
            "sum(up) unless sum(down)",
            false,
        ),
        case(
            "a modifier form divided by a scalar",
            "sum by (job) (up) / 2",
            false,
        ),
        case("a subquery over an aggregation", "sum(up)[10m:1m]", false),
        // The MIRRORS of those: the same expressions with the aggregation written as the
        // other operand, or parenthesised, which must get the same answer.
        case(
            "an aggregation plus a scalar, the scalar written first",
            "1 + sum(rate(a[5m]))",
            false,
        ),
        case("a parenthesised aggregation", "(sum(up))", false),
        case(
            "a parenthesised aggregation divided by another",
            "(sum(rate(a[5m]))) / count(up)",
            false,
        ),
        case("a function applied to an aggregation", "abs(sum(up))", false),
        case("a negated aggregation", "-sum(up)", false),
        // Roots with no aggregation anywhere in them.
        case("a range-vector function", "rate(requests_total[5m])", false),
        case("a bare selector", "requests_total", false),
        case(
            // `topk` is a PromQL aggregation the member's list leaves out.
            "an aggregation operator the published catalog does not list",
            "topk(5, rate(requests_total[5m]))",
            false,
        ),
        case(
            "an identifier one character longer than a published operator",
            "sums(up)",
            false,
        ),
        case("text PromQL cannot parse", "sum(", false),
    ]);
    cases
}

/// How long a poll keeps looking for the settling the clock owes a detector, and how often
/// it looks. Generous: the span is the service's to choose and nothing here asserts how
/// long it took, only that the condition holds in the end.
const SETTLING_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
const SETTLING_LOOK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Look again at one detector until it reports `ACTIVE`, so a request that is only
/// accepted for a settled detector is sent once the CONDITION holds.
async fn poll_until_active(amp: &Amp, region: &str, workspace_id: &str, detector_id: &str) {
    let deadline = std::time::Instant::now() + SETTLING_DEADLINE;
    loop {
        let described = describe_detector(amp, region, workspace_id, detector_id).await;
        let status = text(&described.body["anomalyDetector"]["status"]["statusCode"]);
        if status == STATUS_ACTIVE {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detector {detector_id}: never reported {STATUS_ACTIVE}, last status {status:?}"
        );
        tokio::time::sleep(SETTLING_LOOK_INTERVAL).await;
    }
}

/// The query the service PERSISTED for one detector, read back through
/// `DescribeAnomalyDetector`.
async fn persisted_query(amp: &Amp, region: &str, workspace_id: &str, detector_id: &str) -> String {
    let described = describe_detector(amp, region, workspace_id, detector_id).await;
    assert_eq!(
        described.status, 200,
        "detector {detector_id}: DescribeAnomalyDetector must answer 200, got {described:?}"
    );
    text(&described.body["anomalyDetector"]["configuration"]["randomCutForest"]["query"])
}

/// Assert one refusal is the service's own sentence for an expression no supported
/// aggregation operator wraps.
fn assert_unsupported_expression(case: &str, reply: &Reply) {
    assert_eq!(
        reply.status, 400,
        "case {case:?}: an expression whose root is not a supported aggregation operator \
         must be refused 400, got {reply:?}"
    );
    assert_eq!(
        reply.error_code(),
        "ValidationException",
        "case {case:?}: expected the modelled ValidationException, got {reply:?}"
    );
    assert_eq!(
        text(&reply.body["message"]),
        RANDOM_CUT_FOREST_QUERY_UNSUPPORTED_MESSAGE,
        "case {case:?}: expected the service's sentence for this class, got {reply:?}"
    );
}

/// `CreateAnomalyDetector` judges the query by its ROOT: a create carrying an expression a
/// published aggregation operator wraps is accepted and the expression is read back from
/// the store, and a create carrying any other root mints nothing — whichever operand the
/// aggregation is written as.
#[tokio::test]
async fn create_judges_a_query_by_the_operator_at_its_root() {
    let amp = Amp::new();
    let region = "us-east-1";
    let workspace_id = amp.active_workspace(region, "roots").await;

    for (index, case) in query_cases().iter().enumerate() {
        let name = &case.name;
        let reply = create_detector(
            &amp,
            region,
            &workspace_id,
            &Spec::new(&case.query).create_body(&format!("root{index}"), &[]),
        )
        .await;
        if !case.wrapped {
            assert_unsupported_expression(name, &reply);
            assert!(
                reply.body.get("anomalyDetectorId").is_none(),
                "case {name:?}: a refused create must mint no detector, got {reply:?}"
            );
            continue;
        }
        assert_eq!(
            reply.status, 202,
            "case {name:?}: an expression a published operator wraps must be accepted, \
             got {reply:?}"
        );
        let detector_id = text(&reply.body["anomalyDetectorId"]);
        let stored = persisted_query(&amp, region, &workspace_id, &detector_id).await;
        assert_eq!(
            stored, case.query,
            "case {name:?}: expected the stored query {:?}, got {stored:?}",
            case.query
        );
    }
}

/// `PutAnomalyDetector` applies the same rule to the specification it stores: an
/// expression a published operator wraps replaces the detector's query, and any other root
/// is refused with nothing stored — so the detector still reports the last accepted
/// expression.
///
/// Every accepted row is put to its OWN detector, all of them created before any is put,
/// so the whole table costs one settling span rather than one per row.
#[tokio::test]
async fn put_judges_a_query_by_the_operator_at_its_root() {
    let amp = Amp::new();
    let region = "eu-west-1";
    let workspace_id = amp.active_workspace(region, "roots").await;
    let cases = query_cases();

    // The seed every refused row is put to, and the expression it keeps holding.
    const SEED_QUERY: &str = "sum(up)";
    let seeded = create_detector(
        &amp,
        region,
        &workspace_id,
        &Spec::new(SEED_QUERY).create_body("seed", &[]),
    )
    .await;
    assert_eq!(seeded.status, 202, "seeding a detector: got {seeded:?}");
    let seed_id = text(&seeded.body["anomalyDetectorId"]);

    let accepted: Vec<&QueryCase> = cases.iter().filter(|case| case.wrapped).collect();
    let mut targets: Vec<String> = Vec::new();
    for (index, case) in accepted.iter().enumerate() {
        let name = &case.name;
        let created = create_detector(
            &amp,
            region,
            &workspace_id,
            &Spec::new(SEED_QUERY).create_body(&format!("target{index}"), &[]),
        )
        .await;
        assert_eq!(
            created.status, 202,
            "case {name:?}: seeding the detector to update: got {created:?}"
        );
        targets.push(text(&created.body["anomalyDetectorId"]));
    }
    poll_until_active(&amp, region, &workspace_id, &seed_id).await;
    for detector_id in &targets {
        poll_until_active(&amp, region, &workspace_id, detector_id).await;
    }

    for (case, detector_id) in accepted.iter().zip(&targets) {
        let name = &case.name;
        let reply = put_detector(
            &amp,
            region,
            &workspace_id,
            detector_id,
            &Spec::new(&case.query).put_body(),
        )
        .await;
        assert_eq!(
            reply.status, 202,
            "case {name:?}: an expression a published operator wraps must be accepted, \
             got {reply:?}"
        );
        let stored = persisted_query(&amp, region, &workspace_id, detector_id).await;
        assert_eq!(
            stored, case.query,
            "case {name:?}: expected the stored query {:?}, got {stored:?}",
            case.query
        );
    }

    // The refused rows leave the seed untouched, so they can be sent one after another:
    // nothing is stored and the detector stays settled.
    for case in cases.iter().filter(|case| !case.wrapped) {
        let name = &case.name;
        let reply = put_detector(
            &amp,
            region,
            &workspace_id,
            &seed_id,
            &Spec::new(&case.query).put_body(),
        )
        .await;
        assert_unsupported_expression(name, &reply);
        let stored = persisted_query(&amp, region, &workspace_id, &seed_id).await;
        assert_eq!(
            stored, SEED_QUERY,
            "case {name:?}: a refused update must store nothing, got {stored:?}"
        );
    }

    // The same rule decides a PUT that would CREATE the detector it addresses, so an
    // unwrapped expression cannot bring one into existence either.
    let reply = put_detector(
        &amp,
        region,
        &workspace_id,
        ABSENT_DETECTOR_ID,
        &Spec::new("sum(rate(a[5m])) / sum(rate(b[5m]))").put_body(),
    )
    .await;
    assert_unsupported_expression("a create by put carrying two divided aggregations", &reply);
    let described = describe_detector(&amp, region, &workspace_id, ABSENT_DETECTOR_ID).await;
    assert_eq!(
        described.status, 404,
        "case \"a create by put carrying two divided aggregations\": the refused create \
         must have stored no detector, got {described:?}"
    );
}
