// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP tests for the per-account/Region investigation-group quota refusal
//! on the CONCURRENT create path.
//!
//! Every case drives the real wire path — the production `MultiServiceRouter`,
//! restJson1 serialization, the modelled-constraint walk and the handlers — so what is
//! asserted is what a signed AWS SDK request observes.
//!
//! The rule under test: a `CreateInvestigationGroup` refused by the per-account/Region
//! investigation-group quota is refused with `ServiceQuotaExceededException` (402,
//! `smithy_query(query="operation",operation="CreateInvestigationGroup")`) worded with
//! the service's fixed sentence for that error class, on EVERY path that reaches the
//! quota — so when several creates race in one Region, each of the losers carries that
//! same sentence, byte for byte, and it interpolates nothing: not the cap the emulator
//! enforces, not the number of racers, not the Region, not the account, and nothing the
//! refused request sent.
//!
//! Rows differ along the number of racers, the Region they race in, whether the
//! Region's one slot was claimed and freed before the race or was empty from the start,
//! the FORM of the names the racers send (distinct, shared, and the longest the modelled
//! `@length 1..512` admits), and how many members each create body carries.

use std::sync::Arc;

use serde_json::{json, Value};
use service_com_amazonaws_aiops_aiops::state::MAX_INVESTIGATION_GROUPS_PER_REGION;
use smithy_server_runtime::MultiServiceRouter;

/// The canonical emulator account (`engine::EMULATOR_ACCOUNT_ID`) every group ARN
/// carries: a value the quota sentence may not name.
const ACCOUNT: &str = "000000000000";

/// An account OTHER than the investigation account, for the fuller-body rows.
const FOREIGN_ACCOUNT: &str = "111122223333";

/// A role ARN satisfying the modelled `RoleArn`
/// (`smithy_query(query="operation",operation="CreateInvestigationGroup")`: `@length`
/// 20..2048, `^arn:.*$`).
const ROLE_ARN: &str = "arn:aws:iam::000000000000:role/AIOpsAssistantRole";

/// The modelled error shape a create past the quota reports
/// (`smithy_query(query="operation",operation="CreateInvestigationGroup")`:
/// `ServiceQuotaExceededException`, `@httpError 402`).
const QUOTA_EXCEEDED: &str = "ServiceQuotaExceededException";

/// The sentence the service words a create past the per-account/Region
/// investigation-group quota with: entirely fixed text.
const CANNOT_CREATE_ANOTHER_GROUP: &str = "Cannot create another investigation group.";

/// The longest `name` the modelled `@length 1..512` admits.
const MAX_NAME_LEN: usize = 512;

/// One emulator with an empty store, mounted exactly as the router mounts it.
fn emulator() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(service_com_amazonaws_aiops_aiops::EmulatedService::new(
        engine,
    ));
    router
}

/// A request signed for `aiops` in `region`, the signal the router routes on and the
/// handlers read the Region from.
fn request(
    region: &str,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> http::Request<bytes::Bytes> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", format!("aiops.{region}.amazonaws.com"))
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDAIOPSTEST/20260101/{region}/aiops/aws4_request, \
                 SignedHeaders=host, Signature=0000"
            ),
        );
    let payload = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            bytes::Bytes::from(serde_json::to_vec(value).expect("serialize the request body"))
        }
        None => bytes::Bytes::new(),
    };
    builder.body(payload).expect("a well-formed test request")
}

/// Status and parsed body of one call. An empty body reads as `Value::Null`.
async fn call_in(
    router: &MultiServiceRouter,
    region: &str,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let response = router.dispatch(request(region, method, uri, body)).await;
    let status = response.status().as_u16();
    let error_type = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let raw = response.into_body();
    let mut parsed: Value = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&raw).to_string()))
    };
    // restJson1 carries the error shape in `__type`, and the framework also sets the
    // `x-amzn-errortype` header; fold the header in so one accessor reads either.
    if let (Some(error_type), Value::Object(map)) = (error_type, &mut parsed) {
        map.entry("__type")
            .or_insert_with(|| Value::String(error_type));
    }
    (status, parsed)
}

/// Percent-encode a value for use as a single `@httpLabel` path segment, which is what
/// an SDK does: a non-greedy label may not carry a raw `/`.
fn label(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '/' => "%2F".to_string(),
            ' ' => "%20".to_string(),
            other => other.to_string(),
        })
        .collect()
}

/// The modelled error shape a failed call reported.
fn error_code(body: &Value) -> String {
    body.get("__type")
        .and_then(Value::as_str)
        .unwrap_or("<no __type>")
        // An error `__type` may be namespaced (`com.amazonaws.aiops#Foo`).
        .rsplit('#')
        .next()
        .unwrap_or("<no __type>")
        .to_string()
}

fn message(body: &Value) -> String {
    body.get("message")
        .and_then(Value::as_str)
        .unwrap_or("<no message>")
        .to_string()
}

async fn create(router: &MultiServiceRouter, region: &str, body: &Value) -> (u16, Value) {
    call_in(router, region, "POST", "/investigationGroups", Some(body)).await
}

/// Create a group in `region` that must succeed, and answer its ARN.
async fn create_ok(router: &MultiServiceRouter, region: &str, body: &Value) -> String {
    let (status, created) = create(router, region, body).await;
    assert_eq!(
        status, 201,
        "create in {region}: expected 201, got {status} / {created:?}"
    );
    created
        .get("arn")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("create in {region}: response carried no arn, got {created:?}"))
        .to_string()
}

/// Delete the group `arn` names, freeing the Region's one slot.
async fn delete_ok(router: &MultiServiceRouter, region: &str, arn: &str) {
    let (status, body) = call_in(
        router,
        region,
        "DELETE",
        &format!("/investigationGroups/{}", label(arn)),
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "deleting {arn} in {region}: expected 200, got {status} / {body:?}"
    );
}

/// The ARNs `ListInvestigationGroups` reports in `region`.
async fn listed_arns(router: &MultiServiceRouter, region: &str) -> Vec<String> {
    let (status, body) = call_in(router, region, "GET", "/investigationGroups", None).await;
    assert_eq!(
        status, 200,
        "listing {region}: expected 200, got {status} / {body:?}"
    );
    body.get("investigationGroups")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("listing {region}: no investigationGroups in {body:?}"))
        .iter()
        .map(|item| {
            item.get("arn")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// The shape of the `name` the racers of one row send.
#[derive(Clone, Copy, Debug)]
enum NameForm {
    /// Every racer sends a name of its own.
    Distinct,
    /// Every racer sends the SAME name: a name is not an identifier here, so the
    /// quota — not a name clash — is what refuses the losers.
    Shared,
    /// Every racer sends the longest name the modelled `@length 1..512` admits.
    Longest,
}

/// The name racer `racer` sends in `form`. Every character is one the modelled
/// `^[\-_A-Za-z0-9\[\]\(\)\{\}\.: ]+$` admits.
fn racer_name(form: NameForm, racer: usize) -> String {
    match form {
        NameForm::Distinct => format!("race-racer-{racer}"),
        NameForm::Shared => "race-shared-name".to_string(),
        NameForm::Longest => {
            let head = format!("race-longest-{racer}-");
            let mut name = head.clone();
            name.push_str(&"a".repeat(MAX_NAME_LEN - head.len()));
            name
        }
    }
}

/// The create body racer `racer` fires: the two required members, plus the fuller
/// member set when `fuller` asks for one, so nothing the request carries can be
/// reflected in the refusal.
fn racer_body(form: NameForm, racer: usize, fuller: bool) -> Value {
    let name = racer_name(form, racer);
    if fuller {
        json!({
            "name": name,
            "roleArn": ROLE_ARN,
            "retentionInDays": 30,
            "isCloudTrailEventHistoryEnabled": false,
            "tags": { "Team": "ops" },
            "crossAccountConfigurations": [
                { "sourceRoleArn": format!("arn:aws:iam::{FOREIGN_ACCOUNT}:role/Reader") }
            ],
        })
    } else {
        json!({ "name": name, "roleArn": ROLE_ARN })
    }
}

/// One row of the race table.
#[derive(Clone, Copy, Debug)]
struct Race {
    /// Racers firing at once in one Region.
    racers: usize,
    /// The Region they race in — each Region has its own slot.
    region: &'static str,
    /// Whether the Region's slot is claimed and freed again before the race, so the
    /// race starts from a Region that has already held a group.
    claim_and_free: bool,
    form: NameForm,
    fuller: bool,
}

/// What one racer answered.
struct RacerAnswer {
    racer: usize,
    name: String,
    status: u16,
    body: Value,
}

/// Fire `race` and answer every racer's reply, in racer order.
async fn run_race(router: &Arc<MultiServiceRouter>, race: Race) -> Vec<RacerAnswer> {
    let mut tasks = Vec::with_capacity(race.racers);
    for racer in 0..race.racers {
        let router = Arc::clone(router);
        tasks.push(tokio::spawn(async move {
            let body = racer_body(race.form, racer, race.fuller);
            let name = body
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let (status, answer) = create(&router, race.region, &body).await;
            RacerAnswer {
                racer,
                name,
                status,
                body: answer,
            }
        }));
    }

    let mut answers = Vec::with_capacity(race.racers);
    for task in tasks {
        answers.push(task.await.expect("a racer task must not panic"));
    }
    answers.sort_by_key(|answer| answer.racer);
    answers
}

/// Assert one quota refusal: the status, the modelled error shape, the whole message,
/// and that the message interpolates nothing — not the cap, not the Region, not the
/// account, and nothing the refused request sent.
fn assert_quota_refusal(case: &str, status: u16, body: &Value, region: &str, name: &str) {
    assert_eq!(
        status, 402,
        "case {case:?}: expected 402, got {status} / {body:?}"
    );
    assert_eq!(
        error_code(body),
        QUOTA_EXCEEDED,
        "case {case:?}: expected {QUOTA_EXCEEDED}, got {body:?}"
    );
    let reported = message(body);
    assert_eq!(
        reported, CANNOT_CREATE_ANOTHER_GROUP,
        "case {case:?}: expected {CANNOT_CREATE_ANOTHER_GROUP:?}, got {reported:?}"
    );
    assert!(
        !reported.chars().any(|c| c.is_ascii_digit()),
        "case {case:?}: the sentence states no count and no cap, so it carries no digit, \
         got {reported:?}"
    );
    for (what, forbidden) in [
        ("the Region", region),
        ("the account", ACCOUNT),
        ("the name the refused create sent", name),
        ("the role ARN the refused create sent", ROLE_ARN),
    ] {
        assert!(
            !reported.contains(forbidden),
            "case {case:?}: the sentence names {what} nowhere, got {reported:?}"
        );
    }
}

/// Several creates racing in one Region converge on exactly
/// [`MAX_INVESTIGATION_GROUPS_PER_REGION`] winner, and EVERY loser is refused with the
/// service's fixed quota sentence — identically, whatever it asked for and however many
/// racers lost at once. The winner is the Region's one group afterwards, readable and
/// listed, so the refusals are backed by state and not by a count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_loser_of_a_concurrent_create_race_carries_the_service_sentence() {
    // Rows span the racer count, the Region, a slot that was claimed and freed before
    // the race, the name form and the size of the create body.
    let races = [
        Race {
            racers: 2,
            region: "us-west-2",
            claim_and_free: false,
            form: NameForm::Distinct,
            fuller: false,
        },
        Race {
            racers: 5,
            region: "us-west-2",
            claim_and_free: true,
            form: NameForm::Distinct,
            fuller: false,
        },
        Race {
            racers: 5,
            region: "eu-central-1",
            claim_and_free: false,
            form: NameForm::Shared,
            fuller: false,
        },
        Race {
            racers: 3,
            region: "ap-southeast-4",
            claim_and_free: true,
            form: NameForm::Longest,
            fuller: false,
        },
        Race {
            racers: 8,
            region: "us-gov-west-1",
            claim_and_free: false,
            form: NameForm::Distinct,
            fuller: true,
        },
    ];

    for race in races {
        let case = format!(
            "{} racers in {} (slot reused: {}, names: {:?}, fuller body: {})",
            race.racers, race.region, race.claim_and_free, race.form, race.fuller
        );
        let router = Arc::new(emulator());

        if race.claim_and_free {
            let claimed = create_ok(&router, race.region, &racer_body(race.form, 99, false)).await;
            delete_ok(&router, race.region, &claimed).await;
        }

        let answers = run_race(&router, race).await;

        let mut winners: Vec<String> = Vec::new();
        for answer in &answers {
            if answer.status == 201 {
                let arn = answer.body.get("arn").and_then(Value::as_str);
                let arn = arn.unwrap_or_else(|| {
                    panic!(
                        "case {case:?}: a winner carries an arn, got {:?}",
                        answer.body
                    )
                });
                winners.push(arn.to_string());
            } else {
                assert_quota_refusal(
                    &format!("{case}: racer {}", answer.racer),
                    answer.status,
                    &answer.body,
                    race.region,
                    &answer.name,
                );
                assert!(
                    answer.body.get("arn").is_none(),
                    "case {case:?}: a refused create mints no ARN, got {:?}",
                    answer.body
                );
            }
        }

        assert_eq!(
            winners.len(),
            MAX_INVESTIGATION_GROUPS_PER_REGION,
            "case {case:?}: expected exactly {MAX_INVESTIGATION_GROUPS_PER_REGION} winner(s), \
             got {winners:?}"
        );
        assert_eq!(
            answers.len() - winners.len(),
            race.racers - MAX_INVESTIGATION_GROUPS_PER_REGION,
            "case {case:?}: every racer that did not win must be refused, got {winners:?}"
        );

        // The refusals are backed by state: the Region holds exactly the winners, and
        // each of them reads back through GetInvestigationGroup.
        assert_eq!(
            listed_arns(&router, race.region).await,
            winners,
            "case {case:?}: the Region must hold exactly the winner(s)"
        );
        for arn in &winners {
            let (status, group) = call_in(
                &router,
                race.region,
                "GET",
                &format!("/investigationGroups/{}", label(arn)),
                None,
            )
            .await;
            assert_eq!(
                status, 200,
                "case {case:?}: the winner {arn} must be readable, got {status} / {group:?}"
            );
            assert_eq!(
                group.get("arn").and_then(Value::as_str),
                Some(arn.as_str()),
                "case {case:?}: the read must report the winner's own ARN, got {group:?}"
            );
        }
    }
}

/// The quota sentence does not depend on HOW the quota was reached: a lone sequential
/// create refused while the Region holds its group, and every loser of a race in the
/// same Region, carry one and the same sentence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_concurrent_and_the_sequential_quota_refusals_word_one_sentence() {
    let region = "us-east-1";
    let router = Arc::new(emulator());

    // The concurrent path: the losers of a race in an empty Region.
    let race = Race {
        racers: 4,
        region,
        claim_and_free: false,
        form: NameForm::Distinct,
        fuller: false,
    };
    let answers = run_race(&router, race).await;
    let concurrent: Vec<String> = answers
        .iter()
        .filter(|answer| answer.status != 201)
        .map(|answer| message(&answer.body))
        .collect();
    assert_eq!(
        concurrent.len(),
        race.racers - MAX_INVESTIGATION_GROUPS_PER_REGION,
        "the race must leave {} loser(s), got {concurrent:?}",
        race.racers - MAX_INVESTIGATION_GROUPS_PER_REGION
    );

    // The sequential path: one more create against the Region the race filled.
    let body = racer_body(NameForm::Distinct, 42, false);
    let (status, answer) = create(&router, region, &body).await;
    let name = racer_name(NameForm::Distinct, 42);
    assert_quota_refusal(
        "a sequential create past the quota",
        status,
        &answer,
        region,
        &name,
    );

    for (racer, sentence) in concurrent.iter().enumerate() {
        assert_eq!(
            sentence,
            &message(&answer),
            "loser {racer} of the race and the sequential create must word one sentence, \
             got {sentence:?} and {:?}",
            message(&answer)
        );
    }
}
