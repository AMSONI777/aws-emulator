// SPDX-License-Identifier: CC0-1.0

//! The boundaries AWS Batch applies to a REQUEST before it resolves anything, end to end
//! over the wire.
//!
//! Every case drives a real restJson1 request through the router the emulator mounts, so
//! what is asserted is the response a `batch` client branches on, and every rule is
//! asserted over a TABLE of inputs — the recorded request is one row of each.
//!
//! The rules under test:
//!
//! * a `CreateQuotaShare` naming a share its queue already carries is refused with the
//!   modelled `ClientException` (HTTP 400) stating WHICH name collided on WHICH queue,
//!   bare: `QuotaShare with name <name> already exists for job queue <jobQueue>`, the
//!   queue echoed as the request spelled it;
//! * the identity that create composes (`<jobQueue>/quota-share/<quotaShareName>`) is read
//!   AS an ARN before the queue is looked up: one that is not a well-formed ARN is the ARN
//!   layer's own refusal (HTTP 400 `BadRequestException`), an EARLIER boundary than the
//!   modelled `ClientException` a well-formed reference naming no queue draws;
//! * a `capacityLimits` entry must allocate a positive `maxCapacity`, on the quota-share
//!   plane and on the service-environment plane, on the create and on the update; a
//!   refused call stores nothing and changes nothing;
//! * a quota share's `capacityLimits` that is present and empty is refused with the
//!   sentence AWS words that condition with;
//! * `ListQuotaShares` treats its `jobQueue` as a FILTER: a reference that resolves to no
//!   stored queue answers an empty page, never a refusal;
//! * an identifier an operation resolves by NAME is held to Batch's name pattern before
//!   any lookup: a value outside it is refused `Provided name <value> is not supported
//!   pattern[a-zA-Z_0-9-]{1,128}`, while a well-formed identifier naming nothing keeps the
//!   operation's empty success;
//! * that pattern governs the id a reference NAMES, so the array-child form this service
//!   mints (`<parent>:<index>`) is cancelled and terminated like any other job id.

use serde_json::{json, Value};

use service_com_amazonaws_batch_awsbatchv20160810::scaffolded::FRONTEND_REFUSAL_CODE;
use service_com_amazonaws_batch_awsbatchv20160810::state;

use crate::job_lifecycle::{
    arn, compute_environment, container_properties, describe_job, error_code, error_message,
    job_definition, job_queue, Batch,
};

/// The routes under test (`smithy_query(query="digest")`: each operation's `http.uri`).
const CREATE_SHARE: &str = "/v1/createquotashare";
const UPDATE_SHARE: &str = "/v1/updatequotashare";
const DESCRIBE_SHARE: &str = "/v1/describequotashare";
const LIST_SHARES: &str = "/v1/listquotashares";
const CREATE_ENVIRONMENT: &str = "/v1/createserviceenvironment";
const UPDATE_ENVIRONMENT: &str = "/v1/updateserviceenvironment";
const DESCRIBE_ENVIRONMENTS: &str = "/v1/describeserviceenvironments";

/// The `serviceEnvironmentType` every environment here carries
/// (`smithy_query(query="shape", shape="ServiceEnvironmentType")`).
const ENVIRONMENT_TYPE: &str = "SAGEMAKER_TRAINING";

// The sentences AWS answers these refusals with, written out HERE as the literal text the
// recordings show, so what every case below compares against is AWS's wording and not the
// handler's own statement of it. Each test also asserts that the crate's helper or constant
// says the same thing, so neither side can drift without a failure.

/// AWS's refusal of a `CreateQuotaShare` naming a share the queue already carries.
fn duplicate_share_sentence(quota_share_name: &str, job_queue: &str) -> String {
    format!("QuotaShare with name {quota_share_name} already exists for job queue {job_queue}")
}

/// The identity a `CreateQuotaShare` composes out of its request.
fn composed_identity(job_queue: &str, quota_share_name: &str) -> String {
    format!("{job_queue}/quota-share/{quota_share_name}")
}

/// The ARN layer's refusal of a value it cannot read as an ARN.
fn not_an_arn_sentence(identity: &str) -> String {
    format!("{identity} is not a valid AmazonResourceName (ARN)")
}

/// AWS's refusal of an identifier outside Batch's resource-name pattern.
fn unsupported_name_sentence(identifier: &str) -> String {
    format!("Provided name {identifier} is not supported pattern[a-zA-Z_0-9-]{{1,128}}")
}

/// AWS's refusal of a quota share's non-positive `maxCapacity`.
const QUOTA_SHARE_CAPACITY_SENTENCE: &str = "maxCapacity must be greater than 0.";

/// AWS's refusal of a quota share's `capacityLimits` that is present and empty.
const CAPACITY_LIMITS_EMPTY_SENTENCE: &str = "capacityLimits is required and cannot be empty.";

/// AWS's refusal of a service environment's non-positive `maxCapacity`.
const SERVICE_ENVIRONMENT_CAPACITY_SENTENCE: &str = "Max capacity must be more than 0.";

/// The body of a `CreateQuotaShare` for `name` on `queue`, with `extra` laid over it.
fn share_body(name: &str, queue: &str, extra: Value) -> Value {
    let mut body = json!({
        "quotaShareName": name,
        "jobQueue": queue,
        "capacityLimits": [{"maxCapacity": 4, "capacityUnit": "ml.m5.large"}],
        "resourceSharingConfiguration": {"strategy": "RESERVE"},
        "preemptionConfiguration": {"inSharePreemption": "DISABLED"},
    });
    for (member, value) in extra.as_object().cloned().unwrap_or_default() {
        body[member] = value;
    }
    body
}

/// A compute environment and a job queue called `queue`; answers the queue's ARN.
async fn queue(batch: &Batch, queue: &str) -> String {
    let environment = compute_environment(batch, &format!("ce-for-{queue}")).await;
    job_queue(batch, queue, &environment).await
}

/// The `quotaShares` a `ListQuotaShares` for `reference` answers, requiring the 200.
async fn listed_shares(batch: &Batch, case: &str, reference: &str) -> Value {
    let (status, body) = batch
        .call(LIST_SHARES, json!({"jobQueue": reference}))
        .await;
    assert_eq!(
        status, 200,
        "case {case}: expected ListQuotaShares to answer 200, got {status} {body}"
    );
    body
}

/// The share names a `ListQuotaShares` for `reference` reports.
async fn share_names(batch: &Batch, case: &str, reference: &str) -> Vec<String> {
    let body = listed_shares(batch, case, reference).await;
    body["quotaShares"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|detail| {
            detail["quotaShareName"]
                .as_str()
                .unwrap_or("<no quotaShareName>")
                .to_string()
        })
        .collect()
}

/// RULE: a `CreateQuotaShare` naming a share the queue already carries is refused with the
/// modelled `ClientException` (400) stating the share's name and the queue as the request
/// spelled it, bare — no frontend envelope, and no generic duplicate-key detail.
#[tokio::test]
async fn a_duplicate_quota_share_names_the_share_and_the_queue() {
    let batch = Batch::new();
    let queue_arn = queue(&batch, "jq-duplicates").await;
    let other_arn = queue(&batch, "jq-duplicates-2").await;

    // Rows differ in the SHAPE of the share name (hyphens, underscores and mixed case, one
    // character, the longest accepted), in WHICH queue carries it, and in the FORM the
    // request refers to the queue by — a name stays a name, an ARN stays an ARN, and the
    // refusal echoes whichever was sent.
    let rows: Vec<(String, String)> = vec![
        ("qs-duplicate".to_string(), "jq-duplicates".to_string()),
        ("QS_Duplicate-2".to_string(), queue_arn.clone()),
        ("z".to_string(), "jq-duplicates".to_string()),
        (
            "q".repeat(state::MAX_QUOTA_SHARE_NAME_LEN),
            other_arn.clone(),
        ),
        ("qs-on-both".to_string(), "jq-duplicates".to_string()),
        ("qs-on-both".to_string(), other_arn.clone()),
    ];
    for (name, reference) in rows {
        let case = format!("the share {name:?} on {reference:?}");
        // The first create of the pair is accepted: the refusal below is the COLLISION and
        // not the request.
        batch
            .ok(CREATE_SHARE, share_body(&name, &reference, json!({})))
            .await;
        // Twice more, so the refusal is the steady answer and not a first-repeat quirk.
        for attempt in 1..=2 {
            let (status, refused) = batch
                .call(CREATE_SHARE, share_body(&name, &reference, json!({})))
                .await;
            assert_eq!(
                status, 400,
                "case {case} (attempt {attempt}): expected 400, got {status} {refused}"
            );
            assert_eq!(
                error_code(&refused),
                "ClientException",
                "case {case} (attempt {attempt}): expected the modelled ClientException, got \
                 {refused}"
            );
            let message = error_message(&refused);
            assert_eq!(
                message,
                duplicate_share_sentence(&name, &reference),
                "case {case} (attempt {attempt}): expected the duplicate sentence naming the \
                 share and the queue, got {message:?}"
            );
            // This refusal class carries NO frontend envelope: the sentence stands alone.
            assert!(
                state::enveloped_request_id(&message).is_none(),
                "case {case} (attempt {attempt}): the duplicate sentence carries no envelope, \
                 got {message:?}"
            );
        }
    }

    // One share per (queue, name) pair is stored, and the refusals above added nothing: the
    // name carried by BOTH queues is listed once under each.
    assert_eq!(
        share_names(&batch, "jq-duplicates", "jq-duplicates").await,
        vec![
            "QS_Duplicate-2".to_string(),
            "qs-duplicate".to_string(),
            "qs-on-both".to_string(),
            "z".to_string(),
        ],
        "case jq-duplicates: expected each accepted share exactly once"
    );
    assert_eq!(
        share_names(&batch, "jq-duplicates-2", &other_arn).await,
        vec![
            "q".repeat(state::MAX_QUOTA_SHARE_NAME_LEN),
            "qs-on-both".to_string(),
        ],
        "case jq-duplicates-2: expected each accepted share exactly once"
    );

    // The wording the handler emits is the wording asserted above, so neither can drift
    // from the other without this failing.
    assert_eq!(
        state::quota_share_exists_message("qs-wording", "jq-wording"),
        duplicate_share_sentence("qs-wording", "jq-wording"),
        "case the sentence the handler answers with: expected {:?}",
        duplicate_share_sentence("qs-wording", "jq-wording")
    );
}

/// RULE: the identity a `CreateQuotaShare` composes out of its request is read AS an ARN
/// before anything else — a composed value that is not a well-formed ARN is the
/// ARN layer's `BadRequestException` (400) naming it, where a well-formed reference naming
/// no queue is the modelled `ClientException`.
#[tokio::test]
async fn a_composed_identity_that_is_no_arn_is_refused_ahead_of_the_queue_lookup() {
    let batch = Batch::new();
    let queue_arn = queue(&batch, "jq-arn-shapes").await;
    let name = "qs-arn-shapes";

    // Rows differ in WHICH field of the ARN is unusable: the account id (too short, too
    // long, not digits), a missing resource field, an empty service field, and a value
    // that carries nothing but the scheme.
    let malformed = [
        "arn:aws:batch:us-east-1:12345:job-queue/jq-arn-shapes",
        "arn:aws:batch:us-east-1:0000000000000:job-queue/jq-arn-shapes",
        "arn:aws:batch:us-east-1:abcdefghijkl:job-queue/jq-arn-shapes",
        "arn:aws:batch:us-east-1:000000000000",
        "arn:aws::us-east-1:000000000000:job-queue/jq-arn-shapes",
        "arn:",
    ];
    for reference in malformed {
        let case = format!("the job queue {reference:?}");
        let (status, refused) = batch
            .call(CREATE_SHARE, share_body(name, reference, json!({})))
            .await;
        assert_eq!(
            status, 400,
            "case {case}: expected 400, got {status} {refused}"
        );
        assert_eq!(
            error_code(&refused),
            FRONTEND_REFUSAL_CODE,
            "case {case}: a malformed ARN is the ARN layer's refusal, got {refused}"
        );
        let composed = composed_identity(reference, name);
        assert_eq!(
            error_message(&refused),
            not_an_arn_sentence(&composed),
            "case {case}: expected the composed identity named as no ARN, got {refused}"
        );
        assert_eq!(
            state::composed_quota_share_identity(reference, name),
            composed,
            "case {case}: the identity the handlers compose must be the one asserted here"
        );
        assert_eq!(
            state::not_a_valid_arn_message(&composed),
            not_an_arn_sentence(&composed),
            "case {case}: the sentence the handlers answer must be the one asserted here"
        );
    }

    // A WELL-FORMED reference that names no queue is the other, later boundary: this
    // service's own modelled refusal, under its own code.
    for reference in [
        "jq-never-created".to_string(),
        arn("job-queue/jq-never-created"),
        // An ARN whose account field is empty is well formed (AWS omits the account on the
        // ARNs of some resources), so it reaches the lookup.
        "arn:aws:batch:us-east-1::job-queue/jq-never-created".to_string(),
    ] {
        let case = format!("the well-formed job queue {reference:?}");
        let (status, refused) = batch
            .call(CREATE_SHARE, share_body(name, &reference, json!({})))
            .await;
        assert_eq!(
            status, 400,
            "case {case}: expected 400, got {status} {refused}"
        );
        assert_eq!(
            error_code(&refused),
            "ClientException",
            "case {case}: a reference that names nothing is this service's refusal, got {refused}"
        );
    }

    // The queue that DOES exist still takes the same share, by ARN: the rows above refused
    // the ARN's shape and not the operation.
    batch
        .ok(CREATE_SHARE, share_body(name, &queue_arn, json!({})))
        .await;
    assert_eq!(
        share_names(&batch, "jq-arn-shapes", "jq-arn-shapes").await,
        vec![name.to_string()],
        "case jq-arn-shapes: only the accepted create may have stored a share"
    );
}

/// The `capacityLimits` values no plane accepts: rows differ in the offending quantity and
/// in WHERE in the list the offending entry sits.
fn non_positive_capacities() -> Vec<(String, Value)> {
    vec![
        (
            "a single negative limit".to_string(),
            json!([{"maxCapacity": -5, "capacityUnit": "ml.m6i.large"}]),
        ),
        (
            "a single limit of minus one".to_string(),
            json!([{"maxCapacity": -1, "capacityUnit": "NUM_INSTANCES"}]),
        ),
        (
            "a single limit of zero".to_string(),
            json!([{"maxCapacity": 0, "capacityUnit": "ml.m5.large"}]),
        ),
        (
            "a negative limit AFTER a usable one".to_string(),
            json!([
                {"maxCapacity": 3, "capacityUnit": "ml.m5.large"},
                {"maxCapacity": -2, "capacityUnit": "ml.p4d.24xlarge"},
            ]),
        ),
    ]
}

/// RULE: a quota share's `capacityLimits` must allocate a positive `maxCapacity` in every
/// entry, and may not be present and empty — on the create and on the update alike; a
/// refused call stores nothing and leaves the stored share exactly as it was.
#[tokio::test]
async fn a_quota_share_capacity_limit_must_allocate_a_positive_maximum() {
    let batch = Batch::new();
    queue(&batch, "jq-capacity").await;

    // The share the UPDATE rows are applied to, and the capacity it must keep.
    let stored = json!([{"maxCapacity": 4, "capacityUnit": "ml.m5.large"}]);
    let share = batch
        .ok(CREATE_SHARE, share_body("qs-capacity", "jq-capacity", json!({})))
        .await;
    let share_arn = share["quotaShareArn"].as_str().unwrap_or_default().to_string();

    // Every offending list, plus the present-but-empty list, with the sentence AWS words
    // each condition with. Both are stated INSIDE Batch's input-validation envelope.
    let mut rows = non_positive_capacities()
        .into_iter()
        .map(|(label, limits)| (label, limits, QUOTA_SHARE_CAPACITY_SENTENCE.to_string()))
        .collect::<Vec<(String, Value, String)>>();
    rows.push((
        "a list that is present and empty".to_string(),
        json!([]),
        CAPACITY_LIMITS_EMPTY_SENTENCE.to_string(),
    ));

    // The wording the handlers emit is the wording asserted below.
    assert_eq!(
        state::QUOTA_SHARE_MAX_CAPACITY_POSITIVE, QUOTA_SHARE_CAPACITY_SENTENCE,
        "case the capacity sentence the handlers answer with: expected \
         {QUOTA_SHARE_CAPACITY_SENTENCE:?}"
    );
    assert_eq!(
        state::CAPACITY_LIMITS_REQUIRED, CAPACITY_LIMITS_EMPTY_SENTENCE,
        "case the empty-list sentence the handlers answer with: expected \
         {CAPACITY_LIMITS_EMPTY_SENTENCE:?}"
    );

    for (label, limits, expected) in rows {
        // The CREATE refuses it, and stores nothing: the queue still holds only the share
        // created above.
        let case = format!("create a share with {label}");
        let (status, refused) = batch
            .call(
                CREATE_SHARE,
                share_body(
                    "qs-refused",
                    "jq-capacity",
                    json!({"capacityLimits": limits.clone()}),
                ),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case}: expected 400, got {status} {refused}"
        );
        assert_eq!(
            error_code(&refused),
            "ClientException",
            "case {case}: expected the modelled ClientException, got {refused}"
        );
        let (detail, _) = crate::refusal_contract::enveloped(&case, &error_message(&refused));
        assert_eq!(
            detail, expected,
            "case {case}: expected the capacity rule's sentence, got {detail:?}"
        );
        assert_eq!(
            share_names(&batch, &case, "jq-capacity").await,
            vec!["qs-capacity".to_string()],
            "case {case}: a refused create must store no share"
        );

        // The UPDATE refuses it too, and the stored share keeps the capacity it had.
        let case = format!("update a share with {label}");
        let (status, refused) = batch
            .call(
                UPDATE_SHARE,
                json!({"quotaShareArn": &share_arn, "capacityLimits": limits}),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case}: expected 400, got {status} {refused}"
        );
        let (detail, _) = crate::refusal_contract::enveloped(&case, &error_message(&refused));
        assert_eq!(
            detail, expected,
            "case {case}: expected the capacity rule's sentence, got {detail:?}"
        );
        let described = batch
            .ok(DESCRIBE_SHARE, json!({"quotaShareArn": &share_arn}))
            .await;
        assert_eq!(
            described["capacityLimits"], stored,
            "case {case}: a refused update must leave the stored capacity, got {described}"
        );
    }

    // The smallest capacity the rule admits is ACCEPTED, on both calls, so the refusals
    // above are the bound and not the member.
    let smallest = json!([{"maxCapacity": state::MIN_MAX_CAPACITY, "capacityUnit": "ml.m5.large"}]);
    batch
        .ok(
            CREATE_SHARE,
            share_body(
                "qs-smallest",
                "jq-capacity",
                json!({"capacityLimits": smallest.clone()}),
            ),
        )
        .await;
    batch
        .ok(
            UPDATE_SHARE,
            json!({"quotaShareArn": &share_arn, "capacityLimits": smallest.clone()}),
        )
        .await;
    let described = batch
        .ok(DESCRIBE_SHARE, json!({"quotaShareArn": &share_arn}))
        .await;
    assert_eq!(
        described["capacityLimits"], smallest,
        "case the smallest accepted capacity: expected the update to have been stored, got \
         {described}"
    );
}

/// RULE: a service environment's `capacityLimits` must allocate a positive `maxCapacity`
/// in every entry that states one, on the create and on the update; the refused create
/// leaves no environment behind and the refused update leaves the stored capacity.
#[tokio::test]
async fn a_service_environment_capacity_limit_must_allocate_a_positive_maximum() {
    let batch = Batch::new();

    let stored = json!([{"maxCapacity": 10, "capacityUnit": "NUM_INSTANCES"}]);
    batch
        .ok(
            CREATE_ENVIRONMENT,
            json!({
                "serviceEnvironmentName": "se-capacity",
                "serviceEnvironmentType": ENVIRONMENT_TYPE,
                "capacityLimits": stored.clone(),
            }),
        )
        .await;

    for (label, limits) in non_positive_capacities() {
        // The CREATE refuses it INSIDE the envelope, and leaves no environment behind.
        let case = format!("create a service environment with {label}");
        let (status, refused) = batch
            .call(
                CREATE_ENVIRONMENT,
                json!({
                    "serviceEnvironmentName": "se-refused",
                    "serviceEnvironmentType": ENVIRONMENT_TYPE,
                    "capacityLimits": limits.clone(),
                }),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case}: expected 400, got {status} {refused}"
        );
        assert_eq!(
            error_code(&refused),
            "ClientException",
            "case {case}: expected the modelled ClientException, got {refused}"
        );
        let (detail, _) = crate::refusal_contract::enveloped(&case, &error_message(&refused));
        assert_eq!(
            detail, SERVICE_ENVIRONMENT_CAPACITY_SENTENCE,
            "case {case}: expected the capacity rule's sentence, got {detail:?}"
        );
        let described = batch
            .ok(
                DESCRIBE_ENVIRONMENTS,
                json!({"serviceEnvironments": ["se-refused"]}),
            )
            .await;
        assert_eq!(
            described["serviceEnvironments"].as_array().map(Vec::len),
            Some(0),
            "case {case}: a refused create must leave no environment behind, got {described}"
        );

        // The UPDATE refuses it BARE — this plane is recorded stating the rule without the
        // envelope — and the stored capacity stands.
        let case = format!("update a service environment with {label}");
        let (status, refused) = batch
            .call(
                UPDATE_ENVIRONMENT,
                json!({"serviceEnvironment": "se-capacity", "capacityLimits": limits}),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {case}: expected 400, got {status} {refused}"
        );
        let message = error_message(&refused);
        assert_eq!(
            message, SERVICE_ENVIRONMENT_CAPACITY_SENTENCE,
            "case {case}: expected the bare sentence, got {message:?}"
        );
        assert!(
            state::enveloped_request_id(&message).is_none(),
            "case {case}: this plane's update refusal carries no envelope, got {message:?}"
        );
        let described = batch
            .ok(
                DESCRIBE_ENVIRONMENTS,
                json!({"serviceEnvironments": ["se-capacity"]}),
            )
            .await;
        assert_eq!(
            described["serviceEnvironments"][0]["capacityLimits"], stored,
            "case {case}: a refused update must leave the stored capacity, got {described}"
        );
    }

    // The smallest capacity the rule admits is ACCEPTED on both calls, and so is a limit
    // that states no `maxCapacity` at all (the member is optional, so such an entry states
    // no capacity to hold to the bound).
    assert_eq!(
        state::SERVICE_ENVIRONMENT_MAX_CAPACITY_POSITIVE, SERVICE_ENVIRONMENT_CAPACITY_SENTENCE,
        "case the capacity sentence the handlers answer with: expected \
         {SERVICE_ENVIRONMENT_CAPACITY_SENTENCE:?}"
    );
    let smallest =
        json!([{"maxCapacity": state::MIN_MAX_CAPACITY, "capacityUnit": "NUM_INSTANCES"}]);
    for (label, limits) in [
        ("the smallest accepted capacity", smallest.clone()),
        ("a limit carrying only a unit", json!([{"capacityUnit": "NUM_INSTANCES"}])),
    ] {
        batch
            .ok(
                UPDATE_ENVIRONMENT,
                json!({"serviceEnvironment": "se-capacity", "capacityLimits": limits.clone()}),
            )
            .await;
        let described = batch
            .ok(
                DESCRIBE_ENVIRONMENTS,
                json!({"serviceEnvironments": ["se-capacity"]}),
            )
            .await;
        assert_eq!(
            described["serviceEnvironments"][0]["capacityLimits"], limits,
            "case {label}: expected the update to have been stored, got {described}"
        );
    }
}

/// RULE: `ListQuotaShares` treats its `jobQueue` as a FILTER — a reference that resolves to
/// no stored queue answers an empty page, never a refusal — while a queue that holds shares
/// still reports its own.
#[tokio::test]
async fn a_listing_of_a_queue_nothing_holds_is_an_empty_page() {
    let batch = Batch::new();
    queue(&batch, "jq-listed").await;
    batch
        .ok(CREATE_SHARE, share_body("qs-listed", "jq-listed", json!({})))
        .await;

    // Rows differ in the FORM and shape of the reference: a name, the ARN that name would
    // resolve to, an ARN of another resource kind, a mixed-case name, a name at the
    // documented length bound, and a reference carrying no resource at all.
    let unknown: Vec<String> = vec![
        "jq-no-such-queue".to_string(),
        arn("job-queue/jq-no-such-queue"),
        arn("compute-environment/ce-no-such-thing"),
        "JQ_No-Such-Queue".to_string(),
        "q".repeat(state::MAX_QUOTA_SHARE_NAME_LEN),
        "not-a-queue-at-all".to_string(),
    ];
    for reference in unknown {
        let case = format!("the queue {reference:?}");
        let body = listed_shares(&batch, &case, &reference).await;
        assert_eq!(
            body["quotaShares"].as_array().cloned().unwrap_or_default(),
            Vec::<Value>::new(),
            "case {case}: expected an empty page, got {body}"
        );
        assert!(
            body.get("nextToken").and_then(Value::as_str).is_none(),
            "case {case}: a page that ends the results carries no nextToken, got {body}"
        );
        assert!(
            body.get("__type").is_none() && body.get("message").is_none(),
            "case {case}: an unresolved queue is no refusal, got {body}"
        );
    }

    // The queue that DOES hold a share still reports it, so the empty pages above are the
    // filter and not a blanket.
    assert_eq!(
        share_names(&batch, "jq-listed", "jq-listed").await,
        vec!["qs-listed".to_string()],
        "case jq-listed: expected the stored share to still be listed"
    );
}

/// One operation that resolves an identifier BY NAME: the route, the member the identifier
/// arrives on, the other members the request needs, and the ARN form of that identifier
/// which the name pattern does not govern.
struct Resolver {
    label: &'static str,
    uri: &'static str,
    member: &'static str,
    extra: Value,
    /// Identifiers that are well formed and name nothing: the operation's empty success.
    absent: Vec<String>,
}

/// The identifiers no operation of this service resolves by name: rows differ in WHICH
/// character outside the pattern they carry, and in length.
fn malformed_identifiers() -> Vec<String> {
    vec![
        "not a valid job id!!".to_string(),
        "!! not a valid name !!:1".to_string(),
        "!! not a valid consumable resource identifier !!".to_string(),
        "has a space".to_string(),
        "has/a/slash".to_string(),
        "has.dots".to_string(),
        String::new(),
        "z".repeat(state::MAX_IDENTIFIER_NAME_LEN + 1),
    ]
}

/// RULE: an identifier an operation resolves by NAME is held to Batch's name pattern
/// before any lookup — a value outside it is refused with the pattern sentence, while a
/// well-formed identifier that names nothing keeps the operation's empty success.
#[tokio::test]
async fn an_identifier_outside_the_name_pattern_is_refused_before_any_lookup() {
    let batch = Batch::new();

    // A resource of each kind that the refusals must leave untouched.
    let environment = compute_environment(&batch, "ce-identifiers").await;
    job_queue(&batch, "jq-identifiers", &environment).await;
    job_definition(&batch, "jd-identifiers", container_properties()).await;
    batch
        .ok(
            "/v1/createconsumableresource",
            json!({"consumableResourceName": "cr-identifiers", "totalQuantity": 4}),
        )
        .await;
    let submitted = batch
        .ok(
            "/v1/submitjob",
            json!({
                "jobName": "job-identifiers",
                "jobQueue": "jq-identifiers",
                "jobDefinition": "jd-identifiers",
            }),
        )
        .await;
    let live_job = submitted["jobId"].as_str().unwrap_or_default().to_string();

    let resolvers: Vec<Resolver> = vec![
        Resolver {
            label: "CancelJob",
            uri: "/v1/canceljob",
            member: "jobId",
            extra: json!({"reason": "probe"}),
            absent: vec![
                "d2f30357-a68b-4772-8a03-c2a8564f2244".to_string(),
                arn("job/d2f30357-a68b-4772-8a03-c2a8564f2244"),
            ],
        },
        Resolver {
            label: "TerminateJob",
            uri: "/v1/terminatejob",
            member: "jobId",
            extra: json!({"reason": "probe"}),
            absent: vec![
                "0389e230-0000-4000-8000-000000000000".to_string(),
                arn("job/0389e230-0000-4000-8000-000000000000"),
            ],
        },
        Resolver {
            label: "DeregisterJobDefinition",
            uri: "/v1/deregisterjobdefinition",
            member: "jobDefinition",
            extra: json!({}),
            absent: vec![
                "jd-absent".to_string(),
                "jd-absent:3".to_string(),
                arn("job-definition/jd-absent:3"),
            ],
        },
        Resolver {
            label: "DeleteConsumableResource",
            uri: "/v1/deleteconsumableresource",
            member: "consumableResource",
            extra: json!({}),
            absent: vec![
                "cr-absent".to_string(),
                arn("consumable-resource/cr-absent"),
            ],
        },
    ];

    for resolver in &resolvers {
        for identifier in malformed_identifiers() {
            let case = format!("{} with {identifier:?}", resolver.label);
            let mut body = resolver.extra.clone();
            body[resolver.member] = json!(identifier);
            let (status, refused) = batch.call(resolver.uri, body).await;
            assert_eq!(
                status, 400,
                "case {case}: expected 400, got {status} {refused}"
            );
            assert_eq!(
                error_code(&refused),
                "ClientException",
                "case {case}: expected the modelled ClientException, got {refused}"
            );
            let message = error_message(&refused);
            assert_eq!(
                message,
                unsupported_name_sentence(&identifier),
                "case {case}: expected the name-pattern sentence, got {message:?}"
            );
            assert_eq!(
                state::unsupported_name_message(&identifier),
                unsupported_name_sentence(&identifier),
                "case {case}: the sentence the handlers answer must be the one asserted here"
            );
            assert!(
                state::enveloped_request_id(&message).is_none(),
                "case {case}: this refusal class carries no envelope, got {message:?}"
            );
        }

        // A well-formed identifier that names nothing is the operation's empty success, so
        // the refusals above are the PATTERN and not the lookup.
        for identifier in &resolver.absent {
            let case = format!("{} with the absent {identifier:?}", resolver.label);
            let mut body = resolver.extra.clone();
            body[resolver.member] = json!(identifier);
            let (status, answered) = batch.call(resolver.uri, body).await;
            assert_eq!(
                status, 200,
                "case {case}: expected the empty success, got {status} {answered}"
            );
            assert!(
                answered.get("__type").is_none(),
                "case {case}: expected no error members, got {answered}"
            );
        }
    }

    // Nothing the refusals named was touched: every seeded resource is still there, and no
    // job was fabricated for a refused id.
    let described = batch
        .ok(
            "/v1/describeconsumableresource",
            json!({"consumableResource": "cr-identifiers"}),
        )
        .await;
    assert_eq!(
        described["consumableResourceName"].as_str(),
        Some("cr-identifiers"),
        "case the seeded consumable resource: a refused delete must leave it, got {described}"
    );
    let definitions = batch
        .ok(
            "/v1/describejobdefinitions",
            json!({"jobDefinitionName": "jd-identifiers", "status": state::STATUS_ACTIVE}),
        )
        .await;
    assert_eq!(
        definitions["jobDefinitions"].as_array().map(Vec::len),
        Some(1),
        "case the seeded job definition: a refused deregister must leave it ACTIVE, got \
         {definitions}"
    );
    let jobs = batch
        .ok(
            "/v1/describejobs",
            json!({"jobs": [&live_job, "not-a-known-job-id"]}),
        )
        .await;
    assert_eq!(
        jobs["jobs"].as_array().map(Vec::len),
        Some(1),
        "case the described jobs: only the submitted job may be held, got {jobs}"
    );
}

/// RULE: the name pattern governs the id a job reference NAMES, so the array-child form
/// this service mints (`<parent>:<index>`, `state::array_child_job_id`) is addressed like
/// any other job id — while a reference whose name is outside the pattern is refused
/// whatever index it carries.
#[tokio::test]
async fn an_array_child_id_is_addressed_like_any_other_job_id() {
    let batch = Batch::new();
    let environment = compute_environment(&batch, "ce-array-ids").await;
    let queue_arn = job_queue(&batch, "jq-array-ids", &environment).await;
    let (definition, _) = job_definition(&batch, "jd-array-ids", container_properties()).await;
    let submitted = batch
        .ok(
            "/v1/submitjob",
            json!({
                "jobName": "array-ids",
                "jobQueue": &queue_arn,
                "jobDefinition": &definition,
                "arrayProperties": {"size": 2},
            }),
        )
        .await;
    let parent = submitted["jobId"]
        .as_str()
        .unwrap_or_else(|| panic!("case the array submit: expected a jobId, got {submitted}"))
        .to_string();

    // Rows differ in the operation that ends the child and in WHICH index it addresses.
    // Nothing places a job here, so each child rests in `RUNNABLE` until a caller ends it.
    for (label, uri, index) in [
        ("CancelJob", "/v1/canceljob", 0),
        ("TerminateJob", "/v1/terminatejob", 1),
    ] {
        let child = state::array_child_job_id(&parent, index);
        let case = format!("{label} on the child {child:?}");
        let before = describe_job(&batch, &child).await;
        assert!(
            !state::is_terminal_status(before["status"].as_str().unwrap_or_default()),
            "case {case}: the child must still be endable, got {before}"
        );
        let reason = format!("ended by {label}");
        let (status, answered) = batch
            .call(uri, json!({"jobId": &child, "reason": &reason}))
            .await;
        assert_eq!(
            status, 200,
            "case {case}: a child id is a job id, got {status} {answered}"
        );
        let after = describe_job(&batch, &child).await;
        assert_eq!(
            after["status"].as_str(),
            Some(state::JOB_FAILED),
            "case {case}: the child must have been ended, got {after}"
        );
        assert_eq!(
            after["statusReason"].as_str(),
            Some(reason.as_str()),
            "case {case}: the caller's reason is what the child reports, got {after}"
        );
    }

    for uri in ["/v1/canceljob", "/v1/terminatejob"] {
        // A child of a parent nothing holds is a well-formed id that names nothing: the
        // operation's empty success, as any absent job id is.
        let absent = state::array_child_job_id("d2f30357-a68b-4772-8a03-c2a8564f2244", 3);
        let case = format!("{uri} on the absent child {absent:?}");
        let (status, answered) = batch
            .call(uri, json!({"jobId": &absent, "reason": "probe"}))
            .await;
        assert_eq!(
            status, 200,
            "case {case}: expected the empty success, got {status} {answered}"
        );

        // An index after a name the pattern does not admit is still refused: the index is
        // read apart, the NAME is what the pattern governs.
        let malformed = "not a job id!!:0";
        let case = format!("{uri} on {malformed:?}");
        let (status, refused) = batch
            .call(uri, json!({"jobId": malformed, "reason": "probe"}))
            .await;
        assert_eq!(
            status, 400,
            "case {case}: expected 400, got {status} {refused}"
        );
        assert_eq!(
            error_message(&refused),
            unsupported_name_sentence(malformed),
            "case {case}: expected the name-pattern sentence, got {refused}"
        );
    }
}
