// SPDX-License-Identifier: CC0-1.0

//! How CloudFront's resource-policy surface answers a `ResourceArn` it does not accept, end
//! to end over HTTP.
//!
//! Every assertion goes through the router, so each case exercises routing, restXml
//! (de)serialization, the handler, the persisted state and serialization — the same path a
//! client takes. The rule under test: each of the three operations judges its `ResourceArn`
//! as an ARGUMENT before it resolves it against the store, so the surface answers one of
//! three ways and never confuses two of them:
//!
//! * a value that is no ARN at all cannot be read as one, so it is refused on its FORM —
//!   HTTP 400 `InvalidArgument` with [`MALFORMED_ARN_MESSAGE`];
//! * an ARN whose resource part names any type other than the one this surface attaches
//!   policies to is refused on that TYPE — HTTP 400 `InvalidArgument`, worded as each
//!   operation words it (the two WRITES name the resource type they want,
//!   [`INVALID_RESOURCE_POLICY_RESOURCE_TYPE_MESSAGE`]; the READ demands a usable ARN,
//!   [`INVALID_RESOURCE_POLICY_ARN_MESSAGE`]) — whether or not this service holds a resource
//!   of that type, since the type a parameter names is a property of the value submitted;
//! * an ARN of the ACCEPTED type naming no resource this service holds is reported ABSENT —
//!   HTTP 404 `EntityNotFound` with [`NO_SUCH_RESOURCE_MESSAGE`], the sentence CloudFront
//!   answers for that class — since a policy is attached TO a resource, so the resource has
//!   to exist first.
//!
//! The rows differ along what the rule generalises over: the resource type the ARN names
//! (every type this service mints an ARN for), whether the resource the ARN names EXISTS, how
//! this emulator holds it (a kind that mints an ARN of its own, a kind addressed by the id
//! its own routes use, and a policy AWS publishes rather than the account), the ARN's
//! partition, region and account segments, the form of the resource id, the service the ARN
//! names, and which of the three operations asks.
//!
//! The harness (the router, the request helpers and the element scanner) is the lifecycle
//! suites', reused rather than copied.

use service_com_amazonaws_cloudfront_cloudfront2020_05_31::state::{
    EMPTY_RESOURCE_POLICY_DOCUMENT, INVALID_RESOURCE_POLICY_ARN_MESSAGE,
    INVALID_RESOURCE_POLICY_RESOURCE_TYPE_MESSAGE, MALFORMED_ARN_MESSAGE, MANAGED_CACHE_POLICIES,
    NO_SUCH_RESOURCE_MESSAGE, RESOURCE_POLICY_RESOURCE_TYPE, TAGGABLE_RESOURCE_TYPES,
};
use smithy_server_runtime::MultiServiceRouter;

use crate::distribution_lifecycle::{create_distribution, emulator, Answer, ACCOUNT_ID};
use crate::function_lifecycle::create_key_value_store;
use crate::public_key_lifecycle::{create_key, pem, Key};
use crate::resource_policy_delete::delete_resource_policy;
use crate::resource_policy_lifecycle::{
    created_vpc_origin_arn, distribution_config, get_resource_policy, message, policy,
    put_resource_policy, reported_document, stored, OTHER_RESOURCE_TYPES,
};

/// What the surface answers a row with: a status, an error code and, per operation, the
/// sentence that operation words the condition in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// The FORM refusal: the value is no ARN at all.
    Malformed,
    /// The EXISTENCE answer: the ARN names the accepted type and this service holds no
    /// resource it names.
    Absent,
    /// The TYPE refusal: the ARN names another resource type, held or not.
    WrongType,
}

impl Expected {
    /// The HTTP status and error code this outcome is answered with — one pair for every
    /// operation of the surface, since all three take the one `ResourceArn`.
    fn status_and_code(self) -> (u16, &'static str) {
        match self {
            Expected::Malformed | Expected::WrongType => (400, "InvalidArgument"),
            Expected::Absent => (404, "EntityNotFound"),
        }
    }

    /// The sentence `operation` puts on the wire for this outcome.
    fn message(self, operation: &str) -> &'static str {
        match (self, operation) {
            (Expected::Malformed, _) => MALFORMED_ARN_MESSAGE,
            (Expected::Absent, _) => NO_SUCH_RESOURCE_MESSAGE,
            (Expected::WrongType, "GetResourcePolicy") => INVALID_RESOURCE_POLICY_ARN_MESSAGE,
            (Expected::WrongType, _) => INVALID_RESOURCE_POLICY_RESOURCE_TYPE_MESSAGE,
        }
    }
}

/// Ask all three operations of the surface about `arn`, in the order a client that attaches,
/// reads and removes a policy would.
async fn ask_each_operation(router: &MultiServiceRouter, arn: &str) -> Vec<(&'static str, Answer)> {
    vec![
        (
            "PutResourcePolicy",
            put_resource_policy(router, arn, &policy(arn, "absent-resource-suite")).await,
        ),
        ("GetResourcePolicy", get_resource_policy(router, arn).await),
        (
            "DeleteResourcePolicy",
            delete_resource_policy(router, arn).await,
        ),
    ]
}

/// Create one resource of each kind a row names as EXISTING, answering the ARN that resource
/// carries beside the case each row is of.
///
/// The kinds differ in how this emulator holds them: a distribution and a key value store
/// mint an ARN of their own, a public key is addressed by the id its own routes use, and a
/// cache policy AWS publishes exists without this account ever creating one.
async fn existing_resources(router: &MultiServiceRouter) -> Vec<(String, String)> {
    let created = create_distribution(router, &distribution_config("ref-absent-resource")).await;
    assert_eq!(
        created.status, 201,
        "the distribution must be created for its row to be about its TYPE, got {} ({})",
        created.status, created.raw
    );
    let distribution_arn = created
        .root()
        .find_text("ARN")
        .unwrap_or_default()
        .to_string();

    let key_value_store_arn = create_key_value_store(router, "absent-resource-suite-store").await;

    let key = Key {
        case: "the public key of the absent-resource suite".to_string(),
        caller_reference: "ref-absent-resource-key".to_string(),
        name: "absent-resource-suite-key".to_string(),
        encoded_key: pem(2, 'a'),
        comment: None,
    };
    let uploaded = create_key(router, &key.xml()).await;
    assert_eq!(
        uploaded.status, 201,
        "the public key must be created for its row to be about its TYPE, got {} ({})",
        uploaded.status, uploaded.raw
    );
    let public_key_id = uploaded
        .root()
        .find_text("Id")
        .unwrap_or_default()
        .to_string();

    // A cache policy AWS publishes: it exists under its own id without this account creating
    // anything, and it is NOT the first entry of the catalogue, so the row does not stand on
    // whichever entry happens to come first.
    let published = MANAGED_CACHE_POLICIES
        .get(1)
        .expect("the published cache policy catalogue holds more than one entry");

    vec![
        (
            "the ARN of a distribution that exists".to_string(),
            distribution_arn,
        ),
        (
            "the ARN of a key value store that exists".to_string(),
            key_value_store_arn,
        ),
        (
            "the ARN of a public key that exists".to_string(),
            format!("arn:aws:cloudfront::{ACCOUNT_ID}:public-key/{public_key_id}"),
        ),
        (
            "the ARN of a cache policy AWS publishes".to_string(),
            format!(
                "arn:aws:cloudfront::{ACCOUNT_ID}:cache-policy/{}",
                published.id
            ),
        ),
    ]
}

#[tokio::test]
async fn the_resource_policy_surface_tells_an_absent_resource_from_a_type_it_refuses() {
    let router = emulator();

    // The policy every refusal below has to leave exactly as it is: the surface accepts this
    // ARN, so none of the rows may write under it or remove what it carries.
    let kept_arn = created_vpc_origin_arn(&router, "vo-survives-the-gate").await;
    let kept = policy(&kept_arn, "survivor");
    let written = put_resource_policy(&router, &kept_arn, &kept).await;
    assert_eq!(
        written.status, 200,
        "case the surviving policy: expected HTTP 200 from the write, got {} ({})",
        written.status, written.raw
    );

    let existing = existing_resources(&router).await;
    let mut rows: Vec<(String, String, Expected)> = existing
        .iter()
        .map(|(case, arn)| (case.clone(), arn.clone(), Expected::WrongType))
        .collect();

    // Every resource type this service mints an ARN for, each naming a resource the store
    // holds none of: the type the ARN names is read off the ARN, so every type but the
    // accepted one is the TYPE refusal, and the accepted one — which the store holds nothing
    // for here — is the absent answer.
    rows.extend(
        TAGGABLE_RESOURCE_TYPES
            .iter()
            .chain(OTHER_RESOURCE_TYPES.iter())
            .map(|kind| {
                (
                    format!("an absent {kind}"),
                    format!("arn:aws:cloudfront::{ACCOUNT_ID}:{kind}/absent-resource"),
                    if *kind == RESOURCE_POLICY_RESOURCE_TYPE {
                        Expected::Absent
                    } else {
                        Expected::WrongType
                    },
                )
            }),
    );

    // The accepted type under segments no stored resource carries, and resource ids of other
    // forms: what resolves a resource is the ARN it was minted with, so none of these names
    // one — and each is still an ARN of the type the surface accepts, so each is the absent
    // answer rather than the type refusal.
    let accepted_elsewhere = [
        (
            "the accepted type in another partition".to_string(),
            format!(
                "arn:aws-cn:cloudfront::{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}/vo-absent"
            ),
        ),
        (
            "the accepted type under another account".to_string(),
            format!("arn:aws:cloudfront::111122223333:{RESOURCE_POLICY_RESOURCE_TYPE}/vo-absent"),
        ),
        (
            "the accepted type with the region segment filled".to_string(),
            format!(
                "arn:aws:cloudfront:us-east-1:{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}/vo-absent"
            ),
        ),
        (
            "the accepted type with a one-character id".to_string(),
            format!("arn:aws:cloudfront::{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}/7"),
        ),
        (
            "the accepted type with an id carrying separators".to_string(),
            format!(
                "arn:aws:cloudfront::{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}/vo.absent_9-x"
            ),
        ),
    ];
    rows.extend(
        accepted_elsewhere
            .into_iter()
            .map(|(case, arn)| (case, arn, Expected::Absent)),
    );

    // The same resource part as a row that EXISTS, under segments no stored resource carries:
    // the type is still a distribution's, so what refuses these is the TYPE rather than the
    // store.
    let (_, distribution_arn, _) = rows[0].clone();
    rows.push((
        "an existing distribution's resource part in the other partition".to_string(),
        distribution_arn.replacen("arn:aws:", "arn:aws-cn:", 1),
        Expected::WrongType,
    ));
    rows.push((
        "an existing distribution's resource part under another account".to_string(),
        distribution_arn.replacen(ACCOUNT_ID, "111122223333", 1),
        Expected::WrongType,
    ));

    rows.extend([
        (
            "an ARN of another service naming the accepted type".to_string(),
            format!("arn:aws:ec2:us-east-1:{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}/vo-1"),
            Expected::WrongType,
        ),
        (
            "an ARN of another service entirely".to_string(),
            "arn:aws:s3:::absent-resource-suite-bucket".to_string(),
            Expected::WrongType,
        ),
        (
            "an ARN with no partition".to_string(),
            format!("arn::cloudfront::{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}/vo-1"),
            Expected::WrongType,
        ),
        (
            "an ARN carrying no resource part".to_string(),
            format!("arn:aws:cloudfront::{ACCOUNT_ID}:"),
            Expected::WrongType,
        ),
        (
            "a bare ARN prefix".to_string(),
            "arn:".to_string(),
            Expected::WrongType,
        ),
        (
            "an ARN naming the accepted type with no id".to_string(),
            format!("arn:aws:cloudfront::{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}"),
            Expected::WrongType,
        ),
        (
            "an ARN naming the accepted type with an empty id".to_string(),
            format!("arn:aws:cloudfront::{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}/"),
            Expected::WrongType,
        ),
        (
            "an ARN whose resource type merely starts with the accepted one".to_string(),
            format!("arn:aws:cloudfront::{ACCOUNT_ID}:{RESOURCE_POLICY_RESOURCE_TYPE}-group/vo-1"),
            Expected::WrongType,
        ),
        (
            "a value that is no ARN at all".to_string(),
            "not-an-arn".to_string(),
            Expected::Malformed,
        ),
        (
            "an accepted ARN with its prefix stripped".to_string(),
            kept_arn.strip_prefix("arn:").unwrap_or_default().to_string(),
            Expected::Malformed,
        ),
    ]);

    for (case, arn, expected) in &rows {
        let (status, code) = expected.status_and_code();
        for (operation, answer) in ask_each_operation(&router, arn).await {
            assert_eq!(
                answer.status, status,
                "case {case}/{operation}: expected HTTP {status} for {arn:?}, got {} ({})",
                answer.status, answer.raw
            );
            assert_eq!(
                answer.error_code(),
                code,
                "case {case}/{operation}: expected {code} for {arn:?}, got {:?} ({})",
                answer.error_code(),
                answer.raw
            );
            let sentence = expected.message(operation);
            assert_eq!(
                message(&answer),
                sentence,
                "case {case}/{operation}: expected message {sentence:?}, got {:?}",
                message(&answer)
            );
        }
    }

    // None of the refusals wrote or removed anything: the one policy the store holds is still
    // readable, in the form the write persisted it.
    let read = get_resource_policy(&router, &kept_arn).await;
    assert_eq!(
        read.status, 200,
        "case after the refusals: expected HTTP 200, got {} ({})",
        read.status, read.raw
    );
    let expected = stored(&kept);
    assert_eq!(
        reported_document(&read),
        expected.as_str(),
        "case after the refusals: expected the document {expected:?}, got {:?}",
        reported_document(&read)
    );
}

#[tokio::test]
async fn an_accepted_arn_carrying_no_policy_is_served_rather_than_refused() {
    let router = emulator();

    // An ARN the surface DOES accept is served whether or not a policy is attached to it:
    // the read reports the empty document and the removal is a no-op, where an ARN naming no
    // resource at all is the 404 the table above asserts. The rows differ along the endpoint
    // configuration the resource was created from.
    let mut rows: Vec<(&str, String)> = Vec::new();
    for (case, name) in [
        ("the first resource created", "vo-no-policy".to_string()),
        ("a one-character resource name", "7".to_string()),
        (
            "a resource name carrying separators",
            "vo.no_policy-2".to_string(),
        ),
        (
            "a resource name of sixty-four characters",
            "p".repeat(64),
        ),
    ] {
        rows.push((case, created_vpc_origin_arn(&router, &name).await));
    }

    for (case, arn) in &rows {
        for (operation, answer) in [
            ("GetResourcePolicy", get_resource_policy(&router, arn).await),
            (
                "DeleteResourcePolicy",
                delete_resource_policy(&router, arn).await,
            ),
        ] {
            assert_eq!(
                answer.status, 200,
                "case {case}/{operation}: expected HTTP 200, got {} ({})",
                answer.status, answer.raw
            );
            assert_eq!(
                answer.error_code(),
                "",
                "case {case}/{operation}: expected no error, got {:?} ({})",
                answer.error_code(),
                answer.raw
            );
        }

        // The read reports the policy that grants nothing, which is where a get-then-put
        // flow starts from.
        let read = get_resource_policy(&router, arn).await;
        assert_eq!(
            reported_document(&read),
            EMPTY_RESOURCE_POLICY_DOCUMENT,
            "case {case}: expected the empty document, got {:?}",
            reported_document(&read)
        );

        // And the write under the same ARN is accepted, so what the two calls above answered
        // was the absence of a POLICY rather than a refusal of the parameter.
        let document = policy(arn, case);
        let written = put_resource_policy(&router, arn, &document).await;
        assert_eq!(
            written.status, 200,
            "case {case}: expected HTTP 200 from the write, got {} ({})",
            written.status, written.raw
        );
        let read = get_resource_policy(&router, arn).await;
        let expected = stored(&document);
        assert_eq!(
            reported_document(&read),
            expected.as_str(),
            "case {case}: expected the document {expected:?}, got {:?}",
            reported_document(&read)
        );
    }
}
