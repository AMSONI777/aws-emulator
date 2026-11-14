// SPDX-License-Identifier: CC0-1.0

//! The REFUSAL an agreement request that configures both directory configurations at
//! once is answered with, and what its `Message` reports.
//!
//! RULE: a `CreateAgreement` or `UpdateAgreement` that names both `BaseDirectory` and
//! `CustomDirectories` — which the two operations' own modelled documentation forbids
//! ("Specify either BaseDirectory or CustomDirectories, but not both. Specifying both
//! causes the command to fail.") — is refused 400 `InvalidRequestException` whose
//! `Message` reports the two configurations the request carried: a fixed sentence,
//! then the request's `BaseDirectory`, then the whole `CustomDirectories` structure
//! under its shape name with its five members in model order and their lowerCamelCase
//! labels. Every variable part comes from the REQUEST, so two requests that conflict
//! over different directories read differently and a caller can tell which side to
//! drop.
//!
//! The rows differ along what the rule generalises over: the `BaseDirectory` value
//! (short, deeply nested, carrying spaces and dots, and one at the modelled maximum
//! length), the five `CustomDirectories` values (all distinct, all equal, and the blank
//! value `HomeDirectory`'s pattern admits), and the operation the conflict is sent to
//! (`CreateAgreement`, and `UpdateAgreement` over agreements stored on either
//! configuration). The recorded case — one base directory beside five distinct custom
//! directories, sent to an update — is one row of it.
//!
//! Two controls ride along: the same `CustomDirectories` sent WITHOUT a base directory
//! is served, and sent beside the blank `BaseDirectory` (which names no directory) it
//! is served too — so the refusal is about two configurations being configured, not
//! about sending the member.
//!
//! Every request goes over the real wire path (`POST /` with
//! `X-Amz-Target: TransferService.<Op>`) through the shared [`crate::harness`], so what
//! is asserted is what an SDK sees.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::harness::{
    assert_members, both_directories_configured_message, custom_directories, member_of, Answer,
    Emulator, CUSTOM_DIRECTORY_MEMBERS, ROLE,
};

/// `HomeDirectory`'s modelled `len 0..1024` upper bound, which `BaseDirectory` targets
/// (`smithy_query(query="operation",operation="UpdateAgreement")` reports
/// `BaseDirectory (HomeDirectory, len 0..1024, pattern ^(|/.*)$)`).
const MAX_HOME_DIRECTORY: usize = 1024;

/// A `BaseDirectory` of exactly the modelled maximum length, rooted at `/` as the
/// pattern `^(|/.*)$` requires.
fn longest_base_directory() -> String {
    let mut directory = String::from("/");
    directory.push_str(&"d".repeat(MAX_HOME_DIRECTORY - 1));
    directory
}

/// The request body of a `CustomDirectories` whose five members carry `values`, in model
/// order.
fn custom_directories_of(values: &[String; 5]) -> Value {
    let mut object = serde_json::Map::new();
    for ((member, _), value) in CUSTOM_DIRECTORY_MEMBERS.iter().zip(values.iter()) {
        object.insert((*member).to_string(), json!(value));
    }
    Value::Object(object)
}

/// The `Message` the rule requires for a request carrying `base_directory` beside the
/// five `custom_directories` values, rendered by the shared template in
/// [`crate::harness`].
fn expected_message(base_directory: &str, values: &[String; 5]) -> String {
    both_directories_configured_message(base_directory, &custom_directories_of(values))
}

/// `base` with every member of `overrides` inserted over it.
fn with(base: &Value, overrides: Value) -> Value {
    let mut merged = base.clone();
    let object = merged.as_object_mut().expect("the base is an object");
    for (member, value) in overrides.as_object().expect("the overrides are an object") {
        object.insert(member.clone(), value.clone());
    }
    merged
}

/// The two profiles and the server every agreement here combines.
struct Partnership {
    server_id: String,
    local_profile: String,
    partner_profile: String,
}

impl Partnership {
    async fn create(emulator: &Emulator) -> Self {
        let server_id = emulator.create_server(json!({})).await;
        let local_profile = emulator
            .create_profile(json!({"As2Id": "local-party", "ProfileType": "LOCAL"}))
            .await;
        let partner_profile = emulator
            .create_profile(json!({"As2Id": "partner-party", "ProfileType": "PARTNER"}))
            .await;
        Self {
            server_id,
            local_profile,
            partner_profile,
        }
    }

    /// The members every agreement request of this suite carries.
    fn base_request(&self) -> Value {
        json!({
            "ServerId": &self.server_id,
            "LocalProfileId": &self.local_profile,
            "PartnerProfileId": &self.partner_profile,
            "AccessRole": ROLE,
        })
    }

    /// Create one agreement configured with `directories` and return its `AgreementId`.
    async fn create_agreement(&self, emulator: &Emulator, case: &str, directories: Value) -> String {
        emulator
            .create_agreement(case, with(&self.base_request(), directories))
            .await
    }
}

/// The directory conflict ONE row sends: a `BaseDirectory` and five custom directories,
/// both named in the same request.
struct Conflict {
    case: &'static str,
    base_directory: String,
    custom: [String; 5],
}

/// Five values from one prefix, the shape a caller configures custom directories with.
fn spread(prefix: &str) -> [String; 5] {
    [
        format!("{prefix}/failed"),
        format!("{prefix}/mdn"),
        format!("{prefix}/payload"),
        format!("{prefix}/status"),
        format!("{prefix}/temporary"),
    ]
}

/// The conflicts this suite asserts the rule over. The rows differ along the
/// `BaseDirectory` value and along the five custom directory values: all distinct, all
/// pointing at one directory, one of them the blank value `HomeDirectory`'s pattern
/// `^(|/.*)$` admits, all five blank, and a base directory at the modelled maximum
/// length.
fn conflicts() -> Vec<Conflict> {
    let one_place = "/amzn-s3-demo-bucket/as2/single".to_string();
    vec![
        Conflict {
            case: "five distinct custom directories beside a base directory",
            base_directory: "/amzn-s3-demo-bucket/as2".to_string(),
            custom: spread("/amzn-s3-demo-bucket"),
        },
        Conflict {
            case: "another bucket entirely, so no value is shared with the row above",
            base_directory: "/other-bucket/home/mydirectory".to_string(),
            custom: spread("/other-bucket/as2"),
        },
        Conflict {
            case: "a base directory at the bucket root beside five custom directories \
                   that all name the same place",
            base_directory: "/amzn-s3-demo-bucket".to_string(),
            custom: [
                one_place.clone(),
                one_place.clone(),
                one_place.clone(),
                one_place.clone(),
                one_place,
            ],
        },
        Conflict {
            case: "a deeply nested base directory, and custom directories carrying \
                   spaces and dots",
            base_directory: "/amzn-s3-demo-bucket/a/b/c/d/e/f/g/home".to_string(),
            custom: spread("/amzn-s3-demo-bucket/as2 inbox/v1.0"),
        },
        Conflict {
            case: "one custom directory left blank, the value HomeDirectory's pattern \
                   admits beside a rooted path",
            base_directory: "/amzn-s3-demo-bucket/as2".to_string(),
            custom: {
                let mut values = spread("/amzn-s3-demo-bucket/as2");
                values[1] = String::new();
                values
            },
        },
        Conflict {
            case: "all five custom directories blank",
            base_directory: "/amzn-s3-demo-bucket/as2".to_string(),
            custom: [
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ],
        },
        Conflict {
            case: "a base directory of the modelled maximum length",
            base_directory: longest_base_directory(),
            custom: spread("/amzn-s3-demo-bucket/as2/longest"),
        },
    ]
}

/// Assert `answer` is the modelled refusal, with exactly the `Message` the rule
/// requires, and return that message.
fn assert_conflict_refusal(case: &str, answer: &Answer, expected: &str) -> String {
    // 400 is `InvalidRequestException`'s modelled `@httpError`.
    assert_eq!(
        answer.status, 400,
        "case {case:?}: expected HTTP 400, got {} with body {}",
        answer.status, answer.body
    );
    assert_eq!(
        answer.error_code(),
        "InvalidRequestException",
        "case {case:?}: expected InvalidRequestException, got body {}",
        answer.body
    );
    let actual = member_of(&answer.body, "Message")
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        actual, expected,
        "case {case:?}: expected Message {expected:?}, got {actual:?}"
    );
    actual
}

/// RULE: the both-directories refusal of an agreement UPDATE reports the two
/// configurations the request carried, and nothing is written.
///
/// The rows are [`conflicts`] — the base directory and the five custom directory values
/// the request names — crossed with the configuration the stored agreement already has,
/// so a conflict is asserted both on an agreement living on a base directory and on one
/// living on custom directories.
#[tokio::test]
async fn an_update_naming_both_directory_configurations_reports_both_of_them() {
    let emulator = Emulator::new();
    let partnership = Partnership::create(&emulator).await;

    // (what the stored agreement is configured with, the members DescribeAgreement must
    // keep reporting for it)
    let stored_on: [(&str, Value, Value); 2] = [
        (
            "an agreement stored on a base directory",
            json!({"BaseDirectory": "/amzn-s3-demo-bucket/home/stored"}),
            json!({
                "BaseDirectory": "/amzn-s3-demo-bucket/home/stored",
                "CustomDirectories": null,
            }),
        ),
        (
            "an agreement stored on custom directories",
            json!({"CustomDirectories": custom_directories("/amzn-s3-demo-bucket/as2/stored")}),
            json!({
                "CustomDirectories": custom_directories("/amzn-s3-demo-bucket/as2/stored"),
                "BaseDirectory": null,
            }),
        ),
    ];

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (stored_case, directories, expected_record) in stored_on {
        let agreement_id = partnership
            .create_agreement(&emulator, stored_case, directories)
            .await;

        for conflict in conflicts() {
            let case = format!("{} updated with {}", stored_case, conflict.case);
            let case = case.as_str();
            let answer = emulator
                .call(
                    "UpdateAgreement",
                    json!({
                        "ServerId": &partnership.server_id,
                        "AgreementId": &agreement_id,
                        "BaseDirectory": &conflict.base_directory,
                        "CustomDirectories": custom_directories_of(&conflict.custom),
                        // A change the refusal must not apply either.
                        "Status": "ACTIVE",
                    }),
                )
                .await;
            let message = assert_conflict_refusal(
                case,
                &answer,
                &expected_message(&conflict.base_directory, &conflict.custom),
            );
            seen.insert(message);

            // The refused update wrote NOTHING: the agreement still reports the
            // configuration the create gave it.
            let described = emulator
                .describe_agreement(&partnership.server_id, &agreement_id)
                .await;
            assert_eq!(
                described.status, 200,
                "case {case:?}: expected DescribeAgreement 200, got {} with body {}",
                described.status, described.body
            );
            assert_members(case, described.get("Agreement"), &expected_record);
        }
    }

    // The text is not fixed prose: every row conflicting over different directories read
    // differently, so the two stored configurations contributed one message each per
    // conflict.
    assert_eq!(
        seen.len(),
        conflicts().len(),
        "case \"the refusals of all rows\": expected one distinct Message per conflict, \
         got {seen:?}"
    );
}

/// RULE, on the CREATE the same documented sentence governs: a create naming both
/// configurations is refused with the same reported conflict, and no agreement is
/// written.
#[tokio::test]
async fn a_create_naming_both_directory_configurations_reports_both_of_them() {
    let emulator = Emulator::new();
    let partnership = Partnership::create(&emulator).await;

    for conflict in conflicts() {
        let case = format!("CreateAgreement with {}", conflict.case);
        let case = case.as_str();
        let answer = emulator
            .call(
                "CreateAgreement",
                with(
                    &partnership.base_request(),
                    json!({
                        "BaseDirectory": &conflict.base_directory,
                        "CustomDirectories": custom_directories_of(&conflict.custom),
                    }),
                ),
            )
            .await;
        assert_conflict_refusal(
            case,
            &answer,
            &expected_message(&conflict.base_directory, &conflict.custom),
        );

        // Nothing was created: the store still holds no agreement at all. (`DescribeAgreement`
        // cannot be asked, since a refused create minted no id to address, and
        // `ListAgreements` is still scaffolded, so the store itself is the reader.)
        let agreements = emulator.store().lock().agreements.len();
        assert_eq!(
            agreements, 0,
            "case {case:?}: expected a refused create to persist nothing, got {agreements} \
             stored agreements"
        );
    }
}

/// CONTROL: the very `CustomDirectories` a conflicting row carries is SERVED when no
/// base directory is configured beside it — sent alone, and sent beside the blank
/// `BaseDirectory` that names no directory — so the refusal is about two configurations
/// being configured at once.
#[tokio::test]
async fn custom_directories_without_a_base_directory_are_served() {
    let emulator = Emulator::new();
    let partnership = Partnership::create(&emulator).await;
    let agreement_id = partnership
        .create_agreement(
            &emulator,
            "the agreement the controls update",
            json!({"BaseDirectory": "/amzn-s3-demo-bucket/home/control"}),
        )
        .await;

    for (index, conflict) in conflicts().into_iter().enumerate() {
        let custom = custom_directories_of(&conflict.custom);
        // Alternate the rows between the member left out entirely and the blank value
        // `HomeDirectory`'s pattern admits, which names no directory.
        let (shape, mut request) = if index % 2 == 0 {
            ("no BaseDirectory member at all", json!({}))
        } else {
            ("a blank BaseDirectory", json!({"BaseDirectory": ""}))
        };
        request = with(
            &request,
            json!({
                "ServerId": &partnership.server_id,
                "AgreementId": &agreement_id,
                "CustomDirectories": custom.clone(),
            }),
        );
        let case = format!("{} with {}", conflict.case, shape);
        let case = case.as_str();

        let answer = emulator.call("UpdateAgreement", request).await;
        assert_eq!(
            answer.status, 200,
            "case {case:?}: expected UpdateAgreement 200, got {} with body {}",
            answer.status, answer.body
        );
        let described = emulator
            .describe_agreement(&partnership.server_id, &agreement_id)
            .await;
        assert_members(
            case,
            described.get("Agreement"),
            &json!({"CustomDirectories": custom, "BaseDirectory": null}),
        );
    }
}
