// SPDX-License-Identifier: CC0-1.0

//! Which application a session's triple is resolved inside, driven end to end over HTTP.
//!
//! The rule under test is about identifier SCOPE, not about one pair of applications: a
//! configuration profile and an environment are children of the application the request
//! named, so each of a session's three identifiers resolves only inside its parent. Two
//! applications may therefore hold an environment and a configuration profile of the very
//! same NAME, and each session serves only what its own application's triple has in force;
//! an identifier that names a record held only by the sibling application resolves to
//! nothing and the session is refused with the modelled `ResourceNotFoundException` (404)
//! naming that level's `ResourceType` and the request member that referenced it.
//!
//! Every case drives real requests through the router harness the polling suite sets up
//! ([`super::configuration_session_poll::Emulator`]), which mounts AppConfigData and the
//! AppConfig control plane over one shared engine: both hierarchies are created, deployed
//! and polled through the services' own operations, so what a session resolves comes from
//! the emulator's own state.

use super::configuration_session_poll::{Emulator, Hierarchy};

/// The environment name BOTH applications give their environment, and the profile name
/// both give their configuration profile: the whole point of the suite is that a name at
/// a child level says nothing by itself.
const SHARED_ENVIRONMENT: &str = "Prod";
/// See [`SHARED_ENVIRONMENT`].
const SHARED_PROFILE: &str = "Shared";

/// Which of the two applications a case is talking about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// The application whose session every case polls.
    Own,
    /// The other application, holding same-named children of its own.
    Sibling,
}

/// One configuration, as an application deploys it for its own profile.
#[derive(Debug, Clone, Copy)]
struct Deployed {
    content: &'static [u8],
    content_type: &'static str,
    version_label: Option<&'static str>,
}

/// One delivery case: both applications hold a same-named environment and a same-named
/// configuration profile, each with its OWN configuration deployed. The rows differ along
/// what the rule generalises over — how each identifier is spelled (id or name), which
/// application's session is started first, and the form, content type and labelling of the
/// two configurations.
struct DeliveryCase {
    name: &'static str,
    /// Whether the `[application, environment, configuration profile]` identifier of each
    /// session is spelled as an ID rather than as a NAME.
    by_id: [bool; 3],
    /// Which application's session is started and polled first.
    first: Side,
    own: Deployed,
    sibling: Deployed,
}

const DELIVERY_CASES: &[DeliveryCase] = &[
    DeliveryCase {
        name: "both triples spelled by name, a json document on either side",
        by_id: [false, false, false],
        first: Side::Own,
        own: Deployed {
            content: br#"{"owner":"own","feature":"on"}"#,
            content_type: "application/json",
            version_label: Some("own-1"),
        },
        sibling: Deployed {
            content: br#"{"owner":"sibling","feature":"off"}"#,
            content_type: "application/json",
            version_label: Some("sibling-1"),
        },
    },
    DeliveryCase {
        name: "both triples spelled by id, plain text, the sibling polled first",
        by_id: [true, true, true],
        first: Side::Sibling,
        own: Deployed {
            content: b"own",
            content_type: "text/plain",
            version_label: None,
        },
        sibling: Deployed {
            content: b"sibling",
            content_type: "text/plain",
            version_label: None,
        },
    },
    DeliveryCase {
        name: "the environment by id and the rest by name, yaml against a binary blob",
        by_id: [false, true, false],
        first: Side::Own,
        own: Deployed {
            content: b"owner: own\nextra: 2\n",
            content_type: "application/x-yaml",
            version_label: Some("own-yaml"),
        },
        sibling: Deployed {
            content: &[0x00, 0x9f, 0x92, 0x96, 0xff],
            content_type: "application/octet-stream",
            version_label: Some("sibling-binary"),
        },
    },
    DeliveryCase {
        name: "the profile by id and the rest by name, one and the same version label on \
               both sides",
        by_id: [false, false, true],
        first: Side::Sibling,
        own: Deployed {
            content: br#"{"owner":"own"}"#,
            content_type: "application/json",
            version_label: Some("release-7"),
        },
        sibling: Deployed {
            content: br#"{"owner":"sibling"}"#,
            content_type: "application/json",
            version_label: Some("release-7"),
        },
    },
    DeliveryCase {
        name: "the application by id and the rest by name, only the sibling's version \
               labelled",
        by_id: [true, false, false],
        first: Side::Own,
        own: Deployed {
            content: b"own bytes",
            content_type: "text/plain",
            version_label: None,
        },
        sibling: Deployed {
            content: b"sibling bytes",
            content_type: "application/octet-stream",
            version_label: Some("sibling-only"),
        },
    },
];

/// The identifier of one level, spelled as the case asks for it.
fn spelled(by_id: bool, id: &str, name: &str) -> String {
    if by_id {
        id.to_string()
    } else {
        name.to_string()
    }
}

/// Create the two applications, each with an environment and a configuration profile
/// under the SAME names, and deploy each side's own configuration.
async fn two_applications(
    emulator: &Emulator,
    own: Deployed,
    sibling: Deployed,
) -> (Hierarchy, Hierarchy) {
    let own_hierarchy = emulator
        .create_hierarchy("OwnApplication", SHARED_ENVIRONMENT, SHARED_PROFILE)
        .await;
    let sibling_hierarchy = emulator
        .create_hierarchy("SiblingApplication", SHARED_ENVIRONMENT, SHARED_PROFILE)
        .await;
    emulator
        .deploy(
            &own_hierarchy,
            &own_hierarchy.profile_id,
            own.content,
            own.content_type,
            own.version_label,
        )
        .await;
    emulator
        .deploy(
            &sibling_hierarchy,
            &sibling_hierarchy.profile_id,
            sibling.content,
            sibling.content_type,
            sibling.version_label,
        )
        .await;
    (own_hierarchy, sibling_hierarchy)
}

/// Start a session over `hierarchy`, spelled as the case asks, and poll it once.
async fn poll_once(
    emulator: &Emulator,
    hierarchy: &Hierarchy,
    by_id: [bool; 3],
    case: &str,
    side: Side,
) -> (Vec<u8>, Option<String>, Option<String>) {
    let token = emulator
        .session_token(
            &spelled(
                by_id[0],
                &hierarchy.application_id,
                &hierarchy.application_name,
            ),
            &spelled(
                by_id[1],
                &hierarchy.environment_id,
                &hierarchy.environment_name,
            ),
            &spelled(by_id[2], &hierarchy.profile_id, &hierarchy.profile_name),
        )
        .await;
    let reply = emulator.get_latest_configuration(&token).await;
    assert_eq!(
        reply.status,
        200,
        "case {case:?} ({side:?}): expected 200, got {} body {}",
        reply.status,
        reply.text()
    );
    (
        reply.body.to_vec(),
        reply.header("content-type").map(str::to_string),
        reply.header("version-label").map(str::to_string),
    )
}

/// A session serves the configuration ITS OWN application's triple has in force, even
/// when the sibling application holds an environment and a configuration profile of the
/// same name with another configuration deployed.
#[tokio::test]
async fn a_session_serves_only_its_own_applications_configuration() {
    for case in DELIVERY_CASES {
        let name = case.name;
        let emulator = Emulator::new();
        let (own, sibling) = two_applications(&emulator, case.own, case.sibling).await;

        let order = match case.first {
            Side::Own => [(Side::Own, &own), (Side::Sibling, &sibling)],
            Side::Sibling => [(Side::Sibling, &sibling), (Side::Own, &own)],
        };
        for (side, hierarchy) in order {
            let expected = match side {
                Side::Own => case.own,
                Side::Sibling => case.sibling,
            };
            let other = match side {
                Side::Own => case.sibling,
                Side::Sibling => case.own,
            };
            let (body, content_type, version_label) =
                poll_once(&emulator, hierarchy, case.by_id, name, side).await;
            assert_eq!(
                body.as_slice(),
                expected.content,
                "case {name:?} ({side:?}): expected this application's own content, got {body:?}"
            );
            assert_ne!(
                body.as_slice(),
                other.content,
                "case {name:?} ({side:?}): the sibling application's content was delivered, \
                 got {body:?}"
            );
            assert_eq!(
                content_type.as_deref(),
                Some(expected.content_type),
                "case {name:?} ({side:?}): expected content type {:?}, got {content_type:?}",
                expected.content_type
            );
            assert_eq!(
                version_label.as_deref(),
                expected.version_label,
                "case {name:?} ({side:?}): expected version label {:?}, got {version_label:?}",
                expected.version_label
            );
        }
    }
}

/// Which identifier of a session's triple is taken from the sibling application, and the
/// level the refusal must then name.
struct BorrowedCase {
    name: &'static str,
    /// Which level the request borrows from the sibling application, and whether it
    /// borrows that level's id or a name only the sibling holds.
    borrowed: Borrowed,
    /// The modelled `ResourceType` value the refusal reports, from the model's
    /// `ResourceType` enum (Application, ConfigurationProfile, Deployment, Environment,
    /// Configuration — `smithy_query(query="shape",shape="ResourceType")`).
    resource_type: &'static str,
    /// The `StartConfigurationSession` input member `ReferencedBy` is keyed by.
    referenced_by: &'static str,
}

/// What a case takes from the sibling application.
#[derive(Debug, Clone, Copy)]
enum Borrowed {
    /// The sibling's configuration profile, by the id the control plane minted for it.
    SiblingProfileId,
    /// A configuration profile NAME only the sibling application holds.
    SiblingOnlyProfileName,
    /// The id of a configuration profile only the sibling application holds, so no name
    /// of that profile exists under either application.
    SiblingOnlyProfileId,
    /// The sibling's environment, by the id the control plane minted for it.
    SiblingEnvironmentId,
    /// An environment NAME only the sibling application holds.
    SiblingOnlyEnvironmentName,
    /// The id of an environment only the sibling application holds.
    SiblingOnlyEnvironmentId,
    /// This application's own configuration profile, asked for under the SIBLING
    /// application — the mirror image of the rows above.
    OwnProfileUnderTheSibling,
}

/// The name of the environment created only under the sibling application.
const SIBLING_ONLY_ENVIRONMENT: &str = "SiblingOnlyEnvironment";
/// The name of the configuration profile created only under the sibling application.
const SIBLING_ONLY_PROFILE: &str = "SiblingOnlyProfile";

const BORROWED_CASES: &[BorrowedCase] = &[
    BorrowedCase {
        name: "the sibling's configuration profile, by id, although it is deployed there",
        borrowed: Borrowed::SiblingProfileId,
        resource_type: "ConfigurationProfile",
        referenced_by: "ConfigurationProfileIdentifier",
    },
    BorrowedCase {
        name: "a configuration profile name only the sibling application holds",
        borrowed: Borrowed::SiblingOnlyProfileName,
        resource_type: "ConfigurationProfile",
        referenced_by: "ConfigurationProfileIdentifier",
    },
    BorrowedCase {
        name: "a configuration profile only the sibling application holds, by id",
        borrowed: Borrowed::SiblingOnlyProfileId,
        resource_type: "ConfigurationProfile",
        referenced_by: "ConfigurationProfileIdentifier",
    },
    BorrowedCase {
        name: "the sibling's environment, by id",
        borrowed: Borrowed::SiblingEnvironmentId,
        resource_type: "Environment",
        referenced_by: "EnvironmentIdentifier",
    },
    BorrowedCase {
        name: "an environment name only the sibling application holds",
        borrowed: Borrowed::SiblingOnlyEnvironmentName,
        resource_type: "Environment",
        referenced_by: "EnvironmentIdentifier",
    },
    BorrowedCase {
        name: "an environment only the sibling application holds, by id",
        borrowed: Borrowed::SiblingOnlyEnvironmentId,
        resource_type: "Environment",
        referenced_by: "EnvironmentIdentifier",
    },
    BorrowedCase {
        name: "this application's own configuration profile, asked for under the sibling \
               application",
        // The mirror image: the environment NAME the request carries is one the sibling
        // does hold, so the profile is the only level that cannot resolve there.
        borrowed: Borrowed::OwnProfileUnderTheSibling,
        resource_type: "ConfigurationProfile",
        referenced_by: "ConfigurationProfileIdentifier",
    },
];

/// One configuration each side deploys for the refusal cases: the bytes differ, so a
/// cross-delivery would be visible if a refusal were ever served instead.
const OWN_CONTENT: &[u8] = br#"{"owner":"own"}"#;
/// See [`OWN_CONTENT`].
const SIBLING_CONTENT: &[u8] = br#"{"owner":"sibling"}"#;

/// An identifier that names a record held only by the sibling application resolves to
/// nothing: the session is refused with the modelled `ResourceNotFoundException` naming
/// the level and the request member that referenced it, no token is minted, and the
/// application's own session keeps serving its own configuration.
#[tokio::test]
async fn an_identifier_held_only_by_the_sibling_application_is_not_found() {
    for case in BORROWED_CASES {
        let name = case.name;
        let emulator = Emulator::new();
        let (own, sibling) = two_applications(
            &emulator,
            Deployed {
                content: OWN_CONTENT,
                content_type: "application/json",
                version_label: Some("own"),
            },
            Deployed {
                content: SIBLING_CONTENT,
                content_type: "application/json",
                version_label: Some("sibling"),
            },
        )
        .await;
        let sibling_only_environment = emulator
            .create_environment(&sibling.application_id, SIBLING_ONLY_ENVIRONMENT)
            .await;
        let sibling_only_profile = emulator
            .create_profile(&sibling.application_id, SIBLING_ONLY_PROFILE)
            .await;
        let (application, environment, profile) = match case.borrowed {
            Borrowed::SiblingProfileId => (
                own.application_name.clone(),
                own.environment_name.clone(),
                sibling.profile_id.clone(),
            ),
            Borrowed::SiblingOnlyProfileName => (
                own.application_name.clone(),
                own.environment_name.clone(),
                SIBLING_ONLY_PROFILE.to_string(),
            ),
            Borrowed::SiblingOnlyProfileId => (
                own.application_name.clone(),
                own.environment_name.clone(),
                sibling_only_profile.clone(),
            ),
            Borrowed::SiblingEnvironmentId => (
                own.application_name.clone(),
                sibling.environment_id.clone(),
                own.profile_name.clone(),
            ),
            Borrowed::SiblingOnlyEnvironmentName => (
                own.application_name.clone(),
                SIBLING_ONLY_ENVIRONMENT.to_string(),
                own.profile_name.clone(),
            ),
            Borrowed::SiblingOnlyEnvironmentId => (
                own.application_name.clone(),
                sibling_only_environment.clone(),
                own.profile_name.clone(),
            ),
            Borrowed::OwnProfileUnderTheSibling => (
                sibling.application_name.clone(),
                sibling.environment_name.clone(),
                own.profile_id.clone(),
            ),
        };

        let reply = emulator
            .post_json(
                "/configurationsessions",
                &format!(
                    r#"{{"ApplicationIdentifier":"{application}",
                          "EnvironmentIdentifier":"{environment}",
                          "ConfigurationProfileIdentifier":"{profile}"}}"#
                ),
            )
            .await;
        assert_eq!(
            reply.status,
            404,
            "case {name:?}: expected 404, got {} body {}",
            reply.status,
            reply.text()
        );
        assert_eq!(
            reply.error_code(),
            "ResourceNotFoundException",
            "case {name:?}: expected ResourceNotFoundException, got {}",
            reply.text()
        );
        let body = reply.json();
        assert_eq!(
            body["ResourceType"].as_str(),
            Some(case.resource_type),
            "case {name:?}: expected ResourceType {:?}, got {}",
            case.resource_type,
            reply.text()
        );
        let expected_value = match case.referenced_by {
            "EnvironmentIdentifier" => environment.as_str(),
            _ => profile.as_str(),
        };
        assert_eq!(
            body["ReferencedBy"][case.referenced_by].as_str(),
            Some(expected_value),
            "case {name:?}: expected ReferencedBy to carry {:?} => {expected_value:?}, got {}",
            case.referenced_by,
            reply.text()
        );
        assert!(
            body["InitialConfigurationToken"].is_null(),
            "case {name:?}: a refused session mints no token, got {}",
            reply.text()
        );

        // The refusal changed nothing: each application's own session still serves its
        // own configuration.
        for (side, hierarchy, expected) in [
            (Side::Own, &own, OWN_CONTENT),
            (Side::Sibling, &sibling, SIBLING_CONTENT),
        ] {
            let (served, _, _) = poll_once(
                &emulator,
                hierarchy,
                [false, false, false],
                name,
                side,
            )
            .await;
            assert_eq!(
                served.as_slice(),
                expected,
                "case {name:?} ({side:?}): after the refusal this application must still \
                 serve its own content, got {served:?}"
            );
        }
    }
}

/// A configuration profile of the same name exists under both applications, but only the
/// sibling has deployed into its environment: the session over the undeployed triple is
/// refused as the missing DEPLOYMENT — identified by the whole triple, so `ReferencedBy`
/// carries all three members — and never served the sibling's bytes.
#[tokio::test]
async fn a_deployment_under_the_sibling_application_does_not_make_this_triple_pollable() {
    let emulator = Emulator::new();
    let own = emulator
        .create_hierarchy("OwnApplication", SHARED_ENVIRONMENT, SHARED_PROFILE)
        .await;
    let sibling = emulator
        .create_hierarchy("SiblingApplication", SHARED_ENVIRONMENT, SHARED_PROFILE)
        .await;
    emulator
        .deploy(
            &sibling,
            &sibling.profile_id,
            SIBLING_CONTENT,
            "application/json",
            Some("sibling"),
        )
        .await;

    // Every spelling of the undeployed triple is refused the same way.
    let spellings: &[(&str, [bool; 3])] = &[
        ("all three by name", [false, false, false]),
        ("all three by id", [true, true, true]),
        ("the profile by id, the rest by name", [false, false, true]),
    ];
    for (name, by_id) in spellings {
        let application = spelled(by_id[0], &own.application_id, &own.application_name);
        let environment = spelled(by_id[1], &own.environment_id, &own.environment_name);
        let profile = spelled(by_id[2], &own.profile_id, &own.profile_name);
        let reply = emulator
            .post_json(
                "/configurationsessions",
                &format!(
                    r#"{{"ApplicationIdentifier":"{application}",
                          "EnvironmentIdentifier":"{environment}",
                          "ConfigurationProfileIdentifier":"{profile}"}}"#
                ),
            )
            .await;
        assert_eq!(
            reply.status,
            404,
            "case {name:?}: expected 404, got {} body {}",
            reply.status,
            reply.text()
        );
        let body = reply.json();
        assert_eq!(
            body["ResourceType"].as_str(),
            Some("Deployment"),
            "case {name:?}: expected the Deployment resource type, got {}",
            reply.text()
        );
        for (member, value) in [
            ("ApplicationIdentifier", &application),
            ("EnvironmentIdentifier", &environment),
            ("ConfigurationProfileIdentifier", &profile),
        ] {
            assert_eq!(
                body["ReferencedBy"][member].as_str(),
                Some(value.as_str()),
                "case {name:?}: a deployment is identified by the whole triple, so \
                 ReferencedBy must carry {member}, got {}",
                reply.text()
            );
        }
        assert!(
            body["InitialConfigurationToken"].is_null(),
            "case {name:?}: a refused session mints no token, got {}",
            reply.text()
        );
    }

    // And the sibling, which HAS deployed, still polls its own configuration.
    let (served, _, _) = poll_once(
        &emulator,
        &sibling,
        [false, false, false],
        "the sibling application polls its own deployment",
        Side::Sibling,
    )
    .await;
    assert_eq!(
        served.as_slice(),
        SIBLING_CONTENT,
        "the sibling application must serve its own deployed content, got {served:?}"
    );
}
