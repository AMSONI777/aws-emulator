// SPDX-License-Identifier: CC0-1.0

//! The modelled constraints on this service's input members, measured before an operation
//! reads or writes anything.
//!
//! RULE: every modelled constraint on an input member is enforced BEFORE the operation
//! runs — including a `@pattern` whose expression the request walk's regex engine cannot
//! compile, which that walk treats as matching every value — and a violation is refused
//! with HTTP 400 `ValidationException` carrying AWS's validation sentence, so a refused
//! request stores nothing.
//!
//! Two of this service's string shapes are written with a negative look-ahead, and they
//! are the two this suite drives the rule over:
//!
//! * `RootDirectory$Path` — `smithy_query(query="shape",shape="Path")`: `@length 1..100`
//!   and the `@pattern` spelled in [`PATH_PATTERN`], whose look-ahead is what makes the
//!   path absolute and bounds it at four subdirectories;
//! * `TagKey` — `smithy_query(query="shape",shape="TagKey")`: `@length 1..128` and the
//!   `@pattern` spelled in [`TAG_KEY_PATTERN`], whose look-ahead excludes the namespace
//!   AWS keeps for its own tags and whose character class is the rest of the expression.
//!
//! Every rule is asserted over a TABLE spanning what the expression generalises over
//! (absolute versus relative, the subdirectory count at the published maximum and one
//! past it, each character the class excludes, the reserved prefix and its near misses,
//! the member path's 1-based element position) rather than on the one recorded request,
//! and the constraints the walk DOES measure — `CreationInfo$Permissions`'s pattern,
//! `OwnerUid`/`OwnerGid`'s range, `Path`'s own length bounds — are pinned beside them, so
//! a caller cannot tell which side of the boundary refused the request.
//!
//! The harness (`Emulator`, `Reply`) is the one `file_system_lifecycle.rs` drives this
//! service with; the `Tags` helpers come from `tags.rs`, the two
//! `CreateAccessPoint`/`DescribeAccessPoints` bindings from `access_point_lifecycle.rs`,
//! the four tag-write/read bindings from `mutation_results.rs` and the `UntagResource`
//! binding (with the percent-encoding its `httpQuery` list needs) from `resource_tags.rs`
//! — so this suite adds no second copy of any of them.

use serde_json::{json, Value};

use crate::file_system_lifecycle::{Emulator, Reply};
use crate::mutation_results::{create_tags, delete_tags, list_tags, tag_resource};
use crate::resource_tags::untag_resource;
use crate::tags::{as_set, reported, tags_json};

// ---------------------------------------------------------------------------
// The modelled expressions, written as the model writes them.
// ---------------------------------------------------------------------------

/// `com.amazonaws.efs#Path`'s `@pattern`, from
/// `smithy_query(query="shape",shape="Path")`. Written out here rather than read off the
/// crate, so this suite pins the expression against the model and not against itself.
const PATH_PATTERN: &str = r"^(\/|(\/(?!\.)+[^$#<>;`|&?{}^*/\n]+){1,4})$";

/// `com.amazonaws.efs#TagKey`'s `@pattern`, from
/// `smithy_query(query="shape",shape="TagKey")`; see [`PATH_PATTERN`] for why it is
/// spelled out.
const TAG_KEY_PATTERN: &str = r"^(?![aA]{1}[wW]{1}[sS]{1}:)([\p{L}\p{Z}\p{N}_.:/=+\-@]+)$";

/// `com.amazonaws.efs#Permissions`' `@pattern`, from
/// `smithy_query(query="shape",shape="Permissions")` — an octal mode, so no digit 8 or 9.
const PERMISSIONS_PATTERN: &str = r"^[0-7]{3,4}$";

/// `Path`'s modelled `@length` bounds (`smithy_query(query="shape",shape="Path")`).
const PATH_LENGTH: (usize, usize) = (1, 100);

/// `OwnerUid`/`OwnerGid`'s modelled `@range` bounds
/// (`smithy_query(query="shape",shape="OwnerUid")`): "values from 0 to 2^32 (4294967295)".
const OWNER_ID_RANGE: (i64, i64) = (0, 4_294_967_295);

// ---------------------------------------------------------------------------
// The validation sentence, as both sides of the request boundary word it.
// ---------------------------------------------------------------------------

/// One clause of the sentence: the value the caller submitted, the member path it sat at,
/// and the requirement it failed.
fn clause(member_path: &str, value: &str, requirement: &str) -> String {
    format!("Value '{value}' at '{member_path}' failed to satisfy constraint: {requirement}")
}

/// The requirement a `@pattern` violation states.
fn pattern_requirement(pattern: &str) -> String {
    format!("Member must satisfy regular expression pattern: {pattern}")
}

/// The whole sentence over one or more clauses.
fn envelope(clauses: &[String]) -> String {
    match clauses {
        [only] => format!("1 validation error detected: {only}"),
        many => format!(
            "{} validation errors detected: {}",
            many.len(),
            many.join("; ")
        ),
    }
}

/// Assert one reply is the constraint refusal `expected` words: HTTP 400, the
/// `ValidationException` code a client branches on, and that exact sentence.
fn assert_refused(case: &str, reply: &Reply, expected: &str) {
    assert_eq!(
        (reply.status, reply.error_type.as_deref()),
        (400, Some("ValidationException")),
        "case {case:?}: expected a 400 ValidationException, got {} {:?} with {:?}",
        reply.status,
        reply.error_type,
        reply.body
    );
    let actual = reply
        .body
        .get("message")
        .or_else(|| reply.body.get("Message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(
        actual, expected,
        "case {case:?}: wrong sentence, got {actual:?} in {:?}",
        reply.body
    );
}

// ---------------------------------------------------------------------------
// The two readers every assertion below is taken through.
// ---------------------------------------------------------------------------

/// One `CreateAccessPoint` with a `RootDirectory` carrying exactly `path`.
async fn create_access_point_at(efs: &Emulator, token: &str, fs: &str, path: &str) -> Reply {
    efs.create_access_point(json!({
        "ClientToken": token,
        "FileSystemId": fs,
        "RootDirectory": { "Path": path },
    }))
    .await
}

/// The `RootDirectory.Path` of every access point the file system holds, read back
/// through `DescribeAccessPoints`.
async fn stored_paths(efs: &Emulator, fs: &str) -> Vec<String> {
    let reply = efs
        .describe_access_points(&format!("FileSystemId={fs}"))
        .await;
    assert_eq!(
        reply.status, 200,
        "DescribeAccessPoints({fs}): expected 200, got {} {:?}",
        reply.status, reply.body
    );
    reply
        .get("AccessPoints")
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|description| {
            description["RootDirectory"]["Path"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// `RootDirectory$Path`: the expression the walk in front of the handler cannot compile.
// ---------------------------------------------------------------------------

/// The paths the expression REFUSES, spanning what it generalises over: a path that is
/// not absolute, one subdirectory past the published maximum of four, a segment opening
/// with the dot the look-ahead forbids, an empty segment, and each character the class
/// excludes.
fn refused_paths() -> Vec<(&'static str, String)> {
    let mut rows: Vec<(&'static str, String)> = vec![
        (
            "the issue's relative path",
            "dynamic_provisioning/bad".to_string(),
        ),
        ("a bare relative name", "relative".to_string()),
        ("a relative dot path", "./here".to_string()),
        ("a path relative to the parent", "../up".to_string()),
        (
            "one subdirectory past the published four",
            "/one/two/three/four/five".to_string(),
        ),
        (
            "far past the published four",
            "/a/b/c/d/e/f/g/h".to_string(),
        ),
        (
            "a leading dot the look-ahead forbids",
            "/.hidden".to_string(),
        ),
        (
            "a nested segment opening with a dot",
            "/ok/.hidden".to_string(),
        ),
        ("a trailing slash, so an empty segment", "/a/".to_string()),
        ("an empty segment", "//double".to_string()),
        ("a slash alone past the root branch", "//".to_string()),
    ];
    // Every character the model's own class `[^$#<>;`|&?{}^*/\n]` excludes: a path
    // holding any one of them fails the expression.
    for excluded in [
        '$', '#', '<', '>', ';', '`', '|', '&', '?', '{', '}', '^', '*', '\n',
    ] {
        rows.push((
            "a character the class excludes",
            format!("/dir{excluded}name"),
        ));
    }
    rows
}

/// The paths the expression ADMITS: the root branch, each subdirectory count up to the
/// published maximum, a dot that does not OPEN a segment, a non-ASCII letter, and
/// punctuation the class does not exclude.
fn admitted_paths() -> Vec<(&'static str, String)> {
    vec![
        ("the file system root", "/".to_string()),
        ("one subdirectory", "/one".to_string()),
        ("two subdirectories", "/one/two".to_string()),
        ("three subdirectories", "/one/two/three".to_string()),
        (
            "the published maximum of four subdirectories",
            "/one/two/three/four".to_string(),
        ),
        ("a dot that does not open a segment", "/dir.v2".to_string()),
        ("a non-ASCII letter", "/données".to_string()),
        ("a space", "/two words".to_string()),
        (
            "punctuation the class does not exclude",
            "/a-b_c+d=e@f:g(h)[i]!j'k,l~m%n".to_string(),
        ),
        (
            "the modelled maximum length",
            format!("/{}", "a".repeat(PATH_LENGTH.1 - 1)),
        ),
    ]
}

#[tokio::test]
async fn a_root_directory_path_outside_the_modelled_pattern_is_refused_and_stores_nothing() {
    let efs = Emulator::new();
    let fs = efs.available_file_system("root-dir-refusals").await;

    for (index, (case, path)) in refused_paths().iter().enumerate() {
        let reply = create_access_point_at(&efs, &format!("refused-{index}"), &fs, path).await;
        let expected = envelope(&[clause(
            "rootDirectory.path",
            path,
            &pattern_requirement(PATH_PATTERN),
        )]);
        assert_refused(&format!("{case} ({path:?})"), &reply, &expected);
    }

    // A refused create writes nothing: neither an access point nor the `ClientToken` the
    // idempotency rule reads.
    let left = stored_paths(&efs, &fs).await;
    assert!(
        left.is_empty(),
        "refused creates must leave no access point on {fs}, got {left:?}"
    );
}

#[tokio::test]
async fn a_root_directory_path_the_modelled_pattern_admits_round_trips_through_state() {
    let efs = Emulator::new();
    let fs = efs.available_file_system("root-dir-admitted").await;

    let table = admitted_paths();
    for (index, (case, path)) in table.iter().enumerate() {
        let reply = create_access_point_at(&efs, &format!("admitted-{index}"), &fs, path).await;
        assert_eq!(
            reply.status, 200,
            "case {case:?} ({path:?}): expected 200, got {} {:?}",
            reply.status, reply.body
        );
        assert_eq!(
            reply.get("RootDirectory")["Path"].as_str(),
            Some(path.as_str()),
            "case {case:?}: the create must echo the stored path, got {:?}",
            reply.get("RootDirectory")
        );
    }

    // Read every one of them back: the stored path is the one submitted, verbatim.
    let mut stored = stored_paths(&efs, &fs).await;
    stored.sort();
    let mut expected: Vec<String> = table.iter().map(|(_, path)| path.clone()).collect();
    expected.sort();
    assert_eq!(
        stored, expected,
        "DescribeAccessPoints must report every admitted path and nothing else"
    );
}

// ---------------------------------------------------------------------------
// The nested constraints the request walk DOES measure, worded the same way.
// ---------------------------------------------------------------------------

/// One row of the already-measured-constraint table: the `RootDirectory` to send and the
/// clause it must be refused with.
struct WalkCase {
    case: &'static str,
    root_directory: Value,
    clause: String,
}

fn walk_table() -> Vec<WalkCase> {
    let (min_len, max_len) = PATH_LENGTH;
    let (min_owner, max_owner) = OWNER_ID_RANGE;
    let creation_info = |permissions: &str| {
        json!({
            "Path": "/ok",
            "CreationInfo": { "OwnerUid": 1000, "OwnerGid": 1000, "Permissions": permissions },
        })
    };
    let owner = |uid: i64, gid: i64| {
        json!({
            "Path": "/ok",
            "CreationInfo": { "OwnerUid": uid, "OwnerGid": gid, "Permissions": "0755" },
        })
    };
    vec![
        WalkCase {
            case: "the issue's non-octal three-digit mode",
            root_directory: creation_info("999"),
            clause: clause(
                "rootDirectory.creationInfo.permissions",
                "999",
                &pattern_requirement(PERMISSIONS_PATTERN),
            ),
        },
        WalkCase {
            case: "a non-octal four-digit mode",
            root_directory: creation_info("8888"),
            clause: clause(
                "rootDirectory.creationInfo.permissions",
                "8888",
                &pattern_requirement(PERMISSIONS_PATTERN),
            ),
        },
        WalkCase {
            case: "a mode that is not digits at all",
            root_directory: creation_info("rwx"),
            clause: clause(
                "rootDirectory.creationInfo.permissions",
                "rwx",
                &pattern_requirement(PERMISSIONS_PATTERN),
            ),
        },
        WalkCase {
            case: "one below the published OwnerUid minimum",
            root_directory: owner(min_owner - 1, 1000),
            clause: clause(
                "rootDirectory.creationInfo.ownerUid",
                &(min_owner - 1).to_string(),
                &format!("Member must have value greater than or equal to {min_owner}"),
            ),
        },
        WalkCase {
            case: "one above the published OwnerGid maximum",
            root_directory: owner(1000, max_owner + 1),
            clause: clause(
                "rootDirectory.creationInfo.ownerGid",
                &(max_owner + 1).to_string(),
                &format!("Member must have value less than or equal to {max_owner}"),
            ),
        },
        WalkCase {
            case: "one below the modelled Path minimum length",
            root_directory: json!({ "Path": "" }),
            clause: clause(
                "rootDirectory.path",
                "",
                &format!("Member must have length greater than or equal to {min_len}"),
            ),
        },
        WalkCase {
            case: "one above the modelled Path maximum length",
            root_directory: json!({ "Path": format!("/{}", "a".repeat(max_len)) }),
            clause: clause(
                "rootDirectory.path",
                &format!("/{}", "a".repeat(max_len)),
                &format!("Member must have length less than or equal to {max_len}"),
            ),
        },
    ]
}

#[tokio::test]
async fn the_nested_constraints_the_request_walk_measures_are_refused_the_same_way() {
    let efs = Emulator::new();
    let fs = efs.available_file_system("walk-measured").await;

    for (index, row) in walk_table().iter().enumerate() {
        let reply = efs
            .create_access_point(json!({
                "ClientToken": format!("walk-{index}"),
                "FileSystemId": fs,
                "RootDirectory": row.root_directory,
            }))
            .await;
        assert_refused(
            row.case,
            &reply,
            &envelope(std::slice::from_ref(&row.clause)),
        );
    }

    let left = stored_paths(&efs, &fs).await;
    assert!(
        left.is_empty(),
        "refused creates must leave no access point on {fs}, got {left:?}"
    );
}

// ---------------------------------------------------------------------------
// `TagKey`: the other expression the walk cannot compile.
// ---------------------------------------------------------------------------

/// The tag keys the expression REFUSES: the reserved namespace in every casing of its
/// three letters, and each character the class excludes.
fn refused_tag_keys() -> Vec<(&'static str, String)> {
    let mut rows: Vec<(&'static str, String)> = vec![
        ("the reserved namespace", "aws:owner".to_string()),
        (
            "the reserved namespace upper-cased",
            "AWS:owner".to_string(),
        ),
        (
            "the reserved namespace mixed-cased",
            "aWs:owner".to_string(),
        ),
        ("the reserved prefix alone", "aws:".to_string()),
    ];
    // The model's class `[\p{L}\p{Z}\p{N}_.:/=+\-@]` admits letters, separators, numbers
    // and that punctuation; a key holding anything else fails the expression.
    for excluded in [
        '*', '#', '!', '(', ')', '%', '&', '^', '?', '<', '>', '|', '$', '"',
    ] {
        rows.push((
            "a character the class excludes",
            format!("tag{excluded}key"),
        ));
    }
    rows
}

/// The tag keys the expression ADMITS, including the near misses of the look-ahead: it
/// reserves the three letters FOLLOWED BY A COLON, anchored at the start of the key.
fn admitted_tag_keys() -> Vec<(&'static str, &'static str)> {
    vec![
        ("the Name tag", "Name"),
        ("the reserved letters without the colon", "aws"),
        ("the reserved letters inside a longer word", "awsome"),
        ("the reserved letters with a fourth letter", "awsx:key"),
        ("the reserved prefix not at the start", "my:aws:key"),
        ("a path-like key", "cost:center/eu"),
        ("a non-ASCII letter", "Équipe.de_test"),
        ("a separator", "two words"),
        ("numbers alone", "123"),
        ("the rest of the punctuation", "a-b_c=d+e@f"),
    ]
}

/// A `(key, value)` pair as the `Tags` helper takes it.
fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

#[tokio::test]
async fn a_tag_key_outside_the_modelled_pattern_is_refused_by_every_operation_that_accepts_one() {
    let efs = Emulator::new();
    let fs = efs.available_file_system("tag-key-refusals").await;
    let created = efs
        .create_access_point(json!({
            "ClientToken": "tag-key-control",
            "FileSystemId": fs,
            "Tags": [{ "Key": "Name", "Value": "control" }],
        }))
        .await;
    assert_eq!(
        created.status, 200,
        "CreateAccessPoint for the control: expected 200, got {} {:?}",
        created.status, created.body
    );
    let access_point = created.string("AccessPointId");

    for (index, (case, key)) in refused_tag_keys().iter().enumerate() {
        // `Tags` carries the key in a structure, so the walk's path for it names the
        // element's 1-based position; the key is sent SECOND, which is what pins that
        // position rather than a hard-coded 1.
        let tags = vec![pair("Name", "ok"), pair(key, "v")];
        let in_tags = envelope(&[clause(
            "tags.2.member.key",
            key,
            &pattern_requirement(TAG_KEY_PATTERN),
        )]);
        // `TagKeys` is a list of the shape itself, so the walk's path ends at the element.
        let in_tag_keys = envelope(&[clause(
            "tagKeys.2.member",
            key,
            &pattern_requirement(TAG_KEY_PATTERN),
        )]);

        let label = |operation: &str| format!("{operation}: {case} ({key:?})");

        assert_refused(
            &label("CreateFileSystem"),
            &efs.create_file_system(json!({
                "CreationToken": format!("tag-key-{index}"),
                "Tags": tags_json(&tags),
            }))
            .await,
            &in_tags,
        );
        assert_refused(
            &label("CreateAccessPoint"),
            &efs.create_access_point(json!({
                "ClientToken": format!("tag-key-ap-{index}"),
                "FileSystemId": fs,
                "Tags": tags_json(&tags),
            }))
            .await,
            &in_tags,
        );
        assert_refused(
            &label("CreateTags"),
            &create_tags(&efs, &fs, &tags).await,
            &in_tags,
        );
        for resource in [fs.as_str(), access_point.as_str()] {
            assert_refused(
                &label(&format!("TagResource({resource})")),
                &tag_resource(&efs, resource, &tags).await,
                &in_tags,
            );
        }
        assert_refused(
            &label("DeleteTags"),
            &delete_tags(&efs, &fs, &["Name", key]).await,
            &in_tag_keys,
        );
        for resource in [fs.as_str(), access_point.as_str()] {
            assert_refused(
                &label(&format!("UntagResource({resource})")),
                &untag_resource(&efs, resource, &["Name", key]).await,
                &in_tag_keys,
            );
        }
    }

    // Not one of those refusals changed what a later caller sees: the control's tag set
    // is untouched, and no second file system or access point was minted.
    let held = list_tags(&efs, &access_point).await;
    assert_eq!(
        as_set(&reported(&held)),
        vec![pair("Name", "control")],
        "a refused tag write must leave the stored set alone, got {:?}",
        held.body
    );
    let file_systems = efs.describe_file_systems("").await;
    assert_eq!(
        file_systems
            .get("FileSystems")
            .as_array()
            .map_or(0, Vec::len),
        1,
        "a refused CreateFileSystem must mint nothing, got {:?}",
        file_systems.body
    );
    assert_eq!(
        stored_paths(&efs, &fs).await.len(),
        1,
        "a refused CreateAccessPoint must mint nothing beside the control"
    );
}

#[tokio::test]
async fn a_tag_key_the_modelled_pattern_admits_is_stored_and_removed_as_sent() {
    let efs = Emulator::new();
    let fs = efs.available_file_system("tag-key-admitted").await;
    let table = admitted_tag_keys();
    let tags: Vec<(String, String)> = table.iter().map(|(_, key)| pair(key, "stored")).collect();

    let written = tag_resource(&efs, &fs, &tags).await;
    assert_eq!(
        written.status, 200,
        "TagResource with every admitted key: expected 200, got {} {:?}",
        written.status, written.body
    );
    let held = as_set(&reported(&list_tags(&efs, &fs).await));
    let mut expected = tags.clone();
    expected.sort();
    assert_eq!(
        held, expected,
        "every admitted key must be stored as sent, got {held:?}"
    );

    // The same keys are accepted by the removal path, and removing them leaves nothing.
    let keys: Vec<&str> = table.iter().map(|(_, key)| *key).collect();
    let removed = untag_resource(&efs, &fs, &keys).await;
    assert_eq!(
        removed.status, 200,
        "UntagResource with every admitted key: expected 200, got {} {:?}",
        removed.status, removed.body
    );
    let left = reported(&list_tags(&efs, &fs).await);
    assert!(
        left.is_empty(),
        "every admitted key must be removable, got {left:?} left behind"
    );
}

// ---------------------------------------------------------------------------
// Several violations in one request.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_breaking_several_constraints_is_refused_in_one_envelope() {
    let efs = Emulator::new();
    let fs = efs.available_file_system("many-violations").await;

    // Two members of one request, each outside the expression of its own shape. The walk
    // visits the input's members in the order the shape declares them, so the clauses are
    // reported in that order and the count prefix is plural.
    let reply = efs
        .create_access_point(json!({
            "ClientToken": "many-1",
            "FileSystemId": fs,
            "RootDirectory": { "Path": "relative" },
            "Tags": [{ "Key": "aws:owner", "Value": "v" }],
        }))
        .await;
    let expected = envelope(&[
        clause(
            "tags.1.member.key",
            "aws:owner",
            &pattern_requirement(TAG_KEY_PATTERN),
        ),
        clause(
            "rootDirectory.path",
            "relative",
            &pattern_requirement(PATH_PATTERN),
        ),
    ]);
    assert_refused("a bad tag key and a bad root directory", &reply, &expected);

    // Two elements of ONE list, so the positions in the member paths differ.
    let both_keys = efs
        .create_access_point(json!({
            "ClientToken": "many-2",
            "FileSystemId": fs,
            "Tags": [
                { "Key": "aws:one", "Value": "v" },
                { "Key": "ok", "Value": "v" },
                { "Key": "bad*key", "Value": "v" },
            ],
        }))
        .await;
    let expected_keys = envelope(&[
        clause(
            "tags.1.member.key",
            "aws:one",
            &pattern_requirement(TAG_KEY_PATTERN),
        ),
        clause(
            "tags.3.member.key",
            "bad*key",
            &pattern_requirement(TAG_KEY_PATTERN),
        ),
    ]);
    assert_refused("two bad keys in one list", &both_keys, &expected_keys);

    assert!(
        stored_paths(&efs, &fs).await.is_empty(),
        "neither refusal may leave an access point behind"
    );
}

/// The most clauses a refusal built in the handler carries. A clause is collected per
/// ill-formed ELEMENT and the modelled `Tags` list declares no `@length` bound on the
/// collection, so without this ceiling the response would be sized by the request; the
/// framework's own accumulating walk stops at the same count.
const MAX_CLAUSES: usize = 100;

#[tokio::test]
async fn a_refusal_carries_at_most_the_bounded_number_of_clauses() {
    let efs = Emulator::new();
    let fs = efs.available_file_system("bounded-clauses").await;

    // Four times the ceiling, every element ill-formed: the sentence must state the
    // bounded count and carry exactly that many clauses, not one per element.
    let tags: Vec<(String, String)> = (0..MAX_CLAUSES * 4)
        .map(|index| pair(&format!("aws:{index}"), "v"))
        .collect();
    let reply = efs
        .create_access_point(json!({
            "ClientToken": "bounded-1",
            "FileSystemId": fs,
            "Tags": tags_json(&tags),
        }))
        .await;
    assert_eq!(
        (reply.status, reply.error_type.as_deref()),
        (400, Some("ValidationException")),
        "a list of ill-formed keys must be refused, got {} {:?}",
        reply.status,
        reply.body
    );
    let message = reply
        .body
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let prefix = format!("{MAX_CLAUSES} validation errors detected: ");
    assert!(
        message.starts_with(&prefix),
        "expected the sentence to open with {prefix:?}, got {message:?}"
    );
    assert_eq!(
        message.matches("failed to satisfy constraint:").count(),
        MAX_CLAUSES,
        "expected exactly {MAX_CLAUSES} clauses, got {message:?}"
    );

    assert!(
        stored_paths(&efs, &fs).await.is_empty(),
        "the refusal may leave no access point behind"
    );
}
