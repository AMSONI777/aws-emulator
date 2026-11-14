// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for the LAST phase of an image set's life: what a client polling a
//! deletion to its end reads.
//!
//! RULE: a deletion that has LANDED is reported before it is forgotten — the record answers
//! `GetImageSet` with `imageSetState` / `imageSetWorkflowStatus` `DELETED` and the
//! `deletedAt` the clock stamped on it — and the CLOCK then REAPS that record
//! (`IMAGE_SET_DELETED_RETENTION`). Past the reaping the data store holds no such image
//! set, so every call naming it is answered exactly as it is for an identifier nothing ever
//! minted: HTTP 404 `ResourceNotFoundException` with the service's constant text for an
//! image set it does not hold. That is the answer a client that waits for a deletion by
//! polling until the image set is gone is waiting for, so such a poll terminates.
//!
//! The reaping is a change the CLOCK owes, not one a reader makes: nothing a read does
//! moves it, an image set no delete has landed on is never reaped, and the instant it falls
//! due is dated from the instant the deletion landed, so neither reading nor repeating the
//! delete postpones it.
//!
//! The first suite is a TABLE whose rows differ along what the rule generalises over: how
//! many versions the image set holds, how much pixel data it held, and which read the
//! client polls with. It makes the reaping FALL DUE rather than sleeping out its span — the
//! one write a case makes into the state struct, and it changes no state or status, exactly
//! as `crate::image_set_deletion::move_due_instant` moves a retirement's own due instant.
//! The second suite drives the same rule through the REAL clock and no write at all, polling
//! for the condition rather than for a span.
//!
//! ## Why a seeded image set
//!
//! The image set each case deletes is seeded through the crate's public `state` module with
//! the same `ImageSet` / `ImageFrame` the handlers hold
//! (`crate::image_set_copy::seed_image_set`), and everything each case then asserts goes
//! over real HTTP through the production front door.

use std::time::{Duration, Instant, SystemTime};

use service_com_amazonaws_medicalimaging_ahigatewayservice::state::{
    service_state, ImageFrame, IMAGE_SET_DELETED_RETENTION, IMAGE_SET_DELETION_DELAY,
    IMAGE_SET_NOT_FOUND_MESSAGE,
};

use crate::datastore_lifecycle::{Answer, Emulator};
use crate::image_set_copy::{get_image_set, seed_image_set};
use crate::image_set_deletion::delete_image_set;
use crate::image_set_metadata::get_image_set_metadata;
use crate::image_set_version_listing::list_versions;

/// How long a poll waits for a condition the clock owes before giving up. Generous on
/// purpose: it bounds a hung emulator rather than the spans this service promises, so a
/// loaded host cannot fail a case that is only slow.
const POLL_DEADLINE: Duration = Duration::from_secs(120);

/// How long a poll waits between looks. Short enough that a case does not spend the span it
/// is waiting for on sleeping past it.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Which read a row polls the deletion with.
#[derive(Debug, Clone, Copy)]
enum Polled {
    /// `GetImageSet`, the read the properties of an image set are reported by.
    Properties,
    /// `GetImageSetMetadata`, the read its aggregated DICOM metadata is served by.
    Metadata,
    /// `ListImageSetVersions`, the read its versions are listed by.
    Versions,
}

impl Polled {
    /// One look through this read.
    async fn read(self, emulator: &Emulator, datastore_id: &str, image_set_id: &str) -> Answer {
        match self {
            Self::Properties => get_image_set(emulator, datastore_id, image_set_id, None).await,
            Self::Metadata => {
                get_image_set_metadata(emulator, datastore_id, image_set_id, None).await
            }
            Self::Versions => list_versions(emulator, datastore_id, image_set_id, "").await,
        }
    }
}

/// One row of the reaping table.
#[derive(Debug)]
struct Case {
    case: &'static str,
    versions: u32,
    frames: usize,
    polled: Polled,
}

/// Add `count` image frames to an image set the data store holds, so a row can delete an
/// image set that really held pixel data.
fn seed_frames(emulator: &Emulator, datastore_id: &str, image_set_id: &str, count: usize) {
    let state = service_state(emulator.engine()).expect("the medical-imaging state store");
    let mut store = state.lock();
    let frame_ids: Vec<String> = (0..count).map(|_| store.mint_id()).collect();
    let image_set = store
        .datastores
        .get_mut(datastore_id)
        .expect("the seeded data store")
        .image_sets
        .get_mut(image_set_id)
        .expect("the seeded image set");
    for (index, frame_id) in frame_ids.iter().enumerate() {
        image_set.image_frames.insert(
            frame_id.clone(),
            ImageFrame {
                image_frame_id: frame_id.clone(),
                transfer_syntax_uid: None,
                sop_instance_uid: None,
                pixel_data: vec![(index as u8).wrapping_add(1); 4 * (index + 1)],
            },
        );
    }
}

/// Move the instant the REAPING of a retired image set falls due.
///
/// The only write a case of the first suite makes into the state struct, and it changes no
/// state, status or timestamp: it moves the due instant the clock itself recorded when the
/// deletion landed, so a case can observe the reaping without sleeping out its span.
fn make_reaping_due(emulator: &Emulator, case: &str, datastore_id: &str, image_set_id: &str) {
    let state = service_state(emulator.engine()).expect("the medical-imaging state store");
    let mut store = state.lock();
    let image_set = store
        .datastores
        .get_mut(datastore_id)
        .expect("the seeded data store")
        .image_sets
        .get_mut(image_set_id)
        .unwrap_or_else(|| panic!("case {case:?}: expected the retired image set's record"));
    assert!(
        image_set.reap_due_at.is_some(),
        "case {case:?}: expected the landed deletion to owe its own reaping"
    );
    image_set.reap_due_at = Some(SystemTime::now());
}

/// Whether the record of `image_set_id` is still held in state — read for ONE assertion
/// only: that the reaping really dropped the record rather than hiding it from one reader.
fn record_is_held(emulator: &Emulator, datastore_id: &str, image_set_id: &str) -> bool {
    let state = service_state(emulator.engine()).expect("the medical-imaging state store");
    let store = state.lock();
    store
        .datastores
        .get(datastore_id)
        .is_some_and(|datastore| datastore.image_sets.contains_key(image_set_id))
}

/// Poll `read` until it answers HTTP 404, and answer that answer. Panics past
/// [`POLL_DEADLINE`], which bounds a hung emulator rather than the span being waited for.
async fn poll_until_absent(
    emulator: &Emulator,
    case: &str,
    datastore_id: &str,
    image_set_id: &str,
    read: Polled,
) -> Answer {
    let deadline = Instant::now() + POLL_DEADLINE;
    loop {
        let answer = read.read(emulator, datastore_id, image_set_id).await;
        if answer.status == 404 {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: {read:?} never reported the retired image set absent, last answer \
             {answer:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `GetImageSet` until the deletion has LANDED on `DELETED`, and answer that answer.
async fn poll_until_deleted(
    emulator: &Emulator,
    case: &str,
    datastore_id: &str,
    image_set_id: &str,
) -> Answer {
    let deadline = Instant::now() + POLL_DEADLINE;
    loop {
        let answer = get_image_set(emulator, datastore_id, image_set_id, None).await;
        if answer.status == 200 && answer.string(&["imageSetState"]) == "DELETED" {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: the deletion never landed on DELETED, last answer {answer:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// RULE (above): the tombstone is reported, the clock reaps it, and every read of the image
/// set then answers 404 `ResourceNotFoundException`.
#[tokio::test]
async fn a_landed_deletion_is_reported_and_then_reaped() {
    let cases = [
        Case {
            case: "one version, no pixel data, polled with GetImageSet",
            versions: 1,
            frames: 0,
            polled: Polled::Properties,
        },
        Case {
            case: "two versions holding two frames, polled with GetImageSet",
            versions: 2,
            frames: 2,
            polled: Polled::Properties,
        },
        Case {
            case: "three versions holding one frame, polled with GetImageSetMetadata",
            versions: 3,
            frames: 1,
            polled: Polled::Metadata,
        },
        Case {
            case: "one version holding three frames, polled with ListImageSetVersions",
            versions: 1,
            frames: 3,
            polled: Polled::Versions,
        },
    ];

    for case in &cases {
        let name = case.case;
        let emulator = Emulator::new();
        let datastore_id = emulator
            .active_datastore("reaped.store", "token-reaped-store")
            .await;
        let image_set_id = seed_image_set(&emulator, &datastore_id, case.versions);
        seed_frames(&emulator, &datastore_id, &image_set_id, case.frames);

        let deleted = delete_image_set(&emulator, &datastore_id, &image_set_id).await;
        assert_eq!(
            deleted.status, 200,
            "case {name:?}: expected HTTP 200 from DeleteImageSet, got {deleted:?}"
        );

        // The deletion lands on its own, and while the record stands it REPORTS the
        // deletion: the terminal pair and the instant it was deleted at.
        let landed = poll_until_deleted(&emulator, name, &datastore_id, &image_set_id).await;
        assert_eq!(
            landed.string(&["imageSetWorkflowStatus"]),
            "DELETED",
            "case {name:?}: expected the workflow status DELETED once it landed, got {landed:?}"
        );
        assert!(
            landed.field(&["deletedAt"]).as_f64().is_some_and(|at| at > 0.0),
            "case {name:?}: expected a deletedAt on the tombstone, got {landed:?}"
        );
        assert!(
            record_is_held(&emulator, &datastore_id, &image_set_id),
            "case {name:?}: the record must stand while the deletion is still reported"
        );

        // The reaping is what ends that window, and it is the CLOCK's: making it fall due
        // is all a case does.
        make_reaping_due(&emulator, name, &datastore_id, &image_set_id);

        let absent = poll_until_absent(
            &emulator,
            name,
            &datastore_id,
            &image_set_id,
            case.polled,
        )
        .await;
        assert_eq!(
            absent.error_code, "ResourceNotFoundException",
            "case {name:?}: expected ResourceNotFoundException once the record was reaped, got \
             {absent:?}"
        );
        assert_eq!(
            absent.string(&["message"]),
            IMAGE_SET_NOT_FOUND_MESSAGE,
            "case {name:?}: expected the service's image-set-not-found text, got {absent:?}"
        );
        assert!(
            !record_is_held(&emulator, &datastore_id, &image_set_id),
            "case {name:?}: expected the reaping to drop the record, not to hide it"
        );

        // EVERY read of the image set answers the same way once the record is gone, not
        // just the one the client happened to poll with.
        for read in [Polled::Properties, Polled::Metadata, Polled::Versions] {
            let answer = read.read(&emulator, &datastore_id, &image_set_id).await;
            assert_eq!(
                (answer.status, answer.error_code.as_str()),
                (404, "ResourceNotFoundException"),
                "case {name:?}: expected {read:?} to report the reaped image set absent, got \
                 {answer:?}"
            );
        }
        // A repeat delete cannot resurrect it either: the data store holds no such image
        // set at all.
        let again = delete_image_set(&emulator, &datastore_id, &image_set_id).await;
        assert_eq!(
            (again.status, again.error_code.as_str()),
            (404, "ResourceNotFoundException"),
            "case {name:?}: expected a delete of the reaped image set to be answered as one of \
             an id nothing minted, got {again:?}"
        );
    }
}

/// RULE, through the REAL clock and nothing else: a client that polls `GetImageSet` until
/// the image set is gone reaches that answer on its own, and an image set nothing deleted
/// is never reaped out from under it.
#[tokio::test]
async fn the_clock_alone_reaps_a_retired_image_set() {
    let emulator = Emulator::new();
    let datastore_id = emulator
        .active_datastore("clock.reaped.store", "token-clock-reaped-store")
        .await;
    let retired_id = seed_image_set(&emulator, &datastore_id, 2);
    // A second image set of the same data store, which nothing deletes: the reaping
    // reaches the record a deletion landed on and no other.
    let untouched_id = seed_image_set(&emulator, &datastore_id, 1);

    let deleted = delete_image_set(&emulator, &datastore_id, &retired_id).await;
    assert_eq!(
        deleted.status, 200,
        "case \"the clock reaps it\": expected HTTP 200 from DeleteImageSet, got {deleted:?}"
    );

    let landed = poll_until_deleted(&emulator, "the clock reaps it", &datastore_id, &retired_id)
        .await;
    assert_eq!(
        landed.string(&["imageSetState"]),
        "DELETED",
        "case \"the clock reaps it\": expected the deletion to land on DELETED, got {landed:?}"
    );

    let absent = poll_until_absent(
        &emulator,
        "the clock reaps it",
        &datastore_id,
        &retired_id,
        Polled::Properties,
    )
    .await;
    assert_eq!(
        absent.error_code, "ResourceNotFoundException",
        "case \"the clock reaps it\": expected the poll to reach ResourceNotFoundException, got \
         {absent:?}"
    );
    // The two spans the clock owed are the deletion's and the retention of its record; the
    // poll above waited for the CONDITION, and this states what it was waiting on.
    assert!(
        IMAGE_SET_DELETION_DELAY + IMAGE_SET_DELETED_RETENTION < POLL_DEADLINE,
        "the poll deadline must leave room for the deletion and the retention of its record"
    );

    let untouched = get_image_set(&emulator, &datastore_id, &untouched_id, None).await;
    assert_eq!(
        (untouched.status, untouched.string(&["imageSetState"])),
        (200, "ACTIVE".to_string()),
        "case \"the clock reaps it\": an image set nothing deleted is never reaped, got \
         {untouched:?}"
    );
}
