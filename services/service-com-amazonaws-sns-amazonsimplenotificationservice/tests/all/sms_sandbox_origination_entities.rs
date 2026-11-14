// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for what an SMS sandbox registration is judged on, and what it is
//! NOT judged on: this account's dedicated origination-entity inventory.
//!
//! The RULE asserted here: a sandbox destination number "sends a one-time password (OTP)
//! to that phone number" (`CreateSMSSandboxPhoneNumber` doc) from AWS's own side, so the
//! registration is judged on its own input and on this account's sandbox — never on the
//! account's DEDICATED origination entities, which `ListOriginationNumbers` reports and
//! which an account acquires out of band. A registration is therefore served, and the
//! destination number reported pending with a one-time password delivered to it, whether
//! the account holds no entity at all, entities that cannot send SMS, or SMS-capable
//! ones — and the inventory the listing reports is unchanged by it.
//!
//! The rows differ along what the rule generalises over: the destination-number FORM
//! (both branches of the modelled pattern and both published length bounds, from the
//! sandbox suite's own catalog), the CAPABILITIES of the entities the account holds
//! (none at all, an entity that can only place a voice call or carry MMS, one that can
//! send SMS, and several together), and whether the sandbox already holds the number.
//!
//! Every call goes over the wire through the router the emulator serves in production,
//! so nothing but persisted state carries information between calls.

use std::time::{Duration, SystemTime};

use service_com_amazonaws_sns_amazonsimplenotificationservice::ops::types::NUMBER_CAPABILITY_VALUES;
use service_com_amazonaws_sns_amazonsimplenotificationservice::state::{
    sms_origination, OriginationNumberRecord, SANDBOX_NUMBER_PENDING,
};

use super::sms_sandbox_phone_numbers::accepted_number_forms;
use super::topics_subscriptions_publish::{Answer, Sns};

/// Put one origination number with the capabilities given into the account's inventory,
/// the way the out-of-band provisioning writes it.
fn seed_origination(sns: &Sns, number: &str, capabilities: &[&str]) {
    let state = sns.state();
    let mut state = state.lock();
    state.origination_numbers.insert(
        number.to_string(),
        OriginationNumberRecord {
            phone_number: number.to_string(),
            status: "Active".to_string(),
            iso2_country_code: "US".to_string(),
            route_type: "Transactional".to_string(),
            number_capabilities: capabilities.iter().map(|value| (*value).to_string()).collect(),
            created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        },
    );
}

/// One registration call.
async fn register(sns: &Sns, number: &str) -> Answer {
    sns.call("CreateSMSSandboxPhoneNumber", &[("PhoneNumber", number)])
        .await
}

/// Assert the registration was served and left the number pending with a password of
/// its own.
fn assert_registered(case: &str, sns: &Sns, number: &str, answer: &Answer) {
    assert_eq!(
        answer.status, 200,
        "case {case:?}: expected the registration to be served, got {} / {}",
        answer.status, answer.body
    );
    let state = sns.state();
    let state = state.lock();
    let record = state
        .sandbox_phone_numbers
        .get(number)
        .unwrap_or_else(|| panic!("case {case:?}: the served registration must store a record"));
    assert_eq!(
        record.status, SANDBOX_NUMBER_PENDING,
        "case {case:?}: expected a pending destination number, got {record:?}"
    );
    assert!(
        !record.one_time_password.is_empty(),
        "case {case:?}: the served registration must deliver a one-time password"
    );
}

/// An account holding no origination entity registers a sandbox destination number all
/// the same, whatever form that number takes — which is what makes the verification
/// flow reachable at all.
#[tokio::test]
async fn a_registration_is_served_while_the_account_holds_no_origination_entity() {
    let sns = Sns::new();

    for (case, number) in accepted_number_forms() {
        let answer = register(&sns, &number).await;
        assert_registered(case, &sns, &number, &answer);
    }

    // Nothing the registrations did put an entity in the inventory the listing reports.
    assert!(
        sns.state().lock().origination_numbers.is_empty(),
        "the registrations must not write an origination entity, got {:?}",
        sns.state().lock().origination_numbers
    );
}

/// What the inventory holds does not decide the registration: every capability set — and
/// none at all — leaves the destination number pending just the same.
#[tokio::test]
async fn the_origination_inventory_does_not_decide_the_registration() {
    // (case, the capabilities the account's entities hold). The capability names are the
    // values the modelled `NumberCapability` enum accepts
    // (`crate::ops::types::NUMBER_CAPABILITY_VALUES`).
    let rows: &[(&str, &[&[&str]])] = &[
        ("no entity at all", &[]),
        ("one voice-only entity", &[&["VOICE"]]),
        ("one MMS-only entity", &[&["MMS"]]),
        ("two entities, neither able to send SMS", &[&["VOICE"], &["MMS"]]),
        ("one SMS-capable entity", &[&[sms_origination::SMS_CAPABILITY]]),
        ("one entity able to send SMS and MMS", &[&["MMS", "SMS"]]),
        ("two entities, one of them able to send SMS", &[&["VOICE"], &["SMS"]]),
        ("an entity with every modelled capability", &[NUMBER_CAPABILITY_VALUES]),
    ];

    let destination = "+447700900123";
    for (case, inventory) in rows {
        let sns = Sns::new();
        for (at, capabilities) in inventory.iter().enumerate() {
            seed_origination(&sns, &format!("+1206555{at:04}"), capabilities);
        }

        let answer = register(&sns, destination).await;
        assert_registered(case, &sns, destination, &answer);
    }
}

/// The registration is judged the same on EVERY call, the repeat of one the sandbox
/// already holds included: an inventory emptied out of band stops nothing, and the
/// repeat supersedes the one-time password of the record it keeps.
#[tokio::test]
async fn a_repeat_registration_is_served_once_the_inventory_holds_no_sms_entity() {
    let sns = Sns::new();
    let origination = "+12065550199";
    let destination = "+12065550100";
    seed_origination(&sns, origination, &[sms_origination::SMS_CAPABILITY]);

    let served = register(&sns, destination).await;
    assert_eq!(
        served.status, 200,
        "the first registration must be served, got {} / {}",
        served.status, served.body
    );
    let delivered = sns.state().lock().sandbox_phone_numbers[destination]
        .one_time_password
        .clone();

    sns.state().lock().origination_numbers.remove(origination);

    for (case, number) in [
        ("a number the sandbox already holds", destination),
        ("a number the sandbox does not hold", "+447700900123"),
    ] {
        let answer = register(&sns, number).await;
        assert_registered(case, &sns, number, &answer);
    }

    let state = sns.state();
    let state = state.lock();
    assert_eq!(
        state.sandbox_phone_numbers.len(),
        2,
        "expected one record per registered number, got {:?}",
        state.sandbox_phone_numbers
    );
    assert_ne!(
        state.sandbox_phone_numbers[destination].one_time_password, delivered,
        "a repeat registration must deliver a fresh one-time password"
    );
}
