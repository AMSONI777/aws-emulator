// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for which numbers `CheckIfPhoneNumberIsOptedOut` reports on, and
//! what it reports for them.
//!
//! The RULE asserted here: the opt-out check is held to the FORM its phone-number member
//! documents ("Use E.164 format") exactly as the operations that act on a number are, so
//! a value that is no phone number in that format is refused 400 `InvalidParameter`
//! before the record is read, with the fixed badly-formatted-number sentence and none of
//! the (sensitive) value echoed back. For a number OF that form the check reports this
//! account's record: a number no opt-out was recorded for is reported as opted IN —
//! `isOptedOut` is the modelled boolean whose default is `false`, documented "false – The
//! phone number is opted in" — a number the record says opted out reports `true`, and the
//! read changes nothing either way.
//!
//! The rows differ along what the rule generalises over: the FORM of the number
//! (country codes of one, two and three digits, both published E.164 digit bounds, and —
//! for the refusal — national forms with separators, a value that is no number at all, a
//! country code beginning with zero, and one digit past each published bound) and the
//! opt-out state the record holds. The forms come from the opt-in suite's own catalogs,
//! so the two suites cannot drift on which value is which.
//!
//! Every call goes over the wire through the router the emulator serves in production,
//! so nothing but persisted state carries information between calls.

use std::time::SystemTime;

use service_com_amazonaws_sns_amazonsimplenotificationservice::state::invalid_phone_number_message;

use super::phone_number_opt_in::{e164_numbers, not_e164_values, seed_opted_out_at};
use super::topics_subscriptions_publish::{Answer, Sns};

/// The member both opt-out operations spell their phone number with on the wire.
const PHONE_NUMBER_PARAM: &str = "phoneNumber";

/// One `CheckIfPhoneNumberIsOptedOut` call.
async fn check(sns: &Sns, number: &str) -> Answer {
    sns.call(
        "CheckIfPhoneNumberIsOptedOut",
        &[(PHONE_NUMBER_PARAM, number)],
    )
    .await
}

/// The `isOptedOut` member of an answered check, asserting the call was served.
fn served(case: &str, answer: &Answer) -> bool {
    assert_eq!(
        answer.status, 200,
        "case {case:?}: expected the check to answer 200, got {} / {}",
        answer.status, answer.body
    );
    let reported = answer
        .element("isOptedOut")
        .or_else(|| answer.element("IsOptedOut"))
        .unwrap_or_else(|| {
            panic!(
                "case {case:?}: expected an isOptedOut member, got {}",
                answer.body
            )
        });
    assert!(
        reported == "true" || reported == "false",
        "case {case:?}: expected the modelled boolean, got {reported:?}"
    );
    reported == "true"
}

/// Every number of the documented FORM is answered by the check, and a number with no
/// opt-out record reports `false`.
#[tokio::test]
async fn a_number_with_no_opt_out_record_is_reported_opted_in() {
    let sns = Sns::new();

    for (case, value) in e164_numbers() {
        let answer = check(&sns, &value).await;
        assert!(
            !served(case, &answer),
            "case {case:?}: a number with no opt-out record must report false, got {}",
            answer.body
        );
        // A read is a report: the second check answers the same, and neither wrote a
        // record for the number it was asked about.
        let again = check(&sns, &value).await;
        assert!(
            !served(case, &again),
            "case {case:?}: a second check must report the same, got {}",
            again.body
        );
    }

    assert!(
        sns.state().lock().phone_numbers.is_empty(),
        "the checks must write no opt-out record, got {:?}",
        sns.state().lock().phone_numbers
    );
}

/// The state the check reports is the one the record HOLDS: the same numbers that report
/// `false` with no record report `true` once this account's out-of-band opt-out has
/// written one for them.
#[tokio::test]
async fn an_opted_out_number_is_reported_opted_out() {
    let sns = Sns::new();
    let numbers = e164_numbers();

    for (case, value) in &numbers {
        seed_opted_out_at(&sns, value, SystemTime::now(), None);
        let answer = check(&sns, value).await;
        assert!(
            served(case, &answer),
            "case {case:?}: the seeded opt-out must be reported, got {}",
            answer.body
        );
    }

    assert_eq!(
        sns.state().lock().phone_numbers.len(),
        numbers.len(),
        "the checks must leave exactly the seeded records, got {:?}",
        sns.state().lock().phone_numbers
    );
}

/// A value that is no phone number in E.164 format is refused by the check, with the
/// same sentence the operations that act on a number refuse it with — and the refusal
/// reports no opt-out state at all, so a caller cannot read one off it.
#[tokio::test]
async fn a_value_that_is_no_phone_number_is_refused_by_the_check() {
    let sns = Sns::new();
    // One number the record says opted out, so the refusals below are told apart from a
    // store the calls emptied.
    let opted_out = "+447700900123";
    seed_opted_out_at(&sns, opted_out, SystemTime::now(), None);

    let mut rows: Vec<(String, String)> = not_e164_values()
        .into_iter()
        .map(|(case, value)| (case.to_string(), value))
        .collect();
    // A bare short code: digits with no country code reach no number in E.164 format
    // either, so the same refusal covers it.
    rows.push(("a bare short code".to_string(), "12345".to_string()));

    for (case, value) in &rows {
        let answer = check(&sns, value).await;
        assert_eq!(
            answer.status, 400,
            "case {case:?}: expected 400, got {} / {}",
            answer.status, answer.body
        );
        assert_eq!(
            answer.code(),
            "InvalidParameter",
            "case {case:?}: expected the InvalidParameter code, got {}",
            answer.body
        );
        assert_eq!(
            answer.element("Message"),
            Some(invalid_phone_number_message()),
            "case {case:?}: expected the fixed badly-formatted-number sentence, got {}",
            answer.body
        );
        assert!(
            answer.element("isOptedOut").is_none() && answer.element("IsOptedOut").is_none(),
            "case {case:?}: a refused check must report no opt-out state, got {}",
            answer.body
        );
    }

    // The refusals read and wrote nothing: the seeded record is exactly as it was, and
    // it is still what a served call reports.
    assert_eq!(
        sns.state().lock().phone_numbers.len(),
        1,
        "the refused checks must not add a record, got {:?}",
        sns.state().lock().phone_numbers
    );
    let answer = check(&sns, opted_out).await;
    assert!(
        served("the seeded number", &answer),
        "expected the seeded opt-out to survive every refusal, got {}",
        answer.body
    );
}
