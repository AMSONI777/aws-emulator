// SPDX-License-Identifier: CC0-1.0

//! What a certificate request for a name the account could never prove control of
//! reports, end to end over the wire (`POST /`,
//! `X-Amz-Target: CertificateManager.<Op>`, awsJson1_1).
//!
//! Two rules, both about a PUBLIC request ACM cannot carry into domain validation:
//!
//! 1. A name under a domain the PROVIDER operates is delegated to the provider and to no
//!    customer account, so no evidence from this account could ever cover it. Such a
//!    request is one that fails "upon being requested" rather than entering
//!    `PENDING_VALIDATION` (`smithy_query(query="doc",
//!    shape="com.amazonaws.acm#CertificateDetail", member="Status")`): it settles into
//!    `CertificateStatus` `FAILED` with the `FailureReason` that "exists only when the
//!    certificate status is `FAILED`" and names verification ACM has to obtain outside
//!    the account, `ADDITIONAL_VERIFICATION_REQUIRED`
//!    (`smithy_query(query="shape", shape="com.amazonaws.acm#FailureReason")`). Because
//!    "each domain name that you specify must be validated" (`RequestCertificate` doc),
//!    the FIRST such name ends the whole request: `ValidationStatus` is "the validation
//!    status of the domain name" (`DomainValidation$ValidationStatus` doc), a verdict
//!    about one name, so that name's entry is `FAILED` and the names behind it, which
//!    ACM never judged, stay `PENDING_VALIDATION`.
//! 2. `ValidationDomain` is "the domain name that ACM used to send domain validation
//!    emails" (`smithy_query(query="shape", shape="com.amazonaws.acm#DomainValidation")`),
//!    so it is reduced to a mail suffix only for a certificate ACM validates by EMAIL;
//!    under a method that sends no mail each entry reports its own `DomainName`
//!    verbatim, wildcard label included.
//!
//! The tables span what the rules generalise over: every entry of the service's own
//! catalog of provider-operated domains (including entries no issue cited), the form of
//! the name under one (wildcard, plain, a generated regional endpoint, mixed case), the
//! position of the offending name in the certificate's name set (first, last, the only
//! one), names that merely RESEMBLE a provider domain (which must wait instead), and
//! every modelled `ValidationMethod` for the `ValidationDomain` rule.
//!
//! Each claim is read back through `DescribeCertificate` and `ListCertificates`, so
//! nothing here can pass on a response the store does not back. The transition is owed
//! by the clock and never slept on, so a row that needs the settled state moves the
//! stored due instant into the past — exactly the state the wall clock would have left.

use serde_json::{json, Value};
use service_com_amazonaws_acm_certificatemanager::state::{
    FAILURE_REASON_ADDITIONAL_VERIFICATION_REQUIRED, PROVIDER_OPERATED_DOMAINS,
};

use crate::certificate_lifecycle::{
    describe, hold_pending_validations, request_certificate, router_with_engine,
};
use crate::certificate_validation_state_machine::{
    arns_in_statuses, make_validation_due_now, validations,
};

/// `DomainStatus` of a name whose validation did not complete, and of one ACM is still
/// waiting on (`smithy_query(query="shape", shape="com.amazonaws.acm#DomainStatus")`).
const FAILED: &str = "FAILED";
const PENDING_VALIDATION: &str = "PENDING_VALIDATION";

/// One row of the refusal table: what it exercises, the `RequestCertificate` body, the
/// names the certificate covers in order, and the name ACM stops at.
struct RefusalCase {
    case: String,
    body: Value,
    names: Vec<String>,
    stops_at: String,
}

/// The refusal rows: one per entry of the service's own catalog of provider-operated
/// domains, cycling through the forms a name under one takes, plus two rows that put the
/// offending name somewhere other than first.
fn refusal_cases() -> Vec<RefusalCase> {
    let mut cases = Vec::new();
    for (index, provider_domain) in PROVIDER_OPERATED_DOMAINS.iter().enumerate() {
        // The forms cycle, so the catalog is exercised across all of them rather than
        // one form being asserted only on one entry.
        let name = match index % 4 {
            // A wildcard over a whole regional service domain.
            0 => format!("*.eu-west-1.service.{provider_domain}"),
            // An opaque generated endpoint hostname.
            1 => format!("internal-7737373-1313131313.eu-west-1.service.{provider_domain}"),
            // DNS names are case-insensitive, so the catalog must match whatever case
            // the request spelled.
            2 => format!("Asset.{}", provider_domain.to_uppercase()),
            // The provider's domain itself.
            _ => (*provider_domain).to_string(),
        };
        cases.push(RefusalCase {
            case: format!("the provider-operated name {name}"),
            body: json!({ "DomainName": name, "ValidationMethod": "DNS" }),
            names: vec![name.clone()],
            stops_at: name,
        });
    }

    // The offending name LAST: the request still fails, and the verdict lands on it
    // rather than on the ordinary name ACM never finished judging.
    let first = "front.probe-domain.com".to_string();
    let last = "*.us-west-2.elb.amazonaws.com".to_string();
    cases.push(RefusalCase {
        case: "an ordinary first name beside a provider-operated alternative name".to_string(),
        body: json!({
            "DomainName": first,
            "SubjectAlternativeNames": [last, "back.probe-domain.com"],
            "ValidationMethod": "DNS",
        }),
        names: vec![first, last.clone(), "back.probe-domain.com".to_string()],
        stops_at: last,
    });

    // The offending name FIRST, with ordinary names behind it: those are never judged.
    let wildcard = "*.eu-central-1.elb.amazonaws.com".to_string();
    cases.push(RefusalCase {
        case: "a provider-operated first name with ordinary names behind it".to_string(),
        body: json!({
            "DomainName": wildcard,
            "SubjectAlternativeNames": ["one.probe-domain.net", "two.probe-domain.net"],
            "ValidationMethod": "DNS",
        }),
        names: vec![
            wildcard.clone(),
            "one.probe-domain.net".to_string(),
            "two.probe-domain.net".to_string(),
        ],
        stops_at: wildcard,
    });
    cases
}

/// RULE 1: a request naming a domain the provider operates settles into `FAILED` with
/// `ADDITIONAL_VERIFICATION_REQUIRED`, carrying the failed verdict on the FIRST such
/// name while the names ACM never judged stay `PENDING_VALIDATION`.
#[tokio::test]
async fn a_provider_operated_name_settles_into_failed() {
    for RefusalCase {
        case,
        body,
        names,
        stops_at,
    } in refusal_cases()
    {
        // A fresh store per row, so one row's certificate cannot explain another's.
        let (router, engine) = router_with_engine();
        let arn = request_certificate(&router, &body).await;

        // The refusal is reached THROUGH the status every request enters: it is the
        // outcome that differs, not the entry state.
        hold_pending_validations(&engine);
        let pending = describe(&router, &arn).await;
        assert_eq!(
            pending["Status"].as_str(),
            Some(PENDING_VALIDATION),
            "case {case:?}: a requested certificate enters PENDING_VALIDATION, got {pending}"
        );
        assert!(
            pending["FailureReason"].is_null(),
            "case {case:?}: nothing has failed while the outcome is still owed, got {pending}"
        );

        // Once the stored instant has passed, the outcome is owed whether or not
        // anybody polled, and the next read reports it.
        make_validation_due_now(&engine);
        let settled = describe(&router, &arn).await;
        assert_eq!(
            settled["Status"].as_str(),
            Some(FAILED),
            "case {case:?}: a name no evidence from this account could cover fails the \
             request, got {settled}"
        );
        assert_eq!(
            settled["FailureReason"].as_str(),
            Some(FAILURE_REASON_ADDITIONAL_VERIFICATION_REQUIRED),
            "case {case:?}: a FAILED certificate reports the reason it failed for, got {settled}"
        );
        for absent in ["IssuedAt", "NotBefore", "NotAfter", "Serial"] {
            assert!(
                settled[absent].is_null(),
                "case {case:?}: {absent} cannot exist without issuance, got {settled}"
            );
        }

        // The per-name verdicts: the name ACM stopped at, and only it, is FAILED.
        let entries = validations(&case, &settled);
        let reported: Vec<(&str, &str)> = entries
            .iter()
            .map(|entry| {
                (
                    entry["DomainName"].as_str().unwrap_or_default(),
                    entry["ValidationStatus"].as_str().unwrap_or_default(),
                )
            })
            .collect();
        let expected: Vec<(&str, &str)> = names
            .iter()
            .map(|name| {
                let status = if name.eq_ignore_ascii_case(&stops_at) {
                    FAILED
                } else {
                    PENDING_VALIDATION
                };
                (name.as_str(), status)
            })
            .collect();
        assert_eq!(
            reported, expected,
            "case {case:?}: expected the failed verdict on {stops_at} alone, got {reported:?}"
        );

        // The other reader agrees, and the status is terminal.
        let failed = arns_in_statuses(&router, &[FAILED]).await;
        assert_eq!(
            failed,
            vec![arn.clone()],
            "case {case:?}: expected ListCertificates to report the certificate as FAILED, \
             got {failed:?}"
        );
        let again = describe(&router, &arn).await;
        assert_eq!(
            again, settled,
            "case {case:?}: a settled certificate must read the same every time, got {again}"
        );
    }
}

/// RULE 1, the other side: a name that merely RESEMBLES a provider-operated domain is an
/// ordinary registrable name whose holder could publish the evidence, so its request
/// waits in `PENDING_VALIDATION` rather than failing.
#[tokio::test]
async fn a_name_that_only_resembles_a_provider_domain_waits() {
    // Rows: the catalog entry as a PREFIX rather than a suffix, a registrable label that
    // merely contains it, and a label that shares the suffix without a dot boundary.
    let names = [
        "amazonaws.com.probe-domain.net",
        "cdn.my-amazonaws.com",
        "assets.notcloudfront.net",
        "*.elb-amazonaws.probe-domain.com",
    ];

    for name in names {
        let (router, engine) = router_with_engine();
        let arn =
            request_certificate(&router, &json!({ "DomainName": name, "ValidationMethod": "DNS" }))
                .await;
        // Past every span this emulator owes a requested certificate: a request that was
        // going to be refused up front would already have been.
        make_validation_due_now(&engine);
        let detail = describe(&router, &arn).await;
        assert_eq!(
            detail["Status"].as_str(),
            Some("VALIDATION_TIMED_OUT"),
            "case {name:?}: an ordinary registrable name waits for proof rather than \
             failing, got {detail}"
        );
        assert!(
            detail["FailureReason"].is_null(),
            "case {name:?}: a request that waited carries no FailureReason, got {detail}"
        );
    }
}

/// RULE 2: `ValidationDomain` is the mail suffix only where ACM mails — for a method
/// that sends no mail each entry reports its own `DomainName` verbatim, wildcard label
/// included.
#[tokio::test]
async fn validation_domain_echoes_the_name_unless_acm_mails_it() {
    // Every modelled `ValidationMethod`
    // (`smithy_query(query="shape", shape="com.amazonaws.acm#ValidationMethod")`), plus
    // the absence of one — which ACM validates by email.
    let methods: &[Option<&str>] = &[Some("DNS"), Some("HTTP"), Some("EMAIL"), None];

    for (index, method) in methods.iter().enumerate() {
        let case = format!("ValidationMethod={method:?}");
        let (router, engine) = router_with_engine();
        // The names span the forms the rule distinguishes: a wildcard (the one a mail
        // suffix reduces), its own base, and a deeper name.
        let apex = format!("vd{index}.probe-domain.com");
        let wildcard = format!("*.{apex}");
        let deep = format!("deep.sub.{apex}");
        let mut body = json!({
            "DomainName": wildcard,
            "SubjectAlternativeNames": [apex, deep],
        });
        if let Some(method) = method {
            body["ValidationMethod"] = json!(method);
        }
        let arn = request_certificate(&router, &body).await;
        // The row is about the records the request created, so the transitions the clock
        // owes them are held out.
        hold_pending_validations(&engine);
        let detail = describe(&router, &arn).await;

        let mails = method.unwrap_or("EMAIL") == "EMAIL";
        let entries = validations(&case, &detail);
        for entry in &entries {
            let name = entry["DomainName"].as_str().unwrap_or_default();
            // A mail suffix carries no wildcard label; a method that sends no mail
            // reduces nothing.
            let expected = if mails {
                name.strip_prefix("*.").unwrap_or(name)
            } else {
                name
            };
            assert_eq!(
                entry["ValidationDomain"].as_str(),
                Some(expected),
                "case {case}: expected ValidationDomain {expected} for {name}, got {entry}"
            );
        }
        let wildcard_entry = entries
            .iter()
            .find(|entry| entry["DomainName"].as_str() == Some(wildcard.as_str()))
            .unwrap_or_else(|| panic!("case {case}: no validation for {wildcard} in {detail}"));
        if mails {
            assert_eq!(
                wildcard_entry["ValidationDomain"].as_str(),
                Some(apex.as_str()),
                "case {case}: a wildcard name is mailed at the domain it covers, got \
                 {wildcard_entry}"
            );
        } else {
            assert!(
                wildcard_entry["ValidationDomain"]
                    .as_str()
                    .is_some_and(|domain| domain.starts_with("*.")),
                "case {case}: the wildcard label is part of the name the entry reports, got \
                 {wildcard_entry}"
            );
        }
    }
}
