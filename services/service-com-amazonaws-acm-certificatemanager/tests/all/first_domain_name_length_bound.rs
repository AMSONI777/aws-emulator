// SPDX-License-Identifier: CC0-1.0

//! The bound on a certificate request's FIRST domain name, end to end over the wire
//! (`POST /`, `X-Amz-Target: CertificateManager.<Op>`, awsJson1_1).
//!
//! RULE under test: the first domain name of a certificate request — the one that
//! becomes the certificate's common name, `RequestCertificateRequest$DomainName` — may
//! be at most 64 octets, tighter than the 253 the member's own `@length` admits, and a
//! longer one is refused with HTTP 400 `InvalidDomainValidationOptionsException` and
//! ACM's fixed sentence for that class. The source is the member's documentation
//! (`smithy_query(query="doc", shape="com.amazonaws.acm#RequestCertificateRequest",
//! member="DomainName")`): "In compliance with RFC 5280, the length of the domain name
//! (technically, the Common Name) that you provide cannot exceed 64 octets
//! (characters), including periods. To add a longer domain name, specify it in the
//! Subject Alternative Name field, which supports names up to 253 octets in length."
//! So the same long name stays acceptable as a subject alternative name, all the way to
//! that member's own 253-octet maximum.
//!
//! The table spans what the rule generalises over: the length (both published bounds —
//! the 64 of the common name and the 253 of `DomainNameString` — each with the value one
//! octet to either side of it), the form of the name (plain, wildcard, a generated
//! service hostname), and the member the long name arrives in (`DomainName` against
//! `SubjectAlternativeNames`). Each accepted row is read back through
//! `DescribeCertificate` and each refused row through `ListCertificates`, so nothing is
//! asserted about a response the store does not back.

use serde_json::{json, Value};
use service_com_amazonaws_acm_certificatemanager::state::{
    FIRST_DOMAIN_NAME_OCTET_LIMIT, FIRST_DOMAIN_NAME_TOO_LONG_MESSAGE,
};

use crate::certificate_lifecycle::{
    call, describe, error_code, error_message, list_all_arns, router, router_with_engine,
};

/// The largest `DomainNameString` the model admits: `@length` 1..253. Source:
/// `smithy_query(query="shape", shape="com.amazonaws.acm#DomainNameString")`.
const DOMAIN_NAME_STRING_MAX: usize = 253;

/// An FQDN of exactly `octets` characters, built from labels the modelled
/// `DomainNameString` pattern admits
/// (`^(\*\.)?(((?!-)[A-Za-z0-9-]{0,62}[A-Za-z0-9])\.)+((?!-)[A-Za-z0-9-]{1,62}[A-Za-z0-9])$`):
/// every label is at most 20 characters, well inside the 63 that pattern allows, and the
/// last is never shorter than the two characters it requires of it.
fn fqdn_of(octets: usize) -> String {
    assert!(
        (24..=DOMAIN_NAME_STRING_MAX).contains(&octets),
        "{octets} is outside the lengths this generator builds"
    );
    // Each full label plus the dot that joins it to the next costs 21 characters; what
    // is left over at the end (always between 2 and 22) is the final label.
    let mut lengths = Vec::new();
    let mut left = octets;
    while left > 22 {
        lengths.push(20);
        left -= 21;
    }
    lengths.push(left);
    let name = lengths
        .iter()
        .map(|length| "n".repeat(*length))
        .collect::<Vec<String>>()
        .join(".");
    assert_eq!(
        name.len(),
        octets,
        "the generator must build a name of exactly {octets} octets, got {name:?}"
    );
    name
}

/// A hostname of the shape a load balancer or any other generated service endpoint
/// carries — an opaque label under a regional service domain — of exactly `octets`
/// characters. It is a NAME OF THAT FORM rather than any recorded one: only its length
/// and its shape matter to the rule.
fn generated_hostname(octets: usize) -> String {
    let suffix = ".balancers.probe-domain.net";
    let label = octets
        .checked_sub(suffix.len())
        .expect("the hostname is longer than its suffix");
    format!("internal-{}{suffix}", "7".repeat(label - "internal-".len()))
}

/// One row: what it exercises, the first domain name, and whether ACM accepts it.
type LengthCase = (&'static str, String, bool);

/// The rows, as the rule decides them: at most 64 octets is accepted, more is refused.
fn cases() -> Vec<LengthCase> {
    let limit = FIRST_DOMAIN_NAME_OCTET_LIMIT;
    vec![
        (
            "one octet under the common-name bound",
            fqdn_of(limit - 1),
            true,
        ),
        ("exactly the common-name bound", fqdn_of(limit), true),
        (
            "one octet past the common-name bound",
            fqdn_of(limit + 1),
            false,
        ),
        (
            // A wildcard name is measured as provided, the asterisk label included.
            "a wildcard name at the bound",
            format!("*.{}", fqdn_of(limit - 2)),
            true,
        ),
        (
            "a wildcard name one octet past the bound",
            format!("*.{}", fqdn_of(limit - 1)),
            false,
        ),
        (
            // The class the rule is really about: a generated service hostname is
            // routinely longer than a common name may be.
            "a generated service hostname well past the bound",
            generated_hostname(74),
            false,
        ),
        (
            "the longest name the member's own @length admits",
            fqdn_of(DOMAIN_NAME_STRING_MAX),
            false,
        ),
        (
            "a short name, far inside the bound",
            "short.probe-domain.com".to_string(),
            true,
        ),
    ]
}

/// RULE: a first domain name of at most 64 octets is accepted and persisted; a longer
/// one is HTTP 400 `InvalidDomainValidationOptionsException` with ACM's fixed sentence,
/// and leaves no certificate behind.
#[tokio::test]
async fn the_first_domain_name_is_bounded_at_sixty_four_octets() {
    for (case, domain_name, accepted) in cases() {
        // A router per row, so the store a refusal must leave empty is this row's own.
        let (router, _engine) = router_with_engine();
        let body = json!({ "DomainName": domain_name, "ValidationMethod": "DNS" });
        let (status, response) = call(&router, "RequestCertificate", &body).await;

        if accepted {
            assert_eq!(
                status,
                200,
                "case {case:?}: a first domain name of {} octets is inside the bound, so the \
                 request must succeed, got {status} {response}",
                domain_name.len()
            );
            let arn = response["CertificateArn"].as_str().unwrap_or_else(|| {
                panic!("case {case:?}: RequestCertificate returned no CertificateArn: {response}")
            });
            let detail = describe(&router, arn).await;
            assert_eq!(
                detail["DomainName"].as_str(),
                Some(domain_name.as_str()),
                "case {case:?}: the stored certificate must carry the requested name, got {detail}"
            );
            assert_eq!(
                detail["Subject"].as_str(),
                Some(format!("CN={domain_name}").as_str()),
                "case {case:?}: the first domain name is the certificate's common name, \
                 got {detail}"
            );
        } else {
            assert_eq!(
                status,
                400,
                "case {case:?}: a first domain name of {} octets is past the bound, so the \
                 request must be refused, got {status} {response}",
                domain_name.len()
            );
            assert_eq!(
                error_code(&response),
                "InvalidDomainValidationOptionsException",
                "case {case:?}: expected InvalidDomainValidationOptionsException, got {response}"
            );
            assert_eq!(
                error_message(&response),
                FIRST_DOMAIN_NAME_TOO_LONG_MESSAGE,
                "case {case:?}: expected ACM's fixed sentence for this class, got {response}"
            );
            let stored = list_all_arns(&router, &json!({})).await;
            assert!(
                stored.is_empty(),
                "case {case:?}: a refused request must create no certificate, found {stored:?}"
            );
        }
    }
}

/// RULE: the bound is the COMMON NAME's, so a name too long to be the first domain name
/// is still accepted in `SubjectAlternativeNames` — "which supports names up to 253
/// octets in length" — and the certificate covers it.
#[tokio::test]
async fn a_long_name_is_accepted_as_a_subject_alternative_name() {
    // Rows: one octet past the common-name bound, a generated service hostname, and the
    // longest name `DomainNameString` admits — each refused as the first domain name by
    // the table above.
    let long_names: Vec<(&str, String)> = vec![
        (
            "one octet past the common-name bound",
            fqdn_of(FIRST_DOMAIN_NAME_OCTET_LIMIT + 1),
        ),
        (
            "a generated service hostname",
            generated_hostname(74),
        ),
        (
            "the longest name the member admits",
            fqdn_of(DOMAIN_NAME_STRING_MAX),
        ),
    ];

    for (case, long_name) in long_names {
        let router = router();
        let first = "cn.probe-domain.com";
        let body = json!({
            "DomainName": first,
            "SubjectAlternativeNames": [long_name],
            "ValidationMethod": "DNS",
        });
        let (status, response) = call(&router, "RequestCertificate", &body).await;
        assert_eq!(
            status,
            200,
            "case {case:?}: a {}-octet subject alternative name is inside the member's own \
             253, so the request must succeed, got {status} {response}",
            long_name.len()
        );
        let arn = response["CertificateArn"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: no CertificateArn in {response}"));

        // Read back: the long name is covered by the certificate and has a validation
        // of its own, while the common name stays the short first name.
        let detail = describe(&router, arn).await;
        assert_eq!(
            detail["DomainName"].as_str(),
            Some(first),
            "case {case:?}: the first domain name is unchanged, got {detail}"
        );
        let names: Vec<&str> = detail["SubjectAlternativeNames"]
            .as_array()
            .unwrap_or_else(|| panic!("case {case:?}: no SubjectAlternativeNames in {detail}"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            names.contains(&long_name.as_str()),
            "case {case:?}: the certificate must cover the long name, got {names:?}"
        );
        let validated: Vec<&str> = detail["DomainValidationOptions"]
            .as_array()
            .unwrap_or_else(|| panic!("case {case:?}: no DomainValidationOptions in {detail}"))
            .iter()
            .filter_map(|validation| validation["DomainName"].as_str())
            .collect();
        assert!(
            validated.contains(&long_name.as_str()),
            "case {case:?}: the long name must carry a validation of its own, got {validated:?}"
        );
    }
}
