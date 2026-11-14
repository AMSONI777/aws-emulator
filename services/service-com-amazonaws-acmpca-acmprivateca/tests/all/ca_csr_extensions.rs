// SPDX-License-Identifier: CC0-1.0

//! The extensions the certification request a private CA publishes ASKS FOR.
//!
//! The rule under test: `CertificateAuthorityConfiguration$CsrExtensions` "Describes the
//! certificate extensions to be added to the certificate signing request (CSR)", and
//! `KeyUsage` "Defines one or more purposes for which the key contained in the certificate
//! can be used. Default value for each option is false" — so the PKCS#10 request
//! `GetCertificateAuthorityCsr` hands out carries, among the extensions it asks for (RFC
//! 2985 section 5.4.2), a `keyUsage` extension (RFC 5280 section 4.2.1.3) asserting EXACTLY
//! the bits the configuration set true and no others. A configuration that asks for no key
//! usage asks for no such extension.
//!
//! The rows span what the rule generalises over: which of the nine bits are set — each one
//! alone, the three the issue cited, all nine at once, the two whose bits sit in the second
//! octet of the bit string, and none at all — plus the configurations that name no key usage
//! and no `CsrExtensions` at all.
//!
//! The nine bits are the members of `smithy_query(query="shape",shape="KeyUsage")`, in the
//! order that shape declares them, which is the order RFC 5280 section 4.2.1.3 numbers the
//! named bits of the extension in.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
use x509_cert::ext::Extensions;

use crate::private_ca_lifecycle::{request_of, string, Emulator};

/// The attribute a PKCS#10 request states the extensions it asks for in: `pkcs-9-at-
/// extensionRequest` (RFC 2985 section 5.4.2).
const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";

/// How long a poll for a due transition may take before the suite gives up.
const POLL_DEADLINE: Duration = Duration::from_secs(60);

/// How long a poll waits before looking again.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Every member of `KeyUsage`, with the named bit of the extension it sets.
const BITS: &[(&str, KeyUsages)] = &[
    ("DigitalSignature", KeyUsages::DigitalSignature),
    ("NonRepudiation", KeyUsages::NonRepudiation),
    ("KeyEncipherment", KeyUsages::KeyEncipherment),
    ("DataEncipherment", KeyUsages::DataEncipherment),
    ("KeyAgreement", KeyUsages::KeyAgreement),
    ("KeyCertSign", KeyUsages::KeyCertSign),
    ("CRLSign", KeyUsages::CRLSign),
    ("EncipherOnly", KeyUsages::EncipherOnly),
    ("DecipherOnly", KeyUsages::DecipherOnly),
];

/// One configuration, and the key usage the request it produces must ask for.
struct Row {
    /// The case every assertion of the row names.
    case: String,
    /// The `CsrExtensions` the CA is created with, when the row names any.
    csr_extensions: Option<Value>,
    /// The members the request's `keyUsage` extension must assert, or none when the request
    /// must carry no such extension.
    asserted: Option<Vec<&'static str>>,
}

/// A `CsrExtensions` value asking for the `KeyUsage` members `members` names.
fn key_usage_configuration(members: &[&str]) -> Value {
    let mut usage = serde_json::Map::new();
    for member in members {
        usage.insert((*member).to_string(), json!(true));
    }
    json!({"KeyUsage": Value::Object(usage)})
}

/// Every row this suite drives.
fn rows() -> Vec<Row> {
    // One row per member: a configuration asking for that bit alone.
    let mut rows: Vec<Row> = BITS
        .iter()
        .map(|(member, _)| Row {
            case: format!("{member} alone"),
            csr_extensions: Some(key_usage_configuration(&[member])),
            asserted: Some(vec![member]),
        })
        .collect();
    let every: Vec<&'static str> = BITS.iter().map(|(member, _)| *member).collect();
    rows.push(Row {
        case: "the three a CA certificate is usually asked for".to_string(),
        csr_extensions: Some(key_usage_configuration(&[
            "DigitalSignature",
            "KeyCertSign",
            "CRLSign",
        ])),
        asserted: Some(vec!["DigitalSignature", "KeyCertSign", "CRLSign"]),
    });
    rows.push(Row {
        case: "every member at once".to_string(),
        csr_extensions: Some(key_usage_configuration(&every)),
        asserted: Some(every.clone()),
    });
    rows.push(Row {
        case: "the two bits of the second octet".to_string(),
        csr_extensions: Some(key_usage_configuration(&["EncipherOnly", "DecipherOnly"])),
        asserted: Some(vec!["EncipherOnly", "DecipherOnly"]),
    });
    rows.push(Row {
        case: "a key usage with every member false".to_string(),
        csr_extensions: Some(key_usage_configuration(&[])),
        asserted: None,
    });
    rows.push(Row {
        case: "CsrExtensions naming no key usage".to_string(),
        csr_extensions: Some(json!({})),
        asserted: None,
    });
    rows.push(Row {
        case: "no CsrExtensions at all".to_string(),
        csr_extensions: None,
        asserted: None,
    });
    rows
}

/// A `CreateCertificateAuthority` body for one row.
fn create_request(row: &Row, common_name: &str) -> Value {
    let mut configuration = json!({
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"CommonName": common_name},
    });
    if let Some(csr_extensions) = &row.csr_extensions {
        configuration["CsrExtensions"] = csr_extensions.clone();
    }
    json!({
        "CertificateAuthorityConfiguration": configuration,
        "CertificateAuthorityType": "ROOT",
    })
}

/// Poll `DescribeCertificateAuthority` until the CA reports `status`: a new CA settles on
/// the clock, so the suite looks again until the condition holds.
async fn poll_for_status(emulator: &Emulator, case: &str, arn: &str, status: &str) {
    let deadline = Instant::now() + POLL_DEADLINE;
    loop {
        let described = emulator
            .ok(case, "DescribeCertificateAuthority", &json!({"CertificateAuthorityArn": arn}))
            .await;
        let reported = string(&described["CertificateAuthority"], "Status", case);
        if reported == status {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "case {case:?}: expected the CA to report {status:?}, it still reports {reported:?}"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The `keyUsage` extension the certification request `csr` asks for, when it asks for one.
fn requested_key_usage(csr: &str, case: &str) -> Option<KeyUsage> {
    let request = request_of(csr, case);
    let extensions: Vec<x509_cert::ext::Extension> = request
        .info
        .attributes
        .iter()
        .filter(|attribute| attribute.oid.to_string() == EXTENSION_REQUEST)
        .flat_map(|attribute| attribute.values.iter())
        .flat_map(|value| {
            let der = value.to_der().expect("an attribute value re-encodes");
            Extensions::from_der(&der).unwrap_or_else(|error| {
                panic!("case {case:?}: the requested extensions are a SEQUENCE: {error}")
            })
        })
        .collect();
    let extension = extensions
        .iter()
        .find(|extension| extension.extn_id == KeyUsage::OID)?;
    assert!(
        extension.critical,
        "case {case:?}: a requested keyUsage is marked critical (RFC 5280 section 4.2.1.3)"
    );
    Some(
        KeyUsage::from_der(extension.extn_value.as_bytes()).unwrap_or_else(|error| {
            panic!("case {case:?}: the keyUsage extension is a BIT STRING: {error}")
        }),
    )
}

/// The request a CA publishes asks for the key usage its configuration named, bit for bit.
#[tokio::test]
async fn a_published_request_asks_for_the_key_usage_its_configuration_names() {
    let emulator = Emulator::new();
    let rows = rows();

    // Create every CA first, then poll: the certification request is a product of creation
    // and is published once creation has settled.
    let mut authorities: Vec<String> = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let created = emulator
            .ok(
                &row.case,
                "CreateCertificateAuthority",
                &create_request(row, &format!("csr-extensions-{index}")),
            )
            .await;
        authorities.push(string(&created, "CertificateAuthorityArn", &row.case));
    }
    for (row, arn) in rows.iter().zip(&authorities) {
        poll_for_status(&emulator, &row.case, arn, "PENDING_CERTIFICATE").await;
    }

    for (row, arn) in rows.iter().zip(&authorities) {
        let case = row.case.as_str();
        let csr = string(
            &emulator
                .ok(
                    case,
                    "GetCertificateAuthorityCsr",
                    &json!({"CertificateAuthorityArn": arn}),
                )
                .await,
            "Csr",
            case,
        );
        let usage = requested_key_usage(&csr, case);
        let Some(asserted) = &row.asserted else {
            assert!(
                usage.is_none(),
                "case {case:?}: a configuration asking for no key usage must ask for no \
                 keyUsage extension, got {usage:?}"
            );
            continue;
        };
        let usage = usage.unwrap_or_else(|| {
            panic!("case {case:?}: the published request must ask for a keyUsage extension")
        });
        // Exactly the configured bits: every member the row names is asserted, and every
        // member it does not name is clear.
        for (member, bit) in BITS {
            let expected = asserted.contains(member);
            assert_eq!(
                usage.0.contains(*bit),
                expected,
                "case {case:?}: expected {member} to be {expected}, got {usage:?}"
            );
        }
    }
}
