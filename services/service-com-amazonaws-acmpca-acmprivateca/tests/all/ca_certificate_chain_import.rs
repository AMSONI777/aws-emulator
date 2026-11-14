// SPDX-License-Identifier: CC0-1.0

//! What `ImportCertificateAuthorityCertificate` takes as the CHAIN under a CA certificate.
//!
//! The rule under test: a CA certificate presented with a `CertificateChain` must chain up
//! to it — walking the presented certificate and then the chain in the order it was
//! supplied, every certificate's issuer is the subject of the one after it and carries a
//! signature that one made. A certificate that does not is refused as the modelled
//! certificate mismatch, with the sentence about the chain, and the CA keeps waiting for its
//! certificate: nothing is installed, so it still answers no certificate of its own. The
//! SAME certificate presented with the chain that did sign it activates the CA, which is
//! what says the refusal was about the chain and not about the certificate.
//!
//! The rows span what can diverge in a path: an authority that did not sign it, an authority
//! with the signer's name and another key, a chain of the right certificates in the wrong
//! order, a chain missing the link above the certificate, and a self-signed certificate
//! presented with a chain at all — against the paths that do hold: the one-certificate chain
//! that signed it, the two-certificate chain up to a root, and no chain at all under a
//! self-signed certificate.
//!
//! The authorities are built here, out of a real key pair and real signatures, so a chain
//! this suite presents is a path whose signatures a verifier accepts or rejects on their own
//! merits rather than on anything this crate wrote.

use std::time::{Duration, Instant, SystemTime};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use x509_cert::der::asn1::BitString;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::name::Name;
use x509_cert::request::CertReq;
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

use crate::private_ca_lifecycle::{
    blob, ca_certificate_for, certificate_der, pem_of_bytes, rcgen_subject, root_ca_request,
    string, Emulator,
};
use crate::resource_policy::error_message;

/// The sentence Amazon Web Services Private CA answers a chain mismatch with: fixed text in
/// full, written out here rather than read off the service's own constant so a change to
/// either has to be made in both.
const CHAIN_MISMATCH_MESSAGE: &str = "Certificate does not chain up to certificate chain provided.";

/// `ecdsa-with-SHA256` (RFC 5758 section 3.2): the algorithm every certificate an authority
/// of this suite signs names, which is the pairing its P-256 key makes a signature under.
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

/// How long a poll for a due transition may take before the suite gives up. Generous: it
/// bounds a wait for a CONDITION, and the condition is the service's own settling.
const POLL_DEADLINE: Duration = Duration::from_secs(60);

/// How long a poll waits before looking again.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A signing authority a row of this suite presents a chain of: a key pair, and the
/// certificate that publishes it.
pub(crate) struct Authority {
    /// The certificate that publishes this authority's key — self-signed, or signed by the
    /// authority above it ([`Authority::issued_by`]).
    certificate: Certificate,
    /// The private key, as the PKCS#8 `PrivateKeyInfo` the signer reads it back from. Never
    /// leaves this struct.
    private_key: Vec<u8>,
}

impl Authority {
    /// A new authority whose certificate is self-signed, so it stands as a trust anchor.
    pub(crate) fn new(common_name: &str) -> Self {
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("parameters");
        params.distinguished_name = rcgen_subject(common_name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let certificate = params
            .self_signed(&key)
            .expect("a self-signed certificate")
            .pem();
        Self {
            certificate: Certificate::from_pem(&certificate).expect("it is an X.509 certificate"),
            private_key: key.serialize_der(),
        }
    }

    /// A new authority whose certificate `parent` signed, so the two are a path of two.
    pub(crate) fn issued_by(parent: &Authority, common_name: &str) -> Self {
        let mut authority = Self::new(common_name);
        authority.certificate = parent.certificate_over(
            &authority.certificate.tbs_certificate.subject,
            &authority.certificate.tbs_certificate.subject_public_key_info,
        );
        authority
    }

    /// This authority's certificate, PEM-encoded, as a chain carrying it alone.
    pub(crate) fn chain(&self) -> String {
        pem_of_bytes(
            "CERTIFICATE",
            &self.certificate.to_der().expect("the certificate encodes"),
        )
    }

    /// The CA certificate this authority issues for the certification request `csr`: a
    /// certificate over the subject and the public key that request published — which is
    /// what makes it the certificate of the CA that published it — issued by this authority.
    pub(crate) fn certificate_for(&self, csr: &str) -> String {
        let request = CertReq::from_pem(csr).expect("a PKCS#10 certification request");
        let certificate =
            self.certificate_over(&request.info.subject, &request.info.public_key);
        pem_of_bytes(
            "CERTIFICATE",
            &certificate.to_der().expect("the certificate encodes"),
        )
    }

    /// A certificate over `subject` and `key`, issued by this authority: its issuer is this
    /// authority's subject and its signature is one this authority's private key made over
    /// the certificate body (RFC 5280 section 4.1.1.3).
    ///
    /// Its validity window reaches a century ahead, because a CA activated with it reports
    /// that window as its own and a certificate the CA then issues may not outlive it
    /// (`IssueCertificateRequest$Validity`).
    fn certificate_over(
        &self,
        subject: &Name,
        key: &SubjectPublicKeyInfoOwned,
    ) -> Certificate {
        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(ECDSA_WITH_SHA256).expect("a signature algorithm"),
            parameters: None,
        };
        let not_before = SystemTime::now() - Duration::from_secs(3600);
        let not_after = not_before + Duration::from_secs(100 * 365 * 24 * 3600);
        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number: x509_cert::serial_number::SerialNumber::new(&next_serial())
                .expect("a serial number"),
            signature: algorithm.clone(),
            issuer: self.certificate.tbs_certificate.subject.clone(),
            validity: Validity {
                not_before: Time::try_from(not_before).expect("a representable date"),
                not_after: Time::try_from(not_after).expect("a representable date"),
            },
            subject: subject.clone(),
            subject_public_key_info: key.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let body = tbs_certificate.to_der().expect("the body encodes");
        let signature = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.private_key)
            .expect("the authority's key pair loads")
            .sign(&SystemRandom::new(), &body)
            .expect("the authority signs");
        Certificate {
            tbs_certificate,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(signature.as_ref()).expect("signature bits"),
        }
    }
}

/// A distinct eight-byte serial for every certificate this suite builds, so two of them are
/// never the same certificate.
fn next_serial() -> [u8; 8] {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1 << 40);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .to_be_bytes()
}

/// Create a CA and answer its ARN, without waiting for anything: every CA a test needs is
/// created first, so one poll covers them all.
async fn create_ca(emulator: &Emulator, case: &str, common_name: &str) -> String {
    let created = emulator
        .ok(case, "CreateCertificateAuthority", &root_ca_request(common_name))
        .await;
    string(&created, "CertificateAuthorityArn", case)
}

/// Poll `DescribeCertificateAuthority` until the CA reports `status`.
///
/// A new CA settles into `PENDING_CERTIFICATE` on the clock, so the suite looks again until
/// the condition holds rather than waiting a span of its own.
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

/// The certification request a CA published.
async fn published_csr(emulator: &Emulator, case: &str, arn: &str) -> String {
    let reported = emulator
        .ok(
            case,
            "GetCertificateAuthorityCsr",
            &json!({"CertificateAuthorityArn": arn}),
        )
        .await;
    string(&reported, "Csr", case)
}

/// An `ImportCertificateAuthorityCertificate` body, with a chain when one is presented.
fn import(arn: &str, certificate: &str, chain: Option<&str>) -> Value {
    let mut body = json!({"CertificateAuthorityArn": arn, "Certificate": blob(certificate)});
    if let Some(chain) = chain {
        body["CertificateChain"] = blob(chain);
    }
    body
}

/// A certificate that does not chain up to the chain presented with it is refused, and the
/// CA takes nothing from the refusal.
#[tokio::test]
async fn a_ca_certificate_must_chain_up_to_the_chain_presented_with_it() {
    let emulator = Emulator::new();

    // The authority that signs the certificate under test, and the ones a row presents
    // instead of it: one with ANOTHER name, and one with the signer's own name over another
    // key pair.
    let signer = Authority::new("chain-signer");
    let stranger = Authority::new("another-signer");
    let impostor = Authority::new("chain-signer");
    // And a two-level hierarchy, for the rows about the order and the links of a path.
    let root = Authority::new("chain-root");
    let intermediate = Authority::issued_by(&root, "chain-intermediate");

    // (the case, which authority signs the certificate, the chain presented)
    #[allow(clippy::type_complexity)]
    let rows: Vec<(&'static str, Option<&Authority>, Option<String>)> = vec![
        (
            "the chain of an authority that did not sign it",
            Some(&signer),
            Some(stranger.chain()),
        ),
        (
            "a chain naming the signer over another key pair",
            Some(&signer),
            Some(impostor.chain()),
        ),
        (
            "the certificates of its own path, in the wrong order",
            Some(&intermediate),
            Some(format!("{}{}", root.chain(), intermediate.chain())),
        ),
        (
            "a path missing the link above the certificate",
            Some(&intermediate),
            Some(root.chain()),
        ),
        (
            "a self-signed certificate presented with a chain",
            None,
            Some(signer.chain()),
        ),
    ];

    // Every CA is created first and polled once: a CA settles on the clock, and the rows
    // are independent of one another.
    let mut authorities: Vec<String> = Vec::with_capacity(rows.len());
    for (index, (case, _, _)) in rows.iter().enumerate() {
        authorities.push(create_ca(&emulator, case, &format!("chain-refused-{index}")).await);
    }
    for (case, arn) in rows.iter().map(|(case, _, _)| *case).zip(&authorities) {
        poll_for_status(&emulator, case, arn, "PENDING_CERTIFICATE").await;
    }

    for ((case, issuer, chain), arn) in rows.iter().zip(&authorities) {
        let csr = published_csr(&emulator, case, arn).await;
        let certificate = match issuer {
            Some(issuer) => issuer.certificate_for(&csr),
            None => ca_certificate_for(&csr),
        };
        let answer = emulator
            .refused(
                case,
                "ImportCertificateAuthorityCertificate",
                &import(arn, &certificate, chain.as_deref()),
                "CertificateMismatchException",
            )
            .await;
        let message = error_message(&answer, case);
        assert_eq!(
            message, CHAIN_MISMATCH_MESSAGE,
            "case {case:?}: expected the sentence about the chain, got {message:?}"
        );

        // The CA took nothing: it still waits for its certificate, and still answers none.
        let described = emulator
            .ok(case, "DescribeCertificateAuthority", &json!({"CertificateAuthorityArn": arn}))
            .await;
        assert_eq!(
            string(&described["CertificateAuthority"], "Status", case),
            "PENDING_CERTIFICATE",
            "case {case:?}: a refused import must leave the CA waiting for its certificate"
        );
        let refused = emulator
            .refused(
                case,
                "GetCertificateAuthorityCertificate",
                &json!({"CertificateAuthorityArn": arn}),
                "InvalidStateException",
            )
            .await;
        let message = error_message(&refused, case);
        assert_eq!(
            message,
            format!(
                "The certificate authority {arn} is not in the correct state to have a \
                 certificate signing request."
            ),
            "case {case:?}: expected the state sentence naming the CA, got {message:?}"
        );
    }

    // The SAME certificate, presented with the chain that DID sign it, activates the CA:
    // which is what says every refusal above was about the chain.
    let case = "the chain that signed it, after the refusals";
    let arn = &authorities[0];
    let csr = published_csr(&emulator, case, arn).await;
    emulator
        .ok(
            case,
            "ImportCertificateAuthorityCertificate",
            &import(arn, &signer.certificate_for(&csr), Some(&signer.chain())),
        )
        .await;
    let described = emulator
        .ok(case, "DescribeCertificateAuthority", &json!({"CertificateAuthorityArn": arn}))
        .await;
    assert_eq!(
        string(&described["CertificateAuthority"], "Status", case),
        "ACTIVE",
        "case {case:?}: the certificate with its own chain must activate the CA"
    );
}

/// A certificate presented with a path that holds is taken, and reads back with the chain
/// it was presented with.
#[tokio::test]
async fn a_certificate_presented_with_the_path_that_holds_is_taken() {
    let emulator = Emulator::new();

    let signer = Authority::new("accepted-signer");
    let root = Authority::new("accepted-root");
    let intermediate = Authority::issued_by(&root, "accepted-intermediate");

    // (the case, which authority signs the certificate, the chain presented)
    let rows: Vec<(&'static str, Option<&Authority>, Option<String>)> = vec![
        (
            "the one-certificate chain that signed it",
            Some(&signer),
            Some(signer.chain()),
        ),
        (
            "the two-certificate chain up to its root",
            Some(&intermediate),
            Some(format!("{}{}", intermediate.chain(), root.chain())),
        ),
        (
            "a self-signed certificate with no chain at all",
            None,
            None,
        ),
        (
            "a self-signed certificate with an empty chain",
            None,
            Some(String::new()),
        ),
    ];

    let mut authorities: Vec<String> = Vec::with_capacity(rows.len());
    for (index, (case, _, _)) in rows.iter().enumerate() {
        authorities.push(create_ca(&emulator, case, &format!("chain-taken-{index}")).await);
    }
    for (case, arn) in rows.iter().map(|(case, _, _)| *case).zip(&authorities) {
        poll_for_status(&emulator, case, arn, "PENDING_CERTIFICATE").await;
    }

    for ((case, issuer, chain), arn) in rows.iter().zip(&authorities) {
        let csr = published_csr(&emulator, case, arn).await;
        let certificate = match issuer {
            Some(issuer) => issuer.certificate_for(&csr),
            None => ca_certificate_for(&csr),
        };
        emulator
            .ok(
                case,
                "ImportCertificateAuthorityCertificate",
                &import(arn, &certificate, chain.as_deref()),
            )
            .await;
        let described = emulator
            .ok(case, "DescribeCertificateAuthority", &json!({"CertificateAuthorityArn": arn}))
            .await;
        assert_eq!(
            string(&described["CertificateAuthority"], "Status", case),
            "ACTIVE",
            "case {case:?}: a certificate whose path holds must activate the CA"
        );

        // And it reads back as the certificate and the chain that were presented.
        let read_back = emulator
            .ok(
                case,
                "GetCertificateAuthorityCertificate",
                &json!({"CertificateAuthorityArn": arn}),
            )
            .await;
        assert_eq!(
            certificate_der(&string(&read_back, "Certificate", case), case),
            certificate_der(&certificate, case),
            "case {case:?}: the CA certificate reads back as the one imported"
        );
        let presented_chain: Vec<Vec<u8>> = chain
            .as_deref()
            .filter(|chain| !chain.is_empty())
            .map(|chain| {
                Certificate::load_pem_chain(chain.as_bytes())
                    .expect("the chain under test is a PEM chain")
                    .iter()
                    .map(|certificate| certificate.to_der().expect("it re-encodes"))
                    .collect()
            })
            .unwrap_or_default();
        let read_back_chain: Vec<Vec<u8>> = read_back
            .get("CertificateChain")
            .and_then(Value::as_str)
            .map(|chain| {
                Certificate::load_pem_chain(chain.as_bytes())
                    .expect("the chain reads back as a PEM chain")
                    .iter()
                    .map(|certificate| certificate.to_der().expect("it re-encodes"))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            read_back_chain, presented_chain,
            "case {case:?}: the chain reads back as the certificates presented"
        );
    }
}
