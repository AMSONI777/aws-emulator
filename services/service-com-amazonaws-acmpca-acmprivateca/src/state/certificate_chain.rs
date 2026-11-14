// SPDX-License-Identifier: CC0-1.0

//! What makes a presented CA certificate chain up to the chain presented with it.
//!
//! `ImportCertificateAuthorityCertificate` takes the certificate a signing authority issued
//! for the CA's own certification request together with `CertificateChain`, "a PEM-encoded
//! file that contains all of your certificates, other than the certificate you're importing,
//! chaining up to your root CA" — so the chain is the path a relying party builds from the
//! CA's certificate to a trust anchor, and a certificate that does not sit at the bottom of
//! the path supplied beside it is the modelled mismatch
//! ([`super::CertificateMismatch::Chain`]). Importing it would leave the CA signing under a
//! certificate nothing can be path-validated against, and this service offers no way to undo
//! an import.
//!
//! Chaining up is the pairwise relation RFC 5280 section 6.1 validates a path by: taking the
//! presented certificate followed by the chain in the order it was supplied, each
//! certificate's issuer name is the subject name of the one after it, and each certificate's
//! signature is one that one after it made. The names are compared as the entities they name
//! ([`super::same_distinguished_name`]), and the signature is verified with the in-process
//! cryptography provider under the algorithms it offers ([`verification_algorithm`]): a
//! signature of a pairing it can neither make nor verify is judged by the names alone, which
//! is the same limit `super::key_material` documents for the signatures this service itself
//! writes.

use ::aws_lc_rs::signature::{
    UnparsedPublicKey, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    ECDSA_P521_SHA384_ASN1, ECDSA_P521_SHA512_ASN1, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};

use super::*;

/// Whether `certificate` chains up to `chain`: every certificate of the path
/// `certificate` followed by `chain` was issued by the one after it (the module docs).
///
/// A chain carrying no certificate is no path to judge, so a certificate presented without
/// one chains up trivially — which is the root CA's own self-signed certificate, imported
/// with no chain beside it.
pub fn chains_up_to(certificate: &Certificate, chain: &[Certificate]) -> bool {
    let mut issued = certificate;
    for issuer in chain {
        if !is_issuer_of(issuer, issued) {
            return false;
        }
        issued = issuer;
    }
    true
}

/// Whether `issuer` is the certificate that issued `issued`: it names the entity `issued`
/// names as its issuer, and `issued` carries a signature `issuer`'s public key accepts.
fn is_issuer_of(issuer: &Certificate, issued: &Certificate) -> bool {
    same_distinguished_name(
        &issued.tbs_certificate.issuer,
        &issuer.tbs_certificate.subject,
    ) && signature_stands_up(issued, &issuer.tbs_certificate.subject_public_key_info)
}

/// Whether the signature on `issued` stands up as one made with the private half of
/// `issuer_key`.
///
/// The signature covers the certificate's body as it was encoded (RFC 5280 section 4.1.1.3).
/// A pairing of key and signature algorithm the in-process provider offers no verification
/// for is not contradicted by anything this service can compute, so it stands: the names
/// are then all that is judged.
fn signature_stands_up(issued: &Certificate, issuer_key: &SubjectPublicKeyInfoOwned) -> bool {
    let Some(algorithm) = verification_algorithm(issuer_key, &issued.signature_algorithm.oid)
    else {
        return true;
    };
    let Ok(body) = issued.tbs_certificate.to_der() else {
        return false;
    };
    UnparsedPublicKey::new(algorithm, issuer_key.subject_public_key.raw_bytes())
        .verify(&body, issued.signature.raw_bytes())
        .is_ok()
}

/// The algorithm a signature made with the key `key` publishes, under the signature
/// algorithm `signature` names, verifies with — or `None` for a pairing the in-process
/// provider offers none for.
///
/// The pairings are the ones this service can itself SIGN with (`super::key_material`): an
/// RSA key with a PKCS#1 v1.5 signature of any of the three digests, and each NIST curve
/// with the digests paired with it there. The RSASSA-PSS, SM2 and ML-DSA signature
/// algorithms the model names are the ones it offers no signature for either.
fn verification_algorithm(
    key: &SubjectPublicKeyInfoOwned,
    signature: &ObjectIdentifier,
) -> Option<&'static dyn VerificationAlgorithm> {
    let signature = *signature;
    if key.algorithm.oid == oid::RSA_ENCRYPTION {
        if signature == oid::SHA256_WITH_RSA {
            return Some(&RSA_PKCS1_2048_8192_SHA256);
        }
        if signature == oid::SHA384_WITH_RSA {
            return Some(&RSA_PKCS1_2048_8192_SHA384);
        }
        if signature == oid::SHA512_WITH_RSA {
            return Some(&RSA_PKCS1_2048_8192_SHA512);
        }
        return None;
    }
    if key.algorithm.oid == oid::EC_PUBLIC_KEY {
        let curve = named_curve(key)?;
        if curve == oid::PRIME256V1 && signature == oid::ECDSA_WITH_SHA256 {
            return Some(&ECDSA_P256_SHA256_ASN1);
        }
        if curve == oid::SECP384R1 && signature == oid::ECDSA_WITH_SHA384 {
            return Some(&ECDSA_P384_SHA384_ASN1);
        }
        if curve == oid::SECP521R1 && signature == oid::ECDSA_WITH_SHA384 {
            return Some(&ECDSA_P521_SHA384_ASN1);
        }
        if curve == oid::SECP521R1 && signature == oid::ECDSA_WITH_SHA512 {
            return Some(&ECDSA_P521_SHA512_ASN1);
        }
    }
    None
}

/// The curve an EC public key names in its algorithm parameters (RFC 5480 section 2.1.1.1),
/// or `None` when it names none this service knows.
fn named_curve(key: &SubjectPublicKeyInfoOwned) -> Option<ObjectIdentifier> {
    let parameters = key.algorithm.parameters.as_ref()?;
    ObjectIdentifier::from_bytes(parameters.value()).ok()
}
