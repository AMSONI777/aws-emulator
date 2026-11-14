// SPDX-License-Identifier: CC0-1.0

//! The CANONICAL REQUEST a SigV4 signature of an invoke is computed over, and the
//! string-to-sign built from it — the two values AWS QUOTES BACK when a signature does not
//! match ([`super::Unauthenticated::SignatureMismatch`]).
//!
//! A mismatch is the one authentication failure a caller can act on without asking anybody:
//! AWS answers it with the canonical request and the string-to-sign IT computed, so the
//! client can diff them against its own and see which part of the request its signer read
//! differently — the path, the query, a header it did or did not sign, or the payload hash.
//! Without them the refusal says only that two signatures differ.
//!
//! Neither value is a secret and neither depends on one: both are functions of the REQUEST
//! alone (SigV4's `CanonicalRequest` and `StringToSign`), composed from what the request
//! sent — its method, its path, its query, the headers its own `SignedHeaders` element
//! declares, its payload, and the credential scope and instant its `Authorization` element
//! names. No secret this emulator holds, no key material and nothing of its stores appears
//! in either: every line is what the request itself sent, answered to the sender. Nothing
//! here verifies anything: the verification is the emulator's own ([`super::refusal`]), and
//! this module is only asked once that verification has already refused the signature.
//!
//! The SDK's signer does not publish these two values (`aws_sigv4` exposes the signature it
//! produces, not the canonical request behind it), so they are composed here from the
//! request, to the grammar SigV4 defines: the canonical request is
//! `METHOD\nURI\nQUERY\nHEADERS\n\nSIGNED_HEADERS\nPAYLOAD_HASH`, and the string-to-sign is
//! the algorithm, the instant, the credential scope and the hash of that canonical request.
//!
//! Nothing here reads or writes this service's records.

use std::collections::BTreeSet;

use aws_smithy_runtime_api::http::Request as RtRequest;
use sha2::{Digest, Sha256};

/// The signing algorithm a SigV4 string-to-sign opens with, which is the one an
/// `Authorization` header of this family names.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The element of the `Authorization` header naming the headers the signature covers.
const SIGNED_HEADERS_ELEMENT: &str = "SignedHeaders=";

/// The element naming the access key id and the credential scope.
const CREDENTIAL_ELEMENT: &str = "Credential=";

/// The header carrying the instant the signature was computed at, which is the second line
/// of the string-to-sign.
const DATE_HEADER: &str = "x-amz-date";

/// The header a client may state the payload hash in rather than leaving it to be computed
/// from the body, which is the last line of the canonical request.
const CONTENT_SHA256_HEADER: &str = "x-amz-content-sha256";

/// The query field a presigned URL carries its signature in, which is the one field the
/// canonical query string of such a request leaves out.
const SIGNATURE_FIELD: &str = "X-Amz-Signature";

/// The most bytes of canonical request this plane will quote back.
///
/// A canonical request is as long as the request's own line, query and signed headers, which
/// is far under this for every signer; a composed value past it is one no client could diff
/// anyway, so such a refusal is the sentence alone rather than a quoted value whose size is
/// a multiple of what the request sent. Only this plane's own ANSWER is bounded — nothing of
/// the verification depends on it.
const MAX_QUOTED_CANONICAL_BYTES: usize = 16 * 1024;

/// The two values AWS quotes back for a signature that does not match.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedSigning {
    /// The canonical request this plane computed from the request as it arrived.
    canonical_request: String,
    /// The string-to-sign built from it.
    string_to_sign: String,
}

/// Prints neither value, so neither can reach a log through a formatted record.
///
/// A canonical request covers the headers the request's own `SignedHeaders` element declares,
/// and a client signing with a session credential declares the one its session token travels
/// in — so these two strings can carry the CALLER's own credential. AWS quotes them back to
/// that caller, which is who sent them, and this emulator answers the same; writing them
/// anywhere else is what this keeps from happening by accident.
impl std::fmt::Debug for ExpectedSigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpectedSigning")
            .field("canonical_request", &"<not logged>")
            .field("string_to_sign", &"<not logged>")
            .finish()
    }
}

impl ExpectedSigning {
    /// What the refusal states after its sentence: each value under the line AWS introduces
    /// it with, quoted, exactly as the `execute-api` endpoint reports them.
    #[must_use]
    pub fn stated(&self) -> String {
        format!(
            "\n\nThe Canonical String for this request should have been\n'{canonical}'\n\n\
             The String-to-Sign should have been\n'{string_to_sign}'\n",
            canonical = self.canonical_request,
            string_to_sign = self.string_to_sign,
        )
    }
}

/// The canonical request and string-to-sign of `req`, or `None` when the request does not
/// state enough to compose them — a request carrying no `SignedHeaders` element names no
/// headers for the canonical request to cover, and a request carrying no credential scope
/// names no scope for the string-to-sign — or when the composed value would pass
/// [`MAX_QUOTED_CANONICAL_BYTES`].
#[must_use]
pub fn expected_signing(req: &RtRequest) -> Option<ExpectedSigning> {
    let authorization = req.headers().get("authorization");
    let query = req.uri().split_once('?').map(|(_, query)| query);
    let signed_headers = element(authorization, SIGNED_HEADERS_ELEMENT)
        .or_else(|| query_field(query, "X-Amz-SignedHeaders"))?;
    let scope = credential_scope(
        &element(authorization, CREDENTIAL_ELEMENT)
            .or_else(|| query_field(query, "X-Amz-Credential"))?,
    )?;
    let instant = req
        .headers()
        .get(DATE_HEADER)
        .map(str::to_string)
        .or_else(|| query_field(query, "X-Amz-Date"))?;
    let canonical_request = canonical_request(req, &signed_headers, query);
    if canonical_request.len() > MAX_QUOTED_CANONICAL_BYTES {
        return None;
    }
    let string_to_sign = format!(
        "{ALGORITHM}\n{instant}\n{scope}\n{hash}",
        hash = hex::encode(Sha256::digest(canonical_request.as_bytes())),
    );
    Some(ExpectedSigning {
        canonical_request,
        string_to_sign,
    })
}

/// The canonical request of `req`, to SigV4's own grammar: the verb, the path, the canonical
/// query string, one line per signed header, the signed-header list and the payload hash.
///
/// The path and the query are read by this plane's own readers of them
/// ([`super::super::path_of`]), so the canonical request states the request exactly as the
/// rest of the resolution read it.
///
/// The signed headers are the DISTINCT names the element declares, in the order SigV4's
/// grammar states them ("the header names must be sorted, and each name must appear once"),
/// so a repeated name states one line and copies the header's value once — the composed
/// string is as long as the request's own headers rather than a multiple of them.
fn canonical_request(req: &RtRequest, signed_headers: &str, query: Option<&str>) -> String {
    let signed: BTreeSet<String> = signed_headers
        .split(';')
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    let headers: String = signed
        .iter()
        .map(|name| {
            format!(
                "{name}:{value}\n",
                value = req.headers().get(name.as_str()).unwrap_or_default().trim()
            )
        })
        .collect();
    format!(
        "{method}\n{uri}\n{query}\n{headers}\n{signed}\n{payload}",
        method = req.method().to_ascii_uppercase(),
        uri = super::super::path_of(req.uri()),
        query = canonical_query(query),
        signed = signed.iter().cloned().collect::<Vec<String>>().join(";"),
        payload = payload_hash(req),
    )
}

/// The canonical query string: every field the request sent in the order the canonical
/// request states them — by name, then by value — with the SIGNATURE field left out, since
/// that is the value the signature covers rather than part of what it covers.
///
/// The fields keep the spelling the request sent, because that spelling is what the client
/// signed: re-encoding them here would state a canonical request neither side computed.
fn canonical_query(query: Option<&str>) -> String {
    let fields: BTreeSet<(String, String)> = query
        .unwrap_or_default()
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| match field.split_once('=') {
            Some((name, value)) => (name.to_string(), value.to_string()),
            None => (field.to_string(), String::new()),
        })
        .filter(|(name, _)| name != SIGNATURE_FIELD)
        .collect();
    fields
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<String>>()
        .join("&")
}

/// The payload hash the canonical request closes with: the value the request STATED for it,
/// or the hash of the body it carried.
///
/// A body this plane cannot read in full — one still streaming — hashes as the empty payload,
/// which is the hash of the bytes it has: the quoted value is a diagnostic, and nothing is
/// verified against it.
fn payload_hash(req: &RtRequest) -> String {
    match req.headers().get(CONTENT_SHA256_HEADER) {
        Some(stated) => stated.to_string(),
        None => hex::encode(Sha256::digest(req.body().bytes().unwrap_or_default())),
    }
}

/// The value of the `Authorization` element `element` names, or `None` when the header
/// carries no such element.
fn element(authorization: Option<&str>, element: &str) -> Option<String> {
    authorization?
        .split_once(element)
        .map(|(_, value)| value)?
        .split([',', ' '])
        .next()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The value of the query field `field`, for a presigned request, with its `%2F`-escaped
/// separators decoded — the one escape a credential scope carries.
fn query_field(query: Option<&str>, field: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| *name == field)
        .map(|(_, value)| value.replace("%2F", "/").replace("%2f", "/"))
        .filter(|value| !value.is_empty())
}

/// The CREDENTIAL SCOPE of `credential`: the four fields after the access key id
/// (`<date>/<region>/<service>/aws4_request`), which is the third line of the
/// string-to-sign.
fn credential_scope(credential: &str) -> Option<String> {
    let (_, scope) = credential.split_once('/')?;
    (!scope.is_empty()).then(|| scope.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credential scope every row signs under.
    const SCOPE: &str = "20260101/us-west-2/execute-api/aws4_request";

    /// The instant every row names.
    const INSTANT: &str = "20260101T000000Z";

    /// One request to a deployed stage, signed in the `Authorization` header over
    /// `signed_headers`.
    fn request(uri: &str, signed_headers: &str, body: &[u8]) -> RtRequest {
        let mut req = RtRequest::new(::aws_smithy_types::body::SdkBody::from(body.to_vec()));
        req.set_method("GET").expect("the verb is a verb");
        req.set_uri(uri).expect("the uri is a uri");
        let _ = req.headers_mut().try_insert("host", "example.test");
        let _ = req.headers_mut().try_insert(DATE_HEADER, INSTANT);
        let _ = req.headers_mut().try_insert(
            "authorization",
            format!(
                "{ALGORITHM} Credential=AKIDEXAMPLE/{SCOPE}, \
                 SignedHeaders={signed_headers}, Signature=0123456789abcdef"
            ),
        );
        req
    }

    /// RULE: the canonical request states the verb, the path, the canonical query, one line
    /// per signed header, the signed-header list and the payload hash — so the PATH the
    /// client addressed is readable out of the refusal.
    #[test]
    fn the_canonical_request_states_the_request_it_was_computed_over() {
        let empty_body = hex::encode(Sha256::digest(b""));
        // Rows differ along what the request carries: no query, one field, several fields
        // out of order, and a body.
        let rows: &[(&str, &str, &str, &[u8], String)] = &[
            (
                "no query at all",
                "https://example.test/test/widgets",
                "host;x-amz-date",
                b"",
                format!(
                    "GET\n/test/widgets\n\nhost:example.test\nx-amz-date:{INSTANT}\n\n\
                     host;x-amz-date\n{empty_body}"
                ),
            ),
            (
                "one query field",
                "https://example.test/test/widgets?page=2",
                "host;x-amz-date",
                b"",
                format!(
                    "GET\n/test/widgets\npage=2\nhost:example.test\nx-amz-date:{INSTANT}\n\n\
                     host;x-amz-date\n{empty_body}"
                ),
            ),
            (
                "query fields out of canonical order",
                "https://example.test/test/widgets?page=2&after=a",
                "host;x-amz-date",
                b"",
                format!(
                    "GET\n/test/widgets\nafter=a&page=2\nhost:example.test\n\
                     x-amz-date:{INSTANT}\n\nhost;x-amz-date\n{empty_body}"
                ),
            ),
            (
                "a body the signature covers",
                "https://example.test/test/widgets",
                "host",
                b"{\"n\":1}",
                format!(
                    "GET\n/test/widgets\n\nhost:example.test\n\nhost\n{hash}",
                    hash = hex::encode(Sha256::digest(b"{\"n\":1}"))
                ),
            ),
        ];
        for (case, uri, signed, body, expected) in rows {
            let req = request(uri, signed, body);
            let computed = expected_signing(&req)
                .unwrap_or_else(|| panic!("case {case}: a signed request states its canonical form"));
            assert_eq!(
                &computed.canonical_request, expected,
                "case {case}: got {:?}",
                computed.canonical_request
            );
            assert_eq!(
                computed.string_to_sign,
                format!(
                    "{ALGORITHM}\n{INSTANT}\n{SCOPE}\n{hash}",
                    hash = hex::encode(Sha256::digest(expected.as_bytes()))
                ),
                "case {case}: got {:?}",
                computed.string_to_sign
            );
        }
    }

    /// RULE: the signed headers are the DISTINCT names the element declares, so a name
    /// repeated N times states one line and copies its value once — the quoted value is as
    /// long as the request's own headers, not a multiple of them — and a composed value past
    /// the quoted bound is not stated at all.
    #[test]
    fn a_repeated_signed_header_states_one_line_and_a_long_one_states_none() {
        let value = "v".repeat(1024);
        let mut req = request("https://example.test/test/widgets", "host;x-big", b"");
        let _ = req.headers_mut().try_insert("x-big", value.clone());
        let repeated = format!("{}host", "x-big;".repeat(64));
        // One line per DISTINCT name: the value is copied once however often the element
        // names it.
        let computed = canonical_request(&req, &repeated, None);
        assert_eq!(
            computed.matches(&format!("x-big:{value}")).count(),
            1,
            "case \"a repeated signed header\": expected one line for the name, got {}",
            computed.matches(&format!("x-big:{value}")).count()
        );
        assert!(
            computed.len() < 4 * 1024,
            "case \"a repeated signed header\": expected a value the size of the request's \
             headers, got {} bytes",
            computed.len()
        );

        // Past the bound nothing is quoted: the refusal is its sentence alone.
        let huge = "h".repeat(MAX_QUOTED_CANONICAL_BYTES + 1);
        let mut long = request("https://example.test/test/widgets", "host;x-huge", b"");
        let _ = long.headers_mut().try_insert("x-huge", huge);
        assert_eq!(
            expected_signing(&long),
            None,
            "case \"a canonical request past the quoted bound\": expected nothing quoted back"
        );
    }

    /// RULE: a request that states no signed headers or no credential scope states nothing
    /// to quote back, and the refusal is its sentence alone.
    #[test]
    fn a_request_stating_no_signature_at_all_states_nothing_to_quote_back() {
        let mut bare = RtRequest::new(::aws_smithy_types::body::SdkBody::empty());
        bare.set_method("GET").expect("the verb is a verb");
        bare.set_uri("https://example.test/test/widgets")
            .expect("the uri is a uri");
        assert_eq!(
            expected_signing(&bare),
            None,
            "case \"a request carrying no credential\": expected nothing to quote back"
        );
    }

    /// RULE: a presigned request states the same two values, read off its query, with the
    /// signature field itself left out of the canonical query.
    #[test]
    fn a_presigned_request_states_its_canonical_form_from_its_query() {
        let mut req = RtRequest::new(::aws_smithy_types::body::SdkBody::empty());
        req.set_method("GET").expect("the verb is a verb");
        req.set_uri(
            "https://example.test/test/widgets?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIDEXAMPLE%2F20260101%2Fus-west-2%2Fexecute-api%2Faws4_request\
             &X-Amz-Date=20260101T000000Z&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef",
        )
        .expect("the uri is a uri");
        let _ = req.headers_mut().try_insert("host", "example.test");
        let computed =
            expected_signing(&req).expect("a presigned request states its canonical form");
        assert!(
            !computed.canonical_request.contains(SIGNATURE_FIELD),
            "case \"a presigned request\": the signature field is not part of what it covers, \
             got {:?}",
            computed.canonical_request
        );
        assert!(
            computed.canonical_request.contains("/test/widgets"),
            "case \"a presigned request\": expected the addressed path, got {:?}",
            computed.canonical_request
        );
        assert!(
            computed.string_to_sign.contains(SCOPE),
            "case \"a presigned request\": expected the scope its query names, got {:?}",
            computed.string_to_sign
        );
    }
}
