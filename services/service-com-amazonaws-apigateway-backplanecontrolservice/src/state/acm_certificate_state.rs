// SPDX-License-Identifier: CC0-1.0

//! The STATE Certificate Manager holds a certificate in, for the precondition every custom
//! domain name of this service turns on it: a certificate a domain name is configured to
//! present has to be one Certificate Manager has already ISSUED.
//!
//! `certificateArn` and `regionalCertificateArn` are "the reference to an Amazon Web
//! Services-managed certificate that will be used by" the domain name's endpoint, and
//! `ownershipVerificationCertificateArn` is "the ARN of the public certificate issued by ACM
//! to validate ownership of your custom domain" — so each of them names a certificate this
//! service has to USE. A certificate Certificate Manager has not issued cannot be used for
//! anything: it has no leaf to present and nothing to prove ownership with, so a domain name
//! configured to present one could never serve a request. Whether a certificate has been
//! issued is not a fact this service holds, though — a certificate is Certificate Manager's
//! resource, and `acm:DescribeCertificate` reports its `Status`.
//!
//! It is therefore ASKED there, the way any emulated service reaches another — through the
//! in-process callback ([`smithy_server_runtime::OperationContext::callback`]), over the
//! client below — so this crate names no other service's crate, no socket is opened and
//! nothing leaves the process. Nothing is cached: a certificate imported a moment ago is
//! weighed at once, and one whose validation has just completed stops being refused at once.
//!
//! WHAT THIS GATE READS IS A STATUS, and nothing else. A certificate Certificate Manager
//! answers about is weighed by the status it answered with; an answer that establishes no
//! status — a hop that could not be made, a certificate that service holds no record of, a
//! status outside the modelled catalog — establishes nothing, so it refuses nothing and says
//! so at `warn`. That is the same reading of silence [`super::vpc_endpoints`] takes, and the
//! refusal that IS served is the one the owner's answer grounds.
//!
//! The per-crate client below is this tree's convention for that hop, for the reason
//! [`super::vpc_endpoints`] records: each service asks a different question and takes its own
//! reading of silence. What is shared is already shared — the Region-label grammar and the
//! ARN parse ([`::service_common::arn`]).

/// The one Certificate Manager status a certificate a custom domain name references may be
/// in: `ISSUED`, the status of a certificate that service has issued and can be used from.
///
/// From `CertificateStatus` of the Certificate Manager model
/// (`smithy_query(query="shape",shape="CertificateStatus")` against that service's model:
/// `PENDING_VALIDATION | ISSUED | INACTIVE | EXPIRED | VALIDATION_TIMED_OUT | REVOKED |
/// FAILED`).
const STATUS_ISSUED: &str = "ISSUED";

/// Every status in that catalog, so a status this gate REFUSES on is one the model declares
/// rather than any text that is not [`STATUS_ISSUED`].
///
/// Same source as [`STATUS_ISSUED`]: `CertificateStatus` of the Certificate Manager model.
/// A value outside it is an answer this service cannot read, which establishes nothing (see
/// this module's documentation).
const CERTIFICATE_STATUS_VALUES: &[&str] = &[
    "PENDING_VALIDATION",
    "ISSUED",
    "INACTIVE",
    "EXPIRED",
    "VALIDATION_TIMED_OUT",
    "REVOKED",
    "FAILED",
];

/// The sentence a request naming a certificate Certificate Manager has not issued is refused
/// with.
///
/// FIXED TEXT: it names the STATE the certificate has to be in and carries no part of the
/// request — not the certificate ARN, not the status the certificate is actually in and not
/// the member that named it — which is what keeps this refusal distinguishable from the
/// unreadable-ARN refusal ([`super::INVALID_ARN`]) a value that is no certificate ARN at all
/// earns.
pub const CERTIFICATE_NOT_ISSUED: &str =
    "Certificate is not in an ISSUED state, and cannot be used";

/// How many DISTINCT certificates one request is resolved for.
///
/// One hop per certificate, so the work a single call costs is capped by a constant rather
/// than by how many members the caller sets. It is the shared ceiling on how many
/// certificates ONE resource can reference at all
/// ([`::service_common::acm_certificate_associations::MAX_CERTIFICATES_PER_RESOURCE`]), which
/// is far above the three members of a `DomainName` that name one, so no certificate a domain
/// name can actually hold goes unresolved.
const MAX_CERTIFICATES_RESOLVED: usize =
    ::service_common::acm_certificate_associations::MAX_CERTIFICATES_PER_RESOURCE;

/// An AWS SDK client for Certificate Manager over the in-process callback into this same
/// emulator.
///
/// `region` is the Region the certificate's own ARN names, so the question is asked where the
/// certificate lives — an edge-optimized domain name's certificate is held in one Region
/// whatever Region the caller addressed this service in. The endpoint URL is only the address
/// the callback's transport routes on IN PROCESS. The credentials are the callback's, which
/// sign this in-process hop and never appear in a response.
///
/// A Region read off a caller-supplied ARN is not just data here — it ends up in an endpoint
/// URL's authority — so it is read as a Region LABEL ([`::service_common::arn::region_of`],
/// the one place this tree states that grammar) instead of being interpolated as given:
/// `None` for a value that would name an authority the caller chose rather than the peer
/// service this emulator asks.
fn acm(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
) -> Option<::aws_sdk_acm::Client> {
    let region = ::service_common::arn::region_label(region)?;
    let config = ::aws_sdk_acm::Config::builder()
        .behavior_version(::aws_sdk_acm::config::BehaviorVersion::latest())
        .http_client(ctx.callback().http_client())
        .credentials_provider(ctx.callback().aws_credentials_provider())
        .region(::aws_sdk_acm::config::Region::new(region.to_string()))
        .endpoint_url(format!("https://acm.{region}.amazonaws.com"))
        // The transport is in-process: there is nothing to retry, time out or watch for a
        // stalled stream, and each of those would need a sleep implementation this client is
        // not given. The same goes for caching the identity: the credentials the callback
        // hands over are used directly.
        .retry_config(::aws_sdk_acm::config::retry::RetryConfig::disabled())
        .timeout_config(::aws_sdk_acm::config::timeout::TimeoutConfig::disabled())
        .identity_cache(::aws_sdk_acm::config::IdentityCache::no_cache())
        .stalled_stream_protection(::aws_sdk_acm::config::StalledStreamProtectionConfig::disabled())
        .build();
    Some(::aws_sdk_acm::Client::from_conf(config))
}

/// What the owner of certificates answered about the one a request named.
enum Answer {
    /// No status was established — evidence of nothing (see this module's documentation).
    Unknown,
    /// Whether the certificate asked about has been ISSUED, as Certificate Manager reports
    /// its status.
    Issued(bool),
}

/// Whether a status Certificate Manager reported is one this gate can read, and if so whether
/// it is [`STATUS_ISSUED`].
fn reading_of(status: &str) -> Answer {
    if status == STATUS_ISSUED {
        return Answer::Issued(true);
    }
    if CERTIFICATE_STATUS_VALUES.contains(&status) {
        return Answer::Issued(false);
    }
    Answer::Unknown
}

/// Ask Certificate Manager for the status it holds `certificate_arn` in.
async fn certificate_is_issued(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    request_region: &str,
    certificate_arn: &str,
) -> Answer {
    // The certificate's OWN Region, and the Region the caller addressed for a value whose ARN
    // names none — which is the Region a certificate of this account would be held in anyway.
    let region = ::service_common::arn::region_of(certificate_arn, "acm").unwrap_or(request_region);
    let Some(client) = acm(ctx, region) else {
        ::tracing::warn!(
            "neither the certificate nor the request names a Region label, so the certificate \
             manager cannot be asked"
        );
        return Answer::Unknown;
    };
    match client
        .describe_certificate()
        .certificate_arn(certificate_arn)
        .send()
        .await
    {
        Ok(answer) => match answer
            .certificate()
            .and_then(|certificate| certificate.status())
        {
            Some(status) => reading_of(status.as_str()),
            None => Answer::Unknown,
        },
        Err(error) => {
            // At `warn`: this gate refuses nothing on an answer that establishes no status, so
            // an emulator where the hop cannot be made admits a domain name AWS would refuse,
            // and that is worth seeing. The ARN is metadata of the request, not a secret, and
            // nothing of the certificate itself is read here.
            ::tracing::warn!(
                certificate = %certificate_arn,
                error = %::aws_smithy_types::error::display::DisplayErrorContext(&error),
                "the certificate manager did not report the certificate's state"
            );
            Answer::Unknown
        }
    }
}

/// Resolve every certificate a custom domain name WOULD reference against the state
/// Certificate Manager holds it in.
///
/// `certificate_arns` are the values the record would carry once the call has been applied —
/// for a patch, the members it carries over the ones it leaves stored — so the precondition is
/// weighed against the resource as it would stand rather than against one call's members. A
/// blank member names no certificate and is skipped, and one certificate named twice is asked
/// about once.
///
/// `Ok(())` for a request whose every named certificate Certificate Manager reports as
/// [`STATUS_ISSUED`], and for one no status could be established for (see this module's
/// documentation). `Err` carries [`CERTIFICATE_NOT_ISSUED`] for the operation's
/// `BadRequestException`, so a domain name that could never present its certificate is
/// refused before anything is stored.
pub async fn resolve_certificates_issued<'arn, I>(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    request_region: &str,
    certificate_arns: I,
) -> Result<(), String>
where
    I: IntoIterator<Item = &'arn str>,
{
    let mut asked: Vec<&str> = Vec::new();
    for certificate_arn in certificate_arns {
        let certificate_arn = certificate_arn.trim();
        if certificate_arn.is_empty() || asked.contains(&certificate_arn) {
            continue;
        }
        if asked.len() >= MAX_CERTIFICATES_RESOLVED {
            // At `warn`, for the same reason an unestablished status is logged: past the
            // ceiling this call weighs nothing more, so a request naming more distinct
            // certificates than one resource can reference is admitted on an unresolved tail.
            ::tracing::warn!(
                asked = asked.len(),
                "more distinct certificates were named than one resource can reference, so the \
                 rest were not weighed"
            );
            break;
        }
        asked.push(certificate_arn);
        match certificate_is_issued(ctx, request_region, certificate_arn).await {
            Answer::Unknown | Answer::Issued(true) => {}
            Answer::Issued(false) => return Err(CERTIFICATE_NOT_ISSUED.to_string()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{reading_of, Answer, CERTIFICATE_STATUS_VALUES, STATUS_ISSUED};

    /// Every status of the modelled catalog is read, and only `ISSUED` is a certificate this
    /// service may use; a value outside the catalog establishes nothing.
    #[test]
    fn only_the_issued_status_admits_a_certificate() {
        // (the status the certificate manager reported, admitted?) — the rows are the whole
        // `CertificateStatus` catalog, plus two values outside it.
        let rows: Vec<(&str, Option<bool>)> = vec![
            ("ISSUED", Some(true)),
            ("PENDING_VALIDATION", Some(false)),
            ("INACTIVE", Some(false)),
            ("EXPIRED", Some(false)),
            ("VALIDATION_TIMED_OUT", Some(false)),
            ("REVOKED", Some(false)),
            ("FAILED", Some(false)),
            ("issued", None),
            ("SOMETHING_ELSE", None),
        ];
        for (status, expected) in rows {
            let read = match reading_of(status) {
                Answer::Unknown => None,
                Answer::Issued(issued) => Some(issued),
            };
            assert_eq!(
                read, expected,
                "case {status:?}: expected {expected:?}, got {read:?}"
            );
        }
    }

    /// The catalog this gate reads a status against holds the one status it admits, so no
    /// edit of either can leave `ISSUED` outside it.
    #[test]
    fn the_admitted_status_is_one_of_the_modelled_statuses() {
        assert!(
            CERTIFICATE_STATUS_VALUES.contains(&STATUS_ISSUED),
            "case the catalog: expected {STATUS_ISSUED:?} among {CERTIFICATE_STATUS_VALUES:?}"
        );
    }
}
