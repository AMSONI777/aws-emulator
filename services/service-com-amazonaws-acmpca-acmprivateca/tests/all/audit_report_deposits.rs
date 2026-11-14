// SPDX-License-Identifier: CC0-1.0

//! WHERE an audit report goes, and what the service keeps of the one it produced.
//!
//! The rule under test: `CreateCertificateAuthorityAuditReport` writes the report into the
//! S3 bucket THE REQUEST NAMES — "The name of the S3 bucket that will contain the audit
//! report." (`CreateCertificateAuthorityAuditReportRequest$S3BucketName`) — at the `S3Key`
//! the same call answers ("The key that uniquely identifies the report file in your S3
//! bucket."), under the `AuditReportId` it mints ("An alphanumeric string that contains a
//! report identifier."), and `DescribeCertificateAuthorityAuditReport` then reports that
//! bucket and that key for that id. The object is the report of what the CA had done with
//! its key at the instant it was asked for, so it is written once and a later use of the key
//! neither rewrites it nor moves it.
//!
//! The rows differ along what the rule generalises over: the bucket named (two buckets, so a
//! report lands in the one its own request named and nowhere else), the
//! `AuditReportResponseFormat` member asked for (both of them), and how many uses of the key
//! there are to report (none, one, several). Each row is a CA of its own: this operation's
//! documentation publishes a limit of one report per CA every 30 minutes, so asking one CA
//! for two reports in the same instant would assert on a call production refuses.
//!
//! Every call goes over the wire through the two-service harness in
//! [`super::crl_bucket_resolution`] — the private CA and the object storage its reports go
//! to, mounted on ONE engine — so what the assertions read is the object the service itself
//! deposited.

use serde_json::{json, Value};

use crate::audit_report_rows::poll_for_certificate;
use crate::crl_bucket_resolution::Emulator;
use crate::crl_publication::active_ca;
use crate::private_ca_lifecycle::{blob, csr_pem, string};

/// The bucket most rows name.
const BUCKET: &str = "acme-audit-deposits";

/// A second bucket, so a row can check its report went into the bucket IT named and not into
/// the other one this account holds.
const OTHER_BUCKET: &str = "acme-audit-deposits-elsewhere";

/// The lengths of the hyphen-separated groups of an `AuditReportId`: "len 36..36, pattern
/// ^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$"
/// (`CreateCertificateAuthorityAuditReportResponse$AuditReportId`).
const AUDIT_REPORT_ID_GROUPS: &[usize] = &[8, 4, 4, 4, 12];

/// One report a row asks for.
struct Row {
    /// The case every assertion of this row names.
    case: &'static str,
    /// The common name the row's CA is created under.
    common_name: &'static str,
    /// The bucket the row's request names.
    bucket: &'static str,
    /// The `AuditReportResponseFormat` the row asks for.
    format: &'static str,
    /// The extension the report's key carries for that format.
    extension: &'static str,
    /// How many certificates the row's CA has issued before it asks for the report, which is
    /// how many uses of its key the report states.
    issued: usize,
}

/// Every report this suite asks for: both formats, both buckets, and nothing, one thing and
/// several things to report.
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "a JSON report of a CA that has issued nothing",
            common_name: "deposit-json-none",
            bucket: BUCKET,
            format: "JSON",
            extension: "json",
            issued: 0,
        },
        Row {
            case: "a CSV report of a CA that has issued nothing",
            common_name: "deposit-csv-none",
            bucket: OTHER_BUCKET,
            format: "CSV",
            extension: "csv",
            issued: 0,
        },
        Row {
            case: "a JSON report of a CA that has issued one certificate",
            common_name: "deposit-json-one",
            bucket: OTHER_BUCKET,
            format: "JSON",
            extension: "json",
            issued: 1,
        },
        Row {
            case: "a CSV report of a CA that has issued three certificates",
            common_name: "deposit-csv-three",
            bucket: BUCKET,
            format: "CSV",
            extension: "csv",
            issued: 3,
        },
    ]
}

/// The CA's id: the last segment of its ARN, which is the folder its reports are written
/// under.
fn certificate_authority_id(arn: &str, case: &str) -> String {
    arn.rsplit_once('/')
        .map(|(_, id)| id.to_string())
        .unwrap_or_else(|| panic!("case {case:?}: no id in {arn:?}"))
}

/// Issue one certificate from `arn` and answer its ARN once the issuance has completed.
async fn issue_one(emulator: &Emulator, case: &str, arn: &str, index: usize) -> String {
    let issued = emulator
        .ok(
            case,
            "IssueCertificate",
            &json!({
                "CertificateAuthorityArn": arn,
                "Csr": blob(&csr_pem(&format!("{case}-leaf-{index}"))),
                "SigningAlgorithm": "SHA256WITHRSA",
                "Validity": {"Type": "DAYS", "Value": 30},
            }),
        )
        .await;
    let certificate_arn = string(&issued, "CertificateArn", case);
    // A report states what the CA has DONE with its key, and an issuance completes on the
    // clock, so the suite looks again until the certificate is served rather than waiting a
    // span of its own.
    poll_for_certificate(emulator, case, arn, &certificate_arn).await;
    certificate_arn
}

/// How many uses of the key a deposited report states, in either format: the entries of a
/// JSON array, or the lines of a CSV after its header.
fn stated_rows(case: &str, format: &str, text: &str) -> usize {
    if format == "CSV" {
        let mut lines = text.lines();
        let header = lines.next().unwrap_or_default();
        assert!(
            header.starts_with("awsAccountId,certificateArn,serial,"),
            "case {case:?}: a CSV report opens with its columns, got {text:?}"
        );
        return lines.filter(|line| !line.is_empty()).count();
    }
    let parsed: Value = serde_json::from_str(text)
        .unwrap_or_else(|error| panic!("case {case:?}: the report is JSON: {error}"));
    parsed
        .as_array()
        .unwrap_or_else(|| panic!("case {case:?}: a JSON report is an array: {parsed:?}"))
        .len()
}

/// Every report is deposited in the bucket its own request named, at the key the call
/// answered, and is described there by the id it was minted under.
#[tokio::test]
async fn a_report_is_deposited_in_the_bucket_its_request_named() {
    let emulator = Emulator::new();
    for bucket in [BUCKET, OTHER_BUCKET] {
        assert_eq!(
            emulator.create_bucket(bucket).await,
            200,
            "bucket {bucket:?}: the buckets the reports are deposited in are created \
             through S3"
        );
    }

    let mut minted: Vec<(String, String)> = Vec::new();
    for row in rows() {
        let case = row.case;
        let (arn, _) = active_ca(&emulator, case, row.common_name, None).await;
        for index in 0..row.issued {
            issue_one(&emulator, case, &arn, index).await;
        }

        let created = emulator
            .ok(
                case,
                "CreateCertificateAuthorityAuditReport",
                &json!({
                    "CertificateAuthorityArn": arn,
                    "S3BucketName": row.bucket,
                    "AuditReportResponseFormat": row.format,
                }),
            )
            .await;
        let report_id = string(&created, "AuditReportId", case);
        let key = string(&created, "S3Key", case);

        // The id is an `AuditReportId`: the groups the model's pattern states, of lower-case
        // alphanumerics.
        let groups: Vec<usize> = report_id.split('-').map(str::len).collect();
        assert_eq!(
            groups, AUDIT_REPORT_ID_GROUPS,
            "case {case:?}: expected an AuditReportId of {AUDIT_REPORT_ID_GROUPS:?} groups, \
             got {report_id:?}"
        );
        assert!(
            report_id
                .chars()
                .all(|character| character == '-'
                    || character.is_ascii_digit()
                    || character.is_ascii_lowercase()),
            "case {case:?}: an AuditReportId is lower-case alphanumeric, got {report_id:?}"
        );
        assert_eq!(
            key,
            format!(
                "audit-report/{}/{report_id}.{}",
                certificate_authority_id(&arn, case),
                row.extension
            ),
            "case {case:?}: a report's key names the CA, the report and its format, \
             got {key:?}"
        );
        minted.push((report_id.clone(), key.clone()));

        // The object is in the bucket THIS request named, and it states one entry per use of
        // the CA's key.
        let (status, body) = emulator
            .s3("GET", &format!("{}/{key}", row.bucket), &[], Vec::new())
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected the report at {:?}/{key:?}, got {status}",
            row.bucket
        );
        let text = String::from_utf8(body.clone()).expect("the report is text");
        assert_eq!(
            stated_rows(case, row.format, &text),
            row.issued,
            "case {case:?}: expected {} entr(ies), got {text:?}",
            row.issued
        );

        // And it is in no OTHER bucket this account holds.
        let elsewhere = if row.bucket == BUCKET { OTHER_BUCKET } else { BUCKET };
        let (absent, _) = emulator
            .s3("GET", &format!("{elsewhere}/{key}"), &[], Vec::new())
            .await;
        assert_eq!(
            absent, 404,
            "case {case:?}: the report must be in {:?} alone, {elsewhere:?} answered {absent}",
            row.bucket
        );

        // The service's record of the report answers the same bucket and key for that id.
        let describe = json!({"CertificateAuthorityArn": arn, "AuditReportId": report_id});
        let described = emulator
            .ok(case, "DescribeCertificateAuthorityAuditReport", &describe)
            .await;
        assert_eq!(
            string(&described, "S3BucketName", case),
            row.bucket,
            "case {case:?}: the report is described by the bucket it was asked into, \
             got {described:?}"
        );
        assert_eq!(
            string(&described, "S3Key", case),
            key,
            "case {case:?}: the report is described by the key it was written at, \
             got {described:?}"
        );

        // A later use of the CA's key neither rewrites the object nor moves it: the report is
        // what the CA had done when it was asked for.
        issue_one(&emulator, case, &arn, row.issued).await;
        let (status, after) = emulator
            .s3("GET", &format!("{}/{key}", row.bucket), &[], Vec::new())
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected the report to stay at {key:?}, got {status}"
        );
        assert_eq!(
            after, body,
            "case {case:?}: a report already deposited states what the CA had done, got {:?}",
            String::from_utf8_lossy(&after)
        );
        let again = emulator
            .ok(case, "DescribeCertificateAuthorityAuditReport", &describe)
            .await;
        assert_eq!(
            string(&again, "S3Key", case),
            key,
            "case {case:?}: the report keeps the key it was written at, got {again:?}"
        );
    }

    // Every report this suite asked for was minted under an id and a key of its own.
    for (index, (report_id, key)) in minted.iter().enumerate() {
        for (other_id, other_key) in minted.iter().skip(index + 1) {
            assert_ne!(
                report_id, other_id,
                "every report carries an id of its own, got {report_id:?} twice"
            );
            assert_ne!(
                key, other_key,
                "every report is written at a key of its own, got {key:?} twice"
            );
        }
    }
}
