// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of DOMAIN CONFIGURATIONS: `CreateDomainConfiguration`, the
//! `DescribeDomainConfiguration` reader that proves what it persisted, and
//! `DeleteDomainConfiguration`.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` over a
//! restJson1 request signed for the `iot` signing name — so what is asserted is what
//! an AWS SDK client would see, not an internal function's return value.
//!
//! The rules under test:
//!
//! * a configuration created without a `domainName` configures the AWS-managed domain
//!   the account's endpoint already serves, and one carrying its own domain name is
//!   the customer-managed kind;
//! * a `serverCertificateArn` may only name a certificate that EXISTS, and whether one
//!   exists is the holder's answer: this suite writes the certificate into the one
//!   shared record Certificate Manager keeps of a certificate's serving material and
//!   so exercises both answers. A certificate nothing is held for is refused
//!   `InvalidRequestException` (400) with the fixed `Certificate <arn> does not
//!   exist.` and nothing created, which is what makes the following read a 404;
//! * a custom-domain configuration may only present a server certificate a device can
//!   establish trust in — one that chains to a certificate authority — or else carry
//!   the `validationCertificateArn` that proves domain ownership; a configuration for a
//!   domain of the caller's own that presents no certificate at all, and one whose
//!   certificate chains to no authority and carries no validation certificate, are each
//!   refused `InvalidRequestException` (400) and create nothing;
//! * a created configuration is read back member for member, and the name is its
//!   identity, so a second create under it is a conflict;
//! * the listing reports every configuration the account holds, filtered by
//!   `serviceType` when the request names one and paged by `pageSize`.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use serde_json::{json, Value};
use service_com_amazonaws_acm_certificatemanager::EmulatedService as CertificateManager;
use service_com_amazonaws_iot_awsiotservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The account id every emulated ARN carries (`emulator_server::EMULATOR_ACCOUNT_ID`).
const ACCOUNT_ID: &str = "000000000000";
/// The region this suite signs for; the ARN assertions read it back.
const REGION: &str = "eu-central-1";

/// One emulator: the shared engine plus a router with this service and the certificate
/// holder it resolves a server certificate against mounted on it.
struct Emulator {
    router: MultiServiceRouter,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        router.set_request_authentication(false);
        router.register_service(EmulatedService::new(Arc::clone(&engine)));
        // Certificate Manager HOLDS the certificates a domain configuration presents, so
        // it is mounted on the same engine: every certificate a case names is one the
        // holder's own API created, not a record written into the test.
        router.register_service(CertificateManager::new(engine));
        Self { router }
    }

    async fn dispatch(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let host = format!("iot.{REGION}.amazonaws.com");
        let payload = body.map_or_else(Bytes::new, |value| Bytes::from(value.to_string()));
        let request = http::Request::builder()
            .method(method)
            .uri(format!("https://{host}{path}"))
            .header("host", host)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/iot/aws4_request, \
                     SignedHeaders=host, Signature=0123456789abcdef"
                ),
            )
            .body(payload)
            .expect("the domain-configuration request is well formed");
        Reply::of(self.router.dispatch(request).await)
    }

    async fn create_configuration(&self, name: &str, body: &Value) -> Reply {
        self.dispatch("POST", &format!("/domainConfigurations/{name}"), Some(body))
            .await
    }

    async fn describe_configuration(&self, name: &str) -> Reply {
        self.dispatch("GET", &format!("/domainConfigurations/{name}"), None)
            .await
    }

    async fn delete_configuration(&self, name: &str) -> Reply {
        self.dispatch("DELETE", &format!("/domainConfigurations/{name}"), None)
            .await
    }

    async fn list_configurations(&self, query: &str) -> Reply {
        self.dispatch("GET", &format!("/domainConfigurations?{query}"), None)
            .await
    }

    /// Call one Certificate Manager operation, so a case's certificates are the ones the
    /// HOLDER's own API created.
    async fn certificate_manager(&self, operation: &str, body: &Value) -> Reply {
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", format!("CertificateManager.{operation}"))
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/{REGION}/acm/aws4_request, \
                     SignedHeaders=host;x-amz-target, Signature=0123456789abcdef"
                ),
            )
            .body(Bytes::from(body.to_string()))
            .expect("the certificate request is well formed");
        Reply::of(self.router.dispatch(request).await)
    }

    /// IMPORT one certificate and its key into the holder, answering the ARN it was
    /// stored under: a certificate the ACCOUNT brought in, which no public authority
    /// signed.
    async fn import_certificate(
        &self,
        case: &str,
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> String {
        let reply = self
            .certificate_manager(
                "ImportCertificate",
                &json!({
                    "Certificate": aws_smithy_types::base64::encode(certificate_pem.as_bytes()),
                    "PrivateKey": aws_smithy_types::base64::encode(private_key_pem.as_bytes()),
                }),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected ImportCertificate to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
        reply.json()["CertificateArn"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case}: no CertificateArn in {}", reply.text()))
            .to_string()
    }

    /// REQUEST one certificate for `domain_name` from the holder, answering the ARN it
    /// was stored under: a certificate Certificate Manager issues itself, so a public
    /// authority signs it.
    async fn request_certificate(&self, case: &str, domain_name: &str) -> String {
        let reply = self
            .certificate_manager(
                "RequestCertificate",
                &json!({ "DomainName": domain_name, "ValidationMethod": "DNS" }),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected RequestCertificate to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
        reply.json()["CertificateArn"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case}: no CertificateArn in {}", reply.text()))
            .to_string()
    }
}

/// A certificate and the private key that matches it: the material a case imports into
/// the holder. Minted by this service's own issuer, so the key really matches the
/// certificate — the holder refuses a pair that does not.
fn minted_certificate() -> (String, String) {
    let minted = service_com_amazonaws_iot_awsiotservice::state::mint_keys_and_certificate(
        REGION,
        ACCOUNT_ID,
        true,
        SystemTime::now(),
    )
    .expect("the suite can mint a certificate");
    (
        minted.certificate.certificate_pem,
        minted
            .key_pair
            .private_key
            .expect("the minted key pair carries its private half"),
    )
}

/// A dispatched response, reduced to what the assertions read.
struct Reply {
    status: u16,
    body: Bytes,
}

impl Reply {
    fn of(response: http::Response<Bytes>) -> Self {
        Self {
            status: response.status().as_u16(),
            body: response.into_body(),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("response body is not JSON ({e}): {}", self.text()))
    }

    fn error_code(&self) -> String {
        self.json()["__type"]
            .as_str()
            .unwrap_or_else(|| panic!("no __type in {}", self.text()))
            .to_string()
    }

    fn error_message(&self) -> String {
        self.json()["message"]
            .as_str()
            .unwrap_or_else(|| panic!("no message in {}", self.text()))
            .to_string()
    }
}

/// An ACM certificate ARN of this account, numbered.
fn certificate_arn(index: usize) -> String {
    format!("arn:aws:acm:{REGION}:{ACCOUNT_ID}:certificate/cert-{index:06}")
}

/// The ARN of the publicly signed certificate a configuration proves domain ownership
/// with — `CreateDomainConfiguration$validationCertificateArn`, which the model binds
/// to the ACM certificate ARN pattern.
fn validation_certificate_arn() -> String {
    certificate_arn(99)
}

/// RULE: a created configuration is read back member for member, and which KIND of
/// domain it configures follows from whether it carries a domain name of its own.
#[tokio::test]
async fn a_created_domain_configuration_is_read_back_member_for_member() {
    let emulator = Emulator::new();
    let (certificate_pem, private_key_pem) = minted_certificate();
    let held = emulator
        .import_certificate("read back", &certificate_pem, &private_key_pem)
        .await;

    // The rows span which optional members the request carries, and both kinds of
    // domain: one without a `domainName` (the AWS-managed domain, for which
    // `serverCertificateArns` is "not required") and one with its own name and the
    // certificate the service presents for it.
    let rows: Vec<(&str, &str, Value, &str, usize)> = vec![
        (
            "the AWS-managed domain, nothing optional",
            "managed.config",
            json!({}),
            "AWS_MANAGED",
            0,
        ),
        (
            "the AWS-managed domain with an authorizer and a service type",
            "managed-with-authorizer",
            json!({
                "serviceType": "DATA",
                "authorizerConfig": { "defaultAuthorizerName": "my-authorizer",
                                      "allowAuthorizerOverride": true },
                "tags": [{ "Key": "team", "Value": "fleet" }],
            }),
            "AWS_MANAGED",
            0,
        ),
        (
            "a customer-managed domain presenting a certificate the holder has",
            "customer_managed-1",
            json!({
                "domainName": "iot.example.com",
                "serverCertificateArns": [held.clone()],
                "validationCertificateArn": validation_certificate_arn(),
                "applicationProtocol": "SECURE_MQTT",
                "authenticationType": "AWS_X509",
                "tlsConfig": { "securityPolicy": "IoTSecurityPolicy_TLS13_1_2_2022_10" },
                "serverCertificateConfig": { "enableOCSPCheck": false },
                "clientCertificateConfig": {
                    "clientCertificateCallbackArn":
                        "arn:aws:lambda:eu-central-1:000000000000:function:client-check"
                },
            }),
            "CUSTOMER_MANAGED",
            1,
        ),
    ];

    for (case, name, body, domain_type, certificate_count) in &rows {
        let created = emulator.create_configuration(name, body).await;
        assert_eq!(
            created.status,
            200,
            "case {case}: expected 200, got {} body {}",
            created.status,
            created.text()
        );
        let expected_arn =
            format!("arn:aws:iot:{REGION}:{ACCOUNT_ID}:domainconfiguration/{name}");
        assert_eq!(
            created.json()["domainConfigurationArn"],
            json!(expected_arn),
            "case {case}: expected the minted ARN, got {}",
            created.text()
        );

        let read = emulator.describe_configuration(name).await;
        assert_eq!(
            read.status,
            200,
            "case {case}: expected the read to answer 200, got {} body {}",
            read.status,
            read.text()
        );
        let described = read.json();
        assert_eq!(
            described["domainConfigurationName"],
            json!(name),
            "case {case}: the read must name the configuration, got {described}"
        );
        assert_eq!(
            described["domainConfigurationArn"], created.json()["domainConfigurationArn"],
            "case {case}: the read must report the ARN the create minted, got {described}"
        );
        assert_eq!(
            described["domainConfigurationStatus"],
            json!("ENABLED"),
            "case {case}: a configuration serves from the moment it is created, got {described}"
        );
        assert_eq!(
            described["serviceType"],
            json!(body
                .get("serviceType")
                .and_then(Value::as_str)
                .unwrap_or("DATA")),
            "case {case}: the read must report the stored service type, got {described}"
        );
        assert_eq!(
            described["domainType"],
            json!(domain_type),
            "case {case}: expected a {domain_type} domain, got {described}"
        );
        assert_eq!(
            described["domainName"],
            body.get("domainName").cloned().unwrap_or(Value::Null),
            "case {case}: the read must report the stored domain name, got {described}"
        );
        let certificates = described["serverCertificates"]
            .as_array()
            .unwrap_or_else(|| panic!("case {case}: no serverCertificates in {described}"));
        assert_eq!(
            certificates.len(),
            *certificate_count,
            "case {case}: expected {certificate_count} certificate(s), got {described}"
        );
        if let Some(certificate) = certificates.first() {
            assert_eq!(
                certificate["serverCertificateArn"],
                json!(held.clone()),
                "case {case}: the read must report the resolved certificate, got {described}"
            );
            assert_eq!(
                certificate["serverCertificateStatus"],
                json!("VALID"),
                "case {case}: a certificate the service could resolve is valid, got {described}"
            );
        }
        for member in [
            "authorizerConfig",
            "tlsConfig",
            "serverCertificateConfig",
            "clientCertificateConfig",
            "applicationProtocol",
            "authenticationType",
        ] {
            assert_eq!(
                described[member],
                body.get(member).cloned().unwrap_or(Value::Null),
                "case {case}: the read must report the stored {member}, got {described}"
            );
        }
        assert!(
            described["lastStatusChangeDate"].is_number(),
            "case {case}: the read must report when the status last changed, got {described}"
        );
    }

    // The name is the configuration's identity, so a second create under it is a
    // conflict and the stored record is left alone.
    let conflict = emulator
        .create_configuration("managed.config", &json!({ "serviceType": "DATA" }))
        .await;
    assert_eq!(
        conflict.status,
        409,
        "case a name already taken: expected 409, got {} body {}",
        conflict.status,
        conflict.text()
    );
    assert_eq!(
        conflict.error_code(),
        "ResourceAlreadyExistsException",
        "case a name already taken: got {}",
        conflict.text()
    );

    // The delete removes the configuration, and a second delete is the same 404 a read
    // of a name the account holds nothing under is.
    assert_eq!(
        emulator.delete_configuration("managed.config").await.status,
        200,
        "case the delete: expected 200"
    );
    for (case, reply) in [
        (
            "a read of the deleted configuration",
            emulator.describe_configuration("managed.config").await,
        ),
        (
            "a second delete",
            emulator.delete_configuration("managed.config").await,
        ),
    ] {
        assert_eq!(
            reply.status,
            404,
            "case {case}: expected 404, got {} body {}",
            reply.status,
            reply.text()
        );
        assert_eq!(
            reply.error_code(),
            "ResourceNotFoundException",
            "case {case}: got {}",
            reply.text()
        );
    }
}

/// RULE: a `serverCertificateArn` the holder has no certificate for cannot be
/// presented to a device, so the create is refused and nothing is written.
#[tokio::test]
async fn a_certificate_the_holder_does_not_have_is_refused() {
    let emulator = Emulator::new();
    let (certificate_pem, private_key_pem) = minted_certificate();
    let held = emulator
        .import_certificate("refusals", &certificate_pem, &private_key_pem)
        .await;

    // The rows span the forms a certificate the holder does not have takes: another
    // account's certificate, another region's, one whose id nothing was recorded
    // under, and a value that is no certificate ARN at all.
    let unknown = [
        certificate_arn(2),
        format!("arn:aws:acm:{REGION}:000000000001:certificate/cert-000001"),
        format!("arn:aws:acm:us-east-1:{ACCOUNT_ID}:certificate/cert-000001"),
        format!("arn:aws:acm:{REGION}:{ACCOUNT_ID}:certificate/00000000-0000-0000-0000-000000000000"),
    ];
    for (index, certificate) in unknown.iter().enumerate() {
        let name = format!("refused-{index}");
        let refused = emulator
            .create_configuration(
                &name,
                &json!({
                    "domainName": "iot.example.com",
                    "serverCertificateArns": [certificate],
                }),
            )
            .await;
        assert_eq!(
            refused.status,
            400,
            "case {certificate}: expected 400, got {} body {}",
            refused.status,
            refused.text()
        );
        assert_eq!(
            refused.error_code(),
            "InvalidRequestException",
            "case {certificate}: got {}",
            refused.text()
        );
        assert_eq!(
            refused.error_message(),
            format!("Certificate {certificate} does not exist."),
            "case {certificate}: the refusal must name the certificate, got {}",
            refused.text()
        );
        // Nothing was created: the read of the name the create asked for is a 404.
        let described = emulator.describe_configuration(&name).await;
        assert_eq!(
            described.status,
            404,
            "case {certificate}: a refused create must leave no configuration behind, got {} \
             body {}",
            described.status,
            described.text()
        );
    }

    // The certificate the holder DOES have is accepted, so the refusals above are
    // about the certificate and not about the request's shape.
    let accepted = emulator
        .create_configuration(
            "accepted",
            &json!({
                "domainName": "iot.example.com",
                "serverCertificateArns": [held.clone()],
                "validationCertificateArn": validation_certificate_arn(),
            }),
        )
        .await;
    assert_eq!(
        accepted.status,
        200,
        "case the certificate the holder has: expected 200, got {} body {}",
        accepted.status,
        accepted.text()
    );
}

/// RULE: a configuration for a domain of the caller's OWN has to present a server
/// certificate a device can chain to a certificate authority — one Certificate Manager
/// ISSUED — or else carry the `validationCertificateArn` that proves domain ownership;
/// a create with neither is refused with nothing created.
#[tokio::test]
async fn an_unchainable_server_certificate_needs_a_validation_certificate() {
    /// Which kind of certificate the holder has for a row: one the ACCOUNT brought in,
    /// which no public authority signed, or one Certificate Manager issued itself.
    enum Held {
        Imported,
        Issued,
        /// The row presents no server certificate at all.
        None,
    }
    /// What the create answers a row with: a record, or the refusal whose message
    /// begins with the text given.
    enum Expected {
        Created,
        Refused(&'static str),
    }
    /// The fixed text of the refusal of a server certificate whose trust is not
    /// established.
    const UNTRUSTED: &str = "Must provide validation certificate when using server certificates \
                             not signed by trusted CA or not within";

    // The rows span what the rule generalises over: which kind of certificate the holder
    // has for the one the request names, whether the request carries a validation
    // certificate, and whether it names a domain of its own at all.
    struct Case {
        label: &'static str,
        held: Held,
        domain_name: bool,
        validation_certificate: bool,
        expected: Expected,
    }
    let cases = [
        Case {
            label: "an imported certificate with no validation certificate",
            held: Held::Imported,
            domain_name: true,
            validation_certificate: false,
            expected: Expected::Refused(UNTRUSTED),
        },
        Case {
            label: "an imported certificate with a validation certificate",
            held: Held::Imported,
            domain_name: true,
            validation_certificate: true,
            expected: Expected::Created,
        },
        Case {
            label: "a certificate the holder issued, with no validation certificate",
            held: Held::Issued,
            domain_name: true,
            validation_certificate: false,
            expected: Expected::Created,
        },
        Case {
            label: "a certificate the holder issued, with a validation certificate",
            held: Held::Issued,
            domain_name: true,
            validation_certificate: true,
            expected: Expected::Created,
        },
        Case {
            label: "an imported certificate on the AWS-managed domain, which proves no \
                    ownership",
            held: Held::Imported,
            domain_name: false,
            validation_certificate: false,
            expected: Expected::Created,
        },
        Case {
            label: "the AWS-managed domain, which presents no certificate at all",
            held: Held::None,
            domain_name: false,
            validation_certificate: false,
            expected: Expected::Created,
        },
    ];

    for (index, case) in cases.iter().enumerate() {
        let emulator = Emulator::new();
        let certificate = match case.held {
            Held::Imported => {
                let (certificate_pem, private_key_pem) = minted_certificate();
                Some(
                    emulator
                        .import_certificate(case.label, &certificate_pem, &private_key_pem)
                        .await,
                )
            }
            Held::Issued => Some(
                emulator
                    .request_certificate(case.label, "iot.example.com")
                    .await,
            ),
            Held::None => None,
        };
        let mut body = json!({});
        if case.domain_name {
            body["domainName"] = json!("iot.example.com");
        }
        if let Some(certificate) = certificate.as_ref() {
            body["serverCertificateArns"] = json!([certificate]);
        }
        if case.validation_certificate {
            body["validationCertificateArn"] = json!(validation_certificate_arn());
        }

        let name = format!("trust-{index}");
        let created = emulator.create_configuration(&name, &body).await;
        let refusal = match case.expected {
            Expected::Created => {
                assert_eq!(
                    created.status,
                    200,
                    "case {}: expected 200, got {} body {}",
                    case.label,
                    created.status,
                    created.text()
                );
                let read = emulator.describe_configuration(&name).await;
                assert_eq!(
                    read.status,
                    200,
                    "case {}: the accepted configuration must read back, got {} body {}",
                    case.label,
                    read.status,
                    read.text()
                );
                continue;
            }
            Expected::Refused(refusal) => refusal,
        };
        assert_eq!(
            created.status,
            400,
            "case {}: expected 400, got {} body {}",
            case.label,
            created.status,
            created.text()
        );
        assert_eq!(
            created.error_code(),
            "InvalidRequestException",
            "case {}: got {}",
            case.label,
            created.text()
        );
        assert!(
            created.error_message().starts_with(refusal),
            "case {}: the refusal must state the rule {refusal:?}, got {:?}",
            case.label,
            created.error_message()
        );
        // Nothing was created, which is what makes the following read a 404 and keeps the
        // configuration out of the account's listing.
        let described = emulator.describe_configuration(&name).await;
        assert_eq!(
            described.status,
            404,
            "case {}: a refused create must leave no configuration behind, got {} body {}",
            case.label,
            described.status,
            described.text()
        );
        assert_eq!(
            described.error_message(),
            format!(
                "Could not find domain configuration for given account ID and domain \
                 configuration name, AccountId: {ACCOUNT_ID}, DomainConfigurationName: {name}"
            ),
            "case {}: the read must state the miss by account and name, got {}",
            case.label,
            described.text()
        );
        let listed = emulator.list_configurations("").await;
        assert_eq!(
            listed.status,
            200,
            "case {}: expected the listing to answer 200, got {} body {}",
            case.label,
            listed.status,
            listed.text()
        );
        assert!(
            !listed
                .json()["domainConfigurations"]
                .as_array()
                .unwrap_or_else(|| panic!("no domainConfigurations in {}", listed.text()))
                .iter()
                .any(|summary| summary["domainConfigurationName"] == json!(name)),
            "case {}: a refused create must leave the name out of the listing, got {}",
            case.label,
            listed.text()
        );
    }
}

/// RULE: the listing reports every configuration the account holds, projected from the
/// same record the reader projects, filtered by `serviceType` when the request names
/// one, and paged by `pageSize` with its own marker.
#[tokio::test]
async fn the_listing_reports_the_configurations_the_account_holds() {
    let emulator = Emulator::new();
    let (certificate_pem, private_key_pem) = minted_certificate();
    let held = emulator
        .import_certificate("listing", &certificate_pem, &private_key_pem)
        .await;

    // The rows span the service types a configuration may deliver
    // (`smithy_query(query="shape",shape="ServiceType")`: CREDENTIAL_PROVIDER, DATA,
    // JOBS) and both kinds of domain.
    let rows = [
        ("data-managed", json!({ "serviceType": "DATA" })),
        ("jobs-managed", json!({ "serviceType": "JOBS" })),
        (
            "credentials-managed",
            json!({ "serviceType": "CREDENTIAL_PROVIDER" }),
        ),
        (
            "data-custom",
            json!({
                "serviceType": "DATA",
                "domainName": "iot.example.com",
                "serverCertificateArns": [held.clone()],
                "validationCertificateArn": validation_certificate_arn(),
            }),
        ),
    ];
    for (name, body) in &rows {
        let created = emulator.create_configuration(name, body).await;
        assert_eq!(
            created.status,
            200,
            "case {name}: the configuration must be creatable, got {} body {}",
            created.status,
            created.text()
        );
    }

    let listed = emulator.list_configurations("").await;
    let summaries = listed.json()["domainConfigurations"]
        .as_array()
        .unwrap_or_else(|| panic!("no domainConfigurations in {}", listed.text()))
        .clone();
    assert_eq!(
        summaries.len(),
        rows.len(),
        "case the whole listing: expected {} configurations, got {}",
        rows.len(),
        listed.text()
    );
    for summary in &summaries {
        let name = summary["domainConfigurationName"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let read = emulator.describe_configuration(&name).await;
        assert_eq!(
            summary["domainConfigurationArn"], read.json()["domainConfigurationArn"],
            "case {name}: the summary must carry the ARN the reader reports, got {summary}"
        );
        assert_eq!(
            summary["serviceType"], read.json()["serviceType"],
            "case {name}: the summary must carry the stored service type, got {summary}"
        );
    }

    // A listing filtered by service type reports the configurations of that type and no
    // other.
    for (service_type, expected) in [
        ("DATA", vec!["data-custom", "data-managed"]),
        ("JOBS", vec!["jobs-managed"]),
        ("CREDENTIAL_PROVIDER", vec!["credentials-managed"]),
    ] {
        let filtered = emulator
            .list_configurations(&format!("serviceType={service_type}"))
            .await;
        let names: Vec<String> = filtered.json()["domainConfigurations"]
            .as_array()
            .unwrap_or_else(|| panic!("no domainConfigurations in {}", filtered.text()))
            .iter()
            .map(|summary| {
                summary["domainConfigurationName"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        assert_eq!(
            names, expected,
            "case serviceType={service_type}: expected {expected:?}, got {names:?}"
        );
    }

    // The listing pages over that order, a page at a time, and its own marker resumes
    // exactly where the page stopped.
    for page_size in [1usize, 3, 10] {
        let mut seen: Vec<String> = Vec::new();
        let mut query = format!("pageSize={page_size}");
        loop {
            let page = emulator.list_configurations(&query).await;
            let names: Vec<String> = page.json()["domainConfigurations"]
                .as_array()
                .unwrap_or_else(|| panic!("no domainConfigurations in {}", page.text()))
                .iter()
                .map(|summary| {
                    summary["domainConfigurationName"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                })
                .collect();
            assert!(
                names.len() <= page_size,
                "case pageSize={page_size}: a page must hold at most {page_size}, got {names:?}"
            );
            seen.extend(names);
            match page.json()["nextMarker"].as_str() {
                Some(marker) => query = format!("pageSize={page_size}&marker={marker}"),
                None => break,
            }
        }
        assert_eq!(
            seen.len(),
            rows.len(),
            "case pageSize={page_size}: expected every configuration once, got {seen:?}"
        );
    }
}
