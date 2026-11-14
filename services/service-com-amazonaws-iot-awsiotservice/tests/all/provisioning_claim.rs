// SPDX-License-Identifier: CC0-1.0

//! End-to-end HTTP coverage of `CreateProvisioningClaim`: the temporary certificate a
//! device is given to run a fleet provisioning template, and the refusal of a template
//! the account does not hold.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` over a
//! restJson1 request signed for the `iot` signing name — so what is asserted is what an
//! AWS SDK client would see, not an internal function's return value.
//!
//! The rules under test:
//!
//! * a claim is issued for an EXISTING provisioning template: the response carries a
//!   real certificate and the key pair for it, the certificate is on record under the id
//!   reported — `DescribeCertificate` reads it back — and its validity ends at the
//!   `expiration` reported, since a claim certificate is temporary;
//! * a `templateName` the account holds no template under is
//!   `ResourceNotFoundException` (404) and nothing is issued.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Value};
use service_com_amazonaws_iot_awsiotservice::state::PROVISIONING_CLAIM_VALIDITY;
use service_com_amazonaws_iot_awsiotservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;

/// The region this suite signs for.
const REGION: &str = "ap-south-1";

/// The role a provisioning template provisions under, of more than the modelled minimum
/// length (`RoleArn`, len 20..2048).
const PROVISIONING_ROLE: &str = "arn:aws:iam::123456789012:role/fleet-provisioning";

/// One emulator: a router with this service mounted on its own engine.
struct Emulator {
    router: MultiServiceRouter,
}

impl Emulator {
    fn new() -> Self {
        let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
        let mut router = MultiServiceRouter::new();
        router.set_request_authentication(false);
        router.register_service(EmulatedService::new(engine));
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
            .expect("the provisioning-claim request is well formed");
        Reply::of(self.router.dispatch(request).await)
    }

    async fn create_template(&self, case: &str, template_name: &str, enabled: bool) {
        let reply = self
            .dispatch(
                "POST",
                "/provisioning-templates",
                Some(&json!({
                    "templateName": template_name,
                    "templateBody": template_body(),
                    "provisioningRoleArn": PROVISIONING_ROLE,
                    "enabled": enabled,
                })),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "case {case}: expected CreateProvisioningTemplate to answer 200, got {} body {}",
            reply.status,
            reply.text()
        );
    }

    async fn create_claim(&self, template_name: &str) -> Reply {
        self.dispatch(
            "POST",
            &format!("/provisioning-templates/{template_name}/provisioning-claim"),
            None,
        )
        .await
    }

    async fn describe_certificate(&self, certificate_id: &str) -> Reply {
        self.dispatch("GET", &format!("/certificates/{certificate_id}"), None)
            .await
    }
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

/// A provisioning template body: the one resource a provisioned device gets.
fn template_body() -> String {
    json!({
        "Parameters": { "SerialNumber": { "Type": "String" } },
        "Resources": {
            "thing": {
                "Type": "AWS::IoT::Thing",
                "Properties": { "ThingName": "device-1" },
            },
        },
    })
    .to_string()
}

/// RULE: a claim for a template the account holds is a real certificate and key pair,
/// on record under the id reported and valid until the expiration reported.
#[tokio::test]
async fn a_claim_is_issued_for_a_template_the_account_holds() {
    // The rows span what the rule generalises over: whether the template is enabled, and
    // the form of its name (the modelled `TemplateName` pattern admits letters, digits,
    // `_` and `-`).
    let cases = [
        ("an enabled template", "fleet-template", true),
        ("a template that is not enabled", "disabled_template_1", false),
    ];

    for (label, template_name, enabled) in cases {
        let emulator = Emulator::new();
        emulator.create_template(label, template_name, enabled).await;

        let claim = emulator.create_claim(template_name).await;
        assert_eq!(
            claim.status,
            200,
            "case {label}: expected 200, got {} body {}",
            claim.status,
            claim.text()
        );
        let body = claim.json();
        let certificate_id = body["certificateId"]
            .as_str()
            .unwrap_or_else(|| panic!("case {label}: no certificateId in {}", claim.text()))
            .to_string();
        assert_eq!(
            certificate_id.len(),
            64,
            "case {label}: the id must be the modelled 64-character one, got {certificate_id}"
        );
        assert!(
            body["certificatePem"]
                .as_str()
                .is_some_and(|pem| pem.contains("BEGIN CERTIFICATE")),
            "case {label}: expected a PEM certificate, got {}",
            claim.text()
        );
        assert!(
            body["keyPair"]["PrivateKey"]
                .as_str()
                .is_some_and(|key| key.contains("PRIVATE KEY")),
            "case {label}: expected the claim's private key, got {}",
            claim.text()
        );
        assert!(
            body["keyPair"]["PublicKey"]
                .as_str()
                .is_some_and(|key| key.contains("PUBLIC KEY")),
            "case {label}: expected the claim's public key, got {}",
            claim.text()
        );
        let expiration = body["expiration"]
            .as_f64()
            .unwrap_or_else(|| panic!("case {label}: no expiration in {}", claim.text()));

        // The certificate is ON RECORD under the id reported, and the validity it holds
        // ends exactly at the expiration this response reported — a claim certificate is
        // temporary, so the two are one instant.
        let described = emulator.describe_certificate(&certificate_id).await;
        assert_eq!(
            described.status,
            200,
            "case {label}: expected the claim certificate to read back, got {} body {}",
            described.status,
            described.text()
        );
        let description = described.json();
        assert_eq!(
            description["certificateDescription"]["certificateId"],
            json!(certificate_id),
            "case {label}: the read must report the issued id, got {}",
            described.text()
        );
        let not_after = description["certificateDescription"]["validity"]["notAfter"]
            .as_f64()
            .unwrap_or_else(|| panic!("case {label}: no notAfter in {}", described.text()));
        assert!(
            (not_after - expiration).abs() < 1.0,
            "case {label}: expected the certificate to expire at the reported expiration \
             {expiration}, got {not_after}"
        );
        let not_before = description["certificateDescription"]["validity"]["notBefore"]
            .as_f64()
            .unwrap_or_else(|| panic!("case {label}: no notBefore in {}", described.text()));
        let validity = not_after - not_before;
        assert!(
            (validity - PROVISIONING_CLAIM_VALIDITY.as_secs_f64()).abs() < 1.0,
            "case {label}: expected a claim valid for {}s, got {validity}s",
            PROVISIONING_CLAIM_VALIDITY.as_secs()
        );

        // Two claims for one template are two certificates: each call issues its own.
        let second = emulator.create_claim(template_name).await;
        assert_eq!(
            second.status,
            200,
            "case {label}: expected a second claim to answer 200, got {} body {}",
            second.status,
            second.text()
        );
        assert_ne!(
            second.json()["certificateId"],
            json!(certificate_id),
            "case {label}: each claim must be its own certificate, got {}",
            second.text()
        );
    }
}

/// RULE: a `templateName` the account holds no template under is refused and nothing is
/// issued.
#[tokio::test]
async fn a_claim_for_a_template_the_account_does_not_hold_is_refused() {
    let emulator = Emulator::new();
    emulator.create_template("setup", "fleet-template", true).await;

    // The rows span the forms a name the account holds no template under takes: one
    // never created, one differing only in case, and one whose template was deleted.
    let deleted = "gone-template";
    emulator.create_template("setup", deleted, true).await;
    let removed = emulator
        .dispatch(
            "DELETE",
            &format!("/provisioning-templates/{deleted}"),
            None,
        )
        .await;
    assert_eq!(
        removed.status,
        200,
        "case the deleted template: the delete must succeed, got {} body {}",
        removed.status,
        removed.text()
    );

    for template_name in ["absent-template", "FLEET-TEMPLATE", deleted] {
        let refused = emulator.create_claim(template_name).await;
        assert_eq!(
            refused.status,
            404,
            "case {template_name}: expected 404, got {} body {}",
            refused.status,
            refused.text()
        );
        assert_eq!(
            refused.error_code(),
            "ResourceNotFoundException",
            "case {template_name}: got {}",
            refused.text()
        );
        assert_eq!(
            refused.error_message(),
            format!("Unable to find template named {template_name}"),
            "case {template_name}: the refusal must name the template, got {}",
            refused.text()
        );
    }
}
