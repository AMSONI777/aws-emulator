// SPDX-License-Identifier: CC0-1.0

//! A pool's per-factor MFA configuration is a value, stored as sent and read back.
//!
//! The rule under test: `SetUserPoolMfaConfig` stores the per-factor configuration
//! blocks the request carries — including a software-token block that is carried
//! and DE-ACTIVATED — independently of the mode it leaves the pool in, and
//! `GetUserPoolMfaConfig` projects that stored configuration. The one place the mode
//! constrains the factors is `MfaConfiguration` = `ON`, under which "all users must
//! set up MFA before they can sign in" (`MfaConfiguration` in this service's model),
//! so such a pool takes at least one activated factor; every other combination of
//! the mode and the blocks is stored, echoed and projected as sent, in both
//! directions and however often it is re-applied.
//!
//! The table spans the modes `UserPoolMfaType` admits, the forms a
//! `SoftwareTokenMfaConfigType` can arrive in (left out, carried with `Enabled`
//! omitted so the member's modelled default applies, and carried with each of its
//! two values), and whether the email-message and passkey blocks accompany it. Rows
//! that would ask a pool to REQUIRE a challenge it could never present are the one
//! combination the rule excludes, so they are not in this table; the refusal they
//! get is pinned in `user_pool_mfa_posture_rewrite`.
//!
//! Each row runs against a pool first driven to a fully activated posture, so a
//! handler that latched the activation on, or stored nothing, fails the row rather
//! than passing it by accident. Each assertion names its case and reports the actual
//! value.

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;
use std::sync::Arc;

/// A request's SigV4 credential scope is what routes it to this service. The
/// signature is never checked here: the suite turns request authentication off.
const AUTHORIZATION: &str = "AWS4-HMAC-SHA256 \
     Credential=AKIDEXAMPLE/20260101/us-east-1/cognito-idp/aws4_request, \
     SignedHeaders=host;x-amz-date, Signature=0000";

/// One emulator with just this service mounted.
fn router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.register_service(
        service_com_amazonaws_cognitoidentityprovider_awscognitoidentityproviderservice::EmulatedService::new(engine),
    );
    router.set_request_authentication(false);
    router
}

/// Call `operation` with `body` and return its status and JSON response body.
async fn call(router: &MultiServiceRouter, operation: &str, body: &Value) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", "cognito-idp.us-east-1.amazonaws.com")
        .header("content-type", "application/x-amz-json-1.1")
        .header(
            "x-amz-target",
            format!("AWSCognitoIdentityProviderService.{operation}"),
        )
        .header("authorization", AUTHORIZATION)
        .body(Bytes::from(body.to_string()))
        .expect("the request is well formed");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).unwrap_or_else(|error| {
            panic!(
                "{operation} answered a body that is not JSON ({error}): {:?}",
                String::from_utf8_lossy(response.body())
            )
        })
    };
    (status, payload)
}

/// Call `operation`, requiring success, and return its response body.
async fn ok(router: &MultiServiceRouter, case: &str, operation: &str, body: &Value) -> Value {
    let (status, payload) = call(router, operation, body).await;
    assert_eq!(
        status, 200,
        "case {case:?}: {operation} must succeed, expected 200, got {status} with {payload}"
    );
    payload
}

/// A freshly created pool's id.
async fn pool(router: &MultiServiceRouter, case: &str) -> String {
    let created = ok(
        router,
        case,
        "CreateUserPool",
        &json!({ "PoolName": "mfa-factor-pool" }),
    )
    .await;
    created["UserPool"]["Id"]
        .as_str()
        .unwrap_or_else(|| panic!("case {case:?}: a minted pool id: {created}"))
        .to_string()
}

/// The configuration `GetUserPoolMfaConfig` reports for `user_pool_id`.
async fn read_back(router: &MultiServiceRouter, case: &str, user_pool_id: &str) -> Value {
    ok(
        router,
        case,
        "GetUserPoolMfaConfig",
        &json!({ "UserPoolId": user_pool_id }),
    )
    .await
}

/// The email-message MFA block, whose `Message` carries the `{####}` placeholder
/// `EmailMfaConfigType.Message` requires.
fn email_block() -> Value {
    json!({ "Message": "Your sign-in code is {####}", "Subject": "Your sign-in code" })
}

/// The passkey block, naming only the relying party.
fn web_authn_block() -> Value {
    json!({ "RelyingPartyId": "auth.example.com" })
}

/// Every factor activated and MFA required: the posture each row starts from, so a
/// row that de-activates something has something to de-activate.
fn fully_activated(user_pool_id: &str) -> Value {
    json!({
        "UserPoolId": user_pool_id,
        "MfaConfiguration": "ON",
        "SoftwareTokenMfaConfiguration": { "Enabled": true },
        "EmailMfaConfiguration": email_block(),
        "WebAuthnConfiguration": web_authn_block(),
    })
}

/// One row: the mode and the per-factor blocks a `SetUserPoolMfaConfig` request
/// carries, and the software-token activation state the pool must report back
/// (`None` when the request carries no software-token block at all).
struct FactorCase {
    case: String,
    mode: &'static str,
    software_token: Option<Value>,
    email: Option<Value>,
    web_authn: Option<Value>,
    expected_enabled: Option<bool>,
}

impl FactorCase {
    /// This row as a `SetUserPoolMfaConfig` request against `user_pool_id`.
    fn request(&self, user_pool_id: &str) -> Value {
        let mut request = json!({
            "UserPoolId": user_pool_id,
            "MfaConfiguration": self.mode,
        });
        if let Some(software_token) = &self.software_token {
            request["SoftwareTokenMfaConfiguration"] = software_token.clone();
        }
        if let Some(email) = &self.email {
            request["EmailMfaConfiguration"] = email.clone();
        }
        if let Some(web_authn) = &self.web_authn {
            request["WebAuthnConfiguration"] = web_authn.clone();
        }
        request
    }
}

/// The table: every mode `UserPoolMfaType` admits crossed with every form the
/// software-token block arrives in and with the presence of the email-message and
/// passkey blocks, minus the rows that would require MFA with no activated factor.
fn factor_cases() -> Vec<FactorCase> {
    // `UserPoolMfaType` is an enum of OFF | ON | OPTIONAL (this service's model).
    let modes = ["OFF", "ON", "OPTIONAL"];
    // `SoftwareTokenMfaConfigType` has one member, `Enabled`, "the activation state
    // of TOTP MFA", modelled with a default of false (this service's model) — so a
    // block carrying no `Enabled` is a de-activated factor too.
    let software_tokens = [
        ("no TOTP block", None, None),
        ("a TOTP block defaulting to off", Some(json!({})), Some(false)),
        (
            "TOTP switched off",
            Some(json!({ "Enabled": false })),
            Some(false),
        ),
        (
            "TOTP switched on",
            Some(json!({ "Enabled": true })),
            Some(true),
        ),
    ];
    let emails = [("no email OTP", None), ("email OTP", Some(email_block()))];
    let passkeys = [
        ("no passkeys", None),
        ("passkeys", Some(web_authn_block())),
    ];

    let mut cases = Vec::new();
    for mode in modes {
        for (token_label, software_token, expected_enabled) in &software_tokens {
            for (email_label, email) in &emails {
                for (passkey_label, web_authn) in &passkeys {
                    // Requiring MFA takes an activated factor to challenge with:
                    // TOTP switched on, or email OTP. Passkeys are not one of the
                    // factors an MFA challenge is presented over, so a row that
                    // offers only them is excluded from `ON` as well.
                    let activates_a_factor = *expected_enabled == Some(true) || email.is_some();
                    if mode == "ON" && !activates_a_factor {
                        continue;
                    }
                    cases.push(FactorCase {
                        case: format!(
                            "MfaConfiguration {mode} with {token_label}, {email_label}, \
                             {passkey_label}"
                        ),
                        mode,
                        software_token: software_token.clone(),
                        email: email.clone(),
                        web_authn: web_authn.clone(),
                        expected_enabled: *expected_enabled,
                    });
                }
            }
        }
    }
    cases
}

#[tokio::test]
async fn every_factor_combination_is_stored_as_sent_and_projected_back() {
    let router = router();
    // One pool carries the whole table: each row re-establishes the posture it
    // starts from, so the stored configuration depends on the request rather than on
    // what the pool happened to hold before it.
    let user_pool_id = pool(&router, "the table's pool").await;

    for case in factor_cases() {
        let label = case.case.as_str();
        ok(
            &router,
            label,
            "SetUserPoolMfaConfig",
            &fully_activated(&user_pool_id),
        )
        .await;

        let request = case.request(&user_pool_id);
        let (status, answered) = call(&router, "SetUserPoolMfaConfig", &request).await;
        assert_eq!(
            status, 200,
            "case {label:?}: the write must be accepted, expected 200, got {status} with \
             {answered}"
        );
        assert_eq!(
            answered["MfaConfiguration"],
            json!(case.mode),
            "case {label:?}: expected the stored mode {:?}, got {answered}",
            case.mode
        );
        match case.expected_enabled {
            Some(enabled) => assert_eq!(
                answered["SoftwareTokenMfaConfiguration"],
                json!({ "Enabled": enabled }),
                "case {label:?}: expected the stored TOTP activation state {enabled}, got \
                 {answered}"
            ),
            None => assert!(
                answered.get("SoftwareTokenMfaConfiguration").is_none(),
                "case {label:?}: a request carrying no TOTP block leaves the pool offering no \
                 TOTP, got {answered}"
            ),
        }
        assert_eq!(
            answered.get("EmailMfaConfiguration").is_some(),
            case.email.is_some(),
            "case {label:?}: expected the email OTP block to be stored = {}, got {answered}",
            case.email.is_some()
        );
        assert_eq!(
            answered.get("WebAuthnConfiguration").is_some(),
            case.web_authn.is_some(),
            "case {label:?}: expected the passkey block to be stored = {}, got {answered}",
            case.web_authn.is_some()
        );

        let read = read_back(&router, label, &user_pool_id).await;
        assert_eq!(
            read, answered,
            "case {label:?}: expected the read to project {answered}, got {read}"
        );

        // The read reports the configuration; it does not change it.
        let again = read_back(&router, label, &user_pool_id).await;
        assert_eq!(
            again, read,
            "case {label:?}: expected a second read to project {read}, got {again}"
        );

        // Setting the same configuration again lands on the same configuration.
        let reapplied = ok(&router, label, "SetUserPoolMfaConfig", &request).await;
        assert_eq!(
            reapplied, answered,
            "case {label:?}: expected re-applying the same request to echo {answered}, got \
             {reapplied}"
        );
    }
}

#[tokio::test]
async fn de_activating_a_factor_does_not_need_the_mode_to_move() {
    let router = router();
    let case = "the mode held at OPTIONAL while TOTP is toggled";
    let user_pool_id = pool(&router, case).await;

    // The mode and the factors are independent values: the mode stays where it was
    // put while the software-token factor is activated and de-activated under it,
    // and every step is observable through the read.
    for enabled in [true, false, false, true, false] {
        let request = json!({
            "UserPoolId": user_pool_id,
            "MfaConfiguration": "OPTIONAL",
            "SoftwareTokenMfaConfiguration": { "Enabled": enabled },
        });
        let answered = ok(&router, case, "SetUserPoolMfaConfig", &request).await;
        let expected = json!({
            "MfaConfiguration": "OPTIONAL",
            "SoftwareTokenMfaConfiguration": { "Enabled": enabled },
        });
        assert_eq!(
            answered, expected,
            "case {case:?}: expected the write to echo {expected}, got {answered}"
        );
        let read = read_back(&router, case, &user_pool_id).await;
        assert_eq!(
            read, expected,
            "case {case:?}: expected the read to project {expected}, got {read}"
        );
    }
}
