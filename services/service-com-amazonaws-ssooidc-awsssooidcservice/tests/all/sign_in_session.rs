// SPDX-License-Identifier: CC0-1.0

//! The sign-in session a token belongs to, and what ending that session ends.
//!
//! RULE: every token this mint issues belongs to a sign-in session — a session of its own
//! when the grant spent is the user's own authentication (the device authorization they
//! approved at the access portal), and the session the grant already belongs to when the
//! grant is itself a token of one (a refresh token being rotated, an access token a token
//! exchange is built on, neither of which authenticates the user again). Ending a sign-in
//! session therefore ends EVERY token of it at once, and leaves every other session whole.
//!
//! Invalidating a sign-in session is not an operation of this API — IAM Identity Center's
//! own `Logout` is what makes that call — so, like the user's approval at the verification
//! page, it is driven through this service's own state. Everything that can be observed on
//! the wire is: each grant is spent through the router the production emulator serves.

use serde_json::json;

use service_com_amazonaws_ssooidc_awsssooidcservice as ssooidc;
use ssooidc::state::{
    DESCRIPTION_INVALID_REFRESH_TOKEN, DESCRIPTION_INVALID_SUBJECT_TOKEN,
    GRANT_TYPE_REFRESH_TOKEN, GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_URI_ACCESS_TOKEN,
};

use super::device_authorization_flow::{
    assert_failure, device_flow_token, text, Emulator, REGION,
};

/// One pair of tokens the mint handed out: the access token, and the refresh token beside
/// it when the grant minted one.
struct TokenPair {
    access_token: String,
    refresh_token: Option<String>,
}

/// Whether the store still holds `pair`'s access token, and its refresh token.
fn held(emulator: &Emulator, pair: &TokenPair) -> (bool, bool) {
    let store = emulator.state();
    let store = store.lock();
    (
        store.access_tokens.contains_key(&pair.access_token),
        pair.refresh_token
            .as_ref()
            .is_some_and(|refresh_token| store.refresh_tokens.contains_key(refresh_token)),
    )
}

/// Walk the device flow for a fresh registration and answer the registration and the pair
/// the exchange of the device code minted: one sign-in session, begun by the user's own
/// authentication.
async fn begun_sign_in(emulator: &Emulator, client_name: &str) -> (String, String, TokenPair) {
    let (client_id, client_secret) = emulator
        .registered_client(json!({"clientName": client_name}))
        .await;
    let token = device_flow_token(emulator, &client_id, &client_secret).await;
    let pair = TokenPair {
        access_token: text(&token, "accessToken"),
        refresh_token: Some(text(&token, "refreshToken")),
    };
    (client_id, client_secret, pair)
}

/// Spend `pair`'s refresh token on the wire and answer the pair the rotation issued.
async fn rotated(
    emulator: &Emulator,
    client_id: &str,
    client_secret: &str,
    pair: &TokenPair,
) -> TokenPair {
    let (status, body) = emulator
        .create_token(&json!({
            "clientId": client_id,
            "clientSecret": client_secret,
            "grantType": GRANT_TYPE_REFRESH_TOKEN,
            "refreshToken": pair.refresh_token.as_ref().expect("the pair carries a refresh token"),
        }))
        .await;
    assert_eq!(status, 200, "the refresh-token grant answered {body}");
    TokenPair {
        access_token: text(&body, "accessToken"),
        refresh_token: Some(text(&body, "refreshToken")),
    }
}

/// RULE (above): ending a sign-in session ends every token of it — the pair it was begun
/// with, every pair a rotation of that grant put in their place, and a token exchanged for
/// one of them — while another session of the same registration is untouched.
///
/// The rows differ in how far the session's chain had been rotated when it ended, which is
/// what the rule generalises over: the session is the same one at every link of it.
#[tokio::test]
async fn ending_a_sign_in_session_ends_every_token_of_it() {
    for rotations in [0_usize, 1, 2] {
        let case = format!("{rotations} rotation(s) before the session ended");
        let emulator = Emulator::new();
        let (client_id, client_secret, begun) =
            begun_sign_in(&emulator, "emulator-test-ended").await;
        let mut session = vec![begun];
        for _ in 0..rotations {
            let current = session.last().expect("the session carries a pair");
            let next = rotated(&emulator, &client_id, &client_secret, current).await;
            session.push(next);
        }

        // The other way a token of a session already on record is handed out: an exchange,
        // which is made by another application ("the subject token must be an access token
        // issued by IAM Identity Center to a different client or application").
        let (other_application, _) = emulator
            .registered_client(json!({"clientName": "emulator-test-exchange"}))
            .await;
        let current = session.last().expect("the session carries a pair");
        let (status, body) = emulator
            .post(
                "/token?aws_iam=t",
                REGION,
                &json!({
                    "clientId": other_application,
                    "grantType": GRANT_TYPE_TOKEN_EXCHANGE,
                    "subjectToken": current.access_token,
                    "subjectTokenType": TOKEN_TYPE_URI_ACCESS_TOKEN,
                }),
            )
            .await;
        assert_eq!(
            status, 200,
            "case {case:?}: the token exchange answered {body}"
        );
        session.push(TokenPair {
            access_token: text(&body, "accessToken"),
            refresh_token: None,
        });

        // A second sign-in of the SAME registration, rotated once: what ends is one
        // session, not a registration's tokens.
        let other = device_flow_token(&emulator, &client_id, &client_secret).await;
        let other = TokenPair {
            access_token: text(&other, "accessToken"),
            refresh_token: Some(text(&other, "refreshToken")),
        };
        let other = rotated(&emulator, &client_id, &client_secret, &other).await;

        let spent = session.last().expect("the session carries a pair");
        let spent_access_token = spent.access_token.clone();
        let spent_refresh_token = session
            .iter()
            .rev()
            .find_map(|pair| pair.refresh_token.clone())
            .expect("the session carries a refresh token");
        assert!(
            emulator
                .state()
                .lock()
                .end_sign_in_session(&spent_access_token),
            "case {case:?}: the mint must hold the token whose session is ending"
        );

        for (link, pair) in session.iter().enumerate() {
            assert_eq!(
                held(&emulator, pair),
                (false, false),
                "case {case:?}: no token of the ended session may still be held (link {link})"
            );
        }
        assert_eq!(
            held(&emulator, &other),
            (true, true),
            "case {case:?}: the other session's own tokens must be untouched"
        );

        // On the wire: the ended session's grant resolves to nothing, and the other
        // session's still rotates.
        let (status, body) = emulator
            .create_token(&json!({
                "clientId": client_id,
                "clientSecret": client_secret,
                "grantType": GRANT_TYPE_REFRESH_TOKEN,
                "refreshToken": spent_refresh_token,
            }))
            .await;
        assert_failure(
            &format!("case {case:?}: the refresh grant of an ended session"),
            status,
            &body,
            400,
            "InvalidGrantException",
            "invalid_grant",
        );
        assert_eq!(
            body["error_description"].as_str(),
            Some(DESCRIPTION_INVALID_REFRESH_TOKEN),
            "case {case:?}: expected the invalid-refresh-token description, got {body}"
        );

        let (status, body) = emulator
            .post(
                "/token?aws_iam=t",
                REGION,
                &json!({
                    "clientId": other_application,
                    "grantType": GRANT_TYPE_TOKEN_EXCHANGE,
                    "subjectToken": spent_access_token,
                    "subjectTokenType": TOKEN_TYPE_URI_ACCESS_TOKEN,
                }),
            )
            .await;
        assert_failure(
            &format!("case {case:?}: exchanging a token of an ended session"),
            status,
            &body,
            400,
            "InvalidGrantException",
            "invalid_grant",
        );
        assert_eq!(
            body["error_description"].as_str(),
            Some(DESCRIPTION_INVALID_SUBJECT_TOKEN),
            "case {case:?}: expected the invalid-subject-token description, got {body}"
        );

        let rotated_other = rotated(&emulator, &client_id, &client_secret, &other).await;
        assert_eq!(
            held(&emulator, &rotated_other),
            (true, true),
            "case {case:?}: the other session must still rotate into a pair the mint holds"
        );

        // The session is ended for good: nothing re-animates it, and the token that named
        // it names no session of this mint any more.
        assert!(
            !emulator
                .state()
                .lock()
                .end_sign_in_session(&spent_access_token),
            "case {case:?}: a token the mint no longer holds names no session to end"
        );
    }
}
