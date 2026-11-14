// SPDX-License-Identifier: CC0-1.0

//! What this service answers when its own store cannot be reached at all, end to end over
//! HTTP.
//!
//! RULE: a pre-handler gate that cannot resolve the caller's identity must never report
//! the request as authenticated — so when this service's store is unreachable, every
//! request addressed to one of its routes WITH a bearer credential is answered with the
//! one modelled error that blames nobody (HTTP 429 `TooManyRequestsException`), the same
//! refusal every handler gives for the same condition, and never a 4xx faulting the
//! caller's parameters; a request presenting NO credential is still 401
//! `UnauthorizedException`, because that is decided without the store.
//!
//! The store is unreachable exactly when the service was built over an engine that is not
//! the shared `InMemoryEngine` — the crate is generic over the engine type, and
//! `state::service_state` resolves a store only out of that one. Every other suite here
//! builds the service over the shared engine, where the store always answers, so this is
//! the one suite that exercises the gate's no-store reading. The second test is the
//! control: on the shared engine the same request shapes are answered by the rules the
//! other suites pin, so the no-fault refusal is reserved for the unreachable store.

use super::portal_session::{assert_refusal, body_text, envelope, error_code, Portal};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use service_com_amazonaws_sso_swbportalservice::state::{
    INVALID_SESSION_MESSAGE, STORE_UNAVAILABLE_MESSAGE,
};
use service_com_amazonaws_sso_swbportalservice::EmulatedService;
use smithy_server_runtime::MultiServiceRouter;
use std::sync::Arc;

/// The portal endpoint an SDK addresses; the service claims a request by this host however
/// it was built, since every portal operation is `@optionalAuth` with an empty `@auth`.
const PORTAL_HOST: &str = "portal.sso.us-east-1.amazonaws.com";

/// The access token the control test below signs in, and an account the `Portal` fixture
/// assigns it, so a row with a live credential is served out of state.
const LIVE_TOKEN: &str = "tok-live";
const ASSIGNED_ACCOUNT: &str = "111111111111";
/// A role the fixture assigns that session in [`ASSIGNED_ACCOUNT`].
const ASSIGNED_ROLE: &str = "AdministratorAccess";

/// An engine that is NOT the shared `InMemoryEngine`, so `state::service_state` resolves no
/// store out of it. The crate is generic over the engine type (`EmulatedService<Eng>`), so
/// this is a service a caller of its public constructor can really build.
#[derive(Debug, Default)]
struct NoStore;

/// The `@required` query members of one route, each with a value: `(name, value)`.
type RequiredQuery = &'static [(&'static str, &'static str)];

/// One route this service serves: the method and path of an `@http` binding, and that
/// route's `@required` query members.
type Route = (&'static str, &'static str, RequiredQuery);

/// This service's four routes and the `@required` query members of each, with a value for
/// every one, from the model: `GET /assignment/accounts`, `GET /assignment/roles`
/// (`account_id`), `GET /federation/credentials` (`account_id`, `role_name`) and
/// `POST /logout` — `smithy_query(query="operation", operation="ListAccounts,
/// ListAccountRoles,GetRoleCredentials,Logout")`, whose `http` bindings and `required`
/// members these are. The bearer credential is the fourth route's only required member and
/// rides as a header, so it is varied separately below.
const ROUTES: &[Route] = &[
    ("GET", "/assignment/accounts", &[]),
    ("GET", "/assignment/roles", &[("account_id", ASSIGNED_ACCOUNT)]),
    (
        "GET",
        "/federation/credentials",
        &[
            ("account_id", ASSIGNED_ACCOUNT),
            ("role_name", ASSIGNED_ROLE),
        ],
    ),
    ("POST", "/logout", &[]),
];

/// The routes that bind the modelled `max_result` query member, whose `MaxResultType`
/// carries `range { min: 1, max: 100 }` (same model query): a value outside that range
/// ends the request in the framework's own validation, before any handler runs.
const PAGED_ROUTES: &[&str] = &["/assignment/accounts", "/assignment/roles"];

/// What an AUTHENTICATED caller earns for a request shape, once a reachable store has let
/// the request through and the rest of it is read. Used only by the control test; the
/// unreachable store answers the same refusal whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Inside every modelled rule, so the request is served.
    Served,
    /// This service's modelled refusal of a request it will not read: 400
    /// `InvalidRequestException` — an absent `@required` member, or a value outside the
    /// modelled range.
    Invalid,
}

/// Every request shape this suite sweeps, as `(case, method, uri, what a live session
/// earns)`.
///
/// Rows differ along everything the rule generalises over: which of the four routes is
/// addressed, whether the route carries every `@required` query member or omits one (so
/// the request names no operation and is read by the routing seam rather than by a
/// handler), and whether it carries a value the framework itself will not read (a page
/// bound outside the published range, at each end and one past each) — three different
/// pre-handler paths through the service, which the rule must answer identically.
fn request_shapes() -> Vec<(String, Method, String, Expect)> {
    let mut rows: Vec<(String, Method, String, Expect)> = Vec::new();
    for (method, path, required) in ROUTES {
        let verb: Method = method
            .parse()
            .unwrap_or_else(|_| panic!("the model's method {method:?} must be an HTTP method"));
        // The ONE way a row's URI is spelled, so no two kinds of row can encode a query
        // differently.
        let uri_with = |pairs: Vec<(String, String)>| -> String {
            if pairs.is_empty() {
                return (*path).to_string();
            }
            let joined: Vec<String> = pairs
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            format!("{path}?{}", joined.join("&"))
        };
        let owned = |pairs: Vec<&(&str, &str)>| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect()
        };

        // Every required member present: the request names an operation.
        rows.push((
            format!("{method} {path} with every required parameter"),
            verb.clone(),
            uri_with(owned(required.iter().collect())),
            Expect::Served,
        ));
        // One required query member omitted at a time: the request names no operation.
        for omitted in required.iter() {
            rows.push((
                format!("{method} {path} without {}", omitted.0),
                verb.clone(),
                uri_with(owned(
                    required.iter().filter(|pair| pair.0 != omitted.0).collect(),
                )),
                Expect::Invalid,
            ));
        }
        // Each published bound of the modelled range, which is served, and one past each
        // of them, which the framework's own validation refuses.
        if PAGED_ROUTES.contains(path) {
            for (bound, expect) in [
                (1, Expect::Served),
                (100, Expect::Served),
                (0, Expect::Invalid),
                (101, Expect::Invalid),
            ] {
                let mut pairs = owned(required.iter().collect());
                pairs.push(("max_result".to_string(), bound.to_string()));
                rows.push((
                    format!("{method} {path} with max_result={bound}"),
                    verb.clone(),
                    uri_with(pairs),
                    expect,
                ));
            }
        }
    }
    rows
}

/// Every bearer credential a request can present, as `(case, header value)`. `None` is the
/// request carrying no credential header at all — the one case the store is not needed to
/// decide.
fn credentials() -> Vec<(&'static str, Option<&'static str>)> {
    vec![
        ("no bearer-token header at all", None),
        ("an empty header value", Some("")),
        ("a token that was never issued", Some("tok-never-issued")),
        ("a token of ordinary shape", Some(LIVE_TOKEN)),
    ]
}

/// Build one request: the method, the URI and the credential of a row, addressed to the
/// portal endpoint.
fn request_for(method: &Method, uri: &str, credential: Option<&str>) -> Request<Bytes> {
    let mut builder = Request::builder()
        .method(method.clone())
        .uri(format!("https://{PORTAL_HOST}{uri}"))
        .header("host", PORTAL_HOST);
    if let Some(credential) = credential {
        builder = builder.header("x-amz-sso_bearer_token", credential);
    }
    builder
        .body(Bytes::new())
        .expect("the test built a well-formed request")
}

/// RULE: with the store unreachable, a request presenting a bearer credential is answered
/// 429 `TooManyRequestsException` — the refusal that blames nobody, identical on every
/// route and whichever pre-handler path reads the request — and a request presenting none
/// is answered 401 `UnauthorizedException`. Neither answer ever faults the caller's
/// parameters.
#[tokio::test]
async fn an_unreachable_store_is_refused_without_blaming_the_caller() {
    let mut router = MultiServiceRouter::new();
    router.register_service(EmulatedService::new(Arc::new(NoStore)));

    for (shape_case, method, uri, _) in request_shapes() {
        for (credential_case, credential) in credentials() {
            let case = format!("{shape_case}, presenting {credential_case}");
            let response = router
                .dispatch(request_for(&method, &uri, credential))
                .await;
            match credential {
                // Decided without the store: the request presents nothing to resolve.
                None => assert_refusal(
                    &case,
                    &response,
                    StatusCode::UNAUTHORIZED,
                    "UnauthorizedException",
                    INVALID_SESSION_MESSAGE,
                ),
                // A credential WAS presented and nothing could resolve it, so the answer
                // says that instead of reporting the request as read and judged. An empty
                // header value is a presented header too: what it names is a question for
                // the store, and there is none to ask.
                Some(_) => assert_refusal(
                    &case,
                    &response,
                    StatusCode::TOO_MANY_REQUESTS,
                    "TooManyRequestsException",
                    STORE_UNAVAILABLE_MESSAGE,
                ),
            }

            // Asking the gate is a pure read, so the identical request gets the identical
            // answer: nothing about the first one moved anything on.
            let again = router
                .dispatch(request_for(&method, &uri, credential))
                .await;
            assert_eq!(
                envelope(&again),
                envelope(&response),
                "case {case:?}: the same request must answer the same thing twice, got {:?} \
                 against {:?}",
                envelope(&again),
                envelope(&response)
            );
        }
    }
}

/// RULE (the other side): the no-fault refusal belongs to the unreachable store alone. On
/// the shared engine the store answers, so the same request shapes are judged — an unusable
/// credential is 401, an authenticated caller earns the modelled answer its request
/// deserves (200, or the 400 for a request this service will not read), and no request is
/// ever answered the store's refusal.
#[tokio::test]
async fn a_reachable_store_never_answers_the_store_refusal() {
    let portal = Portal::new();

    for (shape_case, method, uri, expect) in request_shapes() {
        for (credential_case, credential) in credentials() {
            let case = format!("{shape_case}, presenting {credential_case}");
            // Re-seeded per row, so no row depends on what an earlier one did to the
            // session — one of these requests is the `Logout` that ends it.
            portal.sign_in(LIVE_TOKEN, &[ASSIGNED_ACCOUNT]);
            let response = portal.dispatch(request_for(&method, &uri, credential)).await;
            assert_ne!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "case {case:?}: a reachable store must never answer the store's refusal, got \
                 {} {:?}",
                response.status(),
                body_text(&response)
            );
            // Every credential but the live one names no usable session, and that is
            // resolved against the store, so it is the caller's authentication that is
            // refused.
            if credential != Some(LIVE_TOKEN) {
                assert_refusal(
                    &case,
                    &response,
                    StatusCode::UNAUTHORIZED,
                    "UnauthorizedException",
                    INVALID_SESSION_MESSAGE,
                );
                continue;
            }
            // The live session IS read, so each shape earns its own modelled answer: the
            // 400 is reachable only once the caller is authenticated against a store that
            // answered.
            match expect {
                Expect::Served => assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "case {case:?}: inside every modelled rule, expected 200, got {} {:?}",
                    response.status(),
                    body_text(&response)
                ),
                Expect::Invalid => assert_eq!(
                    (response.status(), error_code(&response).as_str()),
                    (StatusCode::BAD_REQUEST, "InvalidRequestException"),
                    "case {case:?}: a request this service will not read, expected 400 \
                     InvalidRequestException, got {} {:?}",
                    response.status(),
                    body_text(&response)
                ),
            }
        }
    }
}
