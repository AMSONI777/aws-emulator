// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the ORDER in which a deployed stage decides a call no deployed method
//! serves: the authorization decision comes first, and the routing answer only afterwards.
//!
//! THE RULE UNDER TEST: a request to a path the deployment holds a RESOURCE for, carrying a
//! SigV4 credential, is authorized before the stage resolves which method serves it —
//! `execute-api:Invoke` on the ARN built from the VERB the request used and the path it
//! addressed. A caller the documents do not allow that ARN is refused `403` with
//! `x-amzn-ErrorType: AccessDeniedException` and the authorization sentence about that very
//! ARN, learning nothing about which verbs the resource defines; a caller they do allow is
//! told what was looked for and not found — `404`, naming the route and the HTTP method. A
//! path the deployment holds no resource for, and any request carrying no credential at all,
//! stay the refusal API Gateway answers an unplaceable route with: `403`
//! `{"message":"Missing Authentication Token"}`.
//!
//! So a least-privilege grant is the boundary for a verb the api does not define too, and the
//! existence of a route is not something an unauthorized caller can probe.
//!
//! The table spans what the rule generalises over: whether the deployment holds a resource at
//! the path (a resource with a method, a resource with NO method at all, and a path with no
//! resource), the verb the request used (one the resource defines and one it does not), the
//! grant in force (one naming just the served verb and one covering every method of the api),
//! and whether the request carries a credential.
//!
//! The role, its documents and the session live in the IAM and STS stores of the SAME shared
//! engine, seeded through the sibling `stage_invoke_identity_policy` suite's helpers.
//! Everything about the api goes through this service's control plane, and every case drives
//! the real wire path to the api's own invoke host.

use serde_json::json;

use crate::execute_api_data_plane::{
    deploy, integration_response, invoke, json_template, method_response, put_integration,
    put_method, Invoked,
};
use crate::rest_api_lifecycle::{create_api, resource_under, Gateway};
use crate::stage_invoke_identity_policy::{
    allow, assert_refused, assert_served, credential, given_policy, given_session, session_arn,
    served_body, Entity, Reason, SESSION_KEY_ID,
};

/// The Region the shared control-plane harness creates the api in.
const REGION: &str = "us-east-1";

/// The stage the api is deployed to.
const STAGE: &str = "s";

/// The IAM action an invoke of a deployed method asks for.
const INVOKE_ACTION: &str = "execute-api:Invoke";

/// The collection resource: deployed, carrying NO method of its own — the parent a per-item
/// method hangs under.
const COLLECTION: &str = "agreements";

/// The item under it, which carries the one `GET` the stage serves.
const ITEM: &str = "one";

/// A path the deployment holds no resource for at all.
const UNKNOWN: &str = "nowhere";

/// One api carrying a methodless collection with a `GET` item under it, deployed to
/// [`STAGE`].
struct Deployed {
    /// The api id.
    api: String,
}

impl Deployed {
    async fn stand_up(gateway: &Gateway, name: &str) -> Self {
        let (api, root) = create_api(gateway, name).await;
        // The collection exists as a RESOURCE and carries no method: the shape a parent of a
        // per-item method has.
        let collection = resource_under(gateway, &api, &root, COLLECTION).await;
        let item = resource_under(gateway, &api, &collection, ITEM).await;
        put_method(
            gateway,
            &api,
            &item,
            "GET",
            json!({ "authorizationType": "AWS_IAM" }),
        )
        .await;
        put_integration(gateway, &api, &item, "GET", json!({ "type": "MOCK" })).await;
        method_response(gateway, &api, &item, "GET", "200", json!({})).await;
        integration_response(
            gateway,
            &api,
            &item,
            "GET",
            "200",
            json!({ "responseTemplates": json_template(&served_body()) }),
        )
        .await;
        deploy(gateway, &api, STAGE).await;
        Self { api }
    }

    /// The ARN of `verb` on the path `within` names inside the stage: the resource an
    /// authorization decision about this call is taken about, built from the REQUEST rather
    /// than from the deployment.
    fn method_arn(&self, verb: &str, within: &str) -> String {
        format!(
            "arn:aws:execute-api:{REGION}:{account}:{api}/{STAGE}/{verb}/{within}",
            account = ::engine::emulator_account_id(),
            api = self.api,
        )
    }

    /// One answered call of `verb` on the path `within` names inside the stage, signed when
    /// `signed` is set.
    async fn call(&self, gateway: &Gateway, verb: &str, within: &str, signed: bool) -> Invoked {
        let scope = credential(SESSION_KEY_ID);
        let headers: Vec<(&str, &str)> = if signed {
            vec![("authorization", scope.as_str())]
        } else {
            Vec::new()
        };
        invoke(
            gateway,
            &self.api,
            verb,
            &format!("/{STAGE}/{within}"),
            &headers,
        )
        .await
    }
}

/// What the stage answers a call it holds no method for.
#[derive(Debug, Clone, Copy)]
enum Answer {
    /// The integration's own body.
    Served,
    /// `403` with the authorization sentence, closed by this reason.
    Denied(Reason),
    /// `404`: the caller may invoke the ARN it named, and the stage holds no method for it —
    /// the sentence naming the route and the HTTP method looked for.
    NotFound,
    /// `403` `{"message":"Missing Authentication Token"}` — the route the endpoint cannot
    /// place at all.
    MissingToken,
}

/// RULE: the authorization decision is taken about the ARN the REQUEST named, before the
/// stage resolves which method serves the call — so an ungranted verb is an authorization
/// refusal and a granted one the stage has no method for is `404`.
#[tokio::test]
async fn authorization_is_decided_before_the_method_is_resolved() {
    let gateway = Gateway::new();
    let deployed = Deployed::stand_up(&gateway, "route-order-rows").await;
    given_session(&gateway);
    let served_path = format!("{COLLECTION}/{ITEM}");
    let get_only = allow(INVOKE_ACTION, &deployed.method_arn("GET", &served_path));
    let every_method = allow(
        INVOKE_ACTION,
        &format!(
            "arn:aws:execute-api:{REGION}:{account}:{api}/*",
            account = ::engine::emulator_account_id(),
            api = deployed.api,
        ),
    );

    // Rows differ along the grant in force, the verb the request used, the path it addressed
    // — one the deployment serves, one it holds a methodless resource for, one it holds no
    // resource for — and whether the request carries a credential at all.
    type Row<'r> = (&'r str, bool, &'r str, String, bool, Answer);
    let rows: Vec<Row<'_>> = vec![
        (
            "the granted verb of the served method",
            true,
            "GET",
            served_path.clone(),
            true,
            Answer::Served,
        ),
        (
            "a verb the resource does not define, under a grant naming only GET",
            true,
            "POST",
            served_path.clone(),
            true,
            Answer::Denied(Reason::NoIdentityGrant),
        ),
        (
            "that same verb under a grant covering every method of the collection",
            false,
            "POST",
            served_path.clone(),
            true,
            Answer::NotFound,
        ),
        (
            "the methodless parent, under a grant naming only the item's GET",
            true,
            "GET",
            COLLECTION.to_string(),
            true,
            Answer::Denied(Reason::NoIdentityGrant),
        ),
        (
            "the methodless parent, under a grant covering every method of the collection",
            false,
            "GET",
            COLLECTION.to_string(),
            true,
            Answer::NotFound,
        ),
        (
            "a verb the resource does not define, carrying no credential",
            false,
            "POST",
            served_path.clone(),
            false,
            Answer::MissingToken,
        ),
        (
            "the methodless parent, carrying no credential",
            false,
            "GET",
            COLLECTION.to_string(),
            false,
            Answer::MissingToken,
        ),
        (
            "a path the deployment holds no resource for, granted and signed",
            false,
            "GET",
            UNKNOWN.to_string(),
            true,
            Answer::MissingToken,
        ),
    ];
    for (case, only_get, verb, within, signed, expected) in &rows {
        given_policy(
            &gateway,
            Entity::Role,
            Some(if *only_get { &get_only } else { &every_method }),
        );
        let answered = deployed.call(&gateway, verb, within, *signed).await;
        match expected {
            Answer::Served => assert_served(case, &answered),
            Answer::Denied(reason) => assert_refused(
                case,
                &answered,
                &session_arn(),
                &deployed.method_arn(verb, within),
                *reason,
            ),
            Answer::NotFound => {
                assert_eq!(
                    answered.status, 404,
                    "case {case:?}: expected 404, got {} with {:?}",
                    answered.status, answered.body
                );
                assert_eq!(
                    answered.message().as_deref(),
                    Some(
                        format!("No method found matching route {within} for http method {verb}.")
                            .as_str()
                    ),
                    "case {case:?}: expected the not-found sentence to name the route and the \
                     method looked for, got {:?}",
                    answered.body
                );
            }
            Answer::MissingToken => {
                assert_eq!(
                    answered.status, 403,
                    "case {case:?}: expected 403, got {} with {:?}",
                    answered.status, answered.body
                );
                assert_eq!(
                    answered.message().as_deref(),
                    Some("Missing Authentication Token"),
                    "case {case:?}: expected the missing-token sentence, got {:?}",
                    answered.body
                );
                assert_eq!(
                    answered.header("x-amzn-errortype"),
                    Some("MissingAuthenticationTokenException"),
                    "case {case:?}: expected the missing-token class, got {:?}",
                    answered.header("x-amzn-errortype")
                );
            }
        }
    }
}
