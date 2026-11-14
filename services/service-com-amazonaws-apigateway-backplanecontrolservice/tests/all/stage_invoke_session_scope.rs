// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for what CAPS the `execute-api` data plane's authorization decision: the
//! SCOPE the credential a request signed with was minted with.
//!
//! THE RULE UNDER TEST: the permissions of a request signed with a temporary credential are the
//! INTERSECTION of the identity's own documents and the session policies its mint passed ("the
//! resulting session's permissions are the intersection of the role's identity-based policy and
//! the session policies", `AssumeRoleRequest$PolicyArns`). So a scope that does not allow
//! `execute-api:Invoke` on the method ARN refuses an invoke the ROLE grants — whether the grant
//! the request would otherwise rest on is the role's own or the api's resource policy — and the
//! refusal closes with the clause naming the class that withheld it (`because no session policy
//! allows the execute-api:Invoke action`), while an explicit `Deny` in the scope closes with its
//! own clause. A credential no mint scoped caps nothing.
//!
//! The table spans what the rule generalises over: what the session policy states about the
//! method (every invoke, this method alone, only another verb, only another api, only another
//! action, nothing at all, an explicit deny) and which grant the request would otherwise rest
//! on.
//!
//! The role, its documents and the scoped session live in the IAM and STS stores of the SAME
//! shared engine, seeded through the sibling `stage_invoke_identity_policy` suite's helpers, so
//! the scope under test is the one `sts:AssumeRole` records and the principal a refusal blames
//! is the one `sts:GetCallerIdentity` answers for the credential the request signed with.
//! Everything about the api goes through this service's control plane and every case drives the
//! real wire path to the api's own invoke host.
//!
//! The gate is `src/service/invoke/execute_api_authorization.rs`, whose own unit tests pin the
//! rule over a table of scope documents; what is added here is the END-TO-END reading of it,
//! through the session a mint recorded.

use serde_json::{json, Value};

use crate::execute_api_data_plane::{
    deploy, integration_response, invoke, json_template, method_response, put_integration,
    put_method, Invoked,
};
use crate::rest_api_lifecycle::{create_api, resource_under, Gateway};
use crate::stage_invoke_identity_policy::{
    allow, assert_refused, assert_served, credential, given_policy, given_scoped_session,
    given_session, served_body, Entity, Reason,
};

/// The Region the shared control-plane harness creates the api in.
const REGION: &str = "us-east-1";

/// The stage the api is deployed to.
const STAGE: &str = "s";

/// The resource the method under test is put on.
const RESOURCE_PATH: &str = "whoami";

/// The IAM action an invoke of a deployed method asks for.
const INVOKE_ACTION: &str = "execute-api:Invoke";

/// The access key id of the scoped session each row vends.
const SCOPED_KEY_ID: &str = "ASIAEXAMPLESCOPED001";

/// The session name that credential is vended under.
const SCOPED_SESSION: &str = "ScopedCredentials";

/// One api carrying `GET /whoami` on an `AWS_IAM` method behind a `MOCK` integration,
/// deployed to [`STAGE`].
struct Deployed {
    /// The api id.
    api: String,
}

impl Deployed {
    async fn stand_up(gateway: &Gateway, name: &str) -> Self {
        let (api, root) = create_api(gateway, name).await;
        let resource = resource_under(gateway, &api, &root, RESOURCE_PATH).await;
        put_method(
            gateway,
            &api,
            &resource,
            "GET",
            json!({ "authorizationType": "AWS_IAM" }),
        )
        .await;
        put_integration(gateway, &api, &resource, "GET", json!({ "type": "MOCK" })).await;
        method_response(gateway, &api, &resource, "GET", "200", json!({})).await;
        integration_response(
            gateway,
            &api,
            &resource,
            "GET",
            "200",
            json!({ "responseTemplates": json_template(&served_body()) }),
        )
        .await;
        deploy(gateway, &api, STAGE).await;
        Self { api }
    }

    /// The ARN of the deployed `GET`: the resource a statement names the method by, and the
    /// one a refusal reports.
    fn method_arn(&self) -> String {
        format!(
            "arn:aws:execute-api:{REGION}:{account}:{api}/{STAGE}/GET/{RESOURCE_PATH}",
            account = ::engine::emulator_account_id(),
            api = self.api,
        )
    }

    /// One answered invoke of the method, signed with `access_key_id`.
    async fn invoke_as(&self, gateway: &Gateway, access_key_id: &str) -> Invoked {
        let scope = credential(access_key_id);
        invoke(
            gateway,
            &self.api,
            "GET",
            &format!("/{STAGE}/{RESOURCE_PATH}"),
            &[("authorization", scope.as_str())],
        )
        .await
    }
}

/// RULE: the effective permission of a request signed with a temporary credential is the
/// intersection of the role's own documents and the session policies its mint passed — a scope
/// that does not allow the method refuses an invoke the role grants, and the clause closing the
/// refusal names the class that withheld it.
#[tokio::test]
async fn a_session_policy_caps_the_grant_the_role_makes() {
    let gateway = Gateway::new();
    let deployed = Deployed::stand_up(&gateway, "session-scope-rows").await;
    given_session(&gateway);
    let method = deployed.method_arn();
    // The ROLE grants every invoke of this api in every row: what each row varies is the
    // SCOPE the credential was vended with.
    given_policy(
        &gateway,
        Entity::Role,
        Some(&allow(
            INVOKE_ACTION,
            &format!(
                "arn:aws:execute-api:{REGION}:{account}:{api}/*",
                account = ::engine::emulator_account_id(),
                api = deployed.api,
            ),
        )),
    );
    let another_verb = method.replace("/GET/", "/POST/");
    let another_api = format!(
        "arn:aws:execute-api:{REGION}:{account}:zzzzzzzzzz/{STAGE}/GET/{RESOURCE_PATH}",
        account = ::engine::emulator_account_id(),
    );

    // Rows differ along what the session policy states about this method.
    type Row<'r> = (&'r str, Option<Value>, Option<Reason>);
    let rows: Vec<Row<'_>> = vec![
        ("no session policy at all", None, None),
        (
            "a session policy allowing this method",
            Some(allow(INVOKE_ACTION, &method)),
            None,
        ),
        (
            "a session policy allowing every invoke",
            Some(allow(INVOKE_ACTION, "*")),
            None,
        ),
        (
            "a session policy allowing only another verb",
            Some(allow(INVOKE_ACTION, &another_verb)),
            Some(Reason::NoSessionGrant),
        ),
        (
            "a session policy allowing only another api",
            Some(allow(INVOKE_ACTION, &another_api)),
            Some(Reason::NoSessionGrant),
        ),
        (
            "a session policy allowing only another action",
            Some(allow("execute-api:InvalidateCache", "*")),
            Some(Reason::NoSessionGrant),
        ),
        (
            "a session policy stating nothing at all",
            Some(json!({ "Version": "2012-10-17", "Statement": [] })),
            Some(Reason::NoSessionGrant),
        ),
        (
            "a session policy denying the action outright",
            Some(json!({
                "Version": "2012-10-17",
                "Statement": [
                    { "Effect": "Allow", "Action": INVOKE_ACTION, "Resource": "*" },
                    { "Effect": "Deny", "Action": INVOKE_ACTION, "Resource": method.clone() },
                ]
            })),
            Some(Reason::SessionDeny),
        ),
    ];
    for (case, scope, refused) in &rows {
        let principal =
            given_scoped_session(&gateway, SCOPED_KEY_ID, SCOPED_SESSION, scope.as_ref());
        let answered = deployed.invoke_as(&gateway, SCOPED_KEY_ID).await;
        match refused {
            None => assert_served(case, &answered),
            Some(reason) => assert_refused(case, &answered, &principal, &method, *reason),
        }
    }
}
