// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the two things an api's own RESOURCE POLICY decides about an invoke
//! that the sibling suites do not carry: a clause written over the ADDRESS the request came
//! from, and WHAT the refusal of a document that explicitly denies the call states.
//!
//! THE RULES UNDER TEST:
//!
//! 1. A condition clause of the api's resource policy written over `aws:SourceIp` is decided
//!    against the address the request came from, under IAM's own IP-address operators: an
//!    `IpAddress` grant covers every request from the network it names (a CIDR block, a bare
//!    address, either IP version) and no other, and a `NotIpAddress` deny refuses every
//!    request from OUTSIDE it. A request this plane can read no address for leaves such a
//!    clause undecided, which never grants while it still refuses.
//! 2. An `execute-api` authorization refusal reports the method's resource with all but the
//!    LAST FOUR digits of the account masked by `*`, and closes with the clause naming the
//!    document class that refused the call — `with an explicit deny in a resource-based
//!    policy` where the api's own document DENIED it, which no grant lifts, against the
//!    clause an identity-based implicit deny closes with, which a grant does lift.
//! 3. A statement of that document whose `Principal` names the IAM ROLE behind an
//!    assumed-role session is about that session, as one naming the session itself is —
//!    while the principal a refusal NAMES stays the session's own.
//! 4. `RestApi$policy` is "a stringified JSON policy document": the document the api STORES
//!    is the caller's with every `Resource` written in the `execute-api:/{stage}/{verb}/{path}`
//!    shorthand expanded to the ARN of the method of this api it names, and the member is
//!    REPORTED as that stored document's text ENCODED as a JSON string — so a reader decodes
//!    the string once to get back the document the decision is taken from.
//!
//! The rows span what the rules generalise over: the NETWORK a clause names (every address,
//! a block, a single address, another block, an IPv6 block), the ADDRESS the request came
//! from (inside the network, outside it, of the other IP version), the OPERATOR the clause is
//! written under (`IpAddress`, `NotIpAddress`), which document refused the call, and the
//! SHAPE of the document a round trip is read back through (one statement, several, a
//! condition, a value carrying characters a JSON string escapes).
//!
//! Everything about the api is written through this service's control plane and every case
//! drives the real wire path — an HTTP request through the router to the api's own invoke
//! host — so what is asserted is what a client at that address sees. The role, its policies
//! and the session the requests sign with are seeded by the sibling
//! `stage_invoke_identity_policy` suite's own helpers, so one session is recorded rather than
//! a second copy of it.
//!
//! The gates are `src/service/resource_policy.rs` (the document, the condition keys an invoke
//! publishes and the sentence a refusal states) and
//! `src/service/invoke/execute_api_authorization.rs` (the identity half), whose unit tests
//! pin the pure rules over tables of documents.

use serde_json::{json, Value};

use crate::execute_api_data_plane::{
    deploy, integration_response, invoke, json_template, method_response, policy_document_of,
    put_integration, put_method, stored_policy_document, Invoked,
};
use crate::rest_api_lifecycle::{create_api, resource_under, string_member, Gateway};
use crate::stage_invoke_identity_policy::{
    allow, assert_refused, assert_served, credential, given_policy, given_session,
    reported_resource, role_arn, served_body, session_arn, Entity, Reason, SESSION_KEY_ID,
};

/// The Region the shared control-plane harness creates an api in, and so the Region of the
/// method ARN a refusal reports.
const REGION: &str = "us-east-1";

/// The stage the api is deployed to, and the resource path of its one method.
const STAGE: &str = "live";
const RESOURCE_PATH: &str = "widgets";

/// The IAM action an invoke of a deployed method asks for.
const INVOKE_ACTION: &str = "execute-api:Invoke";

/// The request header the address a request came from is recorded in where it reached the
/// emulator through a forwarder, which is how a row names the address it comes from.
const FORWARDED_FOR: &str = "x-forwarded-for";

/// The address a request that names none came from: this emulator is reached in process or
/// over the loopback interface.
const LOOPBACK: &str = "127.0.0.1";

/// One api carrying a deployed `AWS_IAM` `GET` behind a `MOCK` integration.
struct Deployed {
    /// The api id.
    api: String,
}

impl Deployed {
    /// Stand the api up and deploy it, because what the data plane serves is read out of
    /// the DEPLOYMENT.
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

    /// The ARN of the deployed method: the resource a statement names it by, and the one a
    /// refusal reports — masked, when reported.
    fn method_arn(&self) -> String {
        format!(
            "arn:aws:execute-api:{REGION}:{account}:{api}/{STAGE}/GET/{RESOURCE_PATH}",
            account = ::engine::emulator_account_id(),
            api = self.api,
        )
    }

    /// The ARN this api's own resources hang off, which is the prefix the `execute-api:/…`
    /// shorthand of a stored statement is expanded under.
    fn arn_prefix(&self) -> String {
        format!(
            "arn:aws:execute-api:{REGION}:{account}:{api}",
            account = ::engine::emulator_account_id(),
            api = self.api,
        )
    }

    /// `UpdateRestApi` replacing `/policy` with `document` (or removing it for `None`), then
    /// `CreateDeployment` so the stage serves the api as it now stands. The document is read
    /// back through `GetRestApi`, so each case proves the round trip it then invokes against.
    async fn set_policy(&self, gateway: &Gateway, case: &str, document: Option<&Value>) {
        let patch = match document {
            Some(document) => json!({
                "patchOperations": [
                    { "op": "replace", "path": "/policy", "value": document.to_string() }
                ]
            }),
            None => json!({ "patchOperations": [{ "op": "remove", "path": "/policy" }] }),
        };
        let patched = gateway
            .call("PATCH", &format!("/restapis/{}", self.api), Some(patch))
            .await;
        assert_eq!(
            patched.status, 200,
            "case {case}: expected UpdateRestApi to answer 200, got {} with {:?}",
            patched.status, patched.body
        );
        let read = self.read(gateway, case).await;
        match document {
            Some(document) => assert_eq!(
                policy_document_of(&string_member(&read, "policy", case), case),
                stored_policy_document(document, &self.arn_prefix()),
                "case {case}: expected GetRestApi to report the policy that was set"
            ),
            None => assert!(
                read.get("policy").is_none_or(Value::is_null),
                "case {case}: expected no policy on the api, got {read:?}"
            ),
        }
        deploy(gateway, &self.api, STAGE).await;
    }

    /// The api as `GetRestApi` reports it.
    async fn read(&self, gateway: &Gateway, case: &str) -> Value {
        let read = gateway
            .call("GET", &format!("/restapis/{}", self.api), None)
            .await;
        assert_eq!(
            read.status, 200,
            "case {case}: expected GetRestApi to answer 200, got {} with {:?}",
            read.status, read.body
        );
        read.body
    }

    /// One answered invoke signed with the seeded session's credential, coming from
    /// `address` when a row names one.
    async fn invoke_from(&self, gateway: &Gateway, address: Option<&str>) -> Invoked {
        let scope = credential(SESSION_KEY_ID);
        let mut headers: Vec<(&str, &str)> = vec![("authorization", scope.as_str())];
        if let Some(address) = address {
            headers.push((FORWARDED_FOR, address));
        }
        invoke(
            gateway,
            &self.api,
            "GET",
            &format!("/{STAGE}/{RESOURCE_PATH}"),
            &headers,
        )
        .await
    }
}

/// A document whose one statement states `effect` for every principal over every path of the
/// api, under `operator` on the address the request came from.
fn addressed(effect: &str, operator: &str, network: &str) -> Value {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": effect,
            "Principal": "*",
            "Action": INVOKE_ACTION,
            "Resource": "execute-api:/*",
            "Condition": { operator: { "aws:SourceIp": network } },
        }]
    })
}

/// RULE 1: an `IpAddress` grant in the api's own document admits exactly the requests whose
/// address lies in the network it names — which is the grant that RESCUES a caller whose own
/// policies allow nothing — and no other.
#[tokio::test]
async fn a_source_ip_grant_admits_the_addresses_it_names_and_no_others() {
    let gateway = Gateway::new();
    let deployed = Deployed::stand_up(&gateway, "source-ip-grant").await;
    given_session(&gateway);
    // The caller's own policies allow nothing at all, so the api's document is the only
    // grant there is: each row is decided by its condition alone.
    given_policy(&gateway, Entity::Role, None);

    // Rows differ along the network the grant names and the address the request came from:
    // every address, the block it came from, the address itself, another block, and an IPv6
    // network reached from each IP version.
    let rows: &[(&str, &str, Option<&str>, bool)] = &[
        ("every address", "0.0.0.0/0", Some("203.0.113.9"), true),
        ("every address, from the loopback", "0.0.0.0/0", None, true),
        ("the block the request came from", "203.0.113.0/24", Some("203.0.113.9"), true),
        ("the address itself", "203.0.113.9", Some("203.0.113.9"), true),
        ("a sibling address of that block", "203.0.113.9", Some("203.0.113.10"), false),
        ("another block entirely", "198.51.100.0/24", Some("203.0.113.9"), false),
        ("the block, reached from outside it", "203.0.113.0/24", Some("198.51.100.7"), false),
        ("the loopback itself", LOOPBACK, None, true),
        ("an IPv6 network, reached over IPv6", "2001:db8::/32", Some("2001:db8::5"), true),
        ("an IPv6 network, reached over IPv4", "2001:db8::/32", Some("203.0.113.9"), false),
    ];
    for (case, network, address, served) in rows {
        deployed
            .set_policy(&gateway, case, Some(&addressed("Allow", "IpAddress", network)))
            .await;
        let answered = deployed.invoke_from(&gateway, *address).await;
        if *served {
            assert_served(case, &answered);
        } else {
            // Nothing granted the call: the identity-based gate's own implicit-deny clause,
            // which a grant would lift.
            assert_refused(
                case,
                &answered,
                &session_arn(),
                &deployed.method_arn(),
                Reason::NoIdentityGrant,
            );
        }
    }
}

/// RULE 1 and 2: a `NotIpAddress` deny refuses every request from outside the network it
/// names — whatever the caller's own policies allow — and the refusal closes with the clause
/// naming the api's own document, which no grant lifts.
#[tokio::test]
async fn a_source_ip_deny_beats_the_identity_grant_and_states_its_own_clause() {
    let gateway = Gateway::new();
    let deployed = Deployed::stand_up(&gateway, "source-ip-deny").await;
    given_session(&gateway);
    // The caller's own policies DO allow the invoke in every row below: what each row
    // asserts is that the document's deny beats that grant, and how it is stated.
    let method = deployed.method_arn();
    given_policy(&gateway, Entity::Role, Some(&allow(INVOKE_ACTION, &method)));

    // Rows differ along the network the deny is written over and the address the request
    // came from: inside the network it admits, outside it, and a network naming a single
    // address.
    let rows: &[(&str, &str, Option<&str>, bool)] = &[
        ("inside the admitted block", "203.0.113.0/24", Some("203.0.113.9"), true),
        ("outside the admitted block", "203.0.113.0/24", Some("198.51.100.7"), false),
        ("the one admitted address", "203.0.113.9", Some("203.0.113.9"), true),
        ("a sibling of the one admitted address", "203.0.113.9", Some("203.0.113.10"), false),
        ("the loopback admitted, reached from it", LOOPBACK, None, true),
        ("the loopback admitted, reached from elsewhere", LOOPBACK, Some("203.0.113.9"), false),
    ];
    for (case, network, address, served) in rows {
        deployed
            .set_policy(
                &gateway,
                case,
                Some(&addressed("Deny", "NotIpAddress", network)),
            )
            .await;
        let answered = deployed.invoke_from(&gateway, *address).await;
        if *served {
            assert_served(case, &answered);
        } else {
            assert_refused(
                case,
                &answered,
                &session_arn(),
                &method,
                Reason::ResourceDeny,
            );
        }
    }
}

/// A document whose one statement states `effect` for `principal` over every path of the
/// api.
fn named_principal(effect: &str, principal: &str) -> Value {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": effect,
            "Principal": { "AWS": principal },
            "Action": INVOKE_ACTION,
            "Resource": "execute-api:/*",
        }]
    })
}

/// RULE 3: a statement naming the IAM ROLE behind the caller's session is about that
/// session — the grant that RESCUES a caller whose own policies allow nothing, and the deny
/// that beats a grant they do allow — and a statement naming another principal is about
/// neither.
#[tokio::test]
async fn a_statement_naming_the_role_behind_the_session_decides_the_invoke() {
    let gateway = Gateway::new();
    let deployed = Deployed::stand_up(&gateway, "named-principal").await;
    given_session(&gateway);
    let method = deployed.method_arn();
    let another_role = format!(
        "arn:aws:iam::{account}:role/someone-else",
        account = ::engine::emulator_account_id()
    );
    let another_session = format!(
        "arn:aws:sts::{account}:assumed-role/{role}/another",
        account = ::engine::emulator_account_id(),
        role = role_arn().rsplit('/').next().expect("the role's name"),
    );

    // Rows differ along the spelling the statement names its principal by: the session, the
    // role behind it, another role of the account, another session of the same role, and
    // every principal.
    let rows: &[(&str, String, bool)] = &[
        ("the session itself", session_arn(), true),
        ("the role behind the session", role_arn(), true),
        ("another role of the account", another_role, false),
        ("another session of the same role", another_session, false),
        ("every principal", "*".to_string(), true),
    ];
    for (case, principal, about_this_caller) in rows {
        // An ALLOW naming the principal rescues a caller whose own policies allow nothing:
        // either grant suffices.
        given_policy(&gateway, Entity::Role, None);
        let rescue = format!("{case}, allowing");
        deployed
            .set_policy(&gateway, &rescue, Some(&named_principal("Allow", principal)))
            .await;
        let answered = deployed.invoke_from(&gateway, None).await;
        if *about_this_caller {
            assert_served(&rescue, &answered);
        } else {
            assert_refused(
                &rescue,
                &answered,
                &session_arn(),
                &method,
                Reason::NoIdentityGrant,
            );
        }

        // A DENY naming the same principal beats the caller's own grant, and names the
        // SESSION rather than whichever spelling the statement used.
        given_policy(&gateway, Entity::Role, Some(&allow(INVOKE_ACTION, &method)));
        let refusal = format!("{case}, denying");
        deployed
            .set_policy(&gateway, &refusal, Some(&named_principal("Deny", principal)))
            .await;
        let answered = deployed.invoke_from(&gateway, None).await;
        if *about_this_caller {
            assert_refused(
                &refusal,
                &answered,
                &session_arn(),
                &method,
                Reason::ResourceDeny,
            );
        } else {
            assert_served(&refusal, &answered);
        }
    }
}

/// RULE 2: the resource a refusal reports masks all but the last four digits of the account,
/// while the resource a statement names the method by — and is granted on — carries the
/// account itself.
#[tokio::test]
async fn a_refusal_reports_the_resource_with_the_account_masked() {
    let gateway = Gateway::new();
    let deployed = Deployed::stand_up(&gateway, "masked-account").await;
    given_session(&gateway);
    given_policy(&gateway, Entity::Role, None);
    let account = ::engine::emulator_account_id();

    let refused = deployed.invoke_from(&gateway, None).await;
    assert_refused(
        "no grant at all",
        &refused,
        &session_arn(),
        &deployed.method_arn(),
        Reason::NoIdentityGrant,
    );
    let reported = reported_resource(&deployed.method_arn());
    assert!(
        refused.body.contains(&reported),
        "case \"the reported resource\": expected {reported:?} in the refusal, got {:?}",
        refused.body
    );
    assert!(
        !refused.body.contains(&deployed.method_arn()),
        "case \"the reported resource\": the resource must not publish the account whole \
         (the account is {account}), got {:?}",
        refused.body
    );
    // The ARN a statement names is the unmasked one: a grant written about it admits the
    // call, which is what makes the masking a property of the REPORT alone.
    given_policy(
        &gateway,
        Entity::Role,
        Some(&allow(INVOKE_ACTION, &deployed.method_arn())),
    );
    let served = deployed.invoke_from(&gateway, None).await;
    assert_served("a grant naming the unmasked resource", &served);
}

/// RULE 4: the api stores its resource policy with every shorthand resource expanded to the
/// method ARN it names, and reports that document as a JSON-encoded string — through every
/// reader of the record.
#[tokio::test]
async fn the_api_reports_its_resource_policy_as_a_json_string() {
    let gateway = Gateway::new();
    let deployed = Deployed::stand_up(&gateway, "stringified-policy").await;

    // Rows differ along the SHAPE of the document stored: one statement, several, a
    // condition, and a value carrying a character a JSON string escapes.
    let rows: &[(&str, Value)] = &[
        (
            "one statement",
            addressed("Allow", "IpAddress", "0.0.0.0/0"),
        ),
        (
            "several statements",
            json!({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": INVOKE_ACTION,
                        "Resource": "execute-api:/*",
                    },
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": INVOKE_ACTION,
                        "Resource": "execute-api:/*",
                        "Condition": { "NotIpAddress": { "aws:SourceIp": "203.0.113.0/24" } },
                    },
                ]
            }),
        ),
        (
            "a statement id carrying a quote and a backslash",
            json!({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "a\"quoted\\id",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": INVOKE_ACTION,
                    "Resource": "execute-api:/*",
                }]
            }),
        ),
    ];
    for (case, document) in rows {
        // `set_policy` itself asserts the GetRestApi round trip; what is added here is that
        // the REPORTED value is the encoded string rather than the document, and that every
        // reader of the record reports it alike.
        deployed.set_policy(&gateway, case, Some(document)).await;
        let reported = string_member(&deployed.read(&gateway, case).await, "policy", case);
        let stored = stored_policy_document(document, &deployed.arn_prefix());
        assert_ne!(
            reported, stored,
            "case {case}: expected the ENCODED document rather than its text"
        );
        assert!(
            !stored.contains("\":") || reported.contains("\\\""),
            "case {case}: expected the document's quotes escaped, got {reported:?}"
        );
        let collection = gateway.call("GET", "/restapis", None).await;
        let listed = crate::rest_api_lifecycle::page_items(&collection.body, case)
            .into_iter()
            .find(|item| item.get("id").and_then(Value::as_str) == Some(deployed.api.as_str()))
            .unwrap_or_else(|| panic!("case {case}: GetRestApis must report the api"));
        assert_eq!(
            string_member(&listed, "policy", case),
            reported,
            "case {case}: expected every reader to report the policy alike"
        );
        assert_eq!(
            policy_document_of(&reported, case),
            stored,
            "case {case}: expected the stored document back from the encoded value"
        );
        let decoded = policy_document_of(&reported, case);
        assert!(
            !decoded.contains("\"execute-api:/") && decoded.contains(&deployed.arn_prefix()),
            "case {case}: expected the stored document to name its resources by ARN, got \
             {decoded:?}"
        );
    }

    // ONE case written out BY HAND, so what the member must carry is an expectation of its
    // own rather than the rule recomputed: the shorthand names the method, and the member
    // comes back as that document's text with every quote escaped.
    let case = "the member, written out";
    deployed
        .set_policy(
            &gateway,
            case,
            Some(&json!({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "execute-api:Invoke",
                    "Resource": format!("execute-api:/{STAGE}/GET/{RESOURCE_PATH}"),
                }]
            })),
        )
        .await;
    let reported = string_member(&deployed.read(&gateway, case).await, "policy", case);
    // The document the api must STORE, written out: the shorthand expanded to the ARN of the
    // method it named.
    let stored = format!(
        "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"execute-api:Invoke\",\"Resource\":\"arn:aws:execute-api:{REGION}:{account}:{api}/{STAGE}/GET/{RESOURCE_PATH}\"}}]}}",
        account = ::engine::emulator_account_id(),
        api = deployed.api,
    );
    assert_eq!(
        policy_document_of(&reported, case),
        stored,
        "case {case}: got {reported:?}"
    );
    // And the member itself is that text with every quote escaped.
    assert_eq!(
        reported,
        stored.replace('"', "\\\""),
        "case {case}: got {reported:?}"
    );
}
