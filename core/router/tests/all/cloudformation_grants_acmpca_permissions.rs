// SPDX-License-Identifier: CC0-1.0

//! A CloudFormation stack that declares an `AWS::ACMPCA::Permission` really GRANTS the
//! permission in Amazon Web Services Private CA, and reports the grant under the identifier
//! that service addresses one by.
//!
//! The rules under test, both of which two crates have to agree on (CloudFormation makes the
//! calls; Amazon Web Services Private CA serves them and holds the grant), so the suite lives
//! here rather than in either crate:
//!
//! 1. **a declared resource of a type this emulator provisions is created through the OWNING
//!    service's own API, and removing its declaration removes it there** — so
//!    `ListPermissions` on the certificate authority a completed stack declared reports the
//!    grant, with the actions and the assigning account the declaration states, and a
//!    deployment that no longer declares it leaves that listing empty.
//! 2. **the physical resource id of a resource whose primary identifier is COMPOSITE is the
//!    values of its parts joined with `|`** — for this type the `CertificateAuthorityArn` and
//!    the `Principal` every call of that service on a grant is addressed by
//!    (`DeletePermission` takes exactly those two) — **which is what the stack reports for the
//!    resource and what `Ref` resolves to.**
//!
//! The rows differ along what the rules generalise over: the Region the stack deploys in, the
//! form the template is written in (JSON or YAML), whether the CA the grant is made on is a
//! root or a subordinate, the ORDER the declaration lists the granted actions in, whether it
//! states the account the grant is assigned from, and how many certificate authorities of the
//! stack are granted on (so the identity reported for a grant is the pair IT names rather than
//! one the stack happens to hold).
//!
//! Every expected value is computed here from what the row declares, never read back out of
//! the answer being checked — except the CA ARN, which that service mints: it is read off the
//! stack's record of the CA, and the grant's expected identity and its expected
//! `CertificateAuthorityArn` are built from it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use super::query_wire::{opt_element, outputs_of, form_encode};

/// How long the suite goes on polling for an outcome that is already due, and how often: a
/// loaded machine can be slower than the emulator's own spans without the rule being any
/// different.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const POLLS: usize = 60;

/// The account id every ARN this emulator mints carries, which is also the account a grant
/// that states no `SourceAccount` is assigned from.
const ACCOUNT: &str = "000000000000";

/// The `StackStatus` values the rules above are stated in.
const CREATE_COMPLETE: &str = "CREATE_COMPLETE";
const UPDATE_COMPLETE: &str = "UPDATE_COMPLETE";

/// The one principal `CreatePermission` grants to: "at this time, the only valid principal is
/// acm.amazonaws.com" (`CreatePermissionRequest$Principal`).
const ACM_PRINCIPAL: &str = "acm.amazonaws.com";

/// The separator CloudFormation joins the parts of a composite physical resource id with.
const COMPOSITE_SEPARATOR: &str = "|";

/// The emulator with the two services this suite exercises, mounted on ONE engine exactly as
/// `core/router/src/lib.rs` mounts them.
fn build_router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_cloudformation_cloudformation::EmulatedService::new(Arc::clone(
            &engine,
        )),
    );
    router.register_service(
        service_com_amazonaws_acmpca_acmprivateca::EmulatedService::new(Arc::clone(&engine)),
    );
    router
}

/// A SigV4 `Authorization` header whose credential scope names `service` in `region`, which is
/// what routes the request and what each handler reads its Region from.
fn authorization(service: &str, region: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/{region}/{service}/aws4_request, \
         SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
    )
}

/// Call one CloudFormation operation over its awsQuery wire, signed for `region`.
async fn cloudformation(
    router: &MultiServiceRouter,
    region: &str,
    action: &str,
    members: &[(&str, &str)],
) -> (u16, String) {
    let mut body = format!("Action={action}&Version=2010-05-15");
    for (key, value) in members {
        body.push('&');
        body.push_str(&form_encode(key));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("cloudformation.{region}.amazonaws.com"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("authorization", authorization("cloudformation", region))
        .body(Bytes::from(body))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload = String::from_utf8_lossy(response.body()).to_string();
    (status, payload)
}

/// Call one Amazon Web Services Private CA operation over its awsJson1_1 wire, signed for
/// `region`.
async fn acm_pca(
    router: &MultiServiceRouter,
    region: &str,
    operation: &str,
    body: &Value,
) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("acm-pca.{region}.amazonaws.com"))
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", format!("ACMPrivateCA.{operation}"))
        .header("authorization", authorization("acm-pca", region))
        .body(Bytes::from(
            serde_json::to_vec(body).expect("the request body serializes"),
        ))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (status, payload)
}

/// The `PhysicalResourceId` the stack reports for ONE of its resources, read through
/// `DescribeStackResource` so the answer carries that resource alone.
async fn physical_id(
    router: &MultiServiceRouter,
    region: &str,
    stack: &str,
    logical_id: &str,
) -> (Option<String>, String) {
    let (status, body) = cloudformation(
        router,
        region,
        "DescribeStackResource",
        &[("StackName", stack), ("LogicalResourceId", logical_id)],
    )
    .await;
    assert_eq!(
        status, 200,
        "DescribeStackResource {logical_id}: expected HTTP 200, got {status} with body {body}"
    );
    (opt_element(&body, "PhysicalResourceId"), body)
}

/// Poll the stack until it reports `expected`, or answer the last status it reported with the
/// `DescribeStacks` body that reported it. The wait is for the CONDITION, with room for a host
/// slower than the emulator's own spans.
async fn wait_for_status(
    router: &MultiServiceRouter,
    region: &str,
    stack: &str,
    expected: &str,
) -> (String, String) {
    for _ in 0..POLLS {
        let (status, body) =
            cloudformation(router, region, "DescribeStacks", &[("StackName", stack)]).await;
        assert_eq!(
            status, 200,
            "DescribeStacks {stack}: expected HTTP 200, got {status} with body {body}"
        );
        let reported = opt_element(&body, "StackStatus").unwrap_or_default();
        if reported == expected {
            return (reported, body);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let (_, body) = cloudformation(router, region, "DescribeStacks", &[("StackName", stack)]).await;
    (opt_element(&body, "StackStatus").unwrap_or_default(), body)
}

/// Every grant Amazon Web Services Private CA holds on `ca_arn`, keyed by the principal that
/// holds it, with the `Permission` that service reports for each.
async fn granted_permissions(
    router: &MultiServiceRouter,
    region: &str,
    ca_arn: &str,
) -> (u16, BTreeMap<String, Value>, Value) {
    let (status, answered) = acm_pca(
        router,
        region,
        "ListPermissions",
        &json!({ "CertificateAuthorityArn": ca_arn }),
    )
    .await;
    let listed = answered
        .get("Permissions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let grants = listed
        .into_iter()
        .filter_map(|permission| {
            let principal = permission.get("Principal")?.as_str()?.to_string();
            Some((principal, permission))
        })
        .collect();
    (status, grants, answered)
}

/// One grant a row declares, and what the rules say it must then be.
struct Grant {
    /// The declaration's logical id, which is also the key of the output exporting its `Ref`
    /// (`<logical id>Ref`).
    logical_id: &'static str,
    /// The logical id of the `AWS::ACMPCA::CertificateAuthority` the grant is made on.
    certificate_authority: &'static str,
    principal: &'static str,
    /// The actions the declaration lists, in the ORDER it lists them.
    actions: &'static [&'static str],
    /// The `SourceAccount` the declaration states, where it states one.
    source_account: Option<&'static str>,
}

impl Grant {
    /// The `Actions` the grant must be reported with: the set the declaration names, in the
    /// order a `Permission` reports them, which is the members' own ordering rather than the
    /// request's.
    fn reported_actions(&self) -> Vec<String> {
        let mut reported: Vec<String> = self.actions.iter().map(|a| (*a).to_string()).collect();
        reported.sort();
        reported
    }

    /// The account the grant must be reported as assigned from: the one the declaration states,
    /// or — for a declaration that states none — the account the request was signed by, which
    /// for this emulator is the account its ARNs carry.
    fn reported_source_account(&self) -> &str {
        self.source_account.unwrap_or(ACCOUNT)
    }
}

/// One row of the table: a template, and the grants it declares.
struct Row {
    case: &'static str,
    region: &'static str,
    template: fn() -> String,
    grants: &'static [Grant],
    /// Every certificate authority the stack declares, by logical id, so a row can assert that
    /// a CA nothing grants on holds no grant.
    certificate_authorities: &'static [&'static str],
}

/// The three actions a grant on a private CA can carry (`ActionType`), which is the whole set
/// a grant has to name.
const EVERY_ACTION: &[&str] = &["IssueCertificate", "GetCertificate", "ListPermissions"];

const ROWS: &[Row] = &[
    Row {
        case: "one grant on a root CA, the actions in the model's own order, JSON",
        region: "us-west-2",
        template: || {
            json!({
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {
                    "Ca": {
                        "Type": "AWS::ACMPCA::CertificateAuthority",
                        "Properties": {
                            "Type": "ROOT",
                            "KeyAlgorithm": "RSA_2048",
                            "SigningAlgorithm": "SHA256WITHRSA",
                            "Subject": { "CommonName": "root.acme-widgets.internal" }
                        }
                    },
                    "CaPermission": {
                        "Type": "AWS::ACMPCA::Permission",
                        "Properties": {
                            "CertificateAuthorityArn": { "Ref": "Ca" },
                            "Principal": "acm.amazonaws.com",
                            "Actions": ["IssueCertificate", "GetCertificate", "ListPermissions"]
                        }
                    }
                },
                "Outputs": {
                    "CaPermissionRef": { "Value": { "Ref": "CaPermission" } }
                }
            })
            .to_string()
        },
        grants: &[Grant {
            logical_id: "CaPermission",
            certificate_authority: "Ca",
            principal: ACM_PRINCIPAL,
            actions: EVERY_ACTION,
            source_account: None,
        }],
        certificate_authorities: &["Ca"],
    },
    Row {
        case: "one grant on a subordinate CA, the actions out of order, with a source account, \
               YAML",
        region: "eu-west-1",
        template: || {
            [
                "Resources:",
                "  Ca:",
                "    Type: AWS::ACMPCA::CertificateAuthority",
                "    Properties:",
                "      Type: SUBORDINATE",
                "      KeyAlgorithm: EC_prime256v1",
                "      SigningAlgorithm: SHA384WITHECDSA",
                "      Subject:",
                "        CommonName: issuing.acme-widgets.internal",
                "  RenewalGrant:",
                "    Type: AWS::ACMPCA::Permission",
                "    Properties:",
                "      CertificateAuthorityArn: !Ref Ca",
                "      Principal: acm.amazonaws.com",
                "      SourceAccount: '000000000000'",
                "      Actions:",
                "        - ListPermissions",
                "        - GetCertificate",
                "        - IssueCertificate",
                "Outputs:",
                "  RenewalGrantRef:",
                "    Value: !Ref RenewalGrant",
                "",
            ]
            .join("\n")
        },
        grants: &[Grant {
            logical_id: "RenewalGrant",
            certificate_authority: "Ca",
            principal: ACM_PRINCIPAL,
            actions: &["ListPermissions", "GetCertificate", "IssueCertificate"],
            source_account: Some(ACCOUNT),
        }],
        certificate_authorities: &["Ca"],
    },
    Row {
        case: "a grant on one of three CAs of the same stack, JSON",
        region: "us-east-1",
        template: || {
            let authority = |common_name: &str| {
                json!({
                    "Type": "AWS::ACMPCA::CertificateAuthority",
                    "Properties": {
                        "Type": "ROOT",
                        "KeyAlgorithm": "RSA_2048",
                        "SigningAlgorithm": "SHA256WITHRSA",
                        "Subject": { "CommonName": common_name }
                    }
                })
            };
            json!({
                "Resources": {
                    "FirstCa": authority("first.acme-widgets.internal"),
                    "SecondCa": authority("second.acme-widgets.internal"),
                    "ThirdCa": authority("third.acme-widgets.internal"),
                    "SecondCaPermission": {
                        "Type": "AWS::ACMPCA::Permission",
                        "Properties": {
                            "CertificateAuthorityArn": { "Ref": "SecondCa" },
                            "Principal": "acm.amazonaws.com",
                            "Actions": ["GetCertificate", "ListPermissions", "IssueCertificate"]
                        }
                    }
                },
                "Outputs": {
                    "SecondCaPermissionRef": { "Value": { "Ref": "SecondCaPermission" } }
                }
            })
            .to_string()
        },
        grants: &[Grant {
            logical_id: "SecondCaPermission",
            certificate_authority: "SecondCa",
            principal: ACM_PRINCIPAL,
            actions: &["GetCertificate", "ListPermissions", "IssueCertificate"],
            source_account: None,
        }],
        certificate_authorities: &["FirstCa", "SecondCa", "ThirdCa"],
    },
];

/// Every row: the stack completes, Amazon Web Services Private CA holds exactly the grants the
/// template declared — with the actions and the assigning account each declaration states —
/// and the identity the stack reports and exports for a grant is the CA-and-principal pair
/// that service addresses it by.
#[tokio::test]
async fn a_stack_grants_the_private_ca_permissions_its_template_declares() {
    let router = build_router();

    for (index, row) in ROWS.iter().enumerate() {
        let case = row.case;
        let region = row.region;
        let stack_name = format!("private-ca-permission-stack-{index}");
        let template = (row.template)();

        let (status, body) = cloudformation(
            &router,
            region,
            "CreateStack",
            &[("StackName", &stack_name), ("TemplateBody", &template)],
        )
        .await;
        assert_eq!(
            status, 200,
            "case {case:?}: expected HTTP 200 from CreateStack, got {status} with body {body}"
        );

        let (stack_status, described) =
            wait_for_status(&router, region, &stack_name, CREATE_COMPLETE).await;
        assert_eq!(
            stack_status, CREATE_COMPLETE,
            "case {case:?}: expected the stack to complete, got {stack_status:?} ({described})"
        );
        let outputs = outputs_of(&described);

        // The ARN that service minted for each declared CA, read off the stack's own record of
        // it: every expectation below about a grant is computed from it.
        let mut authorities: BTreeMap<&str, String> = BTreeMap::new();
        for logical_id in row.certificate_authorities {
            let (reported, body) = physical_id(&router, region, &stack_name, logical_id).await;
            let arn = reported.unwrap_or_default();
            assert!(
                arn.starts_with(&format!(
                    "arn:aws:acm-pca:{region}:{ACCOUNT}:certificate-authority/"
                )),
                "case {case:?}: expected {logical_id} to report the ARN that service minted, \
                 got {arn:?} ({body})"
            );
            authorities.insert(logical_id, arn);
        }

        for grant in row.grants {
            let ca_arn = authorities
                .get(grant.certificate_authority)
                .cloned()
                .unwrap_or_default();
            let expected_identity =
                format!("{ca_arn}{COMPOSITE_SEPARATOR}{}", grant.principal);

            // Rule 2: the stack reports the pair that service addresses the grant by, and the
            // output that exports its `Ref` carries that same value.
            let (reported, body) =
                physical_id(&router, region, &stack_name, grant.logical_id).await;
            assert_eq!(
                reported.as_deref(),
                Some(expected_identity.as_str()),
                "case {case:?}: expected {} to report {expected_identity:?}, got {reported:?} \
                 ({body})",
                grant.logical_id
            );
            let output_key = format!("{}Ref", grant.logical_id);
            assert_eq!(
                outputs.get(&output_key).map(String::as_str),
                Some(expected_identity.as_str()),
                "case {case:?}: expected output {output_key:?} to carry \
                 {expected_identity:?}, got {outputs:?}"
            );

            // Rule 1: the owning service holds the grant, and reports it with what the
            // declaration asked for.
            let (status, grants, answered) = granted_permissions(&router, region, &ca_arn).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected ListPermissions to answer for {ca_arn:?}, got {status} \
                 {answered:?}"
            );
            let Some(permission) = grants.get(grant.principal) else {
                panic!(
                    "case {case:?}: expected a grant to {:?} on {ca_arn:?}, got {grants:?}",
                    grant.principal
                )
            };
            assert_eq!(
                permission
                    .get("CertificateAuthorityArn")
                    .and_then(Value::as_str),
                Some(ca_arn.as_str()),
                "case {case:?}: expected the grant to report the CA it is on, got {permission:?}"
            );
            let reported_actions: Vec<String> = permission
                .get("Actions")
                .and_then(Value::as_array)
                .map(|actions| {
                    actions
                        .iter()
                        .map(|action| action.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(
                reported_actions,
                grant.reported_actions(),
                "case {case:?}: expected the declared actions, got {permission:?}"
            );
            assert_eq!(
                permission.get("SourceAccount").and_then(Value::as_str),
                Some(grant.reported_source_account()),
                "case {case:?}: expected the grant assigned from \
                 {:?}, got {permission:?}",
                grant.reported_source_account()
            );
        }

        // A CA the template grants nothing on holds no grant: what the deployment created is
        // the declared grants and nothing else.
        for logical_id in row.certificate_authorities {
            let granted_on = row
                .grants
                .iter()
                .filter(|grant| grant.certificate_authority == *logical_id)
                .count();
            let ca_arn = authorities.get(logical_id).cloned().unwrap_or_default();
            let (status, grants, answered) = granted_permissions(&router, region, &ca_arn).await;
            assert_eq!(
                status, 200,
                "case {case:?}: expected ListPermissions to answer for {logical_id}, got \
                 {status} {answered:?}"
            );
            assert_eq!(
                grants.len(),
                granted_on,
                "case {case:?}: expected {granted_on} grant(s) on {logical_id}, got {grants:?}"
            );
        }
    }
}

/// A deployment that no longer declares the grant REVOKES it: the CA the stack still declares
/// is left in place and `ListPermissions` on it goes empty, which is what lets a client audit
/// and revoke a permission a template made.
#[tokio::test]
async fn a_deployment_that_drops_the_declaration_revokes_the_grant() {
    let router = build_router();
    let case = "a grant dropped from the template";
    let region = "ap-southeast-2";
    let stack_name = "private-ca-permission-revoked";

    let certificate_authority = json!({
        "Type": "AWS::ACMPCA::CertificateAuthority",
        "Properties": {
            "Type": "ROOT",
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": { "CommonName": "root.acme-widgets.internal" }
        }
    });
    let granting = json!({
        "Resources": {
            "Ca": certificate_authority.clone(),
            "CaPermission": {
                "Type": "AWS::ACMPCA::Permission",
                "Properties": {
                    "CertificateAuthorityArn": { "Ref": "Ca" },
                    "Principal": ACM_PRINCIPAL,
                    "Actions": EVERY_ACTION
                }
            }
        }
    })
    .to_string();
    let without_the_grant = json!({ "Resources": { "Ca": certificate_authority } }).to_string();

    let (status, body) = cloudformation(
        &router,
        region,
        "CreateStack",
        &[("StackName", stack_name), ("TemplateBody", &granting)],
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from CreateStack, got {status} with body {body}"
    );
    let (stack_status, described) =
        wait_for_status(&router, region, stack_name, CREATE_COMPLETE).await;
    assert_eq!(
        stack_status, CREATE_COMPLETE,
        "case {case:?}: expected the stack to complete, got {stack_status:?} ({described})"
    );

    let (reported, body) = physical_id(&router, region, stack_name, "Ca").await;
    let ca_arn = reported.unwrap_or_else(|| {
        panic!("case {case:?}: the CA reports no PhysicalResourceId: {body}")
    });
    let (status, grants, answered) = granted_permissions(&router, region, &ca_arn).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected ListPermissions to answer, got {status} {answered:?}"
    );
    assert!(
        grants.contains_key(ACM_PRINCIPAL),
        "case {case:?}: expected the declared grant before the update, got {grants:?}"
    );

    // The same stack, deployed from a template that declares the CA alone.
    let (status, body) = cloudformation(
        &router,
        region,
        "UpdateStack",
        &[
            ("StackName", stack_name),
            ("TemplateBody", &without_the_grant),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected HTTP 200 from UpdateStack, got {status} with body {body}"
    );
    let (stack_status, described) =
        wait_for_status(&router, region, stack_name, UPDATE_COMPLETE).await;
    assert_eq!(
        stack_status, UPDATE_COMPLETE,
        "case {case:?}: expected the update to complete, got {stack_status:?} ({described})"
    );

    // The CA is still there, and holds nothing.
    let (status, authority) = acm_pca(
        &router,
        region,
        "DescribeCertificateAuthority",
        &json!({ "CertificateAuthorityArn": ca_arn }),
    )
    .await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected the CA to survive the update, got {status} {authority:?}"
    );
    let (status, grants, answered) = granted_permissions(&router, region, &ca_arn).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected ListPermissions to answer after the update, got {status} \
         {answered:?}"
    );
    assert!(
        grants.is_empty(),
        "case {case:?}: expected the grant revoked, got {grants:?}"
    );
}
