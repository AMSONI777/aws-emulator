// SPDX-License-Identifier: CC0-1.0

//! What `RegisterUser` reports when the addressed account's authentication method holds
//! no identity store for the identity type the registration asks for.
//!
//! Every case drives the real wire path — `MultiServiceRouter::dispatch` with a signed
//! restJson1 request — so what is asserted is what a QuickSight SDK client would see:
//! the status, the error code, and the message body the handler rendered.
//!
//! The rule under test: QuickSight reuses `AccessDeniedException` for every refusal an
//! account's own configuration or credentials cause, so the refusal of a registration
//! the account's authentication method forbids carries its reason in the message — the
//! account that is not authorized to create users of that identity type, followed by the
//! identity path's labelled fields naming that account and the namespace the call
//! addressed. The reason is a fact about the account and the namespace the REQUEST
//! named, so the rows below vary those (the account id, the authentication method that
//! holds no QuickSight identity store, and the namespace's name and length) rather than
//! re-running one recorded call.

use serde_json::{json, Value};

use service_com_amazonaws_quicksight_quicksight_20180401::state as qs_state;

use super::data_source_data_set_lifecycle::Harness;
use super::namespace_lifecycle::{create_namespace_in, settle_creation};

/// The region the harness signs for. The refusal names no region, which is one of the
/// things the rows below show.
const REGION: &str = "us-west-2";

/// The namespace every QuickSight account already has.
/// Source: smithy_query(query="operation", operation="RegisterUser") — `Namespace` is a
/// required label.
const DEFAULT_NAMESPACE: &str = "default";

/// The identity type whose users only an account with a QuickSight identity store of its
/// own may hold.
/// Source: smithy_query(query="shape", shape="IdentityType").
const IDENTITY_TYPE_QUICKSIGHT: &str = "QUICKSIGHT";

/// The one `AuthenticationMethodOption` member that gives an account a QuickSight
/// identity store of its own, for the positive control.
/// Source: smithy_query(query="shape", shape="AuthenticationMethodOption").
const IAM_AND_QUICKSIGHT: &str = "IAM_AND_QUICKSIGHT";

/// The message a registration the account's authentication method forbids reads.
///
/// Written out here rather than read from the service so a change to the wording fails
/// this suite: the sentence names the account and the identity type it may not create
/// users of, and the identity path's labelled fields follow it with no separating space,
/// ending in a period and a space.
pub(crate) fn identity_type_refusal_message(account: &str, namespace: &str) -> String {
    format!(
        "Account {account} is not authorized to create QuickSight IdentityType \
         user.AWS account id: {account}, Namespace: {namespace}. "
    )
}

/// `RegisterUser`: `POST /accounts/{AwsAccountId}/namespaces/{Namespace}/users`.
/// Source: smithy_query(query="operation", operation="RegisterUser").
async fn register_quicksight_user(
    harness: &Harness,
    account: &str,
    namespace: &str,
    user_name: &str,
) -> (u16, Value) {
    harness
        .call(
            "POST",
            &format!("/accounts/{account}/namespaces/{namespace}/users"),
            Some(json!({
                "IdentityType": IDENTITY_TYPE_QUICKSIGHT,
                "Email": format!("{user_name}@example.com"),
                "UserRole": "READER",
                "UserName": user_name,
            })),
        )
        .await
}

/// `DescribeUser`:
/// `GET /accounts/{AwsAccountId}/namespaces/{Namespace}/users/{UserName}`.
/// Source: smithy_query(query="operation", operation="DescribeUser").
async fn describe_user(
    harness: &Harness,
    account: &str,
    namespace: &str,
    user_name: &str,
) -> (u16, Value) {
    harness
        .call(
            "GET",
            &format!("/accounts/{account}/namespaces/{namespace}/users/{user_name}"),
            None,
        )
        .await
}

/// `CreateAccountSubscription`: `POST /account/{AwsAccountId}`, with the members the
/// chosen authentication method requires.
/// Source: smithy_query(query="operation", operation="CreateAccountSubscription").
async fn sign_up(harness: &Harness, account: &str, case: &str, subscription: Value) {
    let (status, body) = harness
        .call("POST", &format!("/account/{account}"), Some(subscription))
        .await;
    assert_eq!(
        status, 200,
        "case {case:?}: the sign-up fixture expected 200, got {status} with {body}"
    );
}

/// One row: an account signed up so that it holds no QuickSight identity store, and the
/// namespace a registration addresses in it.
struct Row {
    case: &'static str,
    account: &'static str,
    /// The sign-up this row performs, or `None` when the row signs nothing up — either
    /// because its account never subscribed at all, and so reports the service default,
    /// or because an earlier row already subscribed that account in this shared harness.
    subscription: Option<Value>,
    /// The namespace the registration addresses. `Namespace` is len 0..64 over
    /// `^[a-zA-Z0-9._-]*$`, so a name can hold a dot, a dash or an underscore.
    /// Source: smithy_query(query="shape", shape="Namespace").
    namespace: String,
    /// Whether this row's namespace has to be created first.
    create_namespace: bool,
}

/// The rows span what the rule generalises over: the authentication methods that hold no
/// QuickSight identity store (every member of `AuthenticationMethodOption` except the one
/// that does, plus the account that never subscribed), the account id, and the
/// namespace's name — the default one, one holding each separator the pattern admits, the
/// shortest one and the longest one the model's length bound admits.
/// Source: smithy_query(query="shape", shape="AuthenticationMethodOption") and
/// smithy_query(query="shape", shape="Namespace").
fn rows() -> Vec<Row> {
    vec![
        Row {
            case: "iam-only, the default namespace",
            account: "000000000000",
            subscription: Some(json!({
                "AccountName": "iam-only-users",
                "AuthenticationMethod": "IAM_ONLY",
                "NotificationEmail": "ops@example.com",
                "Edition": "ENTERPRISE",
            })),
            namespace: DEFAULT_NAMESPACE.to_string(),
            create_namespace: false,
        },
        Row {
            case: "iam-only, a namespace holding the separators the pattern admits",
            account: "000000000000",
            subscription: None,
            namespace: "people_ns-2026.eu".to_string(),
            create_namespace: true,
        },
        Row {
            case: "iam-only, the longest namespace the model admits",
            account: "000000000000",
            subscription: None,
            namespace: "n".repeat(64),
            create_namespace: true,
        },
        Row {
            case: "an account that never subscribed, another account id",
            account: "210987654321",
            subscription: None,
            namespace: DEFAULT_NAMESPACE.to_string(),
            create_namespace: false,
        },
        Row {
            case: "an account that never subscribed, the shortest namespace name",
            account: "210987654321",
            subscription: None,
            namespace: "n".to_string(),
            create_namespace: true,
        },
        Row {
            case: "iam-identity-center",
            account: "123456789012",
            subscription: Some(json!({
                "AccountName": "idc-users",
                "AuthenticationMethod": "IAM_IDENTITY_CENTER",
                "NotificationEmail": "ops@example.com",
                "Edition": "ENTERPRISE",
                "AdminGroup": ["quicksight-admins"],
                "IAMIdentityCenterInstanceArn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
            })),
            namespace: DEFAULT_NAMESPACE.to_string(),
            create_namespace: false,
        },
        Row {
            case: "active-directory, in a namespace of its own",
            account: "999999999999",
            subscription: Some(json!({
                "AccountName": "ad-users",
                "AuthenticationMethod": "ACTIVE_DIRECTORY",
                "NotificationEmail": "ops@example.com",
                "Edition": "ENTERPRISE",
                "ActiveDirectoryName": "corp.example.com",
                "Realm": "CORP.EXAMPLE.COM",
                "DirectoryId": "d-906787654321",
                "AdminGroup": ["corp-admins"],
            })),
            namespace: "corp-directory".to_string(),
            create_namespace: true,
        },
    ]
}

#[tokio::test]
async fn a_quicksight_identity_the_accounts_method_forbids_is_refused_by_account_and_namespace() {
    let harness = Harness::new();

    for row in rows() {
        let Row {
            case,
            account,
            subscription,
            namespace,
            create_namespace,
        } = row;

        if let Some(subscription) = subscription {
            sign_up(&harness, account, case, subscription).await;
        }
        if create_namespace {
            let (status, body) = create_namespace_in(
                &harness,
                REGION,
                account,
                json!({ "Namespace": namespace, "IdentityStore": "QUICKSIGHT" }),
            )
            .await;
            assert_eq!(
                status, 200,
                "case {case:?}: the namespace fixture expected 200, got {status} with {body}"
            );
            settle_creation(&harness, account, &namespace);
        }

        let user_name = format!("managed-{}", namespace.len());
        let (status, body) = register_quicksight_user(&harness, account, &namespace, &user_name).await;
        assert_eq!(
            status, 401,
            "case {case:?}: this account holds no QuickSight identity store, so the \
             registration expected 401, got {status} with {body}"
        );
        assert_eq!(
            body["__type"],
            json!("AccessDeniedException"),
            "case {case:?}: expected AccessDeniedException, got {body}"
        );
        let expected = identity_type_refusal_message(account, &namespace);
        assert_eq!(
            body["Message"],
            json!(expected),
            "case {case:?}: expected Message {expected:?}, got {body}"
        );

        // The refused registration persisted nothing, so the read answers accordingly.
        let (status, read) = describe_user(&harness, account, &namespace, &user_name).await;
        assert_eq!(
            status, 404,
            "case {case:?}: a refused registration must persist nothing, got {status} \
             with {read}"
        );
        assert_eq!(
            read["__type"],
            json!("ResourceNotFoundException"),
            "case {case:?}: expected ResourceNotFoundException, got {read}"
        );
        let state = qs_state::service_state(&*harness.engine).expect("the QuickSight store");
        let store = state.lock();
        assert!(
            store.user(account, &namespace, &user_name).is_none(),
            "case {case:?}: a refused registration must persist nothing"
        );
    }
}

#[tokio::test]
async fn the_same_registration_is_served_where_the_account_holds_a_quicksight_identity_store() {
    let harness = Harness::new();
    let account = "300000000003";
    sign_up(
        &harness,
        account,
        "iam-and-quicksight",
        json!({
            "AccountName": "quicksight-users",
            "AuthenticationMethod": IAM_AND_QUICKSIGHT,
            "NotificationEmail": "ops@example.com",
            "Edition": "ENTERPRISE",
        }),
    )
    .await;

    // The refusal is about the account's authentication method, so the very request the
    // rows above are refused is served here — and reads back.
    let user_name = "managed-user";
    let (status, body) =
        register_quicksight_user(&harness, account, DEFAULT_NAMESPACE, user_name).await;
    assert_eq!(
        status, 201,
        "this account holds a QuickSight identity store, so the registration expected \
         201, got {status} with {body}"
    );
    let (status, read) = describe_user(&harness, account, DEFAULT_NAMESPACE, user_name).await;
    assert_eq!(
        status, 200,
        "the registered user must read back, got {status} with {read}"
    );
    assert_eq!(
        read["User"]["IdentityType"],
        json!(IDENTITY_TYPE_QUICKSIGHT),
        "the read must report the identity type the registration asked for, got {read}"
    );
}
