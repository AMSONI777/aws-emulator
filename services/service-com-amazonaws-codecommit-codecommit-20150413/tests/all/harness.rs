// SPDX-License-Identifier: CC0-1.0

//! The readers and assertion helpers the repository suites share, over the wire
//! harness this test target already has.
//!
//! Driving the service — building the emulator, signing a call, asserting a status,
//! reading a value out of a payload — is [`crate::repository_lifecycle`]'s harness
//! (itself signing through [`crate::wire`]), and this module adds nothing to it. What
//! lives here is what more than one repository suite needs: the `GetRepository`
//! metadata projection a stored repository is read back through, the timestamp reader
//! its date members are compared with, the reader that answers a failed call's
//! error code AND the message text that came with it, the selector a repository with
//! no key of its own is encrypted under together with the readings of the KEY that
//! selector resolves to, and the wording CodeCommit
//! refuses a `pullRequestId` or a `revisionId` naming nothing with. One definition
//! each, so two suites cannot disagree about what "the stored repository", "that
//! instant", "that error's message", "that repository's key" or "that refusal's
//! words" means.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::repository_lifecycle::ok;

/// The `repositoryMetadata` a `GetRepository` read reports for a name — the one
/// projection the repository suites read a stored repository through.
pub(crate) async fn metadata_of(router: &MultiServiceRouter, name: &str) -> Value {
    let got = ok(router, "GetRepository", &json!({ "repositoryName": name })).await;
    got.get("repositoryMetadata")
        .unwrap_or_else(|| panic!("no repositoryMetadata for {name:?} in {got}"))
        .clone()
}

/// The Amazon Web Services managed key a repository created without a `kmsKeyId`
/// of its own is encrypted under, by the alias KMS names that key by:
/// `CreateRepository`'s `kmsKeyId` documents that "If no key is specified, the
/// default aws/codecommit Amazon Web Services managed key is used"
/// (`smithy_query(query="doc",shape="CreateRepositoryInput",member="kmsKeyId")`).
/// What a repository REPORTS is the key that alias resolves to
/// ([`managed_encryption_key_arn`]), never the alias.
pub(crate) const DEFAULT_ENCRYPTION_KEY_ALIAS: &str = "alias/aws/codecommit";

/// The ARN of a KMS key id: `arn:<partition>:kms:<region>:<account>:key/<key id>`
/// — the identifier KMS reports a key by, and the form a repository's key is
/// reported in once a bare key id has been resolved to it. Built for the Region
/// every suite signs for ([`crate::repository_lifecycle::REGION`]) and the account
/// every ARN this emulator mints is scoped to.
pub(crate) fn kms_key_arn_of(key_id: &str) -> String {
    format!(
        "arn:aws:kms:{}:{}:key/{key_id}",
        crate::repository_lifecycle::REGION,
        engine::emulator_account_id()
    )
}

/// The ARN of the key KMS holds for `selector` at `region`'s endpoint, read out of
/// the KMS store on the shared engine — the key ITSELF, which is what a
/// repository's `kmsKeyId` reports once the selector it was named by has been
/// resolved. `None` when that endpoint holds no key for the selector.
///
/// Read-only: a lookup resolves a key without associating one, so asking this does
/// not give a predefined Amazon Web Services alias a key — which is what lets a
/// suite check that the CODECOMMIT call is what materialised the managed key.
pub(crate) fn kms_key_arn_for(
    engine: &engine::InMemoryEngine,
    region: &str,
    selector: &str,
) -> Option<String> {
    use service_com_amazonaws_kms_trentservice::state as kms;

    let keys = kms::service_state(engine).expect("the in-memory engine carries the KMS store");
    let keys = keys.lock();
    match keys.resolve(region, selector) {
        kms::KeyRef::Found(key) => Some(key.arn.clone()),
        _ => None,
    }
}

/// The key a repository created with no `kmsKeyId` of its own is encrypted under:
/// the Amazon Web Services managed key KMS holds for this service's predefined
/// alias ([`DEFAULT_ENCRYPTION_KEY_ALIAS`]) in the Region the suites sign for.
///
/// Panics when KMS holds no key for that alias, which is the defect itself: a
/// repository was created without the key behind the alias ever being resolved.
pub(crate) fn managed_encryption_key_arn(engine: &engine::InMemoryEngine) -> String {
    kms_key_arn_for(
        engine,
        crate::repository_lifecycle::REGION,
        DEFAULT_ENCRYPTION_KEY_ALIAS,
    )
    .unwrap_or_else(|| {
        panic!("KMS holds no key for {DEFAULT_ENCRYPTION_KEY_ALIAS}: nothing resolved the alias")
    })
}

/// The key a repository SEEDED straight into the store is encrypted under: this
/// service's own resolution of a create that names no key, so a seeded repository
/// carries exactly what `CreateRepository` would have stored for it.
pub(crate) fn seeded_encryption_key(engine: &engine::InMemoryEngine, region: &str) -> String {
    service_com_amazonaws_codecommit_codecommit_20150413::state::resolve_encryption_key(
        engine, region, None,
    )
}

/// A modelled timestamp member as epoch seconds. awsJson1_1 renders a timestamp as
/// an epoch-seconds number with a fractional part, so instants milliseconds apart
/// are distinguishable here.
pub(crate) fn seconds_at(metadata: &Value, member: &str) -> f64 {
    metadata
        .get(member)
        .and_then(Value::as_f64)
        .unwrap_or_else(|| panic!("no numeric {member} in {metadata}"))
}

/// The modeled error code AND the message text of a failed call by the default
/// caller, with the status asserted — for a suite whose subject is the message
/// rather than the code.
///
/// `crate::repository_lifecycle::error` answers the code alone, which is what a
/// suite checking WHICH error was raised needs. This is the same parse as
/// [`crate::wire::refusal_as`] — it IS that function, bound to the default
/// principal — so there is one definition of how an error's code and message are
/// read off the wire.
pub(crate) async fn error_with_message(
    router: &MultiServiceRouter,
    operation: &str,
    body: &Value,
    expected_status: u16,
) -> (String, String) {
    crate::wire::refusal_as(
        router,
        crate::wire::DEFAULT_ACCESS_KEY_ID,
        operation,
        body,
        expected_status,
    )
    .await
}

/// `InvalidPullRequestIdException`'s message for a pull request id that is not one,
/// as CodeCommit words it: the offending value named in the sentence, then the
/// operation a caller lists the valid ids with.
pub(crate) fn invalid_pull_request_id(pull_request_id: &str) -> String {
    format!(
        "The following pull request ID is not valid: {pull_request_id}. To view a list of valid \
         pull request IDs for this repository, use ListPullRequests."
    )
}

/// `InvalidPullRequestIdException`'s message for a pull request id that was carried
/// but holds no characters: the same sentence, with the clause that says the value
/// was empty or null.
pub(crate) fn empty_pull_request_id(pull_request_id: &str) -> String {
    format!(
        "The following pull request ID is empty or null and therefore not valid: \
         {pull_request_id}. To view a list of valid pull request IDs for this repository, use \
         ListPullRequests."
    )
}

/// `InvalidRevisionIdException`'s message for a revision id that was carried but
/// holds no characters. A revision id's wording names no value.
pub(crate) const EMPTY_REVISION_ID: &str =
    "A revision ID is required, but the value is either empty or null.";

/// `InvalidRevisionIdException`'s message for a revision id that is not the FORM one
/// takes: the requirement, then the length a revision id holds, then where the
/// current one is read from.
pub(crate) const INVALID_REVISION_ID: &str =
    "A revision ID is required, but the value is not valid. Revision IDs are 64 characters in \
     length. To retrieve a valid revision ID, use GetPullRequest.";

/// `PullRequestDoesNotExistException`'s message: a FIXED sentence pair that names no
/// value — not the id the request asked for, and not a repository — and points a
/// caller at the operation that lists the ids that do exist.
pub(crate) const PULL_REQUEST_DOES_NOT_EXIST: &str =
    "The pull request ID does not exist. Verify that you provided a valid pull request ID, and \
     then try your operation again. To get a list of pull request IDs, use ListPullRequests.";
