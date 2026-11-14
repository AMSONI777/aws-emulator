// SPDX-License-Identifier: CC0-1.0

//! The message text QuickSight's conflict and not-found refusals carry.
//!
//! QuickSight identifies the resource a refusal is about the way the service itself
//! does, and every handler that refuses the same error class renders the same
//! template, so the wording a client reads does not depend on which operation it
//! called. Two templates cover the resources this crate holds:
//!
//! * a resource addressed by an ARN (a folder, a data source, a data set, a theme)
//!   is named by that ARN — `"<Kind> <arn> already exists"` for a conflict and
//!   `"<Kind> <arn> is not found"` for a miss, neither ending in a period;
//! * a group or a user, which QuickSight's identity path serves, is named by its name
//!   together with the account it belongs to, and a refusal the account's own
//!   configuration causes is named by that account too — each of them closed by the
//!   labelled fields [`identity_scope_fields`] renders.
//!
//! A refusal about an allowance names the resource whose allowance ran out, and
//! that resource is the parent the counted children hang on, not the child the
//! refused call named.
//!
//! The ARN is built from the serving region and the request's own path labels by
//! the builders beside these in [`crate::state`], so the resource a message names
//! is the resource the request addressed.

use super::{data_set_arn, data_source_arn, folder_arn};

/// The resource kind a folder refusal names.
const FOLDER: &str = "Folder";

/// The resource kind a data-source refusal names — one word, as the service's own
/// `DataSource` shape spells it, not the two words its documentation prose uses.
const DATA_SOURCE: &str = "DataSource";

/// `"<kind> <arn> already exists"`: the conflict a create hits when the id it names
/// is already taken by a resource of that kind.
pub fn arn_exists_message(kind: &str, arn: &str) -> String {
    format!("{kind} {arn} already exists")
}

/// `"<kind> <arn> is not found"`: the miss any operation keyed on an absent resource
/// of that kind reports.
pub fn arn_not_found_message(kind: &str, arn: &str) -> String {
    format!("{kind} {arn} is not found")
}

/// The conflict `CreateFolder` reports for a `FolderId` the account already holds.
pub fn folder_exists_message(region: &str, aws_account_id: &str, folder_id: &str) -> String {
    arn_exists_message(FOLDER, &folder_arn(region, aws_account_id, folder_id))
}

/// The miss a folder operation reports for a `FolderId` the account holds no folder
/// under.
pub fn folder_not_found_message(region: &str, aws_account_id: &str, folder_id: &str) -> String {
    arn_not_found_message(FOLDER, &folder_arn(region, aws_account_id, folder_id))
}

/// The miss a data-source operation reports for a `DataSourceId` the account holds
/// no data source under — the same text whether the call reads, updates or deletes.
pub fn data_source_not_found_message(
    region: &str,
    aws_account_id: &str,
    data_source_id: &str,
) -> String {
    arn_not_found_message(
        DATA_SOURCE,
        &data_source_arn(region, aws_account_id, data_source_id),
    )
}

/// The refusal a data-set write reports for a physical table naming a data source
/// whose connection test failed: the data source by the ARN the request carried, and
/// the status that data source is in now. No trailing period.
pub fn data_source_status_message(data_source_arn: &str, status: &str) -> String {
    format!("{DATA_SOURCE} {data_source_arn} is in status {status}")
}

/// The per-data-set ceiling `CreateRefreshSchedule` reports once a data set already
/// holds every refresh schedule it may hold.
///
/// The exhausted resource is the data set the schedules refresh, so the sentence
/// carries the allowance and that data set's ARN — QuickSight's refresh path calls a
/// data set it prepares for SPICE a prepared data source — rather than the schedule
/// the refused call named. No trailing period.
pub fn refresh_schedule_limit_message(
    region: &str,
    aws_account_id: &str,
    data_set_id: &str,
    max: usize,
) -> String {
    format!(
        "Reached max limit of {max} refresh schedules for preparedDataSource {}",
        data_set_arn(region, aws_account_id, data_set_id)
    )
}

/// The labelled fields QuickSight's identity path closes a refusal with: the account
/// the call addressed, then one field naming what inside that account the refusal is
/// about, ending in a period and a space.
///
/// The sentence before them already ends in its own punctuation, so these fields follow
/// it directly — the caller joins the two with no separator of its own.
fn identity_scope_fields(aws_account_id: &str, label: &str, value: &str) -> String {
    format!("AWS account id: {aws_account_id}, {label}: {value}. ")
}

/// The conflict `CreateGroup` reports for a group name its namespace already holds.
///
/// QuickSight's identity path names the group rather than an ARN, and reports the
/// account it belongs to and the group name as labelled fields after the sentence,
/// which ends in a period and a space.
pub fn group_exists_message(group_name: &str, aws_account_id: &str) -> String {
    format!(
        "Group {group_name} already exists. {}",
        identity_scope_fields(aws_account_id, "groupName", group_name)
    )
}

/// The refusal a registration of an identity type the addressed account's
/// authentication method holds no identity store for reports.
///
/// What forbids the registration is a fact about the ACCOUNT — the authentication
/// method its QuickSight subscription chose — so the sentence names that account and the
/// identity type it may not create users of, spelled the way QuickSight writes that
/// type's name in prose rather than as the enum member
/// (`IdentityType`, [`super::IDENTITY_TYPE_QUICKSIGHT_NAME`]). The identity path's
/// labelled fields then report the account again and the namespace the registration
/// addressed.
pub fn identity_type_not_authorized_message(
    aws_account_id: &str,
    namespace: &str,
    identity_type_name: &str,
) -> String {
    format!(
        "Account {aws_account_id} is not authorized to create {identity_type_name} \
         IdentityType user.{}",
        identity_scope_fields(aws_account_id, "Namespace", namespace)
    )
}

/// The conflict `RegisterUser` reports for a user name its namespace already holds.
///
/// A user is a resource of the same identity path a group is, so it is named the same
/// way: the user name in the sentence, then the account it belongs to and that name as
/// labelled fields, ending in a period and a space.
pub fn user_exists_message(user_name: &str, aws_account_id: &str) -> String {
    format!(
        "User {user_name} already exists. {}",
        identity_scope_fields(aws_account_id, "userName", user_name)
    )
}

/// The miss a user operation reports for a `UserName` the namespace holds no user
/// under — the same text whether the call reads, updates or deletes, and the same
/// template the group reads answer a group nobody holds with.
pub fn user_not_found_message(user_name: &str, namespace: &str, aws_account_id: &str) -> String {
    format!("User {user_name} not found in namespace {namespace} in account {aws_account_id}.")
}
