// SPDX-License-Identifier: CC0-1.0

//! The connection test a data source's create and update settle on.
//!
//! QuickSight does not store a data source and call it healthy: it tests the
//! connection the submitted `DataSourceParameters` describe, and the terminal
//! `ResourceStatus` the resource settles in is that test's OUTCOME — the successful
//! status with no `ErrorInfo` when the test passed, the failed one carrying a
//! [`DataSourceErrorInfo`] when it did not.
//!
//! What the test can decide here is what this emulator KNOWS. One parameter set names
//! a resource of another service in this same emulator — `AthenaParameters` names the
//! account's Athena workgroup — and that one is resolved against the store of the
//! service that OWNS it, so a data source cannot be reported as connected to a
//! workgroup Athena itself does not hold. Every other parameter set names a host, a
//! cluster or a hosted application OUTSIDE the emulator (a MySQL host, a Snowflake
//! account, a Jira site); nothing here can reach one, so there is no failure to
//! report for it and the test passes, exactly as it did before this module existed.
//! Credentials and `RoleArn` members are likewise not resolved: they name an identity
//! the connection assumes, not the source it connects to.
//!
//! LOCK ORDER: the resolution below takes the OWNING service's store lock, so a
//! caller runs the test BEFORE it takes this service's own store guard and never
//! holds both at once — which is what keeps a cycle between the two stores
//! unreachable.

use ::service_com_amazonaws_athena_amazonathena::state as athena;

use crate::ops::types::{DataSourceErrorInfo, DataSourceParameters};

/// `DataSourceErrorInfoType` of a connection test that reached the source's own
/// engine and was refused by it — the class a SQL source reports a failed connection
/// in (model enum `com.amazonaws.quicksight#DataSourceErrorInfoType`).
pub const DATA_SOURCE_ERROR_TYPE_GENERIC_SQL_FAILURE: &str = "GENERIC_SQL_FAILURE";

/// The `ErrorInfo.Message` of a connection test refused because the Athena workgroup
/// the parameters name does not exist.
///
/// The failure is Athena's, so the sentence is about the workgroup the request named:
/// fixed text plus that name. The per-call Athena request id such a message also
/// carries is a value of one run, so nothing here invents one.
pub fn athena_work_group_missing_message(work_group: &str) -> String {
    format!("Athena workgroup {work_group} is not found.")
}

/// The failure the connection test described by `parameters` reports, or `None` when
/// the test passes.
///
/// `None` for absent parameters as well: a data source created without any describes
/// no connection to test.
pub fn connection_test_error<Eng: Send + Sync + 'static>(
    engine: &Eng,
    parameters: Option<&DataSourceParameters>,
) -> Option<DataSourceErrorInfo> {
    let parameters = parameters?;
    match parameters {
        // The one connection target this emulator holds itself: the workgroup the
        // queries of this data source would run in. `WorkGroup` is optional, and a
        // connection that names none runs in the account's default workgroup, which
        // is the one Athena gives every account.
        DataSourceParameters::AthenaParameters(athena_parameters) => {
            let work_group = athena_parameters
                .work_group
                .as_deref()
                .unwrap_or(athena::DEFAULT_WORK_GROUP);
            if holds_athena_work_group(engine, work_group) {
                None
            } else {
                Some(DataSourceErrorInfo {
                    r#type: Some(DATA_SOURCE_ERROR_TYPE_GENERIC_SQL_FAILURE.to_string()),
                    message: Some(athena_work_group_missing_message(work_group)),
                })
            }
        }
        // Every other parameter set describes a source outside this emulator, so
        // there is nothing here to resolve it against and no failure to report.
        _ => None,
    }
}

/// Whether Athena holds the workgroup `work_group`, read out of Athena's OWN store —
/// the same set its `ListWorkGroups` reports, so the two cannot disagree.
///
/// An engine carrying no Athena store at all holds nothing to resolve against, so the
/// workgroup is not reported missing: a deployment without Athena is not evidence
/// that a workgroup does not exist.
fn holds_athena_work_group<Eng: Send + Sync + 'static>(engine: &Eng, work_group: &str) -> bool {
    match athena::service_state(engine) {
        Some(state) => state.lock().holds_work_group(work_group),
        None => true,
    }
}
