// SPDX-License-Identifier: CC0-1.0

//! The version a published managed rule group currently has as its DEFAULT, end to
//! end over the wire.
//!
//! The rule asserted here: the version a vendor currently has as a managed rule
//! group's default is the NEWEST version it still offers, so whichever page of the
//! offered versions a caller asks for — `ListAvailableManagedRuleGroupVersions`
//! lists them newest first, at most `Limit` at a time —
//! `CurrentDefaultVersion` names a version on offer and is the FIRST entry of the
//! first page. A caller that enumerates the versions it may pin therefore always
//! finds the default among the ones it was handed, never a rung it has still to
//! page down to and never one the vendor has retired.
//!
//! Every expectation is composed from the service's own managed-rule-group
//! catalogue (`service_…::state::MANAGED_RULE_GROUP_CATALOGUE`), and the table spans
//! every group in it crossed with the page sizes the model's `PaginationLimit` range
//! admits — the longest published ladder and the groups that offer one version
//! alike.
//!
//! The order, paging and marker of that list are spanned by
//! [`crate::managed_rule_group_versions`]; what a retired version is refused as is
//! spanned by [`crate::managed_rule_group_version_expiry`].
//!
//! Every call goes through the router's front door with the harness in
//! [`crate::web_acl_lifecycle`], so what these tests observe is what an SDK
//! observes.

use serde_json::{json, Value};
use service_com_amazonaws_wafv2_awswaf_20190729::state::{
    ManagedRuleGroupDescriptor, MANAGED_RULE_GROUP_CATALOGUE, MAX_PAGE_SIZE,
};

use crate::web_acl_lifecycle::{create_web_acl, visibility, Waf};

/// A `ListAvailableManagedRuleGroupVersions` request body for `(vendor, name)` in
/// `scope`, asking for `limit` versions when the case names one.
fn request(scope: &str, vendor: &str, name: &str, limit: Option<i32>) -> Value {
    let mut body = json!({ "Scope": scope, "VendorName": vendor, "Name": name });
    if let Some(limit) = limit {
        body["Limit"] = json!(limit);
    }
    body
}

/// The version names a response lists, in the order it listed them.
fn listed_names(response: &Value) -> Vec<String> {
    response["Versions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|version| version["Name"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The newest version a group's vendor offers: the last of the versions the
/// catalogue keeps in release order, which is the first one the list reports.
fn newest_offered(group: &'static ManagedRuleGroupDescriptor) -> &'static str {
    group
        .versions
        .last()
        .unwrap_or_else(|| panic!("{}: a published group offers a version", group.name))
        .name
}

/// The page sizes every group is listed at: a page of one, a few small ones, one
/// the size of the longest published ladder, and both published bounds of the
/// model's `PaginationLimit` range (`range 1..100`, so 1 and [`MAX_PAGE_SIZE`]),
/// plus the request that names no `Limit` at all.
fn page_sizes() -> Vec<Option<i32>> {
    let longest = MANAGED_RULE_GROUP_CATALOGUE
        .iter()
        .map(|group| group.versions.len())
        .max()
        .expect("the catalogue publishes at least one group");
    let mut sizes = vec![None, Some(1), Some(2), Some(3), Some(10), Some(MAX_PAGE_SIZE)];
    if let Ok(longest) = i32::try_from(longest) {
        sizes.push(Some(longest));
    }
    sizes
}

/// Whichever page size a request names, the default version a group reports is the
/// newest version it offers and is listed on the page the call answered.
///
/// The table is the WHOLE catalogue crossed with [`page_sizes`] and both scopes, so
/// the group whose ladder is longest (where a default held at an earlier version
/// would fall off the first page) is covered beside the groups that offer a single
/// version.
#[tokio::test]
async fn the_default_version_is_the_newest_offered_and_on_the_first_page() {
    let waf = Waf::new();
    for group in MANAGED_RULE_GROUP_CATALOGUE {
        let newest = newest_offered(group);
        for scope in ["REGIONAL", "CLOUDFRONT"] {
            for limit in page_sizes() {
                let case = format!("{scope} {}/{} Limit={limit:?}", group.vendor_name, group.name);
                let page = waf
                    .ok(
                        "ListAvailableManagedRuleGroupVersions",
                        request(scope, group.vendor_name, group.name, limit),
                    )
                    .await;
                let reported = page["CurrentDefaultVersion"].as_str();
                assert_eq!(
                    reported,
                    Some(newest),
                    "case {case:?}: expected the newest offered version {newest:?} as \
                     the current default, got {reported:?} in {page}"
                );
                let listed = listed_names(&page);
                assert_eq!(
                    listed.first().map(String::as_str),
                    Some(newest),
                    "case {case:?}: the newest offered version heads the page, got \
                     {listed:?}"
                );
                assert!(
                    listed.iter().any(|name| name == newest),
                    "case {case:?}: the default {newest:?} must be among the versions \
                     the call listed, got {listed:?}"
                );
            }
        }
    }
}

/// The default version is one the vendor OFFERS, never one it has retired, and
/// `DescribeManagedRuleGroup` naming no version describes that same version — the
/// two operations read one catalogue, so they agree.
///
/// One row per published group per scope, which spans the groups whose vendor has
/// retired nothing, one version and several.
#[tokio::test]
async fn the_default_version_is_offered_and_describes_itself() {
    let waf = Waf::new();
    for group in MANAGED_RULE_GROUP_CATALOGUE {
        let newest = newest_offered(group);
        let retired: Vec<&str> = group
            .expired_versions
            .iter()
            .map(|release| release.name)
            .collect();
        assert!(
            !retired.contains(&newest),
            "case {:?}: the default {newest:?} must not be a version the vendor has \
             retired, got the retired list {retired:?}",
            group.name
        );

        for scope in ["REGIONAL", "CLOUDFRONT"] {
            let case = format!("{scope} {}/{}", group.vendor_name, group.name);
            let listed = waf
                .ok(
                    "ListAvailableManagedRuleGroupVersions",
                    request(scope, group.vendor_name, group.name, None),
                )
                .await;
            let default = listed["CurrentDefaultVersion"]
                .as_str()
                .unwrap_or_else(|| panic!("case {case:?}: a default version, got {listed}"));

            let described = waf
                .ok(
                    "DescribeManagedRuleGroup",
                    json!({
                        "Scope": scope,
                        "VendorName": group.vendor_name,
                        "Name": group.name,
                    }),
                )
                .await;
            assert_eq!(
                described["VersionName"],
                json!(default),
                "case {case:?}: a describe naming no version describes the default \
                 {default:?}, got {described}"
            );

            let pinned = waf
                .ok(
                    "DescribeManagedRuleGroup",
                    json!({
                        "Scope": scope,
                        "VendorName": group.vendor_name,
                        "Name": group.name,
                        "VersionName": default,
                    }),
                )
                .await;
            assert_eq!(
                pinned["VersionName"],
                json!(default),
                "case {case:?}: the default version is on offer, so naming it \
                 describes it, got {pinned}"
            );
        }
    }
}

/// The reported default version can be PINNED by a web ACL rule that runs the
/// group, and reads back verbatim: what the list reports as the default is a
/// version a `ManagedRuleGroupStatement` may name.
///
/// One row per published group, so the group with the longest ladder and the ones
/// offering a single version are both pinned.
#[tokio::test]
async fn the_default_version_can_be_pinned_by_a_web_acl_rule() {
    let waf = Waf::new();
    for (index, group) in MANAGED_RULE_GROUP_CATALOGUE.iter().enumerate() {
        let listed = waf
            .ok(
                "ListAvailableManagedRuleGroupVersions",
                request("REGIONAL", group.vendor_name, group.name, None),
            )
            .await;
        let default = listed["CurrentDefaultVersion"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: a default version, got {listed}", group.name))
            .to_string();
        let case = format!("{}@{default}", group.name);
        let acl_name = format!("default-version-{index}");
        let statement = json!({
            "ManagedRuleGroupStatement": {
                "VendorName": group.vendor_name,
                "Name": group.name,
                "Version": &default,
            }
        });
        let rules = json!([{
            "Name": "managed",
            "Priority": 0,
            "Statement": statement.clone(),
            "OverrideAction": { "None": {} },
            "VisibilityConfig": visibility("managed"),
        }]);
        let (acl_id, _arn, _lock) = create_web_acl(&waf, "REGIONAL", &acl_name, rules).await;
        let got = waf
            .ok(
                "GetWebACL",
                json!({ "Name": &acl_name, "Scope": "REGIONAL", "Id": &acl_id }),
            )
            .await;
        assert_eq!(
            got["WebACL"]["Rules"][0]["Statement"], statement,
            "case {case:?}: the pinned default must read back verbatim, got {got}"
        );
    }
}

/// The catalogue reading every expectation above composes itself from: each
/// group's default is the newest version it offers, which is one of the versions it
/// offers and none of the ones it has retired.
#[test]
fn the_published_default_is_the_newest_offered_version() {
    for group in MANAGED_RULE_GROUP_CATALOGUE {
        let case = format!("{}/{}", group.vendor_name, group.name);
        let default = group
            .current_default_version()
            .unwrap_or_else(|| panic!("case {case:?}: a published group offers a version"));
        assert_eq!(
            default,
            newest_offered(group),
            "case {case:?}: the default must be the newest offered version, got \
             {default:?}"
        );
        assert_eq!(
            group
                .versions_newest_first()
                .first()
                .map(|release| release.name),
            Some(default),
            "case {case:?}: the default heads the newest-first ladder, got {default:?}"
        );
        assert!(
            group
                .expired_versions
                .iter()
                .all(|release| release.name != default),
            "case {case:?}: the default {default:?} must not be retired"
        );
    }
}
