// SPDX-License-Identifier: CC0-1.0

//! What a VENDOR publishes about its managed rule groups: the description its
//! catalogue entry carries, and the version ladder it offers — end to end over the
//! wire.
//!
//! The rules asserted here:
//!
//! * `ListAvailableManagedRuleGroups` reports, per group, the description its
//!   PUBLISHER states for the catalogue entry, verbatim
//!   (`ManagedRuleGroupSummary$Description` is "the description of the managed rule
//!   group, provided by Amazon Web Services Managed Rules or the Amazon Web
//!   Services Marketplace seller who manages it"). That text is fixed per group and
//!   is NOT the one-line summary a managed product carries
//!   (`ManagedProductDescriptor$ProductDescription` is "a SHORT description of the
//!   managed rule group").
//! * `ListAvailableManagedRuleGroupVersions` reports the whole ladder of versions
//!   the group's vendor offers, newest first, beside the version the vendor
//!   currently has as the default — the newest version it still offers.
//!   A version the vendor published and has since retired — a gap in the ladder —
//!   is no longer offered and is refused as EXPIRED rather than as a version nobody
//!   published.
//!
//! The order, the paging and the marker of that list, and the ladder of every other
//! catalogued group, are spanned by [`crate::managed_rule_group_versions`]; what the
//! WCUs of a rule set holding managed rule groups cost is spanned by
//! [`crate::check_capacity`]. The tables here are the ones those suites cannot
//! compose from the catalogue, because they are the published data ITSELF: the whole
//! catalogue's descriptions against the publisher's own sentences, and the longest
//! published ladder written out.
//!
//! Every call goes through the router's front door with the harness in
//! [`crate::web_acl_lifecycle`], so what these tests observe is what an SDK
//! observes.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use service_com_amazonaws_wafv2_awswaf_20190729::state::MANAGED_RULE_GROUP_CATALOGUE;

use crate::web_acl_lifecycle::Waf;

/// Published catalogue descriptions, each as its publisher states it for the entry
/// `ListAvailableManagedRuleGroups` reports.
///
/// Source: WAF's published managed-rule-group catalogue, as a recorded
/// `ListAvailableManagedRuleGroups` response carries it in
/// `ManagedRuleGroupSummary$Description`. Some rows are sentences an issue report
/// quotes verbatim; the rest are groups no report quoted, so the table checks the
/// catalogue against the publisher rather than against the one entry an example
/// cited.
///
/// The rows span the forms the publisher's own text takes: a sentence that opens
/// "Contains rules…" and one that opens "This group contains rules…", a one-sentence
/// entry and multi-sentence ones, and the PAIR of near-twin OS-family groups whose
/// sentences differ only in their tails — the publisher states one text per entry,
/// so neither is a template filled in from the group's name.
const PUBLISHED_DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "AWSManagedRulesCommonRuleSet",
        "Contains rules that are generally applicable to web applications. This \
         provides protection against exploitation of a wide range of \
         vulnerabilities, including those described in OWASP publications.",
    ),
    (
        "AWSManagedRulesAdminProtectionRuleSet",
        "Contains rules that allow you to block external access to exposed admin \
         pages. This may be useful if you are running third-party software or \
         would like to reduce the risk of a malicious actor gaining \
         administrative access to your application.",
    ),
    (
        "AWSManagedRulesSQLiRuleSet",
        "Contains rules that allow you to block request patterns associated with \
         exploitation of SQL databases, like SQL injection attacks. This can help \
         prevent remote injection of unauthorized queries.",
    ),
    (
        "AWSManagedRulesAmazonIpReputationList",
        "This group contains rules that are based on Amazon threat intelligence. \
         This is useful if you would like to block sources associated with bots or \
         other threats.",
    ),
    (
        "AWSManagedRulesWordPressRuleSet",
        "The WordPress Applications group contains rules that block request \
         patterns associated with the exploitation of vulnerabilities specific to \
         WordPress sites.",
    ),
    (
        "AWSManagedRulesLinuxRuleSet",
        "Contains rules that block request patterns associated with exploitation \
         of vulnerabilities specific to Linux, including LFI attacks. This can \
         help prevent attacks that expose file contents or execute code for which \
         the attacker should not have had access.",
    ),
    (
        "AWSManagedRulesUnixRuleSet",
        "Contains rules that block request patterns associated with exploiting \
         vulnerabilities specific to POSIX/POSIX-like OS, including LFI attacks. \
         This can help prevent attacks that expose file contents or execute code \
         for which access should not been allowed.",
    ),
    (
        "AWSManagedRulesPHPRuleSet",
        "Contains rules that block request patterns associated with exploiting \
         vulnerabilities specific to the use of the PHP, including injection of \
         unsafe PHP functions. This can help prevent exploits that allow an \
         attacker to remotely execute code or commands.",
    ),
    (
        "AWSManagedRulesAnonymousIpList",
        "This group contains rules that allow you to block requests from services \
         that allow obfuscation of viewer identity. This can include request \
         originating from VPN, proxies, Tor nodes, and hosting providers. This is \
         useful if you want to filter out viewers that may be trying to hide \
         their identity from your application.",
    ),
];

/// The two near-twin OS-family groups: their published sentences share an opening
/// and differ in the tail, which is what a per-group published text looks like and a
/// generated one does not.
const NEAR_TWIN_GROUPS: (&str, &str) = ("AWSManagedRulesLinuxRuleSet", "AWSManagedRulesUnixRuleSet");

/// The versions WAF publishes of the core rule set, NEWEST first.
///
/// Source: a recorded `ListAvailableManagedRuleGroupVersions` response for
/// `(AWS, AWSManagedRulesCommonRuleSet)` — the group with the longest published
/// ladder. Its gaps are the versions its vendor has retired
/// ([`CORE_RULE_SET_RETIRED`]).
const CORE_RULE_SET_LADDER: &[&str] = &[
    "Version_1.22",
    "Version_1.21",
    "Version_1.20",
    "Version_1.19",
    "Version_1.18",
    "Version_1.17",
    "Version_1.16",
    "Version_1.15",
    "Version_1.14",
    "Version_1.12",
    "Version_1.11",
    "Version_1.10",
    "Version_1.9",
    "Version_1.8",
    "Version_1.7",
    "Version_1.6",
    "Version_1.4",
    "Version_1.3",
    "Version_1.1",
    "Version_1.0",
];

/// The version the core rule set's vendor currently has as its default: the newest
/// entry of [`CORE_RULE_SET_LADDER`], which is the one a caller paging the ladder
/// newest first is handed first. That the default is the newest offered version of
/// EVERY published group, at every page size, is spanned by
/// [`crate::managed_rule_group_default_version`].
const CORE_RULE_SET_DEFAULT: &str = "Version_1.22";

/// The version names missing from [`CORE_RULE_SET_LADDER`]: the ones its vendor
/// published and has since retired, each still known to the describe.
const CORE_RULE_SET_RETIRED: &[&str] = &["Version_1.2", "Version_1.5", "Version_1.13"];

/// The core rule set, whose ladder the rows above are written for, and the vendor
/// that publishes it.
const CORE_RULE_SET: &str = "AWSManagedRulesCommonRuleSet";
const AWS_VENDOR: &str = "AWS";

/// The summaries `ListAvailableManagedRuleGroups` answers in `scope`.
async fn summaries(waf: &Waf, scope: &str) -> Vec<Value> {
    waf.ok("ListAvailableManagedRuleGroups", json!({ "Scope": scope }))
        .await["ManagedRuleGroups"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// Every group's published description, gathered by PAGING the catalogue at
/// `limit` groups a page: the whole list a caller sees whichever page size it asks
/// for.
async fn paged_descriptions(waf: &Waf, scope: &str, limit: Option<usize>) -> BTreeMap<String, String> {
    let mut gathered = BTreeMap::new();
    let mut marker: Option<String> = None;
    let mut terminated = false;
    // One page per catalogued group, plus the empty page that ends a paginator's
    // loop, is the most a caller can need; running past that is a paginator that
    // never ends, which the assertion below reports rather than hiding.
    for _ in 0..=MANAGED_RULE_GROUP_CATALOGUE.len() + 1 {
        let mut request = json!({ "Scope": scope });
        if let Some(limit) = limit {
            request["Limit"] = json!(limit);
        }
        if let Some(marker) = &marker {
            request["NextMarker"] = json!(marker);
        }
        let page = waf.ok("ListAvailableManagedRuleGroups", request).await;
        for summary in page["ManagedRuleGroups"].as_array().unwrap_or(&vec![]) {
            gathered.insert(
                summary["Name"].as_str().unwrap_or_default().to_string(),
                summary["Description"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
        }
        match page["NextMarker"].as_str() {
            Some(next) => marker = Some(next.to_string()),
            None => {
                terminated = true;
                break;
            }
        }
    }
    assert!(
        terminated,
        "case {scope:?} at {limit:?} a page: paging must end on a page with no \
         marker, got {gathered:?}"
    );
    gathered
}

/// The version names a `ListAvailableManagedRuleGroupVersions` response lists, in
/// the order it listed them.
fn listed_versions(response: &Value) -> Vec<String> {
    response["Versions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|version| version["Name"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// A `ListAvailableManagedRuleGroupVersions` request body for the core rule set.
fn core_rule_set_versions_request() -> Value {
    json!({ "Scope": "REGIONAL", "VendorName": AWS_VENDOR, "Name": CORE_RULE_SET })
}

/// Every listed summary carries the description its group's publisher states for
/// the catalogue entry, verbatim — in either scope, because the groups on offer are
/// the vendors' and a scope is only the namespace a request is made in — and that
/// text is a different published statement from the short product description the
/// same group's managed-product entry carries.
///
/// The table is the WHOLE catalogue crossed with both scopes, plus the literal rows
/// of [`PUBLISHED_DESCRIPTIONS`], which check the served text against the
/// publisher's own sentences rather than against the catalogue constant.
#[tokio::test]
async fn every_group_lists_the_description_its_publisher_states() {
    let waf = Waf::new();
    for scope in ["REGIONAL", "CLOUDFRONT"] {
        let listed = summaries(&waf, scope).await;
        assert_eq!(
            listed.len(),
            MANAGED_RULE_GROUP_CATALOGUE.len(),
            "case {scope:?}: expected one summary per published group, got {listed:?}"
        );

        for group in MANAGED_RULE_GROUP_CATALOGUE {
            let case = format!("{scope}/{}", group.name);
            let summary = listed
                .iter()
                .find(|summary| summary["Name"] == json!(group.name))
                .unwrap_or_else(|| panic!("case {case:?}: the group must be listed"));
            assert_eq!(
                summary["Description"],
                json!(group.description),
                "case {case:?}: expected the publisher's catalogue description {:?}, \
                 got {summary}",
                group.description
            );
            assert_ne!(
                summary["Description"],
                json!(group.product_description),
                "case {case:?}: the catalogue description is the publisher's own \
                 text for the entry, not the short product description, got {summary}"
            );
        }

        for (group, expected) in PUBLISHED_DESCRIPTIONS {
            let case = format!("{scope}/{group}");
            let summary = listed
                .iter()
                .find(|summary| summary["Name"] == json!(group))
                .unwrap_or_else(|| panic!("case {case:?}: the group must be listed"));
            assert_eq!(
                summary["Description"],
                json!(expected),
                "case {case:?}: expected the published description {expected:?}, got \
                 {summary}"
            );
        }
    }
}

/// Each group's published sentence travels with the GROUP, not with the page it
/// arrives on: the catalogue paged one group at a time, three at a time and in a
/// single full page reports the same text per group, byte for byte, in either
/// scope. And the two near-twin OS-family groups keep their distinct published
/// tails, so what is served is the publisher's text per entry rather than one
/// sentence composed from the entry's name.
///
/// The rows differ along page size and scope — the dimensions a caller can vary on
/// a pure catalogue read — and the expectations are the literal published sentences
/// of [`PUBLISHED_DESCRIPTIONS`], which include groups no report quoted.
#[tokio::test]
async fn the_published_description_follows_the_group_through_every_page_size() {
    let waf = Waf::new();
    for scope in ["REGIONAL", "CLOUDFRONT"] {
        let whole = paged_descriptions(&waf, scope, None).await;
        assert_eq!(
            whole.len(),
            MANAGED_RULE_GROUP_CATALOGUE.len(),
            "case {scope:?}: paging must reach every published group, got {whole:?}"
        );

        for limit in [1, 3, MANAGED_RULE_GROUP_CATALOGUE.len()] {
            let paged = paged_descriptions(&waf, scope, Some(limit)).await;
            assert_eq!(
                paged, whole,
                "case {scope:?} at {limit} a page: the published descriptions must \
                 not depend on the page size, got {paged:?}"
            );

            for (group, published) in PUBLISHED_DESCRIPTIONS {
                let case = format!("{scope}/{group} at {limit} a page");
                let served = paged.get(*group);
                assert_eq!(
                    served.map(String::as_str),
                    Some(*published),
                    "case {case:?}: expected the publisher's sentence {published:?}, \
                     got {served:?}"
                );
            }

            let (linux, posix) = NEAR_TWIN_GROUPS;
            assert_ne!(
                paged.get(linux),
                paged.get(posix),
                "case {scope:?} at {limit} a page: each group carries its own \
                 published sentence, got {:?} and {:?}",
                paged.get(linux),
                paged.get(posix)
            );
        }
    }
}

/// The longest published ladder, as its vendor offers it: every version newest
/// first, the page's own last version as `NextMarker`, and the vendor's default —
/// the newest release on offer.
#[tokio::test]
async fn the_published_ladder_is_offered_newest_first_with_the_vendors_default() {
    let waf = Waf::new();
    let core = waf
        .ok(
            "ListAvailableManagedRuleGroupVersions",
            core_rule_set_versions_request(),
        )
        .await;

    let expected: Vec<String> = CORE_RULE_SET_LADDER
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    assert_eq!(
        listed_versions(&core),
        expected,
        "case \"the core rule set's published ladder\": expected {expected:?}, got \
         {core}"
    );
    assert_eq!(
        core["NextMarker"],
        json!(expected.last()),
        "case \"the core rule set's published ladder\": NextMarker must name the last \
         version on the page, got {core}"
    );
    assert_eq!(
        core["CurrentDefaultVersion"],
        json!(CORE_RULE_SET_DEFAULT),
        "case \"the core rule set's default version\": expected the vendor's \
         default, got {core}"
    );
    assert_eq!(
        core["CurrentDefaultVersion"],
        json!(CORE_RULE_SET_LADDER.first()),
        "case \"the core rule set's default version\": the default is the newest \
         version on offer, got {core}"
    );
    for version in &expected {
        let at = core["Versions"]
            .as_array()
            .and_then(|versions| {
                versions
                    .iter()
                    .find(|listed| listed["Name"] == json!(version))
            })
            .and_then(|listed| listed["LastUpdateTimestamp"].as_f64());
        assert!(
            at.is_some(),
            "case {version:?}: every offered version reports when its vendor last \
             updated it, got {core}"
        );
    }
}

/// A version the vendor has RETIRED — one of the gaps in the published ladder — is
/// not offered, and a call naming it is refused as EXPIRED, while a name no version
/// of the group ever carried is refused differently. One row per retired version,
/// per never-published name, and per offered version the rows above name.
#[tokio::test]
async fn a_retired_version_is_expired_rather_than_unpublished() {
    let waf = Waf::new();
    let listed = listed_versions(
        &waf.ok(
            "ListAvailableManagedRuleGroupVersions",
            core_rule_set_versions_request(),
        )
        .await,
    );

    for retired in CORE_RULE_SET_RETIRED {
        assert!(
            !listed.contains(&(*retired).to_string()),
            "case {retired:?}: a retired version is no longer offered, got {listed:?}"
        );
        waf.refused(
            "DescribeManagedRuleGroup",
            json!({
                "Scope": "REGIONAL",
                "VendorName": AWS_VENDOR,
                "Name": CORE_RULE_SET,
                "VersionName": retired,
            }),
            "WAFExpiredManagedRuleGroupVersionException",
            retired,
        )
        .await;
    }

    for unpublished in ["Version_9.99", "Version_1.2.1"] {
        let (status, body) = waf
            .call(
                "DescribeManagedRuleGroup",
                json!({
                    "Scope": "REGIONAL",
                    "VendorName": AWS_VENDOR,
                    "Name": CORE_RULE_SET,
                    "VersionName": unpublished,
                }),
            )
            .await;
        assert_eq!(
            status, 400,
            "case {unpublished:?}: a version nobody published must be refused, got \
             status {status} and body {body}"
        );
        let code = body["__type"].as_str().unwrap_or_default();
        assert!(
            !code.ends_with("WAFExpiredManagedRuleGroupVersionException"),
            "case {unpublished:?}: a version nobody published is told apart from a \
             retired one, got {body}"
        );
    }

    for offered in [CORE_RULE_SET_DEFAULT, CORE_RULE_SET_LADDER[1]] {
        let described = waf
            .ok(
                "DescribeManagedRuleGroup",
                json!({
                    "Scope": "REGIONAL",
                    "VendorName": AWS_VENDOR,
                    "Name": CORE_RULE_SET,
                    "VersionName": offered,
                }),
            )
            .await;
        assert_eq!(
            described["VersionName"],
            json!(offered),
            "case {offered:?}: an offered version describes itself, got {described}"
        );
    }
}
