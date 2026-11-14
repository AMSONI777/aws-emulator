// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for `Parameter$SupportedEngineModes` on a DB CLUSTER parameter.
//!
//! RULE: the member is answered about the PARAMETER — it is one of that parameter's published
//! columns, like its apply type or its allowed values, and it names the DB engine mode a
//! cluster has to run in for the parameter to apply — so it is the SAME list for a parameter
//! whichever family of its engine publishes it, and it is NOT the set of modes the family's
//! engine VERSIONS publish (`DBEngineVersion$SupportedEngineModes`, which the engine-version
//! report answers per version and which says nothing about any one parameter).
//!
//! The rule is asserted over a TABLE derived from the engine-version catalogue rather than
//! over one request: every DB cluster parameter group family that catalogue publishes, for
//! every engine with a cluster form, read back through both reports that project a cluster
//! parameter —
//!
//! * `DescribeEngineDefaultClusterParameters`, the engine's own defaults for a family, and
//! * `DescribeDBClusterParameters`, a GROUP of that family, before and after a caller sets a
//!   value (the two halves of a group's listing: `engine-default` and `user`).
//!
//! The rows that make the table span the class are the families whose engine versions publish
//! MORE than one engine mode — an Aurora release line with an Aurora Serverless v1 version
//! beside its provisioned ones — which the table is asserted to contain, beside the families
//! whose versions publish one.

use std::collections::{BTreeMap, BTreeSet};

use service_com_amazonaws_rds_amazonrdsv19::state::{
    DB_CLUSTER_ENGINES, DB_INSTANCE_ENGINES, SIBLING_CONTROL_PLANE_ENGINES,
};
use smithy_server_runtime::MultiServiceRouter;

use crate::cluster_parameter_groups::{create_group, modify};
use crate::db_engine_versions::{all_versions_of, list_members};
use crate::db_instances::{call, emulator, expect_ok, optional_text, subtrees, text};

/// The engine mode a DB cluster runs its own DB instances in, which every cluster parameter
/// of these catalogs configures a setting of.
///
/// Source: `CreateDBClusterMessage$EngineMode` ("The DB engine mode of the DB cluster, either
/// `provisioned` or `serverless`"), whose other value "only applies for Aurora Serverless v1
/// DB clusters" — clusters whose configuration the service manages rather than these
/// parameters.
const PROVISIONED: &str = "provisioned";

/// The engine modes a cluster parameter publishes, as this suite expects them: the one mode
/// above, written here rather than read from the code under test.
const EXPECTED_MODES: [&str; 1] = [PROVISIONED];

/// The `SupportedEngineModes` of one reported `<Parameter>`, by parameter name.
///
/// A missing member reads as an empty list, which the assertions below reject just as they
/// reject a wrong one: a cluster parameter publishes the mode it applies in.
fn modes_by_parameter(xml: &str) -> BTreeMap<String, Vec<String>> {
    subtrees(xml, "Parameter")
        .into_iter()
        .map(|entry| {
            (
                text(&entry, "ParameterName"),
                list_members(&entry, "SupportedEngineModes"),
            )
        })
        .collect()
}

/// Assert every parameter in `reported` publishes [`EXPECTED_MODES`], and that there was a
/// parameter to assert on at all — a report with no `<Parameter>` would satisfy a per-entry
/// assertion without exercising the projection under test.
fn assert_modes(case: &str, label: &str, reported: &BTreeMap<String, Vec<String>>) {
    assert!(
        !reported.is_empty(),
        "case {case:?} ({label}): a cluster family publishes cluster parameters, so the report \
         must carry at least one for its modes to be asserted, got none"
    );
    for (name, modes) in reported {
        assert_eq!(
            modes.as_slice(),
            EXPECTED_MODES.as_slice(),
            "case {case:?} ({label}): expected {name}'s SupportedEngineModes \
             {EXPECTED_MODES:?}, got {modes:?}"
        );
    }
}

/// Whether `engine` has a cluster form, which is what makes its families cluster families.
fn has_cluster_form(engine: &str) -> bool {
    DB_CLUSTER_ENGINES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(engine))
}

/// Every DB cluster parameter group family the engine-version catalogue publishes, each with
/// the UNION of the engine modes its own versions publish — read back through
/// `DescribeDBEngineVersions`, the report that owns that per-version fact.
async fn cluster_families(router: &MultiServiceRouter) -> BTreeMap<String, BTreeSet<String>> {
    let mut families: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for engine in DB_INSTANCE_ENGINES
        .iter()
        .chain(SIBLING_CONTROL_PLANE_ENGINES.iter())
        .filter(|engine| has_cluster_form(engine))
    {
        for version in all_versions_of(router, engine).await {
            families
                .entry(version.parameter_group_family)
                .or_default()
                .extend(list_members(&version.scalars, "SupportedEngineModes"));
        }
    }
    families
}

/// The engine defaults of one family, as the modes each reported parameter publishes.
async fn engine_defaults(
    router: &MultiServiceRouter,
    case: &str,
    family: &str,
) -> BTreeMap<String, Vec<String>> {
    let body = expect_ok(
        case,
        call(
            router,
            "DescribeEngineDefaultClusterParameters",
            &[("DBParameterGroupFamily", family)],
        )
        .await,
    );
    modes_by_parameter(&body)
}

/// One group's own parameter listing, as the modes each reported parameter publishes.
async fn group_parameters(
    router: &MultiServiceRouter,
    case: &str,
    group: &str,
) -> BTreeMap<String, Vec<String>> {
    let body = expect_ok(
        case,
        call(
            router,
            "DescribeDBClusterParameters",
            &[("DBClusterParameterGroupName", group)],
        )
        .await,
    );
    modes_by_parameter(&body)
}

// ---------------------------------------------------------------------------
// The engine's own defaults, over every published cluster family
// ---------------------------------------------------------------------------

/// RULE: every cluster parameter a family's engine-default report carries publishes the engine
/// mode the parameter applies in, whatever modes the family's engine VERSIONS publish.
#[tokio::test]
async fn every_published_cluster_family_reports_the_mode_its_parameters_apply_in() {
    let router = emulator();
    let families = cluster_families(&router).await;
    assert!(
        families.len() > 1,
        "the engine-version catalogue must publish cluster families for this table, got \
         {families:?}"
    );

    // The rows that make this table span the class: a family whose versions publish more than
    // one engine mode is the case where reading the member off the VERSIONS would answer with
    // several modes, and a family whose versions publish one is the case where it would look
    // right by accident. Both must be in the table.
    let several: Vec<&String> = families
        .iter()
        .filter(|(_, modes)| modes.len() > 1)
        .map(|(family, _)| family)
        .collect();
    assert!(
        !several.is_empty(),
        "the table must span a family whose engine versions publish more than one engine \
         mode, got {families:?}"
    );
    assert!(
        families.values().any(|modes| modes.len() == 1),
        "the table must span a family whose engine versions publish exactly one engine mode, \
         got {families:?}"
    );

    for (family, version_modes) in &families {
        let case = format!("{family} (its versions publish {version_modes:?})");
        let reported = engine_defaults(&router, &case, family).await;
        assert_modes(&case, "DescribeEngineDefaultClusterParameters", &reported);
    }
}

/// RULE: the modes a parameter publishes belong to the PARAMETER, so a parameter two families
/// of one engine both publish reports the same modes in both — the member does not move with
/// the release line.
#[tokio::test]
async fn a_parameter_two_families_publish_reports_the_same_modes_in_both() {
    let router = emulator();
    let families = cluster_families(&router).await;

    let mut seen: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    let mut shared = 0usize;
    for family in families.keys() {
        let case = format!("{family} against the other families of its engine");
        for (name, modes) in engine_defaults(&router, &case, family).await {
            if let Some((first_family, first_modes)) = seen.get(&name) {
                shared += 1;
                assert_eq!(
                    &modes, first_modes,
                    "case {case:?}: {name} publishes {first_modes:?} for {first_family}, so it \
                     must publish the same for {family}, got {modes:?}"
                );
            } else {
                seen.insert(name, (family.clone(), modes));
            }
        }
    }
    assert!(
        shared > 0,
        "the catalogs must publish at least one parameter under two families for this rule, \
         got {} distinct parameter(s)",
        seen.len()
    );
}

// ---------------------------------------------------------------------------
// A group of the family, both halves of its listing
// ---------------------------------------------------------------------------

/// RULE: a GROUP's listing projects the same per-parameter modes as the engine defaults of its
/// family — for the parameters nobody has set (`Source` `engine-default`) and for the one a
/// caller set (`Source` `user`) alike.
#[tokio::test]
async fn a_group_of_the_family_reports_the_modes_its_parameters_apply_in() {
    let router = emulator();
    let families = cluster_families(&router).await;

    // Rows: the family whose versions publish the MOST engine modes (where reading the member
    // off the versions diverges most), and one whose versions publish the fewest — picked from
    // the catalogue rather than named here, so the table follows the published data.
    let mut by_mode_count: Vec<(&String, &BTreeSet<String>)> = families
        .iter()
        .filter(|(family, _)| !family.is_empty())
        .collect();
    by_mode_count.sort_by_key(|(family, modes)| (modes.len(), (*family).clone()));
    let rows: BTreeSet<&String> = [
        by_mode_count.first().map(|(family, _)| *family),
        by_mode_count.last().map(|(family, _)| *family),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(
        !rows.is_empty(),
        "the engine-version catalogue must publish a cluster family for this table"
    );

    for (index, family) in rows.into_iter().enumerate() {
        let case = format!("a group of {family}");
        let name = format!("emu-cluster-modes-{index}");
        let group = create_group(&router, &case, &name, family).await;

        let defaults = engine_defaults(&router, &case, family).await;
        let listed = group_parameters(&router, &case, &group).await;
        assert_eq!(
            listed.keys().collect::<Vec<&String>>(),
            defaults.keys().collect::<Vec<&String>>(),
            "case {case:?}: a group inherits its family's parameter list, so the two reports \
             must name the same parameters"
        );
        assert_modes(&case, "DescribeDBClusterParameters", &listed);

        // The other half of a group's listing: the parameter a caller SET, reported under
        // `Source` `user`. Its value is the engine default the family just published, so the
        // row exercises the set path without asserting anything about which values are
        // admitted.
        let Some((parameter, value)) = settable(&router, &case, family).await else {
            continue;
        };
        let (status, body) = modify(&router, &group, &parameter, &value, None).await;
        assert_eq!(
            status, 200,
            "case {case:?}: setting {parameter} to its published default must be served, got \
             {body}"
        );
        let after = group_parameters(&router, &case, &group).await;
        let modes = after.get(&parameter).cloned().unwrap_or_default();
        assert_eq!(
            modes.as_slice(),
            EXPECTED_MODES.as_slice(),
            "case {case:?}: {parameter} is still the same parameter once its value is the \
             caller's, so it must publish {EXPECTED_MODES:?}, got {modes:?} in the listing \
             {after:?}"
        );
    }
}

/// One modifiable parameter of `family` and the value it publishes as its default, or `None`
/// where the family publishes no such parameter.
async fn settable(
    router: &MultiServiceRouter,
    case: &str,
    family: &str,
) -> Option<(String, String)> {
    let body = expect_ok(
        case,
        call(
            router,
            "DescribeEngineDefaultClusterParameters",
            &[("DBParameterGroupFamily", family)],
        )
        .await,
    );
    subtrees(&body, "Parameter").into_iter().find_map(|entry| {
        (optional_text(&entry, "IsModifiable").as_deref() == Some("true"))
            .then(|| Some((text(&entry, "ParameterName"), optional_text(&entry, "ParameterValue")?)))
            .flatten()
    })
}
