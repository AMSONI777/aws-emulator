// SPDX-License-Identifier: CC0-1.0

//! The failover-slate configuration ARN on EVERY channel summary `ListChannels`
//! projects, driven over the wire through `MultiServiceRouter::dispatch` exactly as a
//! signed `aws ivs` call arrives.
//!
//! The rule under test: a channel object reports each of its optional configuration ARNs
//! as a PRESENT key holding a string — the ARN of the resource configured for it, or the
//! empty string when none is — and that holds for every summary of every page a list
//! answers with, whatever the number of channels, the page size, the filters, or the
//! shape of the channel itself. A client decides "is a failover slate configured on this
//! channel?" by comparing the value with the empty string, so an absent key is a
//! different answer from "nothing is configured", and a summary that is not the first one
//! of the first page is no different from one that is.
//!
//! `channel_configuration_arns.rs` pins the rule across the PROJECTIONS (create, read,
//! batch read, list, update) for one channel at a time; this suite pins it across the
//! shape of the LIST — its length, its paging and its filters — which is where a summary
//! past the first one, and a page past the first one, is reached at all.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::channel_lifecycle::{text, Ivs};

/// The member the recorded IVS responses carry on every projected channel and that this
/// model revision declares on neither channel shape
/// (`smithy_query(query="shape",shape="Channel,ChannelSummary")`), so it is served by the
/// channel wire projection rather than by a generated field.
const FAILOVER_SLATE: &str = "failoverSlateConfigurationArn";

/// The two optional configuration ARNs `ChannelSummary` DOES declare, each documented
/// `Default: ""` (`smithy_query(query="doc",shape="ChannelSummary",member=...)`): the
/// failover slate reads the same way they do, so every assertion checks it beside them.
const DECLARED_CONFIGURATION_ARNS: &[&str] =
    &["recordingConfigurationArn", "playbackRestrictionPolicyArn"];

/// The value a configuration ARN reads as while nothing is configured for it.
const UNCONFIGURED: &str = "";

/// Assert one summary reports the failover-slate ARN, and the declared configuration ARNs
/// beside it, as a present string holding the unconfigured value.
fn assert_unconfigured_arns(case: &str, where_from: &str, summary: &Value) {
    for member in std::iter::once(&FAILOVER_SLATE).chain(DECLARED_CONFIGURATION_ARNS) {
        let actual = summary.get(*member).cloned().unwrap_or(Value::Null);
        assert_eq!(
            actual,
            Value::String(UNCONFIGURED.to_string()),
            "case {case:?}: {where_from} must report {member} as the unconfigured \
             {UNCONFIGURED:?}, got {actual:?} in {summary}"
        );
    }
}

/// Create `count` channels whose own shapes differ, and answer their ARNs.
///
/// The shapes cycle through the channel surface — the type (and so the preset the type
/// decides), the flags, whether the channel is named and whether it carries tags — so no
/// row of a table below is a set of channels that differ only by name.
async fn channels_of_differing_shapes(ivs: &Ivs, count: usize) -> BTreeSet<String> {
    let shapes: [Value; 5] = [
        json!({}),
        json!({ "type": "BASIC", "tags": { "team": "video" } }),
        json!({ "type": "STANDARD", "authorized": true, "insecureIngest": true }),
        json!({ "type": "ADVANCED_HD", "latencyMode": "NORMAL" }),
        json!({ "type": "ADVANCED_SD", "latencyMode": "LOW" }),
    ];
    let mut arns = BTreeSet::new();
    for index in 0..count {
        let mut request = shapes[index % shapes.len()].clone();
        // A distinct name only so each channel is individually addressable; what the
        // rows vary is the shape above.
        request["name"] = json!(format!("chan-{index}"));
        arns.insert(ivs.create_arn(request).await);
    }
    arns
}

/// Every summary of an unpaged list carries the member, over list lengths from one
/// channel up.
#[tokio::test]
async fn every_summary_of_a_list_reports_the_failover_slate_arn() {
    // Rows differ along the number of channels the list answers with: one, a few, and a
    // length past the default page the absent `maxResults` means is not needed here —
    // paging is the next test's axis.
    for count in [1_usize, 2, 5] {
        let ivs = Ivs::new();
        let expected = channels_of_differing_shapes(&ivs, count).await;

        let listed = ivs.ok("ListChannels", json!({})).await;
        let summaries = listed["channels"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let case = format!("{count} channels listed unpaged");
        assert_eq!(
            summaries.len(),
            count,
            "case {case:?}: expected {count} summaries, got {listed}"
        );
        assert_eq!(
            summaries
                .iter()
                .map(|summary| text(summary, "arn"))
                .collect::<BTreeSet<_>>(),
            expected,
            "case {case:?}: the list must answer exactly the persisted channels, got {listed}"
        );
        for (index, summary) in summaries.iter().enumerate() {
            assert_unconfigured_arns(&case, &format!("the summary at index {index}"), summary);
        }
    }
}

/// Every summary of every page carries it, including the pages a `nextToken` resumes.
#[tokio::test]
async fn every_page_of_a_paginated_list_reports_the_failover_slate_arn() {
    let ivs = Ivs::new();
    let expected = channels_of_differing_shapes(&ivs, 5).await;

    // 1 and 100 are the published bounds of the modelled `MaxChannelResults`
    // (`range(min: 1, max: 100)`); 2 does not divide the set and 5 is exactly it.
    for page_size in [1_usize, 2, 5, 100] {
        let case = format!("maxResults={page_size} over {} channels", expected.len());
        let mut seen = BTreeSet::new();
        let mut token = Value::Null;
        for page_index in 0..(expected.len() + 2) {
            let mut request = json!({ "maxResults": page_size });
            if let Some(token) = token.as_str() {
                request["nextToken"] = json!(token);
            }
            let page = ivs.ok("ListChannels", request).await;
            let summaries = page["channels"].as_array().cloned().unwrap_or_default();
            for (index, summary) in summaries.iter().enumerate() {
                assert_unconfigured_arns(
                    &case,
                    &format!("the summary at index {index} of page {page_index}"),
                    summary,
                );
                seen.insert(text(summary, "arn"));
            }
            token = page.get("nextToken").cloned().unwrap_or(Value::Null);
            if token.as_str().is_none() {
                break;
            }
        }
        assert_eq!(
            seen, expected,
            "case {case:?}: paging must reach every persisted channel, reached {seen:?}"
        );
    }
}

/// Every summary a filtered list answers with carries it: the filters narrow which
/// channels are projected, not how one is projected.
#[tokio::test]
async fn every_summary_of_a_filtered_list_reports_the_failover_slate_arn() {
    let ivs = Ivs::new();
    channels_of_differing_shapes(&ivs, 3).await;

    // One row per `filterBy*` member the operation declares
    // (`smithy_query(query="operation",operation="ListChannels")`), each with a value
    // the channels above match: the name of one of them, and the empty string every
    // unconfigured channel reports for the three configuration ARNs.
    let cases: Vec<(&str, Value, usize)> = vec![
        ("filterByName naming one channel", json!({ "filterByName": "chan-1" }), 1),
        (
            "filterByRecordingConfigurationArn= matching every unconfigured channel",
            json!({ "filterByRecordingConfigurationArn": "" }),
            3,
        ),
        (
            "filterByPlaybackRestrictionPolicyArn= matching every unconfigured channel",
            json!({ "filterByPlaybackRestrictionPolicyArn": "" }),
            3,
        ),
        (
            "filterByAdConfigurationArn= matching every unconfigured channel",
            json!({ "filterByAdConfigurationArn": "" }),
            3,
        ),
    ];

    for (case, request, matches) in cases {
        let listed = ivs.ok("ListChannels", request).await;
        let summaries = listed["channels"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            summaries.len(),
            matches,
            "case {case:?}: expected {matches} summaries, got {listed}"
        );
        for (index, summary) in summaries.iter().enumerate() {
            assert_unconfigured_arns(case, &format!("the summary at index {index}"), summary);
        }
    }
}

/// Listing is a report: repeating it answers byte-identical summaries, so the projected
/// member is a rendering of the stored channel rather than something a read consumed.
#[tokio::test]
async fn repeating_the_list_answers_identical_summaries() {
    let ivs = Ivs::new();
    channels_of_differing_shapes(&ivs, 3).await;

    let first = ivs.ok("ListChannels", json!({})).await;
    for round in 1..3 {
        let again = ivs.ok("ListChannels", json!({})).await;
        assert_eq!(
            again, first,
            "case round {round}: ListChannels must answer identically, got {again} after {first}"
        );
    }
}
