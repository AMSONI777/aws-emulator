// SPDX-License-Identifier: CC0-1.0

//! WHY a `ScanSbom` report says a component was skipped, end-to-end over HTTP.
//!
//! The rule under test: a component the scan drew no conclusion about is
//! reported with the sentence of the skip CONDITION that fired for it — a purl
//! that names no package the scanner looks up (an ecosystem it does not scan,
//! or no `namespace` where that ecosystem's packages are named with one)
//! reports the unsupported-namespace sentence, a purl that does name such a
//! package but whose coordinate the advisory data holds no rule for reports the
//! no-rules sentence — and the two renderings of that one decision (the
//! Inspector forms' `messages[]` entry and the component's own CycloneDX
//! `…:info` property) carry the same sentence. A component the advisory data
//! holds rules for was ruled on and is reported as skipped in neither form.
//!
//! The ecosystems a row is scanned-or-not against, and which of them name a
//! package with a purl `namespace`, are `SCANNED_ECOSYSTEMS` in
//! `src/ops/scan_sbom.rs` (each mapped there to the Amazon Inspector
//! `packageManager` a finding in it is reported under); the advisory catalog the
//! ruled-on rows are written against is
//! `src/state.rs::seed_vulnerability_db`.

use super::scan_sbom::{bom, component, emulator, post_scan};
use serde_json::{json, Value};

/// The namespace the scan's own annotations live under in a CycloneDX report.
const NAMESPACE: &str = "amazon:inspector:sbom_scanner";

/// What a scan reports for a component whose purl names no package it looks up.
const UNSUPPORTED_NAMESPACE: &str = "Component skipped: unsupported purl namespace.";

/// What a scan reports for a component whose purl names a package it looks up
/// but whose coordinate the advisory data holds no rule for.
const NO_RULES: &str = "Component skipped: no supported rules found.";

/// The value of the CycloneDX property named `name`, if the array carries it.
fn property(properties: &Value, name: &str) -> Option<String> {
    properties
        .as_array()?
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
        .and_then(|entry| entry["value"].as_str().map(str::to_string))
}

/// The `info_message` a report's `messages[]` carries for `purl`, if any.
fn message_for(report: &Value, purl: &str) -> Option<String> {
    report["messages"]
        .as_array()?
        .iter()
        .find(|entry| entry["purl"].as_str() == Some(purl))
        .and_then(|entry| entry["info_message"].as_str().map(str::to_string))
}

/// One row of the skip table: a component coordinate, and the sentence the
/// report must carry for it (`None` when the scan ruled on it, so it is not
/// reported as skipped at all).
#[derive(Debug)]
struct SkipCase {
    what: &'static str,
    purl: &'static str,
    name: &'static str,
    version: &'static str,
    expected: Option<&'static str>,
}

/// Every ecosystem the scanner scans, on a package the advisory catalog holds no
/// rule for, plus ecosystems outside that list, plus coordinates the catalog
/// does rule on.
fn cases() -> Vec<SkipCase> {
    vec![
        // Ecosystems the scanner scans: in scope, no rule for this package.
        SkipCase {
            what: "an npm package no advisory mentions",
            purl: "pkg:npm/left-pad@1.0.0",
            name: "left-pad",
            version: "1.0.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a PyPI package no advisory mentions",
            purl: "pkg:pypi/tabulate@0.9.0",
            name: "tabulate",
            version: "0.9.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a maven coordinate no advisory mentions",
            purl: "pkg:maven/com.example/widgets@2.1.0",
            name: "widgets",
            version: "2.1.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a Go module no advisory mentions",
            purl: "pkg:golang/github.com/example/toolkit@1.4.0",
            name: "toolkit",
            version: "1.4.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a cargo crate no advisory mentions",
            purl: "pkg:cargo/not-in-the-catalog@1.0.0",
            name: "not-in-the-catalog",
            version: "1.0.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a RubyGem no advisory mentions",
            purl: "pkg:gem/rake@13.0.6",
            name: "rake",
            version: "13.0.6",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a NuGet package no advisory mentions",
            purl: "pkg:nuget/Serilog@3.1.1",
            name: "Serilog",
            version: "3.1.1",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a composer package no advisory mentions",
            purl: "pkg:composer/monolog/monolog@3.5.0",
            name: "monolog",
            version: "3.5.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "an apk package no advisory mentions",
            purl: "pkg:apk/alpine/busybox@1.36.1",
            name: "busybox",
            version: "1.36.1",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "a deb package no advisory mentions",
            purl: "pkg:deb/debian/zlib@1.2.13",
            name: "zlib",
            version: "1.2.13",
            expected: Some(NO_RULES),
        },
        SkipCase {
            what: "an rpm package no advisory mentions",
            purl: "pkg:rpm/redhat/curl@8.4.0",
            name: "curl",
            version: "8.4.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            // The qualifiers are no part of the coordinate the scan resolves.
            what: "an rpm package carrying purl qualifiers",
            purl: "pkg:rpm/redhat/curl@8.4.0?arch=x86_64",
            name: "curl",
            version: "8.4.0",
            expected: Some(NO_RULES),
        },
        SkipCase {
            // purl writes the type lowercase and specifies it as
            // case-insensitive, so a document spelling it otherwise names the
            // same (scanned) ecosystem.
            what: "a scanned ecosystem spelled in another case",
            purl: "pkg:NPM/right-pad@1.0.0",
            name: "right-pad",
            version: "1.0.0",
            expected: Some(NO_RULES),
        },
        // Ecosystems outside the scanner's coverage: no rule can ever apply.
        SkipCase {
            what: "a Swift package",
            purl: "pkg:swift/github.com/example/Alamofire@5.8.1",
            name: "Alamofire",
            version: "5.8.1",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },        SkipCase {
            what: "a CocoaPods pod",
            purl: "pkg:cocoapods/AFNetworking@4.0.1",
            name: "AFNetworking",
            version: "4.0.1",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a Conan package",
            purl: "pkg:conan/zlib@1.2.13",
            name: "zlib",
            version: "1.2.13",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "an Erlang hex package",
            purl: "pkg:hex/phoenix@1.7.10",
            name: "phoenix",
            version: "1.7.10",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a CRAN package",
            purl: "pkg:cran/ggplot2@3.4.4",
            name: "ggplot2",
            version: "3.4.4",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a Dart pub package",
            purl: "pkg:pub/http@1.1.2",
            name: "http",
            version: "1.1.2",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a container image",
            purl: "pkg:docker/library/nginx@1.25.3",
            name: "nginx",
            version: "1.25.3",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a generic coordinate",
            purl: "pkg:generic/openssl@3.0.6",
            name: "openssl",
            version: "3.0.6",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            // An unscanned ecosystem is unscanned however the document spells
            // the type.
            what: "an unscanned ecosystem spelled in another case",
            purl: "pkg:Swift/github.com/example/SwiftyJSON@5.0.1",
            name: "SwiftyJSON",
            version: "5.0.1",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        // Scanned ecosystems whose packages are NAMED with a purl namespace,
        // on a coordinate that carries none: the group, the module path, the
        // vendor and the distribution are each what makes the name a package,
        // so without one there is no package to hold a rule for.
        SkipCase {
            what: "a maven coordinate with no group",
            purl: "pkg:maven/log4j-core@2.14.1",
            name: "log4j-core",
            version: "2.14.1",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a Go coordinate with no module path",
            purl: "pkg:golang/gin@1.4.0",
            name: "gin",
            version: "1.4.0",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a composer coordinate with no vendor",
            purl: "pkg:composer/monolog@3.5.0",
            name: "monolog",
            version: "3.5.0",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "a deb coordinate with no distribution",
            purl: "pkg:deb/openssl@3.0.6",
            name: "openssl",
            version: "3.0.6",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "an rpm coordinate with no distribution",
            purl: "pkg:rpm/glibc@2.35",
            name: "glibc",
            version: "2.35",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            // The qualifiers name the architecture, not the distribution the
            // package was built by.
            what: "an rpm coordinate carrying qualifiers but no distribution",
            purl: "pkg:rpm/libssl@0.0.1-1?arch=x86_64",
            name: "libssl",
            version: "0.0.1-1",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        SkipCase {
            what: "an apk coordinate with no distribution",
            purl: "pkg:apk/busybox@1.36.1",
            name: "busybox",
            version: "1.36.1",
            expected: Some(UNSUPPORTED_NAMESPACE),
        },
        // Ruled on: the advisory data holds rules for the package, so nothing
        // was skipped — whether or not this release is affected.
        SkipCase {
            what: "a package with a matching advisory",
            purl: "pkg:npm/lodash@4.17.20",
            name: "lodash",
            version: "4.17.20",
            expected: None,
        },
        SkipCase {
            what: "a package whose advisory cleared this release",
            purl: "pkg:npm/lodash@4.17.21",
            name: "lodash",
            version: "4.17.21",
            expected: None,
        },
        SkipCase {
            what: "an OS package with a matching advisory",
            purl: "pkg:deb/debian/openssl@3.0.6",
            name: "openssl",
            version: "3.0.6",
            expected: None,
        },
    ]
}

#[tokio::test]
async fn a_skipped_component_is_reported_with_the_condition_that_fired() {
    let (_engine, router) = emulator();
    for case in cases() {
        let entry = component("ref-a", case.name, case.version, case.purl);

        // The Inspector form reports the decision in `messages[]`.
        let request = json!({
            "sbom": bom(vec![entry.clone()]),
            "outputFormat": "INSPECTOR",
        });
        let (status, response) = post_scan(&router, &request).await;
        assert_eq!(
            status, 200,
            "case {:?}: expected HTTP 200, got {status}: {response}",
            case.what
        );
        let report = &response["sbom"];
        let messages = report["messages"].as_array().cloned().unwrap_or_default();
        match case.expected {
            None => assert!(
                messages.is_empty(),
                "case {:?}: a component that was ruled on is not reported as skipped, got \
                 {messages:?}",
                case.what
            ),
            Some(expected) => {
                assert_eq!(
                    messages.len(),
                    1,
                    "case {:?}: expected one skip message, got {messages:?}",
                    case.what
                );
                assert_eq!(
                    message_for(report, case.purl).as_deref(),
                    Some(expected),
                    "case {:?}: expected the message {expected:?} for {}, got {:?}",
                    case.what,
                    case.purl,
                    messages[0]
                );
            }
        }

        // The CycloneDX form reports the same decision on the component itself.
        let request = json!({
            "sbom": bom(vec![entry]),
            "outputFormat": "CYCLONE_DX_1_5",
        });
        let (status, response) = post_scan(&router, &request).await;
        assert_eq!(
            status, 200,
            "case {:?}: expected HTTP 200, got {status}: {response}",
            case.what
        );
        let properties = &response["sbom"]["components"][0]["properties"];
        let info = property(properties, &format!("{NAMESPACE}:info"));
        assert_eq!(
            info.as_deref(),
            case.expected,
            "case {:?}: the component's own annotation must carry the same decision, got \
             {properties}",
            case.what
        );
    }
}

#[tokio::test]
async fn one_scan_reports_each_skip_condition_on_the_component_it_fired_for() {
    // A multi-ecosystem document: a matched package, packages in scanned
    // ecosystems the advisory data holds no rule for, and two coordinates that
    // name no package the scanner looks up — one in an ecosystem it does not
    // scan, one in a scanned ecosystem but missing the namespace that
    // ecosystem's packages are named with. One scan must report BOTH sentences,
    // each on the component its condition fired for, in document order.
    let components = vec![
        component("ref-a", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
        component("ref-b", "left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0"),
        component("ref-c", "rake", "13.0.6", "pkg:gem/rake@13.0.6"),
        component("ref-d", "libssl", "0.0.1-1", "pkg:rpm/libssl@0.0.1-1?arch=x86_64"),
        component(
            "ref-e",
            "fixture-gin",
            "0.0.1",
            "pkg:golang/github.com/example/fixture-gin@0.0.1",
        ),
        component("ref-f", "zlib", "1.2.13", "pkg:conan/zlib@1.2.13"),
    ];
    let expected = [
        ("pkg:npm/left-pad@1.0.0", NO_RULES),
        ("pkg:gem/rake@13.0.6", NO_RULES),
        ("pkg:rpm/libssl@0.0.1-1?arch=x86_64", UNSUPPORTED_NAMESPACE),
        (
            "pkg:golang/github.com/example/fixture-gin@0.0.1",
            NO_RULES,
        ),
        ("pkg:conan/zlib@1.2.13", UNSUPPORTED_NAMESPACE),
    ];

    let (_engine, router) = emulator();
    let request = json!({
        "sbom": bom(components),
        "outputFormat": "INSPECTOR",
    });
    let (status, response) = post_scan(&router, &request).await;
    assert_eq!(status, 200, "expected HTTP 200, got {status}: {response}");
    let messages = response["sbom"]["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        messages.len(),
        expected.len(),
        "case \"a multi-ecosystem document\": expected {} skip messages, got {messages:?}",
        expected.len()
    );
    for (index, (purl, sentence)) in expected.iter().enumerate() {
        assert_eq!(
            messages[index]["purl"].as_str(),
            Some(*purl),
            "case \"a multi-ecosystem document\": messages[{index}] must name {purl}, got {:?}",
            messages[index]
        );
        assert_eq!(
            messages[index]["info_message"].as_str(),
            Some(*sentence),
            "case \"a multi-ecosystem document\": messages[{index}] must read {sentence:?}, got \
             {:?}",
            messages[index]
        );
    }
}
