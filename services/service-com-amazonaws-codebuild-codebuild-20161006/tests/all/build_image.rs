// SPDX-License-Identifier: CC0-1.0

//! End-to-end cover for the IMAGE a build runs in, driven over the wire the router serves:
//! `POST /` with `X-Amz-Target: CodeBuild_20161006.<Operation>` on awsJson1_1.
//!
//! RULE under test: a build's commands execute inside the Docker image its EFFECTIVE
//! environment names — the project's `environment.image` with `StartBuild`'s `imageOverride`
//! applied for that build only — so what they observe of their environment follows from that
//! image: `CODEBUILD_BUILD_IMAGE` is the image the build is running in, and the image's own
//! root filesystem is there to read, which for a Linux image is where the distribution it is
//! built on is identified (`/etc/os-release`). An image the environment knows no filesystem
//! of presents none rather than invented values, and the files an image presents are the
//! environment's rather than output the build produced, so no artifact is selected out of
//! them.
//!
//! The rows differ along what the rule generalises over: whether the build overrides the
//! project's image, which distribution each image is built on (and which release of it),
//! which direction the override moves in, and whether the image is one the environment knows
//! a filesystem of at all.

use serde_json::{json, Value};

use super::project_build_lifecycle::{create_project, emulator, merged, phase_of, settled_build};

/// A buildspec that exports what the build's own session says about the image it is running
/// in: the agent-provided variable, and the distribution and release the image's own release
/// file identifies.
const PROBE_BUILDSPEC: &str = "version: 0.2\nenv:\n  exported-variables:\n    \
                               - RUNNING_IMAGE\n    - RUNNING_OS\n    \
                               - RUNNING_OS_VERSION\nphases:\n  build:\n    commands:\n      \
                               - export RUNNING_IMAGE=\"$CODEBUILD_BUILD_IMAGE\"\n      \
                               - export RUNNING_OS=\"$(. /etc/os-release && echo $ID)\"\n      \
                               - export RUNNING_OS_VERSION=\"$(. /etc/os-release && echo \
                               $VERSION_ID)\"\n";

/// `CreateProject` members for a project whose builds run `PROBE_BUILDSPEC` on `image`.
fn project_on(image: &str) -> Value {
    json!({
        "source": {"type": "NO_SOURCE", "buildspec": PROBE_BUILDSPEC},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": image,
            "computeType": "BUILD_GENERAL1_SMALL",
        },
    })
}

/// The build's `exportedEnvironmentVariables`, as the value reported for each name.
fn exported(build: &Value) -> Vec<(String, String)> {
    build["exportedEnvironmentVariables"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|variable| {
            (
                variable["name"].as_str().unwrap_or_default().to_string(),
                variable["value"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// The value reported for the exported variable `name`, or `None` when none is reported.
fn exported_value(build: &Value, name: &str) -> Option<String> {
    exported(build)
        .into_iter()
        .find(|(reported, _)| reported == name)
        .map(|(_, value)| value)
}

/// RULE: the image the commands run in is the build's effective one, so the agent-provided
/// variable and the distribution the commands read are that image's — the project's where
/// the build overrode nothing, and the override's where it did.
#[tokio::test]
async fn a_builds_commands_run_in_its_effective_image() {
    let router = emulator();
    /// One row: the case, the project's image, the `StartBuild` members, the image the
    /// commands must report, and the `ID` and `VERSION_ID` that image's release file
    /// identifies.
    type Row = (
        &'static str,
        &'static str,
        Value,
        &'static str,
        &'static str,
        &'static str,
    );
    let rows: Vec<Row> = vec![
        (
            "no override: the project's own image",
            "aws/codebuild/standard:7.0",
            json!({}),
            "aws/codebuild/standard:7.0",
            "ubuntu",
            "22.04",
        ),
        (
            "an override onto an Amazon Linux image",
            "aws/codebuild/standard:7.0",
            json!({"imageOverride": "aws/codebuild/amazonlinux-x86_64-standard:5.0"}),
            "aws/codebuild/amazonlinux-x86_64-standard:5.0",
            "amzn",
            "2023",
        ),
        (
            // Not the image the override above names: the same distribution at another
            // release, so the release the commands read is the image's own.
            "a project built on Amazon Linux 2, with no override",
            "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            json!({}),
            "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "amzn",
            "2",
        ),
        (
            "an override the other way, onto an Ubuntu image",
            "aws/codebuild/amazonlinux-x86_64-standard:5.0",
            json!({"imageOverride": "aws/codebuild/standard:6.0"}),
            "aws/codebuild/standard:6.0",
            "ubuntu",
            "22.04",
        ),
        (
            "an override onto an earlier release of the project's own distribution",
            "aws/codebuild/standard:7.0",
            json!({"imageOverride": "aws/codebuild/standard:5.0"}),
            "aws/codebuild/standard:5.0",
            "ubuntu",
            "20.04",
        ),
        (
            // The overrides travel together on the same request: the compute type the build
            // reports is the override's, and the image the commands see is still the one
            // the image override named.
            "an image override beside a compute-type and timeout override",
            "aws/codebuild/standard:7.0",
            json!({
                "imageOverride": "aws/codebuild/amazonlinux-x86_64-standard:5.0",
                "computeTypeOverride": "BUILD_GENERAL1_MEDIUM",
                "timeoutInMinutesOverride": 5,
            }),
            "aws/codebuild/amazonlinux-x86_64-standard:5.0",
            "amzn",
            "2023",
        ),
    ];

    for (index, (case, image, overrides, expected_image, expected_id, expected_version)) in
        rows.iter().enumerate()
    {
        let project = format!("image-proj-{index}");
        create_project(&router, &project, project_on(image)).await;
        let build = settled_build(&router, &project, overrides.clone()).await;
        assert_eq!(
            build["buildStatus"],
            json!("SUCCEEDED"),
            "case {case:?}: the probing build must succeed, got {build}"
        );
        assert_eq!(
            build["environment"]["image"],
            json!(expected_image),
            "case {case:?}: expected the effective image {expected_image}, got {build}"
        );
        for (name, expected) in [
            ("RUNNING_IMAGE", *expected_image),
            ("RUNNING_OS", *expected_id),
            ("RUNNING_OS_VERSION", *expected_version),
        ] {
            let reported = exported_value(&build, name);
            assert_eq!(
                reported.as_deref(),
                Some(expected),
                "case {case:?}: expected {name} {expected:?} from the image the build ran \
                 in, got {reported:?} in {build}"
            );
        }
    }
}

/// RULE: an image this environment knows no filesystem of presents none — nothing is
/// invented for it — while the variable naming the image is still set, because the agent
/// sets it to whatever image the build is running in.
#[tokio::test]
async fn an_unknown_image_presents_no_filesystem_and_is_still_named() {
    let router = emulator();
    // (case, the image, the value the commands must report for it)
    let rows = [
        (
            "an image from another registry",
            "public.ecr.aws/docker/library/ubuntu:22.04",
        ),
        (
            "an image named by digest",
            "111122223333.dkr.ecr.us-east-1.amazonaws.com/own@sha256:cbbf2f9a99b47fc460d422812b6a5adff7dfee951d8fa2e4a98caa0382cfbdbf",
        ),
    ];
    for (index, (case, image)) in rows.iter().enumerate() {
        let project = format!("unknown-image-proj-{index}");
        create_project(&router, &project, project_on(image)).await;
        let build = settled_build(&router, &project, json!({})).await;
        assert_eq!(
            build["buildStatus"],
            json!("SUCCEEDED"),
            "case {case:?}: the probing build must succeed, got {build}"
        );
        assert_eq!(
            exported_value(&build, "RUNNING_IMAGE").as_deref(),
            Some(*image),
            "case {case:?}: the agent names whatever image the build runs in, got {build}"
        );
        assert_eq!(
            exported_value(&build, "RUNNING_OS").as_deref(),
            Some(""),
            "case {case:?}: no distribution is invented for an image this environment knows \
             no filesystem of, got {build}"
        );
    }
}

/// RULE: the files an image presents are the ENVIRONMENT's, not output the build produced,
/// so a build whose own commands wrote nothing has nothing for its artifacts to select,
/// however much the image's filesystem holds — and one whose commands wrote a file does.
///
/// Where the selected files then GO is the object store's half of the run, which the router
/// this suite drives mounts none of, so what each row asserts on is whether the declared
/// paths matched the build's own output.
#[tokio::test]
async fn the_images_files_are_not_the_builds_output() {
    let router = emulator();
    let destination = json!({"artifacts": {"type": "S3", "location": "image-artifacts"}});
    /// CodeBuild's client error for declared artifact paths that matched nothing the build
    /// produced.
    const MATCHED_NOTHING: &str = "No matching artifact paths found";
    // (case, the commands the build's buildspec runs, whether `**/*` matched anything the
    // build produced)
    let rows: [(&str, &str, bool); 2] = [
        (
            "commands that wrote nothing: the whole tree names no artifact file",
            "echo building",
            false,
        ),
        (
            "commands that wrote one file: that file is what the paths match",
            "echo produced > built.txt",
            true,
        ),
    ];
    for (index, (case, command, matched)) in rows.iter().enumerate() {
        let project = format!("image-artifacts-proj-{index}");
        let buildspec = format!(
            "version: 0.2\nphases:\n  build:\n    commands:\n      - {command}\nartifacts:\n  \
             files:\n    - '**/*'\n"
        );
        create_project(
            &router,
            &project,
            merged(
                json!({"source": {"type": "NO_SOURCE", "buildspec": buildspec}}),
                destination.clone(),
            ),
        )
        .await;
        let build = settled_build(&router, &project, json!({})).await;
        let phase = phase_of(&build, "UPLOAD_ARTIFACTS")
            .unwrap_or_else(|| panic!("case {case:?}: an UPLOAD_ARTIFACTS phase, got {build}"));
        let reported = phase["contexts"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            reported == MATCHED_NOTHING,
            !*matched,
            "case {case:?}: expected the declared paths to match {}, got {phase}",
            if *matched { "the file the build wrote" } else { "nothing" }
        );
    }
}
