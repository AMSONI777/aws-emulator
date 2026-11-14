// SPDX-License-Identifier: CC0-1.0

//! The IMAGE a build runs in: what its commands see of the environment it was given.
//!
//! # The rule this module implements
//!
//! A build's commands execute INSIDE the Docker image its effective environment names —
//! `ProjectEnvironment$image`, "the image tag or image digest that identifies the Docker
//! image to use for this build project", with `StartBuild`'s `imageOverride` applied for
//! that build only. So what the commands observe of their environment follows from THAT
//! image and not from the project's stored one:
//!
//! * CodeBuild's agent sets [`BUILD_IMAGE_VARIABLE`] in the command environment to the image
//!   the build is running in, which is where a buildspec reads it from;
//! * the image's own root filesystem is what the commands read, and a Linux image identifies
//!   the distribution it is built on in a release file at [`OS_RELEASE_PATH`] — a
//!   newline-separated list of shell-compatible assignments (`ID`, `NAME`, `VERSION_ID`,
//!   `PRETTY_NAME`), which is why `. /etc/os-release` is how a script asks which
//!   distribution it is on. That is the os-release format, the same one the ECR emulator's
//!   image scanner READS out of an image's layers; what is written here is one
//!   distribution's own file, so the two share the format and nothing else.
//!
//! Those two are the whole of what this module adds to a build's environment: the shell that
//! runs the commands is [`super::build_shell`]'s, and the image's files are seeded into its
//! working tree there, so a command reads them exactly as it reads any other file of the
//! environment. They are the ENVIRONMENT's files rather than the build's output, so they are
//! not part of what the run takes back out of the tree for its artifacts and its cache.
//!
//! # Where the catalog comes from
//!
//! [`CURATED_IMAGES`] is the images CodeBuild manages itself, from AWS's "Docker images
//! provided by CodeBuild" reference, paired with the distribution each one is built on: the
//! `standard` repository carries the Ubuntu images, the `amazonlinux2-*` repositories
//! Amazon Linux 2 and the `amazonlinux-*` repositories Amazon Linux 2023. Each
//! distribution's fields are that release's own release-file values.
//!
//! An image outside that catalog — a custom image in a registry, a Windows image, which has
//! no release file of this form at all — is one this environment knows no filesystem of:
//! nothing is presented for it, so a build on it reads nothing rather than reading invented
//! values, while the variable naming the image is still set, because the agent sets it
//! whatever the image is.

/// The agent-provided environment variable CodeBuild sets to the image the build is running
/// in.
pub const BUILD_IMAGE_VARIABLE: &str = "CODEBUILD_BUILD_IMAGE";

/// Where a Linux image identifies the distribution it is built on.
const OS_RELEASE_PATH: &str = "/etc/os-release";

/// One distribution a build image is built on, as the fields of its release file that
/// identify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Distribution {
    /// `ID`: the lower-case identifier of the operating system, which is what a script
    /// branches on.
    pub id: &'static str,
    /// `NAME`: the operating system's name without a version.
    pub name: &'static str,
    /// `ID_LIKE`: the distributions this one is derived from, space separated — empty for a
    /// release whose file carries none.
    pub id_like: &'static str,
    /// `VERSION_ID`: the operating system version, as the release numbers it.
    pub version_id: &'static str,
    /// `PRETTY_NAME`: the name and version together, as the release presents them.
    pub pretty_name: &'static str,
}

impl Distribution {
    /// This distribution's release file: one shell-compatible assignment per line, in the
    /// order a release file lists them, so performing the file sets the fields as variables.
    #[must_use]
    pub fn os_release(&self) -> String {
        let mut file = format!("NAME=\"{}\"\n", self.name);
        file.push_str(&format!("ID=\"{}\"\n", self.id));
        if !self.id_like.is_empty() {
            file.push_str(&format!("ID_LIKE=\"{}\"\n", self.id_like));
        }
        file.push_str(&format!("VERSION_ID=\"{}\"\n", self.version_id));
        file.push_str(&format!("PRETTY_NAME=\"{}\"\n", self.pretty_name));
        file
    }
}

/// Amazon Linux 2023, which the `amazonlinux-*` build images are built on.
const AMAZON_LINUX_2023: Distribution = Distribution {
    id: "amzn",
    name: "Amazon Linux",
    id_like: "fedora",
    version_id: "2023",
    pretty_name: "Amazon Linux 2023",
};

/// Amazon Linux 2, which the `amazonlinux2-*` build images are built on.
const AMAZON_LINUX_2: Distribution = Distribution {
    id: "amzn",
    name: "Amazon Linux",
    id_like: "centos rhel fedora",
    version_id: "2",
    pretty_name: "Amazon Linux 2",
};

/// Ubuntu 22.04 LTS, which the later `standard` build images are built on.
const UBUNTU_22_04: Distribution = Distribution {
    id: "ubuntu",
    name: "Ubuntu",
    id_like: "debian",
    version_id: "22.04",
    pretty_name: "Ubuntu 22.04 LTS",
};

/// Ubuntu 20.04 LTS, which the earlier `standard` build images are built on.
const UBUNTU_20_04: Distribution = Distribution {
    id: "ubuntu",
    name: "Ubuntu",
    id_like: "debian",
    version_id: "20.04",
    pretty_name: "Ubuntu 20.04 LTS",
};

/// The images CodeBuild manages itself, each with the distribution it is built on. See this
/// module's header for the source.
const CURATED_IMAGES: &[(&str, Distribution)] = &[
    ("aws/codebuild/standard:5.0", UBUNTU_20_04),
    ("aws/codebuild/standard:6.0", UBUNTU_22_04),
    ("aws/codebuild/standard:7.0", UBUNTU_22_04),
    ("aws/codebuild/amazonlinux2-x86_64-standard:4.0", AMAZON_LINUX_2),
    ("aws/codebuild/amazonlinux2-x86_64-standard:5.0", AMAZON_LINUX_2),
    ("aws/codebuild/amazonlinux2-aarch64-standard:2.0", AMAZON_LINUX_2),
    ("aws/codebuild/amazonlinux2-aarch64-standard:3.0", AMAZON_LINUX_2),
    ("aws/codebuild/amazonlinux-x86_64-standard:5.0", AMAZON_LINUX_2023),
    ("aws/codebuild/amazonlinux-aarch64-standard:3.0", AMAZON_LINUX_2023),
];

/// The distribution `image` is built on, or `None` for an image this environment knows no
/// filesystem of.
#[must_use]
pub fn distribution_of(image: &str) -> Option<Distribution> {
    let image = image.trim();
    CURATED_IMAGES
        .iter()
        .find(|(curated, _)| *curated == image)
        .map(|(_, distribution)| *distribution)
}

/// The files `image` presents in the build environment's filesystem, as `(path, contents)`
/// — empty for an image this environment knows no filesystem of.
#[must_use]
pub fn image_files(image: &str) -> Vec<(String, String)> {
    distribution_of(image)
        .map(|distribution| {
            vec![(
                OS_RELEASE_PATH.to_string(),
                distribution.os_release(),
            )]
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{distribution_of, image_files, AMAZON_LINUX_2023, OS_RELEASE_PATH};

    /// RULE: the image's release file is what identifies the distribution it is built on,
    /// and an image this environment knows no filesystem of presents none.
    #[test]
    fn an_images_filesystem_is_the_one_it_is_built_on() {
        let files = image_files("aws/codebuild/amazonlinux-x86_64-standard:5.0");
        assert_eq!(
            files.len(),
            1,
            "case \"a curated image\": expected its release file, got {files:?}"
        );
        assert_eq!(
            files[0].0, OS_RELEASE_PATH,
            "case \"a curated image\": expected the release file's path, got {files:?}"
        );
        assert_eq!(
            files[0].1,
            AMAZON_LINUX_2023.os_release(),
            "case \"a curated image\": expected its distribution's release file, got {files:?}"
        );
        // An entry of the catalog that is NOT the one above: the same lookup, a different
        // distribution.
        assert_eq!(
            distribution_of("aws/codebuild/standard:6.0").map(|held| held.id),
            Some("ubuntu"),
            "case \"another curated image\": expected the distribution it is built on"
        );
        for image in [
            "public.ecr.aws/docker/library/ubuntu:22.04",
            "aws/codebuild/windows-base:2019-3.0",
            "",
        ] {
            assert!(
                image_files(image).is_empty(),
                "case {image:?}: an image this environment knows no filesystem of presents none"
            );
        }
    }
}
