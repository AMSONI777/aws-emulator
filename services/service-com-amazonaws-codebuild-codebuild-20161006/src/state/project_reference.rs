// SPDX-License-Identifier: CC0-1.0

//! What a PROJECT IDENTIFIER names — the one reading of a value an operation that reports
//! on a build project takes as "the name or the ARN of the project".
//!
//! Those members are typed as plain strings (`BatchGetProjectsInput$names` targets
//! `NonEmptyString`, as does every per-project listing's `projectName`), so the model
//! constrains nothing about their form and an ARN is a legal value there —
//! `BatchGetProjectsInput$names` says so outright ("The names or ARNs of the build
//! projects"). An identifier that IS an ARN is therefore PARSED rather than taken for a
//! name, and its fields decide the answer before any lookup runs:
//!
//! 1. a value that is no project ARN of this service is the project NAME itself;
//! 2. a project ARN whose region field cannot be a Region name is refused on that field,
//!    by the one rule every ARN-addressed operation of this service reads an ARN's fields
//!    with ([`super::arn_region_violation`]);
//! 3. a project ARN naming a Region OTHER than the one the request is signed for is an
//!    input error: a project is a regional resource, so an ARN of another Region names no
//!    project this endpoint can answer about and the value has to be repaired
//!    ([`INVALID_PROJECT_ARN_REGION_MESSAGE`]);
//! 4. a project ARN naming an account other than the one this emulator serves is a
//!    question about ANOTHER account's project. A project of another account is readable
//!    only where that project's own resource-based policy grants this account the action
//!    ("To get information about a project shared with your Amazon Web Services account,
//!    its ARN must be specified"), and a policy is attached only to a resource the
//!    attaching account holds (`crate::ops::put_resource_policy`), so no ARN of another
//!    account carries one here and the call is an authorization failure rather than a
//!    not-found result;
//! 5. anything else resolves on the ARN's RESOURCE NAME, which is what the project store
//!    is keyed by — so the ARN every other API hands back resolves exactly as the bare
//!    name does.
//!
//! Stated once, here, because the question "which project does this value name" has one
//! answer for every operation that asks it: the batch read of projects and the per-project
//! listings must not resolve, refuse or deny one identifier three different ways.

use super::{
    arn_account, arn_region, arn_region_violation, is_arn, project_arn, project_name_from_arn,
};

/// What CodeBuild states as the reason a project ARN it was handed belongs to another
/// Region, carried by the modelled `InvalidInputException`.
///
/// Wholly fixed text — recorded behaviour, as the model states no message for the error:
/// it names neither the ARN nor either Region, so every cross-Region ARN is refused with
/// the same words and a client can key on them. It is the REGION-MATCH question, which is
/// asked only once the region field reads as a Region name at all
/// ([`super::invalid_arn_region_message`] is the answer when it does not).
pub const INVALID_PROJECT_ARN_REGION_MESSAGE: &str =
    "Invalid project ARN: region does not match caller's region";

/// Why a project ARN cannot be resolved for the caller that sent it: the ARN fields are
/// read in order, so the variant is the FIRST question the value fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectArnRefusal<'a> {
    /// A field of the ARN is not well formed — the sentence naming that field and quoting
    /// its value, as [`super::arn_region_violation`] words it. An input error.
    Malformed(String),
    /// The ARN's region field is a Region name, but not the Region the request was signed
    /// for. An input error, stated in [`INVALID_PROJECT_ARN_REGION_MESSAGE`].
    ForeignRegion,
    /// The ARN names a project of another account, carried back so the authorization
    /// refusal can name the resource the request addressed exactly as it was sent.
    ForeignAccount(&'a str),
}

/// A project identifier, read.
///
/// Carries the project NAME the store is keyed by, and the ARN the request addressed the
/// project by when it used one — which is what lets a refusal quote the identifier as the
/// request sent it instead of splicing an already-ARN value into an ARN template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectReference<'a> {
    name: &'a str,
    arn: Option<&'a str>,
}

impl<'a> ProjectReference<'a> {
    /// Read `identifier` as the project it names for a request signed for
    /// `caller_region`, or the first question the value fails.
    ///
    /// The module docs state the order. Nothing is looked up here: the answer is a
    /// function of the value and the request's own Region, which is why an operation can
    /// state these refusals before it takes the store's lock.
    pub fn parse(
        identifier: &'a str,
        caller_region: &str,
    ) -> Result<Self, ProjectArnRefusal<'a>> {
        let Some(name) = project_name_from_arn(identifier) else {
            // No project ARN of this service: the value is the name itself. A name that
            // cannot be written as one is a different question, asked by
            // [`super::project_identifier_violation`]. A value that is an ARN of SOMETHING
            // else still carries itself into a refusal as sent — an ARN is never spliced
            // into an ARN template, whatever it names.
            return Ok(Self {
                name: identifier,
                arn: is_arn(identifier).then_some(identifier),
            });
        };
        if let Some(message) = arn_region_violation(identifier) {
            return Err(ProjectArnRefusal::Malformed(message));
        }
        if arn_region(identifier) != Some(caller_region) {
            return Err(ProjectArnRefusal::ForeignRegion);
        }
        if arn_account(identifier) != Some(::emulator_server::emulator_account_id()) {
            return Err(ProjectArnRefusal::ForeignAccount(identifier));
        }
        Ok(Self {
            name,
            arn: Some(identifier),
        })
    }

    /// The project name this reference resolves to — the key the project store, and every
    /// per-project index beside it, is keyed by.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// The identifier exactly as the request sent it, which is what a lookup resolves and
    /// what a not-found answer reports back: the ARN when the request used one, so a
    /// caller that asked by ARN can match the answer to what it asked, and the name
    /// otherwise.
    pub fn identifier(&self) -> &'a str {
        self.arn.unwrap_or(self.name)
    }

    /// The ARN of the project this reference names: the one the request supplied, or the
    /// ARN the name resolves to in the Region the call is signed for.
    ///
    /// The one place a project-quoting refusal gets its ARN, so an identifier that is
    /// ALREADY an ARN — of a project or of anything else — is never interpolated into an
    /// ARN template, which would state an ARN naming no resource at all.
    pub fn arn(&self, region: &str) -> String {
        match self.arn {
            Some(arn) => arn.to_string(),
            None => project_arn(region, self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Region every row below is signed for.
    const REGION: &str = "us-west-2";

    /// A project ARN of this emulator's own account in `region`.
    fn arn_in(region: &str, name: &str) -> String {
        format!(
            "arn:aws:codebuild:{region}:{}:project/{name}",
            ::emulator_server::emulator_account_id()
        )
    }

    /// RULE: a value that is no project ARN of this service is the project name itself,
    /// and the ARN it is quoted by is the one that name resolves to in the signed Region —
    /// unless the value is already an ARN, which is quoted as sent.
    #[test]
    fn a_value_that_is_no_project_arn_is_the_name() {
        // The forms a project identifier takes that are not a project ARN of this
        // service: a bare name, an ARN of another resource kind of this service, an ARN
        // of another service, and a value with fewer than an ARN's six fields.
        let rows = [
            ("a bare name", "held-project", false),
            (
                "an ARN of another resource kind",
                "arn:aws:codebuild:us-west-2:000000000000:report-group/held-project",
                true,
            ),
            (
                "an ARN of another service",
                "arn:aws:codepipeline:us-west-2:000000000000:held-project",
                true,
            ),
            (
                "a value with too few fields",
                "arn:aws:codebuild:us-west-2",
                false,
            ),
        ];
        for (case, identifier, is_an_arn) in rows {
            let reference = ProjectReference::parse(identifier, REGION)
                .unwrap_or_else(|refusal| panic!("case {case:?}: expected a name, got {refusal:?}"));
            assert_eq!(
                reference.name(),
                identifier,
                "case {case:?}: expected the value itself as the name, got {:?}",
                reference.name()
            );
            assert_eq!(
                reference.identifier(),
                identifier,
                "case {case:?}: expected the value reported back as sent, got {:?}",
                reference.identifier()
            );
            let expected = if is_an_arn {
                identifier.to_string()
            } else {
                arn_in(REGION, identifier)
            };
            assert_eq!(
                reference.arn(REGION),
                expected,
                "case {case:?}: expected {expected:?} quoted, got {:?}",
                reference.arn(REGION)
            );
        }
    }

    /// RULE: a project ARN of the caller's own Region and account resolves on its resource
    /// name, and is quoted back as the request sent it.
    #[test]
    fn the_callers_own_project_arn_resolves_on_its_resource_name() {
        // Names spanning what a project name may carry (`ProjectName`'s pattern:
        // alphanumerics, dash, underscore).
        for name in ["held-project", "held_project", "P9", "a-b_c-0"] {
            let arn = arn_in(REGION, name);
            let reference = ProjectReference::parse(&arn, REGION)
                .unwrap_or_else(|refusal| panic!("case {name:?}: expected a project, got {refusal:?}"));
            assert_eq!(
                reference.name(),
                name,
                "case {name:?}: expected the ARN's resource name, got {:?}",
                reference.name()
            );
            assert_eq!(
                reference.arn(REGION),
                arn,
                "case {name:?}: expected the ARN as sent, got {:?}",
                reference.arn(REGION)
            );
        }
    }

    /// RULE: the region field is read before the account field, so an ARN that misses both
    /// is refused on the region; and a malformed region field is refused as a malformed
    /// field rather than as a Region mismatch.
    #[test]
    fn the_arn_fields_are_read_in_order() {
        let other_account = "arn:aws:codebuild:eu-west-3:210987654321:project/held-project";
        assert_eq!(
            ProjectReference::parse(other_account, REGION),
            Err(ProjectArnRefusal::ForeignRegion),
            "case \"another Region and another account\": expected the region to be read first"
        );
        let malformed = "arn:aws:codebuild:REGION:000000000000:project/held-project";
        assert_eq!(
            ProjectReference::parse(malformed, REGION),
            Err(ProjectArnRefusal::Malformed(
                super::super::invalid_arn_region_message("REGION")
            )),
            "case \"a region field that is no Region name\": expected the field refusal"
        );
    }

    /// RULE: an ARN of another account is an authorization question, and the refusal names
    /// the ARN the request sent.
    #[test]
    fn an_arn_of_another_account_is_carried_back_for_the_authorization_refusal() {
        let foreign = format!("arn:aws:codebuild:{REGION}:210987654321:project/held-project");
        assert_eq!(
            ProjectReference::parse(&foreign, REGION),
            Err(ProjectArnRefusal::ForeignAccount(&foreign)),
            "case \"another account\": expected the ARN carried into the refusal"
        );
    }
}
