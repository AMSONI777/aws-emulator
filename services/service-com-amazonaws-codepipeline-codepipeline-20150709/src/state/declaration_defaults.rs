// SPDX-License-Identifier: CC0-1.0

//! The members of a `PipelineDeclaration` the SERVICE fills in rather than the caller,
//! and the projection every operation that answers with a pipeline structure reports
//! through.
//!
//! A declaration is stored as the caller sent it, but a pipeline has a value for every
//! member the service resolves on its behalf — its type, its execution mode, each
//! action's run order and its configuration — so a client that reads a structure back
//! reads those values rather than having to know the defaults. The two halves live
//! together here because they are one rule seen twice: what a member with no declared
//! value RESOLVES to, and what the structure a caller reads back therefore CARRIES.

use super::*;

/// The `pipelineType` a declaration resolves to: the one it states, else
/// [`DEFAULT_PIPELINE_TYPE`].
///
/// A declaration that states a type keeps it — `UpdatePipeline` is how a pipeline's type
/// is changed — and one that states none is the service's current default type, which is
/// also what `PipelineDeclaration$pipelineType` describes as the type carrying the
/// release-safety and trigger parameters ("V2 type pipelines have the same structure as a
/// V1 type, along with additional parameters for release safety and trigger
/// configuration"): a declaration that names no type is not limited to the V1 parameter
/// set, including the "V2 parameters, such as triggers on Git tags" the same member
/// documents as making a pipeline V2.
pub fn resolved_pipeline_type(declaration: &PipelineDeclaration) -> String {
    declaration
        .pipeline_type
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_PIPELINE_TYPE)
        .to_string()
}

/// The `executionMode` a declaration resolves to: the one it states, else
/// [`DEFAULT_EXECUTION_MODE`].
pub fn resolved_execution_mode(declaration: &PipelineDeclaration) -> String {
    declaration
        .execution_mode
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_EXECUTION_MODE)
        .to_string()
}

/// The pipeline structure to REPORT for `declaration`: the stored one, with every member
/// the service resolves for an action declaration present on it.
///
/// A caller reads a structure back to diff it against the one it submitted, to render the
/// stage graph, or to edit it and send it to `UpdatePipeline` — so every member the
/// SERVICE decides the value of belongs to the structure it reports, or such an
/// edit-then-update cycle would drop the service's own value for it:
///
/// * `ActionDeclaration$inputArtifacts` ("The name or ID of the artifact consumed by the
///   action") and `$outputArtifacts` ("The name or ID of the result of the action
///   declaration") target lists with no minimum length, so an action that consumes or
///   produces nothing has an EMPTY list rather than no list at all;
/// * `$configuration` targets `ActionConfigurationMap`, a map with no minimum size, so an
///   action that configures nothing has an EMPTY map — the same rule the two artifact
///   lists follow;
/// * `$runOrder` is the order the action runs in, and an action that declares none runs in
///   [`DEFAULT_RUN_ORDER`], which is the order the execution plane plans it at
///   ([`run_order`]) and therefore the order the structure reports.
///
/// The ONE place this projection lives, so `CreatePipeline`, `UpdatePipeline` and
/// `GetPipeline` cannot disagree about the structure they report. Nothing else is
/// resolved here: every other member is reported exactly as stored.
pub fn reported_declaration(declaration: &PipelineDeclaration) -> PipelineDeclaration {
    let mut reported = declaration.clone();
    for stage in &mut reported.stages {
        for action in &mut stage.actions {
            if action.input_artifacts.is_none() {
                action.input_artifacts = Some(Vec::new());
            }
            if action.output_artifacts.is_none() {
                action.output_artifacts = Some(Vec::new());
            }
            if action.configuration.is_none() {
                action.configuration = Some(HashMap::new());
            }
            action.run_order = Some(run_order(action));
        }
    }
    reported
}

/// Whether two pipeline structures describe the SAME pipeline, member for member.
///
/// Both are read through [`reported_declaration`] first, so a structure that states a member
/// the service resolves and one that leaves it to the service describe the same pipeline:
/// re-submitting what `GetPipeline` answered — the normal shape of an idempotent re-apply —
/// states exactly the values this service filled in, and that is no difference from what is
/// stored. The `version` member is not part of the comparison: it is the SERVICE's own
/// number, so what a submitted declaration carries for it (a stale one read back, say) says
/// nothing about whether the structure differs.
///
/// The comparison is made on the modelled shape rendered by this service's own JSON codec
/// rather than member by member: the modelled structures derive no equality, and a
/// declaration holds `HashMap` members (an action's `configuration`, the `artifactStores`
/// map) whose iteration order comes from a per-process hash seed, so neither `Debug` nor the
/// rendered bytes of two equal declarations match, while `serde_json::Value`'s own equality
/// compares objects member by member whichever map backs them and keeps the order of the
/// modelled sequences.
///
/// A declaration the codec cannot render is not shown to be the stored one, so a write
/// carrying it is applied as the change it cannot be told apart from.
pub fn declarations_match(stored: &PipelineDeclaration, submitted: &PipelineDeclaration) -> bool {
    let mut stored = reported_declaration(stored);
    let mut submitted = reported_declaration(submitted);
    stored.version = None;
    submitted.version = None;
    match (rendered_declaration(&stored), rendered_declaration(&submitted)) {
        (Some(stored), Some(submitted)) => stored == submitted,
        _ => false,
    }
}

/// One pipeline structure as the JSON value this service's own codec renders for it, which
/// is what makes two of them comparable at all (see [`declarations_match`]).
///
/// A structure the codec cannot render answers `None`, so the comparison is impossible
/// rather than false and the caller decides what to do with that.
fn rendered_declaration(declaration: &PipelineDeclaration) -> Option<::serde_json::Value> {
    use ::aws_smithy_schema::serde::ShapeSerializer;

    let mut serializer = ::aws_smithy_schema_server::json::JsonShapeSerializer::new();
    if let Err(error) = serializer.write_struct(&PipelineDeclaration::SCHEMA, declaration) {
        ::tracing::warn!(
            %error,
            "the JSON codec could not render a pipeline structure, so two of them cannot be compared"
        );
        return None;
    }
    match ::serde_json::from_str::<::serde_json::Value>(&serializer.into_string()) {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            ::tracing::warn!(
                %error,
                "the JSON this service renders for a pipeline structure did not parse back"
            );
            None
        }
    }
}
