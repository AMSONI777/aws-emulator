// SPDX-License-Identifier: CC0-1.0

//! WHERE this service states a constraint one of a COLLECTION's ELEMENTS or one of a MAP's
//! VALUES broke, and WHAT that clause says such an element or value has to satisfy.
//!
//! # The rule
//!
//! The framework's constraint walk reports such a violation at the offending ELEMENT —
//! `<collection>.<1-based position>.member`, naming only the constraint that element broke
//! — while AWS reports it ONCE at the COLLECTION MEMBER, quoting the value that member held
//! (the whole list the caller sent) and nesting, inside
//! `Member must satisfy constraint: [ … ]`, every requirement an ELEMENT of that collection
//! has: the constraints the element shape declares, and — because no list this model
//! declares is `@sparse` — that an element must be present at all.
//!
//! A constraint declared on a MAP's VALUE shape is the same rule over the other collection:
//! the walk reports it at the offending ENTRY (`<map member>.<key>`, the key being the
//! caller's own text) with the one constraint that value broke, while AWS reports it once at
//! the MAP MEMBER, quoting the map the caller sent and nesting the value shape's whole
//! declared set inside `Map value must satisfy constraint: [ … ]` — the sibling of the
//! `Map keys must satisfy constraint: [ … ]` a clause about a key states
//! ([`crate::state::tag_key_shape`]).
//!
//! So one request sending a collection whose elements or values are not all admissible is
//! ONE validation error about one member, whatever an element or value got wrong and however
//! many of them got it wrong.
//!
//! # What is this service's and what is not
//!
//! Only the nested REQUIREMENT is stated here. The envelope, the member path, the value half
//! of the clause, the grouping itself and every clause about a violation that is not an
//! element's are `service-common`'s and the framework's
//! (`service_common::validation_message::aws_validation_refusal_over_elements_stating`,
//! which [`crate::service`] hands this to), so a caller cannot be told the same broken
//! constraint two ways and no sentence is spelled twice in the tree.
//!
//! The requirement is stated here rather than read off the schemas by that shared rendering
//! for two reasons, both properties of THIS model:
//!
//! * every list member of this model's input surface sits INSIDE a structure
//!   (`vpcConfig.subnetIds`, `instanceRequirements.architectures`, `imageConfig.command`,
//!   …), and a member schema carries its own traits and not the members of the shape it
//!   targets — so the member is looked up under its own name in the shape that DECLARES it
//!   ([`LIST_MEMBER_SHAPES`]);
//! * the set AWS states for this service carries the element's presence requirement beside
//!   the constraints the element shape declares.
//!
//! The two renderings [`crate::service`] owns reach the nested set as well, so a requirement
//! inside the brackets reads exactly like one a reported member gets: a `@pattern` without
//! the anchors a whole-value pattern wraps it in, and an enum's value set in the order this
//! service reports that enum in.
//!
//! The one half a MAP's clause needs beyond that is the VALUE it quotes — the map the request
//! carried, which no violation carries and which the shared walk reads back only for a map of
//! STRINGS. A `Weight` map's values are DOUBLES, so the map is read out of the request here
//! ([`submitted_maps`]), rendered through the shared renderer of that form, and handed to the
//! grouping as the collection it quotes.

use ::aws_smithy_schema::Schema;
use ::service_common::validation::unanchored;
use ::service_common::validation_message::{
    element_constraint_set, element_set_requirement, float_value_text, map_value_set_requirement,
    requirement,
};
use smithy_server_runtime::{Violation, ViolationKind};

/// The shapes a refused COLLECTION member is looked up in, to state the whole set of
/// requirements that member's ELEMENTS have.
///
/// Every structure of this model's INPUT surface that declares a list member, so that every
/// list a request can carry is reached: the operation inputs that declare one at their top
/// level, and the structures those inputs nest. A member schema carries its own traits and
/// not the members of the shape it targets, which is why the nested structures are handed
/// over themselves rather than reached through the input that carries them.
///
/// A member two of these shapes declare with DIFFERENT element constraints is not stated at
/// all (`service_common::validation_message::element_constraint_set` answers `None` for one,
/// since a refusal does not say which operation it came from): the collection members these
/// shapes share a name for — `subnetIds` and `securityGroupIds`, declared by the VPC
/// configuration of a function and by that of a capacity provider, and `architectures`,
/// declared by two function operations and by the instance requirements — target lists whose
/// ELEMENT shapes are the same (`SubnetId`, `SecurityGroupId`, `Architecture`), so each of
/// them has one set. Source: `smithy_query(query="shape", shape="CapacityProviderSubnetIds,\
/// SubnetIds,CapacityProviderSecurityGroupIds,SecurityGroupIds,ArchitecturesList")`.
///
/// A list of STRUCTURES (`filterCriteria.filters`) and a list whose element shape declares
/// no constraint at all declare no element constraint set, so a violation inside one keeps
/// the member path the walk reported it at.
const LIST_MEMBER_SHAPES: &[&Schema] = {
    use crate::ops::types;

    &[
        // The operation inputs that declare a list member themselves.
        types::CREATE_FUNCTION_INPUT_SCHEMA,
        types::UPDATE_FUNCTION_CONFIGURATION_INPUT_SCHEMA,
        types::UPDATE_FUNCTION_CODE_INPUT_SCHEMA,
        types::CREATE_EVENT_SOURCE_MAPPING_INPUT_SCHEMA,
        types::UPDATE_EVENT_SOURCE_MAPPING_INPUT_SCHEMA,
        types::PUBLISH_LAYER_VERSION_INPUT_SCHEMA,
        types::UNTAG_RESOURCE_INPUT_SCHEMA,
        types::LIST_DURABLE_EXECUTIONS_BY_FUNCTION_INPUT_SCHEMA,
        // And the structures those inputs nest.
        types::CAPACITY_PROVIDER_VPC_CONFIG_SCHEMA,
        types::INSTANCE_REQUIREMENTS_SCHEMA,
        types::VPC_CONFIG_SCHEMA,
        types::IMAGE_CONFIG_SCHEMA,
        types::CORS_SCHEMA,
        types::ALLOWED_PUBLISHERS_SCHEMA,
        types::EVENT_SOURCE_MAPPING_METRICS_CONFIG_SCHEMA,
    ]
};

/// The requirement a clause states at the collection member `collection` for a constraint
/// one of its ELEMENTS or VALUES broke — the element or value shape's whole declared set plus
/// that element's own presence requirement, nested — or `None` when no shape of this model
/// declares a single such set for that member, which leaves the framework's own per-element
/// clause standing.
///
/// `collection` is the member path the clause is stated at, as a violation path spells it.
/// A MAP of this model's input surface is matched by that whole path
/// ([`VALUE_CONSTRAINED_MAPS`]); a list member is declared in the shape it is nested in, so
/// it is looked up under the last segment of the path ([`LIST_MEMBER_SHAPES`]).
pub(crate) fn element_set(collection: &str) -> Option<String> {
    if let Some(set) = map_value_set(collection) {
        return Some(set);
    }
    let member = collection
        .rsplit_once('.')
        .map_or(collection, |(_, member)| member);
    let declared = element_constraint_set(LIST_MEMBER_SHAPES, member)?;
    let mut requirements: Vec<String> = declared.into_iter().map(stated_requirement).collect();
    // No list this model declares is `@sparse`, so an element has to be there at all, and
    // the set states that beside the constraints its shape declares. The sentence is the
    // framework's own for an absent member, so the set spells no requirement of its own.
    requirements.push(requirement(ViolationKind::MissingRequiredMember));
    Some(element_set_requirement(&requirements))
}

/// One requirement of an element shape, as this service states it: the sentence is the
/// framework's (`service_common::validation_message::requirement`) and the two renderings
/// [`crate::service`] owns are applied to it first, so a requirement nested in a
/// collection's clause reads exactly like the same requirement on a reported member.
fn stated_requirement(declared: ViolationKind) -> String {
    requirement(match declared {
        // The CHECK always ran the model's pattern as written; only the rendering of the
        // expression drops the whole-value anchors.
        ViolationKind::Pattern(pattern) => ViolationKind::Pattern(unanchored(&pattern)),
        ViolationKind::EnumValue(allowed) => {
            ViolationKind::EnumValue(super::reported_enum_order(&allowed))
        }
        other => other,
    })
}

/// One MAP member of this model's INPUT surface whose VALUE shape declares constraints: the
/// member path a clause about one of its values is stated at, the shapes that member is
/// looked up in, and whether its values are FLOATING POINT.
struct ValueConstrainedMap {
    /// The member path a violation at one of this map's values is grouped onto, as a
    /// violation path spells it — the whole path, so a map nested in a structure member is
    /// matched there and nowhere else.
    path: &'static str,
    /// The shapes the member is looked up in to read the value shape's declared constraints.
    /// A member schema carries its own traits and not the members of the shape it targets, so
    /// a nested map's declaring structure is handed over itself; a member two of them declare
    /// over DIFFERENT value shapes is not stated at all
    /// (`service_common::validation_message::element_constraint_set`).
    declared_in: &'static [&'static Schema],
    /// Whether the values are floating point, which decides how a `@range` bound in the set
    /// is written ([`stated_value_requirement`]) and how an entry of the quoted map is
    /// ([`rendered_entry`]).
    ///
    /// STATED rather than read, and the one fact of this row that is: codegen attaches a
    /// collection member's ELEMENT CONSTRAINTS to the member schema and not the element's own
    /// TYPE (`vendor/smithy-macros/src/codegen.rs`, `extract_element_constraints`), and the
    /// member's own `shape_type` is the MAP's — so the value shape's numeric kind is reachable
    /// from the model text alone, which is where the row above cites it from. The set each row
    /// produces is pinned in this module's own tests, so a row that comes to disagree with the
    /// model fails there rather than silently writing an integral bound where AWS writes a
    /// decimal one.
    floating_point: bool,
}

/// Every MAP member of this model's input surface whose VALUE shape declares a constraint, so
/// that every map a request can carry a refused value in is reached.
///
/// Source: `smithy_query(query="shape", shape="AdditionalVersionWeights,Weight,Tags,\
/// TagValue,EnvironmentVariables")`. `AdditionalVersionWeights` targets the `Weight` double
/// under `@range(0.0, 1.0)` and is declared by the routing configuration both alias requests
/// nest; `Tags` targets the `TagValue` string under a `@length` and a `@pattern` and is
/// declared at the top level of the two requests that take one. `EnvironmentVariables` is the
/// third map this surface declares and its value shape declares NO constraint, so no value of
/// it can be refused and it states no set.
const VALUE_CONSTRAINED_MAPS: &[ValueConstrainedMap] = {
    use crate::ops::types;

    &[
        ValueConstrainedMap {
            path: "routingConfig.additionalVersionWeights",
            declared_in: &[types::ALIAS_ROUTING_CONFIGURATION_SCHEMA],
            floating_point: true,
        },
        ValueConstrainedMap {
            path: "tags",
            declared_in: &[
                types::CREATE_FUNCTION_INPUT_SCHEMA,
                types::TAG_RESOURCE_INPUT_SCHEMA,
            ],
            floating_point: false,
        },
    ]
};

/// The map of this model `path` names, or `None` for every other member path.
fn value_constrained_map(path: &str) -> Option<&'static ValueConstrainedMap> {
    VALUE_CONSTRAINED_MAPS
        .iter()
        .find(|declared| declared.path == path)
}

/// The requirement a clause states at the MAP member `map` for a constraint one of its VALUES
/// broke — the value shape's whole declared set plus the value's own presence requirement,
/// nested in `Map value must satisfy constraint: [ … ]` — or `None` when `map` names no map
/// of this model whose values are constrained.
fn map_value_set(map: &str) -> Option<String> {
    let declared = value_constrained_map(map)?;
    let member = map.rsplit_once('.').map_or(map, |(_, member)| member);
    let constraints = element_constraint_set(declared.declared_in, member)?;
    let mut requirements: Vec<String> = constraints
        .into_iter()
        .map(|constraint| stated_value_requirement(constraint, declared.floating_point))
        .collect();
    // No map this model declares is `@sparse`, so an entry's value has to be there at all,
    // exactly as a list's element has to be: the set states that beside the constraints the
    // value shape declares.
    requirements.push(requirement(ViolationKind::MissingRequiredMember));
    Some(map_value_set_requirement(&requirements))
}

/// One requirement of a map's VALUE shape, as this service states it: [`stated_requirement`]
/// over the same sentences, with a `@range` bound of a FLOATING-POINT value shape written as
/// the decimal a floating-point value is written with.
///
/// The framework renders a bound read off the model without a fractional part (`1`, not
/// `1.0`), which is what an INTEGRAL value shape's bound reads as; a floating-point shape's
/// bound is a floating-point value and is written as one, through the one function that
/// writes a floating-point value into a clause
/// (`service_common::validation_message::float_value_text`, which this module also renders a
/// quoted entry with).
fn stated_value_requirement(declared: ViolationKind, floating_point: bool) -> String {
    if !floating_point {
        return stated_requirement(declared);
    }
    stated_requirement(match declared {
        ViolationKind::MinValue(bound) => ViolationKind::MinValue(decimal_bound(&bound)),
        ViolationKind::MaxValue(bound) => ViolationKind::MaxValue(decimal_bound(&bound)),
        other => other,
    })
}

/// `bound` as a floating-point value is written, or unchanged when it is no number at all.
fn decimal_bound(bound: &str) -> String {
    match bound.parse::<f64>() {
        Ok(value) => float_value_text(value),
        Err(_) => bound.to_string(),
    }
}

/// The MAP member of this model a violation at `path` belongs to, or `None` when `path` is
/// not one of a map value's.
///
/// The framework reports a map entry's VALUE at `<map member>.<key>`, where the key is the
/// caller's own text and may itself carry a `.`, so the member is matched as the PREFIX of
/// the path rather than by splitting it: a key that looks like a member name, and a nested
/// structure member whose name collides with a key, both stay with the member they came from.
///
/// The remainder has to be a key and nothing deeper. Every map named here is a map of
/// SCALARS, so the walk reports its entries at the entry itself and never below one; a map
/// of STRUCTURES would be reported at `<map member>.<key>.member.<field>`
/// (`vendor/smithy-schema-server/src/constraints.rs`), which is a violation about a member
/// INSIDE an entry rather than about the entry's value, so the collection step a nested
/// report carries excludes it.
pub(crate) fn map_of_entry(path: &str) -> Option<&'static str> {
    VALUE_CONSTRAINED_MAPS
        .iter()
        .find(|declared| {
            path.strip_prefix(declared.path)
                .and_then(|entry| entry.strip_prefix('.'))
                .is_some_and(|key| !key.is_empty() && !key.contains(ENTRY_MEMBER_STEP))
        })
        .map(|declared| declared.path)
}

/// The step the framework's constraint walk names a collection's child by, which a report
/// about a member INSIDE a map's entry carries and a report about the entry's own value does
/// not (`aws_smithy_schema_server::constraints::path`).
const ENTRY_MEMBER_STEP: &str = ".member.";

/// The MAPS a clause of this refusal quotes: the map the REQUEST carried at each member one
/// of `violations` is about, keyed by the member path that clause is stated at, in the form
/// the shared renderer of a map writes (`{<key>=<value>, …}`, in key order).
///
/// Only a map a violation names is read, and each is read by the shared reader of a map a
/// request body carries (`service_common::submitted_collections`) rather than by a second
/// traversal of this crate's own: the map is read at the dotted member path the clause is
/// stated at, matching each step without regard to case, because a violation path spells a
/// member in lowerCamel while a body carries the wire name the model declares. The SCALAR
/// reader is the one taken, because this model's weights map holds doubles rather than
/// strings. So a refusal reads the body for at most as many members as this model declares
/// constrained maps ([`VALUE_CONSTRAINED_MAPS`]) — a bound from the MODEL and not from the
/// request, whatever member paths a caller's own keys shape. A map whose rendering is past
/// the largest value one clause quotes, and one carrying a value that is no scalar at all,
/// are not offered: the clause then states the member and the set with no value, exactly as
/// it does for a collection whose own `@length` was broken.
///
/// Key order because that is the one order one request's map is stated in twice: the shared
/// walk reads the BUILT input, where a map keeps no wire order, so the order its entries were
/// written in is not recoverable from it — and a clause this service states about a map's
/// KEYS already states one in key order (`crate::state::tag_key_shape`).
pub(crate) fn submitted_maps(
    req: &::aws_smithy_runtime_api::http::Request,
    violations: &[Violation],
) -> ::std::collections::HashMap<String, String> {
    let refused: ::std::collections::BTreeSet<&str> = violations
        .iter()
        .filter_map(|violation| map_of_entry(&violation.path))
        .collect();
    if refused.is_empty() {
        return ::std::collections::HashMap::new();
    }
    let Some(body) = req.body().bytes() else {
        return ::std::collections::HashMap::new();
    };
    refused
        .into_iter()
        .filter_map(|map| Some((map.to_string(), rendered_submitted_map(body, map)?)))
        .collect()
}

/// The map the request body `body` carries at the member path `map`, rendered as a clause
/// quotes one, or `None` when the body carries no map of scalars there.
fn rendered_submitted_map(body: &[u8], map: &str) -> Option<String> {
    let floating_point = value_constrained_map(map).is_some_and(|declared| declared.floating_point);
    let steps: Vec<&str> = map.split('.').collect();
    let held = ::service_common::submitted_collections::submitted_scalar_map_entries_at(
        body, &steps,
    )?;
    let entries: Vec<(&str, String)> = held
        .iter()
        .map(|(key, value)| (key.as_str(), rendered_entry(value, floating_point)))
        .collect();
    ::service_common::validation::rendered_map_in_key_order(&entries)
}

/// One entry's value as a clause quotes it: the text the document wrote it with, which is
/// what the reader above hands over — except for a FLOATING-POINT value shape, whose value a
/// clause writes as the decimal a floating-point value is written with
/// (`service_common::validation_message::float_value_text`), so a weight sent as `2` is
/// quoted `2.0`. A value of that shape the reader did not hand over as a number keeps the
/// text it was written with, because nothing else is known about it.
fn rendered_entry(value: &str, floating_point: bool) -> String {
    match (floating_point, value.parse::<f64>()) {
        (true, Ok(held)) => float_value_text(held),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    //! The set this module states, over the collection members of this model's input
    //! surface rather than the one a report cited. The clause around it, and the status and
    //! error code it travels in, are pinned on the wire in
    //! `tests/all/collection_element_refusals.rs`.

    use super::*;

    /// RULE: a collection member's nested set is the element shape's whole declared set,
    /// each requirement in the framework's words, followed by the element's own presence
    /// requirement — and a member no shape declares a set for is not stated at all.
    ///
    /// The rows span what the set generalises over: the constraint CLASSES an element shape
    /// declares (an enum value set, a length pair with a pattern), how deeply the member is
    /// nested, and a member declared by two shapes over the same element shape.
    #[test]
    fn a_collections_nested_set_is_every_requirement_its_elements_have() {
        let not_null = requirement(ViolationKind::MissingRequiredMember);
        let rows: &[(&str, Option<String>)] = &[
            (
                // The enum element shape `Architecture`, nested one structure deep.
                "instanceRequirements.architectures",
                Some(format!(
                    "Member must satisfy constraint: [Member must satisfy enum value set: \
                     [x86_64, arm64], {not_null}]"
                )),
            ),
            (
                // The same member declared at an operation input's top level: one set.
                "architectures",
                Some(format!(
                    "Member must satisfy constraint: [Member must satisfy enum value set: \
                     [x86_64, arm64], {not_null}]"
                )),
            ),
            (
                // A length pair and a pattern, stated maximum first and with the anchors
                // the model writes dropped.
                "vpcConfig.subnetIds",
                Some(format!(
                    "Member must satisfy constraint: [Member must have length less than or \
                     equal to 1024, Member must have length greater than or equal to 0, \
                     Member must satisfy regular expression pattern: subnet-[0-9a-z]*, \
                     {not_null}]"
                )),
            ),
            (
                "vpcConfig.securityGroupIds",
                Some(format!(
                    "Member must satisfy constraint: [Member must have length less than or \
                     equal to 1024, Member must have length greater than or equal to 0, \
                     Member must satisfy regular expression pattern: sg-[0-9a-zA-Z]*, \
                     {not_null}]"
                )),
            ),
            (
                "instanceRequirements.allowedInstanceTypes",
                Some(format!(
                    "Member must satisfy constraint: [Member must have length less than or \
                     equal to 30, Member must have length greater than or equal to 1, \
                     Member must satisfy regular expression pattern: [a-zA-Z0-9\\.\\*\\-]+, \
                     {not_null}]"
                )),
            ),
            (
                "tagKeys",
                Some(format!(
                    "Member must satisfy constraint: [Member must have length less than or \
                     equal to 128, Member must have length greater than or equal to 1, \
                     Member must satisfy regular expression pattern: \
                     ([\\p{{L}}\\p{{Z}}\\p{{N}}_.:/=+\\-@]*), {not_null}]"
                )),
            ),
            // Members no shape of this model declares an element constraint set for.
            ("filterCriteria.filters", None),
            ("functionName", None),
            ("", None),
        ];

        for (collection, expected) in rows {
            let stated = element_set(collection);
            assert_eq!(
                stated.as_deref(),
                expected.as_deref(),
                "case {collection:?}: expected {expected:?}, got {stated:?}"
            );
        }
    }

    /// RULE: a MAP member's nested set is the value shape's whole declared set, each
    /// requirement in the framework's words — a `@range` bound of a floating-point value
    /// shape written as the decimal a floating-point value is written with — followed by the
    /// value's own presence requirement; and a member this model declares no constrained map
    /// at is not stated at all.
    ///
    /// The rows are every map of [`VALUE_CONSTRAINED_MAPS`], so the set is pinned for the two
    /// constraint classes a value shape of this model declares (a numeric range on a double,
    /// a length pair with a pattern on a string) rather than for the one a report cited.
    #[test]
    fn a_maps_nested_set_is_every_requirement_its_values_have() {
        let not_null = requirement(ViolationKind::MissingRequiredMember);
        let rows: &[(&str, Option<String>)] = &[
            (
                // `Weight`, a DOUBLE under `@range(0.0, 1.0)`: both bounds are written as
                // the decimals a floating-point value is written with.
                "routingConfig.additionalVersionWeights",
                Some(format!(
                    "Map value must satisfy constraint: [Member must have value less than or \
                     equal to 1.0, Member must have value greater than or equal to 0.0, \
                     {not_null}]"
                )),
            ),
            (
                // `TagValue`, a string under a `@length` and a `@pattern`, whose expression
                // is quoted without the anchors a whole-value pattern wraps it in.
                "tags",
                Some(format!(
                    "Map value must satisfy constraint: [Member must have length less than or \
                     equal to 256, Member must have length greater than or equal to 0, \
                     Member must satisfy regular expression pattern: \
                     ([\\p{{L}}\\p{{Z}}\\p{{N}}_.:/=+\\-@]*), {not_null}]"
                )),
            ),
            // The third map of this input surface declares no value constraint at all, and
            // neither does a member that is no map.
            ("environment.variables", None),
            ("routingConfig", None),
            ("functionName", None),
            ("", None),
        ];

        for (map, expected) in rows {
            let stated = element_set(map);
            assert_eq!(
                stated.as_deref(),
                expected.as_deref(),
                "case {map:?}: expected {expected:?}, got {stated:?}"
            );
        }
    }

    /// RULE: a violation is grouped onto a map member only when its path names that member's
    /// own ENTRY — the member as a prefix, then a key, and nothing deeper — so a key carrying
    /// a `.`, a member whose name a key collides with, and a report about a member INSIDE an
    /// entry each stay where they were reported.
    #[test]
    fn only_a_violation_about_an_entrys_own_value_is_grouped_onto_its_map() {
        // (case, the violation path, the map it belongs to)
        let rows: &[(&str, &str, Option<&str>)] = &[
            (
                "an entry of a nested map",
                "routingConfig.additionalVersionWeights.2",
                Some("routingConfig.additionalVersionWeights"),
            ),
            (
                "an entry whose key carries a dot",
                "tags.cost.centre",
                Some("tags"),
            ),
            ("an entry at the top level", "tags.owner", Some("tags")),
            // The map member itself, a member whose name opens one of theirs, and a report
            // about a member inside an entry.
            ("the map member itself", "tags", None),
            ("an entry with no key at all", "tags.", None),
            ("another member entirely", "tagKeys.1.member", None),
            (
                "a member inside an entry",
                "tags.owner.member.name",
                None,
            ),
        ];

        for (case, path, expected) in rows {
            let grouped = map_of_entry(path);
            assert_eq!(
                grouped, *expected,
                "case {case:?}: expected {expected:?}, got {grouped:?}"
            );
        }
    }
}
