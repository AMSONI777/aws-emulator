// SPDX-License-Identifier: CC0-1.0

//! Applying a stored data transformation profile's MAPPING to submitted clinical
//! data: the transform behind the data-transformation endpoint's synchronous
//! surface ([`crate::service::transform_data`]).
//!
//! # What a mapping declares
//!
//! A profile's content is a map of file path to file content (the modelled
//! `ProfileMapping`), and what those files DECLARE is how a source record becomes
//! FHIR R4: the source table a record comes from, the resource type its records
//! become, and one rule per source column naming the element of that resource the
//! column's value is written to. Two spellings of that declaration reach this
//! module, and both are read here because both are content this service holds:
//!
//! * the mapping config a caller writes — a document of `tables` ->
//!   `resourceMappings` -> `fieldMappings`, each rule binding a `sourceColumn` to
//!   the `fhirPath` of a `targetResourceType`; and
//! * the per-entry rule files this service itself computes when a create resolves
//!   its content from a sample data file or from the starter profile library
//!   ([`super::sample_data`], [`super::starter_profiles`]), each binding a
//!   `sourceColumn` — or, for C-CDA, a `sourceSection` — to a `targetElement` of a
//!   `targetResourceType`.
//!
//! Both are read by ONE parser, the maintained `yaml-rust2`: a profile's content is
//! YAML, and YAML 1.2 is a superset of JSON, so the JSON rule files parse as YAML
//! too. Nothing here reads a file's name or extension and nothing matches on the
//! source text: what a file declares is read out of its parse tree, and a key is
//! matched on its letters and digits alone ([`super::normalized_content_name`]), so
//! a declaration is read however its document spells a key's word separators and
//! case.
//!
//! # What a transform produces
//!
//! One FHIR R4 `Bundle` ([`BUNDLE_TYPE`]), carrying the resources the mapping's
//! rules produced from the submitted input — one resource per declared resource
//! mapping per CSV data row, and one per C-CDA section a rule names — plus, when the
//! caller asked for drift detection, the [`DriftFinding`]s that comparing the
//! mapping against the submitted input found. A rule that writes nothing for a
//! record produces no resource: a resource carrying no mapped element would be an
//! answer nothing computed.
//!
//! Every input the caller controls is bounded before it is walked
//! ([`MAX_TRANSFORM_INPUT_BYTES`], [`MAX_TRANSFORM_ROWS`],
//! [`MAX_TRANSFORM_RESOURCES`]), and so is every stored mapping file
//! ([`MAX_MAPPING_NESTING`], [`MAX_MAPPING_INDENT`]): the work one call does is a
//! product of those ceilings rather than of anything a request chose.

use std::collections::{BTreeMap, BTreeSet};

use ::json_dotpath::DotPaths;

use super::normalized_content_name;

/// The most BYTES of input one synchronous transform reads, across every file the
/// request carries.
///
/// A ceiling of this emulator's, not a claim about any AWS quota, and the same order
/// as the sample data one create infers a mapping from
/// ([`super::MAX_SAMPLE_DATA_BYTES`]): the bytes one call takes into this process
/// are bounded by it rather than by how much a caller sent.
pub const MAX_TRANSFORM_INPUT_BYTES: usize = 1 << 20;

/// The most FILES one submitted `CsvInput` carries.
///
/// A ceiling of this emulator's: the modelled `FileInputMap` declares no `@length`,
/// so nothing in the model bounds how many files one request names, and the work a
/// transform does is the product of that count and the rules the stored mapping
/// declares. Each file's NAME is charged against
/// [`MAX_TRANSFORM_INPUT_BYTES`] beside its content, so neither the count nor the
/// size of the input is left to the caller alone.
pub const MAX_TRANSFORM_INPUT_FILES: usize = 50;

/// The most element rules, and the most section rules, one stored mapping
/// contributes.
///
/// A ceiling of this emulator's, and the other half of the product above: a profile
/// version retains up to [`super::MAX_PROFILE_MAPPING_BYTES`], which is room for far
/// more rules than any transform applies, so the rules READ out of it are bounded
/// here rather than by how much content a caller stored.
pub const MAX_MAPPING_RULES: usize = 2_000;

/// The most DATA ROWS one submitted CSV file is transformed from.
///
/// A ceiling of this emulator's, for the reason [`MAX_TRANSFORM_INPUT_BYTES`] is: a
/// file past it is refused rather than transformed in part, so a caller is never
/// handed a Bundle that silently drops rows.
pub const MAX_TRANSFORM_ROWS: usize = 1_000;

/// The most FHIR resources one synchronous transform produces.
///
/// A ceiling of this emulator's: the rules of a mapping and the rows of an input
/// multiply, so the product is bounded too.
pub const MAX_TRANSFORM_RESOURCES: usize = 5_000;

/// The most BYTES of mapped source values one synchronous transform writes into the
/// Bundle it answers, across every resource it produces.
///
/// A ceiling of this emulator's, and the one that bounds the PRODUCT of the two
/// factors a transform multiplies: how many element rules the stored mapping declares
/// (bounded only by what one profile version retains) and how long the submitted
/// values those rules copy are (bounded only by [`MAX_TRANSFORM_INPUT_BYTES`]).
/// Neither a row count nor a resource count bounds that product — one row read by
/// many rules is ONE resource, of a size those two factors decide — so the bytes
/// written are accumulated across the whole call and the transform is refused once
/// they pass this. It also bounds how far one request's answer can be amplified
/// beyond the request.
pub const MAX_TRANSFORM_OUTPUT_BYTES: usize = 8 << 20;

/// What one EMPTY repeat an element path's index creates is charged against
/// [`MAX_TRANSFORM_OUTPUT_BYTES`].
///
/// A path naming `name[3]` where nothing named the earlier repeats creates them, and
/// the structure a write allocates is charged where it is allocated rather than
/// estimated from the path's text — otherwise a short path would buy an arbitrary
/// amount of structure. The figure is the order of one empty `serde_json` object
/// node, so the ceiling bounds resident memory and not only the source bytes copied.
const REPEAT_NODE_BYTES: usize = 64;

/// The most drift findings one transform's report carries.
///
/// A ceiling of this emulator's, and the one that makes the report's size a function
/// of a constant: a finding is recorded per column of the submitted input that no
/// rule reads, and the input's column count is bounded only by
/// [`MAX_TRANSFORM_INPUT_BYTES`]. Past this the comparison stops recording and says
/// so, rather than answering a report larger than the Bundle it is about. Each
/// finding's own text is bounded too — every name it carries is echoed through
/// [`crate::service::non_rpc::bounded`].
pub const MAX_DRIFT_FINDINGS: usize = 1_000;

/// The most C-CDA `section` elements one submitted document is transformed from.
pub const MAX_CCDA_SECTIONS: usize = 500;

/// The deepest flow nesting (`[`/`{`) a mapping file may carry to be read.
///
/// A mapping file is content a caller stored, so its nesting is bounded BEFORE a
/// parser sees it: a file past this is skipped, declaring nothing, rather than
/// driving a parse whose depth a caller chose.
const MAX_MAPPING_NESTING: usize = 32;

/// The widest indentation a line of a mapping file may carry to be read, which is
/// what bounds the depth of its BLOCK nesting.
const MAX_MAPPING_INDENT: usize = 64;

/// The most block-collection indicators (`-`, `?`) one line of a mapping file may
/// carry to be read, which is what bounds the depth of its COMPACT block nesting —
/// the nesting `- - - value` opens on one line without indenting.
const MAX_MAPPING_COMPACT_INDICATORS: usize = 16;

/// The deepest the rule walk descends into one mapping file's tree.
///
/// Both forms of nesting are already bounded above; this is the walk's own stop, so
/// the recursion cannot be driven past it whatever a tree holds.
const MAX_MAPPING_WALK_DEPTH: usize = 64;

/// The most elements a mapping rule's element path may name.
const MAX_PATH_SEGMENTS: usize = 16;

/// The highest element index a mapping rule's element path may name — the bound on
/// the array a path like `name[0].given[0]` builds.
const MAX_PATH_INDEX: usize = 64;

/// The longest narrative a transformed C-CDA section carries, in characters.
const MAX_NARRATIVE_CHARS: usize = 4_000;

/// The `Bundle.type` a transform answers with, from the FHIR R4 `BundleType` value
/// set: `collection`, "a set of resources collected into a single package for ease
/// of distribution". A transform packages the resources it produced and submits
/// them nowhere, so it declares none of the request semantics `transaction` or
/// `batch` carry.
pub const BUNDLE_TYPE: &str = "collection";

/// The FHIR R4 resource type a `Bundle` reports itself as.
const BUNDLE_RESOURCE_TYPE: &str = "Bundle";

/// The `Narrative.status` a transformed C-CDA section's narrative carries, from the
/// FHIR R4 `NarrativeStatus` value set: `additional`, "the contents of the narrative
/// may contain additional information not found in the structured data" — which is
/// what a section's own narrative text is, beside a resource whose structured
/// elements the mapping did not name.
const NARRATIVE_STATUS: &str = "additional";

/// The namespace a FHIR R4 `Narrative.div` is XHTML in.
const XHTML_NAMESPACE: &str = "http://www.w3.org/1999/xhtml";

/// The key a mapping file names a SOURCE TABLE with (`tables[].tableName`). A node
/// that carries it names the table every rule under it reads from.
const TABLE_NAME_KEYS: &[&str] = &["tableName"];

/// The key a mapping file names a table's PRIMARY KEY COLUMN with
/// (`tables[].primaryKeyColumn`): the column whose value identifies the record, and
/// so the logical id of the resource a record becomes.
const PRIMARY_KEY_COLUMN_KEYS: &[&str] = &["primaryKeyColumn"];

/// The key a mapping file names a TARGET RESOURCE TYPE with: `targetResourceType`, as
/// both the mapping config (`resourceMappings[].targetResourceType`) and this
/// service's own rule files ([`super::sample_data`], [`super::starter_profiles`])
/// spell it.
const RESOURCE_TYPE_KEYS: &[&str] = &["targetResourceType"];

/// The key a mapping rule names its SOURCE COLUMN with: `sourceColumn`, as both the
/// mapping config (`fieldMappings[].sourceColumn`) and this service's own inferred
/// rule files spell it.
const SOURCE_COLUMN_KEYS: &[&str] = &["sourceColumn"];

/// The keys a mapping rule names the ELEMENT it writes with: `fhirPath`, as the
/// mapping config spells it (`fieldMappings[].fhirPath`), and `targetElement`, as
/// this service's own inferred rule files do ([`super::sample_data`],
/// [`super::starter_profiles`]).
const TARGET_PATH_KEYS: &[&str] = &["fhirPath", "targetElement"];

/// The key a mapping rule names a C-CDA document SECTION with: `sourceSection`, as
/// this service's starter profile rule files spell it
/// ([`super::starter_profiles`]).
const SOURCE_SECTION_KEYS: &[&str] = &["sourceSection"];

/// The key a mapping file carries its FIELD RULES under
/// (`resourceMappings[].fieldMappings`).
///
/// Read only to admit the second shape the same declaration takes: a MAP of source
/// column to element path, which carries no key of its own for either side.
const FIELD_MAPPINGS_KEYS: &[&str] = &["fieldMappings"];

/// One rule of a mapping: the source column whose value is written, and the element
/// of the target resource it is written to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRule {
    /// The column of the source record the value comes from.
    pub source_column: String,
    /// The element of the target resource it is written to, as the mapping spells
    /// the path (`name[0].family`).
    pub target_path: String,
}

/// One resource a mapping declares over a source TABLE: every data row of that table
/// becomes one resource of [`Self::resource_type`] carrying the elements
/// [`Self::fields`] write.
#[derive(Debug, Clone)]
pub struct TableRule {
    /// The source table this resource is built from, or `None` when the mapping
    /// names none — in which case the rule applies to every submitted file.
    pub table: Option<String>,
    /// The column whose value identifies a record, when the mapping names one.
    pub primary_key_column: Option<String>,
    /// The FHIR R4 resource type a record becomes.
    pub resource_type: String,
    /// The elements each record writes.
    pub fields: Vec<FieldRule>,
    /// Whether this resource was gathered from STANDALONE rules — rules that each
    /// declare their own target resource type, with no enclosing resource mapping to
    /// group them — which is the shape this service's own inferred rule files take.
    /// Such rules are gathered per resource type, and a rule is only ever added to a
    /// resource that does not already write its element, so no rule overwrites
    /// another.
    standalone: bool,
}

/// One resource a mapping declares over a C-CDA document SECTION: each section of
/// the submitted document that the rule names becomes one resource of this type.
#[derive(Debug, Clone)]
pub struct SectionRule {
    /// The C-CDA section the resource is built from, as the mapping names it.
    pub section: String,
    /// The FHIR R4 resource type that section becomes.
    pub resource_type: String,
}

/// Everything a profile's stored content declares about how a source record becomes
/// FHIR R4.
#[derive(Debug, Default)]
pub struct MappingRules {
    /// The resources declared over source tables, in the order the mapping declares
    /// them.
    pub tables: Vec<TableRule>,
    /// The resources declared over C-CDA sections, in that same order.
    pub sections: Vec<SectionRule>,
}

impl MappingRules {
    /// Whether this mapping declares nothing a transform could apply: no section
    /// rule, and no resource with an element to write.
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty() && self.tables.iter().all(|table| table.fields.is_empty())
    }
}

/// What one transform produced: the FHIR R4 Bundle, and what comparing the mapping
/// against the submitted input found.
#[derive(Debug)]
pub struct Transformed {
    /// The Bundle, as the transform's `TransformedData` carries it.
    pub bundle: ::serde_json::Value,
    /// The drift between the mapping and the submitted input.
    pub drift: Drift,
}

/// The drift one transform found, bounded: at most [`MAX_DRIFT_FINDINGS`] findings,
/// each carrying only bounded text, so the report's size is a function of a constant
/// rather than of how many columns the submitted input carries.
#[derive(Debug, Default)]
pub struct Drift {
    /// The divergences found, in the order they were found.
    pub findings: Vec<DriftFinding>,
    /// Whether the comparison stopped recording at [`MAX_DRIFT_FINDINGS`], so the
    /// report says the input diverged in more ways than it lists.
    pub truncated: bool,
}

impl Drift {
    /// Record one finding, unless this log is already full — in which case it records
    /// only that there was more to say.
    fn record(&mut self, finding: DriftFinding) {
        if self.findings.len() >= MAX_DRIFT_FINDINGS {
            self.truncated = true;
            return;
        }
        self.findings.push(finding);
    }
}

/// One difference between what the profile's mapping expects of the source and what
/// the submitted input actually carries.
///
/// Every name a finding carries is ECHOED from the submitted input or the stored
/// mapping, so each is bounded where the finding is built
/// ([`crate::service::non_rpc::bounded`]): a 1 MiB column name is not a 1 MiB
/// finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftFinding {
    /// A submitted file no rule of the mapping reads from.
    UnmappedFile { file: String },
    /// A column a rule reads that the submitted file does not carry.
    MissingColumn { file: String, column: String },
    /// A column the submitted file carries that no rule reads.
    UnmappedColumn { file: String, column: String },
    /// A section a rule reads that the submitted document does not carry.
    MissingSection { section: String },
    /// A section the submitted document carries that no rule reads.
    UnmappedSection { section: String },
}

impl DriftFinding {
    /// This finding as the drift report carries it.
    fn as_json(&self) -> ::serde_json::Value {
        match self {
            Self::UnmappedFile { file } => ::serde_json::json!({
                "Type": "UNMAPPED_FILE",
                "FileName": file,
            }),
            Self::MissingColumn { file, column } => ::serde_json::json!({
                "Type": "MISSING_SOURCE_COLUMN",
                "FileName": file,
                "SourceColumn": column,
            }),
            Self::UnmappedColumn { file, column } => ::serde_json::json!({
                "Type": "UNMAPPED_SOURCE_COLUMN",
                "FileName": file,
                "SourceColumn": column,
            }),
            Self::MissingSection { section } => ::serde_json::json!({
                "Type": "MISSING_SOURCE_SECTION",
                "SourceSection": section,
            }),
            Self::UnmappedSection { section } => ::serde_json::json!({
                "Type": "UNMAPPED_SOURCE_SECTION",
                "SourceSection": section,
            }),
        }
    }
}

/// The drift report a transform answers when the caller asked for drift detection:
/// whether the submitted input diverged from what the mapping expects of it, and
/// every divergence found.
///
/// AWS publishes no schema for this member — it is a `String` carrying the report —
/// so what it states is the comparison's own findings, computed from the mapping and
/// the submitted input and nothing else. A comparison that found more than it
/// records says so rather than growing the report past its ceiling.
pub fn drift_report(drift: &Drift) -> String {
    let mut report = ::serde_json::Map::new();
    report.insert(
        "DriftDetected".to_string(),
        (!drift.findings.is_empty() || drift.truncated).into(),
    );
    report.insert(
        "Findings".to_string(),
        drift
            .findings
            .iter()
            .map(DriftFinding::as_json)
            .collect::<Vec<_>>()
            .into(),
    );
    if drift.truncated {
        report.insert("FindingsTruncated".to_string(), true.into());
    }
    ::serde_json::Value::Object(report).to_string()
}

/// Everything the mapping `mapping` declares, read out of its files.
///
/// A file that declares nothing a rule can be read from contributes nothing — a
/// manifest, a note, a file this emulator wrote for a reader rather than for a
/// transform — and so does one outside the bounds a stored file is read inside (see
/// [`readable_mapping_file`]). What a profile declares is therefore the union of what
/// its files declare, in file-path order.
pub fn mapping_rules(mapping: &BTreeMap<String, String>) -> MappingRules {
    let mut collector = Collector::default();
    for content in mapping.values() {
        let Some(document) = readable_mapping_file(content) else {
            continue;
        };
        walk(&document, &Scope::default(), 0, &mut collector);
    }
    MappingRules {
        tables: collector.tables,
        sections: collector.sections,
    }
}

/// The parse tree of one stored mapping file, or `None` when the file is not one
/// this transform reads.
///
/// Three reasons a file is not read, each about the FILE rather than about what it
/// declares: it nests past the bounds [`nesting_within_bounds`] holds it to; it uses a
/// YAML alias, which the loader would RESOLVE by copying the anchored node (so a short
/// file can expand without bound, and the aliases are refused from the parser's event
/// stream, before any tree exists); or it is not one YAML document at all.
///
/// The nesting bound is checked FIRST, because both the event walk and the loader
/// below descend once per nesting level.
fn readable_mapping_file(content: &str) -> Option<::yaml_rust2::Yaml> {
    if !nesting_within_bounds(content) || unreadable_or_aliased(content) {
        return None;
    }
    let mut documents = ::yaml_rust2::YamlLoader::load_from_str(content).ok()?;
    (documents.len() == 1).then(|| documents.remove(0))
}

/// Whether `text` nests inside the bounds a stored mapping file is read inside.
///
/// Every form YAML nests in is bounded, because what consumes the file afterwards —
/// the parser's event walk and the loader — descends once per level:
///
/// * a FLOW collection, by its opening `[`/`{`, bounded by [`MAX_MAPPING_NESTING`];
/// * a BLOCK collection written across lines, by the indentation of those lines,
///   bounded by [`MAX_MAPPING_INDENT`]; and
/// * a block collection written COMPACTLY, which nests without indenting and without
///   a flow opener — `- - - value` opens one sequence per indicator on the one line —
///   by the indicators on a line, bounded by [`MAX_MAPPING_COMPACT_INDICATORS`].
///
/// The scan is over bytes and makes no attempt to tell a structural character from
/// one inside a quoted scalar: a file carrying enough of any of them to reach a bound
/// is simply not read, so nothing in it can drive the consumers past these ceilings.
fn nesting_within_bounds(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut nesting = 0usize;
    let mut indent = 0usize;
    let mut compact = 0usize;
    let mut counting_indent = true;
    for (at, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'\n' | b'\r' => {
                indent = 0;
                compact = 0;
                counting_indent = true;
            }
            b' ' | b'\t' if counting_indent => {
                indent += 1;
                if indent > MAX_MAPPING_INDENT {
                    return false;
                }
            }
            b'[' | b'{' => {
                counting_indent = false;
                nesting += 1;
                if nesting > MAX_MAPPING_NESTING {
                    return false;
                }
            }
            b']' | b'}' => {
                counting_indent = false;
                nesting = nesting.saturating_sub(1);
            }
            b'-' | b'?' if block_indicator(bytes, at) => {
                counting_indent = false;
                compact += 1;
                if compact > MAX_MAPPING_COMPACT_INDICATORS {
                    return false;
                }
            }
            _ => counting_indent = false,
        }
    }
    true
}

/// Whether the byte at `at` stands as a YAML block-collection indicator rather than
/// as a character of a scalar.
///
/// An indicator stands alone: nothing but whitespace or a line start before it, and
/// whitespace or the end of the line after it. So the `-` of a value like `name-0`,
/// and the pair in a `---` document marker, are not counted.
fn block_indicator(bytes: &[u8], at: usize) -> bool {
    let before = at.checked_sub(1).and_then(|before| bytes.get(before).copied());
    let after = bytes.get(at + 1).copied();
    before.is_none_or(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        && after.is_none_or(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
}

/// Whether `text` is a file this transform will not read: one the parser cannot read
/// at all, or one using a YAML alias.
///
/// Both are read off the parser's own event stream — which reports an alias as an
/// event and copies nothing, unlike the loader, which resolves one by copying the
/// anchored node — so an alias is found before any tree exists.
fn unreadable_or_aliased(text: &str) -> bool {
    #[derive(Default)]
    struct AliasDetector {
        saw_alias: bool,
    }
    impl ::yaml_rust2::parser::EventReceiver for AliasDetector {
        fn on_event(&mut self, event: ::yaml_rust2::parser::Event) {
            if matches!(event, ::yaml_rust2::parser::Event::Alias(_)) {
                self.saw_alias = true;
            }
        }
    }

    let mut detector = AliasDetector::default();
    match ::yaml_rust2::parser::Parser::new_from_str(text).load(&mut detector, true) {
        // A file the parser could not read at all declares nothing either way; the
        // loader below answers that by refusing to load it.
        Err(_) => true,
        Ok(()) => detector.saw_alias,
    }
}

/// What the enclosing nodes of a mapping file have declared so far: a rule inherits
/// the table, the primary key and the target resource type of the node it sits
/// under, so a mapping config states each of them once.
#[derive(Debug, Clone, Default)]
struct Scope {
    table: Option<String>,
    primary_key_column: Option<String>,
    resource_type: Option<String>,
    /// The resource the enclosing `resourceMappings` entry opened, if any: every
    /// field rule under it writes elements of THAT resource.
    resource: Option<usize>,
}

/// The rules gathered out of a profile's files.
#[derive(Debug, Default)]
struct Collector {
    tables: Vec<TableRule>,
    sections: Vec<SectionRule>,
    /// How many element rules have been gathered, across every resource — what
    /// [`MAX_MAPPING_RULES`] bounds. Counted rather than summed on demand so the
    /// ceiling costs one comparison per rule.
    fields: usize,
}

impl Collector {
    /// Open the resource a node declaring a target resource type names, and answer
    /// where its rules go.
    fn open_resource(&mut self, scope: &Scope, resource_type: String) -> usize {
        self.tables.push(TableRule {
            table: scope.table.clone(),
            primary_key_column: scope.primary_key_column.clone(),
            resource_type,
            fields: Vec::new(),
            standalone: false,
        });
        self.tables.len() - 1
    }

    /// Record one field rule against the resource its scope names.
    ///
    /// A rule inside a declared resource mapping joins that resource. A STANDALONE
    /// rule — one that declares its own target resource type with no resource
    /// mapping around it — joins the first standalone resource of the same table and
    /// type that does not already write its element, so two rules never overwrite
    /// one another and a record's columns still land in as few resources as the
    /// mapping allows.
    fn add_field(&mut self, scope: &Scope, rule: FieldRule) {
        // Past the ceiling the mapping declares no more rules to this transform: what
        // a stored mapping can make one call do is bounded by a constant, not by how
        // much content was stored.
        if self.fields >= MAX_MAPPING_RULES {
            return;
        }
        let Some(resource_type) = scope.resource_type.clone() else {
            // A rule naming no target resource type declares nothing that could be
            // built, so it is not a rule of this mapping.
            return;
        };
        self.fields += 1;
        if let Some(resource) = scope.resource.and_then(|index| self.tables.get_mut(index)) {
            resource.fields.push(rule);
            return;
        }
        let joined = self.tables.iter_mut().find(|resource| {
            resource.standalone
                && resource.resource_type == resource_type
                && resource.table == scope.table
                && !resource
                    .fields
                    .iter()
                    .any(|held| held.target_path == rule.target_path)
        });
        match joined {
            Some(resource) => resource.fields.push(rule),
            None => self.tables.push(TableRule {
                table: scope.table.clone(),
                primary_key_column: scope.primary_key_column.clone(),
                resource_type,
                fields: vec![rule],
                standalone: true,
            }),
        }
    }

    /// Record one section rule, up to the ceiling a mapping declares rules to this
    /// transform inside ([`MAX_MAPPING_RULES`]).
    fn add_section(&mut self, section: String, resource_type: String) {
        if self.sections.len() >= MAX_MAPPING_RULES {
            return;
        }
        self.sections.push(SectionRule {
            section,
            resource_type,
        });
    }
}

/// Gather every rule one mapping node — and everything under it — declares.
fn walk(node: &::yaml_rust2::Yaml, scope: &Scope, depth: usize, out: &mut Collector) {
    if depth > MAX_MAPPING_WALK_DEPTH {
        return;
    }
    match node {
        ::yaml_rust2::Yaml::Array(items) => {
            for item in items {
                walk(item, scope, depth + 1, out);
            }
        }
        ::yaml_rust2::Yaml::Hash(map) => walk_mapping(map, scope, depth, out),
        // A scalar declares no rule on its own: every rule binds at least a source
        // and a target, which only a mapping node carries.
        _ => {}
    }
}

/// Gather every rule one mapping node declares, and descend into its values.
fn walk_mapping(
    map: &::yaml_rust2::yaml::Hash,
    scope: &Scope,
    depth: usize,
    out: &mut Collector,
) {
    let mut scope = scope.clone();
    if let Some(table) = scalar_at(map, TABLE_NAME_KEYS) {
        scope.table = Some(table);
    }
    if let Some(primary_key) = scalar_at(map, PRIMARY_KEY_COLUMN_KEYS) {
        scope.primary_key_column = Some(primary_key);
    }
    let declared_type = scalar_at(map, RESOURCE_TYPE_KEYS);
    if let Some(resource_type) = declared_type.clone() {
        scope.resource_type = Some(resource_type);
    }

    // A node binding a source column to a target element IS a rule; its values are
    // the two sides of that binding, so nothing under it is walked again.
    if let (Some(source_column), Some(target_path)) = (
        scalar_at(map, SOURCE_COLUMN_KEYS),
        scalar_at(map, TARGET_PATH_KEYS),
    ) {
        out.add_field(
            &scope,
            FieldRule {
                source_column,
                target_path,
            },
        );
        return;
    }
    // A node binding a document section to a resource type is the C-CDA form of the
    // same declaration.
    if let (Some(section), Some(resource_type)) =
        (scalar_at(map, SOURCE_SECTION_KEYS), scope.resource_type.clone())
    {
        out.add_section(section, resource_type);
        return;
    }
    // A node that declares a target resource type of its own opens a resource: every
    // rule under it writes elements of that one resource, so one row of the source
    // becomes one resource however many columns the node maps.
    if let Some(resource_type) = declared_type {
        scope.resource = Some(out.open_resource(&scope, resource_type));
    }

    for (key, value) in map {
        if key
            .as_str()
            .is_some_and(|key| names_one_of(key, FIELD_MAPPINGS_KEYS))
        {
            walk_field_mappings(value, &scope, depth + 1, out);
        } else {
            walk(value, &scope, depth + 1, out);
        }
    }
}

/// Gather the rules a `fieldMappings` value declares.
///
/// Two shapes, both of them the same declaration: a sequence of rules, each naming
/// its source column and its element path (walked like any other node), or a MAP of
/// source column to element path, which names neither side with a key of its own and
/// so is read here.
fn walk_field_mappings(
    node: &::yaml_rust2::Yaml,
    scope: &Scope,
    depth: usize,
    out: &mut Collector,
) {
    if let ::yaml_rust2::Yaml::Hash(map) = node {
        let names_a_rule_key = map.keys().filter_map(::yaml_rust2::Yaml::as_str).any(|key| {
            names_one_of(key, SOURCE_COLUMN_KEYS)
                || names_one_of(key, TARGET_PATH_KEYS)
                || names_one_of(key, SOURCE_SECTION_KEYS)
                || names_one_of(key, RESOURCE_TYPE_KEYS)
        });
        if !names_a_rule_key {
            for (column, path) in map {
                if let (Some(column), Some(path)) = (column.as_str(), scalar_string(path)) {
                    out.add_field(
                        scope,
                        FieldRule {
                            source_column: column.to_string(),
                            target_path: path,
                        },
                    );
                }
            }
            return;
        }
    }
    walk(node, scope, depth, out);
}

/// Whether `key` is one of `names`, on its letters and digits alone.
fn names_one_of(key: &str, names: &[&str]) -> bool {
    let key = normalized_content_name(key);
    !key.is_empty() && names.iter().any(|name| normalized_content_name(name) == key)
}

/// The scalar value one of the keys `names` carries in `map`, or `None` when the node
/// carries none of them with a scalar value.
fn scalar_at(map: &::yaml_rust2::yaml::Hash, names: &[&str]) -> Option<String> {
    map.iter()
        .filter(|(key, _)| key.as_str().is_some_and(|key| names_one_of(key, names)))
        .find_map(|(_, value)| scalar_string(value))
        .filter(|value| !value.trim().is_empty())
}

/// One YAML scalar as the string a mapping declares with it. A node that is not a
/// scalar names nothing.
fn scalar_string(value: &::yaml_rust2::Yaml) -> Option<String> {
    match value {
        ::yaml_rust2::Yaml::String(text) | ::yaml_rust2::Yaml::Real(text) => {
            Some(text.trim().to_string())
        }
        ::yaml_rust2::Yaml::Integer(number) => Some(number.to_string()),
        ::yaml_rust2::Yaml::Boolean(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// The FHIR R4 Bundle the resources `resources` are packaged in.
fn bundle(resources: Vec<::serde_json::Value>) -> ::serde_json::Value {
    ::serde_json::json!({
        "resourceType": BUNDLE_RESOURCE_TYPE,
        "type": BUNDLE_TYPE,
        "entry": resources
            .into_iter()
            .map(|resource| ::serde_json::json!({ "resource": resource }))
            .collect::<Vec<_>>(),
    })
}

/// One rule of a mapping resolved against the header row of the file it reads: where
/// in a record each value comes from, and where in the resource it goes.
#[derive(Debug)]
struct ResolvedRule<'a> {
    rule: &'a TableRule,
    /// The field of a record each rule reads, and the element path it writes it to —
    /// resolved ONCE here rather than per row, so a path is read as a path a single
    /// time however many records the file holds.
    writes: Vec<(usize, String)>,
    /// The field of a record the primary key column names, when the file carries it.
    primary_key: Option<usize>,
}

/// What one transform was asked for, beside the input itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransformOptions<'a> {
    /// The source every produced resource records itself as coming from, when the
    /// caller asked for provenance; `None` when it did not.
    pub provenance: Option<&'a str>,
    /// Whether to compare the mapping against the submitted input. The comparison is
    /// work only a caller that asked for the drift report reads, so it is not done
    /// otherwise.
    pub detect_drift: bool,
}

/// Transform the submitted CSV files with `rules`, or answer the sentence the
/// transform is refused with.
///
/// Every data row of a submitted file becomes one resource per resource the mapping
/// declares over that file's table — a rule naming a table reads the file that names
/// it, and a rule naming none reads every file — carrying each mapped column whose
/// value the row holds.
pub fn transform_csv(
    rules: &MappingRules,
    files: &BTreeMap<String, String>,
    options: TransformOptions<'_>,
) -> Result<Transformed, String> {
    let bytes: usize = files.values().map(String::len).sum();
    if bytes > MAX_TRANSFORM_INPUT_BYTES {
        return Err(input_too_large_message(bytes));
    }

    let mut resources: Vec<::serde_json::Value> = Vec::new();
    let mut drift = Drift::default();
    // What the Bundle this call answers has been given so far, which is what
    // [`MAX_TRANSFORM_OUTPUT_BYTES`] bounds: the rules of the mapping and the length
    // of the submitted values multiply, so the product is accumulated across every
    // resource rather than bounded per row.
    let mut written = 0usize;
    for (file, content) in files {
        let applicable: Vec<&TableRule> = rules
            .tables
            .iter()
            .filter(|rule| !rule.fields.is_empty())
            .filter(|rule| {
                rule.table
                    .as_ref()
                    .is_none_or(|table| source_table_matches(table, file))
            })
            .collect();
        if applicable.is_empty() {
            if options.detect_drift {
                drift.record(DriftFinding::UnmappedFile {
                    file: echoed(file),
                });
            }
            continue;
        }

        let mut reader = ::csv::ReaderBuilder::new()
            .has_headers(true)
            // A row that does not carry every column of the header is still a
            // record of the columns it does carry, so a ragged file is read rather
            // than refused.
            .flexible(true)
            .from_reader(content.as_bytes());
        let headers: Vec<String> = reader
            .headers()
            .map_err(|_| not_csv_message(file))?
            .iter()
            .map(str::to_string)
            .collect();
        if headers.iter().all(|header| header.trim().is_empty()) {
            return Err(no_header_message(file));
        }

        let resolved = resolve_rules(&applicable, &headers, file, options, &mut drift);
        let mut rows = 0usize;
        for record in reader.records() {
            let record = record.map_err(|_| not_csv_message(file))?;
            // A blank line carries no record: a file's trailing newline is framing,
            // not a row that produces an empty resource.
            if record.iter().all(|field| field.trim().is_empty()) {
                continue;
            }
            rows += 1;
            if rows > MAX_TRANSFORM_ROWS {
                return Err(too_many_rows_message(file));
            }
            for rule in &resolved {
                if let Some(resource) =
                    row_resource(rule, &record, options.provenance, &mut written)?
                {
                    resources.push(resource);
                    if resources.len() > MAX_TRANSFORM_RESOURCES {
                        return Err(too_many_resources_message());
                    }
                }
            }
        }
    }

    Ok(Transformed {
        bundle: bundle(resources),
        drift,
    })
}

/// Resolve each rule against the header row of the file it reads, recording what the
/// header and the mapping disagree about as drift when the caller asked for it.
fn resolve_rules<'a>(
    applicable: &[&'a TableRule],
    headers: &[String],
    file: &str,
    options: TransformOptions<'_>,
    drift: &mut Drift,
) -> Vec<ResolvedRule<'a>> {
    let normalized: Vec<String> = headers
        .iter()
        .map(|header| normalized_content_name(header))
        .collect();
    let mut read: BTreeSet<usize> = BTreeSet::new();
    // The columns already reported missing, so a column several rules read is
    // reported once without scanning the findings again for each rule.
    let mut missing: BTreeSet<&str> = BTreeSet::new();
    let mut resolved = Vec::with_capacity(applicable.len());
    for rule in applicable {
        let mut writes = Vec::with_capacity(rule.fields.len());
        for field in &rule.fields {
            match column_index(headers, &normalized, &field.source_column) {
                Some(index) => {
                    read.insert(index);
                    // A rule whose path names no element this transform can write
                    // writes nothing; the column is still READ, so it is not reported
                    // as one the mapping ignores.
                    if let Some(dotted) = dotted_path(&field.target_path, &rule.resource_type) {
                        writes.push((index, dotted));
                    }
                }
                None => {
                    if options.detect_drift && missing.insert(field.source_column.as_str()) {
                        drift.record(DriftFinding::MissingColumn {
                            file: echoed(file),
                            column: echoed(&field.source_column),
                        });
                    }
                }
            }
        }
        let primary_key = rule
            .primary_key_column
            .as_deref()
            .and_then(|column| column_index(headers, &normalized, column))
            .inspect(|index| {
                read.insert(*index);
            });
        resolved.push(ResolvedRule {
            rule,
            writes,
            primary_key,
        });
    }
    if !options.detect_drift {
        return resolved;
    }
    for (index, header) in headers.iter().enumerate() {
        if !read.contains(&index) && !header.trim().is_empty() {
            drift.record(DriftFinding::UnmappedColumn {
                file: echoed(file),
                column: echoed(header),
            });
        }
    }
    resolved
}

/// `value` as a drift finding carries it: the bounded, single-line form every message
/// of this crate echoes a caller-supplied value in
/// ([`crate::service::non_rpc::bounded`]), so one long column name cannot make one
/// long finding.
fn echoed(value: &str) -> String {
    crate::service::non_rpc::bounded(value)
}

/// Which field of a record the column `column` names, by the header row's own
/// spelling first and then on letters and digits alone, so a mapping names a column
/// however the file spells its word separators and case.
fn column_index(headers: &[String], normalized: &[String], column: &str) -> Option<usize> {
    if let Some(index) = headers.iter().position(|header| header == column) {
        return Some(index);
    }
    let wanted = normalized_content_name(column);
    if wanted.is_empty() {
        return None;
    }
    normalized.iter().position(|header| *header == wanted)
}

/// Whether the source table `table` is the one the submitted file `file` carries.
///
/// A submitted file is named for its table — with or without a file extension — and
/// the two are compared on their letters and digits alone, so a table is read from
/// the file that names it however either spells the name.
fn source_table_matches(table: &str, file: &str) -> bool {
    let wanted = normalized_content_name(table);
    if wanted.is_empty() {
        return false;
    }
    let stem = file.rsplit_once('.').map_or(file, |(stem, _extension)| stem);
    wanted == normalized_content_name(file) || wanted == normalized_content_name(stem)
}

/// The resource one data row produces for one resolved rule, or `None` when the row
/// writes no element of it — a resource carrying no mapped value is an answer nothing
/// computed, so none is produced.
///
/// `written` is what the Bundle this call answers has been given so far, which
/// [`MAX_TRANSFORM_OUTPUT_BYTES`] bounds: it is charged BEFORE each value is copied,
/// so the product of the mapping's rule count and the submitted values' length cannot
/// grow the answer past that ceiling.
fn row_resource(
    resolved: &ResolvedRule<'_>,
    record: &::csv::StringRecord,
    provenance: Option<&str>,
    written: &mut usize,
) -> Result<Option<::serde_json::Value>, String> {
    let mut resource = ::serde_json::json!({ "resourceType": resolved.rule.resource_type });
    if let Some(source) = provenance {
        set_member(&mut resource, "meta", provenance_meta(source));
    }
    // The primary key column identifies the record, so its value is the logical id
    // of the resource the record became — when the value is one a FHIR R4 `id`
    // admits.
    if let Some(id) = resolved
        .primary_key
        .and_then(|index| record.get(index))
        .map(str::trim)
        .filter(|id| is_fhir_id(id))
    {
        set_member(&mut resource, "id", ::serde_json::Value::from(id));
    }

    let mut elements = 0usize;
    for (index, dotted) in &resolved.writes {
        // A field the row does not carry, or carries empty, writes nothing: FHIR R4
        // admits no empty element value, and an absent source value is not a value.
        let Some(value) = record.get(*index).map(str::trim).filter(|v| !v.is_empty()) else {
            continue;
        };
        *written = charged(*written, value.len() + dotted.len())?;
        if write_element(&mut resource, dotted, value, written)? {
            elements += 1;
        }
    }
    Ok((elements > 0).then_some(resource))
}

/// `written` plus `bytes`, or the sentence the transform is refused with once what it
/// has written passes [`MAX_TRANSFORM_OUTPUT_BYTES`].
fn charged(written: usize, bytes: usize) -> Result<usize, String> {
    let charged = written.saturating_add(bytes);
    if charged > MAX_TRANSFORM_OUTPUT_BYTES {
        return Err(too_much_output_message());
    }
    Ok(charged)
}

/// Set the top-level element `member` of `resource`.
///
/// A resource is built as an object, so this always writes; it writes through the
/// object rather than by indexing the value, which would be a panic if it ever
/// stopped being one.
fn set_member(resource: &mut ::serde_json::Value, member: &str, value: ::serde_json::Value) {
    if let Some(object) = resource.as_object_mut() {
        object.insert(member.to_string(), value);
    }
}

/// The `meta` a produced resource records its provenance in: FHIR R4's
/// `Meta.source`, "a uri that identifies the source system of the resource" — here
/// the profile that produced it.
fn provenance_meta(source: &str) -> ::serde_json::Value {
    ::serde_json::json!({ "source": source })
}

/// The element path `path` in the dotted form the path writer takes:
/// `name[0].given[0]` names the element `given` of the first `name`, which is
/// `name.0.given.0`.
///
/// A path may name the resource it is a path INTO first — `Patient.gender`,
/// `Observation.valueQuantity`, the form this service's own inferred rule files write
/// ([`super::sample_data`]) — and that leading segment is the resource, not an element
/// of it: FHIR R4 declares no `Patient` element inside a Patient, so it is dropped
/// rather than written as a member named after the type. `resource_type` is the type
/// the rule declares, compared on letters and digits alone, so only a segment naming
/// THAT resource is dropped.
///
/// `None` for a path this transform does not write: one naming no element, one
/// deeper than [`MAX_PATH_SEGMENTS`], or one naming an index past
/// [`MAX_PATH_INDEX`] — the array such an index would build is bounded, so a stored
/// rule cannot choose how much is allocated.
fn dotted_path(path: &str, resource_type: &str) -> Option<String> {
    let mut segments: Vec<String> = Vec::new();
    for step in path.split('.') {
        let mut parts = step.split('[');
        let element = parts.next().unwrap_or_default().trim();
        if element.is_empty() || element.contains(']') {
            return None;
        }
        // A segment that is a NUMBER names a repeat whichever form it was written in:
        // the path writer reads `name.3.family` and `name[3].family` alike, so the
        // index ceiling is applied to the bare form here as well as to the bracketed
        // one below.
        if element.parse::<usize>().is_ok_and(|index| index > MAX_PATH_INDEX) {
            return None;
        }
        segments.push(element.to_string());
        for index in parts {
            let index: usize = index.strip_suffix(']')?.trim().parse().ok()?;
            if index > MAX_PATH_INDEX {
                return None;
            }
            segments.push(index.to_string());
        }
        if segments.len() > MAX_PATH_SEGMENTS {
            return None;
        }
    }
    // Only a LEADING segment is the resource, and a path that is the resource name
    // alone names no element at all.
    if segments.first().is_some_and(|first| {
        normalized_content_name(first) == normalized_content_name(resource_type)
    }) {
        if segments.len() == 1 {
            return None;
        }
        segments.remove(0);
    }
    (!segments.is_empty()).then(|| segments.join("."))
}

/// Write `value` at the element the dotted path `dotted` names, answering whether it
/// was written.
///
/// The write itself is the path writer's (`json_dotpath`), which builds the objects
/// and arrays the path passes through. It can only APPEND to an array, so the
/// repeats BEFORE the one a rule names are created first — a rule naming `name[1]`
/// where nothing named `name[0]` leaves the earlier repeat EMPTY rather than turning
/// the repeats into an object keyed by their index. An empty repeat is written as an
/// empty object, never as a null: FHIR R4 admits no null entry in a repeating
/// element. Each one is charged to `written` WHERE IT IS ALLOCATED
/// ([`REPEAT_NODE_BYTES`]), so the structure a short path builds is bounded by
/// [`MAX_TRANSFORM_OUTPUT_BYTES`] like everything else the answer holds, and the
/// index itself is bounded by [`MAX_PATH_INDEX`].
fn write_element(
    resource: &mut ::serde_json::Value,
    dotted: &str,
    value: &str,
    written: &mut usize,
) -> Result<bool, String> {
    let mut prefix = String::new();
    for segment in dotted.split('.') {
        if let Ok(index) = segment.parse::<usize>() {
            // The ceiling is re-read HERE, where the padding is performed, rather
            // than relied on from the path reader: this loop is the allocation, so
            // nothing that reaches it may name a repeat past the bound.
            if index > MAX_PATH_INDEX {
                return Ok(false);
            }
            for earlier in 0..index {
                let at = joined(&prefix, &earlier.to_string());
                if resource
                    .dot_get::<::serde_json::Value>(&at)
                    .ok()
                    .flatten()
                    .is_none()
                {
                    *written = charged(*written, REPEAT_NODE_BYTES)?;
                    if resource
                        .dot_set(&at, ::serde_json::Value::Object(::serde_json::Map::new()))
                        .is_err()
                    {
                        return Ok(false);
                    }
                }
            }
        }
        prefix = joined(&prefix, segment);
    }
    Ok(resource.dot_set(dotted, value).is_ok())
}

/// One dotted path and the segment under it.
fn joined(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_string()
    } else {
        format!("{prefix}.{segment}")
    }
}

/// Whether `value` is a FHIR R4 `id`: 1 to 64 characters of `A-Z`, `a-z`, `0-9`, `-`
/// and `.`, as that primitive type's own pattern declares.
fn is_fhir_id(value: &str) -> bool {
    let length = value.chars().count();
    (1..=64).contains(&length)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

/// One `section` of a submitted C-CDA document: the names it answers to, and the
/// narrative it carries.
#[derive(Debug)]
struct DocumentSection {
    /// The names a mapping rule may name this section by: its title and the display
    /// name of its code.
    names: Vec<String>,
    /// The section's own narrative text.
    narrative: String,
}

/// Transform the submitted C-CDA document with `rules`, or answer the sentence the
/// transform is refused with.
///
/// Each section of the document that a rule names becomes one resource of the type
/// that rule names, carrying that section's narrative; a section the mapping does not
/// name, and a rule the document carries no section for, are drift rather than
/// resources.
pub fn transform_ccda(
    rules: &MappingRules,
    document: &str,
    options: TransformOptions<'_>,
) -> Result<Transformed, String> {
    if document.len() > MAX_TRANSFORM_INPUT_BYTES {
        return Err(input_too_large_message(document.len()));
    }
    // A leading byte-order mark and leading whitespace are framing a document may
    // carry ahead of its XML declaration, and say nothing about its content.
    let text = document.trim_start_matches('\u{feff}').trim_start();
    let parsed = ::roxmltree::Document::parse(text)
        .map_err(|error| not_xml_message(&error.to_string()))?;
    let sections = document_sections(&parsed);

    let mut resources: Vec<::serde_json::Value> = Vec::new();
    let mut drift = Drift::default();
    // What the Bundle this call answers has been given so far, bounded exactly as the
    // CSV transform's is ([`MAX_TRANSFORM_OUTPUT_BYTES`]): the sections of the
    // document and the rules that name them multiply too.
    let mut written = 0usize;
    // In DOCUMENT order: a Bundle built from a document carries its resources in the
    // order the document carries the sections they came from.
    for section in &sections {
        let mut named = false;
        for rule in rules.sections.iter().filter(|rule| names(rule, section)) {
            named = true;
            written = charged(written, section.narrative.len())?;
            if let Some(resource) = section_resource(rule, section, options.provenance) {
                resources.push(resource);
                if resources.len() > MAX_TRANSFORM_RESOURCES {
                    return Err(too_many_resources_message());
                }
            }
        }
        if !named && options.detect_drift {
            drift.record(DriftFinding::UnmappedSection {
                section: echoed(section.names.first().map_or("", String::as_str)),
            });
        }
    }
    if options.detect_drift {
        for rule in &rules.sections {
            if !sections.iter().any(|section| names(rule, section)) {
                drift.record(DriftFinding::MissingSection {
                    section: echoed(&rule.section),
                });
            }
        }
    }

    Ok(Transformed {
        bundle: bundle(resources),
        drift,
    })
}

/// Whether `rule` names `section`.
///
/// A section answers to its title and to the display name of its code, each compared
/// on letters and digits alone, so a rule names a section however either spells the
/// name's word separators and case.
fn names(rule: &SectionRule, section: &DocumentSection) -> bool {
    let wanted = normalized_content_name(&rule.section);
    !wanted.is_empty()
        && section
            .names
            .iter()
            .any(|name| normalized_content_name(name) == wanted)
}

/// Every `section` the submitted document carries, in document order.
fn document_sections(document: &::roxmltree::Document<'_>) -> Vec<DocumentSection> {
    document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "section")
        .take(MAX_CCDA_SECTIONS)
        .map(|section| {
            let mut names = Vec::new();
            if let Some(title) = child(section, "title").map(element_text) {
                if !title.is_empty() {
                    names.push(title);
                }
            }
            if let Some(display) = child(section, "code")
                .and_then(|code| code.attribute("displayName"))
                .filter(|display| !display.trim().is_empty())
            {
                names.push(display.trim().to_string());
            }
            DocumentSection {
                names,
                narrative: child(section, "text").map(element_text).unwrap_or_default(),
            }
        })
        .collect()
}

/// The resource one named section becomes, or `None` when the section carries no
/// narrative to put in it — a resource with nothing of the source in it is an answer
/// nothing computed.
fn section_resource(
    rule: &SectionRule,
    section: &DocumentSection,
    provenance: Option<&str>,
) -> Option<::serde_json::Value> {
    if section.narrative.is_empty() {
        return None;
    }
    let mut resource = ::serde_json::json!({ "resourceType": rule.resource_type });
    if let Some(source) = provenance {
        set_member(&mut resource, "meta", provenance_meta(source));
    }
    set_member(
        &mut resource,
        "text",
        ::serde_json::json!({
            "status": NARRATIVE_STATUS,
            "div": format!(
                "<div xmlns=\"{XHTML_NAMESPACE}\">{}</div>",
                xhtml_text(&section.narrative)
            ),
        }),
    );
    Some(resource)
}

/// The first child element of `node` with local name `name`.
///
/// The local name alone decides: every element of a C-CDA document inherits the
/// document's default namespace.
fn child<'a>(node: ::roxmltree::Node<'a, 'a>, name: &str) -> Option<::roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

/// The text `node` and its descendants carry, as one bounded line.
///
/// Only TEXT nodes contribute, so a chunk is read once however deeply the element
/// nests it.
fn element_text(node: ::roxmltree::Node<'_, '_>) -> String {
    let mut text = String::new();
    for descendant in node.descendants().filter(::roxmltree::Node::is_text) {
        let Some(chunk) = descendant.text().map(str::trim).filter(|c| !c.is_empty()) else {
            continue;
        };
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(chunk);
        if text.chars().count() > MAX_NARRATIVE_CHARS {
            break;
        }
    }
    let text = text.trim();
    match text.char_indices().nth(MAX_NARRATIVE_CHARS) {
        Some((end, _)) => text[..end].to_string(),
        None => text.to_string(),
    }
}

/// `text` as the content of an XHTML element: the three characters XML gives a
/// meaning inside element content are written as their entities, so a narrative
/// carrying markup cannot close the `div` it sits in.
fn xhtml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The sentence a transform is refused with when the submitted input is larger than
/// this emulator transforms in one call.
///
/// `pub` because the surface that reads a request holds the submitted data to this
/// same ceiling before copying it out of the request body
/// ([`crate::service::transform_data`]), so both state it in one sentence.
pub fn input_too_large_message(bytes: usize) -> String {
    format!(
        "InputData must carry at most {MAX_TRANSFORM_INPUT_BYTES} bytes of source data, got \
         {bytes}"
    )
}

/// The sentence a transform is refused with when a submitted file could not be read
/// as comma-separated values.
fn not_csv_message(file: &str) -> String {
    format!(
        "The submitted file '{}' could not be read as comma-separated values",
        crate::service::non_rpc::bounded(file)
    )
}

/// The sentence a transform is refused with when a submitted file carries no header
/// row, so no column of it could be mapped.
fn no_header_message(file: &str) -> String {
    format!(
        "The submitted file '{}' holds no header row, so no source column could be mapped",
        crate::service::non_rpc::bounded(file)
    )
}

/// The sentence a transform is refused with when a submitted file carries more data
/// rows than this emulator transforms in one call.
fn too_many_rows_message(file: &str) -> String {
    format!(
        "The submitted file '{}' must carry at most {MAX_TRANSFORM_ROWS} data rows",
        crate::service::non_rpc::bounded(file)
    )
}

/// The sentence a transform is refused with when the mapping and the submitted input
/// together produce more resources than this emulator answers in one Bundle.
fn too_many_resources_message() -> String {
    format!(
        "The profile's mapping produces more than the {MAX_TRANSFORM_RESOURCES} FHIR resources \
         this transform answers in one Bundle"
    )
}

/// The sentence a transform is refused with when the mapping and the submitted input
/// together write more into the Bundle than this emulator answers in one call.
fn too_much_output_message() -> String {
    format!(
        "The profile's mapping writes more than the {MAX_TRANSFORM_OUTPUT_BYTES} bytes of \
         mapped values this transform answers in one Bundle"
    )
}

/// The sentence a transform is refused with when the submitted C-CDA document is not
/// well-formed XML, stating what the parser could not read.
fn not_xml_message(detail: &str) -> String {
    format!(
        "The submitted C-CDA document is not well-formed XML: {}",
        crate::service::non_rpc::bounded(detail)
    )
}

#[cfg(test)]
mod tests {
    //! The mapping reader and the element-path writer, over the shapes a profile's
    //! content declares a rule in. The end-to-end behaviour of the transform is in
    //! `tests/all/transform_data.rs`, over the wire a client reaches it on.

    use super::*;

    /// One mapping file, as a profile's content holds it.
    fn mapping(content: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("mapping-config.yaml".to_string(), content.to_string())])
    }

    /// RULE: a rule binds a source column to the element of a target resource it
    /// writes, however the file nests and spells that binding.
    #[test]
    fn a_rule_is_read_out_of_every_shape_a_mapping_declares_it_in() {
        // (case, the mapping file, the (resource type, column, path) rules it declares)
        /// One row: the case, the mapping file, and the (resource type, source
        /// column, element path) rules it declares.
        type Row = (&'static str, String, Vec<(&'static str, &'static str, &'static str)>);
        let rows: Vec<Row> = vec![
            (
                "the mapping config's tables, resource mappings and field mappings",
                "\
tables:
  - tableName: patients
    primaryKeyColumn: PAT_ID
    resourceMappings:
      - targetResourceType: Patient
        fieldMappings:
          - sourceColumn: LAST_NM
            fhirPath: name[0].family
          - sourceColumn: FIRST_NM
            fhirPath: name[0].given[0]
"
                .to_string(),
                vec![
                    ("Patient", "LAST_NM", "name[0].family"),
                    ("Patient", "FIRST_NM", "name[0].given[0]"),
                ],
            ),
            (
                "field mappings written as a map of column to path",
                "\
tables:
  - tableName: patients
    resourceMappings:
      - targetResourceType: Patient
        fieldMappings:
          LAST_NM: name[0].family
"
                .to_string(),
                vec![("Patient", "LAST_NM", "name[0].family")],
            ),
            (
                "the keys spelled in another case and separator",
                "\
tables:
  - table_name: patients
    resource_mappings:
      - target_resource_type: Patient
        field_mappings:
          - source_column: LAST_NM
            fhir_path: name[0].family
"
                .to_string(),
                vec![("Patient", "LAST_NM", "name[0].family")],
            ),
            (
                // The shape `super::super::sample_data` computes for a column.
                "a standalone JSON rule file, which YAML 1.2 reads too",
                ::serde_json::json!({
                    "sourceFormat": "CSV",
                    "sourceColumn": "SYSTOLIC",
                    "targetResourceType": "Observation",
                    "targetElement": "Observation.valueQuantity",
                })
                .to_string(),
                vec![("Observation", "SYSTOLIC", "Observation.valueQuantity")],
            ),
            (
                "a file that declares no rule at all",
                "a profile note, in prose".to_string(),
                Vec::new(),
            ),
            (
                "a rule naming no target resource type",
                "fieldMappings:\n  - sourceColumn: LAST_NM\n    fhirPath: name[0].family\n"
                    .to_string(),
                Vec::new(),
            ),
            (
                "a file using a YAML alias, which the loader would expand",
                "tables: &t\n  - tableName: patients\nmore: *t\n".to_string(),
                Vec::new(),
            ),
            (
                "a file nesting past the bound a stored file is read inside",
                format!(
                    "{}{}",
                    "[".repeat(MAX_MAPPING_NESTING + 1),
                    "]".repeat(MAX_MAPPING_NESTING + 1)
                ),
                Vec::new(),
            ),
            (
                // Compact block nesting opens a collection per indicator without
                // indenting and without a flow opener.
                "a file nesting compactly past the bound, on one line",
                format!(
                    "{}value",
                    "- ".repeat(MAX_MAPPING_COMPACT_INDICATORS + 1)
                ),
                Vec::new(),
            ),
            (
                // The guard counts a block indicator, not every `-`: a name
                // carrying hyphens is still read.
                "names carrying hyphens, which are not block indicators",
                "\
tables:
  - tableName: patient-records
    resourceMappings:
      - targetResourceType: Patient
        fieldMappings:
          - sourceColumn: LAST-NM
            fhirPath: name[0].family
"
                .to_string(),
                vec![("Patient", "LAST-NM", "name[0].family")],
            ),
        ];

        for (case, content, expected) in rows {
            let rules = mapping_rules(&mapping(&content));
            let declared: Vec<(String, String, String)> = rules
                .tables
                .iter()
                .flat_map(|table| {
                    table.fields.iter().map(|field| {
                        (
                            table.resource_type.clone(),
                            field.source_column.clone(),
                            field.target_path.clone(),
                        )
                    })
                })
                .collect();
            let expected: Vec<(String, String, String)> = expected
                .iter()
                .map(|(resource, column, path)| {
                    ((*resource).to_string(), (*column).to_string(), (*path).to_string())
                })
                .collect();
            assert_eq!(
                declared, expected,
                "case {case:?}: expected the rules {expected:?}, got {declared:?}"
            );
        }
    }

    /// RULE: a mapping declares at most [`MAX_MAPPING_RULES`] rules to one transform,
    /// so what a stored mapping can make one call do is bounded by a constant rather
    /// than by how much content was stored.
    #[test]
    fn a_mapping_declares_at_most_its_ceiling_of_rules() {
        let mut content = String::from(
            "tables:\n  - tableName: wide\n    resourceMappings:\n      - \
             targetResourceType: Patient\n        fieldMappings:\n",
        );
        for index in 0..MAX_MAPPING_RULES + 50 {
            content.push_str(&format!(
                "          - sourceColumn: c{index}\n            fhirPath: p{index}\n"
            ));
        }
        let rules = mapping_rules(&mapping(&content));
        let declared: usize = rules.tables.iter().map(|table| table.fields.len()).sum();
        assert_eq!(
            declared, MAX_MAPPING_RULES,
            "expected the mapping to declare at most {MAX_MAPPING_RULES} rules, got {declared}"
        );
    }

    /// RULE: the rules of ONE declared resource mapping belong to one resource, so a
    /// source row becomes one resource however many columns that mapping reads.
    #[test]
    fn one_declared_resource_mapping_is_one_resource() {        let rules = mapping_rules(&mapping(
            "\
tables:
  - tableName: patients
    primaryKeyColumn: PAT_ID
    resourceMappings:
      - targetResourceType: Patient
        fieldMappings:
          - sourceColumn: LAST_NM
            fhirPath: name[0].family
          - sourceColumn: FIRST_NM
            fhirPath: name[0].given[0]
      - targetResourceType: Observation
        fieldMappings:
          - sourceColumn: SYSTOLIC
            fhirPath: valueQuantity.value
",
        ));
        let shape: Vec<(String, Option<String>, Option<String>, usize)> = rules
            .tables
            .iter()
            .map(|table| {
                (
                    table.resource_type.clone(),
                    table.table.clone(),
                    table.primary_key_column.clone(),
                    table.fields.len(),
                )
            })
            .collect();
        let expected = vec![
            (
                "Patient".to_string(),
                Some("patients".to_string()),
                Some("PAT_ID".to_string()),
                2,
            ),
            (
                "Observation".to_string(),
                Some("patients".to_string()),
                Some("PAT_ID".to_string()),
                1,
            ),
        ];
        assert_eq!(
            shape, expected,
            "expected one resource per declared resource mapping {expected:?}, got {shape:?}"
        );
    }

    /// RULE: standalone rules of the same resource type are gathered into one
    /// resource, and split whenever two of them write the same element, so no rule
    /// overwrites another.
    #[test]
    fn standalone_rules_are_gathered_without_overwriting_one_another() {
        let mut content = BTreeMap::new();
        for (file, column, path) in [
            ("columns/001-last.json", "LAST_NM", "Patient.name[0].family"),
            ("columns/002-first.json", "FIRST_NM", "Patient.name[0].given[0]"),
            ("columns/003-other.json", "OTHER_NM", "Patient.name[0].family"),
        ] {
            content.insert(
                file.to_string(),
                ::serde_json::json!({
                    "sourceColumn": column,
                    "targetResourceType": "Patient",
                    "targetElement": path,
                })
                .to_string(),
            );
        }
        let rules = mapping_rules(&content);
        let gathered: Vec<Vec<String>> = rules
            .tables
            .iter()
            .map(|table| {
                table
                    .fields
                    .iter()
                    .map(|field| field.source_column.clone())
                    .collect()
            })
            .collect();
        let expected = vec![
            vec!["LAST_NM".to_string(), "FIRST_NM".to_string()],
            vec!["OTHER_NM".to_string()],
        ];
        assert_eq!(
            gathered, expected,
            "expected the rules gathered as {expected:?}, got {gathered:?}"
        );
    }

    /// RULE: a section rule binds a C-CDA section to the resource type its entries
    /// become.
    #[test]
    fn a_section_rule_binds_a_section_to_a_resource_type() {
        let rules = mapping_rules(&mapping(
            &::serde_json::json!({
                "sourceSection": "Vital Signs",
                "targetResourceType": "Observation",
            })
            .to_string(),
        ));
        let declared: Vec<(String, String)> = rules
            .sections
            .iter()
            .map(|section| (section.section.clone(), section.resource_type.clone()))
            .collect();
        assert_eq!(
            declared,
            vec![("Vital Signs".to_string(), "Observation".to_string())],
            "expected the section rule to be read, got {declared:?}"
        );
    }

    /// RULE: a mapped value is written at the element its path names, building the
    /// objects and arrays the path passes through — with a path that names the
    /// resource first naming an element OF that resource, not a member of it — and a
    /// path outside the bounds a stored rule is written inside writes nothing.
    #[test]
    fn a_mapped_value_is_written_at_the_element_its_path_names() {
        /// One row: the case, the resource type the rule declares, the path it names,
        /// and the resource the write produces.
        type Row = (&'static str, &'static str, String, Option<::serde_json::Value>);
        let rows: Vec<Row> = vec![
            (
                "an element of the first repeat",
                "Patient",
                "name[0].family".to_string(),
                Some(::serde_json::json!({ "name": [{ "family": "x" }] })),
            ),
            (
                "an element of an array inside a repeat",
                "Patient",
                "name[0].given[0]".to_string(),
                Some(::serde_json::json!({ "name": [{ "given": ["x"] }] })),
            ),
            (
                // An earlier repeat nothing named is left EMPTY, never null: FHIR R4
                // admits no null entry in a repeating element.
                "an index past the first",
                "Patient",
                "name[1].family".to_string(),
                Some(::serde_json::json!({ "name": [{}, { "family": "x" }] })),
            ),
            (
                "a plain element",
                "Patient",
                "gender".to_string(),
                Some(::serde_json::json!({ "gender": "x" })),
            ),
            (
                "a nested element",
                "Observation",
                "valueQuantity.value".to_string(),
                Some(::serde_json::json!({ "valueQuantity": { "value": "x" } })),
            ),
            (
                "the dotted index form the writer itself takes",
                "Patient",
                "name.0.family".to_string(),
                Some(::serde_json::json!({ "name": [{ "family": "x" }] })),
            ),
            (
                // The form `super::super::sample_data` writes a rule in.
                "a path naming the resource it is a path into",
                "Observation",
                "Observation.valueQuantity".to_string(),
                Some(::serde_json::json!({ "valueQuantity": "x" })),
            ),
            (
                "a path naming the resource, spelled another way",
                "Patient",
                "patient.birthDate".to_string(),
                Some(::serde_json::json!({ "birthDate": "x" })),
            ),
            (
                // Only the LEADING segment is the resource: an element of that name
                // deeper in the path is an element.
                "the resource's name deeper in the path",
                "Patient",
                "contact[0].patient".to_string(),
                Some(::serde_json::json!({ "contact": [{ "patient": "x" }] })),
            ),
            (
                "a path naming another resource type, which is an element to write",
                "Observation",
                "subject.reference".to_string(),
                Some(::serde_json::json!({ "subject": { "reference": "x" } })),
            ),
            ("the resource's name alone", "Patient", "Patient".to_string(), None),
            ("no element at all", "Patient", String::new(), None),
            (
                "an unterminated index",
                "Patient",
                "name[0.family".to_string(),
                None,
            ),
            (
                "an index past the bound",
                "Patient",
                format!("name[{}].family", MAX_PATH_INDEX + 1),
                None,
            ),
            (
                // The same ceiling, for the dotted form the writer itself takes: a
                // bare number names a repeat too.
                "a dotted index past the bound",
                "Patient",
                format!("name.{}.family", MAX_PATH_INDEX + 1),
                None,
            ),
            (
                "a dotted index far past the bound",
                "Patient",
                "name.4000000000.family".to_string(),
                None,
            ),
            (
                "a path deeper than the bound",
                "Patient",
                (0..=MAX_PATH_SEGMENTS)
                    .map(|step| format!("step{step}"))
                    .collect::<Vec<_>>()
                    .join("."),
                None,
            ),
        ];

        for (case, resource_type, path, expected) in rows {
            let dotted = dotted_path(&path, resource_type);
            let written = dotted.and_then(|dotted| {
                let mut resource = ::serde_json::json!({});
                let mut budget = 0usize;
                write_element(&mut resource, &dotted, "x", &mut budget)
                    .ok()
                    .filter(|written| *written)
                    .map(|_| resource)
            });
            assert_eq!(
                written, expected,
                "case {case:?} ({path:?} of a {resource_type}): expected {expected:?}, got \
                 {written:?}"
            );
        }
    }

    /// RULE: a submitted file is read by the rule whose table names it, whatever
    /// extension the file carries, and by every rule that names no table.
    #[test]
    fn a_table_is_read_from_the_file_that_names_it() {
        // (case, the table a rule names, the submitted file, whether the rule reads it)
        let rows: [(&str, &str, &str, bool); 6] = [
            ("the table's own name", "patients", "patients", true),
            ("the file carrying an extension", "patients", "patients.csv", true),
            ("another separator and case", "patient_records", "PatientRecords", true),
            ("another table", "patients", "encounters", false),
            ("a table named by the extension alone", "csv", "patients.csv", false),
            ("a rule naming an empty table", "", "patients", false),
        ];

        for (case, table, file, expected) in rows {
            let actual = source_table_matches(table, file);
            assert_eq!(
                actual, expected,
                "case {case:?} ({table:?} vs {file:?}): expected {expected}, got {actual}"
            );
        }
    }
}
