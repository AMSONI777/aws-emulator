// SPDX-License-Identifier: CC0-1.0

//! The tagging rules every operation of this service that carries tags applies:
//! which resource a `resourceArn` addresses, which tag keys the service accepts,
//! and how many tags one resource holds. A tag VALUE is bounded only by the
//! modelled `TagValue` (`@length(0, 256)`), which the boundary already enforces:
//! no rule of this service's own is stated for one, so none is enforced here.
//!
//! The tagging operations address a resource by ARN rather than by the
//! coordinates the rest of this service uses (`ResourceArn`, whose pattern is
//! `^arn:aws[-a-z0-9]*:[a-z0-9]+:[-a-z0-9]*:[0-9]{12}:bucket/.+$`), and
//! `TagResource` documents what such an ARN may name: "The tagged resource can
//! be a table bucket or a table." Both forms are therefore resolved HERE, out of
//! the same records the rest of the control plane reads and writes, so a tag
//! never lands on a resource identity the store no longer holds — a deleted
//! table's ARN is still well formed, and resolving it is the only way to tell it
//! from a live one.
//!
//! The tag KEY rules live here for the same reason: `TagKey` is modelled only by
//! its `@length(1, 128)`, so the reserved prefix and the character set are rules
//! the SERVICE enforces, and every operation that takes a `Tags` map — the two
//! creates as well as `TagResource` — reads them from here rather than stating
//! its own. The reserved namespace is the one rule that depends on WHO asked
//! ([`TagKeyOrigin`]): it is the namespace this service's own control plane
//! writes in, so a caller's TAGGING call may not name a key in it, while the
//! in-process provisioning path another emulated service reaches this one on
//! may — and a create, which is how such a service asks for a resource that
//! already carries those keys, records the set it is given.

use super::*;

/// The most tags one resource of this service holds.
///
/// PUBLISHED, not chosen: `TagResource` documents the figure — "You can add up
/// to 50 tags for each S3 resource."
/// (`smithy_query(query="doc", shape="TagResource")`). It is also what keeps the
/// store BOUNDED, as [`TABLE_BUCKETS_PER_ACCOUNT`] does for table buckets: a
/// caller cannot grow the process's memory without limit by tagging one resource
/// over and over.
pub const MAX_TAGS_PER_RESOURCE: usize = 50;

/// The prefix a tag key reserved for system use carries, so a caller's tag never
/// takes a key the service itself may write. Matched case-insensitively, as the
/// reserved namespace is documented.
pub const RESERVED_TAG_KEY_PREFIX: &str = "aws:";

/// The punctuation a tag key carries beside letters, digits and separators —
/// the set the service names in the sentence it refuses every other character
/// with ([`INVALID_TAG_KEY_MESSAGE`]).
pub const TAG_KEY_PUNCTUATION: [char; 8] = ['_', '.', ':', '/', '=', '+', '@', '-'];

/// How this service states a tag key that is reserved for its own use: the
/// client request error the model's `BadRequestException` (HTTP 400) names,
/// since choosing another key — not retrying — is what makes the request
/// possible. FIXED text, as [`INVALID_TABLE_BUCKET_NAME_MESSAGE`]: it names the
/// reserved prefix, which is the class of the failure, and takes neither the key
/// nor the resource from the request.
pub const RESERVED_TAG_KEY_MESSAGE: &str = "Tags beginning with 'aws:' are reserved for system use.";

/// How this service states a tag key carrying a character it does not accept:
/// the same `BadRequestException` class, worded with the character set the
/// service does accept. FIXED text — the offending key is not echoed.
pub const INVALID_TAG_KEY_MESSAGE: &str = "The provided tags are invalid. Tag key can only contain \
                                           alphanumeric characters, spaces, and _.:/=+@-";

/// How this service states a request that would leave a resource holding more
/// than [`MAX_TAGS_PER_RESOURCE`] tags: the same `BadRequestException` class,
/// worded with the bound the operation publishes. FIXED text — it states the
/// bound, and takes neither a key nor the resource from the request.
pub fn too_many_tags_message() -> String {
    format!("You can add up to {MAX_TAGS_PER_RESOURCE} tags for each S3 resource.")
}

/// Whether `character` is one a tag key carries: a letter, a digit, a separator,
/// or one of [`TAG_KEY_PUNCTUATION`].
///
/// Letters and digits are judged over the whole of Unicode, not just ASCII: a
/// tag travels as UTF-8 and a key in a non-Latin script is a key this service
/// accepts. A separator is a SPACE and its kin, which is what the sentence this
/// rule is stated by names; a control character that happens to be whitespace (a
/// tab, a line break) is not one, so it is refused with every other character
/// outside the set.
pub fn is_tag_key_character(character: char) -> bool {
    character.is_alphanumeric()
        || (character.is_whitespace() && !character.is_control())
        || TAG_KEY_PUNCTUATION.contains(&character)
}

/// Who is naming the tag keys one request carries, which is what decides whether
/// a key in the reserved namespace may be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagKeyOrigin {
    /// A request a CLIENT made. A key in the reserved namespace is the service's
    /// own, so such a request may not write one.
    Caller,
    /// A request another emulated service made in-process on behalf of a resource
    /// it provisions — the path the tags Amazon Web Services sets from inside
    /// itself arrive on, which no client's request can be. A key in the reserved
    /// namespace travels on it.
    Service,
}

/// Where the tag keys this request names came from.
///
/// A tag in the reserved namespace is the service's to set: the refusal
/// ([`RESERVED_TAG_KEY_MESSAGE`]) is the answer to an API CALLER, while the
/// service that owns such a tag sets it from inside, through no public API. In
/// this emulator one service reaches another ONLY through the in-process
/// callback, so that callback is the inside path, and the signal is the
/// [`::smithy_server_runtime::CallbackRecursionDepth`] request EXTENSION the
/// framework's callback transport stamps on every in-process call. An extension
/// never travels over the wire: nothing a client can send — on any socket, signed
/// with any credential — sets it, so a client's reserved key is refused either
/// way. It is the same framework signal other service crates read to tell an
/// in-process call from a client's request.
pub fn tag_key_origin(ctx: &::smithy_server_runtime::OperationContext<'_>) -> TagKeyOrigin {
    match ctx
        .parts()
        .extensions
        .get::<::smithy_server_runtime::CallbackRecursionDepth>()
    {
        Some(_) => TagKeyOrigin::Service,
        None => TagKeyOrigin::Caller,
    }
}

/// Whether `key` lies in the reserved namespace: the prefix is matched
/// case-insensitively, since the namespace is the service's however a request
/// spells it.
pub fn is_reserved_tag_key(key: &str) -> bool {
    let prefix = RESERVED_TAG_KEY_PREFIX.as_bytes();
    let bytes = key.as_bytes();
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The fixed sentence `key` is refused with, or `None` when it is a key a request
/// of this `origin` may write.
///
/// Two rules, in the order they are stated: a key in the reserved namespace is
/// refused to a CALLER, whatever case it spells the prefix in, and every key —
/// whoever named it — must be made of the characters a tag key carries.
pub fn tag_key_refusal(key: &str, origin: TagKeyOrigin) -> Option<&'static str> {
    if origin == TagKeyOrigin::Caller && is_reserved_tag_key(key) {
        return Some(RESERVED_TAG_KEY_MESSAGE);
    }
    if !key.chars().all(is_tag_key_character) {
        return Some(INVALID_TAG_KEY_MESSAGE);
    }
    None
}

/// The fixed sentence the first key of `keys` a request of this `origin` may not
/// write is refused with, or `None` when every key is one it may.
///
/// One implementation serves every operation of this service that takes tag keys
/// — the `tags` map of a create and of `TagResource` alike — because the rules
/// belong to the key, not to the operation that carried it.
///
/// Hand the keys over in their stored (sorted) order, so a request carrying more
/// than one unacceptable key is refused by the same one every time: the
/// modelled `Tags` map deserializes into a hash map, whose iteration order is
/// not stable across runs.
pub fn tag_keys_refusal<'a>(
    keys: impl IntoIterator<Item = &'a str>,
    origin: TagKeyOrigin,
) -> Option<&'static str> {
    keys.into_iter()
        .find_map(|key| tag_key_refusal(key, origin))
}

/// The fixed sentence a tag write is refused with when it would leave the
/// resource holding more than [`MAX_TAGS_PER_RESOURCE`] tags, or `None` when it
/// keeps the resource inside the bound.
///
/// `resident` is what the resource carries now — the empty map for a resource a
/// create is about to mint — and `incoming` what the request applies. A key in
/// both is REPLACED rather than added, so what is judged is the keys the
/// resource would end up holding, which is why the bound lives here rather than
/// in each operation that writes tags.
pub fn tag_count_refusal(
    resident: &BTreeMap<String, String>,
    incoming: &BTreeMap<String, String>,
) -> Option<String> {
    let resulting = resident
        .keys()
        .chain(incoming.keys())
        .collect::<::std::collections::BTreeSet<_>>()
        .len();
    (resulting > MAX_TAGS_PER_RESOURCE).then(too_many_tags_message)
}

/// Which resource of this service a `resourceArn` names, read off the FORM of
/// the ARN: the two the tagging operations document, a table bucket and a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaggableResourceKind {
    /// `…:bucket/<name>` — a table bucket.
    TableBucket,
    /// `…:bucket/<name>/table/<table id>` — a table, as [`table_arn`] builds one.
    Table,
}

/// The resource form `resource_arn` names, or `None` when the value addresses no
/// resource class this service tags.
///
/// The modelled pattern is already enforced at the boundary, so what reaches
/// here carries the `:bucket/` segment and at least one character after it; what
/// it does NOT say is which of the two taggable forms those characters make up,
/// which is what this reads.
pub fn taggable_resource_kind(resource_arn: &str) -> Option<TaggableResourceKind> {
    let within_account = resource_arn.split_once(":bucket/")?.1;
    let mut segments = within_account.split('/');
    segments.next().filter(|name| !name.is_empty())?;
    match (segments.next(), segments.next(), segments.next()) {
        (None, _, _) => Some(TaggableResourceKind::TableBucket),
        (Some("table"), Some(id), None) if !id.is_empty() => Some(TaggableResourceKind::Table),
        _ => None,
    }
}

/// Why a `resourceArn` reached no resource of this store.
///
/// The two cases are different classes of failure, which is why they are kept
/// apart: a value that cannot address a taggable resource at all is the caller's
/// request error, and one that addresses a resource the store does not hold is
/// the `NotFoundException` the tagging operations model. The operation that asks
/// words each in its own modelled error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaggableResourceRefusal {
    /// The value names no resource class this service tags.
    NotTaggable,
    /// A table bucket's ARN, and no table bucket of this account and Region
    /// carries it.
    NoSuchTableBucket,
    /// A table's ARN, and the store holds no such table — it was deleted, or it
    /// never existed.
    NoSuchTable,
}

impl TaggableResourceRefusal {
    /// The fixed sentence this service states the refusal with: the one it
    /// already states that class of failure with everywhere else.
    pub fn message(self) -> &'static str {
        match self {
            Self::NotTaggable => INVALID_RESOURCE_ARN_MESSAGE,
            Self::NoSuchTableBucket => BUCKET_NOT_FOUND_MESSAGE,
            Self::NoSuchTable => TABLE_NOT_FOUND_MESSAGE,
        }
    }

    /// Whether the ARN addressed a resource the store does not hold — the
    /// `NotFoundException` (HTTP 404) the tagging operations model — as against a
    /// value that addresses no taggable resource at all, which is their
    /// `BadRequestException` (HTTP 400).
    pub fn is_absent(self) -> bool {
        !matches!(self, Self::NotTaggable)
    }
}

impl ComAmazonawsS3tablesS3tablebucketsState {
    /// The tags resident on the resource `resource_arn` addresses.
    pub fn resource_tags(
        &self,
        resource_arn: &str,
    ) -> Result<&BTreeMap<String, String>, TaggableResourceRefusal> {
        match taggable_resource_kind(resource_arn).ok_or(TaggableResourceRefusal::NotTaggable)? {
            TaggableResourceKind::TableBucket => self
                .table_buckets
                .get(resource_arn)
                .map(|bucket| &bucket.tags)
                .ok_or(TaggableResourceRefusal::NoSuchTableBucket),
            TaggableResourceKind::Table => self
                .table_by_arn(resource_arn)
                .map(|table| &table.tags)
                .ok_or(TaggableResourceRefusal::NoSuchTable),
        }
    }

    /// The tags resident on the resource `resource_arn` addresses, for a caller
    /// that is about to change them.
    ///
    /// The resource is resolved BEFORE the caller writes anything, so a tag
    /// never lands on a table bucket or a table the store no longer holds.
    pub fn resource_tags_mut(
        &mut self,
        resource_arn: &str,
    ) -> Result<&mut BTreeMap<String, String>, TaggableResourceRefusal> {
        match taggable_resource_kind(resource_arn).ok_or(TaggableResourceRefusal::NotTaggable)? {
            TaggableResourceKind::TableBucket => self
                .table_buckets
                .get_mut(resource_arn)
                .map(|bucket| &mut bucket.tags)
                .ok_or(TaggableResourceRefusal::NoSuchTableBucket),
            TaggableResourceKind::Table => self
                .table_by_arn_mut(resource_arn)
                .map(|table| &mut table.tags)
                .ok_or(TaggableResourceRefusal::NoSuchTable),
        }
    }
}
