// SPDX-License-Identifier: CC0-1.0

//! How a collection of a cluster's Kubernetes API answers a LIST.
//!
//! A list is answered in CHUNKS. The Kubernetes API's list contract is that a
//! client may ask for a chunk size with `limit`, that "the server may choose to
//! return fewer items than the client asked for", and that a list the server did
//! not finish carries a `continue` token in its `metadata` for the client to
//! resume with, beside the `remainingItemCount` of what it has not sent yet. A
//! client that asks for no chunk size is answered the collection as far as the
//! server chose to send it, with the same token when there is more.
//!
//! Chunking is also what BOUNDS this address. A namespace holds up to
//! [`super::kubernetes_objects::MAX_PODS_PER_NAMESPACE`] objects and each of them
//! is as large as the client that created it made it, so an answer that
//! serialised every one of them would let one small `GET` build hundreds of
//! megabytes in memory while this service's store is held. One answer therefore
//! stops at [`MAX_LIST_RESPONSE_BYTES`] and hands back a token instead.

use super::kubernetes_api::MAX_REQUEST_BYTES;
use super::kubernetes_objects::{ApiRefusal, CORE_API_VERSION};

/// The most bytes of objects ONE list answer carries, after which the answer
/// stops and reports a `continue` token.
///
/// It is the ceiling the API server already applies to one request
/// ([`MAX_REQUEST_BYTES`]), so no answer this address writes is larger than the
/// largest body it reads, whatever a namespace holds.
pub const MAX_LIST_RESPONSE_BYTES: usize = MAX_REQUEST_BYTES;

/// What a list request asked for: the chunk size and where to resume.
#[derive(Debug, Default)]
pub struct ListRequest {
    /// `limit`: "the maximum number of responses to return for a list call".
    /// `None` when the request named none, and for `limit=0`, which is how the
    /// parameter's own default states "no limit".
    limit: Option<usize>,
    /// The `continue` token the client sent back: the name to resume AFTER.
    resume_after: Option<String>,
}

impl ListRequest {
    /// The list parameters `query` carries, or the `Status` the API server
    /// refuses a `limit` that is not a number with.
    ///
    /// The tokens this server mints are object names — lowercase RFC 1123
    /// subdomains ([`is_kubernetes_name`]) — so a client echoes one back
    /// unchanged and there is nothing to decode. A parameter this server does
    /// not serve is ignored, as the API server ignores one it does not know.
    pub fn from_query(query: Option<&str>) -> Result<Self, ApiRefusal> {
        let mut parsed = Self::default();
        for parameter in query.unwrap_or_default().split('&') {
            let (name, value) = match parameter.split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            match name {
                "limit" => {
                    // An empty value is the unset parameter, as is "0": the
                    // conversion from the query string's text to the parameter's
                    // own integer type reads both as "no limit".
                    if value.is_empty() {
                        continue;
                    }
                    let limit: usize = value.parse().map_err(|_| ApiRefusal {
                        status: 400,
                        reason: "BadRequest",
                        message: format!("unable to parse query parameter \"limit\": {value}"),
                        resource: None,
                    })?;
                    parsed.limit = (limit > 0).then_some(limit);
                }
                // An empty token is the unset value of the parameter, as a client
                // that has not resumed anything sends.
                "continue" if !value.is_empty() => {
                    parsed.resume_after = Some(value.to_string());
                }
                _ => {}
            }
        }
        Ok(parsed)
    }
}

/// One chunk of the collection `names` names, as the `<Kind>List` a client reads.
///
/// `names` is the collection in the order it is held, which is the order a
/// resumed read continues in; `render` answers the object document for one name,
/// and a name it cannot render is not in the answer. The chunk ends at the
/// client's `limit`, at [`MAX_LIST_RESPONSE_BYTES`], or at the end of the
/// collection — and the first object of a chunk is always carried, so a
/// collection holding one object larger than the budget can still be walked.
pub fn listed(
    kind: &str,
    names: &[String],
    request: &ListRequest,
    render: impl Fn(&str) -> Option<::serde_json::Value>,
) -> ::serde_json::Value {
    let start = match request.resume_after.as_deref() {
        Some(after) => names.partition_point(|name| name.as_str() <= after),
        None => 0,
    };
    let remaining = names.get(start..).unwrap_or_default();
    let mut items: Vec<::serde_json::Value> = Vec::new();
    let mut bytes = 0usize;
    let mut sent = 0usize;
    for name in remaining {
        if request.limit.is_some_and(|limit| items.len() >= limit) {
            break;
        }
        if !items.is_empty() && bytes >= MAX_LIST_RESPONSE_BYTES {
            break;
        }
        sent = sent.saturating_add(1);
        let Some(item) = render(name) else {
            continue;
        };
        bytes = bytes.saturating_add(item.to_string().len());
        items.push(item);
    }
    let unsent = remaining.len().saturating_sub(sent);
    let mut metadata = ::serde_json::Map::new();
    if unsent > 0 {
        // The token names the last object this answer carried, which is where the
        // next chunk resumes after.
        if let Some(last) = remaining.get(sent.saturating_sub(1)) {
            metadata.insert("continue".to_string(), ::serde_json::json!(last));
        }
        metadata.insert(
            "remainingItemCount".to_string(),
            ::serde_json::json!(unsent),
        );
    }
    ::serde_json::json!({
        "kind": kind,
        "apiVersion": CORE_API_VERSION,
        "metadata": ::serde_json::Value::Object(metadata),
        "items": items,
    })
}
