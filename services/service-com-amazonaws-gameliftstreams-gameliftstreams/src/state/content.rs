// SPDX-License-Identifier: CC0-1.0

//! The ONE read of the content an application is created from: how many bytes the
//! Amazon S3 location a request's `ApplicationSourceUri` names holds.
//!
//! "Enter an Amazon S3 URI to a bucket that contains your game or other application"
//! (`CreateApplication`'s `ApplicationSourceUri`), and the create "copies the content
//! and caching for future deployment in a stream group" (`ApplicationStatus`'s
//! `PROCESSING`). The size of what was copied is therefore a property of the OBJECTS at
//! that location at the instant of the create, and the application's read path reports
//! it as `StorageBytes` — so it is read once, here, and recorded on the application
//! record rather than recomputed on every read.
//!
//! The read is made the way any emulated service reaches another: the AWS SDK for Amazon
//! S3 driven over this emulator's own in-process transport, through the operation
//! callback ([`smithy_server_runtime::OperationContext::callback`]), built by the one
//! shared constructor ([`service_common::s3_client`]). No socket is opened, no name is
//! resolved and nothing outside this process is reachable from it, so the objects a
//! caller staged with `PutObject` are the objects this read sums.
//!
//! The walk is BOUNDED in both directions — at most [`MAX_CONTENT_PAGES`] pages and
//! [`MAX_CONTENT_OBJECTS`] objects — because one call of `CreateApplication` has to
//! reach an answer whatever a bucket holds.

/// How many listing pages of the content location this read walks before it stops.
///
/// A listing that kept handing back a continuation token would otherwise be awaited
/// without end.
const MAX_CONTENT_PAGES: usize = 100;

/// How many objects of the content location this read counts before it stops.
const MAX_CONTENT_OBJECTS: usize = 100_000;

/// The bucket and key prefix an `s3://bucket/prefix` URI names, or `None` when the
/// value is not such a URI at all.
///
/// The prefix is the key portion exactly as written: `s3://b/build/` names the keys
/// under `build/`, `s3://b` names every key of the bucket. A trailing separator is
/// NOT added or removed — an S3 listing prefix is a byte prefix of the key, and
/// adding one would exclude the object a URI names directly.
#[must_use]
pub fn source_location(source_uri: &str) -> Option<(&str, &str)> {
    let rest = source_uri.strip_prefix("s3://")?;
    let (bucket, prefix) = match rest.split_once('/') {
        Some((bucket, prefix)) => (bucket, prefix),
        None => (rest, ""),
    };
    (!bucket.is_empty()).then_some((bucket, prefix))
}

/// How many bytes the content at `source_uri` holds, read through this emulator's own
/// Amazon S3 in `region`.
///
/// The sum of the sizes of the objects under the URI's key prefix. Zero when the URI
/// names no bucket, when the store holds nothing there, or when nothing answered the
/// read at all: a size this read did not establish is not reported as one it did.
pub async fn stored_bytes(
    ctx: &::smithy_server_runtime::OperationContext<'_>,
    region: &str,
    source_uri: &str,
) -> i64 {
    let Some((bucket, prefix)) = source_location(source_uri) else {
        return 0;
    };
    // Built by the one shared constructor, so this hop is configured exactly as every
    // other emulated service's hop into the object store is. The endpoint it carries is
    // addressing for the emulator's own router, not a host anything connects to.
    let client = ::service_common::s3_client::s3_client(ctx.callback(), region);
    let mut total: i64 = 0;
    let mut counted: usize = 0;
    let mut continuation: Option<String> = None;
    for _ in 0..MAX_CONTENT_PAGES {
        let mut listing = client.list_objects_v2().bucket(bucket).prefix(prefix);
        if let Some(token) = continuation {
            listing = listing.continuation_token(token);
        }
        let page = match listing.send().await {
            Ok(page) => page,
            Err(failure) => {
                ::tracing::debug!(
                    bucket,
                    prefix,
                    error = %::aws_smithy_types::error::display::DisplayErrorContext(&failure),
                    "the content location of an application could not be listed; it holds \
                     no content this emulator can size"
                );
                return 0;
            }
        };
        for object in page.contents() {
            counted = counted.saturating_add(1);
            if counted > MAX_CONTENT_OBJECTS {
                ::tracing::debug!(
                    bucket,
                    prefix,
                    "the content location of an application holds more objects than this \
                     read sizes"
                );
                return total;
            }
            // Saturating: the total is reported as a `Long`, so no bucket's contents
            // can make the arithmetic overflow.
            total = total.saturating_add(object.size().unwrap_or(0).max(0));
        }
        continuation = page.next_continuation_token().map(str::to_string);
        if continuation.is_none() {
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RULE: an `s3://bucket/key` URI names a bucket and the key prefix under it, and a
    /// value that is not such a URI names no location at all.
    #[test]
    fn a_content_uri_names_a_bucket_and_a_key_prefix() {
        let rows: &[(&str, Option<(&str, &str)>)] = &[
            ("s3://content/build/", Some(("content", "build/"))),
            ("s3://content/build", Some(("content", "build"))),
            ("s3://content/", Some(("content", ""))),
            ("s3://content", Some(("content", ""))),
            (
                "s3://content/deep/nested/path/",
                Some(("content", "deep/nested/path/")),
            ),
            ("s3://", None),
            ("s3:///build/", None),
            ("https://content/build/", None),
            ("content/build/", None),
            ("", None),
        ];
        for (uri, expected) in rows {
            let actual = source_location(uri);
            assert_eq!(
                actual, *expected,
                "case {uri:?}: expected {expected:?}, got {actual:?}"
            );
        }
    }
}
