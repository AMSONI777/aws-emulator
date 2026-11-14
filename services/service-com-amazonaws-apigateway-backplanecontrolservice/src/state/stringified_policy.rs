// SPDX-License-Identifier: CC0-1.0

//! The two things API Gateway does to the RESOURCE POLICY document of an api that the
//! caller's own text does not say: what it NORMALIZES before storing it, and how it REPORTS
//! the stored document back.
//!
//! `RestApi$policy` is "a STRINGIFIED JSON policy document that applies to this RestApi",
//! and the two steps are:
//!
//! * **stored** ([`expanded_policy_resources`]) — a `Resource` element written in the
//!   `execute-api:/{stage}/{verb}/{path}` shorthand API Gateway's own policy examples use
//!   names a method of THIS api, and the service expands it to that method's ARN before
//!   storing the document, so the document a later read reports names its resources the one
//!   way however the caller wrote them;
//! * **reported** ([`stringified_policy`]) — the member carries the stored document's text
//!   ENCODED as a JSON string, every `"` of the document arriving as `\"` and every `\` as
//!   `\\`, so a caller reading `policy` out of a response decodes that string once before it
//!   can parse the document. A caller WRITES the document itself (`{"Version":…}`), which is
//!   what the api stores and what every decision is taken from.
//!
//! The encoding is `serde_json`'s own string serializer rather than a replacement of quotes
//! written here: a document carrying a backslash, a control character or a non-ASCII
//! character is then encoded as the JSON string grammar defines it, and decoding the
//! reported value with any JSON reader yields exactly the document that was stored.
//!
//! Nothing here reads or writes this service's records: both are functions of one value.

/// `document` as the api REPORTS it: its text encoded as a JSON string, without the quotes
/// that would delimit that string.
///
/// A document this cannot encode at all is reported as it is stored, so a read never fails
/// on the rendering of a value a caller already stored.
#[must_use]
pub fn stringified_policy(document: &str) -> String {
    let Ok(encoded) = ::serde_json::to_string(document) else {
        return document.to_string();
    };
    encoded
        .strip_prefix('"')
        .and_then(|encoded| encoded.strip_suffix('"'))
        .map_or_else(|| document.to_string(), str::to_string)
}

/// The prefix of the shorthand a resource-policy statement may name a method of its own api
/// by: `execute-api:/{stage}/{verb}/{path}`, the form API Gateway's own policy examples are
/// written in and the one `execute-api:/*` covers.
const SCOPED_RESOURCE_PREFIX: &str = "execute-api:";

/// The elements of a statement whose values name resources, both of which the expansion
/// below applies to: a document is not read as naming one resource in the shorthand and
/// another in the ARN form.
const RESOURCE_ELEMENTS: [&str; 2] = ["Resource", "NotResource"];

/// `document` with every resource written in the [`SCOPED_RESOURCE_PREFIX`] shorthand
/// expanded to the ARN of the method of `api_id` it names, in `region`.
///
/// A value already written as an ARN, and one in neither form, is left exactly as it was; so
/// is a document that is not JSON at all, since what a caller stored is what a later read
/// reports.
#[must_use]
pub fn expanded_policy_resources(document: &str, region: &str, api_id: &str) -> String {
    let Ok(mut parsed) = ::serde_json::from_str::<::serde_json::Value>(document) else {
        return document.to_string();
    };
    let Some(statements) = parsed
        .get_mut("Statement")
        .and_then(::serde_json::Value::as_array_mut)
    else {
        return document.to_string();
    };
    for statement in statements {
        for element in RESOURCE_ELEMENTS {
            match statement.get_mut(element) {
                Some(::serde_json::Value::String(resource)) => {
                    *resource = expanded_resource(resource, region, api_id);
                }
                Some(::serde_json::Value::Array(resources)) => {
                    for resource in resources.iter_mut() {
                        if let ::serde_json::Value::String(resource) = resource {
                            *resource = expanded_resource(resource, region, api_id);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    parsed.to_string()
}

/// One resource value, expanded: the shorthand's path under the api's own ARN, or the value
/// unchanged where it is not written in the shorthand.
fn expanded_resource(resource: &str, region: &str, api_id: &str) -> String {
    match resource.strip_prefix(SCOPED_RESOURCE_PREFIX) {
        // The shorthand's own separator opens the path, which is also the separator between
        // the api id and the path in the ARN, so the path is appended as it is written.
        Some(path) if path.starts_with('/') => {
            ::emulator_server::emulator_arn("execute-api", region, &format!("{api_id}{path}"))
        }
        _ => resource.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RULE: the reported value is the document's text encoded as a JSON string, so decoding
    /// it once as a JSON string yields the document that was stored.
    #[test]
    fn the_reported_policy_decodes_to_the_stored_document() {
        // Rows differ along what the stored document carries: the quotes every policy
        // carries, a backslash, a control character, a non-ASCII character, and no JSON at
        // all.
        let rows: &[(&str, &str)] = &[
            (
                "a policy document",
                "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\"}]}",
            ),
            ("a value carrying a backslash", "{\"Sid\":\"a\\\\b\"}"),
            ("a value carrying a newline", "{\"Sid\":\"a\nb\"}"),
            ("a value carrying a non-ASCII character", "{\"Sid\":\"ünï\"}"),
            ("not a document at all", "not json"),
            ("nothing at all", ""),
        ];
        for (case, document) in rows {
            let reported = stringified_policy(document);
            let decoded: String = ::serde_json::from_str(&format!("\"{reported}\""))
                .unwrap_or_else(|error| {
                    panic!("case {case}: {reported:?} must decode as a JSON string, got {error}")
                });
            assert_eq!(
                &decoded, document,
                "case {case}: expected the stored document back, got {decoded:?}"
            );
        }
    }

    /// RULE: a resource written in the `execute-api:/…` shorthand is stored as the ARN of
    /// the method of this api it names, and every other value is stored as it was written.
    #[test]
    fn the_scoped_resource_shorthand_is_expanded_to_the_methods_arn() {
        const REGION: &str = "us-west-2";
        const API: &str = "abc1230000";
        let arn = |resource: &str| {
            format!(
                "arn:aws:execute-api:{REGION}:{account}:{resource}",
                account = ::engine::emulator_account_id()
            )
        };
        // Rows differ along the form the value is written in: the shorthand naming one
        // method, the shorthand's wildcard, an ARN already, a value in neither form, and the
        // prefix with no path after it.
        let rows: &[(&str, &str, String)] = &[
            (
                "the shorthand naming one method",
                "execute-api:/test/GET/widgets",
                arn(&format!("{API}/test/GET/widgets")),
            ),
            (
                "the shorthand's wildcard",
                "execute-api:/*",
                arn(&format!("{API}/*")),
            ),
            (
                "an ARN already",
                &arn(&format!("{API}/test/GET/widgets")),
                arn(&format!("{API}/test/GET/widgets")),
            ),
            ("a value in neither form", "*", "*".to_string()),
            (
                "the prefix with no path after it",
                "execute-api:",
                "execute-api:".to_string(),
            ),
        ];
        for (case, written, expected) in rows {
            let document = format!(
                "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\
                 \"Action\":\"execute-api:Invoke\",\"Resource\":\"{written}\"}}]}}"
            );
            let stored: ::serde_json::Value =
                ::serde_json::from_str(&expanded_policy_resources(&document, REGION, API))
                    .unwrap_or_else(|error| panic!("case {case}: the stored document parses: {error}"));
            assert_eq!(
                stored["Statement"][0]["Resource"].as_str(),
                Some(expected.as_str()),
                "case {case}: got {:?}",
                stored["Statement"][0]["Resource"]
            );
        }

        // Every value of a LIST of resources is expanded, and so is a `NotResource`: a
        // document is not read as naming one resource in the shorthand and another in the
        // ARN form.
        let several = "{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"execute-api:Invoke\",\
                        \"NotResource\":[\"execute-api:/test/GET/widgets\",\"execute-api:/*\",\
                        \"*\"]}]}";
        let stored: ::serde_json::Value =
            ::serde_json::from_str(&expanded_policy_resources(several, REGION, API))
                .expect("the stored document parses");
        assert_eq!(
            stored["Statement"][0]["NotResource"],
            ::serde_json::json!([
                arn(&format!("{API}/test/GET/widgets")),
                arn(&format!("{API}/*")),
                "*",
            ]),
            "case \"a list of resources\": got {:?}",
            stored["Statement"][0]["NotResource"]
        );

        // A document that is not a policy at all is stored as the caller wrote it.
        for (case, document) in [
            ("not JSON at all", "not json"),
            ("no statements", "{\"Version\":\"2012-10-17\"}"),
        ] {
            let stored = expanded_policy_resources(document, REGION, API);
            assert_eq!(stored, document, "case {case}: got {stored:?}");
        }
    }

    /// RULE: a document's own quotes are reported escaped, which is what makes the value a
    /// JSON string rather than a document.
    #[test]
    fn a_documents_quotes_are_reported_escaped() {
        let reported = stringified_policy("{\"Version\":\"2012-10-17\"}");
        assert_eq!(
            reported, "{\\\"Version\\\":\\\"2012-10-17\\\"}",
            "case \"a document's quotes\": got {reported:?}"
        );
    }
}
