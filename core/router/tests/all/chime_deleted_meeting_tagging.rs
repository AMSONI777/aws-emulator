// SPDX-License-Identifier: CC0-1.0

//! The tags of a DELETED Chime SDK meeting, across the two services that can serve a
//! tagging call for it.
//!
//! The Amazon Chime family binds the three generic tagging routes (`GET /tags?arn=…`,
//! `POST /tags?operation=tag-resource`, `POST /tags?operation=untag-resource`) in five of
//! its six models, and nothing in a tag or untag request's `Parts` names a service: the
//! resource ARN travels in the request BODY. So a request that names a family endpoint host
//! is served by THAT endpoint, and one that names none — an SDK client pointed at the
//! emulator's own address — is served by the family's declared tagging owner, Chime SDK
//! Identity, whichever member's resource the ARN names.
//!
//! The rule under test: a meeting's tags live exactly as long as the meeting, so once
//! `DeleteMeeting` has run, every tagging call naming that `MeetingArn` is refused with the
//! modelled `BadRequestException` (HTTP 400) reporting the meeting id as invalid — from
//! BOTH members, because which one serves the call is a routing detail the client does not
//! choose. Before the delete the same calls are served, so the refusal is about the deleted
//! meeting and not about the route.
//!
//! The table spans what the rule generalises over: which of the three tagging routes is
//! called, which member serves it (addressed by the Chime SDK Meetings endpoint host, and
//! addressed with no family host at all), whether the meeting carried tags when it was
//! deleted, and which create minted it.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

type Identity =
    service_com_amazonaws_chimesdkidentity_chimeidentityservice::EmulatedService<
        engine::InMemoryEngine,
    >;
type Meetings =
    service_com_amazonaws_chimesdkmeetings_chimemeetingssdkservice::EmulatedService<
        engine::InMemoryEngine,
    >;

/// A SigV4 `Authorization` header whose credential scope names the signing name all six
/// Chime services share, which is what routes a request to the family.
const AUTHORIZATION: &str = "AWS4-HMAC-SHA256 \
     Credential=AKIDTESTCHIME/20260101/us-east-1/chime/aws4_request, \
     SignedHeaders=host;x-amz-date, Signature=0000";

/// The Chime SDK Meetings endpoint host: a request naming it is served by that service.
const MEETINGS_HOST: &str = "meetings-chime.us-east-1.amazonaws.com";

/// The emulator's own address: a request naming it names no family endpoint, so the
/// family's declared tagging owner serves its `/tags` calls.
const EMULATOR_HOST: &str = "localhost:9297";

/// The message a tagging call naming a meeting the Chime SDK Meetings store holds no
/// meeting under is refused with.
const INVALID_MEETING_ID: &str = "Invalid meeting id";

/// Chime SDK Identity and Chime SDK Meetings, mounted on ONE engine exactly as
/// `build_router` mounts them.
fn router() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(Identity::new(Arc::clone(&engine)));
    router.register_service(Meetings::new(engine));
    router
}

/// One answer: the HTTP status, the restJson1 error code, and the parsed body.
struct Reply {
    status: u16,
    code: String,
    body: Value,
}

async fn call(
    router: &MultiServiceRouter,
    method: &str,
    host: &str,
    path: &str,
    body: Option<&Value>,
) -> Reply {
    let payload = body.map_or_else(Vec::new, |value| {
        serde_json::to_vec(value).expect("a request body serializes")
    });
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("host", host)
        .header("authorization", AUTHORIZATION)
        .header("content-type", "application/json")
        .body(Bytes::from(payload))
        .expect("the test request is well formed");

    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let header_code = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = response.into_body();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    let code = header_code
        .or_else(|| {
            body.get("__type")
                .and_then(Value::as_str)
                .map(|wire| wire.rsplit('#').next().unwrap_or(wire).to_string())
        })
        .unwrap_or_default();
    Reply {
        status,
        code,
        body,
    }
}

/// The three tagging routes, as `(name, method, path, body)` for `resource_arn`.
///
/// The list route carries the ARN in a query parameter, percent-encoded with this test
/// crate's one encoder ([`crate::query_wire::form_encode`]) rather than a copy of it.
fn tagging_routes(resource_arn: &str) -> Vec<(&'static str, &'static str, String, Option<Value>)> {
    vec![
        (
            "ListTagsForResource",
            "GET",
            format!(
                "/tags?arn={}",
                crate::query_wire::form_encode(resource_arn)
            ),
            None,
        ),
        (
            "TagResource",
            "POST",
            "/tags?operation=tag-resource".to_string(),
            Some(json!({
                "ResourceARN": resource_arn,
                "Tags": [{ "Key": "env", "Value": "dev" }],
            })),
        ),
        (
            "UntagResource",
            "POST",
            "/tags?operation=untag-resource".to_string(),
            Some(json!({ "ResourceARN": resource_arn, "TagKeys": ["env"] })),
        ),
    ]
}

/// One row: how the meeting is created and whether it carried tags when it was deleted.
struct Case {
    case: &'static str,
    path: &'static str,
    request: Value,
}

#[tokio::test]
async fn a_deleted_meetings_arn_is_refused_by_whichever_member_serves_the_tagging_call() {
    let rows: Vec<Case> = vec![
        Case {
            case: "a meeting created with no tags",
            path: "/meetings",
            request: json!({
                "ClientRequestToken": "tok-dead-plain",
                "MediaRegion": "us-east-1",
                "ExternalMeetingId": "ext-dead-plain",
            }),
        },
        Case {
            case: "a meeting created WITH tags",
            path: "/meetings",
            request: json!({
                "ClientRequestToken": "tok-dead-tagged",
                "MediaRegion": "eu-west-1",
                "ExternalMeetingId": "ext-dead-tagged",
                "Tags": [{ "Key": "team", "Value": "collab" }],
            }),
        },
        Case {
            case: "a meeting created with its attendees",
            path: "/meetings?operation=create-attendees",
            request: json!({
                "ClientRequestToken": "tok-dead-attendees",
                "MediaRegion": "us-east-1",
                "ExternalMeetingId": "ext-dead-attendees",
                "Attendees": [{ "ExternalUserId": "user-dead" }],
            }),
        },
    ];

    for row in rows {
        let Case {
            case,
            path,
            request,
        } = row;
        let router = router();

        let created = call(&router, "POST", MEETINGS_HOST, path, Some(&request)).await;
        assert_eq!(
            created.status, 200,
            "case {case:?}: expected the create to answer 200, got {} with {:?}",
            created.status, created.body
        );
        let meeting = created.body["Meeting"].clone();
        let meeting_id = meeting["MeetingId"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: no MeetingId in {meeting:?}"))
            .to_string();
        let arn = meeting["MeetingArn"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case:?}: no MeetingArn in {meeting:?}"))
            .to_string();

        // While the meeting is LIVE both members serve every tagging route, so the
        // refusals below are about the deleted meeting and not about the route.
        for host in [MEETINGS_HOST, EMULATOR_HOST] {
            for (operation, method, route, body) in tagging_routes(&arn) {
                let reply = call(&router, method, host, &route, body.as_ref()).await;
                assert!(
                    reply.status < 300,
                    "case {case:?} ({operation} at {host}, meeting live): expected it served, \
                     got {} {:?} with {:?}",
                    reply.status,
                    reply.code,
                    reply.body
                );
            }
        }

        let deleted = call(
            &router,
            "DELETE",
            MEETINGS_HOST,
            &format!("/meetings/{meeting_id}"),
            None,
        )
        .await;
        assert_eq!(
            deleted.status, 204,
            "case {case:?}: expected DeleteMeeting to answer 204, got {} with {:?}",
            deleted.status, deleted.body
        );

        // After the delete, every route is refused the same way from both members.
        for host in [MEETINGS_HOST, EMULATOR_HOST] {
            for (operation, method, route, body) in tagging_routes(&arn) {
                let reply = call(&router, method, host, &route, body.as_ref()).await;
                assert_eq!(
                    (
                        reply.status,
                        reply.code.as_str(),
                        reply.body["Message"].as_str()
                    ),
                    (400, "BadRequestException", Some(INVALID_MEETING_ID)),
                    "case {case:?} ({operation} at {host}, meeting deleted): expected the \
                     modelled 400 reporting the meeting id as invalid, got {} {:?} with {:?}",
                    reply.status,
                    reply.code,
                    reply.body
                );
            }
        }
    }
}
