// SPDX-License-Identifier: CC0-1.0

//! An `AWS::CloudFormation::WaitConditionHandle` IS a pre-signed write target, and a signal
//! PUT to it releases the wait conditions declared with it.
//!
//! The rule under test: **the physical resource id of a wait condition handle is a pre-signed
//! absolute `https` URL this emulator serves — carrying the Amazon S3 write target such a
//! handle stands for and the pre-signing query — reported identically by `Ref`, by a stack
//! output built on it and by every per-resource read, stable while the resource is not
//! replaced; and a signal document PUT to that URL is recorded as a resource signal of every
//! `AWS::CloudFormation::WaitCondition` whose `Handle` names that handle, so a wait with the
//! success signals its `Count` asks for proceeds and the `Data` those signals carried is what
//! the wait condition publishes.**
//!
//! Every assertion drives the emulator through its own wire: the stack operations over
//! CloudFormation's awsQuery endpoint, and the signal as the plain, unsigned HTTP `PUT` to
//! the published URL a client really makes. Nothing here spells a URL: the published value is
//! read back off the stack, because its bucket, key and signature are per-run values and only
//! its SHAPE is the contract.
//!
//! The rows differ along what the rule generalises over: how many handles a template declares
//! and how their logical ids are spelled, the Region the stack is created in (which is what
//! the S3 target names), a handle added by an `UpdateStack`, the `Count` a wait condition
//! waits for, how many wait conditions share one handle, what a signal's `Data` carries, and —
//! for the refusals — the method, the body and the signature of the write.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use service_com_amazonaws_cloudformation_cloudformation::state::provisioning::wait_condition_handle;
use smithy_server_runtime::MultiServiceRouter;

use super::harness::{
    call_in, member, router_with_engine, wait_for_the_transition, xml_text, xml_texts, REGION,
};

/// How long one poll of a stack's status waits before asking again, and how many times: a
/// stack's terminal status is clock-owed and what makes a released wait due is a READ, so a
/// client polls. The deadline is generous — nothing here asserts on how fast the host runs.
const POLL_INTERVAL: ::std::time::Duration = ::std::time::Duration::from_millis(100);
const POLL_ATTEMPTS: usize = 300;

/// The suffix every status a stack operation in flight carries ends in.
const IN_PROGRESS: &str = "_IN_PROGRESS";

/// The type whose physical id is the published URL.
const HANDLE_TYPE: &str = "AWS::CloudFormation::WaitConditionHandle";

/// `CreateStack` in one Region.
async fn create_in(
    router: &MultiServiceRouter,
    region: &str,
    name: &str,
    template: &str,
) -> (u16, String) {
    call_in(
        router,
        region,
        "CreateStack",
        &[member("StackName", name), member("TemplateBody", template)],
    )
    .await
}

/// `DescribeStacks` for one stack in one Region: its status and the whole body.
async fn describe(router: &MultiServiceRouter, region: &str, name: &str) -> (String, String) {
    let (status_code, body) =
        call_in(router, region, "DescribeStacks", &[member("StackName", name)]).await;
    assert_eq!(
        status_code, 200,
        "expected DescribeStacks to answer for {name:?}, got {status_code} with {body}"
    );
    (xml_text(&body, "StackStatus").unwrap_or_default(), body)
}

/// Poll until the stack leaves every `*_IN_PROGRESS` status, and answer the status it settled
/// in with the body that reported it.
async fn settled(
    router: &MultiServiceRouter,
    region: &str,
    case: &str,
    name: &str,
) -> (String, String) {
    let mut last = (String::new(), String::new());
    for _ in 0..POLL_ATTEMPTS {
        last = describe(router, region, name).await;
        if !last.0.ends_with(IN_PROGRESS) {
            return last;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!(
        "case {case:?}: {name:?} never left an in-progress status; last was {:?} with {}",
        last.0, last.1
    );
}

/// The `PhysicalResourceId` one resource of a stack reports, read through the
/// `LogicalResourceId` filter so the answer carries that resource alone.
async fn physical_id(
    router: &MultiServiceRouter,
    region: &str,
    stack: &str,
    logical_id: &str,
) -> String {
    let (status_code, body) = call_in(
        router,
        region,
        "DescribeStackResource",
        &[
            member("StackName", stack),
            member("LogicalResourceId", logical_id),
        ],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "expected DescribeStackResource to answer for {stack:?}/{logical_id:?}, got \
         {status_code} with {body}"
    );
    xml_text(&body, "PhysicalResourceId").unwrap_or_default()
}

/// Every `(LogicalResourceId, PhysicalResourceId)` a reader reports, as the map a client
/// reads: the two members are PARALLEL lists in the envelope, sound because every reported
/// resource carries both.
fn reported_ids(body: &str) -> BTreeMap<String, String> {
    xml_texts(body, "LogicalResourceId")
        .into_iter()
        .zip(xml_texts(body, "PhysicalResourceId"))
        .collect()
}

/// `DescribeStackResources` for a whole stack, as that map.
async fn described_ids(
    router: &MultiServiceRouter,
    region: &str,
    stack: &str,
) -> BTreeMap<String, String> {
    let (status_code, body) = call_in(
        router,
        region,
        "DescribeStackResources",
        &[member("StackName", stack)],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "expected DescribeStackResources to answer for {stack:?}, got {status_code} with {body}"
    );
    reported_ids(&body)
}

/// `ListStackResources` for a whole stack, as that map.
async fn listed_ids(
    router: &MultiServiceRouter,
    region: &str,
    stack: &str,
) -> BTreeMap<String, String> {
    let (status_code, body) = call_in(
        router,
        region,
        "ListStackResources",
        &[member("StackName", stack)],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "expected ListStackResources to answer for {stack:?}, got {status_code} with {body}"
    );
    reported_ids(&body)
}

/// A stack's reported outputs, as the key/value map a client reads.
fn outputs_of(xml: &str) -> BTreeMap<String, String> {
    xml_texts(xml, "OutputKey")
        .into_iter()
        .zip(xml_texts(xml, "OutputValue"))
        .collect()
}

/// The `StackId` a stack reports.
fn stack_id_of(xml: &str) -> String {
    xml_text(xml, "StackId").unwrap_or_default()
}

/// One raw write to a published URL: no credential of any kind, as a pre-signed URL is
/// followed.
async fn write(
    router: &MultiServiceRouter,
    method: &str,
    url: &str,
    body: String,
) -> (u16, String) {
    let host = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default()
        .to_string();
    let request = http::Request::builder()
        .method(method)
        .uri(url)
        .header("host", host)
        .header("content-type", "application/json")
        .body(bytes::Bytes::from(body))
        .expect("a well-formed request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    (
        status,
        String::from_utf8_lossy(response.body()).to_string(),
    )
}

/// PUT one signal document to a published handle URL, which must be accepted.
async fn signal(
    router: &MultiServiceRouter,
    case: &str,
    url: &str,
    document: &Value,
) -> (u16, String) {
    let (status, body) = write(router, "PUT", url, document.to_string()).await;
    assert_eq!(
        status, 200,
        "case {case:?}: expected the signal to be accepted, got {status} with {body}"
    );
    (status, body)
}

/// Everything the rule fixes about a published handle URL, asserted of one value: it is an
/// absolute `https` URL on the endpoint this emulator is reached on, its path is the object
/// key of the S3 write target this handle stands for — the stack's own ARN and the handle's
/// logical id — and it carries the pre-signing query and the S3 endpoint that target lives at.
///
/// The key and the signature are per-run values, so the path is read back through the
/// service's own reading of it rather than compared with a spelled-out URL.
fn assert_published_url(case: &str, url: &str, region: &str, stack_id: &str, logical_id: &str) {
    assert!(
        url.starts_with("https://"),
        "case {case:?}: expected an absolute https URL, got {url:?}"
    );
    let (authority, rest) = url
        .trim_start_matches("https://")
        .split_once('/')
        .unwrap_or_default();
    assert!(
        !authority.is_empty() && !rest.is_empty(),
        "case {case:?}: expected a host and a path, got {url:?}"
    );
    let endpoint = smithy_server_runtime::UNSERVED_URL_BASE;
    assert_eq!(
        format!("https://{authority}"),
        endpoint,
        "case {case:?}: expected the URL to name the endpoint this emulator is reached on \
         ({endpoint}), got {url:?}"
    );
    let (path, query) = rest
        .split_once('?')
        .map(|(path, query)| (format!("/{path}"), query))
        .unwrap_or_else(|| (format!("/{rest}"), ""));
    let target = wait_condition_handle::parse_signal_path(&path).unwrap_or_else(|| {
        panic!("case {case:?}: expected {path:?} to name a handle of this service")
    });
    assert_eq!(
        (
            target.stack_id.as_str(),
            target.logical_resource_id.as_str()
        ),
        (stack_id, logical_id),
        "case {case:?}: expected the key to name the stack and the handle, got {path:?}"
    );
    let announced = format!(
        "{}={}",
        wait_condition_handle::S3_ENDPOINT_PARAMETER,
        wait_condition_handle::s3_endpoint(region)
    );
    assert!(
        query.contains(&announced),
        "case {case:?}: expected the query to name the S3 endpoint the target lives at \
         ({announced}), got {query:?}"
    );
    for parameter in ["X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature"] {
        assert!(
            query.contains(parameter),
            "case {case:?}: expected the pre-signing query to carry {parameter}, got {query:?}"
        );
    }
}

/// One row of the published-URL table.
struct HandleCase {
    case: &'static str,
    stack: &'static str,
    /// The Region the stack is created in, which is the one its S3 write target names.
    region: &'static str,
    /// The logical ids the template declares handles under.
    handles: &'static [&'static str],
}

/// The class the rule covers: a template declaring at least one wait condition handle,
/// however many it declares, however their logical ids are spelled and whichever Region the
/// stack is created in.
const HANDLES: &[HandleCase] = &[
    HandleCase {
        case: "one handle in the Region the suite signs for",
        stack: "wch-one",
        region: REGION,
        handles: &["Handle"],
    },
    HandleCase {
        case: "three handles, one with a logical id at the length a template may declare",
        stack: "wch-many",
        region: REGION,
        handles: &[
            "Gate",
            "Gate2",
            "AVeryLongHandleLogicalIdDeclaredByATemplate0123456789",
        ],
    },
    HandleCase {
        case: "a handle of a stack in another Region",
        stack: "wch-elsewhere",
        region: "eu-west-1",
        handles: &["Handle"],
    },
];

/// The template one row deploys: one handle per logical id, with an output publishing what
/// `Ref` resolves to for each.
fn handles_template(handles: &[&str]) -> String {
    let mut resources = serde_json::Map::new();
    let mut outputs = serde_json::Map::new();
    for handle in handles {
        resources.insert((*handle).to_string(), json!({ "Type": HANDLE_TYPE }));
        outputs.insert(
            format!("{handle}Url"),
            json!({ "Value": { "Ref": *handle } }),
        );
    }
    json!({ "Resources": resources, "Outputs": outputs }).to_string()
}

/// RULE: every reader of a handle reports the same pre-signed URL, and two handles of one
/// stack are two different targets.
#[tokio::test]
async fn a_handle_publishes_one_presigned_url_every_reader_agrees_on() {
    for row in HANDLES {
        let (router, _engine) = router_with_engine();
        let template = handles_template(row.handles);
        let (status_code, created) = create_in(&router, row.region, row.stack, &template).await;
        assert_eq!(
            status_code, 200,
            "case {:?}: expected CreateStack to be accepted, got {status_code} with {created}",
            row.case
        );
        let (status, body) = settled(&router, row.region, row.case, row.stack).await;
        assert_eq!(
            status, "CREATE_COMPLETE",
            "case {:?}: expected the stack to be created, got {status} with {body}",
            row.case
        );
        let stack_id = stack_id_of(&body);
        let outputs = outputs_of(&body);
        let described = described_ids(&router, row.region, row.stack).await;
        let listed = listed_ids(&router, row.region, row.stack).await;
        let mut published: Vec<String> = Vec::new();
        for handle in row.handles {
            let read = physical_id(&router, row.region, row.stack, handle).await;
            assert_published_url(row.case, &read, row.region, &stack_id, handle);
            for (reader, reported) in [
                ("DescribeStackResources", described.get(*handle)),
                ("ListStackResources", listed.get(*handle)),
                ("the stack output", outputs.get(&format!("{handle}Url"))),
            ] {
                assert_eq!(
                    reported,
                    Some(&read),
                    "case {:?}: expected {reader} to report the same URL for {handle:?} as \
                     DescribeStackResource ({read}), got {reported:?}",
                    row.case
                );
            }
            published.push(read);
        }
        let mut distinct = published.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            published.len(),
            "case {:?}: expected one target per handle, got {published:?}",
            row.case
        );
    }
}

/// RULE: a handle the stack did not replace keeps the URL it published — an update that adds
/// another handle publishes a second target and leaves the first exactly as it was.
#[tokio::test]
async fn an_update_leaves_an_unreplaced_handles_url_alone() {
    let case = "an update that adds a second handle";
    let (router, _engine) = router_with_engine();
    let stack = "wch-updated";
    let (status_code, created) =
        create_in(&router, REGION, stack, &handles_template(&["Handle"])).await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: expected CreateStack to be accepted, got {status_code} with {created}"
    );
    let (status, body) = settled(&router, REGION, case, stack).await;
    assert_eq!(
        status, "CREATE_COMPLETE",
        "case {case:?}: expected the stack to be created, got {status} with {body}"
    );
    let stack_id = stack_id_of(&body);
    let before = physical_id(&router, REGION, stack, "Handle").await;
    assert_published_url(case, &before, REGION, &stack_id, "Handle");

    let revised = handles_template(&["Handle", "Handle2"]);
    let (status_code, updated) = call_in(
        &router,
        REGION,
        "UpdateStack",
        &[
            member("StackName", stack),
            member("TemplateBody", &revised),
        ],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: expected UpdateStack to be accepted, got {status_code} with {updated}"
    );
    let (status, body) = settled(&router, REGION, case, stack).await;
    assert_eq!(
        status, "UPDATE_COMPLETE",
        "case {case:?}: expected the stack to be updated, got {status} with {body}"
    );
    let after = physical_id(&router, REGION, stack, "Handle").await;
    assert_eq!(
        after, before,
        "case {case:?}: expected the unreplaced handle to keep its URL ({before}), got {after}"
    );
    let second = physical_id(&router, REGION, stack, "Handle2").await;
    assert_published_url(case, &second, REGION, &stack_id, "Handle2");
    assert_ne!(
        second, before,
        "case {case:?}: expected the added handle to publish a target of its own, got {second}"
    );
}

/// One signal a row PUTs: the `UniqueId` it is keyed by and the `Data` it carries.
struct Signalled {
    unique_id: &'static str,
    data: Option<&'static str>,
}

/// One row of the signalling table.
struct SignalCase {
    case: &'static str,
    stack: &'static str,
    /// The `Count` each wait condition declares.
    count: usize,
    /// How many wait conditions the template declares on the ONE handle.
    waits: usize,
    /// The signals the row PUTs to the handle URL, in order.
    signals: &'static [Signalled],
}

/// The class the rule covers: a wait condition released by signals PUT to its handle's URL,
/// however many signals its `Count` asks for, however many wait conditions share the handle,
/// and whatever the signals carry.
const SIGNALS: &[SignalCase] = &[
    SignalCase {
        case: "one wait condition released by one signal carrying data",
        stack: "wch-signal-one",
        count: 1,
        waits: 1,
        signals: &[Signalled {
            unique_id: "1",
            data: Some("ok"),
        }],
    },
    SignalCase {
        case: "a Count of two, released by two signals under different unique ids",
        stack: "wch-signal-two",
        count: 2,
        waits: 1,
        signals: &[
            Signalled {
                unique_id: "i-0abc",
                data: Some("first"),
            },
            Signalled {
                unique_id: "i-0def",
                data: Some("second"),
            },
        ],
    },
    SignalCase {
        case: "two wait conditions on one handle, both released by the same signal",
        stack: "wch-signal-shared",
        count: 1,
        waits: 2,
        signals: &[Signalled {
            unique_id: "host-x",
            data: None,
        }],
    },
];

/// The `Timeout` every signalling row declares: generous, so nothing about the host's speed
/// decides whether the signal arrives before the wait gives up. The row's own assertions are
/// what say the wait was released by the signal.
const GENEROUS_TIMEOUT: &str = "3600";

/// The logical id of the handle, and of the `index`-th wait condition, a signalling row
/// declares.
const HANDLE: &str = "Gate";
fn wait_logical_id(index: usize) -> String {
    format!("Wait{index}")
}

/// The template one signalling row deploys: the handle, `waits` wait conditions on it each
/// waiting for `count` signals, and an output publishing what each wait condition's `Data`
/// resolves to.
fn signalled_template(count: usize, waits: usize) -> String {
    let mut resources = serde_json::Map::new();
    let mut outputs = serde_json::Map::new();
    resources.insert(HANDLE.to_string(), json!({ "Type": HANDLE_TYPE }));
    for index in 0..waits {
        let logical_id = wait_logical_id(index);
        resources.insert(
            logical_id.clone(),
            json!({
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {
                    "Handle": { "Ref": HANDLE },
                    "Timeout": GENEROUS_TIMEOUT,
                    "Count": count,
                },
            }),
        );
        outputs.insert(
            format!("{logical_id}Data"),
            json!({ "Value": { "Fn::GetAtt": [logical_id, "Data"] } }),
        );
    }
    json!({ "Resources": resources, "Outputs": outputs }).to_string()
}

/// RULE: a signal document PUT to the published handle URL is a resource signal of every wait
/// condition declared with that handle — the stack is held until the `Count` each waits for
/// has arrived, and the `Data` the signals carried is what each wait condition publishes.
#[tokio::test]
async fn a_signal_put_to_the_handle_url_releases_the_waits_declared_with_it() {
    for row in SIGNALS {
        let (router, _engine) = router_with_engine();
        let template = signalled_template(row.count, row.waits);
        let (status_code, created) = create_in(&router, REGION, row.stack, &template).await;
        assert_eq!(
            status_code, 200,
            "case {:?}: expected CreateStack to be accepted, got {status_code} with {created}",
            row.case
        );
        // The stack is HELD at the wait condition: nothing has signalled it, so it is still
        // creating even once its own clock-owed span has elapsed.
        wait_for_the_transition().await;
        let (status, body) = describe(&router, REGION, row.stack).await;
        assert_eq!(
            status, "CREATE_IN_PROGRESS",
            "case {:?}: the stack must be held until the handle is signalled, got {body}",
            row.case
        );
        let stack_id = stack_id_of(&body);
        let url = physical_id(&router, REGION, row.stack, HANDLE).await;
        assert_published_url(row.case, &url, REGION, &stack_id, HANDLE);

        let mut carried: BTreeMap<String, String> = BTreeMap::new();
        for (index, sent) in row.signals.iter().enumerate() {
            let mut document = json!({ "Status": "SUCCESS", "UniqueId": sent.unique_id });
            if let Some(data) = sent.data {
                document["Data"] = json!(data);
                carried.insert(sent.unique_id.to_string(), data.to_string());
            }
            signal(&router, row.case, &url, &document).await;
            if index + 1 < row.count {
                // Short of the `Count` it waits for: the wait holds.
                wait_for_the_transition().await;
                let (status, body) = describe(&router, REGION, row.stack).await;
                assert_eq!(
                    status, "CREATE_IN_PROGRESS",
                    "case {:?}: expected the stack to be held while the wait is short of its \
                     Count, got {body}",
                    row.case
                );
            }
        }

        let (status, body) = settled(&router, REGION, row.case, row.stack).await;
        assert_eq!(
            status, "CREATE_COMPLETE",
            "case {:?}: expected the signals to release the wait, got {status} with {body}",
            row.case
        );
        let outputs = outputs_of(&body);
        for index in 0..row.waits {
            let logical_id = wait_logical_id(index);
            let key = format!("{logical_id}Data");
            let published = outputs.get(&key).cloned().unwrap_or_default();
            if carried.is_empty() {
                assert!(
                    published.is_empty(),
                    "case {:?}: expected {key} to publish nothing for signals carrying no \
                     Data, got {published:?}",
                    row.case
                );
                continue;
            }
            let read: BTreeMap<String, String> = ::serde_json::from_str(&published)
                .unwrap_or_else(|error| {
                    panic!(
                        "case {:?}: expected {key} to publish the signals' data as a JSON \
                         object, got {published:?} ({error})",
                        row.case
                    )
                });
            assert_eq!(
                read, carried,
                "case {:?}: expected {key} to publish every signal's data, got {read:?}",
                row.case
            );
        }
    }
}

/// RULE: the published URL describes ONE write — a `PUT` of a signal document presenting the
/// signature this service published — and anything else on that address is refused rather
/// than served.
#[tokio::test]
async fn a_write_the_published_url_does_not_describe_is_refused() {
    let (router, _engine) = router_with_engine();
    let stack = "wch-refusals";
    let case = "the published target of one handle";
    let (status_code, created) =
        create_in(&router, REGION, stack, &handles_template(&["Handle"])).await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: expected CreateStack to be accepted, got {status_code} with {created}"
    );
    let (status, body) = settled(&router, REGION, case, stack).await;
    assert_eq!(
        status, "CREATE_COMPLETE",
        "case {case:?}: expected the stack to be created, got {status} with {body}"
    );
    let url = physical_id(&router, REGION, stack, "Handle").await;
    assert_published_url(case, &url, REGION, &stack_id_of(&body), "Handle");
    // A signature this service did not publish: the last character of the one it did,
    // changed — which is a target a caller assembled rather than the one it was handed.
    let tampered = {
        let mut tampered = url.clone();
        let last = tampered.pop().expect("a signed URL is not empty");
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        tampered
    };
    let rows: &[(&str, &str, String, String, u16)] = &[
        (
            "a read of the write target",
            "GET",
            url.clone(),
            String::new(),
            405,
        ),
        (
            "a delete of the write target",
            "DELETE",
            url.clone(),
            String::new(),
            405,
        ),
        (
            "a body that is not a JSON document",
            "PUT",
            url.clone(),
            "not a document".to_string(),
            400,
        ),
        (
            "a document stating no signal status",
            "PUT",
            url.clone(),
            json!({ "UniqueId": "1" }).to_string(),
            400,
        ),
        (
            "a document stating a status no resource signal has",
            "PUT",
            url.clone(),
            json!({ "Status": "MAYBE", "UniqueId": "1" }).to_string(),
            400,
        ),
        (
            "a document stating no unique id",
            "PUT",
            url.clone(),
            json!({ "Status": "SUCCESS" }).to_string(),
            400,
        ),
        (
            "a document longer than one a signal may carry",
            "PUT",
            url.clone(),
            json!({
                "Status": "SUCCESS",
                "UniqueId": "1",
                "Data": "x".repeat(wait_condition_handle::MAX_SIGNAL_DOCUMENT_BYTES),
            })
            .to_string(),
            400,
        ),
        (
            "a write presenting a signature this service did not publish",
            "PUT",
            tampered,
            json!({ "Status": "SUCCESS", "UniqueId": "1" }).to_string(),
            403,
        ),
    ];
    for (case, method, target, body, expected) in rows {
        let (status, answered) = write(&router, method, target, body.clone()).await;
        assert_eq!(
            status, *expected,
            "case {case:?}: expected HTTP {expected}, got {status} with {answered}"
        );
    }
}
