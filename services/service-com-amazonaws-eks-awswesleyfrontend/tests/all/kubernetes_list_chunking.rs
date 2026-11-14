// SPDX-License-Identifier: CC0-1.0

//! How a collection of the Kubernetes API a cluster publishes answers a LIST.
//!
//! The RULE under test: a list is answered in CHUNKS. A client asks for a chunk
//! size with `limit` ("the maximum number of responses to return for a list
//! call"), the server may send fewer, and a list the server did not finish
//! carries a `continue` token in its `metadata` beside the `remainingItemCount`
//! of what it has not sent — so a client that walks the token sees every object
//! of the collection exactly once, in the order the collection is held, while no
//! single answer has to carry a whole namespace.
//!
//! The suites drive that over a TABLE whose rows differ along what the rule
//! generalises over: the COLLECTION (pods, ConfigMaps, service accounts and the
//! cluster's namespaces, which differ in what one item costs and in whether the
//! cluster came with items of its own), and the chunk size asked for (one item,
//! several, exactly the collection, more than it holds, and none at all).
//!
//! The client is the raw one the Kubernetes API suite uses
//! ([`crate::kubernetes_api::dial`]): a TCP connection to the published port, TLS
//! whose only trust anchor is the published certificate authority, and an HTTP/1.1
//! request written by hand.

use serde_json::json;

use crate::kubernetes_api::{dial, Kubeconfig};
use crate::kubernetes_pod_and_config_map_objects::provisioned;
use crate::wire::emulator;

/// The namespace every collection of this suite is seeded in.
const NAMESPACE: &str = "chunked";

/// How many objects each seeded collection holds. Small on purpose: the rule is
/// about the chunk boundary, and a bigger collection only makes the suite slower.
const SEEDED: usize = 5;

/// One collection under test: where it lives and how an object is created in it.
struct Collection {
    /// What this row varies, named in every assertion it drives.
    label: &'static str,
    /// The path the collection is addressed at.
    path: String,
    /// The `kind` of the list document it answers.
    list_kind: &'static str,
    /// The names this suite created in it.
    created: Vec<String>,
}

/// Seed `NAMESPACE` and one collection of each kind inside it, plus the
/// cluster's own namespace collection, and answer them.
async fn seeded(config: &Kubeconfig) -> Vec<Collection> {
    let created = dial(
        config,
        "the suite's namespace",
        "POST",
        "/api/v1/namespaces",
        Some(&json!({ "metadata": { "name": NAMESPACE } })),
    )
    .await;
    assert_eq!(
        created.status, 201,
        "the suite's namespace must be created, got {created:?}"
    );

    let mut collections = Vec::new();

    // Pods are the heaviest item: each carries the whole spec its create
    // submitted.
    let mut pods = Vec::new();
    for index in 0..SEEDED {
        let name = format!("chunk-pod-{index}");
        let answered = dial(
            config,
            "pods",
            "POST",
            &format!("/api/v1/namespaces/{NAMESPACE}/pods"),
            Some(&json!({
                "metadata": { "name": name },
                "spec": {
                    "containers": [{
                        "name": "app",
                        "image": format!("public.ecr.aws/app:{index}"),
                    }],
                },
            })),
        )
        .await;
        assert_eq!(
            answered.status, 201,
            "pod {name:?} must be created, got {answered:?}"
        );
        pods.push(name);
    }
    collections.push(Collection {
        label: "the namespace's pods",
        path: format!("/api/v1/namespaces/{NAMESPACE}/pods"),
        list_kind: "PodList",
        created: pods,
    });

    let mut config_maps = Vec::new();
    for index in 0..SEEDED {
        let name = format!("chunk-settings-{index}");
        let answered = dial(
            config,
            "configmaps",
            "POST",
            &format!("/api/v1/namespaces/{NAMESPACE}/configmaps"),
            Some(&json!({
                "metadata": { "name": name },
                "data": { "index": index.to_string() },
            })),
        )
        .await;
        assert_eq!(
            answered.status, 201,
            "ConfigMap {name:?} must be created, got {answered:?}"
        );
        config_maps.push(name);
    }
    collections.push(Collection {
        label: "the namespace's ConfigMaps",
        path: format!("/api/v1/namespaces/{NAMESPACE}/configmaps"),
        list_kind: "ConfigMapList",
        created: config_maps,
    });

    // The namespace came with the `default` service account Kubernetes creates in
    // every namespace, so this collection holds one item the suite did not
    // create.
    let mut accounts = vec!["default".to_string()];
    for index in 0..SEEDED {
        let name = format!("chunk-account-{index}");
        let answered = dial(
            config,
            "serviceaccounts",
            "POST",
            &format!("/api/v1/namespaces/{NAMESPACE}/serviceaccounts"),
            Some(&json!({ "metadata": { "name": name } })),
        )
        .await;
        assert_eq!(
            answered.status, 201,
            "service account {name:?} must be created, got {answered:?}"
        );
        accounts.push(name);
    }
    collections.push(Collection {
        label: "the namespace's service accounts",
        path: format!("/api/v1/namespaces/{NAMESPACE}/serviceaccounts"),
        list_kind: "ServiceAccountList",
        created: accounts,
    });

    // The cluster's namespaces: the four Kubernetes creates with a cluster, plus
    // the one this suite created.
    collections.push(Collection {
        label: "the cluster's namespaces",
        path: "/api/v1/namespaces".to_string(),
        list_kind: "NamespaceList",
        created: vec![
            NAMESPACE.to_string(),
            "default".to_string(),
            "kube-node-lease".to_string(),
            "kube-public".to_string(),
            "kube-system".to_string(),
        ],
    });

    collections
}

/// The `metadata.name` of every item of one list answer, in the order it carried
/// them.
fn item_names(label: &str, body: &serde_json::Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap_or_else(|| panic!("case {label:?}: a list answer carries items, got {body}"))
        .iter()
        .map(|item| {
            item["metadata"]["name"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!("case {label:?}: every listed object is named, got {item}")
                })
                .to_string()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// RULE: walking the `continue` token a chunked list hands back visits every
// object of the collection exactly once, in the collection's own order, for any
// chunk size the client asks for.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn walking_the_continue_token_visits_every_object_once() {
    let router = emulator();
    let config = provisioned(&router, "k8s-list-chunking").await;
    let collections = seeded(&config).await;

    for collection in &collections {
        let mut expected = collection.created.clone();
        expected.sort();

        // The rows span the chunk sizes: one item at a time, a few, exactly the
        // collection, more than it holds, and none asked for at all.
        for limit in [Some(1), Some(2), Some(expected.len()), Some(expected.len() + 3), None] {
            let label = format!("{} with limit {limit:?}", collection.label);
            let mut walked: Vec<String> = Vec::new();
            let mut token: Option<String> = None;
            // One read per item at worst, plus the read that reports the end.
            let mut reads = 0usize;
            loop {
                let mut query: Vec<String> = Vec::new();
                if let Some(limit) = limit {
                    query.push(format!("limit={limit}"));
                }
                if let Some(token) = token.as_deref() {
                    query.push(format!("continue={token}"));
                }
                let path = if query.is_empty() {
                    collection.path.clone()
                } else {
                    format!("{}?{}", collection.path, query.join("&"))
                };
                let answered = dial(&config, &label, "GET", &path, None).await;
                assert_eq!(
                    answered.status, 200,
                    "case {label:?}: a list is answered 200, got {answered:?}"
                );
                assert_eq!(
                    answered.body["kind"],
                    json!(collection.list_kind),
                    "case {label:?}: expected a {}, got {:?}",
                    collection.list_kind,
                    answered.body["kind"]
                );
                let names = item_names(&label, &answered.body);
                if let Some(limit) = limit {
                    assert!(
                        names.len() <= limit,
                        "case {label:?}: an answer carries at most the {limit} items asked for, \
                         got {names:?}"
                    );
                }
                let next = answered.body["metadata"]["continue"]
                    .as_str()
                    .map(str::to_string);
                let remaining = answered.body["metadata"]["remainingItemCount"].as_u64();
                match next.as_deref() {
                    Some(next) => {
                        assert_eq!(
                            Some(next.to_string()),
                            names.last().cloned(),
                            "case {label:?}: the token resumes after the last item sent, got {:?}",
                            answered.body["metadata"]
                        );
                        let sent = walked.len() + names.len();
                        assert_eq!(
                            remaining,
                            Some((expected.len() - sent) as u64),
                            "case {label:?}: an unfinished list reports what it has not sent, \
                             got {:?} after {sent} of {}",
                            answered.body["metadata"],
                            expected.len()
                        );
                    }
                    None => assert!(
                        remaining.is_none(),
                        "case {label:?}: a finished list reports nothing remaining, got {:?}",
                        answered.body["metadata"]
                    ),
                }
                walked.extend(names);
                token = next;
                reads += 1;
                assert!(
                    reads <= expected.len() + 2,
                    "case {label:?}: the walk must end within {} reads, got {walked:?}",
                    expected.len() + 2
                );
                if token.is_none() {
                    break;
                }
            }
            assert_eq!(
                walked, expected,
                "case {label:?}: the walk must visit every object of the collection exactly \
                 once, in order"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// RULE: a `limit` that is not a number is no chunk size, so the request is
// refused rather than served as if it had asked for none.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_limit_that_is_not_a_number_is_refused() {
    let router = emulator();
    let config = provisioned(&router, "k8s-list-bad-limit").await;

    // The rows span the ways the parameter fails to name a count.
    for (label, value) in [
        ("a word", "abc"),
        ("a negative count", "-1"),
        ("a fraction", "1.5"),
    ] {
        let answered = dial(
            &config,
            label,
            "GET",
            &format!("/api/v1/namespaces/default/pods?limit={value}"),
            None,
        )
        .await;
        assert_eq!(
            answered.status, 400,
            "case {label:?}: a limit that is no count is refused, got {answered:?}"
        );
        assert_eq!(
            answered.body["reason"],
            json!("BadRequest"),
            "case {label:?}: expected the Kubernetes bad-request Status, got {:?}",
            answered.body
        );
    }

    // A `limit` of zero, and one carrying no value at all, are the parameter's
    // own unset value: they ask for no chunk size rather than for nothing.
    for (label, parameter) in [("a limit of zero", "limit=0"), ("a limit with no value", "limit=")]
    {
        let unlimited = dial(
            &config,
            label,
            "GET",
            &format!("/api/v1/namespaces/default/serviceaccounts?{parameter}"),
            None,
        )
        .await;
        assert_eq!(
            unlimited.status, 200,
            "case {label:?}: an unset limit asks for no chunk size, got {unlimited:?}"
        );
        assert_eq!(
            item_names(label, &unlimited.body),
            vec!["default".to_string()],
            "case {label:?}: the whole collection is answered, got {:?}",
            unlimited.body
        );
    }
}
