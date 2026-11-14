// SPDX-License-Identifier: CC0-1.0

//! The OBJECTS a client creates through the address a cluster publishes for its
//! Kubernetes API server: the Pod it submits a workload as, and the ConfigMap it
//! delivers configuration through.
//!
//! The RULE under test: the object the served API answers a create with is the
//! object it STORED — every member the manifest carried, with only the members
//! the API server defaults filled in — and every core/v1 collection it serves
//! serves the create verb, not only the reads. `Cluster$endpoint` is "the
//! endpoint for your Kubernetes API server", so the documented thing to do with
//! it is to talk Kubernetes there: a Pod a client creates to run an image must
//! read back carrying the container list that names that image (the Kubernetes
//! API requires `PodSpec.containers`, "there must be at least one container in a
//! Pod"), and a ConfigMap a client creates must be stored rather than refused
//! with the `405` that tells a client the verb will never work — the shape
//! Amazon EKS's own Fargate log routing is delivered in.
//!
//! Each suite drives the rule over a TABLE whose rows differ along what it
//! generalises over: how many containers a pod declares, the FORM of the image
//! reference (an explicit tag, no tag at all, `:latest`, a digest, a registry
//! host carrying a port), whether the client set a member the server would
//! otherwise default, which other spec members the manifest carried, the
//! namespace the object was created in, and which of a ConfigMap's two value maps
//! it was created with.
//!
//! The client is the raw one the Kubernetes API suite uses
//! ([`crate::kubernetes_api::dial`]): a TCP connection to the published port, TLS
//! whose only trust anchor is the published certificate authority, and an HTTP/1.1
//! request written by hand.

use serde_json::json;
use smithy_server_runtime::MultiServiceRouter;

use crate::certificate_authority::{create_cluster, REGION};
use crate::kubernetes_api::{dial, kubeconfig_of, poll_until_active, Kubeconfig};
use crate::wire::emulator;

/// Create the cluster `name` and wait for the clock-owed provisioning to be
/// materialised, then read the kubeconfig members a client talks to it with.
///
/// `pub(crate)` so the suite over the LIST contract of the same collections
/// ([`crate::kubernetes_list_chunking`]) reaches a cluster the same way.
pub(crate) async fn provisioned(router: &MultiServiceRouter, name: &str) -> Kubeconfig {
    let created = create_cluster(router, REGION, name).await;
    assert_eq!(
        created.status, 200,
        "cluster {name:?}: expected 200 from CreateCluster, got {created:?}"
    );
    let described = poll_until_active(router, REGION, name).await;
    kubeconfig_of(name, &described)
}

/// The `metadata.name` member of every object document, as a client reads it.
fn name_of(document: &serde_json::Value) -> &serde_json::Value {
    &document["metadata"]["name"]
}

// ---------------------------------------------------------------------------
// RULE: a Pod reads back with the spec it was created with — the containers that
// name its images, verbatim, and every member beside them.
// ---------------------------------------------------------------------------

/// One row of the pod table: the containers the manifest declares.
struct PodCase {
    label: &'static str,
    pod: &'static str,
    /// The containers as the manifest carries them, which is how they must read
    /// back.
    containers: Vec<serde_json::Value>,
}

#[tokio::test]
async fn a_pod_reads_back_with_the_spec_it_was_created_with() {
    let router = emulator();
    let config = provisioned(&router, "k8s-pod-spec").await;

    // The rows differ along what the rule generalises over: how many containers
    // the pod declares, the FORM of the image reference each names (an explicit
    // tag, no tag, `:latest`, a digest, a registry host carrying a port), and
    // which other members the container carries — a pull policy the client chose
    // and an environment it set among them.
    let cases = vec![
        PodCase {
            label: "a private registry image at an explicit tag",
            pod: "pod-explicit-tag",
            containers: vec![json!({
                "name": "app",
                "image": "000000000000.dkr.ecr.us-west-2.amazonaws.com/app:1.4",
                "env": [{ "name": "AWS_REGION", "value": REGION }],
            })],
        },
        PodCase {
            label: "an image reference carrying no tag",
            pod: "pod-no-tag",
            containers: vec![
                json!({ "name": "app", "image": "public.ecr.aws/docker/library/nginx" }),
            ],
        },
        PodCase {
            label: "the :latest tag",
            pod: "pod-latest",
            containers: vec![
                json!({ "name": "app", "image": "public.ecr.aws/docker/library/nginx:latest" }),
            ],
        },
        PodCase {
            label: "a digest reference",
            pod: "pod-digest",
            containers: vec![json!({
                "name": "app",
                "image": "public.ecr.aws/docker/library/nginx@sha256:\
                          0000000000000000000000000000000000000000000000000000000000000001",
            })],
        },
        PodCase {
            label: "a registry host carrying a port and no tag",
            pod: "pod-registry-port",
            containers: vec![json!({ "name": "app", "image": "registry.internal:5000/app" })],
        },
        PodCase {
            label: "a registry host carrying a port and a tag",
            pod: "pod-registry-port-tag",
            containers: vec![json!({ "name": "app", "image": "registry.internal:5000/app:2" })],
        },
        PodCase {
            label: "a pull policy the client chose itself",
            pod: "pod-client-policy",
            containers: vec![json!({
                "name": "app",
                "image": "public.ecr.aws/docker/library/nginx:latest",
                "imagePullPolicy": "Never",
            })],
        },
        PodCase {
            label: "two containers beside each other",
            pod: "pod-two-containers",
            containers: vec![
                json!({ "name": "app", "image": "public.ecr.aws/docker/library/nginx:1.27" }),
                json!({ "name": "sidecar", "image": "public.ecr.aws/aws-cli/aws-cli" }),
            ],
        },
    ];

    for case in &cases {
        let label = case.label;
        let manifest = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": case.pod,
                "labels": { "app": case.pod },
                "annotations": { "owner": "integration-test" },
            },
            "spec": {
                "containers": case.containers,
                "imagePullSecrets": [{ "name": "registry-credentials" }],
            },
        });
        let created = dial(
            &config,
            label,
            "POST",
            "/api/v1/namespaces/default/pods",
            Some(&manifest),
        )
        .await;
        assert_eq!(
            created.status, 201,
            "case {label:?}: expected the pod to be created, got {created:?}"
        );
        assert_eq!(
            created.body["kind"],
            json!("Pod"),
            "case {label:?}: expected a Pod object, got {:?}",
            created.body
        );
        assert_eq!(
            name_of(&created.body),
            &json!(case.pod),
            "case {label:?}: expected the pod the manifest named, got {:?}",
            created.body
        );

        // The container list is the submitted one, in order and unchanged.
        let containers = created.body["spec"]["containers"]
            .as_array()
            .unwrap_or_else(|| {
                panic!(
                    "case {label:?}: a Pod carries its container list, got {:?}",
                    created.body["spec"]
                )
            });
        assert_eq!(
            containers.len(),
            case.containers.len(),
            "case {label:?}: expected {} container(s), got {containers:?}",
            case.containers.len()
        );
        for (index, submitted) in case.containers.iter().enumerate() {
            assert_eq!(
                &containers[index], submitted,
                "case {label:?}: container {index} must read back as it was declared, got {:?}",
                containers[index]
            );
        }

        // Nothing else the manifest carried is dropped, and the members the API
        // server resolves itself are there.
        assert_eq!(
            created.body["spec"]["imagePullSecrets"],
            json!([{ "name": "registry-credentials" }]),
            "case {label:?}: the pull secrets the manifest carried must read back, got {:?}",
            created.body["spec"]
        );
        for member in ["serviceAccountName", "serviceAccount"] {
            assert_eq!(
                created.body["spec"][member],
                json!("default"),
                "case {label:?}: a pod naming no account runs as the namespace's default \
                 account, got {:?}",
                created.body["spec"]
            );
        }
        assert_eq!(
            created.body["metadata"]["labels"],
            json!({ "app": case.pod }),
            "case {label:?}: the labels the manifest carried must read back, got {:?}",
            created.body["metadata"]
        );
        assert_eq!(
            created.body["metadata"]["annotations"],
            json!({ "owner": "integration-test" }),
            "case {label:?}: the annotations the manifest carried must read back, got {:?}",
            created.body["metadata"]
        );

        // Every container of the pod reports a status a typed client can read:
        // its name, the image it declared, the image id (empty until something
        // pulls one), whether it is ready and started, its restart count and the
        // state it is in.
        let statuses = created.body["status"]["containerStatuses"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            statuses.len(),
            case.containers.len(),
            "case {label:?}: every container reports a status, got {:?}",
            created.body["status"]
        );
        for (index, status) in statuses.iter().enumerate() {
            for member in ["name", "image", "imageID", "ready", "restartCount", "state"] {
                assert!(
                    !status[member].is_null(),
                    "case {label:?}: container status {index} must report {member}, got \
                     {status:?}"
                );
            }
        }

        // ROUND TRIP: the read answers the spec the create answered.
        let read_back = dial(
            &config,
            label,
            "GET",
            &format!("/api/v1/namespaces/default/pods/{}", case.pod),
            None,
        )
        .await;
        assert_eq!(
            read_back.status, 200,
            "case {label:?}: the pod reads back at the published address, got {read_back:?}"
        );
        assert_eq!(
            read_back.body["spec"], created.body["spec"],
            "case {label:?}: the pod must read back with the spec the create reported, got {:?} \
             after {:?}",
            read_back.body["spec"], created.body["spec"]
        );
        assert_eq!(
            read_back.body["metadata"], created.body["metadata"],
            "case {label:?}: the pod must read back with the metadata the create reported, got \
             {:?} after {:?}",
            read_back.body["metadata"], created.body["metadata"]
        );
    }

    // Every pod the client created is in the listing, carrying its containers
    // there too.
    let listed = dial(
        &config,
        "the namespace's pods",
        "GET",
        "/api/v1/namespaces/default/pods",
        None,
    )
    .await;
    assert_eq!(
        listed.status, 200,
        "the published address lists the namespace's pods, got {listed:?}"
    );
    let items = listed.body["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for case in &cases {
        let listed_pod = items
            .iter()
            .find(|item| name_of(item) == &json!(case.pod))
            .unwrap_or_else(|| {
                panic!(
                    "case {:?}: expected {:?} among the pods the address lists, got {items:?}",
                    case.label, case.pod
                )
            });
        assert_eq!(
            listed_pod["spec"]["containers"]
                .as_array()
                .map(Vec::len)
                .unwrap_or_default(),
            case.containers.len(),
            "case {:?}: the listed pod carries its containers, got {listed_pod:?}",
            case.label
        );
    }
}

// ---------------------------------------------------------------------------
// RULE: `PodSpec.containers` is required and non-empty, and every container in
// it names a container and an image — a manifest that breaks that is refused and
// stores nothing.
// ---------------------------------------------------------------------------

/// One row of the refused-manifest table: the Pod manifest and the member the
/// validation `Status` is to name.
struct InvalidPodCase {
    label: &'static str,
    pod: &'static str,
    manifest: serde_json::Value,
    member: &'static str,
}

#[tokio::test]
async fn a_pod_manifest_with_no_workload_is_refused() {
    let router = emulator();
    let config = provisioned(&router, "k8s-pod-validation").await;

    // The rows differ along HOW the container list fails to name a workload: it
    // is missing with the spec, missing inside it, present but empty, or an entry
    // of it names no container or no image, or names one twice.
    let cases = [
        InvalidPodCase {
            label: "a manifest with no spec at all",
            pod: "invalid-no-spec",
            manifest: json!({ "metadata": { "name": "invalid-no-spec" } }),
            member: "spec.containers",
        },
        InvalidPodCase {
            label: "a spec naming no containers",
            pod: "invalid-no-containers",
            manifest: json!({
                "metadata": { "name": "invalid-no-containers" },
                "spec": { "serviceAccountName": "default" },
            }),
            member: "spec.containers",
        },
        InvalidPodCase {
            label: "an empty container list",
            pod: "invalid-empty-containers",
            manifest: json!({
                "metadata": { "name": "invalid-empty-containers" },
                "spec": { "containers": [] },
            }),
            member: "spec.containers",
        },
        InvalidPodCase {
            label: "a container with no name",
            pod: "invalid-unnamed-container",
            manifest: json!({
                "metadata": { "name": "invalid-unnamed-container" },
                "spec": { "containers": [{ "image": "public.ecr.aws/app:1" }] },
            }),
            member: "spec.containers[0].name",
        },
        InvalidPodCase {
            label: "a container with no image",
            pod: "invalid-imageless-container",
            manifest: json!({
                "metadata": { "name": "invalid-imageless-container" },
                "spec": { "containers": [{ "name": "app" }] },
            }),
            member: "spec.containers[0].image",
        },
        InvalidPodCase {
            label: "one container named twice",
            pod: "invalid-duplicate-container",
            manifest: json!({
                "metadata": { "name": "invalid-duplicate-container" },
                "spec": {
                    "containers": [
                        { "name": "app", "image": "public.ecr.aws/app:1" },
                        { "name": "app", "image": "public.ecr.aws/app:2" },
                    ],
                },
            }),
            member: "spec.containers[1].name",
        },
    ];

    for case in &cases {
        let label = case.label;
        let refused = dial(
            &config,
            label,
            "POST",
            "/api/v1/namespaces/default/pods",
            Some(&case.manifest),
        )
        .await;
        assert_eq!(
            refused.status, 422,
            "case {label:?}: a pod with no workload is refused, got {refused:?}"
        );
        assert_eq!(
            refused.body["reason"],
            json!("Invalid"),
            "case {label:?}: expected the Kubernetes validation Status, got {:?}",
            refused.body
        );
        let message = refused.body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(case.member),
            "case {label:?}: the refusal names the member that is invalid ({:?}), got {message:?}",
            case.member
        );
        assert!(
            message.contains(case.pod),
            "case {label:?}: the refusal names the pod it refused ({:?}), got {message:?}",
            case.pod
        );

        // A refused create stores nothing: the pod it named does not exist.
        let read_back = dial(
            &config,
            label,
            "GET",
            &format!("/api/v1/namespaces/default/pods/{}", case.pod),
            None,
        )
        .await;
        assert_eq!(
            read_back.status, 404,
            "case {label:?}: a refused create must store no pod, got {read_back:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// RULE: the ConfigMap collection serves the create — the object a client POSTs
// is stored and reads back — and a second create of one name is the conflict it
// is.
// ---------------------------------------------------------------------------

/// One row of the ConfigMap table: the namespace it is created in, whether the
/// client has to create that namespace first, and the value maps it carries.
struct ConfigMapCase {
    label: &'static str,
    namespace: &'static str,
    /// `true` for a namespace Kubernetes does NOT create with the cluster, which
    /// the client therefore creates itself — the shape Amazon EKS's Fargate log
    /// routing takes (`aws-observability`).
    create_namespace: bool,
    name: &'static str,
    manifest: serde_json::Value,
}

#[tokio::test]
async fn a_config_map_is_created_and_reads_back() {
    let router = emulator();
    let config = provisioned(&router, "k8s-config-maps").await;

    // The rows differ along what the rule generalises over: the namespace (one
    // Kubernetes created with the cluster, one the client created), which of the
    // two value maps the object carries, how many keys it holds, and whether it
    // carries labels of its own.
    let cases = [
        ConfigMapCase {
            label: "the Fargate logging ConfigMap in a namespace the client created",
            namespace: "aws-observability",
            create_namespace: true,
            name: "aws-logging",
            manifest: json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "aws-logging",
                    "namespace": "aws-observability",
                    "labels": { "managed-by": "integration-test" },
                },
                "data": {
                    "flb_log_cw": "true",
                    "output.conf": "[OUTPUT]\n    Name cloudwatch_logs\n    Match   *\n",
                },
            }),
        },
        ConfigMapCase {
            label: "a ConfigMap with one key in a namespace of the cluster",
            namespace: "default",
            create_namespace: false,
            name: "application-settings",
            manifest: json!({
                "metadata": { "name": "application-settings" },
                "data": { "log-level": "debug" },
            }),
        },
        ConfigMapCase {
            label: "a ConfigMap carrying binary values",
            namespace: "default",
            create_namespace: false,
            name: "binary-settings",
            manifest: json!({
                "metadata": { "name": "binary-settings" },
                "data": { "mode": "strict" },
                "binaryData": { "seed.bin": "AAECAwQ=" },
            }),
        },
        ConfigMapCase {
            label: "a ConfigMap with no values at all",
            namespace: "kube-system",
            create_namespace: false,
            name: "empty-settings",
            manifest: json!({ "metadata": { "name": "empty-settings" } }),
        },
    ];

    for case in &cases {
        let label = case.label;
        if case.create_namespace {
            let created = dial(
                &config,
                label,
                "POST",
                "/api/v1/namespaces",
                Some(&json!({ "metadata": { "name": case.namespace } })),
            )
            .await;
            assert_eq!(
                created.status, 201,
                "case {label:?}: expected the namespace to be created, got {created:?}"
            );
        }
        let collection = format!("/api/v1/namespaces/{}/configmaps", case.namespace);
        let created = dial(&config, label, "POST", &collection, Some(&case.manifest)).await;
        assert_eq!(
            created.status, 201,
            "case {label:?}: the ConfigMap collection must serve the create, got {created:?}"
        );
        assert_eq!(
            created.body["kind"],
            json!("ConfigMap"),
            "case {label:?}: expected a ConfigMap object, got {:?}",
            created.body
        );
        assert_eq!(
            name_of(&created.body),
            &json!(case.name),
            "case {label:?}: expected the ConfigMap the manifest named, got {:?}",
            created.body
        );
        assert_eq!(
            created.body["metadata"]["namespace"],
            json!(case.namespace),
            "case {label:?}: the object is created in the namespace it was addressed in, got {:?}",
            created.body
        );
        assert!(
            created.body["metadata"]["uid"]
                .as_str()
                .is_some_and(|uid| !uid.is_empty()),
            "case {label:?}: a created object carries the uid the server minted, got {:?}",
            created.body
        );
        for member in ["data", "binaryData", "metadata"] {
            let submitted = &case.manifest[member];
            if member == "metadata" {
                // Only the labels of the metadata are the client's; the rest is
                // the server's own.
                let labels = &submitted["labels"];
                if !labels.is_null() {
                    assert_eq!(
                        created.body["metadata"]["labels"], *labels,
                        "case {label:?}: the labels the manifest carried must read back, got {:?}",
                        created.body["metadata"]
                    );
                }
                continue;
            }
            assert_eq!(
                created.body[member], *submitted,
                "case {label:?}: the {member} the manifest carried must read back, got {:?}",
                created.body
            );
        }

        // ROUND TRIP: it reads back as the object the create reported.
        let path = format!("{collection}/{}", case.name);
        let read_back = dial(&config, label, "GET", &path, None).await;
        assert_eq!(
            read_back.status, 200,
            "case {label:?}: the ConfigMap reads back at the published address, got {read_back:?}"
        );
        assert_eq!(
            read_back.body, created.body,
            "case {label:?}: the ConfigMap must read back as the object the create reported, got \
             {:?} after {:?}",
            read_back.body, created.body
        );

        // A second create of one name addresses an object that now exists.
        let replayed = dial(&config, label, "POST", &collection, Some(&case.manifest)).await;
        assert_eq!(
            replayed.status, 409,
            "case {label:?}: a second create of one ConfigMap is a conflict, got {replayed:?}"
        );
        assert_eq!(
            replayed.body["reason"],
            json!("AlreadyExists"),
            "case {label:?}: the conflict states that the ConfigMap already exists, got {:?}",
            replayed.body
        );

        // And it is in the listing that namespace serves.
        let listed = dial(&config, label, "GET", &collection, None).await;
        assert_eq!(
            listed.status, 200,
            "case {label:?}: the namespace lists its ConfigMaps, got {listed:?}"
        );
        assert_eq!(
            listed.body["kind"],
            json!("ConfigMapList"),
            "case {label:?}: expected a ConfigMapList, got {:?}",
            listed.body
        );
        let names: Vec<String> = listed.body["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| name_of(item).as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            names.iter().any(|name| name == case.name),
            "case {label:?}: expected {:?} among the ConfigMaps the namespace lists, got {names:?}",
            case.name
        );
    }
}

// ---------------------------------------------------------------------------
// RULE: a ConfigMap create the API server cannot serve is refused as the thing
// it is — an unknown namespace, a value that is no ConfigMap value, or more data
// than a ConfigMap holds — and stores nothing.
// ---------------------------------------------------------------------------

/// The most bytes one ConfigMap holds, as the Kubernetes ConfigMap documentation
/// publishes it: "the data stored in a ConfigMap cannot exceed 1 MiB".
const MAX_CONFIG_MAP_BYTES: usize = 1024 * 1024;

#[tokio::test]
async fn a_config_map_create_the_server_cannot_serve_is_refused() {
    let router = emulator();
    let config = provisioned(&router, "k8s-config-map-refusals").await;

    // A namespace the cluster does not hold holds no objects either.
    let absent = dial(
        &config,
        "a namespace the cluster does not hold",
        "POST",
        "/api/v1/namespaces/no-such-namespace/configmaps",
        Some(&json!({ "metadata": { "name": "settings" }, "data": { "a": "b" } })),
    )
    .await;
    assert_eq!(
        absent.status, 404,
        "a ConfigMap cannot be created in a namespace that does not exist, got {absent:?}"
    );
    assert_eq!(
        absent.body["reason"],
        json!("NotFound"),
        "expected the Kubernetes not-found Status, got {:?}",
        absent.body
    );

    // `data` is a string-to-string map, so a value that is not a string is no
    // ConfigMap value.
    let mistyped = dial(
        &config,
        "a data value that is not a string",
        "POST",
        "/api/v1/namespaces/default/configmaps",
        Some(&json!({ "metadata": { "name": "mistyped" }, "data": { "retries": 3 } })),
    )
    .await;
    assert_eq!(
        mistyped.status, 422,
        "a value no ConfigMap can hold is refused, got {mistyped:?}"
    );
    assert_eq!(
        mistyped.body["reason"],
        json!("Invalid"),
        "expected the Kubernetes validation Status, got {:?}",
        mistyped.body
    );

    // The published ceiling: the largest object that fits is served, and one byte
    // past it is refused.
    for (label, name, total_bytes, expected) in [
        (
            "the largest ConfigMap that fits",
            "fits",
            MAX_CONFIG_MAP_BYTES,
            201,
        ),
        (
            "one byte past the ceiling",
            "oversize",
            MAX_CONFIG_MAP_BYTES + 1,
            422,
        ),
    ] {
        // One key, whose own bytes count towards the ceiling with its value's.
        let mut data = serde_json::Map::new();
        data.insert(
            name.to_string(),
            json!("x".repeat(total_bytes - name.len())),
        );
        let manifest = json!({ "metadata": { "name": name }, "data": data });
        let answered = dial(
            &config,
            label,
            "POST",
            "/api/v1/namespaces/default/configmaps",
            Some(&manifest),
        )
        .await;
        assert_eq!(
            answered.status, expected,
            "case {label:?}: expected HTTP {expected}, got {}: {:?}",
            answered.status, answered.body
        );
    }
}

// ---------------------------------------------------------------------------
// RULE: `binaryData` carries base64 ("the binary data ... must be a
// base64-encoded string"), so what a value stores — and what counts towards the
// 1 MiB ceiling — is the bytes it DECODES to, and a value that is not base64 at
// all stores nothing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn binary_config_map_data_is_measured_by_the_bytes_it_decodes_to() {
    let router = emulator();
    let config = provisioned(&router, "k8s-config-map-binary").await;
    let collection = "/api/v1/namespaces/default/configmaps";

    // Four base64 characters carry three bytes, so this value's TEXT is a third
    // past the ceiling while the data it stores is just under it: measured over
    // the decoded bytes it fits, measured over the text it would not.
    let name = "packed";
    let groups = (MAX_CONFIG_MAP_BYTES - name.len()) / 3;
    let encoded = "A".repeat(groups * 4);
    assert!(
        encoded.len() > MAX_CONFIG_MAP_BYTES,
        "the case needs base64 text past the ceiling, got {} characters",
        encoded.len()
    );
    let mut data = serde_json::Map::new();
    data.insert(name.to_string(), json!(encoded));
    let packed = dial(
        &config,
        "base64 text past the ceiling whose data is under it",
        "POST",
        collection,
        Some(&json!({ "metadata": { "name": name }, "binaryData": data })),
    )
    .await;
    assert_eq!(
        packed.status, 201,
        "a ConfigMap whose DECODED data is under the ceiling is stored, got {}: {:?}",
        packed.status, packed.body
    );

    // And a value that is not base64 encodes no data at all.
    let not_base64 = dial(
        &config,
        "a binaryData value that is not base64",
        "POST",
        collection,
        Some(&json!({
            "metadata": { "name": "unencoded" },
            "binaryData": { "seed.bin": "not base64 at all!" },
        })),
    )
    .await;
    assert_eq!(
        not_base64.status, 422,
        "a binaryData value that is not base64 is refused, got {not_base64:?}"
    );
    assert_eq!(
        not_base64.body["reason"],
        json!("Invalid"),
        "expected the Kubernetes validation Status, got {:?}",
        not_base64.body
    );
    let read_back = dial(
        &config,
        "a binaryData value that is not base64",
        "GET",
        &format!("{collection}/unencoded"),
        None,
    )
    .await;
    assert_eq!(
        read_back.status, 404,
        "a refused create must store no ConfigMap, got {read_back:?}"
    );
}

// ---------------------------------------------------------------------------
// RULE: `metadata.labels` and `metadata.annotations` are string-to-string maps,
// so a manifest whose entry holds anything else is refused — for every object
// kind this API serves — rather than stored with that entry dropped.
// ---------------------------------------------------------------------------

/// One row of the metadata table: the collection the manifest is posted to, the
/// manifest itself, and the member the validation `Status` is to name.
struct InvalidMetadataCase {
    label: &'static str,
    collection: &'static str,
    manifest: serde_json::Value,
    member: &'static str,
}

#[tokio::test]
async fn a_manifest_whose_metadata_cannot_be_stored_is_refused() {
    let router = emulator();
    let config = provisioned(&router, "k8s-object-metadata").await;

    // The rows differ along the object kind, which of the two maps holds the
    // value, and how it fails to be one: a non-string entry, and a member that
    // is not a map at all.
    let cases = [
        InvalidMetadataCase {
            label: "a pod label whose value is a number",
            collection: "/api/v1/namespaces/default/pods",
            manifest: json!({
                "metadata": { "name": "labelled-pod", "labels": { "replicas": 3 } },
                "spec": { "containers": [{ "name": "app", "image": "public.ecr.aws/app:1" }] },
            }),
            member: "metadata.labels[replicas]",
        },
        InvalidMetadataCase {
            label: "a pod annotations member that is a list",
            collection: "/api/v1/namespaces/default/pods",
            manifest: json!({
                "metadata": {
                    "name": "annotated-pod",
                    "annotations": ["owner=integration-test"],
                },
                "spec": { "containers": [{ "name": "app", "image": "public.ecr.aws/app:1" }] },
            }),
            member: "metadata.annotations",
        },
        InvalidMetadataCase {
            label: "a ConfigMap annotation whose value is an object",
            collection: "/api/v1/namespaces/default/configmaps",
            manifest: json!({
                "metadata": {
                    "name": "annotated-settings",
                    "annotations": { "owner": { "team": "data" } },
                },
                "data": { "log-level": "debug" },
            }),
            member: "metadata.annotations[owner]",
        },
        InvalidMetadataCase {
            label: "a namespace label whose value is a boolean",
            collection: "/api/v1/namespaces",
            manifest: json!({
                "metadata": { "name": "labelled-namespace", "labels": { "shared": true } },
            }),
            member: "metadata.labels[shared]",
        },
        InvalidMetadataCase {
            label: "a service account label whose value is a list",
            collection: "/api/v1/namespaces/default/serviceaccounts",
            manifest: json!({
                "metadata": { "name": "labelled-account", "labels": { "role": ["reader"] } },
            }),
            member: "metadata.labels[role]",
        },
    ];

    for case in &cases {
        let label = case.label;
        let refused = dial(
            &config,
            label,
            "POST",
            case.collection,
            Some(&case.manifest),
        )
        .await;
        assert_eq!(
            refused.status, 422,
            "case {label:?}: a metadata member no object can carry is refused, got {refused:?}"
        );
        assert_eq!(
            refused.body["reason"],
            json!("Invalid"),
            "case {label:?}: expected the Kubernetes validation Status, got {:?}",
            refused.body
        );
        let message = refused.body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(case.member),
            "case {label:?}: the refusal names the member that is invalid ({:?}), got {message:?}",
            case.member
        );

        // A refused create stores nothing: the object it named does not exist.
        let name = case.manifest["metadata"]["name"]
            .as_str()
            .unwrap_or_default();
        let read_back = dial(
            &config,
            label,
            "GET",
            &format!("{}/{name}", case.collection),
            None,
        )
        .await;
        assert_eq!(
            read_back.status, 404,
            "case {label:?}: a refused create must store no object, got {read_back:?}"
        );
    }
}
