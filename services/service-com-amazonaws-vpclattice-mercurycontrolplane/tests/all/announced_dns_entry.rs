// SPDX-License-Identifier: CC0-1.0

//! End-to-end tests for the host this service ANNOUNCES in a `DnsEntry`.
//!
//! Every case drives the emulator the way a client does — a restJson1 request through the
//! router that mounts the service — and reads what it asserts back out of later requests
//! (`GetService`, `ListServices`, `GetServiceNetworkServiceAssociation`, the association
//! listing), so a create-time artifact and a read path are both under test.
//!
//! The rule under test, asserted over a TABLE of ADDRESSINGS rather than one row: a
//! `DnsEntry.domainName` is the `host[:port]` this emulator answers the request on — the
//! emulator's own endpoint the request reached, or, for a caller that addressed a host
//! naming some service, the address this process is served at — and never a host in a zone
//! AWS serves its own endpoints or its lattice data plane in, which resolves nowhere near
//! this process. The model places no pattern or length constraint on `domainName`
//! (`smithy_query(query="shape",shape="DnsEntry")`), so the one requirement on the value is
//! that the responder answers there.
//!
//! The rows differ in WHAT the client addressed, which is what the rule generalises over:
//! an IPv4 socket address with a port, a loopback name with a port, a bracketed IPv6
//! literal, the emulator's own endpoint without a port, and the service's own published AWS
//! host — the one addressing that names a service, which is answered the address this
//! process is served at instead. These tests drive a router served at no address of its
//! own, so that last row is answered the authority of the unserved base
//! (`smithy_server_runtime::UNSERVED_URL_BASE`), a host RFC 2606 reserves so that nothing
//! resolves it.

use crate::vpclattice_service_slice::{Answer, Lattice, REGION};

/// The `host[:port]` of the base `OperationContext::endpoint` reports for an emulator
/// served on no port at all — what a caller that resolves AWS's own hostnames is announced
/// here, since this process has no address of its own to name.
pub(crate) fn unserved_authority() -> &'static str {
    ::service_common::data_plane_addressing::url_authority(
        ::smithy_server_runtime::UNSERVED_URL_BASE,
    )
}

/// The addressings the table spans, each with the host the service must announce to it.
fn addressing_cases() -> Vec<(&'static str, String, String)> {
    vec![
        (
            "an IPv4 socket address with a port",
            "127.0.0.1:39355".to_string(),
            "127.0.0.1:39355".to_string(),
        ),
        (
            "the loopback name with a port",
            "localhost:9297".to_string(),
            "localhost:9297".to_string(),
        ),
        (
            "a bracketed IPv6 literal with a port",
            "[::1]:9297".to_string(),
            "[::1]:9297".to_string(),
        ),
        (
            "an address carrying no port",
            "127.0.0.1".to_string(),
            "127.0.0.1".to_string(),
        ),
        (
            "the service's own published AWS host",
            format!("vpc-lattice.{REGION}.amazonaws.com"),
            unserved_authority().to_string(),
        ),
    ]
}

/// The `dnsEntry` of `value`, with its `domainName` and `hostedZoneId`.
fn dns_entry_of(case: &str, value: &serde_json::Value) -> (String, String) {
    let entry = &value["dnsEntry"];
    let domain = entry["domainName"].as_str().unwrap_or_else(|| {
        panic!("case {case}: expected a dnsEntry.domainName, got {value}")
    });
    let zone = entry["hostedZoneId"].as_str().unwrap_or_else(|| {
        panic!("case {case}: expected a dnsEntry.hostedZoneId, got {value}")
    });
    (domain.to_string(), zone.to_string())
}

/// Assert the announced host is the one this emulator answers on for `case`, and that it
/// is in no zone AWS publishes an endpoint or its lattice data plane in.
fn assert_announced(case: &str, expected: &str, domain: &str) {
    assert_eq!(
        domain, expected,
        "case {case}: expected the host this emulator answers on ({expected:?}), \
         got {domain:?}"
    );
    // The zones AWS publishes its own endpoints in
    // (`service_common::data_plane_addressing::AWS_ENDPOINT_DNS_SUFFIXES`), plus the zone
    // the real VPC Lattice data plane hands services out in.
    assert!(
        !::service_common::data_plane_addressing::addresses_an_aws_endpoint(domain),
        "case {case}: {domain:?} is a host in a zone AWS serves its own endpoints in, \
         which this emulator does not answer on"
    );
    assert!(
        !domain.contains("vpc-lattice-svcs"),
        "case {case}: {domain:?} names the real lattice data plane, \
         which this emulator does not answer on"
    );
}

/// A hosted-zone id is the per-resource value Route 53 shape: `Z` and 19 `[0-9A-Z]`
/// characters. It is the resource's own, so it must NOT change with the addressing.
fn assert_hosted_zone(case: &str, zone: &str) {
    assert!(
        zone.len() == 20
            && zone.starts_with('Z')
            && zone[1..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase()),
        "case {case}: expected a hosted zone id of `Z` and 19 [0-9A-Z] characters, \
         got {zone:?}"
    );
}

/// Every operation that serializes a `DnsEntry` announces the host this emulator answers
/// the call on: the service create and its read-back and listing, and the association
/// create, its read-back and its listing.
#[tokio::test]
async fn every_dns_entry_announces_the_host_this_emulator_answers_on() {
    let lattice = Lattice::new();

    for (index, (case, host, expected)) in addressing_cases().into_iter().enumerate() {
        // One service and one service network per row, so each row's association is a
        // fresh pair (a pair may be associated only once).
        let network = {
            let created = lattice
                .call_from_host(
                    &host,
                    "POST",
                    "/servicenetworks",
                    Some(serde_json::json!({ "name": format!("announced-net-{index}") })),
                )
                .await;
            assert_eq!(
                created.status, 201,
                "case {case}: the fixture service network expected 201, got {} / {}",
                created.status, created.body
            );
            created.str_field("id")
        };

        // CreateService.
        let created = lattice
            .call_from_host(
                &host,
                "POST",
                "/services",
                Some(serde_json::json!({ "name": format!("announced-host-{index}") })),
            )
            .await;
        assert_eq!(
            created.status, 201,
            "case {case}: CreateService expected 201, got {} / {}",
            created.status, created.body
        );
        let service = created.str_field("id");
        let (domain, zone) = dns_entry_of(case, &created.body);
        assert_announced(&format!("{case}, CreateService"), &expected, &domain);
        assert_hosted_zone(&format!("{case}, CreateService"), &zone);

        // GetService: the read path announces the same host, and reports the service's
        // own hosted zone.
        let read = lattice
            .call_from_host(&host, "GET", &format!("/services/{service}"), None)
            .await;
        assert_eq!(
            read.status, 200,
            "case {case}: GetService expected 200, got {} / {}",
            read.status, read.body
        );
        let (read_domain, read_zone) = dns_entry_of(case, &read.body);
        assert_announced(&format!("{case}, GetService"), &expected, &read_domain);
        assert_eq!(
            read_zone, zone,
            "case {case}: GetService must report the service's own hosted zone {zone:?}, \
             got {read_zone:?}"
        );

        // ListServices: every summary of the listing announces it too.
        let listed = lattice
            .call_from_host(&host, "GET", "/services", None)
            .await;
        assert_eq!(
            listed.status, 200,
            "case {case}: ListServices expected 200, got {} / {}",
            listed.status, listed.body
        );
        let items = listed.body["items"].as_array().cloned().unwrap_or_default();
        assert!(
            !items.is_empty(),
            "case {case}: ListServices must report the persisted services, got {}",
            listed.body
        );
        for item in &items {
            let (listed_domain, _) = dns_entry_of(case, item);
            assert_announced(&format!("{case}, ListServices"), &expected, &listed_domain);
        }

        // CreateServiceNetworkServiceAssociation.
        let associated = lattice
            .call_from_host(
                &host,
                "POST",
                "/servicenetworkserviceassociations",
                Some(serde_json::json!({
                    "serviceIdentifier": service,
                    "serviceNetworkIdentifier": network,
                })),
            )
            .await;
        assert_eq!(
            associated.status, 200,
            "case {case}: the association expected 200, got {} / {}",
            associated.status, associated.body
        );
        let association = associated.str_field("id");
        let (association_domain, association_zone) = dns_entry_of(case, &associated.body);
        assert_announced(
            &format!("{case}, CreateServiceNetworkServiceAssociation"),
            &expected,
            &association_domain,
        );
        assert_eq!(
            association_zone, zone,
            "case {case}: the association reports the associated service's hosted zone \
             {zone:?}, got {association_zone:?}"
        );

        // GetServiceNetworkServiceAssociation.
        let read_association = lattice
            .call_from_host(
                &host,
                "GET",
                &format!("/servicenetworkserviceassociations/{association}"),
                None,
            )
            .await;
        assert_eq!(
            read_association.status, 200,
            "case {case}: the association read-back expected 200, got {} / {}",
            read_association.status, read_association.body
        );
        let (read_association_domain, _) = dns_entry_of(case, &read_association.body);
        assert_announced(
            &format!("{case}, GetServiceNetworkServiceAssociation"),
            &expected,
            &read_association_domain,
        );

        // ListServiceNetworkServiceAssociations.
        let listed_associations = lattice
            .call_from_host(
                &host,
                "GET",
                &format!(
                    "/servicenetworkserviceassociations?serviceNetworkIdentifier={network}"
                ),
                None,
            )
            .await;
        assert_eq!(
            listed_associations.status, 200,
            "case {case}: the association listing expected 200, got {} / {}",
            listed_associations.status, listed_associations.body
        );
        let association_items = listed_associations.body["items"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            association_items.len(),
            1,
            "case {case}: the listing must report the one persisted association, got {}",
            listed_associations.body
        );
        let (listed_association_domain, _) = dns_entry_of(case, &association_items[0]);
        assert_announced(
            &format!("{case}, ListServiceNetworkServiceAssociations"),
            &expected,
            &listed_association_domain,
        );
    }
}

/// One resource, read from several addressings: each caller is announced the host IT
/// reaches this emulator on, and the resource's own hosted zone never moves.
#[tokio::test]
async fn one_service_announces_each_caller_the_host_that_caller_reaches() {
    let lattice = Lattice::new();
    let cases = addressing_cases();
    let (_, first_host, _) = &cases[0];

    let created = lattice
        .call_from_host(
            first_host,
            "POST",
            "/services",
            Some(serde_json::json!({ "name": "announced-per-caller" })),
        )
        .await;
    assert_eq!(
        created.status, 201,
        "the fixture service expected 201, got {} / {}",
        created.status, created.body
    );
    let service = created.str_field("id");
    let (_, zone) = dns_entry_of("the fixture service", &created.body);

    for (case, host, expected) in &cases {
        let read = lattice
            .call_from_host(host, "GET", &format!("/services/{service}"), None)
            .await;
        assert_eq!(
            read.status, 200,
            "case {case}: GetService expected 200, got {} / {}",
            read.status, read.body
        );
        let (domain, read_zone) = dns_entry_of(case, &read.body);
        assert_announced(case, expected, &domain);
        assert_eq!(
            &read_zone, &zone,
            "case {case}: the service's hosted zone {zone:?} must not move with the \
             addressing, got {read_zone:?}"
        );
    }
}

/// Reading a service twice from one addressing announces exactly the same host: the value
/// is a function of the request and the store, not of when it was asked for.
#[tokio::test]
async fn the_announced_host_is_stable_across_reads_from_one_addressing() {
    let lattice = Lattice::new();
    for (index, (case, host, expected)) in addressing_cases().into_iter().enumerate() {
        let created = lattice
            .call_from_host(
                &host,
                "POST",
                "/services",
                Some(serde_json::json!({ "name": format!("stable-host-{index}") })),
            )
            .await;
        assert_eq!(
            created.status, 201,
            "case {case}: CreateService expected 201, got {} / {}",
            created.status, created.body
        );
        let service = created.str_field("id");
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..3 {
            let read: Answer = lattice
                .call_from_host(&host, "GET", &format!("/services/{service}"), None)
                .await;
            assert_eq!(
                read.status, 200,
                "case {case}: GetService expected 200, got {} / {}",
                read.status, read.body
            );
            let (domain, _) = dns_entry_of(case, &read.body);
            assert_announced(case, &expected, &domain);
            seen.push(domain);
        }
        assert!(
            seen.windows(2).all(|pair| pair[0] == pair[1]),
            "case {case}: every read must announce one host, got {seen:?}"
        );
    }
}
