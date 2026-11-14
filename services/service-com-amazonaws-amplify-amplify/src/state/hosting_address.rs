// SPDX-License-Identifier: CC0-1.0

//! The DOMAIN an app's hosting is ANNOUNCED under, and the host or path one branch's site
//! answers on.
//!
//! `App$defaultDomain` is "the default domain for the Amplify app"
//! (`smithy_query(query="doc",shape="App",member="defaultDomain")`) and
//! `Branch$displayName` "is used as the default domain prefix"
//! (`smithy_query(query="doc",shape="Branch",member="displayName")`), so a client that was
//! told both composes `https://<displayName>.<defaultDomain>/` — the deployed page, the
//! branch's basic-authorization challenge, or the redirect a rule states.
//!
//! The member is a DNS DOMAIN of the hosting zone Amplify publishes an app's sites under,
//! and it names the app itself: the app's own id followed by that zone
//! ([`amplify_zone_default_domain`]). It is derived from the app's minted id alone — never
//! from the endpoint, the host or the port the creating request happened to reach — so the
//! value is the same whichever address a client of this emulator is configured with, and a
//! client that was told it composes a site's host by prefixing a branch's label to it.
//!
//! The member is a DOMAIN, so the value is an address and nothing else: no scheme, no path.
//! What that address cannot carry — which app, and which of its branches — is carried in the
//! PATH this plane ALSO serves a site under ([`hosted_site_path`]), exactly as the shared
//! data-plane reading states for a plane served on the emulator's own endpoint, so a client
//! that resolves nothing but one local endpoint can still fetch the site.
//!
//! The domain is resolved ONCE, when the app is created, and persisted as the app's
//! `defaultDomain`, so every later read of that app reports the same string whatever it is
//! addressed at.
//!
//! The same two members decide which requests the edge serves, so the address a branch
//! answers on is composed HERE too, from the stored record, and compared against the
//! address a request carried ([`HostedSiteAddress`]): the HOST a client composes from a
//! default domain under Amplify's own hosting zone ([`hosted_branch_host`],
//! [`names_the_hosting_zone`]), read in one normal form ([`hosted_site_host`]) because a
//! host is the same host however its port, its userinfo, its trailing root dot or its case
//! are written — and the PATH that names the app and the branch for an app announced on this
//! emulator's own endpoint ([`hosted_site_path`], read back by [`addressed_hosted_site`]).

/// The default domain an app of this id carries under Amplify's OWN hosting zone: the value
/// the shape `App$defaultDomain` documents, derived from the app's minted id alone (see the
/// module docs).
///
/// The one form the member takes, and it is inside `DefaultDomain`'s modelled
/// `length 1..1000` (`smithy_query(query="shape",shape="DefaultDomain")`).
pub fn amplify_zone_default_domain(app_id: &str) -> String {
    format!("{app_id}.{AMPLIFY_HOSTING_ZONE}")
}

/// The zone Amplify serves an app's default domain under.
const AMPLIFY_HOSTING_ZONE: &str = "amplifyapp.com";

/// Whether `default_domain` is one Amplify's OWN hosting zone publishes, which is the form
/// a client prefixes a branch's label to ([`hosted_branch_host`]).
///
/// Every app this service creates carries such a domain ([`amplify_zone_default_domain`]),
/// so this is the reading that tells a stored domain from a host that is no zone a branch
/// label could be a label of — an address this emulator is dialled at, which addresses a
/// site by the PATH that names it ([`hosted_site_path`]) instead.
pub fn names_the_hosting_zone(default_domain: &str) -> bool {
    hosted_site_host(default_domain).ends_with(&format!(".{AMPLIFY_HOSTING_ZONE}"))
}

/// The segment that names THIS plane under the reserved data-plane marker, ahead of the
/// app's own id: `/_aws/amplify/<appId>`.
///
/// It is this service's own route key, so no other plane of this emulator reads a path under
/// it.
pub const HOSTING_PLANE_LABEL: &str = "amplify";

/// The path prefix this plane serves ONE app's sites under, on this emulator's own
/// endpoint: `/_aws/amplify/<appId>`, the reserved data-plane marker, this plane's label and
/// the app.
///
/// One spelling, shared by the site addresses composed beneath it ([`hosted_site_path`]) and
/// the reading that claims such a request back ([`addressed_hosted_site`]), so the address
/// this plane serves and the request it claims cannot drift apart.
pub fn hosting_plane_prefix(app_id: &str) -> String {
    format!(
        "/{namespace}/{HOSTING_PLANE_LABEL}/{app_id}",
        namespace = ::service_common::data_plane_addressing::EMULATOR_PATH_NAMESPACE,
    )
}

/// The host one branch's site answers at, as a name to compare an addressed host against:
/// the branch's display name, then the default domain of its app, in the one normal form
/// [`hosted_site_host`] reads a host in.
///
/// This is the composition for a DNS default domain, the one a client prefixes a label to.
pub fn hosted_branch_host(display_name: &str, default_domain: &str) -> String {
    hosted_site_host(&format!("{display_name}.{default_domain}"))
}

/// The path one branch's site answers at on this emulator's own endpoint: the app's own
/// prefix ([`hosting_plane_prefix`]) and the branch's display name, which is the label that
/// names the branch wherever a default domain announces one.
///
/// A client configured with ONE local endpoint resolves nothing but that address, so it
/// cannot dial the app's own hosting domain at all: the app AND the branch are named in the
/// path instead, exactly as the shared data-plane reading states — what the host cannot
/// carry, the path carries.
pub fn hosted_site_path(app_id: &str, display_name: &str) -> String {
    format!("{}/{display_name}", hosting_plane_prefix(app_id))
}

/// A host in the one normal form this edge compares in: no userinfo, no port, no trailing
/// root dot, lowercased — the four ways the same host is written.
///
/// The port is dropped on BOTH sides, so an announced domain that carries this emulator's
/// port is matched by the request that dialled it, and a host is still the same host when
/// a client writes the default port for its scheme or leaves it out.
pub fn hosted_site_host(host: &str) -> String {
    ::service_common::data_plane_addressing::host_only(host)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// How a request ADDRESSES a branch's site — the two addressings the module docs state,
/// each resolved against the records the control plane persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedSiteAddress<'r> {
    /// The HOST a client composed from a DNS default domain:
    /// `<displayName>.<defaultDomain>`.
    Host(&'r str),
    /// The PATH a client that resolves nothing but this emulator's own endpoint composed:
    /// the app the path names and the branch label that follows it.
    Local {
        /// The `appId` the path names.
        app_id: &'r str,
        /// The branch label the path names, which is a branch's `displayName`.
        label: &'r str,
    },
}

/// The site a request PATH addresses and the path WITHIN that site, or `None` for a path
/// that addresses no site of this plane.
///
/// The reading of [`hosted_site_path`]: the reserved data-plane marker, this plane's label,
/// the app's id and the branch's label, with everything after them the path within the site
/// (`/` when nothing follows). It is read on ANY host, because the marker is explicit —
/// the same reason the other local data planes of this workspace read theirs that way.
pub fn addressed_hosted_site(path: &str) -> Option<(HostedSiteAddress<'_>, &str)> {
    let first_segment = ::service_common::data_plane_addressing::first_segment;
    let (namespace, rest) = first_segment(path)?;
    if namespace != ::service_common::data_plane_addressing::EMULATOR_PATH_NAMESPACE {
        return None;
    }
    let (plane, rest) = first_segment(rest)?;
    if plane != HOSTING_PLANE_LABEL {
        return None;
    }
    let (app_id, rest) = first_segment(rest)?;
    let (label, within) = first_segment(rest)?;
    if app_id.is_empty() || label.is_empty() {
        return None;
    }
    Some((HostedSiteAddress::Local { app_id, label }, within))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_apps_domain_is_its_own_id_under_the_hosting_zone() {
        // The rows span the shapes a minted app id takes: the modelled `d`-and-suffix
        // form at both ends of its length, and one whose suffix is all digits.
        let cases: &[&str] = &["d1", "dexamplezone", "d2k7yq1ab3cd4ef5gh6i", "d1234567890"];
        for app_id in cases {
            let domain = amplify_zone_default_domain(app_id);
            assert_eq!(
                domain,
                format!("{app_id}.amplifyapp.com"),
                "case {app_id:?}: expected the app's id under the hosting zone, got {domain:?}"
            );
        }
    }

    #[test]
    fn a_branchs_host_and_an_addressed_host_read_the_same() {
        // The rows span the ways the same host is written: the app's domain dialled
        // plainly, with a port, rooted, in mixed case and carrying userinfo.
        let cases: &[(&str, &str, &str, &str)] = &[
            ("the app's own domain", "main", "d1example.amplifyapp.com", "main.d1example.amplifyapp.com"),
            ("the same domain dialled with a port", "main", "d1example.amplifyapp.com", "main.d1example.amplifyapp.com:44285"),
            ("a display name in mixed case", "Main-Two", "d1example.amplifyapp.com", "MAIN-TWO.d1example.amplifyapp.com"),
            ("a rooted host", "main", "d1example.amplifyapp.com", "main.d1example.amplifyapp.com."),
            ("a host carrying userinfo", "main", "d1example.amplifyapp.com", "visitor@main.d1example.amplifyapp.com"),
        ];
        for (case, display_name, default_domain, addressed) in cases {
            let branch = hosted_branch_host(display_name, default_domain);
            assert_eq!(
                branch,
                hosted_site_host(addressed),
                "case {case:?}: the branch's host {branch:?} must match the addressed \
                 {addressed:?}"
            );
        }
    }

    #[test]
    fn a_host_naming_another_branch_or_another_app_does_not_read_as_this_one() {
        // The rows span what must NOT match: another branch's label, another app's
        // domain, the app's domain with no branch label at all, and a label that only
        // shares a prefix with the branch's.
        let cases: &[(&str, &str)] = &[
            ("another branch", "other.d1example.amplifyapp.com"),
            ("another app's domain", "main.d2example.amplifyapp.com"),
            ("the domain with no branch label", "d1example.amplifyapp.com"),
            ("a label sharing a prefix", "mainline.d1example.amplifyapp.com"),
        ];
        let branch = hosted_branch_host("main", "d1example.amplifyapp.com");
        for (case, addressed) in cases {
            assert_ne!(
                branch,
                hosted_site_host(addressed),
                "case {case:?}: {addressed:?} must not read as the branch's host {branch:?}"
            );
        }
    }

    #[test]
    fn a_domain_under_the_hosting_zone_is_told_from_an_endpoint_address() {
        // The rows span both announced forms: the zone form at several app-id shapes, and
        // the endpoint addresses a client of this emulator is configured with.
        let zone: &[&str] = &[
            "d1example.amplifyapp.com",
            "D1EXAMPLE.AMPLIFYAPP.COM",
            "d1.amplifyapp.com.",
            "d1234567890.amplifyapp.com:443",
        ];
        for domain in zone {
            assert!(
                names_the_hosting_zone(domain),
                "case {domain:?}: expected a domain under the hosting zone"
            );
        }
        let endpoints: &[&str] = &[
            "127.0.0.1:44285",
            "localhost:9297",
            "[::1]:38199",
            "127.0.0.1",
            "amplifyapp.com",
            "notamplifyapp.com",
        ];
        for domain in endpoints {
            assert!(
                !names_the_hosting_zone(domain),
                "case {domain:?}: expected no domain of the hosting zone"
            );
        }
    }

    #[test]
    fn a_site_path_reads_back_the_app_the_branch_and_the_path_within() {
        // The rows span what follows the branch label: nothing, a root, a file, a nested
        // path and a query-less directory — and the labels at both ends of an app id.
        let cases: &[(&str, &str, &str, &str)] = &[
            ("no path at all", "d1example", "main", ""),
            ("the site root", "d1example", "main", "/"),
            ("a document", "d2k7yq1ab3cd4ef5gh6i", "release-2", "/index.html"),
            ("a nested document", "d1", "Main-Two", "/assets/app.css"),
            ("a directory", "d1234567890", "feature", "/docs/"),
        ];
        for (case, app_id, display_name, within) in cases {
            let addressed = format!("{}{within}", hosted_site_path(app_id, display_name));
            let read = addressed_hosted_site(&addressed);
            let expected_within = if within.is_empty() { "/" } else { *within };
            assert_eq!(
                read,
                Some((
                    HostedSiteAddress::Local {
                        app_id,
                        label: display_name
                    },
                    expected_within
                )),
                "case {case:?}: {addressed:?} must read as that site's path, got {read:?}"
            );
        }
    }

    #[test]
    fn a_path_of_another_plane_or_of_the_control_plane_addresses_no_site() {
        // The rows span the paths this reading must not claim: the control plane's own
        // routes, another plane under the same marker, this plane with nothing named
        // after it, and a path carrying the marker somewhere other than first.
        let cases: &[(&str, &str)] = &[
            ("a control-plane route", "/apps/d1example"),
            ("an upload destination", "/apps/d1/deployments/j1/uploads/t1"),
            ("another plane", "/_aws/portal/p1/main"),
            ("this plane naming no app", "/_aws/amplify"),
            ("this plane naming no branch", "/_aws/amplify/d1example"),
            ("the marker not first", "/apps/_aws/amplify/d1/main"),
            ("a relative path", "_aws/amplify/d1/main"),
        ];
        for (case, path) in cases {
            let read = addressed_hosted_site(path);
            assert_eq!(
                read, None,
                "case {case:?}: {path:?} must address no site, got {read:?}"
            );
        }
    }
}
