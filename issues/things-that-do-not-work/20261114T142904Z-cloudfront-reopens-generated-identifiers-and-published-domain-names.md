Issue-Source: trace-sweep-divergence
Issue-Trace: cfetag-response-headers-policy-etag-chain
Issue-Step: task#1
Issue-Severity: MEDIUM
Issue-Corpus: simparity-wire-aws-v1
Issue-Corpus-Kind: wire
Issue-Trace-Ids: cfetag-response-headers-policy-etag-chain cfetag-origin-access-identity-etag-chain cfdeep-origin-access-inuse-conflicts cloudfront-distribution-alias-association-error cloudfront-monitoring-subscription-workflow cloudfront-web-acl-association-workflow cfetag-distribution-etag-chain
Issue-Shape-Id: com.amazonaws.cloudfront#Cloudfront2020_05_31
Issue-Key: cloudfront|CreateResponseHeadersPolicy|2xx->2xx|$headers.location
Issue-Key: cloudfront|CreateCloudFrontOriginAccessIdentity|2xx->2xx|$.CloudFrontOriginAccessIdentity.S3CanonicalUserId
Issue-Key: cloudfront|GetCloudFrontOriginAccessIdentity|2xx->2xx|$.CloudFrontOriginAccessIdentity.S3CanonicalUserId
Issue-Key: cloudfront|CreateDistribution|2xx->2xx|$.Distribution.DomainName
Issue-Key: cloudfront|CreateDistributionWithTags|2xx->2xx|$.Distribution.DomainName
Issue-Key: cloudfront|GetDistribution|2xx->2xx|$.Distribution.DomainName
Issue-Commit: 84412ef57d49d3e319b2b9326649851b03084832

# CloudFront REOPENS: generated identifiers and published domain names do not have AWS's forms

> _Note: this issue was identified against the code base at commit `84412ef57d49d3e319b2b9326649851b03084832`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
CreateResponseHeadersPolicy

## Description
Six causes, one shared fault: the values the CloudFront emulator DERIVES for a resource (the id inside a create response's Location URI, an origin access identity's S3 canonical user id, and a distribution's published DomainName) are not derived the way AWS derives them, so every fixture that asserts the SHAPE of those values (expected is recorded as '<shaped-not-asserted>', i.e. the shape is the assertion and the literal value is not) diverges.

Causes 1-3 REOPEN the resolved issue 20261029T212223Z-cloudfront-generated-identifiers-location-uris-and-post-create.md: the same operations, the same replay keys and (for the canonical user id) the byte-identical value it recorded still diverge, and a resolved issue does not own a live failure. Causes 4-6 are the distribution DomainName form; they are adjacent to the resolved 20261109T120741Z-cloudfront-distribution-and-connection-group-responses-publish-aws-production.md and to the open edge-unreachability issues (e.g. 20261109T143515Z-cloudfront-logs-a-cloudfront-distribution-s-domainname-is-published-as.md, 20261109T181319Z-cloudfront-s3-the-s3-origin-edge-is-unreachable.md), none of which carries these replay keys. The open issue 20261109T120741Z-cloudfront-create-responses-announce-a-location-uri-on.md covers the Location of ten OTHER create operations and not CreateResponseHeadersPolicy's.

Cause 1 of 6: CreateResponseHeadersPolicy's Location URI still fails the recorded shape.
AWS: 201 with 'Location: <service endpoint>/2020-05-31/response-headers-policy/<policy id>', where the authority is a resolvable service endpoint and the last path segment is a response-headers-policy id in CloudFront's id form (Smithy: CreateResponseHeadersPolicy output member Location is bound to the 'Location' httpHeader, http {method POST, uri /2020-05-31/response-headers-policy, code 201}; ResponseHeadersPolicy.Id is required, 'The identifier for the response headers policy'). The fixture asserts that whole shape, not a literal URI.
Emulator: emits 'https://127.0.0.1:<port>/2020-05-31/response-headers-policy/<uuid>' and the step diverges with verdict shape_mismatch on $headers.location. Two things about the emitted value are not AWS-shaped: the authority is a bare IP-literal with a port rather than a host name a client can resolve/address the policy by, and the id segment comes from a fixed-seed generator (the recording of this run and the earlier run cited in the resolved issue carry the same uuid stem for this and other CloudFront resource types, i.e. the generator is seeded identically every boot rather than minting a fresh per-resource id). Hypothesis: the surviving half of the shape failure is the authority form, because the id segment now has valid UUID grouping while the assertion still fails.
Why: a client that follows Location to GET/PUT/DELETE the new policy, or that validates the URI/id form before storing it, builds an address AWS would never have returned; a seeded id generator additionally lets ids collide across resource types and across boots.
Fix: CreateResponseHeadersPolicy's response construction (Location derivation) plus the response-headers-policy id generator in cloudfront state.
Traces: cfetag-response-headers-policy-etag-chain#task#1.

Cause 2 of 6: CreateCloudFrontOriginAccessIdentity returns a constant S3CanonicalUserId.
AWS: 201 whose CloudFrontOriginAccessIdentity.S3CanonicalUserId is THAT identity's own Amazon S3 canonical user id - a per-identity value in the canonical-user-id form (Smithy: CloudFrontOriginAccessIdentity.S3CanonicalUserId, required, 'The Amazon S3 canonical user ID for the origin access identity, used when giving the origin access identity read permission to an object in Amazon S3'). The fixture asserts the shape/provenance, not the literal id.
Emulator: returns a fixed 64-hex constant. It is the SAME string this replay returns for a different identity in a different fixture (cause 3) and the same string the resolved issue recorded, so it is a hard constant rather than a value derived per identity.
Why: the canonical user id is the principal an S3 bucket policy or object ACL grants read to; when every identity shares one value, two origin access identities are indistinguishable to S3 and per-identity origin access control cannot be modelled or tested.
Fix: the origin-access-identity canonical-user-id generator in cloudfront state (derive it per identity, like the identity id).
Traces: cfetag-origin-access-identity-etag-chain#task#1.

Cause 3 of 6: GetCloudFrontOriginAccessIdentity reads back the same constant.
AWS: 200 with that identity's own S3CanonicalUserId, equal to the one its create returned.
Emulator: the identical constant seen in cause 2, for an identity created in a different fixture.
Why/Fix: as cause 2, on GetCloudFrontOriginAccessIdentity's readback projection. The pair of clusters is what proves the value is constant rather than merely oddly shaped.
Traces: cfdeep-origin-access-inuse-conflicts#task#7.

Cause 4 of 6: CreateDistribution publishes a host:port where AWS publishes a CloudFront domain name.
AWS: 201 whose Distribution.DomainName is the distribution's CloudFront DOMAIN NAME - a DNS host name of the documented form, e.g. d111111abcdef8.cloudfront.net (Smithy: Distribution.DomainName, required, 'The distribution's CloudFront domain name. For example: d111111abcdef8.cloudfront.net'). The fixture asserts that form.
Emulator: publishes a bare IP literal with a port appended, e.g. '127.0.0.1:<port>'. That is not a domain name at all: it has no DNS label structure, it carries a port inside a domain-name member, and the port differs per fixture and is not the port the data listener answers on.
Why: DomainName is what a client puts in a Host header, a CNAME/Route53 alias target, a TLS SNI name or an assertion on the *.cloudfront.net form; none of those accepts an address:port pair, so create-then-address-the-distribution breaks and any client validating the member rejects the response.
Fix: the distribution domain-name derivation in cloudfront state (mint a '<distribution id>.cloudfront.net'-form name) plus CreateDistribution's response construction. Note the complementary requirement recorded by the open edge-unreachability issues: the emulator must also ANSWER on the name it publishes, so the fix is a cloudfront.net-form name that the emulator serves - not a bare host:port, which satisfies neither requirement.
Traces: cloudfront-distribution-alias-association-error#setup#1.

Cause 5 of 6: CreateDistributionWithTags - same fault on the tagged-create route.
AWS: 201 with a Distribution.DomainName in the same documented form.
Emulator: the same IP-literal host:port value.
Why/Fix: as cause 4, in CreateDistributionWithTags' response construction / the shared domain-name derivation.
Traces: cloudfront-monitoring-subscription-workflow#setup#1 (2 affected steps, incl. cloudfront-web-acl-association-workflow#setup#1).

Cause 6 of 6: GetDistribution reads the same non-domain value back.
AWS: 200 with the distribution's cloudfront.net-form DomainName, the same value the create returned.
Emulator: the stored host:port. In this cluster the recorded and the emitted values DISPLAY identically and the step still diverges, which is the decisive signal that the requirement is the member's form and provenance (a CloudFront domain name for this distribution) rather than echoing any recorded string - templating the recorded value is not a fix.
Why/Fix: as cause 4, on GetDistribution's readback projection.
Traces: cfetag-distribution-etag-chain#task#5.

The concrete hosts, ports, uuids, 64-hex digests and ids quoted here are per-run values and are not themselves requirements; the requirements are the forms (a resolvable endpoint authority plus an AWS-form id in the Location URI, a per-identity canonical user id, and a DNS domain name of the '<id>.cloudfront.net' form for DomainName).

## Evidence
Replay of simparity-wire-aws-v1 (emulator_up=true, /__admin/health 200; 1303 steps, 1151 passed, score 88.3%). Six unowned mismatch clusters (no stub_path, no owned_by on any of them):
1. CreateResponseHeadersPolicy 201->201 - cfetag-response-headers-policy-etag-chain#task#1: $headers.location shape_mismatch, expected '<shaped-not-asserted>', got 'https://127.0.0.1:36099/2020-05-31/response-headers-policy/e220a839-7b1d-4daf-ae78-9e6aa1b965f4'.
2. CreateCloudFrontOriginAccessIdentity 201->201 - cfetag-origin-access-identity-etag-chain#task#1: $.CloudFrontOriginAccessIdentity.S3CanonicalUserId value_mismatch, expected '<shaped-not-asserted>', got '6e789e6aa1b965f406c45d188009454ff88bb8a8724c81ec1b39896a51a8749b'.
3. GetCloudFrontOriginAccessIdentity 200->200 - cfdeep-origin-access-inuse-conflicts#task#7: same key, same expected, got the IDENTICAL string '6e789e6aa1b965f406c45d188009454ff88bb8a8724c81ec1b39896a51a8749b' for a different identity in a different fixture (and the same string the resolved issue 20261029T212223Z-cloudfront-generated-identifiers-location-uris-and-post-create.md recorded).
4. CreateDistribution 201->201 - cloudfront-distribution-alias-association-error#setup#1: $.Distribution.DomainName value_mismatch, expected '<shaped-not-asserted>', got '127.0.0.1:35035'.
5. CreateDistributionWithTags 201->201 - cloudfront-monitoring-subscription-workflow#setup#1: $.Distribution.DomainName value_mismatch, expected '<shaped-not-asserted>', got '127.0.0.1:37147' (2 affected steps, incl. cloudfront-web-acl-association-workflow#setup#1).
6. GetDistribution 200->200 - cfetag-distribution-etag-chain#task#5: $.Distribution.DomainName value_mismatch where expected and actual both render as '127.0.0.1:36513' - byte-identical rendering, still a divergence.
Note the ports in 1/4/5/6 (36099, 35035, 37147, 36513) differ per fixture and none of them is the emulator's data port reported by the replay summary (38125), so the published authority is not even the one the emulator is reached on.

## Steps to Reproduce
1. git clone the repo and boot the emulator built from that checkout; replay the wire corpus (trace set simparity-wire-aws-v1).
2. Representative step: fixture cfetag-response-headers-policy-etag-chain, step task#1 - POST /2020-05-31/response-headers-policy and read the Location response header; its authority is an IP:port literal and its id segment comes from a boot-constant generator, so the recorded shape assertion fails.
3. cfetag-origin-access-identity-etag-chain#task#1 and cfdeep-origin-access-inuse-conflicts#task#7 - create one origin access identity and read another, and compare CloudFrontOriginAccessIdentity.S3CanonicalUserId: the two different identities report the same 64-hex value.
4. cloudfront-distribution-alias-association-error#setup#1 (CreateDistribution) and cloudfront-monitoring-subscription-workflow#setup#1 (CreateDistributionWithTags) - read Distribution.DomainName: it is '<ip>:<port>', not a '<id>.cloudfront.net'-form DNS name.
5. cfetag-distribution-etag-chain#task#5 (GetDistribution) - the readback republishes the same non-domain value; this step diverges even though the recorded and emitted strings render identically, so compare the value's FORM, not the string.
