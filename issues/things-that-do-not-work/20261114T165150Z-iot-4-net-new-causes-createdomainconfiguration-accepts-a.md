Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: iot.domain-configuration-lifecycle iot.domain-configuration-lifecycle-transitions iot.e2e-fleet-provisioning-claim-to-thing iot.fleet-metric-lifecycle iot.fleet-metric-lifecycle-and-query iot.negative-fleet-metric-index-not-ready-blocked iot.telemetry-fleet-metric-lifecycle-and-aggregation
Issue-Shape-Id: com.amazonaws.iot#AWSIotService
Issue-Key: iot.domain-configuration-lifecycle|_error_code_and_message#17|AssertionError|raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
Issue-Key: iot|DeleteDomainConfiguration|ResourceNotFoundException
Issue-Key: iot.e2e-fleet-provisioning-claim-to-thing|run#15|AssertionError|assert 0 < ttl_seconds < 30 * 60, f"unexpected claim TTL: {ttl_seconds:.0f}s"
Issue-Key: iot.fleet-metric-lifecycle|run#28|AssertionError|assert message == expected_describe, f"expected message {expected_describe!r}, got {message!r}"
Issue-Key: iot.fleet-metric-lifecycle-and-query|run#27|AssertionError|assert message == expected_describe, f"expected message {expected_describe!r}, got {message!r}"
Issue-Key: iot.negative-fleet-metric-index-not-ready-blocked|run#16|AssertionError|assert describe_message == (
Issue-Key: iot.telemetry-fleet-metric-lifecycle-and-aggregation|run#24|AssertionError|assert gone_message == f"An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: FleetMetric {ctx.account}:{metric_name} n
Issue-Commit: de4891d4239c492b9e977f3e9646a8637ce0e129

# iot: 4 net-new causes — CreateDomainConfiguration accepts a self-signed validation certificate, DeleteDomainConfiguration is not idempotent, CreateProvisioningClaim mints a 1-hour claim, and DescribeFleetMetric's not-found message diverges

> _Note: this issue was identified against the code base at commit `de4891d4239c492b9e977f3e9646a8637ce0e129`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
CreateDomainConfiguration

## Description
Four independent root causes under the suite heading '### iot' (80/215 passed). Each is a different operation and a different handler, so they close independently. Causes are numbered; a fixer must close all four before submitting.

Cause 1 of 4: CreateDomainConfiguration accepts a CUSTOMER_MANAGED domain configuration whose validationCertificateArn names a certificate that is NOT signed by a trusted CA.
  Failing check: iot.domain-configuration-lifecycle.
  AWS: Smithy: CreateDomainConfiguration -> POST /domainConfigurations/{domainConfigurationName}; input members domainName (len 1..253), serverCertificateArns (list, len 0..1), validationCertificateArn (AcmCertificateArn, len 1..2048, ACM ARN pattern), serviceType (enum); modeled errors include InvalidRequestException (httpError 400) and CertificateValidationException (400). Recorded behavior: when domainName is supplied (a customer-managed domain) and validationCertificateArn names a self-signed certificate, AWS refuses the create with HTTP 400, error code InvalidRequestException and the message "Validation certificate must be signed by trusted CA" — that string is entirely fixed text, with no request or state values interpolated — and writes nothing, so the following DescribeDomainConfiguration is a 404 ResourceNotFoundException. The validation certificate exists to prove ownership of the domain, so one that chains to no public authority proves nothing and cannot be accepted.
  Emulator: the create SUCCEEDS with HTTP 200 and returns domainConfigurationName plus domainConfigurationArn (arn:aws:iot:<region>:<account>:domainconfiguration/<name>), and the configuration is persisted. In services/service-com-amazonaws-iot-awsiotservice/src/ops/create_domain_configuration.rs the trusted-CA test (`chains_to_a_certificate_authority`) is only reached when `validation_certificate_arn.is_none()`; as soon as ANY validationCertificateArn is present the certificate itself is never inspected, so a self-signed validation certificate waves the create through.
  Why: a client gets a domain configuration AWS would never create. Code that relies on the refusal to catch a mis-issued or self-signed validation certificate sees a healthy ENABLED configuration instead, and devices are expected to trust a domain whose ownership was never proved; the whole negative branch (refusal + absence from Describe/List) becomes unverifiable.
  Fix: the CreateDomainConfiguration handler's certificate-validation path — apply the trusted-CA test to the certificate named by validationCertificateArn (not only to serverCertificateArns when no validation certificate is given) and refuse with the modeled InvalidRequestException before anything is written.
  Traces: iot.domain-configuration-lifecycle (the AWS-managed positive control created and described ENABLED correctly; only the self-signed rejection leg diverges).

Cause 2 of 4: DeleteDomainConfiguration on a name the account holds no configuration under is refused instead of succeeding idempotently.
  Failing check: iot.domain-configuration-lifecycle-transitions.
  AWS: Smithy: DeleteDomainConfiguration -> DELETE /domainConfigurations/{domainConfigurationName}, output is empty, success code 200; ResourceNotFoundException (404) is modeled for it but AWS does not use it for a never-created name. Recorded behavior: deleting a domain configuration that was never created is an idempotent SUCCESS — HTTP 200 with an empty body, no error. Both domain-configuration checks end on exactly this call and treat it as a success; it is the counterpart of the asserted DescribeDomainConfiguration 404 for the same name, i.e. Describe 404s where Delete does not.
  Emulator: HTTP 404 ResourceNotFoundException "Could not find domain configuration for given account ID and domain configuration name, AccountId: <account>, DomainConfigurationName: <name>" (fixed text "Could not find domain configuration for given account ID and domain configuration name, AccountId: " and ", DomainConfigurationName: ", with the caller's account id and the requested name interpolated). services/service-com-amazonaws-iot-awsiotservice/src/ops/delete_domain_configuration.rs removes from `domain_configurations` and, when nothing was removed, returns that error deliberately — its comment contrasts it with the fleet-metric delete.
  Why: idempotent teardown breaks. Cleanup and CloudFormation-style delete paths that call Delete unconditionally (including after a create that AWS refused) now raise where AWS returns 200, so a check or a customer's teardown fails on a resource that is already absent — the state the caller wanted.
  Traces: iot.domain-configuration-lifecycle-transitions (the self-signed-server-certificate refusal, its message, the Describe 404 and the absence from ListDomainConfigurations all passed; the check dies on the final delete). iot.domain-configuration-lifecycle reaches the same call only after Cause 1 is fixed.
  Fix: the DeleteDomainConfiguration handler's not-found path — return the empty 200 output when no record was removed, as the fleet-metric delete already does.

Cause 3 of 4: CreateProvisioningClaim mints a claim certificate that expires one hour after the call instead of the short-lived window AWS issues.
  Failing check: iot.e2e-fleet-provisioning-claim-to-thing.
  AWS: Smithy: CreateProvisioningClaim -> POST /provisioning-templates/{templateName}/provisioning-claim, output certificateId (len 64, ^(0x)?[a-fA-F0-9]+$), certificatePem, keyPair and expiration (timestamp). The model states no validity window, so this is recorded behavior only: the claim is a deliberately SHORT-LIVED credential and the recorded expiration is less than 30 minutes after the call (AWS documents a five-minute provisioning-claim lifetime). The requirement is the bound, not any one recorded instant.
  Emulator: expiration is exactly 3600 s (one hour) after the call — `crate::state::PROVISIONING_CLAIM_VALIDITY` as used in services/service-com-amazonaws-iot-awsiotservice/src/ops/create_provisioning_claim.rs, which sets both the minted certificate's notAfter and the reported expiration. The certificateId shape and the PEM header were correct.
  Why: a claim certificate is a bearer credential handed to an unprovisioned device. A client that treats the returned expiration as the window in which it must complete the fleet-provisioning handshake, or that asserts the credential is short-lived, is told the secret is valid twelve times longer than AWS allows — an emulator that is materially more permissive than production about credential lifetime.
  Fix: the CreateProvisioningClaim handler's validity constant (PROVISIONING_CLAIM_VALIDITY in the iot crate's state module) — set it to AWS's provisioning-claim lifetime (five minutes; in any case under 30 minutes) so the minted certificate's notAfter and the reported expiration both fall inside it.
  Traces: iot.e2e-fleet-provisioning-claim-to-thing (template creation and the claim's id/PEM shape passed; the check dies on the TTL bound before RegisterThing).

Cause 4 of 4: DescribeFleetMetric's ResourceNotFoundException Message does not match the recorded text for four further checks.
  Failing checks: iot.fleet-metric-lifecycle, iot.fleet-metric-lifecycle-and-query, iot.negative-fleet-metric-index-not-ready-blocked, iot.telemetry-fleet-metric-lifecycle-and-aggregation.
  AWS: Smithy: DescribeFleetMetric -> GET /fleet-metric/{metricName}, errors include ResourceNotFoundException (httpError 404). Recorded behavior: these four checks each assert the Error.Message member equals "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: FleetMetric " + <account>:<metricName> + " not found." — fixed text being the whole string apart from <account> (the caller's account id) and <metricName> (the name from the request).
  Emulator: HTTP 404 ResourceNotFoundException with "FleetMetric <account>:<metricName> not found." — exactly the tail of the recorded text, missing the leading "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: " segment. Served from `crate::state::missing_fleet_metric_message` via services/service-com-amazonaws-iot-awsiotservice/src/ops/describe_fleet_metric.rs.
  Why: a client comparing the message against the recorded text does not match. Hypothesis: that leading segment is how botocore renders str(ClientError), so the recorded expectation may encode the rendered exception rather than the Message member — in which case the emulator's tail is already correct. A fixer must confirm against the recording BEFORE prepending the prefix, because emitting the operation name inside the Message member would itself diverge from AWS.
  Related open issue: 20261114T082236Z-iot-refusal-message-fidelity-7-causes-addthingtothinggroup-createstream.md describes this same wording as its Cause 7, but carries only the replay keys of iot.fleet-metric-invalid-aggregation-rejected, iot.telemetry-fleet-metric-invalid-aggregation-rejected and iot.fleet-metric-query-string-preserved. The four checks listed here are NOT in its trace_ids and are not owned by it, so they are filed here to carry their replay keys; closing that issue's Cause 7 should close this one too.
  Fix: the DescribeFleetMetric handler's not-found message (crate::state::missing_fleet_metric_message), only if the recording shows the prefix belongs to the Message member.
  Traces: iot.fleet-metric-lifecycle, iot.fleet-metric-lifecycle-and-query, iot.negative-fleet-metric-index-not-ready-blocked, iot.telemetry-fleet-metric-lifecycle-and-aggregation.

## Evidence
Behavioral suite simparity-behavioral-aws-v1 replayed against the emulator built from this checkout. Total 88/303 passed (29.0%); bootstrap_signal=false. Heading '### iot': 80/215 (37%), 135 failed — the seven checks below are the ones not already owned by an open issue or blocked by an unimplemented scaffold stub.

Cause 1 — [mismatch] iot.domain-configuration-lifecycle:
  File "check_iot_domain_configuration_lifecycle.py", line 59, in run / line 92 in _error_code_and_message
  AssertionError: expected a rejection, but the call SUCCEEDED and returned {'ResponseMetadata': {'HTTPStatusCode': 200, ...}, 'domainConfigurationName': 'sim2real-domain-cfg-<id>', 'domainConfigurationArn': 'arn:aws:iot:<region>:<account>:domainconfiguration/sim2real-domain-cfg-<id>'}
  The refused call: CreateDomainConfiguration(domainConfigurationName=<name>, domainName=<name>.example.com, serverCertificateArns=[<ACM ARN of a self-signed cert>], validationCertificateArn=<ACM ARN of a second self-signed cert>, serviceType='DATA').
  Expected: code InvalidRequestException, Message "Validation certificate must be signed by trusted CA"; then DescribeDomainConfiguration 404 ResourceNotFoundException with "Could not find domain configuration for given account ID and domain configuration name, AccountId: <account>, DomainConfigurationName: <name>"; then DeleteDomainConfiguration succeeds.
  Passed in the same check: the AWS-managed positive control (no domainName) created and DescribeDomainConfiguration reported domainConfigurationStatus ENABLED.

Cause 2 — [error] iot.domain-configuration-lifecycle-transitions:
  botocore.errorfactory.ResourceNotFoundException: An error occurred (ResourceNotFoundException) when calling the DeleteDomainConfiguration operation: Could not find domain configuration for given account ID and domain configuration name, AccountId: <account>, DomainConfigurationName: sim2real-iot-domcfg-<id>
  Reached only after the check's earlier legs PASSED: CreateDomainConfiguration(domainName=..., serverCertificateArns=[self-signed], no validationCertificateArn) was refused InvalidRequestException with the expected message, DescribeDomainConfiguration answered the expected 404, and the name was absent from ListDomainConfigurations. The final line of the check is iot.delete_domain_configuration(domainConfigurationName=name) on that never-created name, which AWS answers 200.
  Handler: services/service-com-amazonaws-iot-awsiotservice/src/ops/delete_domain_configuration.rs lines 145-164 return ResourceNotFoundException when nothing was removed.

Cause 3 — [mismatch] iot.e2e-fleet-provisioning-claim-to-thing:
  File "check_iot_e2e_fleet_provisioning_claim_to_thing.py", line 54, in run
  assert 0 < ttl_seconds < 30 * 60, f"unexpected claim TTL: {ttl_seconds:.0f}s"
  AssertionError: unexpected claim TTL: 3600s
  ttl_seconds = CreateProvisioningClaim(...)['expiration'].timestamp() - time.time(). The 3600 s is the emulator's fixed validity, not a per-run value; the requirement is the bound (under 30 minutes), not a specific instant.
  Passed in the same check: the claim's certificateId matched ^(0x)?[a-fA-F0-9]{64}$ and certificatePem began with "-----BEGIN CERTIFICATE-----".

Cause 4 — four [mismatch] checks, all on DescribeFleetMetric after DeleteFleetMetric:
  iot.fleet-metric-lifecycle: expected message 'An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: FleetMetric <account>:sim2real-fleetmetric-<id> not found.', got 'FleetMetric <account>:sim2real-fleetmetric-<id> not found.'
  iot.fleet-metric-lifecycle-and-query: same expected/actual pair for its own metric name.
  iot.negative-fleet-metric-index-not-ready-blocked: same, asserted at check line 67.
  iot.telemetry-fleet-metric-lifecycle-and-aggregation: AssertionError: expected the exact ResourceNotFoundException message, got 'FleetMetric <account>:sim2real-fleetmetric<id> not found.'
  In all four the error CODE was ResourceNotFoundException as expected, and the preceding legs passed — including, in iot.negative-fleet-metric-index-not-ready-blocked, CreateFleetMetric and GetBucketsAggregation with thing indexing OFF both refusing 404 ResourceNotFoundException "Index AWS_Things does not exist. Please enable index by calling UpdateIndexingConfiguration", and the create/update/list/delete round trip in the other three. The account id and metric names are per-run values filling the message template.

Smithy consulted (services/service-com-amazonaws-iot-awsiotservice/smithy-model/com-amazonaws-iot-awsiotservice.json): CreateDomainConfiguration POST /domainConfigurations/{domainConfigurationName}, 200, errors CertificateValidationException 400 / InvalidRequestException 400 / ResourceAlreadyExistsException 409 / LimitExceededException 410; validationCertificateArn target AcmCertificateArn len 1..2048 with the ACM certificate ARN pattern; serverCertificateArns list len 0..1. DeleteDomainConfiguration DELETE /domainConfigurations/{domainConfigurationName}, output {} with success code 200, errors include ResourceNotFoundException 404. CreateProvisioningClaim POST /provisioning-templates/{templateName}/provisioning-claim with output certificateId/certificatePem/keyPair/expiration and no modeled validity window. DescribeFleetMetric GET /fleet-metric/{metricName}, errors include ResourceNotFoundException 404.

## Steps to Reproduce
Boot the emulator built from this checkout and point botocore iot + acm clients at it. Re-replay the seven checks in trace_ids to confirm all four causes are closed.

Cause 1: acm.import_certificate a self-signed cert for <name>.example.com (server cert) and a second self-signed cert (validation cert). Then CreateDomainConfiguration(domainConfigurationName=<name>, domainName="<name>.example.com", serverCertificateArns=[<server ARN>], validationCertificateArn=[<validation ARN>], serviceType="DATA").
  Expect: HTTP 400 InvalidRequestException, Message "Validation certificate must be signed by trusted CA"; DescribeDomainConfiguration(<name>) then 404 ResourceNotFoundException "Could not find domain configuration for given account ID and domain configuration name, AccountId: <account>, DomainConfigurationName: <name>"; the name absent from ListDomainConfigurations.
  Observe today: HTTP 200 with domainConfigurationName/domainConfigurationArn, and the configuration is describable.

Cause 2: DeleteDomainConfiguration(domainConfigurationName=<a name never created>).
  Expect: HTTP 200, empty body, no error (idempotent), while DescribeDomainConfiguration on the same name stays 404.
  Observe today: HTTP 404 ResourceNotFoundException "Could not find domain configuration for given account ID and domain configuration name, AccountId: <account>, DomainConfigurationName: <name>".

Cause 3: CreateProvisioningTemplate(templateName=T, enabled=True, ...), then CreateProvisioningClaim(templateName=T) and compute expiration - now.
  Expect: a positive TTL well under 30 minutes (AWS's five-minute claim lifetime), and the certificate PEM's notAfter equal to the reported expiration.
  Observe today: exactly 3600 s.

Cause 4: UpdateIndexingConfiguration(thingIndexingConfiguration={'thingIndexingMode':'REGISTRY'}), wait for DescribeIndex('AWS_Things') ACTIVE, CreateFleetMetric(metricName=M, queryString='thingName:*', aggregationType={'name':'Statistics','values':['average']}, period=300, aggregationField='registry.version', indexName='AWS_Things'), DeleteFleetMetric(metricName=M), then DescribeFleetMetric(metricName=M) and read Error.Message. Determine from the recording whether the "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: " segment belongs to the Message member or is botocore's rendering of the exception, and only then change the handler's message.
