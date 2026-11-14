Issue-Severity: MEDIUM
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: lambda-core.network-connector-lifecycle-round-trip lambda-core.delete-releases-connector-name-for-reuse
Issue-Shape-Id: com.amazonaws.lambdacore#LambdaCoreApiService
Issue-Key: lambda-core.network-connector-lifecycle-round-trip|_assert_not_found#37|AssertionError|assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'
Issue-Key: lambda-core.delete-releases-connector-name-for-reuse|run#27|AssertionError|assert dead_update == ("ResourceNotFoundException", f"Network connector not found: {first_id}"), (
Issue-Commit: 6533a5364fe9b92c8a3d23732cb80de0d1d9d8ab

# lambda-core UpdateNetworkConnector's not-found refusal expands the request's Id to an ARN, where AWS names the identifier as supplied

> _Note: this issue was identified against the code base at commit `6533a5364fe9b92c8a3d23732cb80de0d1d9d8ab`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
UpdateNetworkConnector

## Description
One net-new root cause on lambda-core's network-connector update path (com.amazonaws.lambdacore#LambdaCoreApiService), grounded in the two failing lambda-core checks that are neither ALREADY FILED nor OWNED in this replay.

Cause 1 of 1 - UpdateNetworkConnector on an identifier that names no (longer any) connector is correctly refused HTTP 404 / ResourceNotFoundException, but the message no longer states the identifier the request carried: a request addressed by the connector's bare Id is refused naming the full connector ARN that Id determines, where AWS names the Id exactly as supplied.

AWS: Smithy UpdateNetworkConnector (PUT /2026-04-04/network-connectors/{Identifier}, success 202) takes Identifier -> NetworkConnectorIdentifier (@httpLabel, @required, @length 1..140), documented as "The identifier of the network connector to update. You can specify the connector ID, name, or full ARN", and models ResourceNotFoundException at httpError 404 ("The specified network connector does not exist. Verify the identifier (ID, name, or ARN) and Region"). The model does not state the message text, so: recorded behavior only - an UpdateNetworkConnector whose target connector has already been deleted is refused 404 / ResourceNotFoundException with Message "Network connector not found: <the identifier the request carried>". In that message "Network connector not found: " is FIXED text and the single variable part is the request's own Identifier member, restated verbatim - a bare Id stays a bare Id, a name stays a name, an ARN stays that ARN. The recordings separate this from the READ path on the very same resource in the same run: GetNetworkConnector on the removed bare Id is refused naming the ARN the Id determines (arn:aws:lambda:<region>:<account-id>:network-connector:<Id>), while GetNetworkConnector addressed by name or by ARN restates the form supplied - so the Id-to-ARN expansion is not a service-wide rule that the write path may inherit.

Emulator: UpdateNetworkConnector's three not-found arms all build the payload with crate::state::connector_not_found(&region, &input.identifier), the helper that resolves an Id to its ARN. Replaying both checks, the status (404) and the error code (ResourceNotFoundException) are right and the message reads 'Network connector not found: arn:aws:lambda:us-west-2:000000000000:network-connector:nc-0000000000000001' where the requirement is 'Network connector not found: nc-0000000000000001' - the Identifier as sent. (The region, account and connector id above are per-run values filling the template; the divergence is that the supplied Id is expanded to ARN form at all.) The same helper's doc comment asserts the resolution rule is identifier-derived and therefore "one rule answers for a read and for a write alike" - the recordings contradict exactly that generalisation, which is how the fix for the delete path's ARN form (see below) over-reached onto update.

Why: the refusal message is the only thing that says WHICH resource the service considers absent. A client that holds the Id it just called with - the overwhelmingly common case, since Update is addressed by the same Id the create returned - compares the refusal against that Id and sees a resource it never named. Teardown and negative-path assertions of the form "delete the connector, confirm it is gone, assert a mutation on the dead Id is refused for that Id" fail against a conforming expectation, and message parsers that extract the subject to correlate with their own inventory get an ARN where they indexed an id. It also makes the update refusal indistinguishable from one for an ARN-addressed request, erasing the request-echo property AWS keeps.

Fix: lambda-core's UpdateNetworkConnector handler error construction - all three ResourceNotFoundException arms (the pre-validation lookup, the missing-current-version arm, and the re-lookup after the out-of-lock EC2/IAM resolutions) must state the request's Identifier verbatim (the verbatim formatter behind crate::state::connector_not_found's not_found(...) arm) instead of going through the Id-to-ARN resolution used by the read path. This is a refusal-message/serialization defect in that handler, not a state or lifecycle one: the 404 classification, the ordering and the state transitions are already correct. The shared helper's doc comment, which claims the resolution rule is operation-independent, has to be corrected with it so the read path's ARN form (which is right) is not re-applied to writes.

Relation to what is already filed: open issue 20261113T061803Z-lambda-core-deletenetworkconnector-s-post-removal-404-names.md asked for the OPPOSITE resolution on DeleteNetworkConnector (Id -> ARN) and is a different operation and a different replay key; it does not cover UpdateNetworkConnector and neither does open issue 20261023T022015Z-lambda-core-admits-requests-aws-refuses-and-misclassifies.md, whose UpdateNetworkConnector cause is about a missing ClientToken being answered 404 instead of 400. The fixed issue 20261023T022015Z-lambda-core-rejection-messages-diverge-from-aws-not.md established the "Network connector not found: <identifier>" wording but not which identifier form each operation states. No open issue carries either of these replay keys.

Traces: lambda-core.network-connector-lifecycle-round-trip (gone beat 3: UpdateNetworkConnector on the deleted connector), lambda-core.delete-releases-connector-name-for-reuse (the mutation on the dead id).

## Evidence
Behavioral suite simparity-behavioral-aws-v1 replayed against the emulator built from this checkout: 24/33 passed (72.7%), lambda-core 24/28 (86%), bootstrap_signal false. Of lambda-core's four failures, two are OWNED (network-connector-create-nonexistent-subnet-rejected, network-connector-dualstack-network-protocol-persists); the two below are the remainder. Every failing check under cloudformation__ec2__lambda-core, cloudtrail__lambda-core and lambda-core__lambda-microvms is marked OWNED.

[mismatch] lambda-core.network-connector-lifecycle-round-trip
  File "check_lambda_core_network_connector_lifecycle_round_trip.py", line 307, in run
    _assert_not_found(..., "UpdateNetworkConnector on the deleted connector", expected_message=f"Network connector not found: {ident}")
  AssertionError: expected the message 'Network connector not found: nc-0000000000000001', got 'Network connector not found: arn:aws:lambda:us-west-2:000000000000:network-connector:nc-0000000000000001'

  The check reached this assertion having passed every earlier leg, INCLUDING the read-path refusals on the same removed connector: GetNetworkConnector on the bare Id was accepted as 'Network connector not found: <created Arn>' (the ARN form, which the emulator gets right), and Get by name and by ARN restated the form supplied. Only the UpdateNetworkConnector message differs.

[mismatch] lambda-core.delete-releases-connector-name-for-reuse
  File "check_lambda_core_delete_releases_connector_name_for_reuse.py", line 129, in run
    assert dead_update == ("ResourceNotFoundException", f"Network connector not found: {first_id}")
  AssertionError: UpdateNetworkConnector on the deleted id 'nc-0000000000000001' returned ('ResourceNotFoundException', 'Network connector not found: arn:aws:lambda:us-west-2:000000000000:network-connector:nc-0000000000000001'), expected ('ResourceNotFoundException', 'Network connector not found: ...')

Expected (AWS): HTTP 404, Error.Code 'ResourceNotFoundException', Error.Message == 'Network connector not found: ' + the request's Identifier verbatim. Fixed text: 'Network connector not found: '. Variable part: the Identifier member of the request (a bare Id when the caller addressed the connector by Id, a name when by name, an ARN when by ARN).
Actual (emulator): HTTP 404, Error.Code 'ResourceNotFoundException', Error.Message 'Network connector not found: arn:aws:lambda:<region>:<account-id>:network-connector:<Id>' for an Id-addressed request.

Code: services/service-com-amazonaws-lambdacore-lambdacoreapiservice/src/ops/update_network_connector.rs lines 296-301 (first lookup), 316-320 (missing current version) and 417-422 (re-lookup after the out-of-lock resolutions) all call crate::state::connector_not_found(&region, &input.identifier); services/service-com-amazonaws-lambdacore-lambdacoreapiservice/src/state.rs lines 612-622 (the Id-to-ARN resolution), 626-633 (not_found, the verbatim formatter), 584-586 (connector_arn), and the doc comment at lines 595-611 that generalises the read path's rule to writes.

## Steps to Reproduce
1. git_clone, then run_behavioral_suite() and look at lambda-core.network-connector-lifecycle-round-trip (fails at its gone-beat-3 Update assertion) and lambda-core.delete-releases-connector-name-for-reuse (fails at its dead-id Update assertion).
2. Or by hand against the booted emulator (region us-west-2):
   a. Create a VPC, a subnet in it and a security group, plus an IAM role trusting lambda.amazonaws.com with the Lambda VPC-access policy attached.
   b. POST /2026-04-04/network-connectors with Name=<unique>, OperatorRole=<roleArn>, Configuration={"VpcEgressConfiguration":{"SubnetIds":[<subnetId>],"SecurityGroupIds":[<sgId>],"NetworkProtocol":"IPv4","AssociatedComputeResourceTypes":["MicroVm"]}}. Note the returned Id and Arn.
   c. Poll GET /2026-04-04/network-connectors/<Id> until State is ACTIVE.
3. DELETE /2026-04-04/network-connectors/<Id>, then poll GET /2026-04-04/network-connectors/<Id> until it answers 404 ResourceNotFoundException (the removal has completed).
4. PUT /2026-04-04/network-connectors/<Id> with the same Configuration. Expect HTTP 404 / ResourceNotFoundException with Message 'Network connector not found: <Id>'. Observe 'Network connector not found: arn:aws:lambda:us-west-2:<account-id>:network-connector:<Id>'.
5. Contrast the cases that must NOT change: GET on the removed <Id> keeps naming the ARN the Id determines, and GET addressed by the connector's name or ARN keeps restating the form supplied - so only the update path's identifier resolution changes.
