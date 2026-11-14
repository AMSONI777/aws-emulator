Issue-Source: trace-sweep-divergence
Issue-Trace: emr-run-job-flow-step-writes-s3-output
Issue-Step: teardown#37
Issue-Severity: HIGH
Issue-Corpus: simparity-wire-aws-v1
Issue-Corpus-Kind: wire
Issue-Trace-Ids: emr-run-job-flow-step-writes-s3-output
Issue-Shape-Id: com.amazonaws.emr#ElasticMapReduce
Issue-Key: ec2|DetachInternetGateway|2xx->4xx|status
Issue-Key: ec2|DeleteInternetGateway|2xx->4xx|status
Issue-Key: ec2|DescribeNetworkInterfaces|2xx->2xx|$
Issue-Related: 20261103T123451Z-ec2-reads-resolve-resources-outside-the-request-s.md
Issue-Commit: 2936d3a144ae5eebae9f6b7387af703153caab29

# ec2 VPC teardown never converges: internet-gateway detach/delete refused and a terminated instance's ENI is never released (3 causes)

> _Note: this issue was identified against the code base at commit `2936d3a144ae5eebae9f6b7387af703153caab29`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
DetachInternetGateway

## Description
Three net-new causes in the ec2 service, all sharing one fault: the teardown half of a VPC's lifecycle does not converge. Two gateway lifecycle calls that AWS answers 200 are refused with HTTP 400, and the primary elastic network interface of an instance that has already been terminated is never released, so dependency-ordered teardown can never finish. The fixture's earlier steps all pass, so this is purely the release path.

Cause 1 of 3 — DetachInternetGateway refuses the detach of an attached internet gateway with HTTP 400.
AWS: DetachInternetGateway takes InternetGatewayId and VpcId (Smithy: DetachInternetGatewayRequest.InternetGatewayId and .VpcId, both @required; output shape Unit, errors [] — refusals come from EC2's common client-error set, e.g. Gateway.NotAttached, InvalidInternetGatewayID.NotFound, DependencyViolation). When the named gateway IS attached to the named VPC and no instance in the VPC still has a public address mapped, the call succeeds with HTTP 200 and an empty DetachInternetGatewayResponse carrying return 'true'. The recording shows exactly that: status 200.
Emulator: answers HTTP 400 for the detach of the gateway it itself attached earlier in the same fixture (the AttachInternetGateway step passed).
Why: a client doing ordered teardown (detach gateway -> delete gateway -> delete subnets -> delete VPC) is blocked at the first step and cannot tell a genuine DependencyViolation from an emulator refusal, because no error body distinguishes them. Every repeated run leaks a gateway and the VPC can never be deleted.
Fix: the DetachInternetGateway handler and its dependency/attachment bookkeeping in state — the attachment record is not resolvable for detach, or a stale dependent (the terminated instance of cause 3) still blocks it.
Traces: emr-run-job-flow-step-writes-s3-output#teardown#37.

Cause 2 of 3 — DeleteInternetGateway refuses the delete of a gateway with no remaining attachments with HTTP 400.
AWS: DeleteInternetGateway takes only InternetGatewayId (Smithy: DeleteInternetGatewayRequest.InternetGatewayId @required; output Unit, errors [] — refusals are the common client errors, DependencyViolation when the gateway is still attached to a VPC, InvalidInternetGatewayID.NotFound when the id does not exist). Once the gateway is detached, the delete returns HTTP 200 with an empty DeleteInternetGatewayResponse carrying return 'true'. The recording shows status 200.
Emulator: answers HTTP 400.
Why: the gateway is unreleasable, so the owning VPC stays undeletable and the account never returns to a clean state. As with cause 1 the 400 carries nothing that lets a client distinguish 'still attached' from 'unknown id'.
Fix: the DeleteInternetGateway handler and the attachment-reference bookkeeping in state it consults.
Traces: emr-run-job-flow-step-writes-s3-output#teardown#38.

Cause 3 of 3 — a terminated instance's primary ENI is never deleted, so a filtered DescribeNetworkInterfaces never drains.
AWS: an instance's primary network interface is created by the launch with Attachment.DeleteOnTermination true, so when the instance is terminated EC2 detaches and deletes that interface. A DescribeNetworkInterfaces read filtered on the instance's subnet therefore converges to HTTP 200 with an EMPTY networkInterfaceSet (Smithy: DescribeNetworkInterfacesResult.NetworkInterfaces, xmlName networkInterfaceSet; errors [] — the operation always answers 200 for a legal filter). The recording polls exactly this: the set reaches zero items.
Emulator: for the whole 180s poll window (13 attempts) DescribeNetworkInterfaces keeps returning one item for the terminated instance's interface, with attachment status 'attached' (deleteOnTermination 'true'), interface status 'in-use' and a public-IP association still present. The interface is never detached and never deleted.
Why: a client that waits for ENIs to drain before deleting the subnet/VPC — the documented and only reliable teardown order — waits forever, and anything that counts interfaces in use (quota checks, IP-exhaustion logic) sees phantom consumption. It also plausibly causes causes 1 and 2: a lingering attached ENI with a public association is exactly what would make the emulator treat the gateway as still in use. Hypothesis: TerminateInstances does not run the delete-on-termination release for the primary interface.
Why the per-run values are NOT the requirement: the recorded interface id, attachment id, MAC, private/public addresses, subnet/vpc ids, availability zone and requestId differ in every environment; the requirement is only that the set becomes empty after the instance reaches terminated.
Fix: the TerminateInstances handler's instance-teardown path in state (release of attachments whose deleteOnTermination is true), and the ENI projection DescribeNetworkInterfaces reads from.
Traces: emr-run-job-flow-step-writes-s3-output#teardown#32.

Related but NOT covering these: open issue 20261103T123451Z-ec2-refuses-valid-requests-with-400-or-501.md owns the DeleteSubnet/DeleteVpc 400s of this same teardown (steps teardown#35 and teardown#39) but not the internet-gateway pair; 20261105T144252Z-ec2-route-table-and-vpc-endpoint-lifecycle-operations.md owns the route-table delete; 20261112T213706Z-ec2-never-releases-elb-managed-enis-so-subnet.md is about ELB-MANAGED interfaces, not an instance's own delete-on-termination primary ENI; 20261109T233927Z-ec2-revokesecuritygroupingress-answers-400-for-a-rule-teardown.md owns the ingress revokes. None of them carries the replay keys named above.

## Evidence
Replay of simparity-wire-aws-v1 against the emulator (emulator_up true, score 86.0%).

Cause 1 — ec2 DetachInternetGateway, fixture emr-run-job-flow-step-writes-s3-output step teardown#37: divergence key 'service=ec2|DetachInternetGateway|status=200->400|keys=status'. Expected HTTP 200 (empty success body, return 'true'); actual HTTP 400. Single-step cluster.

Cause 2 — ec2 DeleteInternetGateway, same fixture step teardown#38: divergence key 'service=ec2|DeleteInternetGateway|status=200->400|keys=status'. Expected HTTP 200 (empty success body, return 'true'); actual HTTP 400. Single-step cluster.

Cause 3 — ec2 DescribeNetworkInterfaces, same fixture step teardown#32: divergence key 'service=ec2|DescribeNetworkInterfaces|status=200->200|keys=$,$.DescribeNetworkInterfacesResponse.networkInterfaceSet'. Detail: 'poll capped at 180s' and '$.DescribeNetworkInterfacesResponse.networkInterfaceSet: poll: 1 item(s), not 0 after 13 attempt(s)'. Expected the set to drain to zero items after the instance was terminated; actual a single item persisting with attachment.status 'attached', attachment.deleteOnTermination 'true', status 'in-use' and an association carrying a public IPv4. The concrete interface/attachment/address/subnet/vpc ids and the requestId in that payload are per-run values and are not part of the requirement.

## Steps to Reproduce
1. Replay the wire corpus simparity-wire-aws-v1 against the emulator.
2. Inspect fixture emr-run-job-flow-step-writes-s3-output:
   - step teardown#32: after TerminateInstances, poll DescribeNetworkInterfaces filtered on the launch subnet and watch for the networkInterfaceSet to empty — it stays at 1 item for the full 180s.
   - step teardown#37: DetachInternetGateway with the fixture's InternetGatewayId + VpcId (the pair AttachInternetGateway accepted earlier in the same fixture) — expect 200, observe 400.
   - step teardown#38: DeleteInternetGateway with that same gateway id — expect 200, observe 400.
3. Equivalent by hand: create a VPC + subnet + internet gateway, attach the gateway, run an instance in the subnet, terminate it, wait for its ENI to disappear from DescribeNetworkInterfaces, then detach and delete the gateway. Each of the three reads/calls diverges as above.
