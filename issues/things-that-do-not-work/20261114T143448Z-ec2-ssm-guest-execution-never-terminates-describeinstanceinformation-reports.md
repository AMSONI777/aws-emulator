Issue-Severity: CRITICAL
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: ec2__ssm.guest-imdsv1-read-rejected-once-http-tokens-is-required ec2__ssm.guest-user-data-does-not-rerun-after-a-stop-start-cycle ec2__ssm.guest-user-data-output-read-back-through-run-command ec2__ssm.imds-token-ttl-above-21600-seconds-rejected-while-the-maximum-is-served ec2__ssm.run-command-shows-sshd-listening-while-no-group-allows-port-22-from-the-internet ec2__ssm.ssm-send-command-to-a-stopped-instance-rejected-and-no-invocation-is-created ec2__ssm.vscan-inventory-omits-a-host-whose-profile-role-lacks-the-ssm-core-policy-until-it-is-attached ec2__ssm.vscan-run-command-to-an-instance-without-a-profile-rejected-invalid-instance-id ec2__ssm.security-group-no-ingress-keeps-empty-list-and-default-egress ec2__ssm.vscan-inventory-agent-version-matches-the-installed-rpm-on-a-deprecated-ami ec2__ssm.vscan-inventory-platform-and-address-agree-with-ec2 ec2__ssm.start-session-opens-and-terminates-a-channel-to-an-instance-with-no-ingress
Issue-Key: ec2__ssm.guest-imdsv1-read-rejected-once-http-tokens-is-required|_poll#13|Timeout|time.sleep(interval_s)
Issue-Key: ec2__ssm.guest-user-data-does-not-rerun-after-a-stop-start-cycle|_poll#12|Timeout|time.sleep(interval_s)
Issue-Key: ec2__ssm.guest-user-data-output-read-back-through-run-command|_poll#19|Timeout|time.sleep(interval_s)
Issue-Key: ec2__ssm.imds-token-ttl-above-21600-seconds-rejected-while-the-maximum-is-served|_poll#15|Timeout|time.sleep(interval_s)
Issue-Key: ec2__ssm.run-command-shows-sshd-listening-while-no-group-allows-port-22-from-the-internet|_run_shell#10|Timeout|time.sleep(5)
Issue-Key: ec2__ssm.ssm-send-command-to-a-stopped-instance-rejected-and-no-invocation-is-created|_poll#27|Timeout|time.sleep(interval_s)
Issue-Key: ec2__ssm.vscan-inventory-omits-a-host-whose-profile-role-lacks-the-ssm-core-policy-until-it-is-attached|run#19|Timeout|assert _info(ctx, managed) is not None, f"the managed control {managed!r} left the inventory"
Issue-Key: ec2__ssm.vscan-run-command-to-an-instance-without-a-profile-rejected-invalid-instance-id|_poll#14|Timeout|time.sleep(interval_s)
Issue-Key: ec2__ssm.security-group-no-ingress-keeps-empty-list-and-default-egress|run#25|AssertionError|assert never is None, (
Issue-Key: ec2__ssm.vscan-inventory-agent-version-matches-the-installed-rpm-on-a-deprecated-ami|run#13|AssertionError|assert info.get("IsLatestVersion") is False, (
Issue-Key: ec2__ssm.vscan-inventory-platform-and-address-agree-with-ec2|run#14|AssertionError|assert got == want and want, (
Issue-Key: ec2__ssm|StartSession|NotImplemented
Issue-Commit: 09a4de48f58372094bfcb9a0bb2c4d192074b72e

# ec2+ssm: guest execution never terminates, DescribeInstanceInformation reports Online for an egress-less instance, agent version/IsLatestVersion and SourceId are synthetic, and StartSession is a stub

> _Note: this issue was identified against the code base at commit `09a4de48f58372094bfcb9a0bb2c4d192074b72e`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
SendCommand

## Description
Five net-new root causes for this service.

Cause 1 of 5: In-guest execution through SSM Run Command never reaches a terminal status.
AWS: a SendCommand invocation against a managed node advances Pending -> InProgress -> Success/Failed/TimedOut within seconds, and GetCommandInvocation then reports a terminal Status, a real ResponseCode (0 on success) and the guest's StandardOutputContent — which is how IMDSv1/IMDSv2 token behavior, userdata output, sshd state and inventory-after-repair are observed from inside the instance. Smithy: GetCommandInvocation -> Status/StatusDetails/ResponseCode/StandardOutputContent.
Emulator: the invocation is created with HTTP 200 and never advances (Status='Pending', StatusDetails='Pending', ResponseCode=-1, empty ExecutionStartDateTime/StandardOutputContent), so each of these guest-execution checks is killed by the 60 s check budget with "Check timed out after 60.0s".
Why: no client can ever read a command result back from a host; every guest-observed property (IMDS token enforcement, userdata semantics across stop/start, listening ports) is unobservable and polling loops hang.
Fix: the SSM command-invocation state machine behind services/service-com-amazonaws-ssm-amazonssm/src/ops/send_command.rs and the invocation state GetCommandInvocation/ListCommandInvocations read.
Traces: ec2__ssm.guest-imdsv1-read-rejected-once-http-tokens-is-required, ec2__ssm.guest-user-data-does-not-rerun-after-a-stop-start-cycle, ec2__ssm.guest-user-data-output-read-back-through-run-command, ec2__ssm.imds-token-ttl-above-21600-seconds-rejected-while-the-maximum-is-served, ec2__ssm.run-command-shows-sshd-listening-while-no-group-allows-port-22-from-the-internet, ec2__ssm.ssm-send-command-to-a-stopped-instance-rejected-and-no-invocation-is-created, ec2__ssm.vscan-inventory-omits-a-host-whose-profile-role-lacks-the-ssm-core-policy-until-it-is-attached, ec2__ssm.vscan-run-command-to-an-instance-without-a-profile-rejected-invalid-instance-id.

Cause 2 of 5: DescribeInstanceInformation reports an instance as a registered managed node even when it has no network path to the SSM endpoint.
AWS: SSM Agent registers by calling the SSM service outbound. An instance whose only security group has ZERO egress rules cannot reach the endpoint, so it never appears in DescribeInstanceInformation (and the operation returns an empty list for it, not a synthesized row). Smithy: DescribeInstanceInformation -> InstanceInformationList of InstanceInformation{PingStatus, LastPingDateTime, AgentVersion, RegistrationDate, ...}.
Emulator: the instance is reported with PingStatus='Online', a LastPingDateTime, AgentVersion and RegistrationDate, i.e. registration is synthesized from the launch rather than derived from reachability.
Why: reachability and least-privilege-network tests pass against the emulator and fail on AWS; an operator cannot use managed-node presence as evidence that the host actually has egress to Systems Manager.
Fix: the managed-node registration/ping state feeding services/service-com-amazonaws-ssm-amazonssm/src/ops/describe_instance_information.rs must be gated on the instance's effective egress path to the SSM endpoint.
Traces: ec2__ssm.security-group-no-ingress-keeps-empty-list-and-default-egress.

Cause 3 of 5: InstanceInformation.IsLatestVersion is always true and AgentVersion is constant, regardless of the AMI the node booted.
AWS: AgentVersion is the SSM Agent version actually installed on the node — an older/deprecated AMI bundles an older agent — and IsLatestVersion is false when that version trails the current release. Smithy: InstanceInformation.AgentVersion (pattern ^[0-9]{1,6}(\.[0-9]{1,6}){2,3}$) and InstanceInformation.IsLatestVersion ("Indicates whether the latest version of SSM Agent is running").
Emulator: a node launched from a deprecated AMI reports the same AgentVersion as a current-AMI node and IsLatestVersion=True.
Why: patch/vulnerability tooling that selects nodes whose agent trails the current release finds none, so a fleet that needs an agent upgrade looks healthy.
Fix: derive AgentVersion from the AMI/instance state and compute IsLatestVersion against the catalog's current agent release in the DescribeInstanceInformation handler.
Traces: ec2__ssm.vscan-inventory-agent-version-matches-the-installed-rpm-on-a-deprecated-ami.

Cause 4 of 5: InstanceInformation omits SourceId for an EC2 managed node.
AWS (recorded behavior; the model defines the member but not this value): for the same instance, the SSM inventory row's SourceId equals the EC2 instance id, so inventory and EC2 agree on the resource identity. Smithy: InstanceInformation.SourceId (length 0-128, pattern ^[a-zA-Z0-9:_-]*$) and SourceType.
Emulator: the row carries InstanceId/PingStatus/AgentVersion/PlatformType/IPAddress/ComputerName but no SourceId at all (and no PlatformName/PlatformVersion/IamRole), so the join against EC2 on SourceId fails with None.
Why: a client correlating SSM inventory rows with EC2 resources on SourceId gets nothing to join on.
Fix: populate SourceId (and the companion source/platform members) when projecting managed-node state in the DescribeInstanceInformation handler.
Traces: ec2__ssm.vscan-inventory-platform-and-address-agree-with-ec2.

Cause 5 of 5: StartSession answers NotImplemented, so a Session Manager channel to an instance can never be opened or terminated.
AWS: StartSession on a managed node returns SessionId, TokenValue and StreamUrl, and TerminateSession then closes it; a node with no inbound ingress is still reachable this way.
Emulator: StartSession returns the scaffold refusal — error code 'NotImplemented', message "operation StartSession is scaffolded but not implemented in this emulator" — which is not an AWS error code for this operation.
Why: Session Manager is the documented way to reach a host with no inbound rules; every such workflow fails with an error code no AWS SDK models.
Fix: implement services/service-com-amazonaws-ssm-amazonssm/src/ops/start_session.rs (the same stub is already filed for the ssm service by the suite's auto-filed scaffold issue; this entry records the ec2__ssm check whose replay key is not carried by it).
Traces: ec2__ssm.start-session-opens-and-terminates-a-channel-to-an-instance-with-no-ingress.

## Evidence
Cause 1: eight checks end with "Error: Check timed out after 60.0s" while polling for a terminal invocation status; the stuck payload observed by sibling checks is {'Status': 'Pending', 'StatusDetails': 'Pending', 'ResponseCode': -1, 'ExecutionStartDateTime': '', 'StandardOutputContent': ''} with HTTP 200. Expected a terminal Status with ResponseCode 0 and stdout.
Cause 2: "an instance whose only group has ZERO egress rules has no path out at all, so it must never phone the SSM service; DescribeInstanceInformation reported it anyway: {'InstanceId': 'i-<id>', 'PingStatus': 'Online', 'AgentVersion': '3.3.2746.0', 'IsLatestVersion': True, 'PlatformType': 'Linux', 'ResourceType': 'EC2Instance', 'IPAddress': '10.x.x.x', 'ComputerName': 'ip-10-x-x-x...'}". Expected: that instance absent from InstanceInformationList. (Instance id, address and timestamps are per-run values.)
Cause 3: "an agent bundled with 'amzn2-ami-hvm-2.0.20251020.0-x86_64-gp2' (deprecated <date>) must be flagged as not the latest release; IsLatestVersion was True".
Cause 4: "SSM SourceId None must equal EC2's 'i-<id>' for the same instance; row {... no SourceId ...}".
Cause 5: "botocore.exceptions.ClientError: An error occurred (NotImplemented) when calling the StartSession operation: operation StartSession is scaffolded but not implemented in this emulator". Expected: a SessionId/TokenValue/StreamUrl, then TerminateSession.

## Steps to Reproduce
Cause 1: launch an instance with AmazonSSMManagedInstanceCore, SendCommand('AWS-RunShellScript', ['curl -s http://169.254.169.254/latest/meta-data/instance-id']) and poll GetCommandInvocation — Status stays 'Pending', ResponseCode -1.
Cause 2: create a security group with no egress rules, launch an instance whose only group is that one, then DescribeInstanceInformation — the instance is listed with PingStatus 'Online'.
Cause 3: launch one instance from the current AL2 AMI and one from a deprecated AL2 AMI, DescribeInstanceInformation both — AgentVersion is identical and IsLatestVersion is True for both.
Cause 4: DescribeInstanceInformation for an EC2 managed node — the row has no SourceId key.
Cause 5: ssm StartSession(Target=<instance id>) — returns NotImplemented.
