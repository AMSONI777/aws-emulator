Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: cloudformation__ec2__ssm.cfn-deploy-ssm-document-association-ec2-positive cloudformation__ec2__ssm.cfn-ec2-instance-profile-enables-ssm-agent-registration-positive cloudformation__ec2__ssm.cfn-ec2-tag-propagation-to-ssm-inventory-positive cloudformation__ec2__ssm.cfn-ssm-association-missing-target-tag-negative cloudformation__ec2__ssm.cfn-ssm-document-wrong-instance-tag-key-negative cloudformation__ec2__ssm.cfn-ssm-parameter-referenced-in-ec2-userdata-positive cloudformation__ec2__ssm.cfn-update-ec2-instance-type-triggers-ssm-reregistration-positive cloudformation__ec2__ssm.cli-script-cfn-deploy-ec2-then-ssm-command-positive cloudformation__ec2__ssm.cli-script-cfn-update-stack-security-group-blocks-ssm-negative cloudformation__ec2__ssm.cli-script-ssm-command-denied-without-iam-role-negative cloudformation__ec2__ssm.deploy-ec2-3-group-rename-replaces-the-group-and-source-group-rule-still-drops-an-unrelated-instance cloudformation__ec2__ssm.deploy-ec2-3-instance-type-update-reboots-in-place-tags-do-not-drift-tracks-out-of-band-ingress cloudformation__ec2__ssm.sdk-ssm-command-output-retrieved-from-ec2-positive cloudformation__ec2__ssm.sdk-ssm-encrypted-parameter-used-in-ec2-launch-positive cloudformation__ec2__ssm.sdk-ssm-list-command-invocations-scoped-to-ec2-instance-positive cloudformation__ec2__ssm.sdk-ssm-missing-sendcommand-permission-negative cloudformation__ec2__ssm.sdk-ssm-run-command-timeout-on-stopped-ec2-negative cloudformation__ec2__ssm.sdk-ssm-send-command-executes-on-ec2-instance-positive
Issue-Key: cloudformation__ec2__ssm.cfn-deploy-ssm-document-association-ec2-positive|_poll_until#10|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.cfn-ec2-instance-profile-enables-ssm-agent-registration-positive|_poll_until#9|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.cfn-ec2-tag-propagation-to-ssm-inventory-positive|run#15|AssertionError|assert got_ids == [instance_id], (
Issue-Key: cloudformation__ec2__ssm.cfn-ssm-association-missing-target-tag-negative|_poll_until#12|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.cfn-ssm-document-wrong-instance-tag-key-negative|_poll_until#12|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.cfn-ssm-parameter-referenced-in-ec2-userdata-positive|_poll_until#12|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.cfn-update-ec2-instance-type-triggers-ssm-reregistration-positive|run#15|AssertionError|assert stack["StackStatus"] == "UPDATE_COMPLETE", (
Issue-Key: cloudformation__ec2__ssm.cli-script-cfn-deploy-ec2-then-ssm-command-positive|_poll_until#21|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.cli-script-cfn-update-stack-security-group-blocks-ssm-negative|run#21|AssertionError|assert upd_status == "UPDATE_COMPLETE", f"stack update did not complete: {upd_status}"
Issue-Key: cloudformation__ec2__ssm.cli-script-ssm-command-denied-without-iam-role-negative|_poll_until#26|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.deploy-ec2-3-group-rename-replaces-the-group-and-source-group-rule-still-drops-an-unrelated-instance|_run_shell#19|AssertionError|raise AssertionError(f"command on {instance_id} never succeeded within {timeout_s}s: {last!r}")
Issue-Key: cloudformation__ec2__ssm.deploy-ec2-3-instance-type-update-reboots-in-place-tags-do-not-drift-tracks-out-of-band-ingress|_run_shell#18|Timeout|time.sleep(3)
Issue-Key: cloudformation__ec2__ssm.sdk-ssm-command-output-retrieved-from-ec2-positive|_poll_invocation#10|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.sdk-ssm-encrypted-parameter-used-in-ec2-launch-positive|_poll_invocation#17|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.sdk-ssm-list-command-invocations-scoped-to-ec2-instance-positive|_poll_invocation#12|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.sdk-ssm-missing-sendcommand-permission-negative|_client_error#11|AssertionError|raise AssertionError(f"expected SendCommand to be denied, but it SUCCEEDED and returned {result!r}")
Issue-Key: cloudformation__ec2__ssm.sdk-ssm-run-command-timeout-on-stopped-ec2-negative|_poll_invocation#9|Timeout|time.sleep(interval_s)
Issue-Key: cloudformation__ec2__ssm.sdk-ssm-send-command-executes-on-ec2-instance-positive|_poll_invocation#11|Timeout|time.sleep(interval_s)
Issue-Commit: 743af1aef2870b34c6c9092ae87b31cfc860bafb

# cloudformation__ec2__ssm: 6 net-new causes — SSM Run Command never executes on an instance, State Manager associations never execute, DescribeInstanceInformation ignores tag filters, two EC2 stack updates roll back, and SendCommand performs no IAM authorization

> _Note: this issue was identified against the code base at commit `743af1aef2870b34c6c9092ae87b31cfc860bafb`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
SendCommand

## Description
Six distinct root causes in the CloudFormation+EC2+SSM surface. All six must be closed before this issue is submitted; each names its own failing checks.

Cause 1 of 6 — SSM Run Command is accepted but never executed on the instance.
AWS: SendCommand returns a Command whose Status is Pending, the agent on the targeted managed instance picks the command up, and GetCommandInvocation/ListCommandInvocations move that invocation to a terminal Status (Success for a shell script that runs), with ResponseCode 0 and StandardOutputContent carrying what the script printed on the guest. Recorded behavior: the invocation reaches Success and stdout is the real output of the command (e.g. the path `ls` echoes back).
Emulator: SendCommand answers 200 with Status 'Pending'/StatusDetails 'Pending' (see the response quoted in the evidence) and nothing further happens: no invocation ever reaches a terminal state, GetCommandInvocation yields nothing usable, and no command runs on the guest. One check states it outright — "command on i-... never succeeded within 45.53s: None" — and every other check that must run a shell command on an instance exhausts its budget while polling for completion ("Check timed out after 60.0s"); one of them stalls immediately after DescribeInstanceInformation has already reported the instance Online, which rules out registration as the stall point.
Why: Run Command is the only way these clients reach inside an instance. A caller sees a command accepted and then never completing: no output, no failure, no terminal status — so nothing built on Run Command (bootstrapping, patch scans, remote probes, CLI `ssm send-command` + `wait`) can ever finish or be tested.
Fix: the SSM Run Command data plane — the SendCommand handler plus the invocation state machine behind GetCommandInvocation/ListCommandInvocations/ListCommands — must drive an accepted command to a terminal invocation with ResponseCode and captured stdout/stderr for the targeted instance.
Traces: cloudformation__ec2__ssm.deploy-ec2-3-group-rename-replaces-the-group-and-source-group-rule-still-drops-an-unrelated-instance, .cfn-ec2-instance-profile-enables-ssm-agent-registration-positive, .cfn-ssm-parameter-referenced-in-ec2-userdata-positive, .cli-script-cfn-deploy-ec2-then-ssm-command-positive, .cli-script-ssm-command-denied-without-iam-role-negative, .deploy-ec2-3-instance-type-update-reboots-in-place-tags-do-not-drift-tracks-out-of-band-ingress, .sdk-ssm-command-output-retrieved-from-ec2-positive, .sdk-ssm-encrypted-parameter-used-in-ec2-launch-positive, .sdk-ssm-list-command-invocations-scoped-to-ec2-instance-positive, .sdk-ssm-run-command-timeout-on-stopped-ec2-negative, .sdk-ssm-send-command-executes-on-ec2-instance-positive.

Cause 2 of 6 — State Manager associations never execute.
AWS: an AWS::SSM::Association created by CloudFormation against a tag target is scheduled; DescribeAssociation's Overview.Status moves to Success (or Failed), DescribeAssociationExecutions records at least one execution even when the target set is empty, and DescribeAssociationExecutionTargets resolves the matched instance ids. Recorded behavior only for the exact Overview payloads.
Emulator: the association's Overview never leaves its initial state, so every check that waits for Overview.Status in {Success, Failed} exhausts its budget; no association execution is ever observable.
Why: a client cannot tell a scheduled association from an inert record, and the whole tag-targeting contract (an association that matches resolves its targets; one that matches nothing records an execution with zero targets) is unobservable.
Fix: the SSM State Manager association scheduler/state machine behind DescribeAssociation (Overview), DescribeAssociationExecutions and DescribeAssociationExecutionTargets must actually run an association against its resolved targets.
Traces: cloudformation__ec2__ssm.cfn-deploy-ssm-document-association-ec2-positive, .cfn-ssm-association-missing-target-tag-negative, .cfn-ssm-document-wrong-instance-tag-key-negative.

Cause 3 of 6 — DescribeInstanceInformation ignores tag: filters.
AWS: DescribeInstanceInformation supports tag-key filters; Filters=[{"Key": "tag:<Key>", "Values": [<value>]}] resolves to the managed instances carrying that EC2 tag — here the single CloudFormation-tagged instance. Filtering by InstanceIds works in the emulator (other checks get Online back through it), so the instance IS registered; only the tag filter fails.
Emulator: the same call returns an empty InstanceInformationList.
Why: tag-based targeting is how SSM inventory and association/maintenance-window targets are selected. A client filtering by tag sees no managed instances at all and concludes the fleet is empty.
Fix: the DescribeInstanceInformation handler's filter evaluation in the ssm service must match tag: filters against the instance's EC2 tags.
Traces: cloudformation__ec2__ssm.cfn-ec2-tag-propagation-to-ssm-inventory-positive.

Cause 4 of 6 — a stack update that must replace an EC2 instance (AMI change) rolls back.
AWS: UpdateStack whose only change is the instance's ImageId replaces the AWS::EC2::Instance: the stack reaches UPDATE_COMPLETE, the old instance id goes to shutting-down/terminated, and the new id appears in the stack outputs.
Emulator: the update ends UPDATE_ROLLBACK_COMPLETE, so the replacement never happens.
Why: AMI roll-forward is a routine update; a client that changes an AMI gets a failed, rolled-back stack and cannot replace an instance at all.
Fix: the CloudFormation AWS::EC2::Instance resource handler's update/replacement path (create-new-then-delete-old for the create-only ImageId property) must carry the update to completion instead of failing it.
Traces: cloudformation__ec2__ssm.cfn-update-ec2-instance-type-triggers-ssm-reregistration-positive.

Cause 5 of 6 — a stack update that changes a security group's egress rules rolls back.
AWS: UpdateStack that narrows an AWS::EC2::SecurityGroup's egress (dropping outbound 443 from the target instance's group) completes in place: the stack reaches UPDATE_COMPLETE and the new rule set is live.
Emulator: the update ends UPDATE_ROLLBACK_COMPLETE.
Why: a client cannot modify security-group rules through CloudFormation; the stack is left at its old rules and reports a failed update, and security changes delivered as template edits silently do not apply.
Fix: the CloudFormation AWS::EC2::SecurityGroup resource handler's in-place update path for egress/ingress rule changes.
Traces: cloudformation__ec2__ssm.cli-script-cfn-update-stack-security-group-blocks-ssm-negative.

Cause 6 of 6 — SendCommand performs no IAM authorization.
AWS: a caller whose identity policy explicitly denies ssm:SendCommand is refused with HTTP 400 and error code AccessDeniedException; the message is AWS's standard explicit-deny sentence "User: <caller arn> is not authorized to perform: ssm:SendCommand on resource: <instance arn> with an explicit deny in an identity-based policy" — the fixed text is everything but the two ARNs, which come from the request's credentials and its target instance (here arn:aws:sts::<account>:assumed-role/<role>/<session> and arn:aws:ec2:<region>:<account>:instance/<instance-id>). No Command record is created.
Emulator: the denied caller's SendCommand answers HTTP 200 with a full Command payload (CommandId minted, Status Pending), i.e. the call is authorized and recorded.
Why: an overly permissive data plane — a principal that AWS refuses can dispatch commands to instances. Least-privilege policies are unenforced and every negative authorization test passes vacuously.
Fix: the SendCommand handler's authorization step in the ssm service must evaluate the caller's identity policy and refuse with 400 AccessDeniedException and the message above before minting a Command.
Traces: cloudformation__ec2__ssm.sdk-ssm-missing-sendcommand-permission-negative.

## Evidence
Cause 1 — cloudformation__ec2__ssm.deploy-ec2-3-group-rename-... : "AssertionError: command on i-00000000000000001 never succeeded within 45.53242823400001s: None" (the invocation poll never saw any invocation). The ten sibling checks listed under Cause 1 fail as "Error: Check timed out after 60.0s" while polling run-command completion; e.g. .cfn-ec2-instance-profile-enables-ssm-agent-registration-positive stalls in _run_shell AFTER its DescribeInstanceInformation(InstanceIds=[...]) poll already returned PingStatus Online. The accepted-but-inert shape is visible in the SendCommand response the emulator returned in .sdk-ssm-missing-sendcommand-permission-negative: {'Command': {'CommandId': '<uuid>', 'DocumentName': 'AWS-RunShellScript', 'Status': 'Pending', 'StatusDetails': 'Pending', 'InstanceIds': ['i-00000000000000001'], 'TargetCount': 1, 'CompletedCount': 0, ...}, HTTPStatusCode 200}.

Cause 2 — .cfn-deploy-ssm-document-association-ec2-positive, .cfn-ssm-association-missing-target-tag-negative, .cfn-ssm-document-wrong-instance-tag-key-negative: "Error: Check timed out after 60.0s"; each polls describe_association(...)["AssociationDescription"]["Overview"] until Status is in {Success, Failed} (timeout_s=600) after the managed-instance poll.

Cause 3 — .cfn-ec2-tag-propagation-to-ssm-inventory-positive: "AssertionError: expected describe_instance_information(tag:Sim2realEnv='env-adf7177c6c18') to resolve to ['i-00000000000000001'], got []".

Cause 4 — .cfn-update-ec2-instance-type-triggers-ssm-reregistration-positive: "AssertionError: expected UPDATE_COMPLETE after AMI change, got 'UPDATE_ROLLBACK_COMPLETE'".

Cause 5 — .cli-script-cfn-update-stack-security-group-blocks-ssm-negative: "AssertionError: stack update did not complete: UPDATE_ROLLBACK_COMPLETE".

Cause 6 — .sdk-ssm-missing-sendcommand-permission-negative: "AssertionError: expected SendCommand to be denied, but it SUCCEEDED and returned {...'Status': 'Pending'...}, HTTPStatusCode 200". Expected: code AccessDeniedException with message "User: arn:aws:sts::<account>:assumed-role/<deny-role>/<session> is not authorized to perform: ssm:SendCommand on resource: arn:aws:ec2:<region>:<account>:instance/<instance-id> with an explicit deny in an identity-based policy", and no Command in ListCommands.

## Steps to Reproduce
Cause 1: launch an EC2 instance with an SSM instance profile, wait until DescribeInstanceInformation(Filters=[{"Key":"InstanceIds",...}]) reports PingStatus Online, then SendCommand(DocumentName="AWS-RunShellScript", Parameters={"commands":["touch /tmp/m && ls /tmp/m"]}) and poll GetCommandInvocation. Emulator: the invocation never reaches a terminal Status and no output is ever produced. AWS: Status Success, ResponseCode 0, StandardOutputContent "/tmp/m".
Cause 2: deploy a stack with an AWS::SSM::Association targeting the instance by tag, then poll DescribeAssociation(AssociationId=...).AssociationDescription.Overview. Emulator: Status never becomes Success/Failed, and DescribeAssociationExecutions records nothing.
Cause 3: deploy a stack that tags an instance (e.g. Sim2realEnv=<value>) and call DescribeInstanceInformation(Filters=[{"Key":"tag:Sim2realEnv","Values":[<value>]}]). Emulator: []. AWS: the tagged instance.
Cause 4: deploy a stack with an AWS::EC2::Instance whose ImageId comes from a parameter; UpdateStack with a different AMI id. Emulator: UPDATE_ROLLBACK_COMPLETE. AWS: UPDATE_COMPLETE, old instance terminating, new instance id in outputs.
Cause 5: deploy a stack containing an AWS::EC2::SecurityGroup with outbound 443, then UpdateStack with a template that removes that egress rule. Emulator: UPDATE_ROLLBACK_COMPLETE. AWS: UPDATE_COMPLETE.
Cause 6: assume a role whose identity policy explicitly denies ssm:SendCommand and call SendCommand against the instance. Emulator: HTTP 200 with a Command. AWS: 400 AccessDeniedException with the explicit-deny message, and ListCommands still empty.
