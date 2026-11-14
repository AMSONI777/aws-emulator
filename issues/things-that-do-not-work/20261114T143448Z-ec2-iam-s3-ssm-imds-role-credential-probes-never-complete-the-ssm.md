Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-put-object-outside-role-policy-denied ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-withdrawn-after-disassociate-iam-instance-profile
Issue-Key: ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-put-object-outside-role-policy-denied|_poll#18|TimeoutError|raise TimeoutError(f"{what}: the run budget ended first; not graded")
Issue-Key: ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-withdrawn-after-disassociate-iam-instance-profile|_poll#16|TimeoutError|raise TimeoutError(f"{what}: the run budget ended first; not graded")
Issue-Commit: 09a4de48f58372094bfcb9a0bb2c4d192074b72e

# IMDS role-credential probes never complete: the SSM Run Command invocation that reads instance credentials never reaches a terminal status

> _Note: this issue was identified against the code base at commit `09a4de48f58372094bfcb9a0bb2c4d192074b72e`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
GetCommandInvocation

## Description
One net-new root cause (Cause 1 of 1).

Cause 1 of 1: An SSM Run Command invocation used to probe IMDS role credentials from inside the guest never reaches a terminal status.
AWS: SendCommand's per-instance invocation advances Pending -> InProgress -> Success/Failed within seconds on a node carrying AmazonSSMManagedInstanceCore, and GetCommandInvocation then reports a terminal Status with ResponseCode and StandardOutputContent — which is how an in-guest probe reports whether IMDS served credentials, whether an S3 PutObject outside the role's policy was denied, and whether the credentials disappear after DisassociateIamInstanceProfile. Smithy: GetCommandInvocation -> Status/StatusDetails/ResponseCode/StandardOutputContent; CommandInvocationStatus's terminal members are Success, Cancelled, TimedOut, Failed.
Emulator: the invocation is accepted (HTTP 200) and never becomes terminal; the harness gives up with "TimeoutError: invocation <id> reaching a terminal status: the run budget ended first; not graded" on both checks, so no in-guest credential verdict is ever produced.
Why: a client that drives an instance through Run Command to assert that IMDS credentials are scoped to the role's policy, or withdrawn when the profile is disassociated, hangs forever instead of getting a verdict; the security property under test can never be observed.
Fix: the SSM command-invocation state machine — the invocation records written by services/service-com-amazonaws-ssm-amazonssm/src/ops/send_command.rs and read back by GetCommandInvocation must be advanced to a terminal status (and carry the guest's ResponseCode/stdout).
Traces: ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-put-object-outside-role-policy-denied, ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-withdrawn-after-disassociate-iam-instance-profile.

## Evidence
ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-put-object-outside-role-policy-denied: "TimeoutError: invocation <id> reaching a terminal status: the run budget ended first; not graded".
ec2__iam__s3__ssm.xsvc-ec2-3-imds-credentials-withdrawn-after-disassociate-iam-instance-profile: same TimeoutError on its own invocation.
Expected: GetCommandInvocation reports a terminal Status ('Success' or 'Failed') with a real ResponseCode and the probe's stdout. Actual: the invocation never leaves the non-terminal state for the whole run budget. Invocation ids are per-run values.

## Steps to Reproduce
1. Launch an EC2 instance with an instance profile whose role allows S3 writes only under one prefix, plus AmazonSSMManagedInstanceCore; wait for it to report Online in DescribeInstanceInformation.
2. ssm SendCommand(DocumentName='AWS-RunShellScript', InstanceIds=[<id>]) with a script that reads IMDS role credentials and attempts an S3 PutObject outside the allowed prefix.
3. Poll GetCommandInvocation(CommandId, InstanceId) for a terminal Status — it never becomes terminal.
4. Repeat after ec2 DisassociateIamInstanceProfile: the probe that should observe credentials withdrawn likewise never terminates.
