Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: cloudwatch__ec2__ssm.dcwagent-custom-statsd-value-and-guest-only-memory-metric-reach-cloudwatch cloudwatch__ec2__ssm.dcwagent-disk-used-percent-tracks-bytes-written-in-guest-while-an-unconfigured-metric-never-appears cloudwatch__ec2__ssm.dcwagent-statsd-value-blocked-while-the-agent-is-not-running-then-arrives-once-started
Issue-Key: cloudwatch__ec2__ssm.dcwagent-custom-statsd-value-and-guest-only-memory-metric-reach-cloudwatch|_poll#20|Timeout|time.sleep(interval_s)
Issue-Key: cloudwatch__ec2__ssm.dcwagent-disk-used-percent-tracks-bytes-written-in-guest-while-an-unconfigured-metric-never-appears|_poll#19|Timeout|time.sleep(interval_s)
Issue-Key: cloudwatch__ec2__ssm.dcwagent-statsd-value-blocked-while-the-agent-is-not-running-then-arrives-once-started|_poll#21|Timeout|time.sleep(interval_s)
Issue-Commit: 09a4de48f58372094bfcb9a0bb2c4d192074b72e

# CloudWatch agent scenarios never finish: in-guest statsd/memory/disk metrics never reach CloudWatch because the Run Command invocation that configures and feeds the agent never terminates

> _Note: this issue was identified against the code base at commit `09a4de48f58372094bfcb9a0bb2c4d192074b72e`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
SendCommand

## Description
One net-new root cause (Cause 1 of 1).

Cause 1 of 1: The in-guest CloudWatch-agent path never produces a metric because the SSM Run Command invocation that installs/configures the agent and generates the load never reaches a terminal status.
AWS: SendCommand against a managed node advances the per-instance invocation Pending -> InProgress -> Success within seconds, and GetCommandInvocation then reports a terminal Status with ResponseCode 0 and the guest's stdout; the amazon-cloudwatch-agent started that way publishes its configured metrics (statsd counters, mem_used_percent, disk_used_percent) into the CloudWatch namespace, where GetMetricStatistics/GetMetricData return datapoints, while a metric absent from the agent config never appears. Smithy: SendCommand -> Command{Status, StatusDetails, CompletedCount}; GetCommandInvocation -> Status/StatusDetails/ResponseCode/StandardOutputContent.
Emulator: the invocation is created with HTTP 200 and then stays Status='Pending', StatusDetails='Pending', ResponseCode=-1, with empty ExecutionStartDateTime/StandardOutputContent for the whole budget (the same payload is captured verbatim by the sibling EBS-telemetry checks in this service after 180 s of polling). No agent ever runs, no datapoint is ever published, and all three dcwagent checks are killed by the 600 s check budget.
Why: a client that uses Run Command to configure the CloudWatch agent and then reads the metric back gets neither a command result nor a datapoint, and cannot tell a non-publishing metric from a non-running agent — the negative half of the contract (an unconfigured metric must never appear) is unverifiable because the positive half never happens.
Fix: the SSM command-invocation state machine (services/service-com-amazonaws-ssm-amazonssm/src/ops/send_command.rs and the invocation state GetCommandInvocation reads) must advance invocations to a terminal status, and the guest-side agent/metric ingestion path that PutMetricData-equivalent publishing depends on must be driven from it.
Traces: cloudwatch__ec2__ssm.dcwagent-custom-statsd-value-and-guest-only-memory-metric-reach-cloudwatch, cloudwatch__ec2__ssm.dcwagent-disk-used-percent-tracks-bytes-written-in-guest-while-an-unconfigured-metric-never-appears, cloudwatch__ec2__ssm.dcwagent-statsd-value-blocked-while-the-agent-is-not-running-then-arrives-once-started.

## Evidence
All three dcwagent checks end with "Error: Check timed out after 600.0s" — no datapoint and no command result inside a 600 s budget.
The stuck state is captured verbatim by sibling checks in the same service that poll the same API with an explicit deadline: "invocation <id> reaching a terminal status not met within 180s (check-wide deadline 600s, 185s used; last observed: {'CommandId': ..., 'InstanceId': 'i-<id>', 'DocumentName': 'AWS-RunShellScript', 'ResponseCode': -1, 'ExecutionStartDateTime': '', 'ExecutionElapsedTime': '', 'ExecutionEndDateTime': '', 'Status': 'Pending', 'StatusDetails': 'Pending', 'StandardOutputContent': '', ... 'HTTPStatusCode': 200})".
Expected: Status 'Success', ResponseCode 0, non-empty StandardOutputContent, and CloudWatch datapoints for the configured metrics only. Command ids, instance ids and timestamps in that payload are per-run values.

## Steps to Reproduce
1. Launch an EC2 instance with an instance profile carrying AmazonSSMManagedInstanceCore and wait for it to report Online in ssm DescribeInstanceInformation.
2. ssm SendCommand(DocumentName='AWS-RunShellScript', InstanceIds=[<id>]) with a script that writes an amazon-cloudwatch-agent config (a statsd metric plus mem_used_percent / disk_used_percent) and starts the agent.
3. Poll GetCommandInvocation(CommandId, InstanceId): the Status never leaves 'Pending' and ResponseCode stays -1.
4. cloudwatch GetMetricStatistics for the configured metric: no datapoints ever appear.
