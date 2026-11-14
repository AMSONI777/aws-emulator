Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: ec2__events__sqs.events-ec2-lifecycle-protected-terminate-rejected-emits-no-shutting-down
Issue-Key: ec2__events__sqs.events-ec2-lifecycle-protected-terminate-rejected-emits-no-shutting-down|_drain#22|Timeout|msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
Issue-Commit: 54cc30c6fad79cfe6c1612c15a6c83a97395199b

# ec2__events__sqs: the termination-protection lifecycle check reaches no verdict — the refused TerminateInstances / shutting-down event scenario is cut off at the suite budget

> _Note: this issue was identified against the code base at commit `54cc30c6fad79cfe6c1612c15a6c83a97395199b`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
TerminateInstances

## Description
Cause 1 of 1: the EC2 instance-lifecycle scenario that grades the termination-protection refusal together with the 'shutting-down' EventBridge notification makes no observable progress and is killed at the suite's 60 s budget, so none of its assertions is ever answered.

AWS: TerminateInstances on an instance with DisableApiTermination=true is refused with error code OperationNotPermitted; the message's fixed text is "The instance '" + "' may not be terminated. Modify its 'disableApiTermination' instance attribute and try again.", its only variable part being the instance-id from the request — and the instance stays 'running' with the attribute still true. Terminating an UNPROTECTED instance publishes an "EC2 Instance State-change Notification" (source aws.ec2) with detail.state="shutting-down" and detail.instance-id to the default event bus, and a rule pinning that source/detail-type/state delivers one envelope per transition to its SQS target; after DisableApiTermination is set to false, the same instance's termination publishes the same envelope on the same rule. The Smithy model carries no timing, so the delivery itself is recorded behavior only: on AWS the launch reaches 'running' and the envelope lands within seconds, well inside the check's own 600 s ceilings.

Emulator: the check never returns a verdict — the replay reports only "Error: Check timed out after 60.0s". Its blocking waits are (a) a poll for each launched instance to reach 'running' (600 s ceiling) and (b) a long-poll drain of the rule's queue for the control instance's shutting-down envelope (600 s drain). Hypothesis: the event wait is the one that never satisfies — this service already has an open issue, 20261107T075601Z-ec2-events-sqs-ec2-eventbridge-volume-instance-lifecycle-notifications-never-arrive.md, stating that EC2 instance/volume lifecycle notifications never reach EventBridge for the sibling checks in this very group. That issue does not carry this check's replay key, so this scenario is unaccounted for and its protection-refusal assertions (error code, message template, DescribeInstanceAttribute after the refusal, state unchanged) have never been exercised.

Why: a client that drives EC2 lifecycle off EventBridge (auto-remediation, draining, inventory) sees nothing at all, and a client relying on termination protection gets no evidence that the refusal is the documented OperationNotPermitted with the documented sentence or that a refused call leaves the attribute and the instance state untouched. A scenario that cannot even reach its assertions also hides any further divergence behind it.

Fix: the EC2 instance-lifecycle event emission path (instance state transitions published to the default event bus as "EC2 Instance State-change Notification") and the RunInstances -> 'running' convergence that precedes it; and, once the scenario runs, the TerminateInstances handler's DisableApiTermination refusal (code + message template).

Traces: ec2__events__sqs.events-ec2-lifecycle-protected-terminate-rejected-emits-no-shutting-down.

## Evidence
Failing check: [mismatch] ec2__events__sqs.events-ec2-lifecycle-protected-terminate-rejected-emits-no-shutting-down
Detail reported by the replay: "Error: Check timed out after 60.0s" — no assertion was reached.

Expected (AWS): the scenario completes — RunInstances converges to 'running'; TerminateInstances on the protected instance is refused with Code=OperationNotPermitted and Message "The instance '<instance-id>' may not be terminated. Modify its 'disableApiTermination' instance attribute and try again."; DescribeInstanceAttribute still reports DisableApiTermination=true; the unprotected sibling's termination delivers one "EC2 Instance State-change Notification" envelope with detail.state="shutting-down" to the rule's SQS queue; after ModifyInstanceAttribute clears protection, the protected instance's termination delivers the same envelope.

Actual (emulator): the check makes no progress inside its waits (instance -> 'running' poll, 600 s ceiling; shutting-down envelope drain, 600 s ceiling) and is terminated by the suite at 60 s, so no verdict exists for any of the above.

Sibling checks in the same group fail on EC2 EventBridge lifecycle notifications never arriving (open issue 20261107T075601Z-ec2-events-sqs-ec2-eventbridge-volume-instance-lifecycle-notifications-never-arrive.md), which does not name this check.

## Steps to Reproduce
1. Create a VPC (10.84.0.0/16) and a subnet (10.84.1.0/24).
2. RunInstances twice with t3.micro in that subnet: one with DisableApiTermination=true ('protected'), one without ('control'). Poll DescribeInstances until both report state 'running'.
3. PutRule on the default bus with pattern {"source":["aws.ec2"],"detail-type":["EC2 Instance State-change Notification"],"detail":{"state":["shutting-down"],"instance-id":[<protected>,<control>]}} and PutTargets an SQS queue (queue policy allowing events.amazonaws.com).
4. TerminateInstances on <protected> — expect OperationNotPermitted with the documented message, and the attribute/state unchanged.
5. TerminateInstances on <control> and ReceiveMessage on the queue — expect one shutting-down envelope naming <control> within seconds.
6. ModifyInstanceAttribute DisableApiTermination=false on <protected>, TerminateInstances, and expect its shutting-down envelope on the same queue.
Observed: the run does not get far enough to answer step 4 or 5 and is cut off at the 60 s suite budget.
