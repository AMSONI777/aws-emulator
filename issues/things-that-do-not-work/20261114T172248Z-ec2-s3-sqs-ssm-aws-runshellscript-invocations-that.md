Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: ec2__s3__sqs__ssm.instance-job-writes-objects-and-every-s3-event-lands-in-sqs-with-matching-etag-size-sequencer ec2__s3__sqs__ssm.s3pointer-guest-reduces-the-whole-multipart-object-to-a-verified-checksum-and-leaves-nothing-on-failure ec2__s3__sqs__ssm.sqsfail-guest-job-failure-keeps-the-message-writes-no-partial-result-and-redrives-to-the-dlq ec2__s3__sqs__ssm.sqsjob-poisoned-job-leaves-no-partial-result-and-returns-to-the-queue-until-its-input-exists ec2__s3__sqs__ssm.sqsjob-worker-drains-queue-and-every-result-object-holds-the-independently-computed-answer ec2__s3__sqs__ssm.sqsrace-poisoned-job-writes-no-result-object-and-lands-in-dlq ec2__s3__sqs__ssm.sqsrace-two-workers-one-queue-write-every-job-result-exactly-once
Issue-Key: ec2__s3__sqs__ssm.instance-job-writes-objects-and-every-s3-event-lands-in-sqs-with-matching-etag-size-sequencer|_json_line#7|AssertionError|assert lines, (
Issue-Key: ec2__s3__sqs__ssm.s3pointer-guest-reduces-the-whole-multipart-object-to-a-verified-checksum-and-leaves-nothing-on-failure|_json_line#7|AssertionError|assert lines, (
Issue-Key: ec2__s3__sqs__ssm.sqsfail-guest-job-failure-keeps-the-message-writes-no-partial-result-and-redrives-to-the-dlq|_run_worker#7|AssertionError|assert inv["ResponseCode"] == expect_rc, (
Issue-Key: ec2__s3__sqs__ssm.sqsjob-poisoned-job-leaves-no-partial-result-and-returns-to-the-queue-until-its-input-exists|_assert_poison_refused#7|AssertionError|assert inv["ResponseCode"] == 0, (
Issue-Key: ec2__s3__sqs__ssm.sqsjob-worker-drains-queue-and-every-result-object-holds-the-independently-computed-answer|_assert_jobs#7|AssertionError|assert inv["ResponseCode"] == 0, (
Issue-Key: ec2__s3__sqs__ssm.sqsrace-poisoned-job-writes-no-result-object-and-lands-in-dlq|_guest_json#7|AssertionError|assert inv["ResponseCode"] == 0, (
Issue-Key: ec2__s3__sqs__ssm.sqsrace-two-workers-one-queue-write-every-job-result-exactly-once|_guest_json#7|AssertionError|assert inv["ResponseCode"] == 0, (
Issue-Commit: 225b72df8882575de41dd997e8ca538d39a59320

# ec2__s3__sqs__ssm: AWS-RunShellScript invocations that run `python3`/`aws` in the guest end Failed with ResponseCode 127, and the failure carries no stderr (2 causes)

> _Note: this issue was identified against the code base at commit `225b72df8882575de41dd997e8ca538d39a59320`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
SendCommand

## Description
2 net-new root causes, both in SSM Run Command's guest execution, grounded in all seven failing checks under the `ec2__s3__sqs__ssm` heading. Every one of these scenarios uses a managed node as its only observation point: the work (reading/writing S3 objects through a gateway endpoint, polling SQS from inside the VPC, computing checksums over multipart bytes) is performed by a program the check ships to the instance with `AWS-RunShellScript`, so nothing the scenario grades is observable unless that script runs.

Nearest open issues, none of which carries any of these seven checks' replay keys: 20261114T161545Z-ec2-route53-route53resolver-ssm-an-aws-runshellscript-script.md (same two causes, grounded on two route53resolver checks, and its cause 2 was that ResponseCode AND stderr were both lost — here ResponseCode is now reported as 127 while stderr is still empty, so the residue is narrower); 20261115T000000Z-ec2-ssm-a-managed-nodes-guest-has-no-network-programs.md (asks for ping/tracepath/a TCP listener and a VPC packet-path model — no cause below is a network measurement); 20261111T040849Z-ec2-s3-sqs-ssm-a-launched-ec2-instance-never-comes-online-in.md and 20261113T113607Z-ec2-s3-sqs-ssm-the-sqs-race-worker.md (both describe the instance never coming Online in SSM — that is no longer what happens: the node IS Online, SendCommand IS accepted and the invocation DOES reach a terminal status, it reaches `Failed`). A fix to any of those closes neither cause here.

Cause 1 of 2: a Run Command script that writes a program with a here-document and runs an interpreter or the AWS CLI is reported Failed instead of running.
  AWS: an `AWS-RunShellScript` invocation on an Online managed node runs the document's `commands` as a real shell script in the instance's real guest. Scripts of the form `set -uo pipefail` / `cat > /tmp/<file>.py <<'EOF' … EOF` / `python3 /tmp/<file>.py`, and `python3 - <<'EOF' … EOF`, and `aws s3api get-object --bucket <b> --key <k> /tmp/src`, therefore write the file and run the interpreter and the CLI the AMI ships (these checks launch the AMI named by the public parameter /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64, which ships python3 and the AWS CLI), and GetCommandInvocation reports `Status` `Success`, `ResponseCode` 0 and the program's stdout in `StandardOutputContent`. Smithy: GetCommandInvocation output members `Status` (CommandInvocationStatus), `ResponseCode` (integer), `StandardOutputContent` (@length 0..24000), `StandardErrorContent` (@length 0..8000), `StatusDetails` (@length 0..100); a script's success or failure is the GUEST's, not the API's, so no modelled error is involved — the per-shell wording of a diagnostic is recorded behavior only.
  Emulator: the invocation settles `Status` `'Failed'` / `StatusDetails` `'Failed'` with `ResponseCode` 127 — the status a shell answers for a program it could not find — and `StandardOutputContent` `''`. Per services/service-com-amazonaws-ssm-amazonssm/src/state/guest_execution.rs the script is performed in the bounded in-process shell session reached through `ComAmazonawsEc2Amazonec2State::run_in_instance_guest`, which has "no process, no socket and no host path in it" and where "a command the session provides no program for answers the status a shell answers for a utility it could not find". So `python3` and `aws` are not provided, and the script ends 127 on its first such line, before any S3 read, SQS receive or checksum is ever performed. Note the instance-job script redirects the CLI's stderr to /tmp/get.err and `cat`s it back on failure and still produces nothing, so here-document/file redirection under /tmp does not survive either.
  Why: a client that drives an in-VPC agent by shipping it a program — the standard way to observe or act on anything only reachable from inside the VPC, and what all seven of these scenarios do — gets a failed invocation instead of its program's output and side effects. None of the behavior under test (S3 event notifications carrying the eTag/size/sequencer of bytes a guest wrote, an overwrite and delete raising the sequencer, a guest worker draining a queue, a poisoned job returning to the queue, redrive to a DLQ, two workers partitioning one queue exactly once) is observable at all, however faithful the S3 and SQS planes are.
  Fix: the guest-execution seam the invocation runs in — the in-process shell session reached through `ComAmazonawsEc2Amazonec2State::run_in_instance_guest` and the program environment it installs, read by services/service-com-amazonaws-ssm-amazonssm/src/state/guest_execution.rs. It needs the shell features a RunShellScript script delivers a program with (here-document redirection to a writable path under /tmp and reading it back, `2>` to a file), a `python3` interpreter able to run a script that talks to the emulator's S3/SQS endpoints, and the `aws` CLI the launched image ships.
  Traces: all seven check ids in trace_ids; the five that assert `ResponseCode` directly report rc=127 ('the worker failed on the host: rc=127 stderr=\'\'', 'the worker pass exited 127, expected 3', "the command on i-… failed on the host: status='Failed' rc=127 stderr=''"), the two that read stdout first report "the guest reported no stdout: 'Failed' stderr=''".

Cause 2 of 2: a Failed invocation reports an empty StandardErrorContent, so the failure carries no diagnostic.
  AWS: when a RunShellScript script ends non-zero the agent reports the script's own stderr in `StandardErrorContent` alongside the non-zero `ResponseCode`; for a program the shell cannot find, that stderr is the shell's own diagnostic for the failing line — fixed text of the form `<program>: command not found`, whose only variable part is the program name taken from the script line that failed (recorded behavior only for the exact per-shell wording; the requirement is that a non-empty diagnostic accompanies a Failed status and a non-zero code).
  Emulator: `Status` `'Failed'` and `ResponseCode` 127 are reported, but `StandardErrorContent` is `''` on every one of these seven invocations — the reason the guest failed is serialized nowhere a client can read.
  Why: a client or operator cannot tell a missing interpreter from a syntax error, a permission failure or a killed probe; all of them look like an empty Failed. Automation that branches on `StandardErrorContent` to retry, report or classify has nothing to branch on, and the checks' own diagnostics (which print the last 600 bytes of stderr) degrade to ''.
  Fix: the invocation-result projection in SSM's guest execution and the GetCommandInvocation serializer — carry the session's stderr stream into `StandardErrorContent` (and keep `StatusDetails` consistent) instead of dropping it when the script ends non-zero.
  Traces: all seven check ids in trace_ids; every reported assertion message ends in `stderr=''`.

## Evidence
Replay of simparity-behavioral-aws-v1 against this checkout. Per-service pass rate ec2__s3__sqs__ssm 1/8 (12%), 7 failed — none marked ALREADY FILED and none OWNED by an open issue.

[mismatch] ec2__s3__sqs__ssm.instance-job-writes-objects-and-every-s3-event-lands-in-sqs-with-matching-etag-size-sequencer
  AssertionError: the guest reported no stdout: 'Failed' stderr=''
  (script: `aws s3api get-object --bucket <b> --key in/source /tmp/src` then `python3 - <<'GENEOF' …`)

[mismatch] ec2__s3__sqs__ssm.s3pointer-guest-reduces-the-whole-multipart-object-to-a-verified-checksum-and-leaves-nothing-on-failure
  AssertionError: the guest reported no stdout: 'Failed' stderr=''
  (script: `set -uo pipefail` / `cat > /tmp/job.py <<'JOBEOF' … JOBEOF` / `python3 /tmp/job.py`)

[mismatch] ec2__s3__sqs__ssm.sqsfail-guest-job-failure-keeps-the-message-writes-no-partial-result-and-redrives-to-the-dlq
  AssertionError: the worker pass exited 127, expected 3; stdout='' stderr=''

[mismatch] ec2__s3__sqs__ssm.sqsjob-poisoned-job-leaves-no-partial-result-and-returns-to-the-queue-until-its-input-exists
  AssertionError: the worker itself failed on the host, so nothing about the poisoned job was measured: rc=127 stderr=''

[mismatch] ec2__s3__sqs__ssm.sqsjob-worker-drains-queue-and-every-result-object-holds-the-independently-computed-answer
  AssertionError: the worker failed on the host: rc=127 stderr=''

[mismatch] ec2__s3__sqs__ssm.sqsrace-poisoned-job-writes-no-result-object-and-lands-in-dlq
  AssertionError: the command on i-00000000000000001 failed on the host: status='Failed' rc=127 stderr=''

[mismatch] ec2__s3__sqs__ssm.sqsrace-two-workers-one-queue-write-every-job-result-exactly-once
  AssertionError: the command on i-00000000000000001 failed on the host: status='Failed' rc=127 stderr=''

All seven send DocumentName="AWS-RunShellScript", Parameters={"commands": [<one multi-line script>]}, TimeoutSeconds=600. Everything up to the send succeeds: the VPC/subnets/security groups and S3 gateway endpoint are created, the instance reaches `running`, the node is reported as a managed node, SendCommand is accepted and GetCommandInvocation reaches a terminal status.

Expected (AWS): Status='Success', ResponseCode=0, StandardOutputContent ending in the one JSON line the shipped program prints (its manifest / per-job report), and the program's S3 writes and SQS receives/deletes visible afterwards.
Actual (emulator): Status='Failed', StatusDetails='Failed', ResponseCode=127, StandardOutputContent='', StandardErrorContent='' — the script never ran (cause 1) and the failure carries no diagnostic (cause 2). The instance id and command ids above are per-run values, not part of the requirement.

## Steps to Reproduce
1. Build and boot the emulator from this checkout.
2. Replay simparity-behavioral-aws-v1 and re-run the seven check ids in trace_ids (report heading `ec2__s3__sqs__ssm`).
3. Or directly, against the emulator:
   a. Create a VPC, a subnet, and an S3 gateway VPC endpoint on its route table; create an S3 bucket and an SQS queue.
   b. Create an IAM role + instance profile carrying arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore (plus s3/sqs access), read the AMI id from the public parameter /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 and RunInstances a t3.micro with that profile into the subnet.
   c. Poll ssm DescribeInstanceInformation until the node reports PingStatus=Online.
   d. ssm SendCommand DocumentName=AWS-RunShellScript, InstanceIds=[<id>], Parameters={"commands": ["set -uo pipefail\ncat > /tmp/p.py <<'EOF'\nimport json; print(json.dumps({\"ok\": True}))\nEOF\npython3 /tmp/p.py\n"]}.
   e. Poll ssm GetCommandInvocation(CommandId=…, InstanceId=…) to a terminal status.
   Expected: Status=Success, ResponseCode=0, StandardOutputContent containing the JSON line the program printed.
   Actual: Status=Failed, ResponseCode=127, StandardOutputContent='', StandardErrorContent=''.
4. Same with commands=["aws s3api get-object --bucket <bucket> --key <key> /tmp/src"] — expect 0 and the object on disk; actual 127 with empty stderr.
5. Cause 2 alone, needing no interpreter: send commands=["definitely-not-a-program"] and read GetCommandInvocation — expect a `definitely-not-a-program: command not found` diagnostic in StandardErrorContent with ResponseCode 127; actual is ResponseCode 127 with StandardErrorContent=''.
