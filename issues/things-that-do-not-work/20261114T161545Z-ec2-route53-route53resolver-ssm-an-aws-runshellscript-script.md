Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-addresses-answer-the-private-hosted-zone ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-query-denied-when-the-security-group-revokes-udp-53
Issue-Key: ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-addresses-answer-the-private-hosted-zone|_ssm_run#8|AssertionError|assert inv["Status"] == "Success", (
Issue-Key: ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-query-denied-when-the-security-group-revokes-udp-53|_ssm_run#8|AssertionError|assert inv["Status"] == "Success", (
Issue-Commit: f6b0c298eebfdd6ec09360560eae62088bddff9b

# ec2__route53__route53resolver__ssm: an AWS-RunShellScript script that writes and runs a Python program Fails in the guest, and the failed invocation reports no stderr (2 causes)

> _Note: this issue was identified against the code base at commit `f6b0c298eebfdd6ec09360560eae62088bddff9b`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
SendCommand

## Description
Two net-new root causes, both in SSM Run Command's guest execution, observed from the two Route 53 Resolver endpoint data-plane checks. Both checks use a managed node as their only observation point into the VPC: Route 53 Resolver's data plane answers in-VPC sources only, so the DNS answer the check grades is observable ONLY from a script run inside the instance.

Related open issue, which does NOT cover either cause: issues/things-that-do-not-work/20261115T000000Z-ec2-ssm-a-managed-nodes-guest-has-no-network-programs.md asks for a VPC PACKET-PATH model plus ping/tracepath/a TCP listener/a package database. Neither cause below is about a network measurement program or a packet path — cause 1 is about the shell session's ability to write a file with a heredoc and run a `python3` interpreter at all (the probe is a pure-socket DNS client, not a network utility), and cause 2 is about what GetCommandInvocation reports when a script does fail. A fix to that issue's program list closes neither.

Cause 1 of 2: a Run Command script that writes a program to a file and runs `python3` is reported Failed instead of running.
  AWS: an `AWS-RunShellScript` invocation on an Online managed node runs the document's `commands` as a real shell script in the instance's real guest. A script of the form `set -uo pipefail` / `cat > /tmp/<file>.py <<'EOF' ... EOF` / `python3 /tmp/<file>.py '<json-arg>'` therefore writes the file and runs the interpreter the AMI ships (the check launches the `/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64` image, which ships python3), and GetCommandInvocation reports `Status` `Success`, `ResponseCode` 0 and the program's stdout in `StandardOutputContent`. Smithy: GetCommandInvocation output `Status` (CommandInvocationStatus enum), `ResponseCode` (integer, default 0), `StandardOutputContent` (@length 0..24000), `StandardErrorContent` (@length 0..8000), `StatusDetails` (@length 0..100). The script's success or failure is the GUEST's, not the API's — no modelled error is involved.
  Emulator: the invocation reaches a terminal `Status` of `Failed` with `StandardOutputContent` `''`. Per services/service-com-amazonaws-ssm-amazonssm/src/state/guest_execution.rs the invocation is performed in a bounded in-process shell session with "no process, no socket and no host path in it", and "a command the session provides no program for answers the status a shell answers for a utility it could not find" — so the heredoc redirection into /tmp and/or the `python3` interpreter the script needs are not provided, and the whole script ends non-zero before the probe ever sends a DNS query.
  Why: a client that drives an in-VPC agent by shipping it a program — the standard way to observe anything the data plane only answers from inside the VPC, and what both of these checks do — gets a failed invocation instead of its program's output. Nothing in the resolver-endpoint data plane (an inbound endpoint's addresses answering a private hosted zone, or a security-group revoke of udp/53 denying that query) is observable at all, no matter how faithful the route53resolver control plane is.
  Fix: the guest-execution seam the invocation runs in — the in-process shell session reached through `ComAmazonawsEc2Amazonec2State::run_in_instance_guest` and the programs its environment installs (`service_common::posix_shell_session::EnvironmentPrograms`). It needs the shell features a RunShellScript script uses to deliver a program (here-document redirection to a writable path under /tmp, and reading that path back) and a `python3` interpreter the launched image would ship, able to run a script that opens a UDP and a TCP socket to port 53 of an address inside the VPC and print one JSON line.
  Traces: ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-addresses-answer-the-private-hosted-zone; ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-query-denied-when-the-security-group-revokes-udp-53.

Cause 2 of 2: a Failed invocation reports an empty StandardErrorContent, so the failure carries no diagnostic.
  AWS: when a RunShellScript script ends non-zero, the agent reports the script's own stderr in `StandardErrorContent` and the script's exit status in `ResponseCode` — a missing interpreter yields the shell's own diagnostic on stderr (`<program>: command not found` for the failing line) and a non-zero `ResponseCode` (127 for a not-found program), with `Status` `Failed` and `StatusDetails` `Failed`. The fixed text here is the shell's diagnostic form; the variable part is the program name taken from the script line that failed. Recorded behavior only for the exact per-shell wording; what is required is that a non-empty diagnostic and a non-zero code accompany a Failed status.
  Emulator: `Status` `'Failed'` with BOTH `StandardOutputContent` `''` AND `StandardErrorContent` `''` — the failure is reported with no output of any kind, so the guest's reason for failing is not serialized anywhere a client can read.
  Why: a client (or an operator) cannot tell a missing interpreter from a syntax error, a permission failure or a timed-out probe; every one of them looks like an empty Failed. Automation that branches on `StandardErrorContent` or on `ResponseCode` to retry or to report sees nothing to branch on.
  Fix: the invocation-result projection in SSM's guest execution and GetCommandInvocation serializer — the session's stderr stream and exit status must be carried into `StandardErrorContent` and `ResponseCode` (and `StatusDetails`) rather than dropped when the script ends non-zero.
  Traces: ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-addresses-answer-the-private-hosted-zone; ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-query-denied-when-the-security-group-revokes-udp-53.

## Evidence
Replay of simparity-behavioral-aws-v1 against this checkout, both checks under the `ec2__route53__route53resolver__ssm` heading:

[mismatch] ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-addresses-answer-the-private-hosted-zone
  File "...inbound_resolver_endpoint_addresses_answer_the_private_hosted_zone.py", line 384, in _dig -> line 366, in _ssm_run
  assert inv["Status"] == "Success"
  AssertionError: the in-VPC probe script must run to completion; SSM reports 'Failed' stdout='' stderr=''

[mismatch] ec2__route53__route53resolver__ssm.inbound-resolver-endpoint-query-denied-when-the-security-group-revokes-udp-53
  File "...inbound_resolver_endpoint_query_denied_when_the_security_group_revokes_udp_53.py", line 367, in _dig -> line 349, in _ssm_run
  assert inv["Status"] == "Success"
  AssertionError: the in-VPC probe script must run to completion; SSM reports 'Failed' stdout='' stderr=''

The script sent in both cases (check helper `_dig`/`_ssm_run`) is, verbatim:
  commands = ["set -uo pipefail",
              "cat > /tmp/s2rdig.py <<'S2R_DIG_EOF'", <pure-socket DNS client in Python>, "S2R_DIG_EOF",
              "python3 /tmp/s2rdig.py '<json spec>'"]
  DocumentName = "AWS-RunShellScript", TimeoutSeconds = 240
Everything before this point in both checks succeeds: the VPC, subnets and security group are created, the instance reaches `running`, DescribeInstanceInformation reports `PingStatus` `Online` with `ResourceType` `EC2Instance`, the private hosted zone and its A records are written, and the resolver endpoint reaches `OPERATIONAL`. SendCommand is accepted and GetCommandInvocation reaches a terminal status — it reaches `Failed`.

Expected (AWS): `Status` `Success`, `ResponseCode` 0, `StandardOutputContent` containing one JSON line `{"results": [{"query": ..., "rcode": "NOERROR", "answers": [...]}, ...]}` printed by the probe.
Actual (emulator): `Status` `Failed`, `StandardOutputContent` `''`, `StandardErrorContent` `''` (cause 1 = the script does not run; cause 2 = the failure reports neither stdout nor stderr nor a usable code).

## Steps to Reproduce
1. Build and boot the emulator from this checkout.
2. Replay simparity-behavioral-aws-v1 and re-run the two check ids in trace_ids.
3. Or directly, against the emulator:
   a. Create a VPC (e.g. 10.91.0.0/16) with two subnets in usable AZs, and a security group permitting udp/53 and tcp/53 from the VPC CIDR.
   b. Create an IAM role + instance profile carrying arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore; RunInstances a t3.micro from the AMI id in the public parameter /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 into one subnet with that profile.
   c. Poll ssm DescribeInstanceInformation until the instance reports PingStatus=Online.
   d. ssm SendCommand DocumentName=AWS-RunShellScript, InstanceIds=[<id>], Parameters={"commands": ["set -uo pipefail", "cat > /tmp/p.py <<'EOF'", "import sys; print('{\"ok\": true}')", "EOF", "python3 /tmp/p.py"]}.
   e. Poll ssm GetCommandInvocation(CommandId=<id>, InstanceId=<id>) to a terminal status.
   Expected: Status=Success, ResponseCode=0, StandardOutputContent containing the JSON line the program printed.
   Actual: Status=Failed, StandardOutputContent='', StandardErrorContent='' — the script never ran (cause 1) and the failure carries no diagnostic or exit code (cause 2).
4. Cause 2 alone, without needing python3: send commands=["exit 7"] or commands=["definitely-not-a-program"] and read GetCommandInvocation. Expected a non-zero ResponseCode and, for the second, a `definitely-not-a-program: command not found` diagnostic in StandardErrorContent; actual is an empty StandardErrorContent.
