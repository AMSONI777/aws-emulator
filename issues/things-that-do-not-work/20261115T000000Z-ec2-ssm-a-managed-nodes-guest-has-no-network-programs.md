Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: ec2__ssm.mtu-jumbo-frames-carry-an-unfragmented-payload-across-availability-zones-in-one-vpc ec2__ssm.mtu-path-mtu-collapses-to-1500-when-the-same-eni-sends-through-the-internet-gateway ec2__ssm.mtu-tcp-negotiates-a-segment-size-that-reveals-the-path-mtu-without-losing-a-byte ec2__ssm.dtgw-transit-gateway-forwards-packets-between-two-vpcs-and-a-blackholed-route-stops-them ec2__ssm.sep-network-truth-vpc-peering-carries-packets-only-with-routes-on-both-sides ec2__ssm.sep-network-truth-sg-source-group-rule-admits-members-only-and-drops-as-timeout-not-refusal ec2__ssm.vscan-inventory-agent-version-matches-the-installed-rpm-on-a-deprecated-ami
Issue-Key: ec2__ssm.mtu-jumbo-frames-carry-an-unfragmented-payload-across-availability-zones-in-one-vpc|_json_marker#5|AssertionError|assert inv["ResponseCode"] == 0, (
Issue-Key: ec2__ssm.mtu-path-mtu-collapses-to-1500-when-the-same-eni-sends-through-the-internet-gateway|_json_marker#5|AssertionError|assert inv["ResponseCode"] == 0, (
Issue-Key: ec2__ssm.mtu-tcp-negotiates-a-segment-size-that-reveals-the-path-mtu-without-losing-a-byte|_legs#5|AssertionError|assert "SIM2REAL_LISTENING" in sink["StandardOutputContent"], (
Issue-Key: ec2__ssm.dtgw-transit-gateway-forwards-packets-between-two-vpcs-and-a-blackholed-route-stops-them|_poll#5|Timeout|time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))
Issue-Key: ec2__ssm.sep-network-truth-vpc-peering-carries-packets-only-with-routes-on-both-sides|_legs#5|AssertionError|assert base["local"] == st["nonce"], (
Issue-Key: ec2__ssm.sep-network-truth-sg-source-group-rule-admits-members-only-and-drops-as-timeout-not-refusal|_legs#5|AssertionError|assert base["local"] == st["nonce"], (
Issue-Key: ec2__ssm.vscan-inventory-agent-version-matches-the-installed-rpm-on-a-deprecated-ami|run#17|AssertionError|assert rpm_version == version, (
Issue-Commit: 3bd56f3581a93dde5b982de16e37f58616506edc

# ec2__ssm: a managed node's guest has none of the programs these scenarios read the VPC data plane with, so every SSM-observed network check fails on its own assertion (1 cause)

> _Note: this report CARRIES FORWARD the second cause of
> `issues/things-that-now-work/20261104T121102Z-ec2-ssm-the-duplicate-security-group-rule-refusal.md`.
> The gate that cause was filed for — an EC2 instance never becoming a managed node, so every
> check hung at its agent-online poll — is closed: an instance whose instance profile's role
> lets the agent register IS a managed node
> (`services/service-com-amazonaws-ssm-amazonssm/src/state/node_registration.rs`), and a
> command sent to one RUNS in that instance's guest, reporting the guest's own output and
> exit code (`src/state/guest_execution.rs`,
> `services/service-com-amazonaws-ec2-amazonec2/src/state/guest_commands.rs`). What is left
> is the capability below, which is what these seven checks now fail on._

## Operation
SendCommand

## Description
Cause 1 of 1: the guest a command runs in provides none of the programs these checks measure the network with, and the emulator models no packet path between two instances — so each check reaches its own assertion and fails there instead of hanging.

AWS: an `AWS-RunShellScript` invocation on a managed node runs a real shell in a real guest, so `ping -M do -s <size>`, `tracepath`, a socket listener and a client against it, and `rpm -q amazon-ssm-agent` all answer from the instance's own operating system and from the VPC the packet crosses — which is what lets a client observe the jumbo MTU inside one VPC, the path MTU collapsing to 1500 through an internet gateway, the TCP segment size that reveals it, transit-gateway forwarding and a blackholed route, VPC peering with routes on one or both sides, a source-group rule dropping as a timeout rather than a refusal, and the agent build the host's package database holds.

Emulator: the invocation is performed in the bounded in-process shell session that instance's own boot script runs in, which provides the session-local utilities and the machine's files and nothing else. So:

* `ping`, `tracepath` and the rest are commands it has no program for, and it answers the status a shell answers for a utility it could not find — the `mtu-jumbo-frames…` and `mtu-path-mtu…` checks now fail at `assert inv["ResponseCode"] == 0`.
* nothing in the guest can LISTEN on a port and nothing can dial one, so the two `sep-network-truth…` checks and `mtu-tcp-negotiates…` fail on their listener/nonce legs (`SIM2REAL_LISTENING`, `base["local"] == st["nonce"]`).
* no package database exists, so `rpm -q amazon-ssm-agent` answers nothing and `vscan-inventory-agent-version…` fails at `assert rpm_version == version`.
* `dtgw-transit-gateway…` still exhausts the harness budget in a poll of its own.

Why: a client that uses a managed node as its observation point into the VPC — which is what every one of these scenarios does — gets a failed invocation instead of a measurement, and no amount of control-plane fidelity substitutes for it.

Fix: the capability these checks need is a VPC PACKET PATH the emulator can answer questions about (an MTU per route, a route evaluation across a peering connection and a transit gateway, and a security-group/NACL admission decision between two interfaces), plus the guest programs that read it, provided to the guest session as the programs its environment installs
(`service_common::posix_shell_session::EnvironmentPrograms`) rather than as output synthesised per check: `ping` (with and without the don't-fragment flag and a payload size), `tracepath`, a bounded TCP listener and client the session can run, and a package database the image's own packages are read from. Each program must answer from that model and from the instance's own state, and a path the model says drops a packet must look to the guest the way a drop looks (a timeout), not like a refusal.

## Evidence
Replay of simparity-behavioral-aws-v1 against the checkout that closed the managed-node gate: `duplicate-ssh-ingress-rule-rejected-and-rule-count-unchanged` passes; the seven checks above no longer hang at the agent-online poll or at the command poll — each reaches its own assertion and fails there, with the first divergences quoted in the `Issue-Key` lines above.

## Steps to Reproduce
1. Build and boot the emulator from this checkout. 2. Replay simparity-behavioral-aws-v1 and re-run the check ids in trace_ids.
3. Or directly: create a VPC with subnets in two AZs, an IAM role/instance profile carrying `arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore`, RunInstances two instances with that profile, poll `ssm DescribeInstanceInformation` until both report `PingStatus` `Online` (this now settles), then `SendCommand` `AWS-RunShellScript` with `commands=["ping -M do -s 8972 -c 3 <the other instance's private address>"]` and read `GetCommandInvocation`.
   Expected: the guest answers the ping, reporting an unfragmented 9001-byte path inside the VPC. Actual: `Status` `Failed` with `ResponseCode` 127 — the guest has no such program.
