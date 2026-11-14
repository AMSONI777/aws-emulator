Issue-Severity: MEDIUM
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: ds.e2e-trust-create-verify-delete-flow
Issue-Shape-Id: com.amazonaws.directoryservice#DirectoryService_20150416
Issue-Key: ds.e2e-trust-create-verify-delete-flow|_wait_for_trust_gone#26|Timeout|time.sleep(interval_s)
Issue-Commit: 4c77ade3d5e6aed90c9f3ce2b3b42ec7a5a8e0f0

# ds: the two-directory trust create/verify/delete happy-path flow reaches NO verdict — every clock-owed ds transition settles only after the probe that follows the call, so the scenario is killed at the 60 s check ceiling

> _Note: this issue was identified against the code base at commit `4c77ade3d5e6aed90c9f3ce2b3b42ec7a5a8e0f0`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
DescribeTrusts

## Description
ONE net-new cause, in the ds control plane. It is grounded in the only failing check the behavioral suite lists under the heading '### ds' in this replay that is marked neither ALREADY FILED (stub-blocked on EnableRadius) nor OWNED by an open issue. ds answers 130/157 behavioral checks in this run, so this is not a bootstrap gap.

Related open issues that this replay does NOT mark as owning this check, and which therefore do not cover it: 20261114T005944Z-ds-3-net-new-causes-the-trust-create.md lists ds.e2e-trust-create-verify-delete-flow in its Issue-Trace-Ids, but its replay key for that check is pinned to the poll frame `_wait_for_trust_gone#30|Timeout|return`, and in THIS run the check is killed at a different frame, so the suite reports it as ungraded and unowned again; 20261113T164150Z-ds-3-net-new-causes-the-msad-stage.md, 20261112T080746Z-ds-2-net-new-causes-registereventtopic-s-topicname.md (Cause 2, ds.trust-lifecycle-create-verify-delete) and 20261111T085740Z-ds-the-ldaps-enable-disable-and-directory-data.md carry sibling check ids for the SAME mechanism on the directory-stage chain, the trust chain and the LDAPS/data-access toggles. All of them should land as one work item: the fix is the transition-span contract, not any one scenario.

Cause 1 of 1: the two-directory, two-way trust create / verify / delete happy-path flow never reaches a single assertion (failing check id: ds.e2e-trust-create-verify-delete-flow).

AWS: the whole walk is modelled. Smithy (services/service-com-amazonaws-directoryservice-directoryservice-20150416/smithy-model/com-amazonaws-directoryservice-directoryservice-20150416.json): TrustState = [Creating, Created, Verifying, VerifyFailed, Verified, Updating, UpdateFailed, Updated, Deleting, Deleted, Failed]; DirectoryStage = [Requested, Creating, Created, Active, Inoperable, Impaired, Restoring, RestoreFailed, Deleting, Deleted, Failed, Updating]; CreateTrust input {DirectoryId @required ^d-[0-9a-f]{10}$, RemoteDomainName @required, TrustPassword @required @sensitive, TrustDirection @required} / output {TrustId @pattern ^t-[0-9a-f]{10}$}, errors ClientException(400), EntityAlreadyExistsException(400), EntityDoesNotExistException(400), InvalidParameterException(400), ServiceException(500), UnsupportedOperationException(400); VerifyTrust input {TrustId @required} / output {TrustId}; DeleteTrust input {TrustId @required, DeleteAssociatedConditionalForwarder default false} / output {TrustId}; DescribeTrusts input {DirectoryId, TrustIds, NextToken, Limit} / output {Trusts, NextToken}, errors incl. EntityDoesNotExistException (client, httpError 400, members {Message, RequestId}, doc 'The specified entity could not be found.'). So AWS ACCEPTS each trust call and answers before the trust settles, and exposes the settling walk through DescribeTrusts. For the wall clock there is recorded behavior only: a real Managed Microsoft AD takes 20-45 minutes to reach Active, which is why clients poll at 15-20 s intervals; the 60 s per-check ceiling is this emulator environment's, not the recording's.

Emulator: NO status, error-code, message or shape divergence is reported for this check. The entire replay output is 'Error: Check timed out after 60.0s', with no exception frame — the signature of a kill inside a poll sleep. The reason is the crate's clock-owed-transition contract, which deliberately makes every owed transition fall due only AFTER the probe that immediately follows the call that started it: services/service-com-amazonaws-directoryservice-directoryservice-20150416/src/state.rs:129-142 TRANSITION_SPAN = 500 ms, documented 'The project's emulator contract requires such a transition to fall due 250-750 ms after the call that starts it, so a caller acting immediately after the create still observes the transient state'; :144-169 STAGE_REQUESTED / STAGE_CREATING and DIRECTORY_BUILD_SPAN = 3 s; :171-180 directory_active_at(now) = now + TRANSITION_SPAN + DIRECTORY_BUILD_SPAN; src/state.rs:17-29 advance_clock, which materialises 'a trust leaving Creating or Verifying (and a torn-down one settling on Deleted and then leaving the store)' the same way; src/state/directory_deletion.rs for the Deleting -> Deleted -> record-forgotten chain. A client that calls, probes once (reading the transient), then sleeps its poll interval therefore pays ONE FULL POLL INTERVAL per transition. This scenario owes seven such legs — CreateMicrosoftAD x2 polled for Stage 'Active' at 20 s, CreateTrust x2 polled for TrustState in {Created, Verified} at 15 s, VerifyTrust polled for 'Verified' at 15 s, DeleteTrust x2 polled until gone at 15 s — i.e. >= 115 s of pure sleeping inside a 60 s ceiling, before any ec2/sts request traffic the scenario also issues.

Why: a client gets NO verdict on the contract this scenario exists to pin, so a regression in any part of it passes unnoticed. Ungraded are: that both directories report non-empty DnsIpAddrs once Stage is 'Active'; that CreateTrust mints a TrustId matching ^t-[0-9a-f]{10}$ and the trust leaves Creating for TrustState 'Created'; that VerifyTrust drives it to 'Verified' (and not 'VerifyFailed'); that after DeleteTrust both trusts disappear from DescribeTrusts(DirectoryId=...); and that a SECOND DeleteTrust on the same id is refused with HTTP 400 and Error.Code 'EntityDoesNotExistException' carrying AWS's wording for that class, 'Trust: <trustId> does not exist : RequestId: <requestId>'. In that message the FIXED text is 'Trust: ' and ' does not exist : RequestId: '; the variable parts are the trust id taken from the REQUEST and the RequestId taken from the response. No single run's literal trust id, directory id, host, port or timestamp is part of the requirement. A trust that never changed state, or a deleted trust that kept reading back, passes today.

Fix: no ds operation handler answers wrongly here — the owner is this crate's clock-owed-transition contract where it meets a polling client: services/service-com-amazonaws-directoryservice-directoryservice-20150416/src/state.rs (TRANSITION_SPAN, DIRECTORY_BUILD_SPAN, directory_active_at), the trust transitions advance_clock materialises, and src/state/directory_deletion.rs's teardown chain. A settled value must be reachable on the client's FIRST probe after the call that starts the transition, across the directory-stage chain (Requested/Creating -> Active) and the trust state machine (Creating -> Created, Verifying -> Verified, Deleting -> gone) — accepting that the transient values and the refusals that depend on them (DirectoryUnavailableException, DirectoryInDesiredStateException) stop being observable and that in-tree suites pinning them must be loosened. Alternatively the transition-span contract has to be settled explicitly; either way it cannot be left failing.

Traces: ds.e2e-trust-create-verify-delete-flow (verdict 'mismatch', detail 'Check timed out after 60.0s', killed inside a poll helper's time.sleep(interval_s)).

## Evidence
Behavioral suite simparity-behavioral-aws-v1, replayed against the emulator built from this checkout: Total 145/180 passed (80.6%); mismatched 27, errored 8, skipped 0, unloadable 0. Per service: ds 130/157 (83%) 27 failed; ds__ec2 15/21 (71%) 6 failed; ds__logs 0/1; ds__sns 0/1.

Failing check clustered here (listed under the heading '### ds'; the ONLY ds-family failure in this report marked neither ALREADY FILED nor OWNED):

  [mismatch] ds.e2e-trust-create-verify-delete-flow
    Error: Check timed out after 60.0s

No status, error-code, message or shape divergence is reported — and no exception frame, only the timeout.

Owed sleeping, read off the check's own source as the report prints it (each poll probes immediately after the call that starts the transition, reads the TRANSIENT value, then sleeps one full interval):
  create_microsoft_ad x2 -> _wait_for_directory_stage {'Active'}, interval_s=20.0  -> 40 s
  create_trust x2        -> _wait_for_trust_state {'Created','Verified'}, interval_s=15.0 -> 30 s
  verify_trust           -> _wait_for_trust_state {'Verified','VerifyFailed'}, 15.0 -> 15 s
  delete_trust x2        -> _wait_for_trust_gone, interval_s=15.0 -> 30 s
                                                           total owed  >= 115 s
against a 60 s per-check ceiling, before the ec2 (create_vpc / create_subnet / authorize_security_group_ingress / describe_availability_zones) and sts traffic the scenario also issues.

Why the first probe always misses, from this checkout (services/service-com-amazonaws-directoryservice-directoryservice-20150416/):
  src/state.rs:129-142 — TRANSITION_SPAN = Duration::from_millis(500), documented: 'The project's emulator contract requires such a transition to fall due 250-750 ms after the call that starts it, so a caller acting immediately after the create still observes the transient state.'
  src/state.rs:144-157 — STAGE_REQUESTED = "Requested", STAGE_CREATING = "Creating" ('the stage a create owes is a CHAIN rather than one step').
  src/state.rs:159-180 — DIRECTORY_BUILD_SPAN = Duration::from_secs(3) and directory_active_at(now) = now + TRANSITION_SPAN + DIRECTORY_BUILD_SPAN: the settled 'Active' exists ~3.5 s after the create but is first READ by whatever call comes after the client's 20 s sleep.
  src/state.rs:17-29 — advance_clock 'materialises the status transitions the clock has already made due', explicitly including 'a trust leaving Creating or Verifying (and a torn-down one settling on Deleted and then leaving the store)': the trust legs are built the same way.
  src/state/directory_deletion.rs — the Deleting -> Deleted -> record-forgotten chain, one span per step.

Expected (AWS / the check), none of which is reached:
  1. Both directories report a non-empty DnsIpAddrs list once DescribeDirectories reports Stage 'Active'.
  2. CreateTrust(TrustDirection='Two-Way') returns a TrustId matching ^t-[0-9a-f]{10}$, and DescribeTrusts(DirectoryId=..., TrustIds=[trustId]) reports TrustState 'Created' (or 'Verified'), never 'Failed'.
  3. VerifyTrust(TrustId=...) drives the trust to TrustState 'Verified' (not 'VerifyFailed').
  4. After DeleteTrust, the trust disappears from DescribeTrusts(DirectoryId=...).
  5. A repeat DeleteTrust(TrustId=<same id>) is refused with HTTP 400, Error.Code 'EntityDoesNotExistException' and Error.Message 'Trust: <trustId> does not exist : RequestId: <requestId>' — fixed text 'Trust: ' + ' does not exist : RequestId: ', trust id from the request, RequestId from the response (EntityDoesNotExistException.RequestId is @pattern ^([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})$).

Actual (emulator): not one of those five assertions is reached. The check is killed at the 60 s ceiling inside a poll sleep.

Smithy consulted (services/service-com-amazonaws-directoryservice-directoryservice-20150416/smithy-model/com-amazonaws-directoryservice-directoryservice-20150416.json):
  TrustState = [Creating, Created, Verifying, VerifyFailed, Verified, Updating, UpdateFailed, Updated, Deleting, Deleted, Failed]
  DirectoryStage = [Requested, Creating, Created, Active, Inoperable, Impaired, Restoring, RestoreFailed, Deleting, Deleted, Failed, Updating]
  CreateTrust: input {DirectoryId @required ^d-[0-9a-f]{10}$, RemoteDomainName @required, TrustPassword @required @sensitive, TrustDirection @required, TrustType, ConditionalForwarderIpAddrs, SelectiveAuth} -> output {TrustId ^t-[0-9a-f]{10}$}; errors ClientException(400), EntityAlreadyExistsException(400), EntityDoesNotExistException(400), InvalidParameterException(400), ServiceException(500), UnsupportedOperationException(400)
  VerifyTrust / DeleteTrust: input {TrustId @required} -> output {TrustId}; errors incl. EntityDoesNotExistException(400)
  DescribeTrusts: input {DirectoryId, TrustIds, NextToken, Limit} -> output {Trusts, NextToken}, paginated; errors incl. EntityDoesNotExistException(400), InvalidNextTokenException(400)
  EntityDoesNotExistException: client error, httpError 400, members {Message, RequestId}

Corroborating replay context: ds checks that owe only ONE clock-owed leg do reach their assertions in this same run and fail on response CONTENT instead of the clock, which locates the overrun in the number of clock-owed legs rather than in slow request service. The scenario builds its own VPC, subnets, directories and trusts, so nothing in it depends on a real account or on a live-only value.

## Steps to Reproduce
1. git_clone(), then run_behavioral_suite(). The check id ds.e2e-trust-create-verify-delete-flow reproduces this cause; it is marked neither ALREADY FILED nor OWNED in this report (the open issue 20261114T005944Z-ds-3-net-new-causes-the-trust-create.md names it, but its replay key is pinned to a different poll frame, so the suite does not treat it as owned).
2. Reproduce by hand against the emulator with botocore clients for 'sts', 'ec2' and 'ds'. Create a VPC (10.91.0.0/16) with two subnets in distinct AZs. Call ds:CreateMicrosoftAD twice (distinct DNS names, distinct ShortNames, Edition='Standard', VpcSettings={VpcId, SubnetIds=[a,b]}).
3. For each directory: call ds:DescribeDirectories(DirectoryIds=[<id>]) IMMEDIATELY after the create — observe a transient Stage ('Requested'/'Creating') — then sleep 20 s and call again. Observe that the settled 'Active' only becomes visible on that SECOND probe, so the client pays a full poll interval per leg. Once Active, assert DnsIpAddrs is non-empty.
4. Authorize each directory's VpcSettings.SecurityGroupId for the peer group, and call ds:CreateConditionalForwarder on each side for the other's domain. Then ds:CreateTrust(DirectoryId=..., RemoteDomainName=<peer>, TrustPassword=<compliant>, TrustDirection='Two-Way') on both sides: each must return a TrustId matching ^t-[0-9a-f]{10}$, and ds:DescribeTrusts(DirectoryId=..., TrustIds=[<id>]) must report TrustState 'Created' — again only on the probe AFTER the 15 s sleep.
5. ds:VerifyTrust(TrustId=<a>) then poll DescribeTrusts for TrustState 'Verified'. ds:DeleteTrust on both ids then poll until neither is listed by DescribeTrusts(DirectoryId=...).
6. Call ds:DeleteTrust(TrustId=<a>) a second time: it must answer HTTP 400, Error.Code 'EntityDoesNotExistException', Error.Message 'Trust: <trustId> does not exist : RequestId: <requestId>' (fixed text 'Trust: ' and ' does not exist : RequestId: '; the trust id is the one in the REQUEST, the RequestId is the response's UUID). Then DescribeTrusts(DirectoryId=<dir a>) must not list that trust id. Summing the owed intervals in steps 3-5 gives >= 115 s against the 60 s ceiling, which is why nothing above is graded in the suite.
7. Localise (diagnostic only, do not keep): set TRANSITION_SPAN and DIRECTORY_BUILD_SPAN in services/service-com-amazonaws-directoryservice-directoryservice-20150416/src/state.rs to zero and replay — the check then reaches its assertions. Keeping that erases the modelled transient values (Requested/Creating, trust Creating/Verifying/Deleting) from the observable surface, so the real fix is to make a settled value reachable on the client's FIRST probe after the call without erasing the transients, or to settle the transition-span contract explicitly.
8. Re-replay ds.e2e-trust-create-verify-delete-flow and confirm it reaches a verdict on every assertion in steps 3-6 instead of dying in a sleep. Land together with 20261114T005944Z-ds-3-net-new-causes-the-trust-create.md, 20261113T164150Z-ds-3-net-new-causes-the-msad-stage.md, 20261112T080746Z-ds-2-net-new-causes-registereventtopic-s-topicname.md (Cause 2) and 20261111T085740Z-ds-the-ldaps-enable-disable-and-directory-data.md, which carry sibling check ids for the same mechanism.
