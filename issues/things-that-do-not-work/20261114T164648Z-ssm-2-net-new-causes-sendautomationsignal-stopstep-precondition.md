Issue-Source: trace-sweep-divergence
Issue-Trace: ssm-automation-signal-stopstep-and-invalid-filter-error
Issue-Step: task#4
Issue-Severity: HIGH
Issue-Corpus: simparity-wire-aws-v1
Issue-Corpus-Kind: wire
Issue-Trace-Ids: ssm-automation-signal-stopstep-and-invalid-filter-error ssm-automation-stop-and-signal-error-paths ssm-catalog-list-documents
Issue-Shape-Id: com.amazonaws.ssm#AmazonSSM
Issue-Key: ssm|SendAutomationSignal|4xx->4xx|$.Message
Issue-Key: ssm|ListDocuments|2xx->2xx|$.DocumentIdentifiers[Name="AWS-GatherSoftwareInventory"].CreatedDate
Issue-Key: ssm|ListDocuments|2xx->2xx|$.DocumentIdentifiers[Name="AWS-GatherSoftwareInventory"].Tags
Issue-Related: 20261111T045110Z-ssm-3-net-new-causes-listdocuments-serves-no.md
Issue-Commit: 225b72df8882575de41dd997e8ca538d39a59320

# ssm: 2 net-new causes — SendAutomationSignal StopStep precondition refusal is generic and ListDocuments serves no Amazon-owned document catalog

> _Note: this issue was identified against the code base at commit `225b72df8882575de41dd997e8ca538d39a59320`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
SendAutomationSignal

## Description
Two net-new SSM response-fidelity causes found by replaying the wire corpus. Both must be closed before this issue is submitted.

Cause 1 of 2: SendAutomationSignal with SignalType=StopStep and no StepName in the Payload is refused with the generic 'signal isn't valid' prose instead of AWS's StopStep precondition message.
- AWS: Smithy: SendAutomationSignal input = AutomationExecutionId (required, @length 36..36), SignalType (required, enum SignalType = [Approve, Reject, StartStep, StopStep, Resume, Revoke]), Payload (AutomationParameterMap, @length 1..200); modeled errors AutomationExecutionNotFoundException, AutomationStepNotFoundException, InvalidAutomationSignalException (client, HTTP 400). For SignalType=StopStep AWS checks the signal's required Payload entry before anything else and refuses with HTTP 400, error type InvalidAutomationSignalException and the message 'One StepName is required when signal type is StopStep.' — that message is entirely fixed text for this error class (it names the member 'StepName' and the signal type 'StopStep' from the request's SignalType; there are no per-run values in it). The recorded response confirms the status (400) and the error type; only the message text diverges.
- Emulator: answers HTTP 400 with the same error type but the message "Failed to process signal StopStep. The signal isn't valid for the current Automation execution." — i.e. it emits the Smithy doc sentence of InvalidAutomationSignalException ('The signal isn't valid for the current Automation execution.') prefixed with 'Failed to process signal <SignalType>.', so the generic 'wrong signal for this execution state' refusal stands in for the missing-StepName precondition.
- Why: a client cannot distinguish 'I forgot the StepName payload entry' (a caller bug it must fix by adding Payload={'StepName': [...]}) from 'this execution is not in a state that accepts StopStep' (a retry/ordering condition). Runbook tooling and tests that match on AWS's StopStep message, or that branch on it to decide whether to retry, take the wrong branch against the emulator.
- Fix: SendAutomationSignal's input validation in the ssm service crate — add the StopStep precondition check (Payload must carry exactly one StepName) ahead of the execution-state signal check, and render AWS's fixed message for it rather than reusing the InvalidAutomationSignalException doc sentence as a catch-all.
- Traces: ssm-automation-signal-stopstep-and-invalid-filter-error#task#4 (representative), ssm-automation-stop-and-signal-error-paths#task#7.

Cause 2 of 2: ListDocuments on a fresh account serves no Amazon-owned document catalog, and the few documents it does serve are missing most DocumentIdentifier members.
- AWS: Smithy: ListDocuments -> ListDocumentsResult.DocumentIdentifiers (DocumentIdentifierList of DocumentIdentifier), paginated (NextToken/MaxResults @range 1..50). DocumentIdentifier members include Name, Owner, DocumentType, DocumentVersion, DocumentFormat, SchemaVersion, PlatformTypes, TargetType, Tags, CreatedDate. Recorded behavior: an account with no customer documents still lists the full Amazon-published catalog — hundreds of entries with Owner 'Amazon' across the AWS-*, AWSConfigRemediation-*, AWSConformancePacks-*, AWSCodeDeployAgent* and AWSApp2Container-* families — each carrying DocumentType (Command/Automation/Policy/ConformancePack...), DocumentFormat (JSON or YAML), DocumentVersion '1', SchemaVersion ('2.2' for Command, '0.3' for Automation), PlatformTypes (e.g. ['Windows','Linux','MacOS']), Categories where the document declares them, TargetType where declared (e.g. '/AWS::EC2::Instance'), an empty Tags list and a CreatedDate.
- Emulator: the response omits every Amazon-owned document in the recording (the comparison reports each as 'missing', e.g. AWS-ASGEnterStandby, AWS-ASGExitStandby, AWS-ApplyPatchBaseline, AWS-ConfigureAWSPackage, AWS-RunPatchBaseline, the whole AWSConfigRemediation-* and AWSConformancePacks-* families). Only a small hard-coded handful is served (AWS-RunShellScript, AWS-RunPowerShellScript, AWS-GatherSoftwareInventory, AWS-ConfigureS3BucketVersioning, AWS-DisableS3BucketPublicReadWrite, AWS-EnableS3BucketEncryption, AWS-PublishSNSNotification, AWS-UpdateSSMAgent), and those entries drop Categories, CreatedDate, DocumentFormat, Tags, TargetType and, for AWS-RunPowerShellScript/AWS-RunShellScript, SchemaVersion and the second PlatformTypes entry.
- Why: every client that discovers runbooks/commands instead of hard-coding them sees an almost empty catalog, so console-style document pickers, 'is AWS-RunPatchBaseline available' preflights and anything filtering by Owner=Amazon, DocumentType, PlatformTypes or TargetType gets an empty or wrongly-shaped result and concludes the managed documents do not exist in the account. The partially populated entries additionally break clients that read DocumentFormat/SchemaVersion before calling GetDocument.
- Fix: the ssm document catalog seed/state plus ListDocuments' response projection — seed the Amazon-owned document set and populate the full DocumentIdentifier projection (Owner, DocumentType, DocumentFormat, SchemaVersion, DocumentVersion, PlatformTypes, Categories, TargetType, Tags, CreatedDate) for every served document.
- Traces: ssm-catalog-list-documents#task#1.
- Related open issue: 20261111T045110Z-ssm-3-net-new-causes-listdocuments-serves-no.md describes the same missing Amazon-owned catalog on this fixture step, but the replay reports this cluster as unowned (its diverging key set has grown — per-document members such as AWS-GatherSoftwareInventory.CreatedDate/Tags and AWS-RunPowerShellScript.PlatformTypes[1] now diverge too), so it is filed here rather than assumed covered.

## Evidence
Replay of trace set simparity-wire-aws-v1 (175 fixtures, 850 steps, 465 passed, score 54.7%, emulator_up=true, bootstrap_signal=false).

Cause 1 — fixture ssm-automation-signal-stopstep-and-invalid-filter-error, step task#4, operation SendAutomationSignal, verdict mismatch, expected_status 400 / actual_status 400:
  $.Message: value_mismatch (expected 'One StepName is required when signal type is StopStep.', got "Failed to process signal StopStep. The signal isn't valid for the current Automation execution.")
  Also affected: ssm-automation-stop-and-signal-error-paths#task#7.
  Fixed text of AWS's message: the whole sentence 'One StepName is required when signal type is StopStep.' — 'StepName' is the required Payload member name and 'StopStep' is the request's SignalType; no value comes from a run.

Cause 2 — fixture ssm-catalog-list-documents, step task#1, operation ListDocuments, verdict mismatch, expected_status 200 / actual_status 200:
  $.DocumentIdentifiers[Name="AWS-ASGEnterStandby"]: missing (expected {'Categories': ['InstanceManagement'], 'DocumentFormat': 'JSON', 'DocumentType': 'Automation', 'DocumentVersion': '1', 'Name': 'AWS-ASGEnterStandby', 'Owner': 'Amazon', 'PlatformTypes': ['Windows','Linux','MacOS'], 'SchemaVersion': '0.3', 'Tags': [], 'TargetType': '/AWS::EC2::Instance', 'CreatedDate': <timestamp>}, got None)
  $.DocumentIdentifiers[Name="AWS-ApplyAnsiblePlaybooks"]: missing (expected a Command document, SchemaVersion '2.2', PlatformTypes ['Linux'], got None)
  ... the same 'missing' verdict for the remaining Amazon-owned documents, including the full AWSConfigRemediation-* and AWSConformancePacks-* families.
  $.DocumentIdentifiers[Name="AWS-ConfigureS3BucketVersioning"].Categories / .CreatedDate / .DocumentFormat / .Tags / .TargetType: missing
  $.DocumentIdentifiers[Name="AWS-RunPowerShellScript"].Categories / .CreatedDate / .SchemaVersion / .Tags / .PlatformTypes[1]: missing
  $.DocumentIdentifiers[Name="AWS-RunShellScript"].Categories / .CreatedDate / .SchemaVersion / .Tags: missing
  (Timestamps, request ids and generated ids in the recording are per-run values and are not part of the requirement.)

## Steps to Reproduce
Cause 1: replay fixture ssm-automation-signal-stopstep-and-invalid-filter-error, step task#4 — start an Automation execution, then call SendAutomationSignal with that AutomationExecutionId, SignalType='StopStep' and no StepName entry in Payload. AWS answers HTTP 400 InvalidAutomationSignalException with $.Message 'One StepName is required when signal type is StopStep.'; the emulator answers HTTP 400 with $.Message "Failed to process signal StopStep. The signal isn't valid for the current Automation execution.". Same divergence at ssm-automation-stop-and-signal-error-paths#task#7.

Cause 2: replay fixture ssm-catalog-list-documents, step task#1 — call ListDocuments against a fresh account with no customer documents. AWS returns the Amazon-owned catalog (Owner 'Amazon', hundreds of AWS-*/AWSConfigRemediation-*/AWSConformancePacks-* entries) with the full DocumentIdentifier projection; the emulator returns only a handful of AWS-* documents, each missing Categories, CreatedDate, DocumentFormat, Tags and TargetType (and SchemaVersion / a PlatformTypes entry for AWS-RunShellScript and AWS-RunPowerShellScript).
