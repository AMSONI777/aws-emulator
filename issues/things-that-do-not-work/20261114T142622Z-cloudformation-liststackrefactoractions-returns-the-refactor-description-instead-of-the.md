Issue-Source: trace-sweep-divergence
Issue-Trace: cloudformation-stack-refactor-lifecycle
Issue-Step: task#10
Issue-Severity: MEDIUM
Issue-Corpus: simparity-wire-aws-v1
Issue-Corpus-Kind: wire
Issue-Trace-Ids: cloudformation-stack-refactor-lifecycle
Issue-Shape-Id: com.amazonaws.cloudformation#CloudFormation
Issue-Key: cloudformation|ListStackRefactorActions|2xx->2xx|$.ListStackRefactorActionsResponse.ListStackRefactorActionsResult.StackRefactorActions.member.Description
Issue-Key: cloudformation|ListStackRefactorActions|2xx->2xx|$.ListStackRefactorActionsResponse.ListStackRefactorActionsResult.StackRefactorActions.member.TagResources
Issue-Key: cloudformation|ListStackRefactorActions|2xx->2xx|$.ListStackRefactorActionsResponse.ListStackRefactorActionsResult.StackRefactorActions.member.UntagResources
Issue-Commit: 84412ef57d49d3e319b2b9326649851b03084832

# ListStackRefactorActions returns the refactor description instead of the per-action description and omits the action tag plan

> _Note: this issue was identified against the code base at commit `84412ef57d49d3e319b2b9326649851b03084832`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
ListStackRefactorActions

## Description
One net-new wire divergence in the CloudFormation stack-refactor plan read-out. The emulator's ListStackRefactorActions answers 200 but the StackRefactorAction it serializes is not the planned action AWS describes: it re-uses the refactor-level description and leaves the action's tag plan out entirely.

=== Cause 1 of 1: the StackRefactorAction carries the refactor's own Description and no TagResources/UntagResources (fixture cloudformation-stack-refactor-lifecycle, step task#10, operation ListStackRefactorActions) ===
AWS: Smithy: ListStackRefactorActions(StackRefactorId required, NextToken @length 1..1024, MaxResults @range 1..100) -> StackRefactorActions (required list) + NextToken, @paginated(items=StackRefactorActions). The list member StackRefactorAction models Action (enum StackRefactorActionType: MOVE|CREATE), Entity (Stack|Resource), PhysicalResourceId, ResourceIdentifier, Description (@length 1..1024, documented as "A description to help you identify the refactor" for THAT action), Detection (AUTO|MANUAL), DetectionReason, TagResources (list of Tag, "Assigns one or more tags to specified resources"), UntagResources (list of TagKey @length 1..128, "Removes one or more tags to specified resources") and ResourceMapping. So Description is a per-action string that CloudFormation itself computes when it plans the action, and TagResources/UntagResources are the tag mutations the action will apply to the moved resource. Recorded behavior: for a resource MOVE whose template properties are unchanged between source and destination, the action's Description is the fixed text 'No configuration changes detected.', TagResources lists the CloudFormation-managed tags the destination stack will assign to the moved resource — keys 'aws:cloudformation:stack-name', 'aws:cloudformation:logical-id' and 'aws:cloudformation:stack-id', whose values come from the destination stack and the resource's logical id in it (stack name, logical id, stack ARN) — and UntagResources lists exactly those same three keys, to be removed as they are carried over from the source stack. In the recording the values are the destination stack's name, the moved resource's logical id and the destination stack's ARN; those particular strings are the template slots filled from request/state, not part of the requirement. The fixed parts are the Description text and the three aws:cloudformation:* tag keys.
Emulator: answers 200 with StackRefactorActions.member.Description = the refactor-level Description echoed from the CreateStackRefactor request (in the recording 'probe-refactor') instead of the computed per-action text, and with TagResources and UntagResources absent from the member entirely (both read as None).
Why: a client inspecting a refactor plan before executing it cannot tell what the refactor will actually do. The per-action Description is what tooling and the console surface as the reason for each planned action, so it reads back the caller's own label and conveys nothing about whether a configuration change was detected. With the tag plan missing, a caller reviewing or diffing the plan sees no tag mutations at all and will conclude the moved resource keeps its source-stack CloudFormation tags, so approval gates and plan-diff checks that assert on the aws:cloudformation:* tag transfer either fail or silently pass on an empty plan.
Fix: the ListStackRefactorActions handler and its StackRefactorAction serializer, together with the refactor-plan computation in the service's stack-refactor state — the plan stored at CreateStackRefactor time must record a per-action description and the add/remove tag sets for each moved resource, and the serializer must emit the modelled TagResources/UntagResources members.
Traces: cloudformation-stack-refactor-lifecycle#task#10. The open issue 20261102T023139Z-cloudformation-stack-refactor-execution-stackset-import-validation-and.md covers step task#12 of the same fixture (ExecuteStackRefactor never advancing ExecutionStatus) and does not carry this step's replay key or touch the action plan's contents; the open stub issues 20261101T164248Z-cloudformation-liststackrefactors-stub.md and 20261109T123922Z-cloudformation-executestackrefactor-stub.md are about other operations.

## Evidence
Cause 1 — cloudformation-stack-refactor-lifecycle#task#10, ListStackRefactorActions, status 200->200 (verdict mismatch, 1 affected step):
  $.ListStackRefactorActionsResponse.ListStackRefactorActionsResult.StackRefactorActions.member.Description: value_mismatch
    expected: 'No configuration changes detected.'
    actual:   'probe-refactor'   (the Description supplied to CreateStackRefactor)
  $.ListStackRefactorActionsResponse.ListStackRefactorActionsResult.StackRefactorActions.member.TagResources: missing
    expected: {'member': [{'Key': 'aws:cloudformation:stack-name', 'Value': <destination stack name>}, {'Key': 'aws:cloudformation:logical-id', 'Value': <moved resource logical id>}, {'Key': 'aws:cloudformation:stack-id', 'Value': <destination stack ARN>}]}
    actual:   None
  $.ListStackRefactorActionsResponse.ListStackRefactorActionsResult.StackRefactorActions.member.UntagResources: missing
    expected: {'member': ['aws:cloudformation:stack-name', 'aws:cloudformation:logical-id', 'aws:cloudformation:stack-id']}
    actual:   None

Fixed vs variable: the Description text 'No configuration changes detected.' and the three tag KEYS are fixed; the tag VALUES are taken from the destination stack and the resource's logical id in it. The recorded run's concrete values (stack name 'sim2real-probe-cloudformation-cfn-rfB-a474c29f', logical id 'MovedParam', stack ARN 'arn:aws:cloudformation:us-west-2:000000000000:stack/sim2real-probe-cloudformation-cfn-rfB-a474c29f/ec9ad945-...') are per-run and are not themselves the requirement.

## Steps to Reproduce
Replay the wire corpus simparity-wire-aws-v1 against the emulator (replay_wire_corpus), or exercise the step directly:

Cause 1: fixture cloudformation-stack-refactor-lifecycle, step task#10. Create two stacks (a source holding a resource and an empty destination), call CreateStackRefactor with Description set to any label and a ResourceMapping moving that resource from the source stack to the destination stack, wait until DescribeStackRefactor reports Status CREATE_COMPLETE, then call ListStackRefactorActions(StackRefactorId=<that id>) and inspect the returned StackRefactorActions member. AWS reports the move action with Description 'No configuration changes detected.' and with TagResources/UntagResources naming the aws:cloudformation:stack-name, aws:cloudformation:logical-id and aws:cloudformation:stack-id tags; the emulator reports the CreateStackRefactor Description and omits both tag lists.
