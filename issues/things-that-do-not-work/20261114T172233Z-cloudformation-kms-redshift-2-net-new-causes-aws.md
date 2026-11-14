Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-round-trip-and-delete cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-invalid-kms-key-rejected
Issue-Key: cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-round-trip-and-delete|run#11|AssertionError|assert (out["GrantRef"], out["GrantArn"]) == (want_arn, want_arn), f"Ref/GetAtt {out!r}"
Issue-Key: cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-invalid-kms-key-rejected|run#11|AssertionError|assert got == want, f"DescribeKey of the missing key raised {got!r}, expected {want!r}"
Issue-Commit: a2d6c7a74c3b04e1146167d89a2a7f728862e388

# cloudformation__kms__redshift: 2 net-new causes — AWS::Redshift::SnapshotCopyGrant Ref returns the grant name and GetAtt Arn uses a slash-form ARN, and the degenerate all-zeros ambient account id corrupts account-masked KMS refusal messages

> _Note: this issue was identified against the code base at commit `a2d6c7a74c3b04e1146167d89a2a7f728862e388`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
CreateSnapshotCopyGrant

## Description
Two distinct root causes, both reached through CloudFormation stacks that declare an AWS::Redshift::SnapshotCopyGrant on a stack-owned AWS::KMS::Key.

Cause 1 of 2 — the CloudFormation resource AWS::Redshift::SnapshotCopyGrant publishes the wrong Ref value and a wrong-shaped Arn attribute. Failing check: cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-round-trip-and-delete.
AWS:      recorded/documented behavior only — the Smithy model carries no ARN member for this resource (CreateSnapshotCopyGrant returns SnapshotCopyGrant{SnapshotCopyGrantName, KmsKeyId, Tags}; DescribeSnapshotCopyGrants returns SnapshotCopyGrants + Marker, no Arn), so the requirement comes from the Redshift ARN namespace and the CloudFormation resource reference (https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-snapshotcopygrant.html). Redshift resource ARNs are colon-delimited on the resource type: the grant's ARN is `arn:<partition>:redshift:<region>:<account>:snapshotcopygrant:<SnapshotCopyGrantName>`. Both `{"Ref": "<Grant>"}` and `{"Fn::GetAtt": ["<Grant>", "Arn"]}` resolve to that same ARN string. Fixed text: the literal segments `arn:`, `:redshift:` and `:snapshotcopygrant:`; the variable parts are the partition, region and account of the stack (taken from the StackId/caller identity) and the SnapshotCopyGrantName taken from the template property.
Emulator: `Ref` resolves to the bare grant name (the physical id is the name, not the ARN), and the `Arn` attribute is minted in the S3/ECS-style slash form `arn:<partition>:redshift:<region>:<account>:snapshot-copy-grant/<name>` — a hyphenated resource type and a `/` separator, neither of which Redshift uses. In the replay the stack reached CREATE_COMPLETE and published GrantRef=`<grant-name>` and GrantArn=`arn:aws:redshift:<region>:<account>:snapshot-copy-grant/<grant-name>` where both outputs must have been `arn:aws:redshift:<region>:<account>:snapshotcopygrant:<grant-name>`.
Why:      a template that passes `!Ref Grant` or `!GetAtt Grant.Arn` into an IAM policy resource element, a cross-region snapshot-copy configuration, a tagging call or another stack via Export/ImportValue gets a string that is not an ARN at all (Ref) or an ARN no Redshift or IAM ARN parser matches (GetAtt). Policies written against it never match, and any consumer that splits the ARN on `:` to recover the resource type/name reads the wrong fields. The deploy looks healthy, so the breakage surfaces only downstream.
Fix:      the CloudFormation resource provider for AWS::Redshift::SnapshotCopyGrant — its physical-resource-id/Ref resolution and its ARN construction for the `Arn` attribute (the shared Redshift ARN minting helper must use the `:snapshotcopygrant:` colon form, not `<type>/<name>`). Redshift's own CreateSnapshotCopyGrant/DescribeSnapshotCopyGrants handlers are consistent with the model here; only the ARN/Ref projection diverges.
Traces:   cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-round-trip-and-delete (stack reached CREATE_COMPLETE; the assertion on Ref/GetAtt Arn is the first failure, so the later DescribeSnapshotCopyGrants-after-delete and key PendingDeletion legs of that check were never exercised and may hide further divergence).

Cause 2 of 2 — the emulator's ambient AWS account identifier is the degenerate all-zeros string `000000000000`, so an account-redacting client eats a twelve-digit run out of an otherwise-correct KMS NotFoundException message. Failing check: cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-invalid-kms-key-rejected. This is the same root cause already filed as 20261113T201216Z-cloudformation-route53-the-emulator-s-ambient-aws-account-identifier-is.md (observed there on a Route 53 handler reason); that issue is not recorded as owning this check, so it is reported here for the KMS/Redshift path it also breaks, and a fixer that closes that one closes this cause too.
AWS:      recorded behavior only for the account value — Smithy states nothing about it (the STS account member is an unconstrained string); AWS allocates every account a non-degenerate 12-digit id and reserves the all-zero string as a non-account sentinel. KMS DescribeKey for a syntactically valid key id the account never created answers HTTP 400 with error code NotFoundException and the message `Key '<key-arn>' does not exist`, where the fixed text is `Key '` ... `' does not exist` and the variable part is the requested KeyId normalized to its full ARN `arn:<partition>:kms:<region>:<account>:key/<key-id>`.
Emulator: the refusal itself is faithful — code NotFoundException and that exact wording with the requested key id normalized to an ARN. What diverges is the identity the emulator speaks for: its account id is the twelve-character all-zero string, which is a substring of other identifiers. The check masks the caller's own account out of the message before comparing, so with the probe key id `00000000-0000-0000-0000-000000000000` the mask consumes the key's final twelve zeros as well as the ARN's account segment and the compared message becomes `Key 'arn:aws:kms:<region>:<account>:key/00000000-0000-0000-0000-<account>' does not exist` instead of `Key 'arn:aws:kms:<region>:<account>:key/00000000-0000-0000-0000-000000000000' does not exist`. Derivation: the two strings differ by exactly one twelve-zero run replaced with the mask token, which is only possible when the emulator's account value is `000000000000`.
Why:      any client that embeds, redacts or pattern-matches the caller's account id — log scrubbers, ARN parsers, cross-account policy comparisons, test harnesses — collides with unrelated digit runs, and anything that rejects the reserved all-zero account id misbehaves against the emulator while working against AWS. The same value is stamped into every ARN the emulator mints.
Fix:      the emulator's ambient caller identity / default account value (the account the STS identity resolution reports and that the ARN-minting engine stamps in) should be a non-degenerate 12-digit account id. Nothing in the KMS DescribeKey handler or its NotFoundException serializer needs to change.
Traces:   cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-invalid-kms-key-rejected (the masked-message comparison is the first failure, so the ROLLBACK_COMPLETE, CREATE_FAILED-reason and SnapshotCopyGrantNotFoundFault legs of that check were never exercised).

## Evidence
Cause 1 — failing check cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-round-trip-and-delete:

AssertionError: Ref/GetAtt {'GrantRef': 'sim2real-cfnrs-scg-41dc56efc341', 'GrantArn': 'arn:aws:redshift:us-west-2:000000000000:snapshot-copy-grant/sim2real-cfnrs-scg-41dc56efc341', 'KeyId': 'd2201702-aaa1-448b-b157-694036fd391c', 'KeyArn': 'arn:aws:kms:us-west-2:000000000000:key/d2201702-aaa1-448b-b157-694036fd391c'}

Expected (AWS): GrantRef == GrantArn == arn:<partition>:redshift:<region>:<account>:snapshotcopygrant:<SnapshotCopyGrantName>.
Actual (emulator): GrantRef == the bare <SnapshotCopyGrantName>; GrantArn == arn:<partition>:redshift:<region>:<account>:snapshot-copy-grant/<SnapshotCopyGrantName> (hyphenated resource type, '/' separator). The name/id/account values above are this run's and are not part of the requirement.

Cause 2 — failing check cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-invalid-kms-key-rejected:

AssertionError: DescribeKey of the missing key raised ('NotFoundException', "Key 'arn:aws:kms:us-west-2:<account>:key/00000000-0000-0000-0000-<account>' does not exist"), expected ('NotFoundException', "Key 'arn:aws:kms:us-west-2:<account>:key/00000000-0000-0000-0000-000000000000' does not exist")

Expected (AWS): with a real 12-digit account id, only the ARN's account segment is masked and the message reads Key 'arn:<partition>:kms:<region>:<account>:key/<requested-key-id>' does not exist.
Actual (emulator): same status class, same error code NotFoundException, same fixed text and same echoed key id — but because the emulator's account id is the twelve-character all-zero string, the account mask also consumes the last twelve zeros of the key id, proving the ambient account value is 000000000000.

## Steps to Reproduce
Cause 1:
1. Boot the emulator and CreateStack with a template declaring an AWS::KMS::Key and an AWS::Redshift::SnapshotCopyGrant whose KmsKeyId is {"Ref": "Key"}, with Outputs GrantRef={"Ref":"Grant"} and GrantArn={"Fn::GetAtt":["Grant","Arn"]}.
2. Wait for CREATE_COMPLETE and read DescribeStacks Outputs.
3. Observe GrantRef is the bare SnapshotCopyGrantName and GrantArn is arn:<partition>:redshift:<region>:<account>:snapshot-copy-grant/<name>; both must be arn:<partition>:redshift:<region>:<account>:snapshotcopygrant:<name>.
4. Replay: cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-round-trip-and-delete.

Cause 2:
1. Call sts:GetCallerIdentity against the emulator — observe Account == "000000000000".
2. Call kms:DescribeKey with KeyId="00000000-0000-0000-0000-000000000000" and read the NotFoundException message.
3. Replace the caller's own account id with a placeholder, as any account-redacting client does: twelve zeros disappear from the middle of the echoed key id as well as from the ARN's account segment, because the emulator's account id is itself twelve zeros.
4. Replay: cloudformation__kms__redshift.cfn-redshift-snapshotcopygrant-invalid-kms-key-rejected.
