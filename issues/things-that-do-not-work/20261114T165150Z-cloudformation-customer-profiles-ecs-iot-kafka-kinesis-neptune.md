Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: cloudformation__customer-profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables.cdk-streaming-iot-estate-serves-and-destroys
Issue-Key: cloudformation__customer-profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables.cdk-streaming-iot-estate-serves-and-destroys|_run_cli#15|AssertionError|assert result.returncode == 0, (
Issue-Commit: de4891d4239c492b9e977f3e9646a8637ce0e129

# cloudformation__customer-profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables: the ten-stack streaming/IoT CDK estate cannot be deployed — CloudFormation refuses a synthesized template with "Template format error", so `cdk deploy --all` exits 1

> _Note: this issue was identified against the code base at commit `de4891d4239c492b9e977f3e9646a8637ce0e129`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
CreateStack

## Description
One root cause, reported under the suite heading '### cloudformation__customer-profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables' (0/1 passed).

Cause 1 of 1: CloudFormation rejects at least one of the CDK-synthesized templates of this estate at template-parse time, so `cdk deploy --all` of the whole estate exits 1 and nothing is provisioned.
  Failing check: cloudformation__customer-profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables.cdk-streaming-iot-estate-serves-and-destroys.
  AWS: CloudFormation's template parser and resource-type registry are not part of the Smithy model (the cloudformation model declares CreateStack/DescribeStacks/DescribeStackEvents/DescribeEvents and their shapes only), so this is recorded behavior only. Recorded behavior: real AWS ACCEPTS every template this CDK app synthesizes — `cdk bootstrap` then `cdk deploy --all` exits 0 and all ten stacks of the estate (AppRoles, Connect, S3Etl, Iot, EventBridge, Ecs, Kinesis, RdsDms, Msk, Neptune) reach CREATE_COMPLETE, after which the estate serves (Customer Profiles domain, the seeded S3 ETL objects, an IoT thing shadow, the EventBridge bus, an InService ECS container instance, the Kinesis stream, the S3 Tables tables, the MSK topic and the Neptune graph) and `cdk destroy` removes it without residue. The deploy must not fail on a template the CDK produced.
  Emulator: the CLI output tail ends in a CloudFormation refusal — "Template format error: U…" (the replay captured the message truncated at that point, but "Template format error: " is the emulator's own template-parse refusal prefix, served as HTTP 400 ValidationError from CreateStack; the emulator uses it for example in "Template format error: Unrecognized resource types: [<Type>]", see open issue 20261109T181259Z-cloudformation-connecthealth-aws-healthagent-domain-is-not-a.md). `cdk deploy --all` therefore exits 1 and the check asserts nothing about the estate. Everything printed before the refusal is CDK's own local cfn-lint style WARNING/E9006 annotations (RDS engine-version list, StorageEncrypted, desiredCapacity), which are advisory and not failures; the only error is the CloudFormation one.
  Why: a client cannot deploy this estate as infrastructure-as-code at all. A template-parse refusal is indistinguishable, to a user, from "my template is malformed", so an unsupported resource type or template construct in the emulator reads as a defect in the user's own app; and because the deploy never starts, the entire estate contract behind it (every stack's CREATE_COMPLETE, the cross-stack wiring, the data-plane behavior of nine services, the negative branches the check exercises — a missing shadow, an undefined search key, malformed EventBridge detail, a missing S3 Tables namespace — and the clean `cdk destroy`) is unverifiable.
  Fix: the CloudFormation crate's template parser / resource-type registry and the resource handlers it dispatches to. The first step is to recover the full refusal text (the replay truncated it after "Template format error: U") by submitting the synthesized templates of this app's ten stacks to CreateStack one at a time and reading the ValidationError message; then register the construct or resource type(s) it names and add their handlers, so the template is accepted and the stack proceeds to per-resource handling instead of being refused at parse.
  Traces: cloudformation__customer-profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables.cdk-streaming-iot-estate-serves-and-destroys.

## Evidence
Behavioral suite simparity-behavioral-aws-v1 replayed against the emulator built from this checkout. Total 88/303 passed (29.0%); bootstrap_signal=false. Heading '### cloudformation__customer-profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables': 0/1 (0%), 1 failed [mismatch].

  File "check_cloudformation__customer_profiles__ecs__iot__kafka__kinesis__neptune__rds__s3tables_cdk_streaming_iot_estate_serves_and_destroys.py", line 797, in _cdk
    _run_cli(ctx, cmd, work, timeout_s, f"`cdk {' '.join(args[:2])}`")
  File "...", line 810, in _run_cli
    assert result.returncode == 0, (
  AssertionError: `cdk deploy --all` exited 1, expected 0; output tail: "... (CloudFormation Validate)\n   sim2real-sio-<id>-RdsDms/AppMysql/Resource (AppMysql08E2FCF9) aws-cdk-lib.aws_rds.CfnDBInstance\n   Acknowledge with 'CloudFormation-Validate::E9006'\n\nWARNING StorageEncrypted: RDS instance should have StorageEncrypted set to true (CloudFormation Validate)\n   ...\n   Acknowledge with 'CloudFormation-Validate::W9008'\n\nWARNING desiredCapacity has been configured. ... (Construct Annotations)\n   sim2real-sio-<id>-Ecs/EcsAsg\n   Acknowledge with 'Annotation::@aws-cdk/aws-autoscaling:desiredCapacitySet'\nTemplate format error: U

The prerequisites the runner needed were present: require_tools("cdk", "node") passed and the CLI ran to the point of calling CloudFormation, so this is not a missing-tool or network failure of the runner. The CDK annotations quoted above (E9006 engine-version list, W9008 StorageEncrypted, desiredCapacitySet) are local advisory warnings emitted by the CDK CLI, not the failure; the deploy's non-zero exit is the CloudFormation "Template format error: " refusal, the emulator's template-parse ValidationError. The replay output truncates that message after its first character of detail ("U"), which is why the exact unsupported type/construct must be recovered by resubmitting the synthesized templates.

Stack names, the sim2real-sio-<id> prefix, the CDK logical ids and the temp directory path above are per-run values and are not part of the requirement.

Assertions never reached in the check: all ten stacks (AppRoles, Connect, S3Etl, Iot, EventBridge, Ecs, Kinesis, RdsDms, Msk, Neptune) reaching CREATE_COMPLETE; the interface endpoints iot.data/ecs/ecs-agent/ecs-telemetry present in every VPC zone; the three seeded ETL objects raw/orders_2026_01.csv, raw/orders_2026_02.csv, raw/orders_2026_03.csv with one body read back byte-exact; the operator role carrying only ReadOnlyAccess and the read-only role carrying AmazonS3TablesReadOnlyAccess + ReadOnlyAccess; an Auto Scaling member InService; the IoT shadow, EventBridge bus, Kinesis stream, S3 Tables tables, MSK topic and Neptune graph serving; the four negative branches (missing shadow, undefined search key, malformed detail, missing namespace) being refused; and `cdk destroy` leaving no residue.

Model note: CloudFormation's template parser and resource-type registry are not modelled in the cloudformation Smithy model, so the acceptance of a CDK-synthesized template is recorded behavior only.

## Steps to Reproduce
Boot the emulator built from this checkout and point the CDK CLI and botocore clients at it (cdk and node must be on PATH). Re-replay the check in trace_ids to confirm the fix.

1. Run the check's app (the ten-stack cdk_streaming_iot_estate, region us-east-1): `cdk bootstrap`, then `cdk deploy --all --ci --no-version-reporting --no-notices`.
   Expect: exit 0, with all ten stacks CREATE_COMPLETE.
   Observe today: exit 1; the output tail ends with CloudFormation's "Template format error: U…" refusal.
2. Recover the full refusal: run `cdk synth` for each of the ten stacks and POST each synthesized template to CreateStack directly, reading the HTTP 400 ValidationError message in full. It names the resource type(s) or template construct the emulator's parser does not recognize.
3. Register that type/construct in the CloudFormation crate's resource-type registry with its schema and add its resource handler (delegating to the owning service's operations), so CreateStack accepts the template and any property problem is reported as a per-resource PROPERTY_VALIDATION/CREATE_FAILED event rather than a template-parse refusal.
4. Re-run step 1 and then the estate's serve-and-destroy assertions (profiles, seeded S3 objects, IoT shadow, EventBridge bus, InService container instance, Kinesis stream, S3 Tables tables, MSK topic, Neptune graph; the four negative branches; `cdk destroy` leaving no residue).
