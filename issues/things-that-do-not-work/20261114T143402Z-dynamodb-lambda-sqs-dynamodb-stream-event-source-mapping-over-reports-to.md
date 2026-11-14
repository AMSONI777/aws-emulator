Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: dynamodb__lambda__sqs.dotnet-dynamodb-stream-new-and-old-image-fidelity-via-onfailure-destination
Issue-Key: dynamodb__lambda__sqs.dotnet-dynamodb-stream-new-and-old-image-fidelity-via-onfailure-destination|run#17|AssertionError|assert len(records) == 1, (
Issue-Commit: 09a4de48f58372094bfcb9a0bb2c4d192074b72e

# DynamoDB-stream event source mapping over-reports to its OnFailure destination: an accepted INSERT batch and an already-dead-lettered batch are both written as RetryAttemptsExhausted

> _Note: this issue was identified against the code base at commit `09a4de48f58372094bfcb9a0bb2c4d192074b72e`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
Invoke

## Description
Cause 1 of 1: a DynamoDB-stream event source mapping with BatchSize=1 and DestinationConfig.OnFailure writes MORE OnFailure records than the batches that actually exhausted their retries — a batch whose invocation the handler accepted, and a batch that was already reported, are both written to the destination. Failing check id: dynamodb__lambda__sqs.dotnet-dynamodb-stream-new-and-old-image-fidelity-via-onfailure-destination.

AWS: a table created with StreamSpecification.StreamViewType = NEW_AND_OLD_IMAGES (Smithy, dynamodb: CreateTable.StreamSpecification -> StreamViewType enum, member NEW_AND_OLD_IMAGES) emits one stream Record per item write whose `dynamodb` StreamRecord carries Keys, SequenceNumber, StreamViewType and the images as typed attribute maps: NewImage ONLY for eventName INSERT (OldImage absent), and BOTH OldImage (pre-image) and NewImage (post-image) for eventName MODIFY. Smithy, lambda: CreateEventSourceMapping input carries DestinationConfig (OnFailure.Destination), BatchSize @range 1..10000 and MaximumRetryAttempts @range -1..10000; POST /2015-03-31/event-source-mappings, 202. The content of the OnFailure record written to the destination queue is recorded behavior only (not modeled): the recording shows one JSON body per batch that exhausted retries, carrying version, timestamp, requestContext{functionArn, condition "RetryAttemptsExhausted", approximateInvokeCount} and DDBStreamBatchInfo{shardId, batchSize, streamArn, startSequenceNumber, approximateArrivalOfFirstRecord, endSequenceNumber, approximateArrivalOfLastRecord}. The invariant AWS holds, and the one this check grades, is one-to-one: exactly ONE OnFailure record for a batch whose invocations are exhausted, NONE for a batch whose invocation succeeded, and never a second record for a batch already reported. With BatchSize=1 on a single shard reader this makes the record count per write deterministic.

Emulator: the check writes an always-rejected warm-up item, drains the destination queue of its OnFailure record, then writes one item the handler must ACCEPT (Marker equal to the handler's EXPECTED_MARKER, so its NewImage/OldImage fidelity check passes) followed by one always-rejected trailing sentinel, and drains again. AWS leaves exactly one record on that second drain — the trailing sentinel's. The emulator left TWO. Both are well-formed (condition "RetryAttemptsExhausted", batchSize 1, the correct streamArn), but their startSequenceNumber/endSequenceNumber identify the FIRST and SECOND records of the shard — the already-drained warm-up write and the accepted INSERT — and neither identifies the trailing sentinel that is the only write that should have been reported. The check fails with AssertionError: "INSERT produced 1 extra OnFailure record(s) beyond the trailing sentinel: the handler's NewImage/OldImage fidelity check for an INSERT record failed". Hypothesis for the two sub-mechanisms, neither stated by the model nor by the recording: the INSERT record is marshalled into the invocation event without a faithful typed NewImage (or with an OldImage that AWS omits on INSERT), so the handler throws and the accepted batch is dead-lettered; and a batch whose OnFailure record was already written is not checkpointed, so it is written to the destination again after the next write. The divergence itself is the record count and the sequence numbers those records name, independent of the mechanism.

Why: a consumer that uses an OnFailure destination as its poison-record ledger cannot trust it. Records the function processed successfully appear in the dead-letter sink, so operators reprocess or alert on data that was never lost, while duplicate reports of one batch inflate every failure count derived from the sink. Worse, because the INSERT record is rejected, a NEW_AND_OLD_IMAGES consumer that reads dynamodb.NewImage/OldImage sees no faithful before/after pair at all — the exact contract the stream view type exists to provide.

Fix: the Lambda event-source-mapping delivery path for DynamoDB stream sources — (a) its stream-record-to-invocation-event marshalling, which must place the typed attribute maps under dynamodb.NewImage/OldImage per the stream's StreamViewType and omit OldImage for INSERT, and (b) its OnFailure disposition and checkpoint state, which must emit one destination record per exhausted batch and none for a batch that succeeded or was already reported. Not the DynamoDB stream itself: the stream records are produced and sequenced, and the warm-up rejection reaches the destination correctly.

Note: open issue 20261109T172142Z-dynamodb-lambda-sqs-dynamodb-stream-records-never-reach-net-java-or.md lists this check id, but it describes stream records never reaching the .NET/Java/Ruby handler at all (its replay key for this check is a TimeoutError in _await_failure_records, waiting for the warm-up rejection that never came). Records now DO reach the handler — the warm-up rejection arrives — so that issue does not cover this defect; this is the next-layer divergence in the same path, failing on a different assertion.

Values that are per-run and NOT requirements: the shardId, stream and function ARNs, the generated table/queue/function names, the timestamps, approximateInvokeCount and the literal sequence-number digits. The requirement is the record COUNT per batch and that each record's startSequenceNumber/endSequenceNumber name the batch that actually exhausted its retries.

Traces: dynamodb__lambda__sqs.dotnet-dynamodb-stream-new-and-old-image-fidelity-via-onfailure-destination (check source at check_dynamodb__lambda__sqs_dotnet_dynamodb_stream_new_and_old_image_fidelity_via_onfailure_destination.py line 328, assertion after the INSERT leg).

## Evidence
Expected (AWS): after draining the warm-up OnFailure record, a PutItem of an item the handler accepts followed by one always-rejected sentinel PutItem leaves EXACTLY ONE message on the OnFailure destination queue — the sentinel's batch — with requestContext.condition "RetryAttemptsExhausted", DDBStreamBatchInfo.batchSize 1, and startSequenceNumber/endSequenceNumber equal to the sentinel record's own sequence number. No record for the accepted INSERT, and no second record for the already-reported warm-up batch.

Actual (emulator): TWO messages on the destination queue. Both bodies are well-formed and both carry requestContext.condition "RetryAttemptsExhausted", approximateInvokeCount 1, DDBStreamBatchInfo.batchSize 1 and the correct streamArn, but their start/endSequenceNumber are the first and second records of the shard rather than the trailing sentinel's:
  record A: DDBStreamBatchInfo.startSequenceNumber = endSequenceNumber = <shard record #1>  (the warm-up write, whose OnFailure record had already been drained)
  record B: DDBStreamBatchInfo.startSequenceNumber = endSequenceNumber = <shard record #2>  (the INSERT the handler accepted)
The check therefore fails:
  AssertionError: INSERT produced 1 extra OnFailure record(s) beyond the trailing sentinel: the handler's NewImage/OldImage fidelity check for an INSERT record failed: [<two RetryAttemptsExhausted bodies>]
Status/error code: none — this is not a refusal. Every API call in the leg succeeded (CreateTable 200, CreateEventSourceMapping 202 reaching State Enabled, PutItem 200, ReceiveMessage 200); the divergence is in the records the emulator delivers to the OnFailure destination.

## Steps to Reproduce
1. CreateTable with KeySchema pk (HASH, S), BillingMode PAY_PER_REQUEST and StreamSpecification {StreamEnabled: true, StreamViewType: NEW_AND_OLD_IMAGES}; wait for TableStatus ACTIVE and LatestStreamArn.
2. CreateQueue for the OnFailure destination and read its QueueArn.
3. CreateFunction with Runtime dotnet8 whose handler validates each DynamoDB stream record and THROWS unless the record's dynamodb.NewImage carries Marker equal to the EXPECTED_MARKER environment variable (and, for MODIFY, OldImage.Value = "1" / NewImage.Value = "2").
4. CreateEventSourceMapping from the table's LatestStreamArn to the function with BatchSize=1, StartingPosition LATEST and DestinationConfig {OnFailure: {Destination: <queue ARN>}}; wait until State is Enabled.
5. PutItem an item whose Marker does NOT match EXPECTED_MARKER (the warm-up). Wait for its OnFailure record and drain the queue empty.
6. PutItem {pk: "row-1", Marker: <EXPECTED_MARKER>, Value: {N: "1"}} — the handler must accept this record.
7. PutItem a second non-matching sentinel item.
8. Poll the destination queue until a message arrives, then drain it fully.
9. Observe TWO messages instead of one. Inspect each body's DDBStreamBatchInfo.startSequenceNumber: they name the warm-up record and the accepted INSERT, not the trailing sentinel.
