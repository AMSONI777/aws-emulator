Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: apigateway__dynamodb__lambda__logs.ddb-esm-destination-on-failure-missing-config-negative
Issue-Key: apigateway__dynamodb__lambda__logs.ddb-esm-destination-on-failure-missing-config-negative|_poll_until#22|Timeout|time.sleep(interval_s)
Issue-Commit: 47219b124a45386662a63382125b929260efea78

# apigateway__dynamodb__lambda__logs: a DynamoDB-stream ESM with MaximumRetryAttempts=0 produces no observable delivery — neither the record after the exhausted one nor the OnFailure SQS batch-info record ever appears

> _Note: this issue was identified against the code base at commit `47219b124a45386662a63382125b929260efea78`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
CreateEventSourceMapping

## Description
Cause 1 of 1: a DynamoDB-Streams event source mapping with MaximumRetryAttempts=0 neither moves past the always-failing record (the next record's side effect never lands) nor, on the sibling mapping configured with DestinationConfig.OnFailure = an SQS queue, delivers the failure record — the scenario makes no progress and is killed at the runner cap. Failing check: apigateway__dynamodb__lambda__logs.ddb-esm-destination-on-failure-missing-config-negative.

AWS: Smithy (lambda): CreateEventSourceMapping accepts MaximumRetryAttempts and DestinationConfig; DestinationConfig$OnFailure is 'The destination configuration for failed invocations' and OnFailure$Destination is documented as 'To retain records of failed invocations from Kinesis, DynamoDB, self-managed Apache Kafka, or Amazon MSK, you can configure an Amazon SNS topic, Amazon SQS queue, Amazon S3 bucket, or Kafka topic as the destination.' Recorded behavior: with MaximumRetryAttempts=0 and BatchSize=1 on a TRIM_HORIZON DynamoDB stream, a batch whose handler raises is attempted once and then discarded, the shard is NOT stalled and the following record is delivered and processed (its PutItem side effect appears); the failing record's own side effect never appears. With an OnFailure SQS destination, the discarded batch produces one SQS message whose JSON body carries a 'DDBStreamBatchInfo' object (the pointer to the failed batch: stream arn, shard id, start/end sequence numbers, batch size and the approximate arrival timestamp) — 'DDBStreamBatchInfo' is the fixed key; its values come from the stream and the batch. With no destination configured the record is simply dropped and appears nowhere.

Emulator: no part of that is observable. The check polls the results table for the record that follows the always-failing one, and polls the destination queue with ReceiveMessage, and is terminated with 'Error: Check timed out after 60.0s' having satisfied no barrier — so neither 'the ESM continued past the exhausted record' nor 'the OnFailure destination received a DDBStreamBatchInfo message' ever becomes true.

Why: MaximumRetryAttempts plus an OnFailure destination is the standard way to keep a stream consumer from stalling on a poison record while retaining it for reprocessing. If no delivery is observable, a client cannot tell a poison-pill shard stall from normal progress, and the failed batch is lost rather than retained: the DDBStreamBatchInfo pointer that reprocessing tooling consumes never arrives.

Fix: the Lambda event-source-mapping poller for DynamoDB streams — the retry/discard accounting for MaximumRetryAttempts and the shard-advance after a batch is exhausted, plus the OnFailure destination writer that must publish the DDBStreamBatchInfo record to the configured SQS/SNS/S3 destination. Related open issues describe the same OnFailure gap for other service groupings and do not carry this check's replay key: 20261101T210635Z-dynamodb-kinesis-lambda-an-event-source-mapping-s.md, 20261103T062653Z-dynamodb-events-lambda-a-dynamodb-streams-esm-with.md and 20261026T005239Z-dynamodb-kinesis-lambda-a-dynamodb-streams-event-source.md.

Traces: the failing check id above.

## Evidence
Expected (AWS): after PutItem of {id:negA, fail:true} then {id:negB, fail:false} into the stream-enabled table whose ESM has MaximumRetryAttempts=0 and BatchSize=1, a Scan of the results table contains 'negB' and never 'negA'. On the second table, whose ESM adds DestinationConfig={OnFailure:{Destination:<queueArn>}}, PutItem of {id:posA, fail:true} results in exactly one SQS message whose JSON body contains a 'DDBStreamBatchInfo' object.

Actual (emulator): 'Error: Check timed out after 60.0s'. No barrier is met: the results-table scan never contains 'negB' and ReceiveMessage on the OnFailure queue returns no Messages, so neither `assert len(messages) > 0, "OnFailure destination queue received no message for the always-failing record"` nor the preceding progress wait is ever satisfied.

## Steps to Reproduce
1. CreateTable twice with StreamSpecification (NEW_AND_OLD_IMAGES) plus a plain results table; CreateQueue and GetQueueAttributes for its QueueArn.
2. Create a Lambda execution role allowing dynamodb:GetRecords/GetShardIterator/DescribeStream on both stream arns, dynamodb:ListStreams, dynamodb:PutItem on the results table and sqs:SendMessage on the queue.
3. CreateFunction whose handler raises ValueError when the NewImage has fail='true' and otherwise PutItem's the record id into the results table.
4. CreateEventSourceMapping on stream #1 with BatchSize=1, StartingPosition=TRIM_HORIZON, MaximumRetryAttempts=0; and on stream #2 with the same plus DestinationConfig={OnFailure:{Destination:<queueArn>}}.
5. PutItem {id:negA,fail:true} then {id:negB,fail:false} into table #1 and Scan the results table: 'negB' should appear (the shard advanced) and 'negA' never should. PutItem {id:posA,fail:true} into table #2 and ReceiveMessage on the queue: one message whose body JSON has a 'DDBStreamBatchInfo' key should arrive. Actual: nothing arrives for either and the scenario is killed at the runner cap.
