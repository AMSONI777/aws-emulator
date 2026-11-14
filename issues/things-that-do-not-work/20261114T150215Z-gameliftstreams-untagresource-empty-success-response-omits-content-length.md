Issue-Source: trace-sweep-divergence
Issue-Trace: gameliftstreams-stream-group-application-association-lifecycle
Issue-Step: task#13
Issue-Severity: MEDIUM
Issue-Corpus: simparity-wire-aws-v1
Issue-Corpus-Kind: wire
Issue-Trace-Ids: gameliftstreams-stream-group-application-association-lifecycle
Issue-Shape-Id: com.amazonaws.gameliftstreams#GameLiftStreams
Issue-Key: gameliftstreams|UntagResource|2xx->2xx|$headers.content-length
Issue-Commit: d86ba179c5d8f834b6ff97eae2a4be90662aba63

# gameliftstreams UntagResource empty success response omits Content-Length header

> _Note: this issue was identified against the code base at commit `d86ba179c5d8f834b6ff97eae2a4be90662aba63`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
UntagResource

## Description
One net-new root cause in the gameliftstreams tagging path, found by replaying wire fixture gameliftstreams-stream-group-application-association-lifecycle against the emulator built from this checkout. The replay report flagged this cluster neither stub_path nor owned_by.

Related-but-not-covering: open issue 20261103T145438Z-gameliftstreams-stream-group-read-path-drops-capacity-and.md carries, as its cause 3, the SAME framing fault on TagResource (step task#11) and its replay pointer covers TagResource only. It does not name UntagResource or step task#13, so UntagResource's divergence is not exercised by that issue's replay and would be closed unrun. If the fix is made in the shared empty-output serializer both are closed together, but this cause must be re-replayed on its own step.

=== Cause 1 of 1: UntagResource's empty success response carries no Content-Length header (step task#13) ===
AWS: Smithy (services/service-com-amazonaws-gameliftstreams-gameliftstreams/smithy-model/com-amazonaws-gameliftstreams-gameliftstreams.json): UntagResource is DELETE /tags/{ResourceArn} with input members ResourceArn (@httpLabel, required) and TagKeys (@httpQuery "tagKeys", required), @idempotent, and output shape UntagResourceResponse — a structure with NO members — success code 200 (codeDefaulted). AWS frames such an empty REST-JSON success with a Content-Length header describing the body it actually sent (0 for a bodiless response, 2 for the `{}` document). The recording asserts only that the header is PRESENT and shaped (`<shaped-not-asserted>`), not a particular numeric value, so the requirement is the PRESENCE of Content-Length on an empty-body success for an operation whose output shape has no members — not a specific length. No error code or message is involved: this is a 2xx framing requirement.
Emulator: the status (204) matched the recording, but the response carries no Content-Length header at all — replay reports `$headers.content-length: missing (expected '<shaped-not-asserted>', got None)`.
Why: an HTTP client that frames a response body by Content-Length and receives neither Content-Length nor chunked framing must read until the connection closes, or treat the message as unterminated. On a keep-alive connection (the default for every AWS SDK) that either stalls the read or desynchronizes the connection so the NEXT response on it is misparsed, and strict clients and intermediary proxies reject the response outright. The result is that an untag call the emulator considers successful surfaces to the caller as a transport error or a hang rather than a success.
Fix: the response serializer for operations whose output shape has no members — it must emit Content-Length for the empty body it writes. This is shared framing rather than UntagResource-specific, so the same change covers TagResource and every other empty-output operation in this service; the defect is in the serializer, not in the UntagResource handler's logic (the tag removal itself and the status matched).
Traces: gameliftstreams-stream-group-application-association-lifecycle#task#13.

## Evidence
Replay of wire trace set simparity-wire-aws-v1 against the emulator built from this checkout (emulator_up=true, /__admin/health answered 200, 48 steps total, 38 passed, score 79.2%, bootstrap_signal=false). Divergence cluster: fixture gameliftstreams-stream-group-application-association-lifecycle, step task#13, service gameliftstreams, operation UntagResource, verdict mismatch, expected status 204 / actual status 204, affected_count 1, stub_path empty, owned_by empty.

Detail reported by the replay:
  $headers.content-length: missing (expected '<shaped-not-asserted>', got None)

Expected: an empty-body 2xx success carrying a Content-Length header (value shaped, not asserted — AWS sends the length of the body it wrote).
Actual: empty-body response with the matching status but NO Content-Length header.

Model evidence (services/service-com-amazonaws-gameliftstreams-gameliftstreams/smithy-model/com-amazonaws-gameliftstreams-gameliftstreams.json): UntagResource http { method: DELETE, uri: /tags/{ResourceArn}, code: 200 (defaulted) }, output_shape UntagResourceResponse with no members, @idempotent; modeled errors AccessDeniedException(403), ValidationException(400), ThrottlingException(429), InternalServerException(500) — none of which is at issue here, the status was correct.

The only divergence is the missing framing header; no per-run value (request id, timestamp, generated ARN) is part of this finding.

## Steps to Reproduce
Boot the emulator built from this checkout and replay fixture gameliftstreams-stream-group-application-association-lifecycle, step task#13, or by hand:
1. CreateApplication over S3 content and poll GetApplication until Status == READY.
2. CreateStreamGroup(... LocationConfigurations=[{LocationName=<region>, AlwaysOnCapacity=<n>}]) and poll GetStreamGroup until the group is ACTIVE.
3. TagResource(ResourceArn=<group ARN>, Tags={<k>: <v>}).
4. UntagResource(ResourceArn=<group ARN>, TagKeys=[<k>]) and inspect the RAW response headers (e.g. curl -i, or an HTTP trace rather than an SDK call, since SDKs hide framing).
5. Observe the success response has no Content-Length header at all, where AWS frames the empty-body success with Content-Length (0 for a bodiless response, 2 for `{}`). The status and empty body themselves match.
