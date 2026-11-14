Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: bedrock.bedrock-concurrent-converse-calls-do-not-cross-contaminate-responses
Issue-Key: bedrock.bedrock-concurrent-converse-calls-do-not-cross-contaminate-responses|run#6|AssertionError|assert nonce in answer, (
Issue-Commit: d7c92a359e65b119da339df847b0735e9ef403e3

# bedrock: Converse serves one constant notice string for every prompt, so concurrent calls cannot be correlated with their own requests

> _Note: this cause was identified against the code base at commit `d7c92a359e65b119da339df847b0735e9ef403e3`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

> _Provenance: this was cause 1 of 6 of `20261029T171601Z-bedrock-converse-serves-a-constant-notice-string-inline.md`. Causes 2, 3, 4, 5 and 6 of that report (the unresolvable `guardrailVersion`, the inline guardrail that never intervened, the invocation-logging delivery, the account-enforced guardrail and the `CreateEvaluationJob` pass-role gate) are fixed and that report now sits under `issues/things-that-now-work/`; this cause is unfixed and is re-filed here so its check is not recorded as working. Its `Issue-Key` and its one `Issue-Trace-Ids` entry moved with it. The same defect for the `bedrock-runtime` service token, with its own 30-odd check ids and keys, is `20261028T194707Z-bedrock-runtime-generation-stage-serves-a-constant-emulator.md`, which does NOT carry this check's key — which is why this file exists rather than a line in that one._

## Operation
Converse

## Description
The generation stage behind the Converse API returns one constant notice string for every prompt, so no answer is ever responsive to its own request: under 8-way concurrency all 8 calls get the same bytes and no answer can be correlated with the request it belongs to.

AWS: Smithy `Converse` -> `ConverseResponse` with `output` (`ConverseOutput`), `stopReason` (`StopReason`) and `usage` (`TokenUsage`) all `@required`; the generated text is not described by the model, so recorded behaviour only — `Converse` on `amazon.nova-lite-v1:0` with the prompt "Reply with exactly this token and nothing else, no punctuation and no commentary: &lt;nonce&gt;" returns an assistant text block containing THAT request's own nonce, and each of N concurrent calls returns ITS OWN nonce (the nonce is a per-request value, never a literal).

Emulator: every call returns HTTP 200, `stopReason='end_turn'` and the single text block 'No language model runs in this emulator.' — extended, where the generation budget admits it, with '&lt;modelId&gt; generated no text for this request. The request carried N message(s) and M input token(s).' All 8 concurrent calls return that identical string, so request/response correlation is unobservable and a cross-contaminated response cannot be told from a correctly routed one.

Why: a client that READS the completion (echo, extraction, agent loops, and any correlation or isolation test under concurrency) cannot be exercised at all against this emulator.

## The ONE blocker, for whoever picks this up
NOTHING in this emulator can run a language model: there is no in-process model runtime, no inference-engine crate in the tree, no weights, and no external process available to the platform. The text is produced by `services/service-com-amazonaws-bedrockruntime-amazonbedrockfrontendservice/src/state/generation.rs`, which says plainly that no model ran rather than pretending otherwise.

A generation stage that instead COMPUTES the text from the request was implemented once and refused at the merge gate as output synthesised to look computed (code_reviewer BLOCKER on that same file), which is the correct call: a rule-based answer generator is not inference, and an answer derived from the prompt, a digest or a word list would be a fabricated success. Closing this cause therefore needs a real model runtime in the platform; it is not a fix anyone can write in a service crate.

What already works and must be preserved: the turn semantics, the conversation validation, the token accounting, the stop reason (including `stop_sequence` and `max_tokens`), the guardrail stages, the prompt cache, the latency, the `AWS/Bedrock` metric publication and the invocation-logging record — all computed from the request that was actually served.

## Evidence
Behavioral suite simparity-behavioral-aws-v1, check `bedrock.bedrock-concurrent-converse-calls-do-not-cross-contaminate-responses` [mismatch]:

```
Request: 8 concurrent Converse(modelId='amazon.nova-lite-v1:0',
  messages=[{'role':'user','content':[{'text':'Reply with exactly this token and nothing else,
  no punctuation and no commentary: <nonce>'}]}],
  inferenceConfig={'maxTokens':30,'temperature':0.0})
Expected (AWS): each reply contains its OWN nonce.
Actual: AssertionError: call 0 asked the model to echo 'zqc5128eba94' and got
  'No language model runs in this emulator.' back -- its own answer did not reach it.
  Full mapping: all 8 (nonce, answer) pairs returned the identical string.
```

## Steps to Reproduce
1. Fire 8 concurrent bedrock-runtime `Converse` calls on `amazon.nova-lite-v1:0`, each asking the model to echo a distinct nonce.
2. Expected: each answer contains its own nonce. Observed: all 8 return the same constant notice.

Replay: bedrock.bedrock-concurrent-converse-calls-do-not-cross-contaminate-responses.
