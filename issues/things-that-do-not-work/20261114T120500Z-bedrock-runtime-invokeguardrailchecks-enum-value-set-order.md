Issue-Source: trace-sweep-divergence
Issue-Trace: bedrock-runtime-invoke-guardrail-checks-error-paths
Issue-Step: task#3
Issue-Severity: LOW
Issue-Corpus: simparity-wire-aws-v1
Issue-Corpus-Kind: wire
Issue-Trace-Ids: bedrock-runtime-invoke-guardrail-checks-error-paths
Issue-Shape-Id: com.amazonaws.bedrockruntime#AmazonBedrockFrontendService
Issue-Key: bedrock-runtime|InvokeGuardrailChecks|4xx->4xx|$.message
Issue-Commit: 3d912af2fb7e4756d4e6b34f308b670200addafe

# bedrock-runtime InvokeGuardrailChecks: the enum-constraint refusal lists the sensitive-information entity types in the model's order, not the order the service emits

> _Filed as the one remaining cause of 20261029T213834Z (now under things-that-now-work, whose Resolution section records it): that issue's other three causes are fixed, and this one is carried forward on its own so the divergence stays tracked._

## Operation
InvokeGuardrailChecks

## Description
A `checks.sensitiveInformation.entities[].type` outside its enum is refused with AWS's
standard constraint template, and everything about the emulator's refusal matches the
recording — HTTP 400, `ValidationException`, the template, the count, the rejected value,
the member path, and all 31 values of `GuardrailChecksSensitiveInformationEntityType` —
except the ORDER the bracketed value set is listed in. The emulator lists the model's
declaration order, which for this enum is alphabetical (ADDRESS, AGE, AWS_ACCESS_KEY, …);
the recording shows the service's own order, which begins
US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER, US_BANK_ROUTING_NUMBER, MAC_ADDRESS,
AWS_ACCESS_KEY, …

WHY IT IS NOT FIXED YET — what a fixer needs that the recording does not give:

1. The order is not derivable from the value names. It is neither the model's declaration
   order (which every model in this tree carrying this catalog states alphabetically) nor
   its reverse, and it is not any hash-table iteration order over the names: Java
   `String.hashCode` bucket order with and without `HashMap`'s spread, and FNV-1a bucket
   order, were each computed for every table size 2..256 in both directions, plus the raw
   hash and the value length as sort keys — none reproduces even the recorded prefix. That
   is what an identity-hash-ordered collection looks like, and such a collection iterates
   differently per service run.
2. The recording does not disclose the order. The replay's expected message is truncated
   mid-token ("… Member must satisfy enum value se"), and the sweep that found this cause
   elided the set after four of its 31 values, so 27 positions are simply unknown. Writing
   a permutation into the emulator would invent them and would still differ byte for byte,
   which is worse than the honest divergence.

## Evidence
Replay of `bedrock-runtime-invoke-guardrail-checks-error-paths`, step `task#3`
(InvokeGuardrailChecks), 400 -> 400, `$.message` value_mismatch: both sides read
"1 validation error detected: Value 'NOT_A_REAL_ENTITY_TYPE' at
'checks.sensitiveInformation.entities.1.member.type' failed to satisfy constraint: Member
must satisfy enum value set: [...]", and the bracketed sets hold the same 31 values in two
different orders. Every other key of this fixture passes.

Smithy (com.amazonaws.bedrockruntime): `GuardrailChecksSensitiveInformationEntityType`
declares its 31 values alphabetically
(`smithy_query(query="shape",shape="GuardrailChecksSensitiveInformationEntityType")`);
`InvokeGuardrailChecks` models `ValidationException` (@httpError 400).

## Steps to Reproduce
1. Boot the emulator and replay `bedrock-runtime-invoke-guardrail-checks-error-paths`.
2. Inspect step `task#3`: the 400 body's `$.message` carries the whole value set in the
   model's alphabetical order where the recording carries the service's own order.
3. A recording (or AWS documentation) that states that order IN FULL closes this in one
   line: add it to `crate::state::service_value_order`'s table, beside
   `CONTENT_FILTER_CATEGORY_ORDER` and `MESSAGE_ROLE_ORDER`, the two orders a recording did
   disclose in full. Nothing else about the refusal needs to change.
