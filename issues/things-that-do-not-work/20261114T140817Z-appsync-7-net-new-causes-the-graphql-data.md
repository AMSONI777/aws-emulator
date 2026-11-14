Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: appsync.graphql-query-execution-vtl-local-resolver appsync.graphql-query-none-datasource-resolver appsync.graphql-query-list-argument-foreach-sum appsync.graphql-append-error-partial-data-and-nonnull-propagation appsync.graphql-resolver-error-returns-http-200-with-errors-envelope appsync.graphql-query-validation-rejected-before-execution appsync.graphql-query-depth-and-resolver-count-limits appsync.graphql-pipeline-stash-prev-result-and-before-return appsync.pipeline-resolver-function-chain-stash-propagation appsync.pipeline-resolver-update-reorders-execution appsync.resolver-pipeline-function-ordering appsync.flush-api-cache-clears-cache appsync.flush-api-cache-immediate-clear appsync.e2e-api-cache-flush-then-fresh-fetch appsync.delete-api-key-revokes-data-plane-access appsync.create-resolver-accepts-unparseable-vtl-fails-only-at-query-time appsync.graphql-resolver-util-error-returns-graphql-error appsync.e2e-api-cache-flush-affects-resolver-invocation appsync.graphql-query-execution-js-local-resolver appsync.graphql-appsync-js-resolver-live-execution appsync.graphql-introspection-query-and-disabled-config appsync.appsync-merged-api-executes-source-api-resolver appsync.api-key-expiry-ttl-enforced-denies-access appsync.appsync-deleted-api-key-subscription-rejected appsync.appsync-graphql-query-end-to-end appsync.appsync-subscription-delivers-mutation-to-realtime-subscriber appsync.appsync-subscription-filter-excludes-nonmatching-mutation appsync.auth-type-switch-to-iam-denies-api-key-and-admits-sigv4 appsync.deep-appsync-3-appsync-rt-evict-from-api-cache-spares-sibling-key appsync.deep-appsync-3-appsync-rt-invalidation-completes-only-matching-subscriber appsync.deep-appsync-3-appsync-rt-operation-level-cache-separates-operation-names appsync.graphql-deleted-api-key-refused-on-data-plane appsync.graphql-field-selection-alias-and-fragment-shaping appsync.per-resolver-caching-keys-scope-cache-entries appsync.pipeline-function-error-short-circuits-later-stages appsync.schema-replacement-swaps-the-served-schema-atomically appsync.update-resolver-changes-query-behavior
Issue-Shape-Id: com.amazonaws.appsync#AWSDeepdishControlPlaneService
Issue-Key: appsync.graphql-query-execution-vtl-local-resolver|_poll_graphql#9|AssertionError|raise AssertionError(f"graphql endpoint never met expectation; last={last_body}")
Issue-Key: appsync.graphql-query-none-datasource-resolver|_poll_until#13|AssertionError|raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")
Issue-Key: appsync.graphql-query-list-argument-foreach-sum|_poll_until#12|AssertionError|raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")
Issue-Key: appsync.graphql-append-error-partial-data-and-nonnull-propagation|run#14|AssertionError|assert body["data"].get("partial") == "partial-value", (
Issue-Key: appsync.graphql-resolver-error-returns-http-200-with-errors-envelope|run#15|AssertionError|assert isinstance(errors, list) and len(errors) == 1, (
Issue-Key: appsync.graphql-query-validation-rejected-before-execution|run#10|AssertionError|assert body["data"]["echo"] == "echo-abc", (
Issue-Key: appsync.graphql-query-depth-and-resolver-count-limits|_refused#14|AssertionError|assert err.get("errorType") == error_type, (
Issue-Key: appsync.graphql-pipeline-stash-prev-result-and-before-return|_compose#15|AssertionError|assert not body.get("errors"), f"unexpected GraphQL errors: {body.get('errors')!r}"
Issue-Key: appsync.pipeline-resolver-function-chain-stash-propagation|_poll_until#13|AssertionError|raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")
Issue-Key: appsync.pipeline-resolver-update-reorders-execution|_poll_until#13|AssertionError|raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")
Issue-Key: appsync.resolver-pipeline-function-ordering|_gql#22|AssertionError|assert not body.get("errors"), f"expected no GraphQL errors, got {body.get('errors')!r}"
Issue-Key: appsync.flush-api-cache-clears-cache|_query_ping_with_retry#16|AssertionError|raise AssertionError(f"GraphQL query against {endpoint} never succeeded: {last_error}")
Issue-Key: appsync.flush-api-cache-immediate-clear|_gql#24|AssertionError|assert not body.get("errors"), f"expected no GraphQL errors, got {body.get('errors')!r}"
Issue-Key: appsync.e2e-api-cache-flush-then-fresh-fetch|_fetch_now#20|AssertionError|assert not body.get("errors"), body.get("errors")
Issue-Key: appsync.delete-api-key-revokes-data-plane-access|_poll_until#13|AssertionError|raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")
Issue-Key: appsync.create-resolver-accepts-unparseable-vtl-fails-only-at-query-time|run#17|AssertionError|assert body.get("data", {}).get("good") == "2", (
Issue-Key: appsync.graphql-resolver-util-error-returns-graphql-error|run#13|AssertionError|assert errors[0]["message"] == "boom-custom", errors[0]
Issue-Key: appsync.e2e-api-cache-flush-affects-resolver-invocation|run#17|AssertionError|assert "errors" not in first, first
Issue-Key: appsync.graphql-query-execution-js-local-resolver|run#11|AssertionError|assert body["data"]["echo"] == "hello-appsync-js", body
Issue-Key: appsync.graphql-appsync-js-resolver-live-execution|run#11|AssertionError|assert data.get("jsEarly") == "early-return-value", (
Issue-Key: appsync.graphql-introspection-query-and-disabled-config|run#10|TypeError|assert data["__schema"]["queryType"]["name"] == "Query", (
Issue-Key: appsync.appsync-merged-api-executes-source-api-resolver|run#33|AssertionError|assert merged_body["data"]["sourceOnly"] == marker, (
Issue-Key: appsync.api-key-expiry-ttl-enforced-denies-access|_wait_for_graphql_success#20|Timeout|time.sleep(interval_s)
Issue-Key: appsync.appsync-deleted-api-key-subscription-rejected|_fill#52|Timeout|return False
Issue-Key: appsync.appsync-graphql-query-end-to-end|_poll_until#20|Timeout|time.sleep(interval_s)
Issue-Key: appsync.appsync-subscription-delivers-mutation-to-realtime-subscriber|_fill#35|Timeout|return False
Issue-Key: appsync.appsync-subscription-filter-excludes-nonmatching-mutation|_fill#38|Timeout|return False
Issue-Key: appsync.auth-type-switch-to-iam-denies-api-key-and-admits-sigv4|_poll_until#14|Timeout|time.sleep(interval_s)
Issue-Key: appsync.deep-appsync-3-appsync-rt-evict-from-api-cache-spares-sibling-key|_poll_until#11|Timeout|time.sleep(interval_s)
Issue-Key: appsync.deep-appsync-3-appsync-rt-invalidation-completes-only-matching-subscriber|_fill#24|Timeout|return False
Issue-Key: appsync.deep-appsync-3-appsync-rt-operation-level-cache-separates-operation-names|_poll_until#12|Timeout|time.sleep(interval_s)
Issue-Key: appsync.graphql-deleted-api-key-refused-on-data-plane|_poll_until#10|Timeout|time.sleep(interval_s)
Issue-Key: appsync.graphql-field-selection-alias-and-fragment-shaping|_poll_until#8|Timeout|time.sleep(interval_s)
Issue-Key: appsync.per-resolver-caching-keys-scope-cache-entries|_poll_until#22|Timeout|time.sleep(interval_s)
Issue-Key: appsync.pipeline-function-error-short-circuits-later-stages|_poll_until#18|Timeout|time.sleep(interval_s)
Issue-Key: appsync.schema-replacement-swaps-the-served-schema-atomically|_poll_until#16|Timeout|time.sleep(interval_s)
Issue-Key: appsync.update-resolver-changes-query-behavior|_poll_graphql#10|Timeout|time.sleep(2.0)
Issue-Commit: 8a8830456e168aad64737c1eda6ee6081a6c4868

# appsync: 7 net-new causes — the GraphQL data plane refuses to run VTL mapping-template resolvers, the APPSYNC_JS sandbox has no `util`, the request handler's result never reaches the response handler, runtime.earlyReturn is ignored, introspection answers a null __schema, a merged API does not route to the source resolver, and 15 data-plane checks never reach their awaited state

> _Note: this issue was identified against the code base at commit `8a8830456e168aad64737c1eda6ee6081a6c4868`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
CreateResolver

## Description
Seven net-new root causes, all in the emulator's GraphQL data plane (the listener serving GraphqlApi$uris.GRAPHQL and the resolver-dispatch/runtime path behind it). Sibling open issues report the same family of symptoms for OTHER service tokens and therefore do not cover these appsync-token checks: 20261114T043034Z-appsync-dynamodb-events-vtl-mapping-template-resolvers-are.md, 20261114T065108Z-appsync-cognito-identity-a-resolver-defined-by-vtl.md, 20261114T070045Z-appsync-cognito-idp-dynamodb-vtl-mapping-template-resolvers.md, 20261114T102203Z-appsync-dynamodb-events-a-vtl-resolver-backed-putitem.md and 20261114T055125Z-appsync-graphql-data-plane-never-executes-an-appsync.md (RELATIONAL_DATABASE/APPSYNC_JS only).

Cause 1 of 7: VTL mapping-template resolvers and pipeline functions are never executed; every such field answers data:<field>=null plus a GraphQL error whose message is emulator-authored.
AWS: CreateResolver (Smithy: appsync CreateResolver, POST /v1/apis/{apiId}/types/{typeName}/resolvers; members requestMappingTemplate / responseMappingTemplate target MappingTemplate @length 1..65536 @pattern "^.*$"; kind UNIT|PIPELINE; errors BadRequestException 400, NotFoundException 404, UnauthorizedException 401, ConcurrentModificationException 409, InternalFailureException 500) and CreateFunction (POST /v1/apis/{apiId}/functions, same two template members) define a resolver by VTL templates, and AppSync RUNS those templates for the bound field — VTL is a first-class, fully supported resolver runtime, not a deprecated one. The GraphQL POST itself is not modeled — recorded behavior only: POSTing a query for a VTL-resolved field returns HTTP 200 with a body that has NO "errors" member and data.<field> set to the value the response template renders.
Emulator: HTTP 200 with data.<field>=null and errors=[{"path":["<field>"],"message":"This field's resolver is defined by mapping templates, which this endpoint does not run; define it with APPSYNC_JS code."}]. For pipeline resolvers the same message is prefixed with the function name (e.g. "<functionName>: This field's resolver ..."). The fixed text is that whole sentence; the only variable part is the field name in `path` and the function-name prefix for a pipeline stage. AWS has no such error class or sentence at all.
Why: every VTL-based AppSync application is unusable against the emulator. A client cannot distinguish "my template is wrong" from "the endpoint does not run templates"; caching, pipeline ordering, $util.appendError partial-data semantics, query-depth limits and auth checks downstream of resolution can never be exercised, and the control plane's 200s on CreateResolver/CreateFunction are therefore meaningless.
Fix: the GraphQL data-plane executor must evaluate VTL request/response mapping templates (unit and pipeline, including $util/$context bindings and stash propagation) and return the rendered value in the data envelope instead of substituting a refusal message.
Traces: appsync.graphql-query-execution-vtl-local-resolver, appsync.graphql-query-none-datasource-resolver, appsync.graphql-query-list-argument-foreach-sum, appsync.graphql-append-error-partial-data-and-nonnull-propagation, appsync.graphql-resolver-error-returns-http-200-with-errors-envelope, appsync.graphql-query-validation-rejected-before-execution, appsync.graphql-query-depth-and-resolver-count-limits, appsync.graphql-pipeline-stash-prev-result-and-before-return, appsync.pipeline-resolver-function-chain-stash-propagation, appsync.pipeline-resolver-update-reorders-execution, appsync.resolver-pipeline-function-ordering, appsync.flush-api-cache-clears-cache, appsync.flush-api-cache-immediate-clear, appsync.e2e-api-cache-flush-then-fresh-fetch, appsync.delete-api-key-revokes-data-plane-access, appsync.create-resolver-accepts-unparseable-vtl-fails-only-at-query-time.

Cause 2 of 7: the APPSYNC_JS data-plane sandbox does not bind the @aws-appsync/utils `util` object, so any resolver that calls util.* fails at query time.
AWS: recorded behavior only (the data-plane POST is not modeled). An APPSYNC_JS resolver/function runs with `util` available (util.error, util.appendError, util.unauthorized, util.dynamodb.toMapValues, util.autoId, ...); util.error(msg) produces a GraphQL error carrying that message, and util.dynamodb.toMapValues(obj) returns the attribute-value map. Smithy only bounds the code: CreateResolver.code targets Code @length 1..32768 with runtime AppSyncRuntime (APPSYNC_JS/1.0.0).
Emulator: the query returns HTTP 200 with data.<field>=null and a GraphQL error message that is a bare JS reference failure — "util is not defined" — or, when the call is nested, "cannot read property 'toMapValues' of undefined". The sentence is the sandbox's own ReferenceError text, not an AppSync error message.
Why: a client gets an unrelated runtime error instead of its own util.error/util.unauthorized message, and no DynamoDB-shaped request built with util.dynamodb can ever be produced; it reads as "my code is broken" when the runtime is.
Fix: the APPSYNC_JS evaluation sandbox used by the data-plane resolver dispatcher must expose the @aws-appsync/utils module surface (`util`, including util.dynamodb and util.error/appendError/unauthorized) before invoking the request/response handlers.
Traces: appsync.graphql-resolver-util-error-returns-graphql-error, appsync.e2e-api-cache-flush-affects-resolver-invocation.

Cause 3 of 7: the APPSYNC_JS request handler's result is never threaded into the response handler — ctx.result is null for every executed field.
AWS: recorded behavior only. For a unit resolver the value the request function returns (for a NONE/local data source, its `payload`) becomes the data-source result and is handed to the response function as ctx.result, so a response function returning e.g. `"response-handler-ran:" + ctx.result.x` yields the request handler's value in the data envelope.
Emulator: the response handler demonstrably runs but sees nothing: the field resolves to the marker concatenated with `null` (HTTP 200, {"data":{"echo":"response-handler-ran:null"}}). The fixed part of the divergence is that ctx.result is null; the marker string is the check's own value.
Why: every APPSYNC_JS resolver that returns data derived from its request handler (the standard local/NONE pattern and every data-source read) silently returns null instead of the value, with no error — clients see a successful response with missing data.
Fix: the resolver-dispatch path must carry the request handler's returned payload (or the data-source invocation result) into the response handler's ctx.result.
Traces: appsync.graphql-query-execution-js-local-resolver.

Cause 4 of 7: runtime.earlyReturn() is ignored — the response handler still runs and its value wins.
AWS: recorded behavior only. In APPSYNC_JS, calling runtime.earlyReturn(value) in the request function ends the resolver (or pipeline stage) immediately and returns `value` as the field's result; the response function is NOT invoked.
Emulator: the field instead resolves to the response handler's output ('response-handler-ran:null'), proving the early return was discarded and the handler ran anyway.
Why: short-circuit patterns (cache hits, validation, authorization bail-outs) return the wrong value, so logic that depends on skipping the response handler behaves inverted.
Fix: honour runtime.earlyReturn in the APPSYNC_JS runtime shim — terminate the stage with the supplied value and skip the response handler.
Traces: appsync.graphql-appsync-js-resolver-live-execution.

Cause 5 of 7: the data plane does not answer GraphQL introspection queries — __schema comes back null.
AWS: recorded behavior only for the POST; the toggle is modeled (Smithy: CreateGraphqlApi.introspectionConfig targets GraphQLApiIntrospectionConfig ENABLED|DISABLED). With introspection ENABLED (the default), POSTing `{ __schema { queryType { name } types { name } } }` returns HTTP 200 and data.__schema populated, with queryType.name == "Query"; with it DISABLED AWS answers a GraphQL error instead.
Emulator: the 200 body carries data.__schema == null, so the client's `data["__schema"]["queryType"]` raises (TypeError: 'NoneType' object is not subscriptable). The ENABLED and DISABLED configurations are therefore indistinguishable.
Why: every GraphQL client, codegen tool and IDE that introspects the endpoint before issuing operations fails against the emulator, and introspectionConfig cannot be exercised at all.
Fix: the data plane's query executor must serve introspection fields (__schema/__type) from the API's active schema, and gate them on the api's introspectionConfig.
Traces: appsync.graphql-introspection-query-and-disabled-config.

Cause 6 of 7: a merged API does not route a field to the SOURCE API's resolver.
AWS: recorded behavior only for the data-plane POST; the association is modeled (AssociateSourceGraphqlApi/StartSchemaMerge, SourceApiAssociation). After a source API is associated and merged into a MERGED api, querying the merged endpoint for a field contributed by the source API executes the SOURCE api's resolver and returns its value.
Emulator: the merged endpoint answers HTTP 200 with the merged-only field null — {"data": {"sourceOnly": null}} — i.e. the field exists in the merged schema but no resolver is dispatched (the resolver's marker value never appears; the marker literal is per-run).
Why: merged APIs are inert: a client that fronts several source APIs through one merged endpoint gets nulls for every delegated field, so the whole federation feature cannot be used. (Open issues 20261109T041647Z-appsync-control-plane-9-net-new-causes-merge.md and 20261112T024108Z-appsync-schema-merge-2-net-new-causes-a.md cover the CONTROL-plane merge state, not resolver dispatch on the merged endpoint.)
Fix: the merged API's data-plane dispatcher must resolve a merged field through the owning source API's resolver and data source.
Traces: appsync.appsync-merged-api-executes-source-api-resolver.

Cause 7 of 7: 15 further data-plane checks never reach the state the emulator is expected to serve and exhaust the 60 s cap.
AWS: recorded behavior only — each of these checks polls the published GraphQL endpoint (or the realtime endpoint) for a response AWS returns promptly: a query result after a schema/resolver change, a 401 UnauthorizedException for a deleted or wrong-provider API key, a cache hit/eviction, or a subscription message delivered over the realtime WebSocket.
Emulator: no awaited response is ever produced; the replay output for each is exactly "Check timed out after 60.0s", so no status/code/message is observable. Given causes 1-6, the data plane serves either a null field or a refusal sentence of its own for these same paths, and never the awaited value.
Why: a client's request simply never completes as AWS's would; subscriptions, caching and auth-switch behaviour are unobservable.
Fix: the same data-plane components as causes 1-4 (resolver dispatch/runtime), plus the API-key/auth gate on the GraphQL endpoint and the realtime (WebSocket) publisher; re-replay these 15 checks after causes 1-6 are fixed, since several are expected to clear with them.
Traces: appsync.api-key-expiry-ttl-enforced-denies-access, appsync.appsync-deleted-api-key-subscription-rejected, appsync.appsync-graphql-query-end-to-end, appsync.appsync-subscription-delivers-mutation-to-realtime-subscriber, appsync.appsync-subscription-filter-excludes-nonmatching-mutation, appsync.auth-type-switch-to-iam-denies-api-key-and-admits-sigv4, appsync.deep-appsync-3-appsync-rt-evict-from-api-cache-spares-sibling-key, appsync.deep-appsync-3-appsync-rt-invalidation-completes-only-matching-subscriber, appsync.deep-appsync-3-appsync-rt-operation-level-cache-separates-operation-names, appsync.graphql-deleted-api-key-refused-on-data-plane, appsync.graphql-field-selection-alias-and-fragment-shaping, appsync.per-resolver-caching-keys-scope-cache-entries, appsync.pipeline-function-error-short-circuits-later-stages, appsync.schema-replacement-swaps-the-served-schema-atomically, appsync.update-resolver-changes-query-behavior.

## Evidence
Cause 1 — appsync.graphql-query-execution-vtl-local-resolver [mismatch]:
  AssertionError: graphql endpoint never met expectation; last={'data': {'echoVtl': None}, 'errors': [{'path': ['echoVtl'], 'message': "This field's resolver is defined by mapping templates, which this endpoint does not run; define it with APPSYNC_JS code."}]}
  Expected (AWS): HTTP 200, no "errors" member, data.echoVtl == the value the response template renders.
  Same message on: graphql-query-none-datasource-resolver, graphql-query-list-argument-foreach-sum, graphql-append-error-partial-data-and-nonnull-propagation (expected $util.appendError to keep the resolved value: got data={'partial': None}), graphql-resolver-error-returns-http-200-with-errors-envelope (expected exactly ONE error for the single failing field, got one per field), graphql-query-validation-rejected-before-execution ("control: expected the valid document to resolve"), graphql-query-depth-and-resolver-count-limits (expected typed error 'QueryDepthLimitReached', got None), flush-api-cache-clears-cache, flush-api-cache-immediate-clear, e2e-api-cache-flush-then-fresh-fetch, delete-api-key-revokes-data-plane-access, create-resolver-accepts-unparseable-vtl-fails-only-at-query-time (even the positive control field is refused this way).
  Pipeline form, prefixed with the function name: graphql-pipeline-stash-prev-result-and-before-return -> [{'path': ['compose'], 'message': "fn00b5ee31dbe3: This field's resolver is defined by mapping templates, which this endpoint does not run; define it with APPSYNC_JS code."}]; same shape in pipeline-resolver-function-chain-stash-propagation, pipeline-resolver-update-reorders-execution, resolver-pipeline-function-ordering.

Cause 2 — appsync.graphql-resolver-util-error-returns-graphql-error [mismatch]:
  AssertionError: {'path': ['fail'], 'message': 'util is not defined'}
  Expected (AWS): the GraphQL error message passed to util.error(...).
  appsync.e2e-api-cache-flush-affects-resolver-invocation [mismatch]:
  AssertionError: {'data': {'increment': None}, 'errors': [{'path': ['increment'], 'message': "cannot read property 'toMapValues' of undefined"}]} — i.e. util.dynamodb is undefined.

Cause 3 — appsync.graphql-query-execution-js-local-resolver [mismatch]:
  AssertionError: {'data': {'echo': 'response-handler-ran:null'}}
  Expected (AWS): the request handler's payload value in place of `null` (ctx.result bound).

Cause 4 — appsync.graphql-appsync-js-resolver-live-execution [mismatch]:
  AssertionError: expected runtime.earlyReturn to return its value directly, got 'response-handler-ran:null'

Cause 5 — appsync.graphql-introspection-query-and-disabled-config [error]:
  assert data["__schema"]["queryType"]["name"] == "Query"
  TypeError: 'NoneType' object is not subscriptable  (data.__schema is null in the 200 body)

Cause 6 — appsync.appsync-merged-api-executes-source-api-resolver [mismatch]:
  AssertionError: the merged API did not route the field to the SOURCE API's resolver; expected the resolver's marker 'srcmark-<per-run>', got {'data': {'sourceOnly': None}}

Cause 7 — all fifteen listed checks report exactly: "Error: Check timed out after 60.0s" with no response captured.

Smithy cited: appsync CreateResolver (POST /v1/apis/{apiId}/types/{typeName}/resolvers; requestMappingTemplate/responseMappingTemplate -> MappingTemplate @length 1..65536 @pattern ^.*$; kind ResolverKind; code -> Code @length 1..32768; runtime AppSyncRuntime; errors BadRequestException 400 / NotFoundException 404 / UnauthorizedException 401 / ConcurrentModificationException 409 / InternalFailureException 500); CreateFunction (POST /v1/apis/{apiId}/functions, same template members); CreateGraphqlApi.introspectionConfig -> GraphQLApiIntrospectionConfig, queryDepthLimit @range 0..75. The GraphQL data-plane POST and its {data,errors} envelope are not modeled — recorded behavior only.

## Steps to Reproduce
1. api = appsync.create_graphql_api(name=..., authenticationType="API_KEY")["graphqlApi"]; key = appsync.create_api_key(apiId=api["apiId"])["apiKey"]["id"].
2. appsync.start_schema_creation(apiId, definition=b'schema { query: Query } type Query { echoVtl(msg: String!): String echo: String partial: String }'); poll get_schema_creation_status to SUCCESS.
3. appsync.create_data_source(apiId, name="local_none", type="NONE").
4. VTL (cause 1): appsync.create_resolver(apiId, typeName="Query", fieldName="echoVtl", dataSourceName="local_none", requestMappingTemplate='{"version":"2017-02-28","payload":{"msg":$util.toJson($ctx.args.msg)}}', responseMappingTemplate='$util.toJson($ctx.result.msg)'). POST {"query":"query { echoVtl(msg: \"hi\") }"} to api["uris"]["GRAPHQL"] with header x-api-key: <key>.
   Observed: 200 with data.echoVtl null and errors[0].message "This field's resolver is defined by mapping templates, which this endpoint does not run; define it with APPSYNC_JS code."
   Expected: 200, no errors member, data.echoVtl == "hi".
   Repeat with kind="PIPELINE" + create_function(... requestMappingTemplate/responseMappingTemplate ...) to see the function-name-prefixed variant.
5. util (cause 2): create_resolver with runtime={name:"APPSYNC_JS",runtimeVersion:"1.0.0"} and code calling `util.error("boom")` in the response function; query the field.
   Observed: errors[0].message == "util is not defined"; Expected: "boom". Likewise a request function using util.dynamodb.toMapValues({...}) reports "cannot read property 'toMapValues' of undefined".
6. ctx.result / earlyReturn (causes 3-4): APPSYNC_JS code whose request function returns {payload:{x:"v"}} and whose response function returns "response-handler-ran:" + ctx.result.x -> observed "response-handler-ran:null". Add runtime.earlyReturn("early") to the request function -> observed the response handler's string again instead of "early".
7. Introspection (cause 5): POST {"query":"query { __schema { queryType { name } } }"} -> observed 200 with data.__schema == null; expected queryType.name == "Query". Repeat on an api created with introspectionConfig="DISABLED" — both behave identically.
8. Merged API (cause 6): create a MERGED api with mergedApiExecutionRoleArn, associate a source api that owns Query.sourceOnly with a resolver returning a marker, start_schema_merge, wait for MERGE_SUCCESS, then query sourceOnly on the MERGED endpoint -> observed {"data":{"sourceOnly":null}}; expected the source resolver's value.
9. Cause 7: re-run the fifteen listed checks; each polls its endpoint until the 60 s cap with no awaited response ever served.
