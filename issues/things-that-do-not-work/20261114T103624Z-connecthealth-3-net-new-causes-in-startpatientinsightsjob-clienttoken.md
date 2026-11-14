Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: connecthealth.start-patient-insights-job-conflicting-client-token-rejected connecthealth.start-patient-insights-job-unseeded-patient-rejected connecthealth.start-patient-insights-job-succeeds-and-produces-summary
Issue-Shape-Id: com.amazonaws.connecthealth#ConnectHealth
Issue-Key: connecthealth.start-patient-insights-job-conflicting-client-token-rejected|run#20|AssertionError|assert replay["jobId"] != job_id, f"expected the replay to start a new job, got the same jobId {job_id!r}"
Issue-Key: connecthealth.start-patient-insights-job-unseeded-patient-rejected|run#15|AssertionError|raise AssertionError(f"expected the unseeded patientId to be rejected, but it SUCCEEDED: {neg_result!r}")
Issue-Key: connecthealth|GetObject|NoSuchKey
Issue-Commit: 56c740a142f364f3afe5a03d1f4a6c95646b69cc

# connecthealth: 3 net-new causes in StartPatientInsightsJob — clientToken deduplicates instead of starting a new job, an unseeded patientId is accepted instead of refused, and a SUCCEEDED job's reported summary object is never written

> _Note: this issue was identified against the code base at commit `56c740a142f364f3afe5a03d1f4a6c95646b69cc`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
StartPatientInsightsJob

## Description
Three distinct net-new root causes under the suite heading '### connecthealth' (20/24 passed, 4 failed). connecthealth.create-subscription-malformed-domain-id-rejected is marked OWNED by 20261109T181259Z-connecthealth-2-net-new-causes-every-patient-insights.md and is excluded. The remaining three failures are all in the patient-insights job surface and are bundled because they share one service; each is numbered below and carries its own failing check ids. A fixer must close ALL THREE before submitting.

Context: the earlier blocker filed as Cause 1 of 20261109T181259Z-connecthealth-2-net-new-causes-every-patient-insights.md (HealthLake DatastoreEndpoint published on a real-AWS host) no longer fires — the three checks below now get past CreateDomain, bucket setup, CreateFHIRDatastore and the FHIR Patient seed and reach connecthealth assertions for the first time. Everything described here is behavior behind that, newly observable.

=== Cause 1 of 3: a repeated clientToken deduplicates the job instead of starting a new one ===
Failing check: connecthealth.start-patient-insights-job-conflicting-client-token-rejected.
AWS: Smithy (services/service-com-amazonaws-connecthealth-connecthealth/smithy-model/com-amazonaws-connecthealth-connecthealth.json) models StartPatientInsightsJob as POST /domain/{domainId}/patient-insights-job (hostPrefix 'runtime.', success 200); input clientToken targets NonEmptyString and carries @idempotencyToken; output jobId -> JobId (@required, @length 1..36) and jobArn -> JobArn (@required, pattern ^arn:aws[-a-z]*:health-agent:...:domain/<domain>/patient-insights-job/<job>$). ConflictException (409) is modelled. The model does not state that the token suppresses a second job, and the recorded behavior is that it does NOT: a second StartPatientInsightsJob with the SAME clientToken and byte-identical parameters (same domainId, patientContext, insightsContext, encounterContext, userContext, inputDataConfig, outputDataConfig) is accepted with 200 and starts a SECOND, independent job carrying a DIFFERENT jobId (and a correspondingly different jobArn), which GetPatientInsightsJob then reads back as its own job with the submitted encounterContext.encounterReason. No refusal is recorded either — the call is neither 409 ConflictException nor a replay of the first job.
Emulator: the replay is answered 200 but with the SAME jobId as the first call, i.e. the emulator treats clientToken as a deduplication key and returns the already-created job instead of minting a new one. Observed: both calls returned jobId '476367d7eb2a8abc6d87663be07dc892' (that hex value is this run's minted id, a per-run value, not part of the requirement; the requirement is simply that the two ids differ).
Why: a client that reuses a token across submissions — a retry wrapper, a scheduled per-patient job keyed on a stable token, or any caller that does not rotate the token — silently loses every submission after the first: it gets a success and a jobId, but no new job exists, so its second encounter's insights are never produced and it polls a job that answers for the earlier submission. On real AWS the same code produces two jobs. It also masks the opposite class of bug, since no caller can observe whether the service deduplicates or not.
Fix: StartPatientInsightsJob's handler/state in the connecthealth crate — drop the clientToken-keyed lookup that returns an existing job and mint a fresh jobId/jobArn per accepted request (the token is an @idempotencyToken for auto-fill purposes only here, not a dedup index into the job store).
Traces: connecthealth.start-patient-insights-job-conflicting-client-token-rejected (assert replay['jobId'] != job_id).

=== Cause 2 of 3: a patientId that is not in the linked FHIR datastore is accepted instead of refused with ValidationException ===
Failing check: connecthealth.start-patient-insights-job-unseeded-patient-rejected.
AWS: Smithy models ValidationException as a client error with httpError 400; patientContext (PatientInsightsPatientContext) and inputDataConfig (InputDataConfig, carrying fhirServer.fhirEndpoint) are both @required. The model does not word the refusal — recorded behavior: StartPatientInsightsJob resolves patientContext.patientId against the FHIR datastore named by inputDataConfig.fhirServer.fhirEndpoint, and a well-formed patientId for which that datastore holds no Patient resource is refused with HTTP 400 ValidationException whose message is exactly 'Patient could not be found in datastore.' — that whole sentence is fixed text, with no part interpolated from the request. The refusal is also stateless: a second attempt with a fresh clientToken against the same still-unseeded patientId is refused identically (the earlier rejection registers nothing), while a seeded patient in the same domain and datastore is accepted.
Emulator: the unseeded patientId is ACCEPTED. The call answers HTTP 200 with a jobArn/jobId/creationTime (observed: jobArn 'arn:aws:health-agent:<region>:<account>:domain/dom-<id>/patient-insights-job/<jobId>', jobId '60c0e8f477a4b7afeb2f3deb850095bf' — per-run values), i.e. no patient resolution against the FHIR server is performed at all, so no ValidationException is ever produced for this class.
Why: this is an overly-permissive refusal gap. A client with a wrong, stale or mistyped patient identifier gets a success and a job id from the emulator, then polls a job that cannot have real input; on AWS the same request is refused synchronously at submission with a message the caller can act on. Code paths that handle 'Patient could not be found in datastore.' (fall back to another identifier system, re-index, surface a clinician-facing error) are never exercised, and tests written against the emulator pass for inputs AWS rejects.
Fix: StartPatientInsightsJob's validation path in the connecthealth crate must resolve patientContext.patientId against the FHIR server named in inputDataConfig.fhirServer.fhirEndpoint before accepting the job, and refuse an unresolvable id with 400 ValidationException and the fixed message 'Patient could not be found in datastore.' without recording any job state.
Traces: connecthealth.start-patient-insights-job-unseeded-patient-rejected (both the first attempt and the retry against the same unseeded id).

=== Cause 3 of 3: a job that reports SUCCEEDED and names an insightsOutput.uri never materialises that summary object ===
Failing check: connecthealth.start-patient-insights-job-succeeds-and-produces-summary.
AWS: Smithy models GetPatientInsightsJob output insightsOutput -> InsightsOutput (whose uri is S3Uri) and jobStatus -> JobStatus (@required). The content of the output object is recorded behavior only: once the job reaches SUCCEEDED, the object at insightsOutput.uri EXISTS in the configured outputDataConfig.s3OutputPath bucket and GetObject on it answers 200 with the summary JSON document — TotalCount, and PatientSummaries[] holding one PatientSummary whose PatientId is the submitted patientContext.patientId, whose SummaryType is 'Pre-visit' for an insightsContext.insightsType of PRE_VISIT, and whose Sections[] carry at least one non-empty ClinicalNarrative[].Text. The bucket, job id, patient id and generated narrative text are request/state values; the member names and the 'Pre-visit' mapping are the fixed part.
Emulator: the job does reach SUCCEEDED and does report an insightsOutput.uri inside the configured bucket, but the object is absent: GetObject of that exact key answers 404 NoSuchKey ('An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.'). Nothing writes the job's work product, so the terminal success status is reported for a job that produced no insights.
Why: a client follows the documented flow — start the job, poll to SUCCEEDED, read the object the job names — and is handed a 404 at the last step, with no way to distinguish 'the job produced nothing' from 'the output was never stored'. The service's entire work product (the generated clinical summary) is unreachable through the emulator even though every status it reports says the work completed.
Fix: the job's terminal-success transition in the connecthealth crate must materialise the summary object (and its processing-metadata sibling) into the bucket/prefix from outputDataConfig.s3OutputPath at exactly the key insightsOutput.uri reports, with the recorded document shape (TotalCount, PatientSummaries[].PatientSummary with PatientId, SummaryType derived from insightsContext.insightsType, and Sections[].ClinicalNarrative[].Text) so s3's GetObject finds the key.
Not covered elsewhere: open wire issue 20261109T171442Z-s3-getobject-answers-404-for-the-patient-insights.md describes the same missing object from the s3/GetObject side (fixture step), and open wire issue 20261109T171442Z-connecthealth-patient-insights-job-responses-diverge-epoch-number.md describes the prefix-only insightsOutput.uri and absent statusDetails; neither carries this behavioral check's replay key (the suite does not report it as owned), so it is filed here — if either of those is fixed, re-replay this check to confirm.
Traces: connecthealth.start-patient-insights-job-succeeds-and-produces-summary (GetObject of insightsOutput.uri).

## Evidence
Behavioral suite simparity-behavioral-aws-v1 replayed against the emulator built from this checkout: 20/26 passed (76.9%), 3 mismatched, 3 errored, 0 skipped, bootstrap_signal=false. Heading '### connecthealth': 20/24 (83%), 4 failed; connecthealth.create-subscription-malformed-domain-id-rejected is OWNED by 20261109T181259Z-connecthealth-2-net-new-causes-every-patient-insights.md and excluded. The two '### cloudformation__connecthealth' failures are OWNED by 20261109T181259Z-cloudformation-connecthealth-aws-healthagent-domain-is-not-a.md. The remaining three cluster into the three causes above.

Cause 1 — connecthealth.start-patient-insights-job-conflicting-client-token-rejected [mismatch]:
  File "check_connecthealth_start_patient_insights_job_conflicting_client_token_rejected.py", line 137, in run
    assert replay["jobId"] != job_id, f"expected the replay to start a new job, got the same jobId {job_id!r}"
  AssertionError: expected the replay to start a new job, got the same jobId '476367d7eb2a8abc6d87663be07dc892'
  Setup that succeeded first: connecthealth CreateDomain, s3 CreateBucket + PutObject(input.json), healthlake CreateFHIRDatastore polled to ACTIVE, FHIR Patient seeded and readable/searchable. Two StartPatientInsightsJob calls with the identical clientToken and identical body: expected two different jobIds (the second a new job, readable via GetPatientInsightsJob with encounterContext.encounterReason == 'Annual checkup'), got one jobId twice. The 32-hex id is a per-run value.

Cause 2 — connecthealth.start-patient-insights-job-unseeded-patient-rejected [mismatch]:
  File "check_connecthealth_start_patient_insights_job_unseeded_patient_rejected.py", line 185, in run
    raise AssertionError(f"expected the unseeded patientId to be rejected, but it SUCCEEDED: {neg_result!r}")
  AssertionError: expected the unseeded patientId to be rejected, but it SUCCEEDED: {'ResponseMetadata': {'HTTPStatusCode': 200, ...}, 'jobArn': 'arn:aws:health-agent:us-west-2:000000000000:domain/dom-4b4339e9ad5cfe80/patient-insights-job/60c0e8f477a4b7afeb2f3deb850095bf', 'jobId': '60c0e8f477a4b7afeb2f3deb850095bf', 'creationTime': ...}
  Expected: HTTP 400 ValidationException, message exactly 'Patient could not be found in datastore.' (entire sentence fixed, nothing interpolated), and no job created. Observed: HTTP 200 and a created job. The region, account, domain id, job id and timestamp above are per-run values; the divergence is the 200-vs-400 class.

Cause 3 — connecthealth.start-patient-insights-job-succeeds-and-produces-summary [error]:
  botocore.errorfactory.NoSuchKey: An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.
  The check got as far as: StartPatientInsightsJob accepted for a seeded patient, GetPatientInsightsJob polled to jobStatus == 'SUCCEEDED', insightsOutput.uri present and pointing into the configured output bucket (scheme s3, netloc == the bucket) — all passing. It then issued s3 GetObject(Bucket=<that bucket>, Key=<the path from insightsOutput.uri>) and got 404 NoSuchKey instead of the summary document. Expected body members: TotalCount == 1; PatientSummaries with exactly one entry; PatientSummary.PatientId == the submitted patientContext.patientId; PatientSummary.SummaryType == 'Pre-visit' for insightsType PRE_VISIT; Sections non-empty with at least one non-empty ClinicalNarrative[].Text.

Model citations used (services/service-com-amazonaws-connecthealth-connecthealth/smithy-model/com-amazonaws-connecthealth-connecthealth.json): StartPatientInsightsJob POST /domain/{domainId}/patient-insights-job, 200, hostPrefix 'runtime.'; clientToken -> NonEmptyString @idempotencyToken; jobId -> JobId @required @length(1,36); jobArn -> JobArn @required with the health-agent ARN pattern; errors AccessDeniedException 401 / ConflictException 409 / InternalServerException 500 / ResourceNotFoundException 404 / ThrottlingException 429 / ValidationException 400. GetPatientInsightsJob GET /domain/{domainId}/patient-insights-job/{jobId}, 200, @readonly; output jobStatus -> JobStatus @required, insightsOutput -> InsightsOutput, statusDetails -> NonEmptyString.

## Steps to Reproduce
Boot the emulator and point botocore connecthealth / healthlake / s3 clients at it. Re-replay the three checks in trace_ids.

Shared setup (all three causes):
1. connecthealth CreateDomain(name=<unique>) -> domainId.
2. s3 CreateBucket(<unique>), PutBucketTagging, PutObject(Key='input.json').
3. healthlake CreateFHIRDatastore(DatastoreName=<unique>, DatastoreTypeVersion='R4', ClientToken=<name>); poll DescribeFHIRDatastore to DatastoreStatus == ACTIVE; take DatastoreProperties.DatastoreEndpoint.
4. SigV4-sign (service 'healthlake', Content-Type application/fhir+json) PUT <DatastoreEndpoint>/Patient/<patient-id> with a minimal Patient whose identifier[0].value == <patient-id>; confirm GET <DatastoreEndpoint>/Patient/<patient-id> is 200 and GET <DatastoreEndpoint>/Patient?identifier=<patient-id> returns a Bundle with >= 1 entry.
5. Job body used below: StartPatientInsightsJob(domainId, clientToken, patientContext={patientId, dateOfBirth, pronouns}, insightsContext={insightsType:'PRE_VISIT'}, encounterContext={encounterReason:'Annual checkup'}, userContext={role:'CLINICIAN', userId, specialty:'PRIMARY_CARE'}, inputDataConfig={fhirServer:{fhirEndpoint:<DatastoreEndpoint>}, s3Sources:[{uri:'s3://<bucket>/input.json'}]}, outputDataConfig={s3OutputPath:'s3://<bucket>/output/'}).

Cause 1 (clientToken dedup):
6. Call StartPatientInsightsJob once with clientToken=T; record jobId J1.
7. Call it again with the SAME clientToken=T and a byte-identical body.
   Expect: 200 with a jobId != J1 (a second, independent job), and GetPatientInsightsJob(domainId, that jobId) reading it back with encounterContext.encounterReason == 'Annual checkup'.
   Observe: 200 with jobId == J1 — the token deduplicated and no second job exists.

Cause 2 (unseeded patient accepted):
8. Call StartPatientInsightsJob with a fresh clientToken and patientContext.patientId set to a well-formed id that was NEVER written to the datastore (everything else as above).
   Expect: HTTP 400 ValidationException with message 'Patient could not be found in datastore.' and no job created.
   Observe: HTTP 200 with jobArn/jobId/creationTime — the job starts.
9. Repeat step 8 with another fresh clientToken against the same still-unseeded id: expect the identical 400 refusal (the first rejection must register nothing); observe another 200.
   Positive control (must keep passing): the same call for the SEEDED patientId is accepted and GetPatientInsightsJob reports jobStatus in SUBMITTED/IN_PROGRESS/SUCCEEDED.

Cause 3 (summary object never written):
10. Call StartPatientInsightsJob for the seeded patient; poll GetPatientInsightsJob(domainId, jobId) until jobStatus is terminal.
    Expect and observe: jobStatus == 'SUCCEEDED' with insightsOutput.uri inside s3://<bucket>/ (this part passes).
11. s3 GetObject(Bucket=<bucket>, Key=<path component of insightsOutput.uri>).
    Expect: 200 with the summary JSON — TotalCount 1, PatientSummaries[0].PatientSummary.PatientId == the submitted patientId, SummaryType 'Pre-visit', Sections[] with at least one non-empty ClinicalNarrative[].Text.
    Observe: 404 NoSuchKey 'The specified key does not exist.' — no object was ever written at the location the SUCCEEDED job reports.
