Issue-Severity: HIGH
Issue-Corpus: simparity-behavioral-aws-v1
Issue-Corpus-Kind: behavioral
Issue-Trace-Ids: iot.role-alias-lifecycle-and-delete-conflict
Issue-Shape-Id: com.amazonaws.iot#AWSIotService
Issue-Key: iot.role-alias-lifecycle-and-delete-conflict|_fetch_role_alias_credentials#31|Timeout|time.sleep(3)
Issue-Commit: dafb6a92f3304d60364f819845fa972c02211566

# iot: the published iot:CredentialProvider endpoint serves no certificate-authenticated credential exchange, because the core listener requests no client certificate

> _Split out of `20261114T082236Z-iot-control-plane-gaps-9-causes-untrusted-domain.md` (its Cause 4 of 9), whose other eight causes are implemented. This cause is kept open on its own because it cannot be served from inside the emulator today: the blocker is in the read-only `vendor/` tree, named below._

## Operation
DescribeEndpoint (the `iot:CredentialProvider` endpoint it publishes)

## Description
AWS: recorded behavior only — the IoT credentials provider is an endpoint-only API and is
not an operation in the iot Smithy model. `DescribeEndpoint(endpointType='iot:CredentialProvider')`
returns an address that serves `GET /role-aliases/{roleAlias}/credentials` over MUTUAL TLS,
authenticated by the device's X.509 certificate and carrying no SigV4 signature: the
certificate is the principal, its attached IoT policy must allow
`iot:AssumeRoleWithCertificate` on the role alias ARN, and the answer is HTTP 200 with a JSON
body whose `credentials` object carries `accessKeyId`, `secretAccessKey` and `sessionToken`.

Emulator: the request never succeeds, so the role-alias lifecycle the check drives
(`describe`/`update` of `credentialDurationSeconds`, the attached-policy
`DeleteConflictException`, the ACTIVE-certificate `CertificateStateException`,
`DeleteRoleAlias` and the post-delete refusals) never reaches a verdict: the check retries the
mTLS GET every 3 s and is killed at the harness's 60 s cap.

## Why this is open rather than fixed
The exchange is authenticated BY THE CLIENT CERTIFICATE, and no client certificate can reach a
handler in this emulator: the core builds exactly one rustls server configuration, and it is
built `with_no_client_auth()` —
`vendor/server/src/tls_certificate_authority.rs:91-99` (`TlsCertificateAuthority::server_config`,
the configuration every listener in `vendor/server/src/listeners.rs` starts from). A search of
`vendor/` for `client_cert`, `peer_cert` or `ClientCert` finds nothing, so the TLS layer never
requests a peer certificate and never exposes one. Without it there is no principal to
authorise `iot:AssumeRoleWithCertificate` against, and vending credentials to an unauthenticated
caller would be worse than the current refusal, so nothing was changed for this cause.

REQUIRED CORE CHANGE: a core listener that REQUESTS the client certificate (rustls
`WebPkiClientVerifier`, or an acceptor that admits an unauthenticated peer but records one when
it is presented) and places the presented certificate chain in the request's extensions, so a
service handler can resolve it to the IoT certificate principal. With that, this service can
claim `GET /role-aliases/{roleAlias}/credentials` in its `can_handle` (as other services claim
their own data-plane paths), evaluate the certificate's attached policies through
`state::policy_evaluation`, mint the session with `ctx.credential_store()` and refuse the call
once the alias is deleted.

## Related open issues
`20261111T093215Z-iot-3-net-new-causes-the-published-endpoint.md` Cause 1 describes the same
endpoint and the same missing exchange for two other checks; it does not carry this check's
replay key, which is why this record exists.

## Steps to Reproduce
1. Boot the emulator. iam `CreateRole` with a trust policy for the service principal
   `credentials.iot.amazonaws.com`; iot `CreateRoleAlias(roleAlias=A, roleArn=..., credentialDurationSeconds=900)`.
2. iot `CreateKeysAndCertificate(setAsActive=true)`; `CreatePolicy` allowing
   `iot:AssumeRoleWithCertificate` on the role alias ARN; `AttachPolicy` to the certificate ARN.
3. iot `DescribeEndpoint(endpointType='iot:CredentialProvider')` and take `endpointAddress`.
4. Issue an mTLS HTTPS `GET https://<endpointAddress>/role-aliases/A/credentials` presenting that
   certificate and key as the TLS client certificate, with no SigV4 signature: no 200 is ever
   served.
5. Replay `iot.role-alias-lifecycle-and-delete-conflict`.
