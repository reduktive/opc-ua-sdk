# Client push certificate management

An administrative client that inspects what a server has rejected and what it currently trusts. It
talks to [`server/push_certificates`](../../server/push_certificates/README.md).

## What you will learn

- That certificate management is ordinary Method calls on the `ServerConfiguration` Object — there is
  no special client API for it.
- That every one of those Methods requires the SecurityAdmin Role, demonstrated by a refusal.
- Reading the rejected-certificate list, which is the first thing to check when a client cannot
  connect.
- Reading the TrustList, which is a FileType node like any other.
- Where the certificate-rotation cycle goes next, and why it needs a certificate authority.

## Prerequisites

An installed SDK, and `example_server_push_certificates` already running in another terminal.

## Run it

```bash
./example_client_push_certificates
```

## Expected output

```text
=== client/push_certificates ===
Manage a server's certificates over OPC UA.

  1. Client ready, server at opc.tcp://127.0.0.1:<port>
  2. 'operator' called GetRejectedList: BadUserAccessDenied (0x801F0000)
     Authenticated, and still refused. Certificate management needs SecurityAdmin.
  3. 'security-admin' called GetRejectedList: 0 certificate(s) rejected so far
  4. Read the TrustList as a file: <masked> of TrustListDataType
     Rotating the server's own certificate is the other half: CreateSigningRequest,
     then UpdateCertificate and ApplyChanges once your CA has signed it.
  5. Closed both Sessions and stopped the client

OK  client/push_certificates
```

Step 2 is the point. The operator authenticated successfully and was still refused: the Role, not the
login, is what gates certificate management. The byte count in step 4 is masked when the behaviour
test compares this output, because a DER encoding's exact length is not fixed.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client` | `ua::client::Client` |
| 2, 3 | `connect_as`, `call_configuration_method`, `rejected_count` | `ua::client::UsernamePasswordIdentity`, `ua::client::TypedAccess::try_call_method_sync`, `ua::MethodId` |
| 4 | `read_trust_list` | `ua::client::Connection::files`, `ua::client::FileTransferClient::read_all_sync` |
| 5 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Decode the TrustList bytes into a `TrustListDataType` to list what is trusted certificate by
  certificate. The public headers do not currently expose a UA Binary decoder for an arbitrary
  structure read out of a file, so this example reports the encoded size instead.
- Add a certificate to the trust list with the TrustList Object's own `AddCertificate` Method, and
  remove one with `RemoveCertificate`.
- Complete the rotation cycle: `CreateSigningRequest`, take the request to your CA, then
  `UpdateCertificate` and `ApplyChanges`. Expect the server's existing Sessions to be affected when
  changes are applied.
- Treat a growing rejected list as a signal. It is either a client you forgot to enrol, or one you
  did not expect.

## Related

- `examples/server/push_certificates` — the server whose certificates these operations manage.
- `examples/client/authentication` — the Roles that decide whether these calls are allowed.
- `examples/client/file_transfer` — the file mechanism the TrustList read uses.
