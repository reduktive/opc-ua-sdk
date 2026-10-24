# Server push certificate management

A server whose certificates and trust list can be managed over OPC UA by an administrative client.
Push-model means the server exposes the operations and the client drives them; the alternative,
pull-model, has the server fetch from a Global Discovery Server instead, and this SDK's pull-model
support is incomplete and is not exampled.

## What you will learn

- That the push service needs nothing switched on: it is live whenever the server has a real
  application-group certificate store and crypto provider.
- That every one of its Methods is gated on the SecurityAdmin Role, and how to grant that Role to one
  named account rather than to everyone who logged in.
- Why an administrative endpoint should not also accept anonymous Sessions.
- What a server built with SDK-generated development credentials cannot do, and why.

## Prerequisites

None beyond an installed SDK. The example provisions its own development certificate on first run.

## Run it

```bash
./example_server_push_certificates
```

## Expected output

```text
=== server/push_certificates ===
Let one named administrator manage this server's certificates.

  1. Opened the PKI that the push service will manage
  2. SecurityAdmin granted to 'security-admin', Operator to 'operator'
     The push Methods under ServerConfiguration are live; nothing switches them on.
  3. Listening, one Basic256Sha256 SignAndEncrypt endpoint, username tokens only
     opc.tcp://127.0.0.1:<port>
     Run example_client_push_certificates in another terminal. Press Ctrl+C to stop.
  4. Stopped on Ctrl+C

OK  server/push_certificates
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `main` | `examples::open_development_pki`, `ua::CertificateStore` |
| 2 | `accepted_identities` | `ua::server::CompositeAuthenticator`, `SimpleUserPasswordAuthenticator` |
| 2 | `identity_role_map`, `create_server` | `ua::server::RoleConfiguration`, `ua::server::WellKnownRole::SecurityAdmin` |
| 3 | `start_secure_server` | `ua::server::ServerEndpointConfig`, `ua::UserTokenType::UserName` |
| 4 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Grant SecurityAdmin by certificate thumbprint rather than by user name where your administrators
  hold client certificates.
- Keep certificate management on its own endpoint, or its own listener, away from the endpoint your
  ordinary clients use.
- Give the server a certificate store on a protected, backed-up path. Everything the push service
  does, it does to the contents of that store.
- Enable auditing so that an UpdateCertificate or an ApplyChanges leaves a record. A change to what a
  server trusts is exactly the kind of change an audit trail exists for.

## Related

- `examples/client/push_certificates` — the administrative client that drives these operations.
- `examples/server/authentication` — Roles and identities in the foreground, as their own subject.
- `examples/client/file_transfer` — the TrustList is read as a file, using that example's mechanism.
