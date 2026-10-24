# Client authentication

Approaches the same Variable three times with three different credentials: anonymous, a username and
password, and an X.509 user certificate. Nothing about the node changes between the attempts — only
who is asking. It talks to [`server/authentication`](../../server/authentication/README.md).

## What you will learn

- Presenting a user identity on a Session, and where on the wire it travels.
- Reading the difference between "the node is not writable" and "you may not write it".
- Handling an expected refusal with the non-throwing `try_` form, without hiding real failures.
- Presenting an X.509 certificate and its key pair as a user credential.
- Why a Session is closed and reopened to change identity.

## Prerequisites

An installed SDK, and `example_server_authentication` already running in another terminal.

## Run it

```bash
./example_client_authentication
```

## Expected output

```text
=== client/authentication ===
The same node, three credentials, three outcomes.

  1. Client ready, server at opc.tcp://127.0.0.1:<port>
  2. Anonymous Session read Setpoint = 25
  3. Anonymous Session write refused: BadUserAccessDenied (0x801F0000)
     The node is writable. The Observer Role this Session holds is not.
  4. Session as 'operator' wrote Setpoint = 30
  5. Session holding an X.509 user certificate wrote Setpoint = 35
  6. Closed all three Sessions and stopped the client

OK  client/authentication
```

Step 3 is the point. The Variable's AccessLevel says it is writable, and the write is still refused,
because the anonymous Session holds only the Observer Role. Authentication buys authorization.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client` | `ua::client::Client`, `ua::ApplicationConfig` |
| 2 | `connect_as`, `resolve_setpoint` | `ua::client::EasyConnectConfig`, `ua::client::AnonymousIdentity` |
| 3 | `refused_write` | `ua::client::Connection::try_write_value_sync`, `ua::StatusCode` |
| 4 | `connect_as` | `ua::client::UsernamePasswordIdentity` |
| 5 | `certificate_identity`, `connect_as` | `ua::client::X509Identity`, `ua::CertificateStore` |
| 6 | `main` | `ua::client::Connection::close_sync`, `ua::Runtime::shutdown` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Read the username and password from your own prompt or secret store. Never accept a password on a
  command line, where it lands in shell history and in the process table.
- Issue a real user certificate per person, rather than reusing the application's own certificate as
  this example does.
- Keep one Connection per identity for the lifetime of the work it does. Changing identity means a
  new Session, so it is a coarse operation, not a per-request one.
- Inspect the endpoint's advertised UserTokenPolicies before connecting if you need to discover which
  credentials a server will accept.

## Related

- `examples/server/authentication` — the server that accepts these three identities.
- `examples/client/minimal` — the same read and write without an identity.
- `examples/reference_client` — identity handling inside a production-shaped application.
