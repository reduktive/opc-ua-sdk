# Reference server

A production-shaped OPC UA server application, and the companion to the
[reference client](../reference_client/README.md). Where
[`server/minimal`](../server/minimal/README.md) shows the shortest path to a working server, this
one shows what a server that has to be *operated* looks like: a persistent PKI, explicit
certificate provisioning, an information model imported from an external NodeSet, namespace-level
role permissions, a validated write handler, a Method that reports a rich failure, and orderly
shutdown.

## What you will learn

- Keeping application PKI in a persistent store, with the key credential from the environment.
- Provisioning peer trust as a deliberate operator action, with fingerprints to verify.
- Refusing to start in a state where the server can serve nobody.
- Importing a NodeSet2 model and binding live behaviour to its nodes through generated types.
- Granting namespace-level role permissions and requiring a secure Session.
- Building a `StatusCode` with an `ErrorDetail` a client can actually act on.
- Shutting down in order on SIGINT or SIGTERM.

## Prerequisites

An installed SDK, and a private-key credential in the environment:

```bash
read -rsp 'Reference key password: ' REDUKTIVE_REFERENCE_KEY_PASSWORD
printf '\n'
export REDUKTIVE_REFERENCE_KEY_PASSWORD
```

The server needs at least one trusted client certificate before it will start. The
[client README](../reference_client/README.md#run-it) has the full two-application provisioning
sequence; run that first.

## Run it

```bash
./reference_server --pki /tmp/reduktive-reference/server-pki --listen 127.0.0.1:4840 \
  --model examples/reference_server/model/Reduktive.ReferenceServer.NodeSet2.xml
```

## Expected output

```text
=== reference_server ===
A production-shaped OPC UA server application.

  1. Opened the persistent PKI
     Server certificate SHA-256: <fingerprint>
  2. Created the server
  3. Imported the model from Reduktive.ReferenceServer.NodeSet2.xml
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Demo namespace: urn:reduktive:reference-server:demo
     Nodes: UptimeSeconds, Setpoint, and Divide(numerator, divisor)
     Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  reference_server
```

The console log sink is set to `Error`, so a healthy run shows only the lines above. Raise it in
`run()` to see the SDK's own diagnostics.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `reference::prepare_application_pki` (`reference_common`) | `ua::Crypto`, `ua::CertificateStoreFiles` |
| — | `provision`, `require_a_trust_anchor` | `ua::CertificateStore` |
| 2 | `server_config`, `server_components` | `ua::server::Server`, `ua::server::ServerComponents` |
| 3 | `try_configure_demo_model` (`demo_model.cpp`) | `ua::AddressSpace`, `ua::FileStream`, generated `Demo` type |
| — | `try_validate_setpoint`, `try_divide` (`demo_logic.cpp`) | `ua::Result`, `ua::ErrorDetail` |
| 4 | `add_secure_endpoint` (`endpoints.cpp`) | `ua::server::ListenerHandle`, `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

The information model itself is
[`Reduktive.ReferenceServer.NodeSet2.xml`](model/Reduktive.ReferenceServer.NodeSet2.xml), and it is
the authority for the nodes and Method signatures:

| Browse path | Type | Access | Purpose |
| --- | --- | --- | --- |
| `Demo/UptimeSeconds` | `UInt32` Variable | Read | Seconds since the process started |
| `Demo/Setpoint` | `Double` Variable | Read, Write, Subscribe | A value constrained to `0..100` |
| `Demo/Divide` | Method `(Int32, Int32) -> Int32` | Call | A successful call, and a rich rejection |

The generated C++ for that model is checked in under `generated/reference_demo`, so building and
running this example needs no code generation, no Python, and no NodeSet repository. A maintainer
regenerates it only after changing the model's structure.

## Make it yours

- Replace anonymous authentication with your deployment's identities and role mapping, in
  `server_components`.
- Provision CA-issued application certificates and revocation information instead of the
  self-signed certificate this creates on first run.
- Take the private-key credential from a platform secret provider rather than the environment.
- Replace the NodeSet with your own model, regenerate its types, and bind your handlers in
  `demo_model.cpp`. Keep domain logic in `demo_logic.cpp`, where it stays testable on its own.
- Persist application values in the system that owns them, and tune diagnostic disclosure, limits,
  and logging to your threat model.
- Do not add a `None` endpoint to make commissioning convenient. Discovery works before a
  SecureChannel; access to the model does not.

## Related

- `examples/reference_client` — the client that exercises this server.
- `examples/server/minimal` — the same ideas with everything operational removed.
- `examples/server/nodeset_and_methods` — NodeSet import and Method binding on their own.
