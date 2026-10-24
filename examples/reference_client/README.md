# Reference client

A production-shaped OPC UA client application, and the companion to the
[reference server](../reference_server/README.md). Where
[`client/minimal`](../client/minimal/README.md) shows the shortest path to a working client, this
one shows what a client that has to be *operated* looks like: a persistent PKI, explicit
certificate provisioning, a refusal to connect before an operator has established trust, request
diagnostics, and a complete pass over the server's demo model including a failure it expects.

## What you will learn

- Keeping application PKI in a persistent store, with the key credential from the environment.
- Provisioning peer trust as a deliberate operator action, with fingerprints to verify.
- Connecting with `easy_connect` and customising exactly the configuration it selected.
- Resolving a model by namespace URI and BrowseName, never by a hard-coded NodeId.
- Consuming a browse cursor, and closing it so the server can release its continuation point.
- Monitoring a value with a Subscription, and what a data-change callback may safely do.
- The two result layers of a Method call, and reading a server's `ErrorDetail` off the wire.

## Prerequisites

An installed SDK, a private-key credential in the environment, and a reference server that trusts
this client.

## Run it

Choose a credential without putting it in shell history, then provision both applications:

```bash
read -rsp 'Reference key password: ' REDUKTIVE_REFERENCE_KEY_PASSWORD
printf '\n'; export REDUKTIVE_REFERENCE_KEY_PASSWORD
mkdir -p /tmp/reduktive-reference

./reference_server --pki /tmp/reduktive-reference/server-pki \
  --export-certificate /tmp/reduktive-reference/server.der --provision-only
./reference_client --pki /tmp/reduktive-reference/client-pki \
  --export-certificate /tmp/reduktive-reference/client.der --provision-only
```

Check both printed fingerprints over an independent channel, then import each into the other's
trust list, start the server, and run the client:

```bash
./reference_server --pki /tmp/reduktive-reference/server-pki \
  --trust-certificate /tmp/reduktive-reference/client.der --provision-only
./reference_client --pki /tmp/reduktive-reference/client-pki \
  --trust-certificate /tmp/reduktive-reference/server.der --provision-only

./reference_client --pki /tmp/reduktive-reference/client-pki --endpoint opc.tcp://127.0.0.1:4840
```

## Expected output

```text
=== reference_client ===
A production-shaped OPC UA client application.

  1. Opened the persistent PKI
     Client certificate SHA-256: <fingerprint>
  2. Connected securely to opc.tcp://127.0.0.1:<port>
  3. Resolved the demo model by namespace URI and BrowseName
  4. Browsed the Demo object
     Demo contains: Divide, Setpoint, UptimeSeconds
  5. Read a Variable
     <masked>
  6. Wrote a Variable and read it back
     Setpoint written, read back = 37.5
  7. Subscribed to a Variable
     Data-change notification reported 61.25
  8. Called a Method
     Divide(84, 2) = 42
  9. Called a Method the server rejects
     Divide(84, 0) rejected: BadInvalidArgument (0x80AB0000)
     Server detail: [client.tier2.typed_access.call_method] CallMethodBadPerMethodStatus: the server returned a bad per-method Call status; the per-input-argument results identify the rejected argument (BadInvalidArgument (0x80AB0000))
  caused by: [client.tier0.session.decode_diagnostic] server diagnostics decoded at the wire boundary (BadInvalidArgument (0x80AB0000))
    operation.index = 0
    caused by: [server.unknown.reference_server.demo.divide] server.symbolic.ReferenceDivideByZero: Divide rejected the request because the divisor was zero
      node.id = <nodeid>
      value = 0
      error.message = Supply a non-zero divisor
  10. Closed the Session and stopped the client

OK  reference_client
```

Step 9 is the one call this client expects to fail. The detail it prints was built by the server,
and reached the client because it asked for operation diagnostics and the server's policy allows
sending them.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `reference::prepare_application_pki` (`reference_common`) | `ua::Crypto`, `ua::CertificateStoreFiles` |
| — | `provision`, `require_a_trust_anchor` | `ua::CertificateStore` |
| 2 | `connect` | `ua::client::Client`, `ua::client::EasyConnectConfig` |
| 3 | `resolve_demo_nodes` (`demo.cpp`) | `ua::client::NamespaceTable`, `ua::hierarchical_path` |
| 4 | `list_demo_children` | `ua::client::BrowseCursor` |
| 5 | `read_uptime` | `ua::client::Connection::read_value_sync` |
| 6 | `update_setpoint` | `ua::client::Connection::write_value_sync` |
| 7 | `watch_setpoint` | `ua::client::Subscription`, `ua::client::MonitorRequest` |
| 8 | `call_divide` | `ua::client::TypedAccess::call_method_sync` |
| 9 | `call_divide_by_zero` | `ua::CallResult`, `ua::ErrorDetail` |
| 10 | `main` | `ua::client::Connection::close_sync`, `ua::Runtime::shutdown` |

## Make it yours

- Point `--endpoint` at your own server and change the namespace URI and BrowseNames in
  `demo.cpp` to nodes it publishes.
- Present a real user identity instead of connecting anonymously.
- Configure a `ReconnectPolicy` and observe connection state. This client disables reconnect
  because it makes one deterministic pass and exits; a long-running client should not.
- Take the private-key credential from a platform secret provider rather than the environment.
- Decide what your application does with a failure. This one lets unexpected failures reach the
  process boundary, and handles exactly one expected failure where it occurs.

## Related

- `examples/reference_server` — the server this client exercises.
- `examples/client/minimal` — the same connection with everything operational removed.
- `examples/client/subscriptions` — subscriptions, filters, and deadbands on their own.
