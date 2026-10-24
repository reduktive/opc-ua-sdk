# Minimal client

Connects securely to `examples/server/minimal`, finds a value by name, reads it, writes a new
value, and reads it back. It is the client half of the two programs that `quickstart/roundtrip`
runs in a single process.

## What you will learn

- Creating a client with an injected crypto provider and certificate store.
- Connecting with `easy_connect`, which discovers endpoints and selects the strongest one.
- Resolving a namespace URI to the index this particular server assigned it.
- Translating a BrowseName path into a NodeId, instead of hard-coding one.
- Reading and writing a value with the typed accessors.
- Closing the Session before stopping the client.

## Prerequisites

An installed SDK, and `example_server_minimal` already running in another terminal.

## Run it

```bash
./example_client_minimal
```

## Expected output

```text
=== client/minimal ===
Connect securely, read a value, write it, and close.

  1. Opened the development PKI
  2. Connected to opc.tcp://127.0.0.1:4840
  3. Resolved Demo/Setpoint by namespace URI and BrowseName
  4. Read Setpoint = 25
  5. Wrote Setpoint, read it back = 42.5
  6. Closed the Session and stopped the client

OK  client/minimal
```

Step 4 reads 25 because the server seeds that value at startup. Run the client twice without
restarting the server and the second run reads 42.5.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `examples::open_development_pki` | `ua::Crypto`, `ua::CertificateStore` |
| 2 | `create_client`, `connect` | `ua::client::Client`, `ua::client::EasyConnectConfig` |
| 3 | `resolve_setpoint` | `ua::client::NamespaceTable`, `ua::hierarchical_path`, `ua::client::TypedAccess` |
| 4 | `main` | `ua::client::Connection::read_value_sync` |
| 5 | `main` | `ua::client::Connection::write_value_sync`, `ua::Variant` |
| 6 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Point `endpointUrl` at your own server, and change `specNamespaceUri`, `folderName` and
  `variableName` to nodes it publishes.
- Replace the development PKI with your own store, and trust the server's certificate only after
  checking its fingerprint over an independent channel.
- Present a real user identity instead of connecting anonymously.
- Configure a reconnect policy for a client that must survive a dropped connection: see
  `examples/client/reconnect_and_keepalive`.

## Related

- `examples/server/minimal` — the server this client talks to.
- `examples/client/browse_and_call` — discovering a server's model and calling a Method.
- `examples/client/subscriptions` — being told when a value changes, instead of polling it.
