# Minimal server

The smallest standalone OPC UA server worth running: one secure endpoint, one namespace of its
own, and one value a client can read and write. It is the server half of the two programs that
`quickstart/roundtrip` runs in a single process.

## What you will learn

- Creating a server with an injected crypto provider and certificate store.
- Registering a namespace, and why the index it returns is not portable between servers.
- Granting namespace-level role permissions, and requiring a secure Session to reach the nodes.
- Creating an Object and a Variable in code, and attaching them where a client can find them.
- Advertising a `Basic256Sha256` `SignAndEncrypt` endpoint on a UA TCP listener.
- Shutting down in order when the operator presses Ctrl+C.

## Prerequisites

An installed SDK. The example creates its own development certificates on first run.

## Run it

```bash
./example_server_minimal
```

## Expected output

```text
=== server/minimal ===
The smallest standalone secure OPC UA server.

  1. Opened the development PKI
  2. Created the server
  3. Published Demo/Setpoint in namespace urn:reduktive:opcua-sdk:example:minimal
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:4840
     Run example_client_minimal in another terminal. Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/minimal
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `examples::open_development_pki` | `ua::Crypto`, `ua::CertificateStore` |
| 2 | `create_server` | `ua::server::Server`, `ua::server::ServerComponents` |
| 3 | `add_namespace`, `add_demo_folder` | `ua::AddressSpace`, `ua::NodeAccessor`, `ua::VariableAccessor` |
| 4 | `start_secure_server` | `ua::server::ListenerHandle`, `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Listen somewhere else with `--listen host:port` if the default port is already taken on your
  machine. The default is deliberately fixed and documented, because a server worth connecting to
  is one whose address you can write down.
- Replace the development PKI with your own certificate store and a certificate issued by your
  authority. `examples/reference_server` shows a persistent, operator-provisioned PKI.
- Replace `AnonymousAuthenticator` and the Observer grant with your own identities and roles.
- Change `defaultBindAddress` to the interface and port you serve on, and make sure your
  certificate's subject alternative names cover that address.
- Add your own nodes in `add_demo_folder`, or import a NodeSet instead: see
  `examples/server/nodeset_and_methods`.
- Bind a read or write handler on a Variable whose value belongs to equipment or another system,
  rather than letting the address space store it.

## Related

- `examples/client/minimal` — the client that reads and writes this server's `Setpoint`.
- `examples/quickstart/roundtrip` — both halves in one process, with the PKI in the foreground.
- `examples/server/address_space` — building a larger information model in code.
