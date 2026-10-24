# Address space in code

A server whose information model is built node by node, with no NodeSet file and no generated
code. Where [`server/minimal`](../minimal/README.md) publishes a single Variable, this one builds a
small structured model: a folder, an Object beneath it, two Variables with different access levels,
and a Method with the argument metadata a client needs to discover its signature.

## What you will learn

- What a node needs before a client can use it: a BrowseName, a type definition, an incoming
  hierarchical reference, and — for a Variable — a data type and an access level.
- The difference between `Organizes` and `HasComponent`.
- Making a Variable read-only or read-write through its `AccessLevel`, and why that is separate
  from the namespace's role permissions.
- Adding a Method in one call with `ua::add_method_sync`: the Method node, its `InputArguments` and
  `OutputArguments` Properties and its typed handler come from one description of the arguments.
- Writing a handler that needs the address space in the asynchronous form, completing the call
  through `ua::MethodResultCallback`, and refusing a bad argument with `ua::reject_argument`.

## Prerequisites

An installed SDK. The example creates its own development certificates on first run.

## Run it

```bash
./example_server_address_space
```

## Expected output

```text
=== server/address_space ===
A server whose information model is built node by node in code.

  1. Opened the development PKI
  2. Created the server
  3. Built Plant/Boiler with two Variables and one Method
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:4841
     Run example_client_browse_and_call in another terminal. Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/address_space
```

The model it publishes is:

| Browse path | Node class | Access |
| --- | --- | --- |
| `Plant` | Object (Folder) | Browse |
| `Plant/Boiler` | Object | Browse |
| `Plant/Boiler/Temperature` | Variable, `Double` | Read |
| `Plant/Boiler/Setpoint` | Variable, `Double` | Read, Write |
| `Plant/Boiler/Scale` | Method `(Double) -> Double` | Call |

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `examples::open_development_pki` | `ua::Crypto`, `ua::CertificateStore` |
| 2 | `create_server` | `ua::server::Server`, `ua::server::ServerComponents` |
| 3 | `examples::plant::add_namespace` (`model.cpp`) | `ua::AddressSpace`, `ua::RolePermissionType` |
| 3 | `examples::plant::add_plant` (`model.cpp`) | `ua::NodeAccessor`, `ua::VariableAccessor`, `ua::MethodAccessor` |
| 3 | the `Scale` Method in `add_plant` | `ua::add_method_sync`, `ua::inputs`, `ua::outputs`, `ua::MethodResultCallback` |
| 4 | `start_secure_server` | `ua::server::ListenerHandle`, `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Listen somewhere else with `--listen host:port` if the default port is already taken on your
  machine. The default is deliberately fixed and documented, because a server worth connecting to
  is one whose address you can write down.
- Replace `Plant/Boiler` in `model.cpp` with your own objects and variables.
- Give a Variable a read or write handler when its value belongs to equipment or another system,
  instead of letting the address space store it.
- Define your own ObjectType and instantiate it, rather than creating each instance node by node.
- Import a NodeSet2 file instead of building the model in code, when the model is designed
  elsewhere or shared with other tools: see `examples/reference_server`.
- Replace the development PKI, the anonymous authenticator, and the Observer grant with your own.

## Related

- `examples/client/browse_and_call` — the client that discovers and calls this model.
- `examples/server/minimal` — the smallest possible model.
- `examples/reference_server` — the same ideas with the model imported from a NodeSet.
