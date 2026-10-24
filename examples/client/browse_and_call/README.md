# Browse and call

Walks a server's information model without knowing any of its NodeIds, then calls one of its
Methods. It talks to [`server/address_space`](../../server/address_space/README.md).

## What you will learn

- Resolving a namespace URI to the index a particular server assigned it.
- Listing a node's children with a browse cursor, and closing it so the server can release its
  continuation point.
- Translating a BrowseName path into the NodeId the server chose.
- Calling a Method: naming both the owning Object and the Method, and decoding its output.

## Prerequisites

An installed SDK, and `example_server_address_space` already running in another terminal.

## Run it

```bash
./example_client_browse_and_call
```

## Expected output

```text
=== client/browse_and_call ===
Discover a server's model, then call a Method on it.

  1. Connected to opc.tcp://127.0.0.1:4841
  2. Resolved urn:reduktive:opcua-sdk:example:plant to namespace index 2
  3. Browsed the Objects folder for this server's own model
     Plant contains: Boiler (Object)
  4. Translated Plant/Boiler to the NodeId this server chose
     Boiler contains: Temperature (Variable), Setpoint (Variable), Scale (Method)
  5. Translated the Method's path the same way
  6. Called Scale(1.25), new Setpoint = 100
  7. Closed the Session and stopped the client

OK  client/browse_and_call
```

The namespace index on line 2 is that server's choice, which is exactly why the client looks it up
instead of assuming it. Line 6 scales the Setpoint the server currently holds, so running the
client twice without restarting the server gives 125 the second time.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect` | `ua::client::Client`, `ua::client::EasyConnectConfig` |
| 2 | `main` | `ua::client::NamespaceTable` |
| 3 | `browse_children` | `ua::client::BrowseCursor`, `ua::client::BrowseOptions` |
| 4 | `main` | `ua::hierarchical_path`, `ua::client::TypedAccess` |
| 5 | `main` | `ua::hierarchical_path` |
| 6 | `main` | `ua::client::TypedAccess::call_method_sync`, `ua::CallResult` |
| 7 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Point `endpointUrl` and `specNamespaceUri` at your own server and model.
- Browse from a different starting node, or follow a specific reference type instead of
  `HierarchicalReferences`.
- Handle a Method that rejects its arguments: `examples/reference_client` shows the two result
  layers of a Call and how a server's `ErrorDetail` reaches you.
- Register the nodes you use repeatedly, so the server can give you faster identifiers for them.

## Related

- `examples/server/address_space` — the server this client explores.
- `examples/client/minimal` — reading and writing a value you already know the path to.
- `examples/reference_client` — the same operations in a production-shaped application.
