# NodeSet and methods

Imports an information model from a NodeSet2 file and gives it behaviour. The model is designed in
[`model/Pump.NodeSet2.xml`](model/Pump.NodeSet2.xml); the application supplies only what a file
cannot — a Variable's runtime value and a Method's body.

No code generation is involved. The SDK's type generator produces typed accessors for a model,
which is worth having for a large one — [`reference_server`](../../reference_server/README.md) uses
it — but a NodeSet is perfectly usable without it, and this is that path.

## What you will learn

- Registering a namespace *before* import, so the file's `ns=1` maps to a real runtime index.
- Importing a NodeSet2 file with `import_nodeset_sync`.
- Why a namespace index is never hard-coded but an identifier within one may be.
- Finding an imported node and giving a Variable its runtime value.
- Installing a Method handler on a node that came from a file.

## Prerequisites

An installed SDK. The example creates its own development certificates on first run.

## Run it

From this directory, so the default relative model path resolves:

```bash
./example_server_nodeset_and_methods
```

Or name the model explicitly:

```bash
./example_server_nodeset_and_methods /path/to/Pump.NodeSet2.xml
```

## Expected output

```text
=== server/nodeset_and_methods ===
Import a model from a file, then give it behaviour.

  1. Created the server
  2. Imported Pump.NodeSet2.xml into namespace index 2
  3. Bound Speed = 1450 and the Stop handler
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:4842
     Model: Pump with Speed (Double, read/write) and Stop().
     Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/nodeset_and_methods
```

Connect any OPC UA client and call `Stop` to watch `Speed` drop to zero.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server`, `ua::server::ServerComponents` |
| 2 | `add_namespace`, `import_model` | `ua::AddressSpace`, `ua::FileStream` |
| 3 | `bind_behaviour` | `ua::VariableAccessor`, `ua::MethodAdapter` |
| 4 | `start_secure_server` | `ua::server::ListenerHandle`, `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Listen somewhere else with `--listen host:port` if the default port is already taken on your
  machine. The default is deliberately fixed and documented, because a server worth connecting to
  is one whose address you can write down.
- Replace the NodeSet with your own model, and update the identifiers in `bind_behaviour` to match
  the nodes it declares.
- Find nodes by BrowseName instead of identifier, if your model's identifiers are not stable.
- Generate typed accessors for a larger model, so a mistyped identifier becomes a compile error:
  see `examples/reference_server`.
- Give a Variable a read handler instead of a stored value, when the value belongs to equipment.
- Export the running address space back to a NodeSet2 file to see what the server actually holds.

## Related

- `examples/server/address_space` — the same kind of model, built in code instead.
- `examples/reference_server` — a NodeSet plus generated typed accessors.
- `examples/client/browse_and_call` — discovering a model like this one from a client.
