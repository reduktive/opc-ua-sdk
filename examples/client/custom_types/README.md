# Client custom types

Reads a structure whose type this program was never compiled against. The Connection resolves the
type from the server's own DataType node and hands back a value whose fields can be walked by name.
It talks to [`server/custom_types`](../../server/custom_types/README.md).

## What you will learn

- That a client can decode a server's own DataTypes with no generated code and no shared header.
- Which read path carries the type-resolution pass, and why that matters.
- Walking a `DynamicStructure` by field, using the descriptor the server supplied.
- Reading the DataType node for its name: the definition describes the shape, the node carries the
  name.
- What an unresolvable type looks like, and why it decodes opaquely instead of failing the message.

## Prerequisites

An installed SDK, and `example_server_custom_types` already running in another terminal.

## Run it

```bash
./example_client_custom_types
```

## Expected output

```text
=== client/custom_types ===
Decode a structure this program was never built for.

  1. Connected to opc.tcp://127.0.0.1:<port> and resolved Reading
  2. Read the value; its type resolved to PumpReading
  3. It has 4 fields, described by the server:
     SerialNumber = String(PMP-1043)
     FlowRate = Double(12.5)
     Pressure = Double(4.25)
     MaintenanceNote (optional) = String(Impeller replaced 2026-08-14)
  4. Closed the Session and stopped the client

OK  client/custom_types
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect`, `resolve_reading` | `ua::client::Connection::typed`, `ua::hierarchical_path` |
| 2 | `decoded_or_throw`, `type_name` | `ua::DynamicStructure`, `ua::RefStructure`, `ua::AttributeId::BrowseName` |
| 3 | `describe_field` | `ua::DynamicStructureTypeDescriptor::field`, `ua::StructureField` |
| 4 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Read through `typed()` when a value may carry a custom type. The type-resolution pass runs on that
  path; the lower-level single-node read deliberately returns the value verbatim.
- Set `TypeResolutionPolicy::mode` to `Eager` and name your types in `eagerTypes` when the first read
  must not pay for resolution.
- Register a generated C++ type for a DataType you do control. The resolver prefers a registered type
  over a dynamically built one, so the same code returns your concrete class.
- Expect an opaque structure, not an exception, from a type the server does not describe. Its bytes
  are preserved and will round-trip if you write them back unchanged.

## Related

- `examples/server/custom_types` — the server that defines and publishes this type.
- `examples/client/browse_and_call` — reading a Method's argument metadata, which is the same idea.
- `examples/client/minimal` — reading a built-in type, where none of this is needed.
