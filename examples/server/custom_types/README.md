# Server custom types

Defines a structured DataType the SDK has never heard of, publishes it in the address space, and
serves a Variable whose value is one of them. Nothing is generated and nothing is compiled in: the
address space is the whole description, and a client reads it from there.

## What you will learn

- Describing a structure with a `StructureDefinition`: a base type and an ordered field list.
- The three nodes and references a custom DataType needs to be *discoverable*, not just present.
- Why the inverse `HasEncoding` reference has to be added explicitly.
- Building a value of a runtime-defined type with `DynamicStructure`.
- That the encodings available are UA Binary and UA XML. There is no JSON encoder in this SDK.

## Prerequisites

None beyond an installed SDK. The example provisions its own development certificate on first run.

## Run it

```bash
./example_server_custom_types
```

## Expected output

```text
=== server/custom_types ===
Define a DataType of your own and publish values of it.

  1. Created the server
  2. Published the PumpReading DataType and its Default Binary encoding
  3. Published Pump/Reading, a Variable of type PumpReading
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Run example_client_custom_types in another terminal. Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/custom_types
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server` |
| 2 | `add_namespace` | `ua::RolePermissionType` |
| 2 | `pump_reading_definition` | `ua::StructureDefinition`, `ua::StructureField` |
| 2 | `publish_data_type` | `ua::DataTypeAccessor::set_data_type_definition`, `ua::ReferenceTypeId::HasEncoding` |
| 3 | `make_reading` | `ua::DynamicStructureTypeDescriptor`, `ua::DynamicStructure` |
| 3 | `add_reading_variable` | `ua::VariableAccessor::set_data_type` |
| 4 | `start_secure_server` | `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Add fields at the end of the definition, never in the middle. Field order is part of the type, and
  inserting one changes what every already-encoded value means.
- Use `StructureType::StructureWithOptionalFields` when a field may legitimately be absent, rather
  than agreeing on a sentinel value out of band.
- Define your types in a NodeSet2 file instead, import it, and generate C++ for them with
  `ua_generate_types()`. That is the right route when the types are yours and stable; this one is
  for types decided at runtime.
- Check both `HasEncoding` directions if a client reports your type as opaque. A published type with
  no inverse edge is undiscoverable, and the failure is silent by design.

## Related

- `examples/client/custom_types` — the client that decodes these values with no shared header.
- `examples/server/nodeset_and_methods` — the NodeSet route to the same destination.
- `examples/server/address_space` — building instances rather than types.
