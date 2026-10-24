# Server data access

Publishes measurements a client can interpret without being told what they mean. A plain Variable
holding `82.5` is a number; an OPC UA Part 8 Data Access variable carries its engineering range and
its units in Properties beside the value, so any client can present it correctly with no prior
agreement. Read [`client/data_access`](../../client/data_access/README.md) next, which consumes it.

## What you will learn

- Instantiating a Data Access variable type through its generated C++ type, so every Property the
  type mandates is created, typed and referenced for you.
- Why `AnalogUnitRangeType` and not `AnalogItemType`: instantiation materialises exactly what a type
  *mandates*, and `EngineeringUnits` is Optional on the plainer type.
- Publishing `EURange` — the range a client's percent deadband is a percentage of.
- Publishing `EngineeringUnits` as a UNECE unit code rather than a string nobody can parse.
- Naming the two states of a `TwoStateDiscreteType`, so a Boolean means something to a display.
- That an instantiation handle *owns* the nodes it created, and `release()` hands them to the
  address space.

## Prerequisites

None beyond an installed SDK. The example provisions its own development certificate on first run.

## Run it

```bash
./example_server_data_access
```

## Expected output

```text
=== server/data_access ===
Publish measurements that carry their own range and units.

  1. Created the server
  2. Published Boiler/Temperature, EURange 0 to 200 degC
  3. Published Boiler/Pump, 'Running' or 'Stopped'
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Run example_client_data_access in another terminal. Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/data_access
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server`, `ua::server::ServerComponents` |
| 2 | `examples::process::publish_temperature` | `ua::AnalogUnitRange`, `ua::Range`, `ua::EUInformation` |
| 2–3 | `examples::process::write_property` | `ua::Property`, `ua::DataValue` |
| 3 | `examples::process::publish_pump` | `ua::TwoStateDiscrete`, `ua::LocalizedText` |
| 4 | `start_secure_server` | `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Set `rangeLow` and `rangeHigh` to your instrument's calibrated range. Every client that filters
  this value by a percentage is filtering by a percentage of what you put here, so a wrong range is
  a wrong filter on every client at once.
- Replace `celsiusUnitId` with your own UNECE unit code. Look it up rather than inventing one: the
  code is what makes the unit machine-readable, and the display name is only for people.
- Choose the type that matches what you actually publish. `AnalogUnitRangeType` mandates both a
  range and units; `AnalogItemType` mandates only the range; `BaseAnalogType` mandates neither.
  Reaching for a Property the type does not mandate returns `BadNodeIdUnknown`, because
  instantiation never created it.
- Add `MultiStateDiscreteType` or `MultiStateValueDiscreteType` for a value that is one of several
  named states rather than one of two.

## Related

- `examples/client/data_access` — the client that reads these and filters by a percent deadband.
- `examples/server/address_space` — building plain Variables node by node, without a Part 8 type.
- `examples/client/subscriptions` — an absolute deadband, which needs no range to be meaningful.
