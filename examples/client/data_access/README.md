# Client data access

Reads a measurement together with the range and units that give it meaning, then filters it by a
percentage of that range. It talks to
[`server/data_access`](../../server/data_access/README.md).

[`client/subscriptions`](../subscriptions/README.md) filters a plain Variable with an absolute
deadband — "tell me when it moves by 5" — which means something only if you already know what 5
means. A percent deadband says "when it moves by 10 percent of the instrument's range", and this
client is never told that range: the node publishes it, and the SDK reads it and composes the filter.

## What you will learn

- Resolving a Data Access node into a typed handle through `connection.data_access()`.
- Reading a value together with its `EURange` and `EngineeringUnits` in one result.
- That Optional Properties arrive as an empty `std::optional` rather than a fabricated default.
- Building a `PercentDeadband` filter from the node's own range, without hard-coding the range.
- Reading a `TwoStateDiscreteType`, where the server names both states.
- What the SDK refuses locally, before composing a request at all.

## Prerequisites

An installed SDK, and `example_server_data_access` already running in another terminal.

## Run it

```bash
./example_client_data_access
```

## Expected output

```text
=== client/data_access ===
Read a measurement with the range and units that explain it.

  1. Connected to opc.tcp://127.0.0.1:<port>
  2. Read Temperature as an AnalogUnitRangeType
     82.5 degC, range 0 to 200
  3. Read Pump as a TwoStateDiscreteType
     true, which this server calls 'Running'
  4. Monitored Temperature with a 10 percent deadband
     Initial value 82.5
  5. Wrote 90 then 130; the item's next value was 130
  6. A 150 percent deadband is refused: BadDeadbandFilterInvalid (0x808E0000)
     A percent deadband is a percentage of EURange, so only 0 to 100 can mean anything.
  7. Closed the Subscription, the Session, and the client

OK  client/data_access
```

Step 5 is the point. Ten percent of the range 0 to 200 is twenty degrees, so a move from 82.5 to 90
is inside the band and the server never reports it; 130 is outside it, so that is the next value the
item delivers. The client did nothing to work that out.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect`, `resolve` | `ua::client::Client`, `ua::hierarchical_path` |
| 2 | `examples::readings::describe` | `ua::client::DataAccessAccessor`, `ua::client::AnalogItemValue` |
| 3 | `examples::readings::report_pump_state` | `ua::client::TwoStateDiscreteValue` |
| 4 | `examples::readings::watch_with_deadband` | `AnalogItemHandle::make_percent_deadband_filter` |
| 4 | `examples::readings::monitor_with` | `ua::client::MonitorRequest`, `ua::DataChangeFilter` |
| 5 | `report_deadband_effect` | `ua::client::Connection::write_value_sync` |
| 6 | `main` | `ua::Result<ua::DataChangeFilter>` |
| 7 | `main` | `ua::client::Subscription::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Change `deadbandPercent` and watch which writes survive. The band is a percentage of the *node's*
  range, so the same number means a different amount of movement on a different node.
- Resolve with the accessor that matches the type you actually have. `analog_unit_range_sync`
  requires both a range and units; `analog_item_sync` requires the range; `base_analog_sync`
  requires neither and accepts a node with no analog Properties at all.
- Handle an absent Optional Property rather than assuming a default. `engineeringUnits` is an
  `std::optional`, and a server that publishes no units is not the same as one publishing empty ones.
- Use an absolute deadband where the node has no range to be a percentage of: see
  `examples/client/subscriptions`.

## Related

- `examples/server/data_access` — the server that publishes these nodes.
- `examples/client/subscriptions` — absolute deadbands, and monitoring the same node twice.
- `examples/client/minimal` — reading a plain Variable, where none of this applies.
