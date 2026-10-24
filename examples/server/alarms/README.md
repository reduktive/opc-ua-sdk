# Server alarms

Raises an alarm that persists until somebody deals with it.
[`server/events`](../events/README.md) raises an event: a thing happened, once, and whoever was
listening heard it. An alarm is different in the way that matters operationally — it has state that
outlives the moment, a client connecting later can ask what is currently wrong, and it is not
finished when it stops being true. Somebody has to acknowledge it.

## What you will learn

- Creating an `AlarmConditionType` condition over a Variable, as a node with state rather than a
  message.
- Driving that state from application logic: the SDK owns the condition's bookkeeping, and only your
  code knows what "too hot" means.
- Activating and deactivating a condition, and why deactivating does not finish it.
- Why a Method handler holds a `weak_ptr` to the condition and not a `shared_ptr`.
- Granting `Operator` rather than `Observer`, because acknowledging is a Method call.

## Prerequisites

None beyond an installed SDK. The example provisions its own development certificate on first run.

## Run it

```bash
./example_server_alarms
```

## Expected output

```text
=== server/alarms ===
Raise an alarm that persists until somebody acknowledges it.

  1. Created the server
  2. Published Boiler/Temperature and a Heat Method
  3. Attached a HighTemperature alarm, threshold 90
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Run example_client_alarms in another terminal. Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/alarms
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server`, `ua::server::ServerComponents` |
| 2 | `examples::boiler::add_boiler` | `ua::NodeAccessor`, `ua::MethodAdapter` |
| 3 | `examples::boiler::add_high_temperature_alarm` | `ua::Conditions`, `ua::ConditionInstance`, `ua::AlarmConditionLogic` |
| 4 | `start_secure_server` | `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Set `highThreshold` and `highSeverity` to your process and your escalation policy. Severity is
  the 1–1000 scale OPC UA defines, and an operator's alarm list is usually sorted by it.
- Drive the condition from whatever actually knows the process state — a scanner, a driver, a
  message bus — rather than from a Method. `Heat` exists so a client can move the value on demand.
- Use a `LimitAlarmType` and `ua::LimitAlarmLogic` when the condition is "this value crossed a
  limit". The SDK then evaluates the limits and the deadband for you, instead of the `if` in
  `add_high_temperature_alarm`.
- Add `ConfirmedState` with `set_supports_confirm(true)` when acknowledging is not the end of the
  workflow and an operator must also confirm the fix.
- Keep the handler's capture weak. It lives on a node the address space owns; an owning capture
  closes a cycle through the server, and the symptom is a clean run that never exits.

## Related

- `examples/client/alarms` — the client that tracks and acknowledges this alarm.
- `examples/server/events` — plain events, with no state and nothing to acknowledge.
- `examples/server/data_access` — publishing the range and units that a limit alarm would use.
