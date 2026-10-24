# Events and alarms (server)

Raises an OPC UA event when something happens in the model. The server publishes a `Tank` with a
`Level` and a `Fill` Method; filling past the high threshold raises an event, and filling below it
does not.

## What you will learn

- The difference between a value changing and something *happening*.
- Building a `GenericEvent` and the `BaseEventType` fields it carries.
- What `emit_event` fills in for you: `EventId`, `Time`, `ReceiveTime`, and a clamped severity.
- Granting `ReceiveEvents` at namespace level, without which a client is told nothing.
- Raising an event from inside a Method handler.

## Prerequisites

An installed SDK. The example creates its own development certificates on first run.

## Run it

```bash
./example_server_events
```

## Expected output

```text
=== server/events ===
Raise an event when something happens in the model.

  1. Created the server
  2. Published Tank with Level and Fill, high threshold 90
  3. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:4843
     Run example_client_events in another terminal. Press Ctrl+C to stop.
  4. Stopped on Ctrl+C

OK  server/events
```

The server prints nothing when it raises an event; the event goes to subscribed clients. Run
`example_client_events` to watch one arrive.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server`, `ua::server::ServerComponents` |
| 2 | `add_namespace` | `ua::RolePermissionType`, `ua::PermissionType::Bit::ReceiveEvents` |
| 2 | `add_tank` | `ua::NodeAccessor`, `ua::MethodAdapter`, `ua::GenericEvent` |
| 3 | `start_secure_server` | `ua::server::ListenerHandle`, `ua::server::ServerEndpointConfig` |
| 4 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Listen somewhere else with `--listen host:port` if the default port is already taken on your
  machine. The default is deliberately fixed and documented, because a server worth connecting to
  is one whose address you can write down.
- Raise your own event types by giving `GenericEvent` a different EventType NodeId, so clients can
  filter for exactly the events they care about.
- Set a severity that means something in your domain. OPC UA allows 1 to 1000, and a server that
  reports everything at one severity gives an operator nothing to sort by.
- Use a Condition rather than a plain event when the situation has a state an operator must
  acknowledge, confirm, or shelve — the SDK supports the full Alarms and Conditions model.
- Attach a server-wide event listener for auditing, remembering that it is a hook and not a
  delivery mechanism.

## Related

- `examples/client/events` — the client that receives these events.
- `examples/client/subscriptions` — being told a value changed, which is the other half.
- `examples/server/address_space` — building the model this one raises events about.
