# Events and alarms (client)

Subscribes to a server's events and waits to be told that something happened. It talks to
[`server/events`](../../server/events/README.md).

A Subscription reports that a value changed. An event reports that something *happened*, with its
own message, severity, and source. This client shows the difference directly: it fills the tank
below the threshold and nothing arrives, then past it and an event does.

## What you will learn

- Getting an `EventSubscriber` from a Connection.
- Why events are published by a *notifier* — usually the Server Object — and not by the node that
  caused them.
- Subscribing with the default filter, which matches every event on that notifier.
- The `BaseEventType` fields every event carries.
- What an event callback may safely do.

## Prerequisites

An installed SDK, and `example_server_events` already running in another terminal.

## Run it

```bash
./example_client_events
```

## Expected output

```text
=== client/events ===
Be told when something happens, not just when a value changes.

  1. Connected to opc.tcp://127.0.0.1:4843 and resolved Tank/Fill
  2. Subscribed to events from the Server Object
  3. Filled by 40 (below the threshold), event raised: false
  4. Filled by 45 (past the threshold), event received
     Source:   Tank
     Severity: 700
     Message:  Tank level 95 reached the high threshold
  5. Closed the Session and stopped the client

OK  client/events
```

Line 3 is as important as line 4: the level changed, and no event was raised, because nothing
happened that the model considers worth reporting.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect`, `resolve` | `ua::client::Client`, `ua::hierarchical_path` |
| 2 | `main` | `ua::client::EventSubscriber`, `ua::client::EventSubscription` |
| 2–4 | `examples::Queue` | the callback boundary: append and wake, nothing slow |
| 3–4 | `main` | `ua::client::TypedAccess::call_method_sync` |
| 4 | `main` | `ua::client::EventNotification` |
| 5 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Point `endpointUrl` and `specNamespaceUri` at your own server.
- Supply an `EventFilter` to select only the event types and fields you want, instead of taking
  every event on the notifier.
- Subscribe to a notifier deeper in the address space when you care about one area of the plant.
- Track alarms rather than raw events when the situation has a state to acknowledge or confirm:
  the SDK provides an alarm and condition tracker for exactly that.

## Related

- `examples/server/events` — the server that raises these events.
- `examples/client/subscriptions` — data changes, the other half of being told things.
- `examples/reference_client` — a production-shaped client.
