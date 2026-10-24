# Subscriptions

Asks the server to report a value when it changes, rather than polling for it, and shows exactly
what a deadband filter does by monitoring the same Variable twice — once unfiltered, once with a
deadband. It talks to [`server/minimal`](../../server/minimal/README.md).

## What you will learn

- Creating a Subscription, and reading back the publishing interval the server revised it to.
- Attaching monitored items, and what the initial notification means.
- What a data-change callback may safely do, and why it must not block.
- Applying an absolute deadband so the server never reports a change smaller than it.
- Closing a Subscription explicitly rather than letting it time out on the server.

## Prerequisites

An installed SDK, and `example_server_minimal` already running in another terminal.

## Run it

```bash
./example_client_subscriptions
```

## Expected output

```text
=== client/subscriptions ===
Be told when a value changes, instead of asking for it.

  1. Connected to opc.tcp://127.0.0.1:<port> and resolved Demo/Setpoint
  2. Created a Subscription, revised interval <duration> ms
  3. Monitored Setpoint twice: no filter, and a 5 absolute deadband
     Initial value, unfiltered: 25
     Initial value, deadband:   25
  4. Wrote 31, unfiltered item reported 31, deadband item reported 31
  5. Wrote 32 then 50, deadband item's next value was 50
  6. Closed the Subscription, the Session, and the client

OK  client/subscriptions
```

Line 5 is the whole point. The write of 32 is a change of 2, inside the 5 deadband, so the server
never reports it on that item — its next value is 50, and 32 never crossed the network at all.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect`, `resolve_setpoint` | `ua::client::Client`, `ua::hierarchical_path` |
| 2 | `main` | `ua::client::Subscriptions`, `ua::client::SubscriptionConfig` |
| 3 | `monitor`, `absolute_deadband` | `ua::client::MonitorRequest`, `ua::DataChangeFilter` |
| 3 | `report_initial_values` | `ua::client::DataChangeEvent`, the value reported on creation |
| 3–5 | `examples::Queue` | the callback boundary: append and wake, nothing slow |
| 4–5 | `main` | `ua::client::Connection::write_value_sync` |
| 6 | `main` | `ua::client::Subscription::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Point `endpointUrl` and `specNamespaceUri` at your own server, and monitor your own nodes.
- Monitor many nodes in one Subscription. One Subscription carries one Publish stream, so grouping
  items by how often you need them is usually better than one Subscription each.
- Use a percent deadband instead of an absolute one for a value with a declared engineering range.
- Set `queueSize` and `discardOldest` for a value that changes faster than you consume it.
- Configure a reconnect policy so a dropped connection recovers its Subscriptions: see
  `examples/client/reconnect_and_keepalive`.

## Related

- `examples/server/minimal` — the server this client subscribes to.
- `examples/client/minimal` — reading a value once instead of watching it.
- `examples/reference_client` — subscriptions inside a production-shaped application.
