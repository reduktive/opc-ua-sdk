# Reconnect and keep-alive

Survives a server that goes away and comes back. The client connects with a reconnect policy,
subscribes to a value, waits while the server is stopped and restarted, and then shows that its
Subscription is still delivering — without rebuilding anything by hand.

This is the difference between a demonstration and something you can deploy. A client that gives up
on the first dropped TCP connection is not usable in a plant, where switches reboot, links flap, and
servers are restarted for maintenance.

## What you will learn

- Configuring a `ReconnectPolicy`, and what happens without one.
- Tuning the backoff to the outage you actually expect, and why the default may be too patient.
- The connection states an outage moves through: `Active`, `Reconnecting`, `Active` again — and
  that `Reconnecting` is not `Failed`.
- Recovering Subscriptions across the outage with `TransferThenRecreate`.

## Prerequisites

An installed SDK, and `example_server_minimal` already running in another terminal.

## Run it

Start the client, then stop the server with Ctrl+C and start it again while the client is waiting:

```bash
./example_client_reconnect_and_keepalive
```

## Expected output

```text
=== client/reconnect_and_keepalive ===
Survive a server that goes away and comes back.

  1. Connected to opc.tcp://127.0.0.1:<port> with a reconnect policy
  2. Subscribed to Demo/Setpoint
  3. Waiting for the server to restart
  4. Server went away; the Connection is reconnecting, not failed
  5. Server came back; the Connection recovered on its own
     Session recreated, subscriptions recreated, monitored items recreated: 1
  6. Subscription still delivering: reported 64
  7. Closed the Session and stopped the client

OK  client/reconnect_and_keepalive
```

Step 6 is the point. Nothing between steps 4 and 6 re-created the Subscription or the monitored
item: the SDK re-established the channel and Session and brought them back with it.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `connect` | `ua::client::ReconnectPolicy`, `ua::client::BackoffPolicy` |
| 2 | `main` | `ua::client::Subscription`, `ua::client::MonitorRequest` |
| 3–5 | `examples::reconnect::ReconnectObserver` | `ua::client::ConnectionObserver`, `ua::client::ReconnectOutcome` |
| 6 | `examples::Queue::wait_for_value` | the callback boundary, across a reconnect |
| 7 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Set the backoff from the outage you expect. The default doubles from one second to a
  sixty-second ceiling, which suits a link that may be down for hours; this example uses half a
  second to five seconds, which suits a server restarted for maintenance. Keep the jitter, so a
  fleet of clients does not retry in lockstep.
- Set `maxAttempts` if your application should give up and escalate rather than retry forever.
- Observe connection-state changes instead of polling `state()`, so your application learns about
  an outage the moment it happens rather than when it next looks.
- Decide what your application does *while* disconnected. Operations queue rather than failing
  immediately, which is usually what you want, but a control action that is no longer safe to
  apply late should be dropped by you rather than delivered on recovery.

## Related

- `examples/client/subscriptions` — the Subscription this one keeps alive.
- `examples/server/minimal` — the server to stop and restart.
- `examples/reference_client` — a production-shaped client, which disables reconnect deliberately
  because it makes one deterministic pass and exits.
