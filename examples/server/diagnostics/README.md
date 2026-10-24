# Server diagnostics

What a running server can tell you about itself, through the two mechanisms it offers: a
`ServerObserver`, told about each event as it happens, and health snapshots, sampled on demand. An
idle server has nothing to report, so this one connects a client to itself and does a little work
over that Session. Both halves run in one process, so it needs no second terminal.

## What you will learn

- Installing a `ServerObserver` and overriding only the hooks you care about.
- What an observer hook may safely do, and why it must return promptly.
- The difference between a gauge (`current_*`) and a cumulative total (`cumulated_*`).
- Reading per-Session counters to attribute load, and `unauthorizedRequestCount` to spot a client
  asking for things it may not have.
- Why a diagnostics snapshot is approximate rather than a coherent instant.

## Prerequisites

None beyond an installed SDK. The example provisions its own development certificate on first run.

## Run it

```bash
./example_server_diagnostics
```

## Expected output

```text
=== server/diagnostics ===
What a running server can tell you about itself.

  1. Created the server with a ServerObserver installed
  2. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Before any client: 0 Sessions now, 0 since the server started
  3. A client connected and read one Variable
     Session created, name 'diagnostics probe'
     Session activated, user 'anonymous'
  4. Sampled the server-wide and per-Session counters
     With one client: 1 Sessions now, 1 since the server started
     'diagnostics probe': 2 requests, 2 reads, 0 browses, 0 unauthorized
  5. The session gauge fell back; the cumulative total did not
     Session closed
     After the Session closed: 0 Sessions now, 1 since the server started
     Press Ctrl+C to stop.
  6. Stopped on Ctrl+C

OK  server/diagnostics
```

Step 5 is the pair worth remembering. The gauge returns to zero when the client leaves; the
cumulative total does not, which is what makes it usable as a rate.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `RecordingObserver`, `create_server` | `ua::server::ServerObserver`, `ua::server::Server::set_observer` |
| 2 | `start_secure_server` | `ua::server::ServerEndpointConfig`, `ua::server::ListenerHandle` |
| 3 | `connect_probe` | `ua::client::Client`, `ua::client::EasyConnectConfig` |
| 3, 5 | `RecordingObserver`, `examples::Queue` | the callback boundary: append and return, nothing slow |
| 4 | `report_server_counters` | `ua::server::ServerHealthSnapshot` |
| 4 | `report_session_counters` | `ua::server::SessionHealthSnapshot` |
| 6 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Override the hooks this example leaves alone: rejected certificates, failed authentications,
  dropped events, and shutdown are all reported the same way.
- Send the observer's events to your audit log rather than to a queue. Do the writing on your own
  thread; the hook itself must return promptly.
- Sample `health_snapshot()` on a timer and publish the fields your monitoring system understands.
  The same numbers are also readable over OPC UA from the server's own diagnostic nodes.
- Watch `rejectedSessionCount` and `securityRejectedRequestsCount` in production. A rise in either is
  usually the first sign of a misconfigured client or a probe.
- Delete the in-process client. It exists only to give an otherwise idle server something to report.

## Related

- `examples/client/minimal` — the client half, in the foreground, as its own subject.
- `examples/server/authentication` — where `unauthorizedRequestCount` comes from.
- `examples/reference_server` — diagnostics inside a production-shaped application.
