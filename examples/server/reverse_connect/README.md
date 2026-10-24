# Server Reverse Connect

A server that dials out to a listening client instead of waiting to be called. This is the case where
the *server* is the one behind a firewall: it opens the TCP connection and sends a ReverseHello, and
from that point the roles are the usual ones. Only who dialled is different.

## What you will learn

- Configuring a reverse-connect target, and why it carries its own endpoint definitions.
- That a server doing this needs no listener at all.
- Why the advertised EndpointUrl must be covered by the server's certificate even though nothing
  listens there.
- How the retry interval lets either side be started first.
- That the security terms are unchanged: dialling out weakens nothing.

## Prerequisites

None beyond an installed SDK. Start `example_client_reverse_connect` too — this server retries until
that listener exists, so the order does not matter.

## Run it

```bash
./example_server_reverse_connect
```

## Expected output

```text
=== server/reverse_connect ===
Dial out to a listening client instead of waiting.

  1. Created the server, with no listener of its own
  2. Published Demo/Setpoint for the client to read
  3. Dialling opc.tcp://127.0.0.1:<port>, retrying every 2s
     Advertising itself as opc.tcp://localhost:<port>
     Run example_client_reverse_connect in another terminal. Press Ctrl+C to stop.
  4. Stopped dialling and shut down on Ctrl+C

OK  server/reverse_connect
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server`, `ua::server::ServerComponents` |
| 2 | `add_namespace`, `add_demo_folder` | `ua::AddressSpace`, `ua::VariableAccessor` |
| 3 | `reverse_endpoint`, `dial_client` | `ua::server::ServerConfig::ReverseConnectTarget`, `ua::server::ReverseConnectHandle` |
| 4 | `main` | `ua::server::Server::stop_reverse_connect_sync` |

## Make it yours

- Dial a different client with `--endpoint opc.tcp://host:port`.
- Set `serverEndpointUrl` to a host name your server's certificate actually covers. A client
  validates the certificate against it exactly as it would for an inbound connection.
- Start several targets to reach several clients. Each returns its own handle and is stopped
  independently.
- Tune `periodicConnectInterval` and `maxPendingSockets` for how often you are willing to dial and
  how many attempts may be in flight.
- Keep an ordinary listener as well, if some clients reach you directly and others do not. The two
  are independent.

## Related

- `examples/client/reverse_connect` — the listening client this server dials.
- `examples/server/minimal` — the same server waiting to be called instead.
- `examples/server/diagnostics` — `ServerObserver` reports reverse-connect activity too.
