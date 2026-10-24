# Client Reverse Connect

A client that listens for its server to call, and then drives the conversation exactly as any other
client would. It talks to [`server/reverse_connect`](../../server/reverse_connect/README.md); start
either one first.

## What you will learn

- Opening a reverse-connect listener and restricting it to named servers.
- Taking a connection the server made and opening a SecureChannel over it with `ConnectMode::Reverse`.
- Why this example works at tier 0: the managed `Connection` facade does not drive reverse connections.
- Creating and activating a Session, and reading through it, without the tier-2 facade.
- Why a dialled client must already hold the server's certificate, and where it gets it from.

## Prerequisites

An installed SDK, and `example_server_reverse_connect` running. The server retries until this
listener exists, so either order works.

## Run it

```bash
./example_client_reverse_connect
```

## Expected output

```text
=== client/reverse_connect ===
Listen for the server to call, then drive as usual.

  1. Client ready
  2. Listening on opc.tcp://127.0.0.1:<port> for one named server
  3. The server dialled in; opened a Basic256Sha256 SignAndEncrypt channel
  4. Created and activated a Session over that channel
  5. Read the server's state: Running
  6. Closed the Session, the channel, and the listener

OK  client/reverse_connect
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client` | `ua::client::Client`, `ua::client::Client::core` |
| 2 | `listen` | `ua::client::ReverseConnectListenerConfig`, `ua::client::ExpectedServer` |
| 3 | `provisioned_server_certificate`, `accept_channel` | `ua::CertificateStore::get_trusted_certificates_sync`, `ua::client::ConnectMode` |
| 4 | `session_request` | `ua::client::SecureChannel::create_session_sync`, `ua::client::Session::activate_sync` |
| 5 | `read_server_state` | `ua::client::Session::attributes`, `ua::ReadRequest` |
| 6 | `main` | `ua::client::CoreClient::stop_reverse_connect_sync` |

## Make it yours

- Listen somewhere else with `--listen host:port`.
- Name every server you will accept in `expectedServers`. An empty list accepts nobody, which is the
  right default: a listening client is reachable from anywhere that can route to it.
- Provision the server certificates you expect into your trust list ahead of time, after checking
  their fingerprints. A dialled client cannot run GetEndpoints first, so there is no opportunity to
  learn a certificate at connect time.
- Raise `maxQueuedConnections` if several servers dial you and you accept them in turn.
- Keep the listener open and call `open_channel_sync` again to take the next connection, rather than
  stopping and restarting it.

## Related

- `examples/server/reverse_connect` — the server that dials this listener.
- `examples/client/minimal` — the same read through the managed facade, in one line.
- `examples/client/discovery` — the discovery step a reverse-connect client cannot perform.
