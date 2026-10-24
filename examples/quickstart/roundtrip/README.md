# Quickstart: secure round trip

A complete OPC UA exchange in one process and one command: the program creates a server and a
client, gives each a certificate, has each trust the other, opens a signed and encrypted channel
between them, reads one value, and shuts both down. Run this first to confirm your build works.

## What you will learn

- Owning the worker threads with `ua::Runtime`, and letting it stop what it started.
- Creating a self-signed application instance certificate and a file-backed certificate store.
- Establishing mutual trust by exchanging public certificates.
- Advertising a `Basic256Sha256` `SignAndEncrypt` endpoint on a UA TCP listener.
- Connecting with `easy_connect`, which discovers endpoints and picks the strongest one.
- Reading a value from the built-in `ServerStatus` object.

## Prerequisites

An installed SDK. Nothing else: no arguments, no configuration file, no certificates to prepare,
and no port to choose.

## Run it

```bash
./example_quickstart_roundtrip
```

## Expected output

```text
=== quickstart/roundtrip ===
A secure OPC UA server and client in one process.

  1. Created a certificate for each half
  2. Each half now trusts the other's certificate
  3. Server listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:38417
  4. Client opened a secure channel and an activated Session
  5. Read ServerStatus State = Running
  6. Closed the Session, then stopped both halves

OK  quickstart/roundtrip
```

The port on line 3 changes on every run: the example binds port 0 and lets the operating system
choose, so it never collides with anything already listening.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `provision_peer` | `ua::Crypto`, `ua::CertificateStoreFiles` |
| 2 | `trust_peer` | `ua::CertificateStore` |
| 3 | `start_secure_server` | `ua::server::Server`, `ua::server::ServerEndpointConfig` |
| 4 | `connect_to` | `ua::client::Client`, `ua::client::EasyConnectConfig` |
| 5 | `main` | `ua::client::Connection::read_value_sync` |
| 6 | `main` | `ua::client::Connection::close_sync`, `ua::Runtime::shutdown` |

## Make it yours

- Split the two halves into separate programs. `examples/server/minimal` and
  `examples/client/minimal` are exactly that, and are the shape a real deployment takes.
- Replace the temporary directory with a permanent PKI root, so certificates survive a restart.
- Replace the self-signed certificates with ones issued by your own authority, and import the peer
  certificate deliberately after checking its fingerprint over a separate channel.
- Take the private-key password from a secret provider instead of the fixed string behind
  `examples::development_crypto()` (`examples/support/example_pki.cpp`).
- Give the server an address space of its own, and read from that instead of `ServerStatus`.

## Related

- `examples/server/minimal` — the server half as a standalone program.
- `examples/client/minimal` — the client half as a standalone program.
- `examples/reference_server` and `examples/reference_client` — the production-shaped pair, with
  persistent PKI, configuration, roles, and orderly shutdown.
