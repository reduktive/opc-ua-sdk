# Discovery

Asks an address what applications it hosts and on what terms they will talk, without opening a
Session or making any trust decision. It talks to
[`server/authentication`](../../server/authentication/README.md), which advertises three kinds of
user credential and so has something worth reporting.

Two related services are deliberately absent. FindServersOnNetwork is a Local Discovery Server ME
service: this SDK's server answers `BadServiceUnsupported`, and its bundled multicast-DNS transport
emits no records, so nothing here calls it. `RegisterServer` is a different capability, available on
a server configured as a Local Discovery Server, and is not exampled yet either.

## What you will learn

- The difference between FindServers ("who is here?") and GetEndpoints ("on what terms?").
- What an EndpointDescription actually contains, and why it is a complete offer.
- Reading the UserTokenPolicies an endpoint advertises before choosing a credential.
- Using `securityLevel` to rank endpoints, and what the ranking means.
- Why neither call needs a Session, a certificate decision, or a user identity.

## Prerequisites

An installed SDK, and `example_server_authentication` already running in another terminal.

## Run it

```bash
./example_client_discovery
```

## Expected output

```text
=== client/discovery ===
Ask an address what it is and how it will talk to you.

  1. Client ready, asking opc.tcp://127.0.0.1:<port>
  2. FindServers returned 1 application(s)
     OPC UA SDK Server [urn:reduktive:opcua-sdk:example:server]
  3. GetEndpoints returned 1 endpoint(s)
     [securityLevel 55] Basic256Sha256 SignAndEncrypt, accepts Anonymous, UserName, Certificate
  4. Chose the highest securityLevel offered: [securityLevel 55] Basic256Sha256 SignAndEncrypt, accepts Anonymous, UserName, Certificate
     Connect on exactly those terms, or let easy_connect make the same choice.
  5. Stopped the client; no Session was ever opened

OK  client/discovery
```

This server offers one endpoint, so the choice in step 4 is not a hard one. A production server
usually offers several — different SecurityPolicies, different MessageSecurityModes, sometimes
different credentials — and step 4 is where you compare them.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `main` | `ua::client::Client::discovery`, `ua::client::Discovery` |
| 2 | `find_servers` | `ua::client::FindServersOptions`, `ua::ApplicationDescription` |
| 3 | `get_endpoints`, `describe` | `ua::client::GetEndpointsOptions`, `ua::EndpointDescription`, `ua::UserTokenPolicy` |
| 4 | `strongest` | `ua::EndpointDescription::security_level` |
| 5 | `main` | `ua::Runtime::shutdown` |

## Make it yours

- Point it at another address with `--endpoint opc.tcp://host:port`.
- Point it at a Local Discovery Server. FindServers then answers with every server registered there,
  which is how one well-known address stands in for a whole machine.
- Filter GetEndpoints by transport profile, or FindServers by `serverUris`, when a machine hosts more
  applications than you care about.
- Feed the chosen endpoint into `ua::client::ConnectionConfig` to connect on exactly those terms,
  instead of letting `easy_connect` rank them for you.
- Reject an endpoint whose `securityLevel` is below your own floor rather than taking the best on
  offer. The server ranks its own endpoints; that ranking is its opinion, not your policy.

## Related

- `examples/server/authentication` — the server being discovered here.
- `examples/client/minimal` — connecting once an endpoint has been chosen.
- `examples/client/reconnect_and_keepalive` — what happens after the connection exists.
