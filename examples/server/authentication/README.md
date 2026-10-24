# Server authentication and authorization

A server that accepts three different kinds of user identity — anonymous, username/password, and an
X.509 user certificate — and gives each one different rights over the same node. Authentication and
authorization are two separate decisions, and this example keeps them visibly separate.

## What you will learn

- Composing one authenticator per kind of user identity token with `CompositeAuthenticator`.
- Verifying a username and password without the SDK ever holding your credential store.
- Accepting an X.509 user certificate, validated against a certificate store.
- Mapping an authenticated identity to a well-known Role, and granting permissions per Role.
- Why a UserTokenPolicy carries its own SecurityPolicy, separate from the channel's.

## Prerequisites

None beyond an installed SDK. The example provisions its own development certificate on first run.

## Run it

```bash
./example_server_authentication
```

## Expected output

```text
=== server/authentication ===
Accept three kinds of user identity, and give each one different rights.

  1. Opened the development PKI
  2. Accepting anonymous, username/password, and X.509 user identities
  3. Observer may read Demo/Setpoint; Operator may also write it
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Run example_client_authentication in another terminal. Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/authentication
```

The port is replaced by `<port>` when the behaviour test compares this output; a real run prints the
port it bound.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `main` | `examples::open_development_pki` |
| 2 | `accepted_identities`, `create_server` | `ua::server::CompositeAuthenticator`, `SimpleUserPasswordAuthenticator`, `X509UserAuthenticator` |
| 2 | `identity_role_map` | `ua::server::RoleConfiguration`, `ua::IdentityCriteriaType` |
| 3 | `add_namespace` | `ua::RolePermissionType`, `ua::PermissionType`, `ua::AccessRestrictionType` |
| 3 | `add_demo_folder` | `ua::AddressSpace`, `ua::VariableAccessor`, `ua::AccessLevelType` |
| 4 | `start_secure_server` | `ua::server::ServerEndpointConfig`, `ua::UserTokenType` |
| 5 | `main` | `examples::wait_for_shutdown_signal`, `ua::Runtime::shutdown` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Replace the password check in `accepted_identities` with a call to your directory service. The SDK
  never stores or compares credentials; it hands you the presented pair and takes your answer.
- Replace the `AuthenticatedUser` grant in `identity_role_map` with `UserName` or `Thumbprint`
  criteria naming your actual accounts.
- Give each node its own RolePermissions where a whole namespace is too coarse.
- Drop a token kind you do not want by removing both its authenticator and its UserTokenPolicy.
  Removing only one of the two leaves an endpoint that advertises a credential it will always reject.

## Related

- `examples/client/authentication` — the client that presents each of these identities in turn.
- `examples/server/minimal` — the same server shape with anonymous access only.
- `examples/reference_server` — role policy inside a production-shaped application.
