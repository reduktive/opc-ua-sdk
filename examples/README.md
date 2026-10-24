# Examples

Complete, buildable programs that show how to use the Reduktive OPC UA SDK. Every example here
builds as part of the SDK tree and also on its own, against an installed SDK package: copy the
example's directory together with `support/`, then point CMake at your SDK install prefix.

Start with **`quickstart/roundtrip`**. It runs in one command and proves your build works.

## The examples

| Example | Shows | Capability-matrix rows |
| --- | --- | --- |
| [`quickstart/roundtrip`](quickstart/roundtrip) | A secure server and client in one process | OPC TCP, UA Secure Conversation, and UA Binary; Server construction with injected `Crypto` and application certificate store; Managed connection lifecycle, endpoint selection, reconnect, keep-alive, and subscription recovery (connection and endpoint selection) |
| [`server/minimal`](server/minimal) | The smallest standalone secure server | Multi-listener lifecycle, endpoints, SecureChannels, Sessions, graceful shutdown, and health snapshots (listener, endpoints, shutdown); Mutable multi-namespace address space, accessors, instantiation, NodeSet2 import and export (built in code); Subscription, Publish/Republish, monitored-item, triggering, and transfer services (serves the subscriptions example) |
| [`client/minimal`](client/minimal) | Connect, read, write, close | Managed connection lifecycle, endpoint selection, reconnect, keep-alive, and subscription recovery (connection and endpoint selection); Read, Write, Browse/BrowseNext, TranslateBrowsePaths, Call, Register/UnregisterNodes (Read, Write, TranslateBrowsePaths) |
| [`server/address_space`](server/address_space) | Building a namespace in code | Mutable multi-namespace address space, accessors, instantiation, NodeSet2 import and export (built in code); Read, Write, Browse/BrowseNext, TranslateBrowsePaths, Call, Register/UnregisterNodes (Call handler) |
| [`server/nodeset_and_methods`](server/nodeset_and_methods) | Importing a NodeSet and binding a Method | Mutable multi-namespace address space, accessors, instantiation, NodeSet2 import and export (NodeSet2 import); Read, Write, Browse/BrowseNext, TranslateBrowsePaths, Call, Register/UnregisterNodes (Call handler) |
| [`client/browse_and_call`](client/browse_and_call) | Browsing, path translation, calling a Method | Read, Write, Browse/BrowseNext, TranslateBrowsePaths, Call, Register/UnregisterNodes (Browse, TranslateBrowsePaths, Call); Typed values, methods, browse cursors, namespace URI remapping, and dynamic type resolution (browse cursors and methods) |
| [`client/subscriptions`](client/subscriptions) | Monitoring values as they change | Subscriptions, Publish/Republish, transfer, data-change monitored items, triggering, and fallback polling (data-change monitored items and filters) |
| [`server/events`](server/events) | Raising an event when the model changes | Events, Conditions, alarms, refresh, acknowledge/confirm, shelving, and condition metrics (events only) |
| [`server/alarms`](server/alarms) | An alarm that persists until acknowledged | Events, Conditions, alarms, refresh, acknowledge/confirm, shelving, and condition metrics (conditions, activation, acknowledge) |
| [`client/events`](client/events) | Receiving events as they are raised | Event monitoring |
| [`client/alarms`](client/alarms) | Tracking what is wrong, and acknowledging it | Alarm/condition tracking |
| [`client/reconnect_and_keepalive`](client/reconnect_and_keepalive) | Surviving a dropped connection | Managed connection lifecycle, endpoint selection, reconnect, keep-alive, and subscription recovery |
| [`server/authentication`](server/authentication) | Accepting three kinds of user identity | Server Anonymous, username/password, and X.509 authenticators; Role-based authorization, well-known roles, and RoleSet management; FindServers and GetEndpoints server services (answers the discovery example) |
| [`client/authentication`](client/authentication) | Presenting a credential, and what it buys | Client Anonymous, username/password, X.509, and opaque issued-token identities (issued tokens excluded) |
| [`client/discovery`](client/discovery) | Finding servers and endpoints before connecting | FindServers, GetEndpoints, and FindServersOnNetwork service calls (FindServers and GetEndpoints) |
| [`server/diagnostics`](server/diagnostics) | Observing and counting what the server does | Server diagnostics, service/session/subscription counters, structured audit events, and observers |
| [`server/file_transfer`](server/file_transfer) | Serving a directory and a file as nodes | File and FileDirectory transfer (server side) |
| [`client/file_transfer`](client/file_transfer) | Listing, reading, and creating files | File and FileDirectory transfer (client side) |
| [`server/history`](server/history) | Answering HistoryRead with a real historian | Historical Access service layer with application delegate; Bundled Historical Access engine and SQLite store |
| [`client/history`](client/history) | Reading a value's past, and adding to it | Historical Access reads, updates, and cursors |
| [`server/reverse_connect`](server/reverse_connect) | Dialling out to a listening client | Client-listening and server-initiated Reverse Connect (server side) |
| [`client/reverse_connect`](client/reverse_connect) | Listening for the server to call | Client-listening and server-initiated Reverse Connect (client side); Low-level secure channel and session handles |
| [`server/custom_types`](server/custom_types) | Defining and publishing a DataType of your own | Mutable multi-namespace address space, accessors, instantiation, NodeSet2 import and export (DataType nodes built in code) |
| [`client/custom_types`](client/custom_types) | Decoding a type with no generated code | Typed values, methods, browse cursors, namespace URI remapping, and dynamic type resolution (dynamic type resolution) |
| [`server/data_access`](server/data_access) | Publishing values with their range and units | Data Access, generic properties, state machines, and server diagnostics facades (server-side Data Access variable types) |
| [`client/data_access`](client/data_access) | Reading a value with its range and units | Data Access, generic properties, state machines, and server diagnostics facades (Data Access only) |
| [`server/push_certificates`](server/push_certificates) | Exposing certificate management to an administrator | Push-model certificate and TrustList management (server side); Role-based authorization, well-known roles, and RoleSet management (SecurityAdmin gate) |
| [`client/push_certificates`](client/push_certificates) | Inspecting what a server rejected and trusts | Push-model certificate and TrustList management (client side) |
| [`reference_server`](reference_server) | A production-shaped server application | X.509 parsing, certificate creation, chain validation, filesystem trust lists, rejected-certificate storage, and offline CRLs (persistent operator-provisioned PKI); Companion-spec C++ type generation from NodeSets; Role-based authorization, well-known roles, and RoleSet management |
| [`reference_client`](reference_client) | A production-shaped client application | Managed connection lifecycle, endpoint selection, reconnect, keep-alive, and subscription recovery; Structured status/detail errors and pluggable logging |

Every example in the table is built, runs, and is verified by a behaviour test. The two Historical
Access examples are the one exception: they need the SDK's optional history component, and in a build
without it their targets and their tests are not created at all.

## Capabilities with no example yet

Rows of the SDK capability matrix that it marks a production path, and that no program here
demonstrates. The list is published so you can tell the difference between "not supported" and
"not yet exampled", and it is named row by row so it cannot quietly fall behind the matrix.

- `QueryFirst and QueryNext client calls`
- `Add/Delete Nodes and References client calls`
- `RegisterServer and RegisterServer2 server-as-LDS registry` — an optional component rather than a
  production path, listed here because an evaluator looks for it beside the discovery example.

## Capabilities deliberately not exampled

An example is a commitment to support, and the matrix marks each of these below a production path.
They are not exampled in this release: non-transparent redundancy and failover, pull-model GDS
certificate management, the bundled multicast-DNS transport, server-side QueryFirst and QueryNext,
server-side Add/Delete Nodes and References, HTTPS and WebSocket transports, PubSub, and JSON
encoding. See the SDK capability matrix in the documentation for what each of those means.

## Building an example on its own

Every example here also builds outside this repository, against an installed SDK. Copy the
example's directory together with `support/` (and `reference_common/` for the reference pair), then:

```bash
cmake -S <example directory> -B build -DCMAKE_PREFIX_PATH=<SDK install prefix>
cmake --build build
```

## Running the behaviour tests

Each example has an `expected_output.txt` beside it, and a test that runs the program and compares
its whole output to that file:

```bash
ctest --test-dir <your build directory> -R '^example\.'
```
