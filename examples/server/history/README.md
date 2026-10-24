# Server Historical Access

Answers HistoryRead and HistoryUpdate with a real historian behind them. The SDK's history *services*
are live on every server it builds; what a base server has not got is anything to store values in,
and its default delegate answers `BadHistoryOperationUnsupported`. This example plugs in the SDK's
optional bundled engine over its SQLite store.

## What you will learn

- Why Historical Access is a host integration, and what the SDK does and does not supply.
- Wrapping a namespace in a `HistoryNamespace` so it answers history for the nodes it holds.
- The three things that mark a Variable as historised, and why all three are needed.
- That `ReadHistory` and `InsertHistory` are permissions of their own, separate from `Read` and
  `Write`.
- That nothing records a value into history for you: a historian is fed by your collector.

## Prerequisites

An SDK built with the optional history component (`UASDK_BUILD_HISTORY` and
`UASDK_BUILD_HISTORY_SQLITE`, both on by default). Without it this example is not built, and its
behaviour test is not registered.

Consuming an installed SDK, ask for the component:

```cmake
find_package(uasdk CONFIG REQUIRED)
find_package(uasdk CONFIG REQUIRED COMPONENTS history sqlite-store)
target_link_libraries(your_server PRIVATE uasdk::uasdk uasdk::history-sqlite)
```

## Run it

```bash
./example_server_history
```

## Expected output

```text
=== server/history ===
Answer HistoryRead with a real historian behind it.

  1. Created the server
  2. Opened the bundled SQLite history store
  3. Published Plant/Temperature as a historised Variable
  4. Seeded 5 samples, five minutes apart
  5. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Run example_client_history in another terminal. Press Ctrl+C to stop.
  6. Stopped on Ctrl+C

OK  server/history
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server`, `ua::server::RoleConfiguration` |
| 2 | `main` | `ua::history::SqliteHistoryStore`, `ua::history::HistoryEngineDelegate` |
| 3 | `add_history_namespace` | `ua::history::HistoryNamespace`, `ua::PermissionType` |
| 3 | `add_historised_variable` | `ua::VariableAccessor::set_historizing`, `ua::AccessLevelType` |
| 4 | `seed_history` | `ua::NamespaceHistoryDelegate::UpdateDataItem`, `ua::PerformUpdateType` |
| 5 | `start_secure_server` | `ua::server::ServerEndpointConfig` |
| 6 | `main` | `examples::wait_for_shutdown_signal` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Point the SQLite store at a real, backed-up path instead of a temporary directory, and decide what
  its retention policy is. The SDK does not delete anything for you.
- Replace `seed_history` with your actual collector: whatever produces the values calls the historian
  on its own schedule, with its own timestamps.
- Implement `NamespaceHistoryDelegate` yourself against an existing historian, and drop the bundled
  engine entirely. That is the same integration point, with your storage behind it.
- Withhold `InsertHistory` and `ModifyHistory` from Roles that may read the archive but must not
  rewrite it. An archive that any client can edit is not evidence of anything.
- Add the Annotations Property with `ua::history::add_annotations_property` where operators need to
  record why a value looks the way it does.

## Related

- `examples/client/history` — the client that reads and extends this archive.
- `examples/server/address_space` — building the model the historised node lives in.
- `examples/server/authentication` — where the Roles in `add_history_namespace` come from.
