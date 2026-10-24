# Client Historical Access

Reads a window of a Variable's past, then adds a sample to it. It talks to
[`server/history`](../../server/history/README.md).

## What you will learn

- Asking a server whether it keeps history for a node before assuming it does.
- Reading a time window, and why a history read always names one.
- Draining a `HistoryReadCursor`, and what a continuation point costs the server.
- Inserting into an archive, and reading the per-value result the server answers with.
- That a `DataValue`'s timestamps are optional, and code must not assume they are present.

## Prerequisites

An installed SDK, and `example_server_history` already running in another terminal. The client half
needs nothing optional — HistoryRead and HistoryUpdate are core client services — but the server it
talks to needs the SDK's optional history component.

## Run it

```bash
./example_client_history
```

## Expected output

```text
=== client/history ===
Read a Variable's past, and add to it.

  1. Connected to opc.tcp://127.0.0.1:<port> and resolved Temperature
  2. Server keeps history for this node: yes
  3. HistoryRead Raw returned 5 samples
     2026-01-01T09:00  20
     2026-01-01T09:05  20.5
     2026-01-01T09:10  21
     2026-01-01T09:15  21.5
     2026-01-01T09:20  22
  4. Inserted one sample, server answered GoodEntryInserted (0x00A20000)
  5. HistoryRead Raw now returns 6 samples
  6. Closed the Session and stopped the client

OK  client/history
```

The timestamps are fixed by the server, not taken from the clock, so a reader's own run prints these
exact lines. A real archive's timestamps come from whatever produced the values.

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect`, `resolve_temperature` | `ua::client::Connection::history`, `ua::hierarchical_path` |
| 2 | `main` | `ua::client::HistoryFacade::is_history_capable_sync` |
| 3 | `window`, `drain`, `describe` | `ua::client::TimeRange`, `ua::client::HistoryReadCursor` |
| 4 | `main` | `ua::client::HistoryFacade::insert_data_sync`, `ua::client::HistoryUpdateResult` |
| 6 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Bound the read with `numValuesPerNode` when the window might be enormous. The cursor pages either
  way; the bound is what stops the first page being the whole archive.
- Use `read_processed_sync` with an aggregate NodeId to have the server compute an average or a
  minimum, rather than shipping every raw sample to compute it here.
- Use `read_at_time_sync` when you want the value *as of* particular instants rather than everything
  in a range.
- Expect `BadHistoryOperationUnsupported` from a server with no historian behind its routes. That is
  a complete and correct answer, not a fault.
- Check `operationResults` per value, not just the outer status. A per-entry `Bad_EntryExists` is
  value quality, not a service failure.

## Related

- `examples/server/history` — the server whose archive this reads.
- `examples/client/subscriptions` — watching a value's present instead of its past.
- `examples/client/minimal` — reading the current value once.
