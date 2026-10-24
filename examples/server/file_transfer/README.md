# Server file transfer

Publishes a directory and a file as address-space nodes, so a client can list, read, create and write
them over OPC UA. A file travels through the same Session as everything else, under the same
security and the same authorization, which is the reason to do it this way rather than alongside.

## What you will learn

- Backing a `FileDirectoryType` node with a real filesystem directory.
- Backing a `FileType` node with a real file, and what its Methods and Properties do.
- Which permissions a client needs to *read* a file, and which extra ones it needs to *create* one.
- Why concurrent clients get independent file handles with independent stream positions.
- Where the SDK stops and your application starts: it chooses the path and the permissions, and
  nothing else.

## Prerequisites

None beyond an installed SDK. The example provisions its own development certificate on first run.

## Run it

```bash
./example_server_file_transfer
```

## Expected output

```text
=== server/file_transfer ===
Serve a directory and a file as OPC UA nodes.

  1. Created the server
  2. Serving a directory holding one file, manual.txt
  3. Published Documents as a FileDirectoryType with one FileType child
  4. Listening, one Basic256Sha256 SignAndEncrypt endpoint
     opc.tcp://127.0.0.1:<port>
     Run example_client_file_transfer in another terminal. Press Ctrl+C to stop.
  5. Stopped on Ctrl+C

OK  server/file_transfer
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_server` | `ua::server::Server`, `ua::server::RoleConfiguration` |
| 2 | `seed_directory` | `examples::TemporaryDirectory` |
| 3 | `add_namespace` | `ua::RolePermissionType`, `ua::PermissionType` |
| 3 | `publish_directory` | `ua::FileDirectoryHelper`, `ua::InstantiationOptions` |
| 3 | `publish_file` | `ua::FileHelper` |
| 4 | `start_secure_server` | `ua::server::ServerEndpointConfig` |
| 5 | `main` | `examples::wait_for_shutdown_signal` |

## Make it yours

- Bind somewhere else with `--listen host:port`.
- Serve a real, persistent directory instead of a temporary one, and decide what happens to it when
  the server restarts.
- Pass `writable = false` to publish a directory clients may read but not change.
- Grant a read-only Role `Browse`, `Read` and `Call` and withhold `AddNode` and `DeleteNode`. Opening
  and reading a file is a Method call; creating one adds a node.
- Attach a helper to a node you modelled yourself with `attach_sync`, rather than letting the helper
  instantiate the subtree.
- Use `ua::TemporaryFileTransferHelper` where a client should build a whole file and commit it in one
  step, rather than writing into a live one.

## Related

- `examples/client/file_transfer` — the client that lists, reads and creates these files.
- `examples/server/address_space` — building a model node by node.
- `examples/server/authentication` — where the Roles in `add_namespace` come from.
