# Client file transfer

Lists a directory on a server, reads a file out of it, and creates a new one, all inside the same
Session. It talks to [`server/file_transfer`](../../server/file_transfer/README.md).

## What you will learn

- Listing a directory node and telling a subdirectory from a file by its TypeDefinition.
- Reading a whole file in one call, and when to open a handle and read it in pieces instead.
- Creating a file on the server and writing its contents.
- Why a `FileHandle` is move-only, and what it does when it goes out of scope.
- That a file transfer carries exactly the security and authorization of the Session it travels in.

## Prerequisites

An installed SDK, and `example_server_file_transfer` already running in another terminal.

## Run it

```bash
./example_client_file_transfer
```

## Expected output

```text
=== client/file_transfer ===
List, read, and create files through OPC UA.

  1. Connected to opc.tcp://127.0.0.1:<port> and resolved Documents
  2. Directory holds: manual.txt
  3. Read manual.txt in one call, 44 bytes
     First line: Reduktive OPC UA SDK
  4. Created and wrote reading.txt
  5. Directory now holds: manual.txt, reading.txt
  6. Created Manuals/ and a file inside it
     Manuals holds: reading.txt
  7. Read manual.txt a chunk at a time: 44 bytes
     Seeked to byte 16 and read on:  SDK File transf
  8. Deleted Manuals/, directory now holds: manual.txt, reading.txt
  9. Closed the Session and stopped the client

OK  client/file_transfer
```

## How it works

| Step | Where | SDK type |
| --- | --- | --- |
| 1 | `create_client`, `connect`, `resolve` | `ua::client::Connection::files`, `ua::hierarchical_path` |
| 2, 5 | `list` | `ua::client::FileTransferClient::list_directory_sync`, `ua::client::FileSystemEntry` |
| 3 | `main`, `as_text` | `ua::client::FileTransferClient::read_all_sync`, `ua::ByteString` |
| 4 | `main`, `bytes_of` | `ua::client::FileTransferClient::create_file_sync`, `write_all_sync` |
| 6 | `main` | `ua::client::Connection::close_sync` |

## Make it yours

- Point it at another server with `--endpoint opc.tcp://host:port`.
- Use `open_sync` and read in chunks for a file too large to hold in memory. The returned
  `FileHandle` closes the server-side handle when it goes out of scope, so an abandoned transfer
  leaves nothing behind on the server.
- Use `set_position_sync` to resume an interrupted transfer rather than starting again.
- Create subdirectories with `create_directory_sync`, and remove entries with the directory's Delete
  Method, when your Role permits it.
- Expect `BadUserAccessDenied` on create if your Session's Role has `Call` but not `AddNode`. That is
  the server's authorization, not a bug in the transfer.

## Related

- `examples/server/file_transfer` — the server this client talks to.
- `examples/client/browse_and_call` — Method calls in the foreground, which is what these are.
- `examples/client/authentication` — why a Role decides whether the create in step 4 succeeds.
