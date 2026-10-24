// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FILE_TRANSFER_CLIENT_H
#define UA_FILE_TRANSFER_CLIENT_H

/// @file
/// @brief Tier-2 public `FileTransferClient` + `FileHandle` (client design section 8.10): the
/// per-`Connection`
///        facade for the File Transfer service set (Part 20) and its move-only, close-on-destruct file
///        handle. Returned by `Connection::files()`.
/// @ingroup client

#include "ua_byte_string.h"
#include "ua_logger.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_string.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <atomic>
#include <functional>
#include <memory>
#include <vector>

namespace ua::client
{

namespace detail
{
class WireOps;
struct FileHandleState;
struct FileTransferClientTestAccess;
}  // namespace detail

class Connection;
class FileTransferClient;

/// @ingroup client
/// Part 20 section 4.2.2 Open-mode bit flags. Wire type: `Byte`.
enum class FileOpenMode : std::uint8_t
{
  Read = 0x01,
  Write = 0x02,
  EraseExisting = 0x04,  ///< Combine with Write to truncate-on-open.
  Append = 0x08,  ///< Combine with Write to position at EOF on open.
};

/// @param a The a.
/// @param b The b.
/// @return The requested value.
/// Bitwise-OR two @ref ua::client::FileOpenMode flag sets (so `Write | EraseExisting` is well-typed).
constexpr FileOpenMode operator|(FileOpenMode a, FileOpenMode b)
{
  return static_cast<FileOpenMode>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}

/// @param value Value to write or evaluate.
/// @param mask The mask.
/// @return True iff any bit of @p mask is set in @p value.
constexpr bool any_set(FileOpenMode value, FileOpenMode mask)
{
  return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(mask)) != 0;
}

/// Callback invoked for byte string result notifications.
using ByteStringResult = ua::Result<ua::ByteString>;
/// Callback invoked for uint64 result notifications.
using UInt64Result = ua::Result<std::uint64_t>;

/// A move-only handle to one server-allocated `fileHandle` (client design section 8.10, CL-FILE-001).
///
/// `FileHandle` owns the close-on-destruct obligation for exactly one open FileType `fileHandle`: dropping a
/// live handle fires a fire-and-forget `FileType.Close` against the originating Connection. It is therefore
/// **move-only** (section 7.0: any handle that releases a server resource on destruction is move-only)  -
/// copying would duplicate the close-on-destruct obligation on one `fileHandle`, so the copy operations are
/// deleted and the close-duty transfers exactly once on move. Move-ASSIGNMENT first fires Close on any live
/// handle it displaces (else the displaced server `fileHandle` would leak), then adopts the source. A
/// moved-from handle is inert (its dtor is a no-op).
///
/// The handle binds to its originating Connection's wire interface by a `weak_ptr` (CL-MULTI): every op locks
/// it and completes `Bad_ConnectionClosed` if the Connection is gone, and the handle cannot be smuggled onto
/// a different Connection (it is move-only, so there is no copy to transfer).
///
/// Each op follows the section 7.0 async / sync / try_sync triple:
///  - `*_async`     -  never throws; the callback receives a `Result<...>` on the executor.
///  - `*_sync`      -  blocks; returns the bare value; throws `UaException` when the Result is not Good (an
///                     Uncertain answer included). A Good subcode on the answer is not returned; the
///                     `try_*_sync` form returns it.
///  - `try_*_sync`  -  blocks; returns `Result<...>`; never throws.
///
/// Each op's Result carries the FileType Call's ServiceResult and the Method's statusCode combined
/// (`ua::detail::combined_status`), so a Good subcode or an Uncertain code the server answers reaches the
/// caller; an Uncertain call without output arguments is answered with its code and no value.
///
/// @warning The `*_sync` / `try_*_sync` variants block the calling thread; they MUST NOT be called from the
///          Connection's executor thread.
/// @ingroup client
class FileHandle
{
public:
  /// Constructs an invalid sentinel handle (`is_valid() == false`; every op fast-fails, dtor is a no-op).
  FileHandle() = default;

  // MOVE-ONLY (section 7.0 / section 8.10.1): copying would duplicate the close-on-destruct obligation on one
  // server `fileHandle`, so the copy operations are deleted; move transfers the close-duty exactly once.
  FileHandle(const FileHandle&) = delete;
  FileHandle& operator=(const FileHandle&) = delete;
  /// Returns or updates the file handle.
  FileHandle(FileHandle&&) noexcept = default;
  /// @param other The other.
  /// @return A reference to this object.
  /// Fires Close on any live handle this displaces (exactly-once close-duty) before adopting @p other.
  FileHandle& operator=(FileHandle&& other) noexcept;

  /// Fires a fire-and-forget `FileType.Close` when the handle is live and not already closed (CL-FILE-001).
  ~FileHandle();

  /// @return True iff the handle owns a not-yet-closed server `fileHandle` (false once closed or moved-from).
  [[nodiscard]] bool is_valid() const noexcept;

  /// @return The FileType Object NodeId the handle was opened on (empty NodeId when moved-from).
  [[nodiscard]] ua::NodeId file_node() const noexcept;

  /// @return The `FileOpenMode` the handle was opened with.
  [[nodiscard]] FileOpenMode mode() const noexcept;

  /// @return The per-read/write cap resolved at Open (CL-FILE-002): the FileType instance's optional
  ///         `MaxByteStringLength`, otherwise `ServerCapabilities.MaxByteStringLength`, otherwise the
  ///         configured 64 KiB safe default.
  [[nodiscard]] std::uint32_t max_byte_string_length() const noexcept;

  /// @param maxBytes The max bytes.
  /// @param callback Completion callback that receives the operation result.
  /// Reads up to @p maxBytes bytes (capped at @ref max_byte_string_length, CL-FILE-002). An empty
  /// `ByteString` is end-of-file (CL-FILE-003), surfaced verbatim (the caller / `read_all` decides).
  void read_async(std::uint32_t maxBytes, std::function<void(ByteStringResult)> callback) noexcept;
  /// @param maxBytes The max bytes.
  /// @return The requested value.
  /// Synchronously read. A Good subcode on the answer is not returned; try_read_sync() returns it.
  ua::ByteString read_sync(std::uint32_t maxBytes);
  /// @param maxBytes The max bytes.
  /// @return The requested value.
  /// Attempts to read sync without throwing.
  ByteStringResult try_read_sync(std::uint32_t maxBytes) noexcept;

  /// @param data The data.
  /// @param callback Completion callback that receives the operation result.
  /// Writes @p data at the handle's current position. Rejects locally with `Bad_InvalidState` if the handle
  /// was opened read-only (CL-FILE-004).
  void write_async(ua::ByteString data, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param data The data.
  /// Synchronously write.
  void write_sync(ua::ByteString data);
  /// @param data The data.
  /// @return The requested value.
  /// Attempts to write sync without throwing.
  ua::VoidResult try_write_sync(ua::ByteString data) noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Reads the handle's current byte position.
  void get_position_async(std::function<void(UInt64Result)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously get position. A Good subcode on the answer is not returned; try_get_position_sync()
  /// returns it.
  std::uint64_t get_position_sync();
  /// @return The requested value.
  /// Attempts to get position sync without throwing.
  UInt64Result try_get_position_sync() noexcept;

  /// @param position The position.
  /// @param callback Completion callback that receives the operation result.
  /// Sets the handle's current byte position.
  void set_position_async(std::uint64_t position, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param position The position.
  /// Synchronously set position.
  void set_position_sync(std::uint64_t position);
  /// @param position The position.
  /// @return The requested value.
  /// Attempts to set position sync without throwing.
  ua::VoidResult try_set_position_sync(std::uint64_t position) noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Closes the handle now (idempotent, CL-FILE-001). After a close, further reads/writes fail
  /// `Bad_InvalidState`. Completes Good even when the wire Close reports bad (the server discards the handle
  /// on Session-end); a bad wire Close is logged at the wire boundary, not surfaced. A Good subcode or an
  /// Uncertain code the server answers the Close with is the result.
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously close.
  void close_sync();
  /// @return The requested value.
  /// Attempts to close sync without throwing.
  ua::VoidResult try_close_sync() noexcept;

private:
  friend class FileTransferClient;
  friend struct ua::client::detail::FileTransferClientTestAccess;

  explicit FileHandle(std::shared_ptr<detail::FileHandleState> state) : mState(std::move(state))
  {}

  /// Fires the fire-and-forget `FileType.Close` iff this handle is live and not already closed (CL-FILE-001).
  /// Shared by the dtor and move-assignment so the close-duty is discharged exactly once on either path.
  void fire_close_if_owed() noexcept;

  std::shared_ptr<detail::FileHandleState> mState;
};

/// Callback invoked for file handle result notifications.
using FileHandleResult = ua::Result<FileHandle>;

/// @ingroup client
/// The file system entry kind.
enum class FileSystemEntryKind
{
  Directory,
  File,
};

/// Public file system entry API.
/// @ingroup client
struct FileSystemEntry
{
  /// The node id.
  ua::NodeId nodeId;
  /// The browse name.
  ua::QualifiedName browseName;
  /// The display name.
  ua::LocalizedText displayName;
  /// The kind.
  FileSystemEntryKind kind{};
};

/// Callback invoked for file system entry list result notifications.
using FileSystemEntryListResult = ua::Result<std::vector<FileSystemEntry>>;
/// Callback invoked for node id result notifications.
using NodeIdResult = ua::Result<ua::NodeId>;

/// The per-`Connection` tier-2 facade for the File Transfer service set (client design section 8.10).
///
/// A lightweight, copyable value handle over the same tier-1 wire interface (`detail::WireOps`) as its parent
/// @ref Connection, reached via `Connection::files()`. It holds no strand state of its own; every method
/// composes the correct FileType Method Call and forwards it through the wire interface (which serializes on
/// the Connection strand internally). Completions are delivered on the Connection executor.
///
/// **Cycle-safe (section 9.8.3).** Neither the facade nor the per-handle `detail::FileHandleState` holds a
/// strong `shared_ptr` back to the owning facade / `ConnectionImpl`: the only back-reference is a `weak_ptr`
/// to the wire interface, locked per op and bailed if gone. Every internal async completion weak-captures the
/// per-handle state and bails cleanly if the handle was dropped mid-flight  -  no dangling deref, no
/// self-owning cycle.
///
/// **Status codes.** The open's Result carries the Open Call's ServiceResult and statusCode combined;
/// read_all and write_all carry the Open's and every chunk's code combined; list_directory carries every
/// Browse page's code combined; a directory Method's Result carries its Call's code. A Good subcode or an
/// Uncertain code is never replaced with plain Good. The lookups the SDK acts on itself (the FileType Method
/// and Property paths, MaxByteStringLength, UserWritable, a FileDirectoryType Method) use only a Good answer:
/// an Uncertain one is refused with `Bad_InternalError` (`ReferencesAnswerUncertain` /
/// `ReadAnswerUncertain`). Each `*_sync` form throws unless the Result is Good; a Good subcode on the answer
/// is returned only by its `try_*_sync` form.
///
/// @warning The `*_sync` / `try_*_sync` variants block the calling thread; they MUST NOT be called from the
///          Connection's executor thread.
/// @ingroup client
class FileTransferClient
{
public:
  /// Returns or updates the file transfer client.
  FileTransferClient(const FileTransferClient&) = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  FileTransferClient& operator=(const FileTransferClient&) = default;
  /// Returns or updates the file transfer client.
  FileTransferClient(FileTransferClient&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  FileTransferClient& operator=(FileTransferClient&&) noexcept = default;
  ~FileTransferClient() = default;

  /// Opens the FileType Object @p fileNode in @p mode and hands back a @ref FileHandle carrying the
  /// @param fileNode The file node.
  /// @param mode The mode.
  /// @param callback Completion callback that receives the operation result.
  /// server-allocated `fileHandle` (CL-FILE-001). Rejects locally with `Bad_InvalidArgument` if @p mode
  /// contains neither Read nor Write (CL-FILE-004). A failed Open constructs no handle (no Close is owed).
  void open_async(
    ua::NodeId fileNode, FileOpenMode mode, std::function<void(FileHandleResult)> callback) noexcept;
  /// @param fileNode The file node.
  /// @param mode The mode.
  /// @return The requested value.
  /// Synchronously open. A Good subcode on the answer is not returned; try_open_sync() returns it.
  FileHandle open_sync(ua::NodeId fileNode, FileOpenMode mode);
  /// @param fileNode The file node.
  /// @param mode The mode.
  /// @return The requested value.
  /// Attempts to open sync without throwing.
  FileHandleResult try_open_sync(ua::NodeId fileNode, FileOpenMode mode) noexcept;

  /// One-shot read of the whole file: Open(Read)  to  loop Read to EOF  to  Close (CL-FILE-002/-003).
  /// @param fileNode The file node.
  /// @param callback Completion callback that receives the operation result.
  /// Accumulates into a single `ByteString`. Honours an aggregate ceiling (@ref max_read_all_bytes,
  /// section 9.6.23.2): a file whose accumulated bytes would exceed the ceiling terminates with a bad Result
  /// (source `client.tier2.file_transfer.read_all`) rather than reading unbounded into memory. The
  /// internally-owned handle is dropped on completion, firing the fire-and-forget Close.
  void read_all_async(ua::NodeId fileNode, std::function<void(ByteStringResult)> callback) noexcept;
  /// @param fileNode The file node.
  /// @return The requested value.
  /// Synchronously read all. A Good subcode on the answer is not returned; try_read_all_sync() returns it.
  ua::ByteString read_all_sync(ua::NodeId fileNode);
  /// @param fileNode The file node.
  /// @return The requested value.
  /// Attempts to read all sync without throwing.
  ByteStringResult try_read_all_sync(ua::NodeId fileNode) noexcept;

  /// Writes all @p data using cap-sized sequential FileType.Write calls: read `UserWritable`,
  /// @param fileNode The file node.
  /// @param data The data.
  /// @param callback Completion callback that receives the operation result.
  /// Open(Write|EraseExisting), write every chunk, then Close (CL-FILE-004). A false `UserWritable`
  /// rejects locally before Open.
  void write_all_async(
    ua::NodeId fileNode, ua::ByteString data, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param fileNode The file node.
  /// @param data The data.
  /// Synchronously write all.
  void write_all_sync(ua::NodeId fileNode, ua::ByteString data);
  /// @param fileNode The file node.
  /// @param data The data.
  /// @return The requested value.
  /// Attempts to write all sync without throwing.
  ua::VoidResult try_write_all_sync(ua::NodeId fileNode, ua::ByteString data) noexcept;

  /// Browses every forward `Organizes` child and classifies it from `TypeDefinition`, never BrowseName
  /// @param directoryNode The directory node.
  /// @param callback Completion callback that receives the operation result.
  /// (Part 20 section 4.3.1, CL-FILE-005). Continuation points are drained before completion.
  void list_directory_async(
    ua::NodeId directoryNode, std::function<void(FileSystemEntryListResult)> callback) noexcept;
  /// @param directoryNode The directory node.
  /// @return The requested value.
  /// Synchronously list directory. A Good subcode on the answer is not returned; try_list_directory_sync()
  /// returns it.
  std::vector<FileSystemEntry> list_directory_sync(ua::NodeId directoryNode);
  /// @param directoryNode The directory node.
  /// @return The requested value.
  /// Attempts to list directory sync without throwing.
  FileSystemEntryListResult try_list_directory_sync(ua::NodeId directoryNode) noexcept;

  /// @param directoryNode The directory node.
  /// @param name The name.
  /// @param callback Completion callback that receives the operation result.
  /// Calls the directory object's resolved instance `CreateDirectory` Method (Part 20 section 4.3.3).
  void create_directory_async(
    ua::NodeId directoryNode, ua::String name, std::function<void(NodeIdResult)> callback) noexcept;
  /// @param directoryNode The directory node.
  /// @param name The name.
  /// @return The requested value.
  /// Synchronously create directory. A Good subcode on the answer is not returned;
  /// try_create_directory_sync() returns it.
  ua::NodeId create_directory_sync(ua::NodeId directoryNode, ua::String name);
  /// @param directoryNode The directory node.
  /// @param name The name.
  /// @return The requested value.
  /// Attempts to create directory sync without throwing.
  NodeIdResult try_create_directory_sync(ua::NodeId directoryNode, ua::String name) noexcept;

  /// Calls the directory object's resolved instance `CreateFile` Method with `requestFileOpen=false`
  /// @param directoryNode The directory node.
  /// @param name The name.
  /// @param callback Completion callback that receives the operation result.
  /// (Part 20 section 4.3.4), returning the created FileType NodeId. Use `open_*` afterwards when an
  /// SDK-owned, close-on-destruct FileHandle is required; this prevents an unowned raw server handle from
  /// escaping.
  void create_file_async(
    ua::NodeId directoryNode, ua::String name, std::function<void(NodeIdResult)> callback) noexcept;
  /// @param directoryNode The directory node.
  /// @param name The name.
  /// @return The requested value.
  /// Synchronously create file. A Good subcode on the answer is not returned; try_create_file_sync() returns
  /// it.
  ua::NodeId create_file_sync(ua::NodeId directoryNode, ua::String name);
  /// @param directoryNode The directory node.
  /// @param name The name.
  /// @return The requested value.
  /// Attempts to create file sync without throwing.
  NodeIdResult try_create_file_sync(ua::NodeId directoryNode, ua::String name) noexcept;

  /// @param directoryNode The directory node.
  /// @param objectToDelete The object to delete.
  /// @param callback Completion callback that receives the operation result.
  /// Calls `DeleteFileSystemObject` on the parent directory; never uses DeleteNodes (Part 20 section 4.3.5).
  void delete_async(ua::NodeId directoryNode, ua::NodeId objectToDelete,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param directoryNode The directory node.
  /// @param objectToDelete The object to delete.
  /// Synchronously delete.
  void delete_sync(ua::NodeId directoryNode, ua::NodeId objectToDelete);
  /// @param directoryNode The directory node.
  /// @param objectToDelete The object to delete.
  /// @return The requested value.
  /// Attempts to delete sync without throwing.
  ua::VoidResult try_delete_sync(ua::NodeId directoryNode, ua::NodeId objectToDelete) noexcept;

  /// @param sourceDirectoryNode The source directory node.
  /// @param objectToMoveOrCopy The object to move or copy.
  /// @param targetDirectoryNode The target directory node.
  /// @param createCopy The create copy.
  /// @param newName The new name.
  /// @param callback Completion callback that receives the operation result.
  /// Calls `MoveOrCopy` on the source parent directory (Part 20 section 4.3.6).
  void move_or_copy_async(ua::NodeId sourceDirectoryNode, ua::NodeId objectToMoveOrCopy,
    ua::NodeId targetDirectoryNode, bool createCopy, ua::String newName,
    std::function<void(NodeIdResult)> callback) noexcept;
  /// @param sourceDirectoryNode The source directory node.
  /// @param objectToMoveOrCopy The object to move or copy.
  /// @param targetDirectoryNode The target directory node.
  /// @param createCopy The create copy.
  /// @param newName The new name.
  /// @return The requested value.
  /// Synchronously move or copy. A Good subcode on the answer is not returned; try_move_or_copy_sync()
  /// returns it.
  ua::NodeId move_or_copy_sync(ua::NodeId sourceDirectoryNode, ua::NodeId objectToMoveOrCopy,
    ua::NodeId targetDirectoryNode, bool createCopy, ua::String newName);
  /// @param sourceDirectoryNode The source directory node.
  /// @param objectToMoveOrCopy The object to move or copy.
  /// @param targetDirectoryNode The target directory node.
  /// @param createCopy The create copy.
  /// @param newName The new name.
  /// @return The requested value.
  /// Attempts to move or copy sync without throwing.
  NodeIdResult try_move_or_copy_sync(ua::NodeId sourceDirectoryNode, ua::NodeId objectToMoveOrCopy,
    ua::NodeId targetDirectoryNode, bool createCopy, ua::String newName) noexcept;

  /// @return The aggregate `read_all_async` ceiling in bytes (section 9.6.23.2; default 64 MiB).
  [[nodiscard]] std::uint64_t max_read_all_bytes() const noexcept
  {
    return mMaxReadAllBytes;
  }

  /// @param ceiling The ceiling.
  /// Overrides the aggregate `read_all_async` ceiling (section 9.6.23.2). Advanced use.
  void set_max_read_all_bytes(std::uint64_t ceiling) noexcept
  {
    mMaxReadAllBytes = ceiling;
  }

private:
  friend class Connection;
  friend struct ua::client::detail::FileTransferClientTestAccess;

  FileTransferClient(std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::Logger logger = {}, std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration = {});

  std::weak_ptr<detail::WireOps>
    mWireOps;  ///< upward wire interface (section 8.2A.13); locked per op, bail if gone
  boost::asio::any_io_executor mExecutor;  ///< where handles / boundary failures are delivered
  ua::Logger mLogger;  ///< logs the dtor/close best-effort outcome at the wire boundary (CL-FILE-001)
  std::shared_ptr<const std::atomic<std::uint64_t>> mSessionGeneration;
  std::uint32_t mDefaultMaxByteStringLength = 0x10000;  ///< 64 KiB per-read fallback cap (CL-FILE-002)
  std::uint64_t mMaxReadAllBytes = 64ULL * 1024ULL * 1024ULL;  ///< 64 MiB read_all ceiling (section 9.6.23.2)
};

}  // namespace ua::client

#endif  // UA_FILE_TRANSFER_CLIENT_H
