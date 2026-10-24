// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Convenience helpers backing FileType, FileDirectoryType, and TemporaryFileTransferType
///        nodes with real filesystem I/O.
/// @ingroup address_space

#ifndef UA_FILE_SYSTEM_HELPERS_H
#define UA_FILE_SYSTEM_HELPERS_H

#include "ua_address_space.h"
#include "ua_file.h"
#include "ua_file_directory.h"
#include "ua_file_stream.h"
#include "ua_instantiation_options.h"
#include "ua_result.h"
#include "ua_temporary_file_transfer.h"
#include "ua_variant.h"

#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <utility>

namespace ua
{

struct MethodCallContext;

class FileHelper;

/// Result of a FileHelper create/attach operation: the helper on success, an @ref ErrorDetail on
/// failure.
using FileHelperResult = Result<FileHelper>;

/// Convenience class that backs a `FileType` address-space node with real filesystem I/O.
///
/// All six FileType methods (Open, Close, Read, Write, GetPosition, SetPosition) are wired
/// automatically to operate on the given filesystem path. Concurrent clients receive independent
/// file handles with independent stream positions. The four mandatory properties (Size, Writable,
/// UserWritable, OpenCount) are populated automatically; Size and OpenCount are dynamic, queried
/// from live state by their read handlers.
///
/// A helper created via `create_async`/`create_sync` owns the FileType subtree it instantiates and
/// removes it on destruction (RAII); call @ref release to detach that ownership. A helper produced
/// by `attach_async`/`attach_sync` wraps a pre-existing node and never owns it.
/// @ingroup address_space
class FileHelper
{
public:
  /// Constructs an empty helper that backs no node.
  FileHelper() = default;

  /// Callback type reporting the outcome of @ref create_async.
  using CreateCompleteCallback = std::function<void(FileHelperResult)>;

  /// Callback type reporting the outcome of @ref attach_async.
  using AttachCompleteCallback = std::function<void(FileHelperResult)>;

  /// Creates a new FileType instance under @p parent and wires all method/property handlers.
  ///
  /// Posts the instantiation and handler installation to the address space and completes
  /// asynchronously; the callback runs on an unspecified worker thread, so do not block it.
  ///
  /// @param addressSpace Address space in which the node is created.
  /// @param parent       Node under which the new FileType instance is created.
  /// @param browseName   Browse name of the new node.
  /// @param filePath     Filesystem path the FileType methods operate on.
  /// @param options      Instantiation options for the new subtree.
  /// @param writable     Whether the file may be opened for writing (drives the Writable /
  ///                     UserWritable properties and rejects write opens when false).
  /// @param maxFileSize Optional maximum resulting file size in bytes; absent leaves writes uncapped.
  /// @param complete     Receives the outcome: on success the Result holds the owning
  ///                     @ref FileHelper; on failure it carries an @ref ErrorDetail. This overload
  ///                     never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    std::filesystem::path filePath, const InstantiationOptions& options, bool writable,
    CreateCompleteCallback complete, std::optional<uint64_t> maxFileSize = std::nullopt) noexcept;

  /// Creates a new FileType instance under @p parent, blocking until complete.
  ///
  /// @param addressSpace Address space in which the node is created.
  /// @param parent       Node under which the new FileType instance is created.
  /// @param browseName   Browse name of the new node.
  /// @param filePath     Filesystem path the FileType methods operate on.
  /// @param options      Instantiation options for the new subtree.
  /// @param writable     Whether the file may be opened for writing (drives the Writable /
  ///                     UserWritable properties and rejects write opens when false).
  /// @param maxFileSize Optional maximum resulting file size in bytes; absent leaves writes uncapped.
  /// @return The owning @ref FileHelper, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async, create_sync
  static FileHelperResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, std::filesystem::path filePath, const InstantiationOptions& options,
    bool writable = true, std::optional<uint64_t> maxFileSize = std::nullopt) noexcept;

  /// Creates a new FileType instance under @p parent, blocking until complete.
  ///
  /// @param addressSpace Address space in which the node is created.
  /// @param parent       Node under which the new FileType instance is created.
  /// @param browseName   Browse name of the new node.
  /// @param filePath     Filesystem path the FileType methods operate on.
  /// @param options      Instantiation options for the new subtree.
  /// @param writable     Whether the file may be opened for writing (drives the Writable /
  ///                     UserWritable properties and rejects write opens when false).
  /// @param maxFileSize Optional maximum resulting file size in bytes; absent leaves writes uncapped.
  /// A Good subcode on the answer is not returned; try_create_sync() returns it.
  /// @return The owning @ref FileHelper.
  /// @throws UaException if the creation fails.
  /// @see create_async, try_create_sync
  static FileHelper create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, std::filesystem::path filePath, const InstantiationOptions& options,
    bool writable = true, std::optional<uint64_t> maxFileSize = std::nullopt);

  /// Wraps an existing FileType node and wires all method/property handlers.
  ///
  /// Posts the handler installation to the address space and completes asynchronously; the callback
  /// runs on an unspecified worker thread, so do not block it. The resulting helper does not own the
  /// node and leaves it in place on destruction.
  ///
  /// @param addressSpace    Address space containing the node.
  /// @param existingInstance Node id of the existing FileType instance to back.
  /// @param filePath        Filesystem path the FileType methods operate on.
  /// @param writable        Whether the file may be opened for writing (drives the Writable /
  ///                        UserWritable properties and rejects write opens when false).
  /// @param complete        Receives the outcome: on success the Result holds the non-owning
  ///                        @ref FileHelper; on failure it carries an @ref ErrorDetail. This
  ///                        overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(AddressSpace addressSpace, const NodeId& existingInstance,
    std::filesystem::path filePath, bool writable, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing FileType node, blocking until complete.
  ///
  /// @param addressSpace    Address space containing the node.
  /// @param existingInstance Node id of the existing FileType instance to back.
  /// @param filePath        Filesystem path the FileType methods operate on.
  /// @param writable        Whether the file may be opened for writing (drives the Writable /
  ///                        UserWritable properties and rejects write opens when false).
  /// @return The non-owning @ref FileHelper, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async, attach_sync
  static FileHelperResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance,
    std::filesystem::path filePath, bool writable = true) noexcept;

  /// Wraps an existing FileType node, blocking until complete.
  ///
  /// @param addressSpace    Address space containing the node.
  /// @param existingInstance Node id of the existing FileType instance to back.
  /// @param filePath        Filesystem path the FileType methods operate on.
  /// @param writable        Whether the file may be opened for writing (drives the Writable /
  ///                        UserWritable properties and rejects write opens when false).
  /// A Good subcode on the answer is not returned; try_attach_sync() returns it.
  /// @return The non-owning @ref FileHelper.
  /// @throws UaException if the attach fails.
  /// @see attach_async, try_attach_sync
  static FileHelper attach_sync(AddressSpace addressSpace, const NodeId& existingInstance,
    std::filesystem::path filePath, bool writable = true);

  /// Returns the node id of the backed FileType instance.
  /// @return The node id of the backed FileType instance.
  const NodeId& node_id() const;

  /// Returns the @ref File handle wrapping the backed FileType instance.
  /// @return The @ref File handle wrapping the backed FileType instance.
  const File& file() const;

  /// Open the backing file and return the FileType handle a Client would get from `Open`.
  ///
  /// The handle is issued out of the same table the FileType's own Open/Read/Write/Close Methods
  /// use, so it is a real handle rather than a token only this helper understands: the file's own
  /// Read rejects anything else. It is what a caller needs when a Method's contract is to hand back
  /// an already-open file -- `FileDirectoryType::CreateFile` with `RequestFileOpen` set, and
  /// `TemporaryFileTransferType`'s generate Methods -- both of which otherwise have to invent a
  /// handle their own file will not accept.
  ///
  /// Safe to call before @ref release() -- the open handle lives in the shared state the installed
  /// method handlers hold, and that outlives this accessor.
  ///
  /// @param mode      OPC 10000-20 section 4.2.1 open-mode byte, as the Open Method takes it.
  /// @param sessionId Session the handle is issued to, checked on every later call against it. Null
  ///                  for an internal caller, which forms its own handle space no Client can reach.
  /// @return The new file handle, or an error if the backing file could not be opened.
  Result<uint32_t> try_open_handle(uint8_t mode, const NodeId& sessionId = {});

  /// Detaches RAII ownership of the created subtree so it persists beyond this handle's lifetime.
  ///
  /// No-op for a helper produced by `attach_async`/`attach_sync`, which never owns its node.
  void release();

  /// Registers a callback that runs, with no lock held, whenever a Close removes the file's last
  /// open handle. Survives @ref release "release": the installed handlers own the state that holds it.
  /// @param callback Retained handler invoked whenever the last open handle closes.
  void on_all_handles_closed(std::function<void()> callback);

  /// Implementation-only state shared between the FileHelper instance and the method/property
  /// handlers it installs.
  ///
  /// Exposed in the public surface so that the callback-canonical install flow (defined in the
  /// `.cpp`) can access it; not part of the supported API.
  struct State
  {
    /// One open FileType handle: the stream, and the Session entitled to use it.
    ///
    /// Part 20 section 4.2.1 states the fileHandle "is generated by the server and is unique for the
    /// Session. Clients cannot transfer the fileHandle to another Session but need to get a new
    /// fileHandle by calling the Open Method." The handle id alone is therefore not sufficient
    /// authority to act on a stream, and the owning Session is stored beside it so every method
    /// can check the caller against it.
    struct OpenHandle
    {
      /// NodeId of the Session that called Open, from `MethodCallContext::sessionId`.
      ///
      /// Null for a direct or internal call made with no session context. Such handles form their
      /// own space: an internal caller cannot reach a client Session's handles, and no client
      /// Session can reach an internal one, because both directions fail the same equality test.
      NodeId sessionId;
      FileStream stream;  ///< The open stream and its independent position.

      /// The OPC 10000-20 section 4.2.1 mode byte the handle was opened with.
      ///
      /// Kept because the mode is a *permission mask on the handle*, not just an instruction to the
      /// Open call: the Read and Write bits gate the matching operation for the handle's whole life.
      /// A backing stream opened in a stdio mode that happens to allow both directions would
      /// otherwise serve a file's contents through a handle that asked for no read access at all.
      uint8_t mode{0};

      /// The handle's slot in the address space's FileType handle budget, which bounds the handles one
      /// Session, and all Sessions together, may hold open (`ServerConfig::ResourceLimits::
      /// openFileHandlesPerSession` and `openFileHandles`). Released when the handle ends, by whatever
      /// route.
      std::shared_ptr<const void> budgetSlot;
    };

    std::filesystem::path filePath;  ///< Filesystem path the FileType methods operate on.
    bool writable{true};  ///< Whether the file may be opened for writing.
    /// Largest size a Write may grow the file to (DEF-7); nullopt leaves it unbounded.
    std::optional<uint64_t> maxFileSize;
    /// Invoked (with no lock held) when Close removes the last open handle (DEF-7: a transient
    /// transfer file ends its transfer on the client's Close, Part 20 4.4).
    std::function<void()> onAllHandlesClosed;
    std::mutex mutex;  ///< Guards the open-handle table.
    std::map<uint32_t, OpenHandle> handles;  ///< Open file handles keyed by FileType handle id.
    uint32_t nextHandle{1};  ///< Next handle id to allocate on Open.

    /// Opaque ownership of the implementation-private AddressSpace Session-cleanup registration.
    /// The registered callback captures this State weakly, so this token does not form a cycle.
    std::shared_ptr<void> sessionCleanupRegistration;

    /// The largest ByteString a single Read may serve, or 0 for unbounded.
    ///
    /// OPC 10000-20 section 4.2.1: the file's own `MaxByteStringLength` Property caps it, and where the
    /// Property is absent the Server-wide `ServerCapabilities.MaxByteStringLength` applies instead --
    /// "must consult both, in that order".
    uint32_t maxByteStringLength{0};

    /// Whether @ref maxByteStringLength has been established yet.
    ///
    /// The Server-wide capability is read on the first Open rather than when the handlers are
    /// installed. A FileType is routinely created while the server is still being configured -- before
    /// it is started -- and an address-space read issued then comes back `Bad_Shutdown`, so an
    /// install-time resolution silently leaves every file uncapped. By the first Open the server is
    /// necessarily running.
    bool maxByteStringLengthResolved{false};

    /// Address space the Server-wide capability is read from. Weak: the handlers this State backs are
    /// owned by nodes inside that same address space, so a strong reference closes a cycle.
    WeakAddressSpace addressSpace;

    /// Keeps this file subscribed to Session closure for as long as the State lives.
    ///
    /// OPC 10000-20 section 4.2.2 gives a fileHandle a lifetime bounded by its Session -- it "is valid
    /// while the session is open" -- and nothing in the node graph observes a Session ending, so
    /// without this the handles of a Client that simply disconnects are never reclaimed. They are
    /// not merely a leak of an open stream: section 4.2.2 also makes writes exclusive, so one abandoned
    /// write handle refuses every later Open on that file, for every Client, until the server is
    /// restarted.
    ///
    /// Held as an opaque token (`ua::detail::AddressSpaceSessionEvents`): destroying it
    /// unsubscribes, so the registration lasts exactly as long as the handles it protects.
    std::shared_ptr<const void> sessionClosedSubscription;
  };

  /// The shared state backing this file's installed handlers.
  ///
  /// Exposed so a parent `FileDirectoryHelper` can hold it weakly and ask whether the file has open
  /// handles -- OPC 10000-20 section 4.3.5 refuses a delete while anything under the object is open, and the
  /// directory keeps metadata only. Not part of the supported API.
  ///
  /// @return The shared state; outlives this accessor, because the installed handlers hold it.
  std::shared_ptr<State> shared_state() const
  {
    return mState;
  }

  /// Implementation-only constructor used by the install flow once handlers are wired and the File
  /// handle is ready.
  ///
  /// @param file  The @ref File handle wrapping the wired FileType node.
  /// @param state Shared state backing the installed method and property handlers.
  explicit FileHelper(File file, std::shared_ptr<State> state);

private:
  Result<uint32_t> try_open_handle(uint8_t mode, const NodeId& sessionId, uint32_t requestedHandle);

  File mFile;
  std::shared_ptr<State> mState;

  friend class TemporaryFileTransferHelper;
};

class FileDirectoryHelper;

/// Result of a @ref FileDirectoryHelper factory: the helper on success, or an @ref ErrorDetail.
using FileDirectoryHelperResult = Result<FileDirectoryHelper>;

/// Convenience class that backs a `FileDirectoryType` address-space node with a real filesystem
/// directory.
///
/// The four FileDirectoryType methods are wired automatically against the backing directory path:
///
///   - `CreateFile` creates a file on disk and a child FileType node backed by FileHelper.
///   - `CreateDirectory` creates a directory on disk and a child FileDirectoryType node backed
///     recursively by FileDirectoryHelper.
///   - `DeleteFileSystemObject` deletes the file/directory on disk and removes the child node(s).
///   - `MoveOrCopy` currently returns `BadNotSupported` (cross-directory coordination is a planned
///     follow-up).
///
/// Create-only: only objects created through the methods appear in the address space; pre-existing
/// on-disk content is not reflected (a continuously-accurate view of an external directory belongs
/// in a custom Namespace, not this helper). `CreateFile` with `RequestFileOpen=true` returns the
/// new node with FileHandle 0 - clients open it via the File's Open method (auto-open-on-create is
/// a follow-up).
///
/// @note The created subtree is owned by this handle through RAII: on destruction the instantiated
///       node(s) are removed from the address space unless @ref release has been called.
/// @ingroup address_space
class FileDirectoryHelper
{
public:
  /// Constructs an empty handle that owns no node and wires no method handlers.
  FileDirectoryHelper() = default;

  /// Callback type reporting the outcome of @ref create_async.
  using CreateCompleteCallback = std::function<void(FileDirectoryHelperResult)>;

  /// Creates a new FileDirectoryType instance under @p parent, backed by @p dirPath, and wires all
  /// method handlers.
  ///
  /// @p dirPath is created on disk if it does not exist. Posts the instantiation to the address
  /// space and completes asynchronously; the callback runs on an unspecified worker thread, so do
  /// not block it. This is the overload to use from inside a method handler or any other callback
  /// the address space itself invokes - @ref try_create_sync blocks waiting on that address space,
  /// which a thread of its own executor cannot do.
  ///
  /// @param addressSpace Address space the new node is instantiated into.
  /// @param parent       Node the new FileDirectoryType instance is organized under.
  /// @param browseName   BrowseName of the new instance.
  /// @param dirPath      Filesystem directory backing the node; created if absent.
  /// @param options      Instantiation options for the new subtree.
  /// @param writable     Whether the directory and its created files accept writes.
  /// @param complete     Receives the owning helper, or an @ref ErrorDetail on failure. This
  ///                     overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    std::filesystem::path dirPath, const InstantiationOptions& options, bool writable,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new FileDirectoryType instance under @p parent, backed by @p dirPath, and wires all
  /// method handlers.
  ///
  /// @p dirPath is created on disk if it does not exist.
  ///
  /// @param addressSpace Address space the new node is instantiated into.
  /// @param parent       Node the new FileDirectoryType instance is organized under.
  /// @param browseName   BrowseName of the new instance.
  /// @param dirPath      Filesystem directory backing the node; created if absent.
  /// @param options      Instantiation options for the new subtree.
  /// @param writable     Whether the directory and its created files accept writes.
  /// @return The owning helper on success, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async, create_sync, try_attach_sync
  static FileDirectoryHelperResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, std::filesystem::path dirPath, const InstantiationOptions& options,
    bool writable = true) noexcept;

  /// Creates a new FileDirectoryType instance under @p parent, backed by @p dirPath, and wires all
  /// method handlers.
  ///
  /// @p dirPath is created on disk if it does not exist.
  ///
  /// @param addressSpace Address space the new node is instantiated into.
  /// @param parent       Node the new FileDirectoryType instance is organized under.
  /// @param browseName   BrowseName of the new instance.
  /// @param dirPath      Filesystem directory backing the node; created if absent.
  /// @param options      Instantiation options for the new subtree.
  /// @param writable     Whether the directory and its created files accept writes.
  /// A Good subcode on the answer is not returned; try_create_sync() returns it.
  /// @return The owning helper.
  /// @throws UaException if instantiation or method wiring fails.
  /// @see try_create_sync, try_attach_sync
  static FileDirectoryHelper create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, std::filesystem::path dirPath, const InstantiationOptions& options,
    bool writable = true);

  /// Wraps an existing FileDirectoryType node and wires all method handlers against @p dirPath.
  ///
  /// Unlike @ref try_create_sync, no node is instantiated; the returned helper does not own the
  /// wrapped node and does not remove it on destruction.
  ///
  /// @param addressSpace    Address space containing the node.
  /// @param existingInstance FileDirectoryType node to wire method handlers onto.
  /// @param dirPath         Filesystem directory the wrapped node operates on.
  /// @param writable        Whether the directory and its created files accept writes.
  /// @return The helper on success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_create_sync, create_sync
  static FileDirectoryHelperResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance,
    std::filesystem::path dirPath, bool writable = true) noexcept;

  /// Returns the NodeId of the backed FileDirectoryType node.
  /// @return The NodeId of the backed FileDirectoryType node.
  const NodeId& node_id() const;

  /// Returns the typed accessor for the backed FileDirectoryType node.
  /// @return The typed @ref FileDirectory accessor for the backed node.
  const FileDirectory& directory() const;

  /// Detaches RAII ownership of the created subtree so it persists beyond this handle's lifetime.
  ///
  /// After this call the helper's destructor no longer removes the instantiated node(s) from the
  /// address space.
  void release();

  /// Implementation-only shared state between the helper and the method handlers it installs.
  struct State;

  /// The shared state backing this directory's installed handlers.
  ///
  /// Exposed for the same reason as `FileHelper::shared_state`: a parent directory holds its
  /// children's state weakly so it can answer "is anything under here open?" before deleting. Not
  /// part of the supported API.
  ///
  /// @return The shared state; outlives this accessor, because the installed handlers hold it.
  std::shared_ptr<State> shared_state() const
  {
    return mState;
  }

  /// Constructs a helper bound to an already-instantiated @p directory and its shared @p state.
  ///
  /// @param directory Typed accessor for the backed FileDirectoryType node.
  /// @param state     Shared state driving the installed method handlers.
  explicit FileDirectoryHelper(FileDirectory directory, std::shared_ptr<State> state);

private:
  FileDirectory mDirectory;
  std::shared_ptr<State> mState;
};

class TemporaryFileTransferHelper;

/// Result of constructing a @ref TemporaryFileTransferHelper, or an @ref ErrorDetail on failure.
using TemporaryFileTransferHelperResult = Result<TemporaryFileTransferHelper>;

/// Configuration and host hooks for a @ref TemporaryFileTransferHelper.
///
/// Carries the on-disk location and parent Node for transient transfer files, plus two
/// optional host callbacks (@ref onCommit, @ref onGenerateForRead) that decide what an uploaded
/// file becomes and what bytes a read transfer serves. Both callbacks default to unset, which
/// yields a scratch transfer (uploads discarded, reads served an empty file).
/// @ingroup address_space
struct TemporaryFileTransferConfig
{
  std::filesystem::path tempDir;  ///< Filesystem directory holding the transient transfer files.
  NodeId transientFileParent;  ///< Node under which transient FileType nodes are created (browsable).

  /// Invoked on CloseAndCommit of a write transfer with the path of the uploaded temp file.
  ///
  /// Decides what the uploaded bytes become (for example, replacing a target file). A failing
  /// @ref VoidResult (carrying an @ref ErrorDetail) fails the commit. Any other answer's code is
  /// CloseAndCommit's status, with its output: an Uncertain code reaches the client as it is, and a Good
  /// subcode is answered plain Good with the ErrorDetail `MethodStatusQualified` (OPC 10000-4 5.11.2.4).
  /// When unset, the upload is discarded (scratch transfer). The path is valid only for the duration of the
  /// call. The @ref MethodCallContext is held by shared ownership and may be null.
  std::function<VoidResult(const std::filesystem::path& uploadedFile, shared_ptr<const MethodCallContext>)>
    onCommit;

  /// Largest size an upload (a write transfer's temp file) may grow to, in bytes (DEF-7); 0 leaves it
  /// unbounded. A Write past it is refused with Bad_OutOfRange. Default 64 MiB. Per-call API
  /// configuration: not a field of the process configuration file.
  uint64_t maxFileSize{64ull * 1024 * 1024};
  /// Most transfers one Session may hold open at once (DEF-7); 0 leaves it unbounded. A further
  /// GenerateFileFor* is refused with Bad_TooManyOperations until one is closed. Default 8.
  uint32_t maxActiveTransfersPerSession{8};

  /// Invoked on GenerateFileForRead to obtain the file the client will read.
  ///
  /// Returns the path of the file to serve, or an @ref ErrorDetail on failure. An Uncertain answer, with
  /// or without a path, is not acted on: GenerateFileForRead answers `Bad_InternalError`
  /// (`AnswerUncertain`, the hook's code as its cause). When unset, an empty temp file is served.
  /// The @ref MethodCallContext is held by shared ownership and may be null.
  std::function<Result<std::filesystem::path>(
    const Variant& generateOptions, shared_ptr<const MethodCallContext>)>
    onGenerateForRead;
};

/// Convenience class backing a `TemporaryFileTransferType` node in the address space.
///
/// Implements the GenerateFileForWrite, GenerateFileForRead, and CloseAndCommit methods. Each
/// transfer gets a transient `FileType` node backed by a `FileHelper` over a temp file in
/// @ref TemporaryFileTransferConfig::tempDir; CloseAndCommit invokes the host commit hook (for
/// write transfers), then removes the transient node and temp file. Transfers complete
/// synchronously, so the CompletionStateMachine output is left null (valid for synchronous
/// completion).
///
/// This is a value handle that holds shared ownership of the created subtree. Copying shares the
/// same backing state; destroying the last handle tears the subtree down unless @ref release was
/// called first.
/// @ingroup address_space
class TemporaryFileTransferHelper
{
public:
  /// Constructs an empty handle that backs no node.
  TemporaryFileTransferHelper() = default;

  /// Instantiates a TemporaryFileTransferType node under @p parent and backs it with this helper.
  ///
  /// @param addressSpace Address space the node is created in.
  /// @param parent       Node under which the transfer object is instantiated.
  /// @param browseName   Browse name of the new transfer object.
  /// @param options      Instantiation options for the created subtree.
  /// @param config       Configuration and host hooks (see @ref TemporaryFileTransferConfig).
  /// @return The helper handle on success, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_sync
  static TemporaryFileTransferHelperResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    TemporaryFileTransferConfig config) noexcept;

  /// Instantiates a TemporaryFileTransferType node under @p parent and backs it with this helper.
  ///
  /// @param addressSpace Address space the node is created in.
  /// @param parent       Node under which the transfer object is instantiated.
  /// @param browseName   Browse name of the new transfer object.
  /// @param options      Instantiation options for the created subtree.
  /// @param config       Configuration and host hooks (see @ref TemporaryFileTransferConfig).
  /// A Good subcode on the answer is not returned; try_create_sync() returns it.
  /// @return The helper handle.
  /// @throws UaException if instantiation fails.
  /// @see try_create_sync
  static TemporaryFileTransferHelper create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options, TemporaryFileTransferConfig config);

  /// Returns the node id of the instantiated transfer object.
  /// @return The node id of the instantiated transfer object.
  const NodeId& node_id() const;

  /// Returns the underlying @ref TemporaryFileTransfer wrapper for the instantiated node.
  /// @return The @ref TemporaryFileTransfer wrapper for the instantiated node.
  const TemporaryFileTransfer& transfer() const;

  /// Detaches RAII ownership of the created subtree so it persists beyond this handle's lifetime.
  ///
  /// After this call, destroying the handle no longer removes the transfer object from the address
  /// space.
  void release();

  /// Opaque shared backing state for the helper.
  struct State;

  /// Constructs a helper that wraps an already-instantiated transfer object and its backing state.
  ///
  /// @param transfer Wrapper for the instantiated TemporaryFileTransferType node.
  /// @param state    Shared backing state owning the transient transfer machinery.
  explicit TemporaryFileTransferHelper(TemporaryFileTransfer transfer, std::shared_ptr<State> state);

private:
  static Result<uint32_t> open_transient_file_handle(
    FileHelper& file, uint8_t mode, const NodeId& sessionId, uint32_t requestedHandle);

  TemporaryFileTransfer mTransfer;
  std::shared_ptr<State> mState;
};

}  // namespace ua

#endif  // UA_FILE_SYSTEM_HELPERS_H
