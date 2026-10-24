// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_route.h"
#include "ua_file_system_helpers.h"

#include "ua_address_space_session_events.h"
#include "ua_guid.h"
#include "ua_file_stream.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_file.h"
#include "ua_log_exception.h"
#include "ua_node.h"
#include "ua_node_id.h"
#include "ua_owner_only_directory.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status_code.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include "fmt/format.h"

#include <optional>
#include <algorithm>
#include <fstream>
#include <map>
#include <mutex>
#include <system_error>
#include <utility>

namespace ua
{

struct TemporaryFileTransferHelper::State
{
  State(AddressSpace as, NodeId id, TemporaryFileTransferConfig cfg)
    : addressSpace(as.weak()), nodeId(std::move(id)), config(std::move(cfg))
  {}

  // Weak, NOT strong: this State is captured by the GenerateFileForWrite/Read and
  // CloseAndCommit method handlers, which are stored on the TemporaryFileTransfer's
  // method nodes inside the address space. A strong AddressSpace here closes a
  // reference cycle (AddressSpace -> method node -> handler -> State -> AddressSpace)
  // that leaks the entire node graph when the server is destroyed. Handlers run only
  // while the server (and thus the address space) is alive, so lock() succeeds at use.
  WeakAddressSpace addressSpace;
  NodeId nodeId;
  TemporaryFileTransferConfig config;

  std::mutex mutex;

  struct Entry
  {
    // Deliberately does NOT retain the FileHelper accessor. The transient node is
    // owned by the address space and is removed explicitly on commit; retaining
    // the accessor here kept the transient file's node subtree alive in a
    // reference cycle (the file's method/property handlers and the cached node
    // handles inside the accessor mutually root one another), leaking it whenever
    // a generated file was never closed/committed. CloseAndCommit needs only the
    // identifiers below - matching the FileDirectory helper, which stores metadata
    // (not the accessor) and does not leak.
    NodeId fileNodeId;
    std::filesystem::path path;
    bool isWrite{false};

    /// NodeId of the Session that called GenerateFileForRead/Write, or null for a call carrying no
    /// session context.
    ///
    /// Part 20 section 4.4.1: the generated temporary FileType Object "is not browsable in the AddressSpace
    /// and can only be accessed with the NodeId and FileHandle returned by the Methods **in the same
    /// Session**." Non-browsable is not the protection -- the handle comes from a monotonic counter,
    /// so any client that generates one transfer knows the ids around it. The Session is.
    NodeId sessionId;

    /// Handle table of the transient file, held weakly for the reason the accessor is not held at
    /// all. CloseAndCommit closes the transfer's handle through it before the onCommit hook reads the
    /// file: Part 20 section 4.4.5 has the Method "apply the content of the written file", and until
    /// the stream is closed the last Write can still sit in its stdio buffer, so the hook would read
    /// a truncated file.
    std::weak_ptr<FileHelper::State> fileState;
  };

  std::map<uint32_t, Entry> active;
  /// Transfers a Session has asked for whose transient node is still being created (DEF-7): counted
  /// against the quota with `active`, so concurrent GenerateFileFor* calls cannot all pass the check.
  std::map<NodeId, uint32_t> pendingBySession;
  /// Open transfers per Session, kept alongside `active` (DEF-7): the quota check reads one entry
  /// instead of scanning every Session's transfers, so a generate costs O(log Sessions).
  std::map<NodeId, uint32_t> activeBySession;
  uint32_t nextHandle{1};

  /// Records an open transfer; the caller holds `mutex`.
  void insert_active_locked(uint32_t fileHandle, Entry entry)
  {
    ++activeBySession[entry.sessionId];
    active.emplace(fileHandle, std::move(entry));
  }

  /// Removes an open transfer and hands its entry back; the caller holds `mutex`.
  Entry detach_active_locked(std::map<uint32_t, Entry>::iterator it)
  {
    Entry detached = std::move(it->second);
    active.erase(it);
    const auto count = activeBySession.find(detached.sessionId);
    if (count != activeBySession.end() && --count->second == 0)
      activeBySession.erase(count);
    return detached;
  }

  /// A Session's quota slot, held from admission until its transient node exists or the creation
  /// has failed (DEF-7). Released exactly once on whichever path completes; a path that releases
  /// nothing (an exception between admission and the create, a callback never run) is covered by
  /// the destructor, so a slot can neither leak nor be given back twice.
  class Reservation
  {
  public:
    Reservation(std::shared_ptr<State> state, NodeId sessionId)
      : mState{std::move(state)}, mSessionId{std::move(sessionId)}
    {}

    Reservation(const Reservation&) = delete;
    Reservation& operator=(const Reservation&) = delete;
    Reservation(Reservation&&) = delete;
    Reservation& operator=(Reservation&&) = delete;

    ~Reservation()
    {
      release();
    }

    void release()
    {
      if (auto state = std::exchange(mState, nullptr))
        state->release_reservation(mSessionId);
    }

    /// For a caller already holding `mutex`.
    void release_locked()
    {
      if (auto state = std::exchange(mState, nullptr))
        state->release_reservation_locked(mSessionId);
    }

  private:
    std::shared_ptr<State> mState;
    NodeId mSessionId;
  };

  /// Keeps this helper subscribed to Session closure; destroying it unsubscribes.
  std::shared_ptr<const void> sessionCleanupRegistration;

  /// The Node transient FileType Objects are created under, created on first use.
  ///
  /// OPC 10000-20 section 4.4.1: the generated temporary FileType Object "is not browsable in the
  /// AddressSpace and can only be accessed with the NodeId and FileHandle returned by the Methods in
  /// the same Session." A transient file hung off `config.transientFileParent` is browsable by
  /// definition -- a client walking the hierarchy finds `Transient_1` and has the NodeId the clause
  /// says only the caller should hold. The holder carries no inverse hierarchical Reference from
  /// anything reachable, so nothing browses to it and nothing browses through it, which is the same
  /// technique `SubscriptionDiagnosticsNodeManager` uses for its staging node.
  ///
  /// `config.transientFileParent` stays in the configuration and stays meaningful: it names the
  /// namespace the transient nodes are allocated in, which is what makes their NodeIds belong to the
  /// deployment's own space rather than to the SDK's.
  NodeId transientHolder;
  /// Whether the holder has been created. Guarded by `mutex`.
  bool transientHolderCreated{false};

  /// The holder's NodeId in namespace @p ns. Named from this transfer's own NodeId, so it is the same
  /// every time; `mutex` must be held.
  NodeId transient_holder_id(uint16_t ns)
  {
    if (transientHolder.is_null())
      transientHolder = NodeId{ns, String{transient_holder_name(nodeId)}};
    return transientHolder;
  }

  static std::string transient_holder_name(const NodeId& transferNodeId)
  {
    return fmt::format("__TransientFiles_{}", ua::to_string(transferNodeId));
  }

  /// Creates the holder, once, and then calls @p done with its NodeId.
  ///
  /// Asynchronous and outside `mutex`: this runs from the GenerateFileForRead and GenerateFileForWrite
  /// method handlers on a thread of the address space's executor, and the target namespace may answer
  /// the create by posting to that executor. The BrowseName travels as a creation attribute, so there
  /// is no second write. Two first calls racing may both ask for the create; the loser's
  /// Bad_NodeIdExists is the holder the winner made, and is success.
  static void ensure_transient_holder_async(const std::shared_ptr<TemporaryFileTransferHelper::State>& state,
    AddressSpace& addressSpace, NodeId holderId, std::function<void(NodeIdResult)> done)
  {
    {
      const std::lock_guard lock{state->mutex};
      if (state->transientHolderCreated)
      {
        done(NodeIdResult{std::move(holderId)});
        return;
      }
    }
    auto browseName = QualifiedName{holderId.namespace_index(), transient_holder_name(state->nodeId)};
    addressSpace.create_node_async(holderId,
      NodeClass::Object,
      InitialAttributes{{AttributeId::BrowseName, Variant{std::move(browseName)}}},
      [state, holderId, done = std::move(done)](NodeAccessorResult created) mutable
      {
        if (!created.is_good() && created.status_code() != StatusCode{Status::BadNodeIdExists})
        {
          const StatusCode refused =
            ::ua::detail::lookup_failure(holderId, created.status_code(), "TemporaryFileTransferHelper");
          // A holder the namespace created but answered Uncertain is removed again before the refusal is
          // answered, so that the next call does not take it as the holder a racing call made.
          auto holding = state->addressSpace.lock();
          if (holding && created.has_value())
          {
            holding->delete_node_async(holderId,
              /*deleteForwardHierarchicallyReferencedNodes=*/true,
              ReferenceHalves::Both,
              [refused, done = std::move(done)](VoidResult) mutable { done(NodeIdResult{refused}); });
            return;
          }
          done(NodeIdResult{refused});
          return;
        }
        {
          const std::lock_guard lock{state->mutex};
          state->transientHolderCreated = true;
        }
        done(NodeIdResult{std::move(holderId)});
      });
  }

  /// What a generated transfer hands back: the transient file's node and the handle its own Read and
  /// Write will accept.
  struct TransientFile
  {
    uint32_t fileHandle{0};
    NodeId fileNodeId;
  };

  using TransientResult = Result<TransientFile>;

  /// Creates a transient FileType node backed by `explicitPath`, or by a name derived from the
  /// handle when none is given (the file is created empty for writes).
  ///
  /// ASYNC, and not merely for tidiness. This is reached from the GenerateFileForRead and
  /// GenerateFileForWrite method handlers, which run on a thread of the address space's executor.
  /// The shape this replaces called `FileHelper::create_sync` there - blocking that thread on a
  /// future for work queued to the same executor, while holding `mutex`. That is a wait a
  /// multi-threaded pool absorbs and a single-threaded one deadlocks on, with a lock held.
  ///
  /// The lock is taken only to allocate the handle and name the file - which must be atomic, since
  /// the name is derived from the handle - and again to record the entry. It is never held across
  /// the create.
  ///
  /// @param sessionId The Session generating the transfer, recorded on the entry so CloseAndCommit
  ///                  can refuse a handle presented by anyone else (Part 20 section 4.4.1).
  static void make_transient_async(const std::shared_ptr<TemporaryFileTransferHelper::State>& state,
    bool isWrite, std::optional<std::filesystem::path> explicitPath, NodeId sessionId,
    std::function<void(TransientResult)> done)
  {
    std::optional<AddressSpace> addressSpace;
    std::filesystem::path path;
    NodeId holder;
    uint16_t ns = 0;
    uint32_t handle = 0;
    InstantiationOptions options;
    std::shared_ptr<Reservation> reservation;  // outlives the lock below: its release takes `mutex`
    {
      const std::lock_guard lock{state->mutex};
      auto locked = state->addressSpace.lock();
      if (!locked)
      {
        done(TransientResult{StatusCode{Status::BadInvalidState},
          make_error_detail("AddressSpaceDestroyed",
            "Address space has been destroyed; cannot create transient file node",
            "TemporaryFileTransferHelper")});
        return;
      }
      addressSpace = std::move(locked);
      // DEF-7: a Session holds at most maxActiveTransfersPerSession transfers at once; the transient
      // node, its temp file and its FileHelper are resources a client could otherwise multiply at will.
      if (const auto quota = state->config.maxActiveTransfersPerSession; quota > 0)
      {
        const auto pending = state->pendingBySession.find(sessionId);
        const auto open = state->activeBySession.find(sessionId);
        const auto held = (open == state->activeBySession.end() ? 0u : open->second) +
                          (pending == state->pendingBySession.end() ? 0u : pending->second);
        if (held >= quota)
        {
          done(TransientResult{StatusCode{Status::BadTooManyOperations},
            ErrorDetail::build("TransientTransferQuotaExceeded",
              "The Session already holds the configured maximum of open transfers",
              "TemporaryFileTransferHelper")
              .context(ua::ContextKeys::sizeMax, std::to_string(quota))});
          return;
        }
      }
      ++state->pendingBySession[sessionId];  // reserved until the create completes, either way
      reservation = std::make_shared<Reservation>(state, sessionId);
      handle = state->nextHandle++;  // names the transient node; the FileHandle comes from the file
      ns = state->config.transientFileParent.namespace_index();
      holder = state->transient_holder_id(ns);
      // DEF-7: the file name carries a fresh GUID, not the counter: a predictable name lets a local
      // user pre-plant a file or symlink at the path a transfer is about to use. fmt needs a
      // constant format string, so the direction is an argument rather than part of it.
      path = explicitPath ? std::move(*explicitPath)
                          : state->config.tempDir / fmt::format("xfer_{}_{}.bin",
                                                      isWrite ? 'w' : 'r',
                                                      ua::to_string(Guid::create_and_generate()));
      options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
      options.targetNamespaceIndex = ns;
    }

    if (isWrite || !explicitPath)
    {
      // DEF-7: created exclusively (O_CREAT|O_EXCL|O_NOFOLLOW, owner-only): an existing file or a
      // planted symlink at the path is an error, never truncated or followed.
      FileStream create{path.string()};
      const auto created = create.open_for_exclusive_write();
      if (created.is_bad())
      {
        reservation->release();
        done(TransientResult{StatusCode{Status::BadInternalError},
          ErrorDetail::build("TransientFileCreateFailed",
            "The transient transfer file could not be created exclusively",
            "TemporaryFileTransferHelper")
            .context(ua::ContextKeys::filePath, path.string())
            .cause(created)});
        return;
      }
      try
      {
        create.close();
      }
      catch (...)
      {
        // The exclusive create succeeded, so the empty file must not stay behind; the call completes
        // with the close failure's own status and detail (rethrowing would reach the method handler
        // after its completion callback was moved into `done`).
        remove_quietly(path);
        reservation->release();
        done(TransientResult{ua::exception_to_status_code(std::current_exception())});
        return;
      }
    }

    const bool ownsFile = isWrite || !explicitPath;  // the helper created it: it removes it on failure
    // DEF-7: a write transfer's file may grow only to the configured ceiling (0 = unbounded).
    const std::optional<uint64_t> uploadLimit = (isWrite && state->config.maxFileSize > 0)
                                                  ? std::optional<uint64_t>{state->config.maxFileSize}
                                                  : std::nullopt;
    ensure_transient_holder_async(state,
      *addressSpace,
      std::move(holder),
      [weakAddressSpace = addressSpace->weak(),
        state,
        isWrite,
        ownsFile,
        path,
        ns,
        handle,
        options,
        uploadLimit,
        sessionId = std::move(sessionId),
        done = std::move(done),
        reservation](NodeIdResult holderResult) mutable
      {
        if (!holderResult.is_good())
        {
          reservation->release();
          if (ownsFile)
            remove_quietly(path);
          done(TransientResult{holderResult.status_code(), holderResult.shared_detail()});
          return;
        }
        // The completion holds the address space weakly (CALLS-21 rule 1).
        auto owner = weakAddressSpace.lock();
        if (!owner)
        {
          reservation->release();
          if (ownsFile)
            remove_quietly(path);
          done(TransientResult{::ua::detail::address_space_gone("TemporaryFileTransferHelper")});
          return;
        }
        FileHelper::create_async(
          *owner,
          holderResult.value(),
          QualifiedName{ns, String{fmt::format("Transient_{}", handle)}},
          path,
          options,
          isWrite,
          [state,
            isWrite,
            ownsFile = ownsFile,  // a mutable copy: cleared once the entry owns the file
            path,
            sessionId = std::move(sessionId),
            handle,
            done = std::move(done),
            reservation](FileHelperResult created) mutable
          {
            try
            {
              if (!created.is_good())
              {
                reservation->release();
                if (ownsFile)
                  remove_quietly(
                    path);  // DEF-7: a GUID name is never reused, so a failure must not orphan it
                done(TransientResult{created.status_code(), created.shared_detail()});
                return;
              }
              auto file = std::move(created).value();
              const auto fileNodeId = file.node_id();

              // OPC 10000-20 section 4.4.1: the Methods return a NodeId *and* a FileHandle, and the
              // handle has to be one the transient file's own Read and Write accept. Allocating it from
              // this helper's private counter produced a number the file rejected with
              // Bad_InvalidArgument, so the transfer the Client was told to proceed with could never
              // begin. The handle comes from the file's own table, taken before `release` and outliving
              // the accessor because the installed method handlers hold that state.
              const uint8_t mode = isWrite ? uint8_t{0x02} : uint8_t{0x01};
              auto opened =
                TemporaryFileTransferHelper::open_transient_file_handle(file, mode, sessionId, handle);
              if (!opened.is_good())
              {
                reservation->release();
                if (ownsFile)
                  remove_quietly(path);
                const StatusCode cause = opened.status_code();
                done(TransientResult{cause.as_status(),
                  ErrorDetail::build("TransientFileNotOpenable",
                    "The transient file could not be opened for the transfer it was generated for",
                    "TemporaryFileTransferHelper")
                    .cause(cause)});
                return;
              }
              const uint32_t fileHandle = opened.value();
              // DEF-7 / Part 20 4.4: a read transfer ends with the client's Close on the transient file;
              // a write transfer with CloseAndCommit, which detaches the entry first so this callback
              // then finds nothing to do. Either way the Session's quota is released.
              file.on_all_handles_closed(
                [weak = std::weak_ptr<TemporaryFileTransferHelper::State>{state}, fileHandle]
                {
                  if (auto lockedState = weak.lock())
                    lockedState->release_transfer(fileHandle);
                });
              std::weak_ptr<FileHelper::State> fileState = file.shared_state();
              file.release();
              {
                const std::lock_guard lock{state->mutex};
                state->insert_active_locked(
                  fileHandle, Entry{fileNodeId, std::move(path), isWrite, sessionId, std::move(fileState)});
                reservation->release_locked();
                ownsFile = false;  // the entry owns the file from here
              }
              done(TransientResult{TransientFile{fileHandle, fileNodeId}});
            }
            catch (...)
            {
              reservation->release();  // a no-op on a path that already released: the count stays exact
              if (ownsFile)
                remove_quietly(path);
              done(TransientResult{ua::exception_to_status_code(std::current_exception())});
            }
          },
          uploadLimit);
      });
  }

  static void remove_quietly(const std::filesystem::path& path)
  {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
  }

  void release_reservation_locked(const NodeId& sessionId)
  {
    const auto it = pendingBySession.find(sessionId);
    if (it == pendingBySession.end())
      return;
    if (--it->second == 0)
      pendingBySession.erase(it);
  }

  void release_reservation(const NodeId& sessionId)
  {
    const std::lock_guard lock{mutex};
    release_reservation_locked(sessionId);
  }

  /// The client closed the transient file (DEF-7): the transfer is over, its entry, temp file and
  /// transient node go, and the Session's quota slot with them. A handle CloseAndCommit already
  /// detached is not found here and nothing happens.
  void release_transfer(uint32_t fileHandle)
  {
    Entry detached;
    {
      const std::lock_guard lock{mutex};
      const auto it = active.find(fileHandle);
      if (it == active.end())
        return;
      detached = detach_active_locked(it);
    }
    cleanup_entry(std::move(detached), "Temporary file Close cleanup");
  }

  void release_session(const NodeId& sessionId)
  {
    if (sessionId.is_null())
      return;

    for (;;)
    {
      Entry detached;
      bool found = false;
      {
        const std::lock_guard lock{mutex};
        const auto it = std::find_if(active.begin(),
          active.end(),
          [&sessionId](const auto& item) { return item.second.sessionId == sessionId; });
        if (it == active.end())
          break;
        detached = detach_active_locked(it);
        found = true;
      }
      if (!found)
        break;
      cleanup_entry(std::move(detached), "Temporary file Session cleanup");
    }
  }

  /// Removes a detached transfer's temp file and transient node, logging what cannot be removed.
  void cleanup_entry(Entry detached, const char* what)
  {
    {
      auto as = addressSpace.lock();
      const auto logger = as ? as->logger().with_category("temporary-file-transfer") : Logger{};
      std::error_code error;
      std::filesystem::remove(detached.path, error);
      if (error)
      {
        log_exception(logger,
          LogLevel::Error,
          what,
          StatusCode{Status::BadUnexpectedError,
            ErrorDetail::build("TemporaryFileRemovalFailed",
              "Temporary file cleanup could not remove the backing path",
              "TemporaryFileTransferHelper")
              .context(ContextKeys::filePath, detached.path.string())
              .context(ContextKeys::errorMessage, error.message())});
      }

      if (as)
      {
        as->delete_node_async(detached.fileNodeId,
          /*deleteForwardHierarchicallyReferencedNodes=*/true,
          ReferenceHalves::Both,
          [logger, what](VoidResult result)
          {
            if (result.is_bad())
              log_exception(logger, LogLevel::Error, what, result.status_code());
          });
      }
    }
  }
};

namespace
{

void install_handlers(
  const TemporaryFileTransfer& transfer, std::shared_ptr<TemporaryFileTransferHelper::State> state)
{
  transfer.set_generate_file_for_write_handler_sync(
    [state](const MethodCall& call,
      const TemporaryFileTransfer::GenerateFileForWriteInputArguments&,
      MethodResultCallback<TemporaryFileTransfer::GenerateFileForWriteOutputArguments>
        complete)
    {
      const auto& ctx = ::ua::detail::MethodCallAccess::shared_context(call);
      // No lock taken here. make_transient_async holds `mutex` only to allocate the handle and name
      // the file, and again to record the entry - never across the create, which is what stops this
      // method handler blocking a pool thread on work queued to that same pool.
      TemporaryFileTransferHelper::State::make_transient_async(state,
        /*isWrite=*/true,
        std::nullopt,
        ctx ? ctx->sessionId : NodeId{},
        [complete = std::move(complete)](TemporaryFileTransferHelper::State::TransientResult result) mutable
        {
          if (!result.is_good())
          {
            complete(result.status_code());
            return;
          }
          TemporaryFileTransfer::GenerateFileForWriteOutputArguments out;
          out.fileNodeId = result.value().fileNodeId;
          out.fileHandle = result.value().fileHandle;
          complete(out);
        });
    });

  transfer.set_generate_file_for_read_handler_sync(
    [state](const MethodCall& call,
      const TemporaryFileTransfer::GenerateFileForReadInputArguments& in,
      MethodResultCallback<TemporaryFileTransfer::GenerateFileForReadOutputArguments>
        complete)
    {
      const auto& ctx = ::ua::detail::MethodCallAccess::shared_context(call);
      try
      {
        // Fire the host-pluggable onGenerateForRead hook with NO lock held: it may synchronously
        // re-enter a transfer method on this same helper, and state->mutex is non-recursive, so
        // firing it under the lock would self-deadlock (callback-safety golden rule). config is
        // immutable after construction, so reading the hook lock-free is safe; only `active` /
        // `nextHandle` (mutated in make_transient) require the lock.
        std::optional<std::filesystem::path> source;
        if (state->config.onGenerateForRead)
        {
          auto result = state->config.onGenerateForRead(in.generateOptions, ctx);
          // The helper creates the transfer from the path the hook names, so an Uncertain answer, with or
          // without a path, is refused with the hook's code as the cause; a Bad one is the Method's status.
          if (!result.is_good())
          {
            complete(::ua::detail::answer_failure(
              result.status_code(), "AnswerUncertain", "TemporaryFileTransferHelper"));
            return;
          }
          source = std::move(result).value();
        }

        // Without a hook the name is derived from the handle, so naming and allocating it have to be
        // one critical section - which is why make_transient_async builds the default path itself
        // rather than taking one from here.
        TemporaryFileTransferHelper::State::make_transient_async(state,
          /*isWrite=*/false,
          std::move(source),
          ctx ? ctx->sessionId : NodeId{},
          [complete = std::move(complete)](TemporaryFileTransferHelper::State::TransientResult result) mutable
          {
            if (!result.is_good())
            {
              complete(result.status_code());
              return;
            }
            TemporaryFileTransfer::GenerateFileForReadOutputArguments out;
            out.fileNodeId = result.value().fileNodeId;
            out.fileHandle = result.value().fileHandle;
            // CompletionStateMachine left null: synchronous transfer. Fired with no lock held.
            complete(out);
          });
      }
      catch (...)
      {
        complete(ua::exception_to_status_code(std::current_exception()));
      }
    });

  transfer.set_close_and_commit_handler_sync(
    [state](const MethodCall& call,
      const TemporaryFileTransfer::CloseAndCommitInputArguments& in,
      MethodResultCallback<TemporaryFileTransfer::CloseAndCommitOutputArguments>
        complete)
    {
      const auto& ctx = ::ua::detail::MethodCallAccess::shared_context(call);
      // Look up and detach the entry under the lock, then RELEASE the lock before firing the host
      // onCommit hook: onCommit is host-pluggable and may synchronously re-enter a transfer method on
      // this same helper, which would self-deadlock the non-recursive state->mutex (callback-safety
      // golden rule). config is immutable, so reading the hook lock-free below is safe.
      NodeId fileNodeId;
      std::filesystem::path entryPath;
      std::weak_ptr<FileHelper::State> fileState;
      bool isWrite = false;
      bool found = false;
      {
        const std::lock_guard lock{state->mutex};
        auto it = state->active.find(in.fileHandle);
        // Part 20 section 4.4.1: the transfer file "can only be accessed with the NodeId and FileHandle
        // returned by the Methods in the same Session". A handle belonging to another Session is
        // reported exactly as an unknown one, so the refusal reveals nothing about which transfers
        // are in flight for other clients.
        if (it != state->active.end() && !(it->second.sessionId == (ctx ? ctx->sessionId : NodeId{})))
        {
          it = state->active.end();
        }
        if (it != state->active.end())
        {
          auto detached = state->detach_active_locked(it);
          fileNodeId = detached.fileNodeId;
          entryPath = std::move(detached.path);
          fileState = std::move(detached.fileState);
          isWrite = detached.isWrite;
          found = true;
        }
      }

      if (!found)
      {
        complete(MethodResult<TemporaryFileTransfer::CloseAndCommitOutputArguments>{
          StatusCode{Status::BadInvalidArgument}});
        return;
      }

      // Close the transfer's own handle before the hook reads the file: the last Write may still be in
      // the stream's buffer, and fclose() is what writes it out. The stream is taken out of the table
      // and closed with no lock held; a close that fails means the file is incomplete, so it is the
      // Method's answer and the hook does not run over it.
      VoidResult commitResult;
      if (auto lockedFileState = fileState.lock())
      {
        std::optional<FileStream> stream;
        {
          const std::lock_guard lock{lockedFileState->mutex};
          if (auto handle = lockedFileState->handles.extract(in.fileHandle))
            stream.emplace(std::move(handle.mapped().stream));
        }
        if (stream)
        {
          try
          {
            stream->close();
          }
          catch (...)
          {
            commitResult = ua::exception_to_status_code(std::current_exception());
          }
        }
      }

      // onCommit fired with NO lock held.
      if (isWrite && state->config.onCommit && !commitResult.is_bad())
      {
        try
        {
          commitResult = state->config.onCommit(entryPath, ctx);
        }
        catch (...)
        {
          commitResult = StatusCode{Status::BadInternalError,
            ErrorDetail::build(
              "FileCommitHookThrew", "The file commit hook threw an exception", "TemporaryFileTransferHelper")
              .cause(ua::exception_to_status_code(std::current_exception()))};
        }
      }

      // The temp file is ours; remove it synchronously.
      std::error_code ec;
      std::filesystem::remove(entryPath, ec);

      // Method outcome: the commit hook's code is the Method's status. A Bad one surfaces without outputs;
      // any other keeps its code with the outputs (no CompletionStateMachine: the transfer is synchronous),
      // so a Good subcode reaches the Call service, which answers it as OPC 10000-4 5.11.2.4 asks, and an
      // Uncertain commit reaches the client as Uncertain.
      using CloseAndCommitResult = MethodResult<TemporaryFileTransfer::CloseAndCommitOutputArguments>;
      CloseAndCommitResult output = commitResult.is_bad()
                                      ? CloseAndCommitResult{commitResult.status_code()}
                                      : CloseAndCommitResult::with_status(commitResult.status_code(),
                                          TemporaryFileTransfer::CloseAndCommitOutputArguments{});

      // Defer the method response until the transient node is ACTUALLY removed. delete_node_async
      // runs on the address-space executor; completing before it finishes lets a caller that
      // re-reads the node right after CloseAndCommit returns still observe it mid-deletion - the
      // race that intermittently failed TempTransferTest on a loaded 32-bit shard. Completing inside
      // the deletion callback makes "CloseAndCommit returned" deterministically imply "the transient
      // node is gone", so a correctly-written test needs no polling (mirrors the
      // CreateSubscription<->diagnostics defer-until-ready pattern). The transient node is removed
      // regardless of commit outcome.
      if (auto as = state->addressSpace.lock())
        as->delete_node_async(fileNodeId,
          /*deleteForwardHierarchicallyReferencedNodes=*/true,
          ReferenceHalves::Both,
          [complete = std::move(complete), output = std::move(output)](VoidResult) mutable
          { complete(std::move(output)); });
      else
        complete(std::move(output));
    });
}

}  // namespace

TemporaryFileTransferHelper::TemporaryFileTransferHelper(
  TemporaryFileTransfer transfer, std::shared_ptr<State> state)
  : mTransfer(std::move(transfer)), mState(std::move(state))
{}

Result<uint32_t> TemporaryFileTransferHelper::open_transient_file_handle(
  FileHelper& file, uint8_t mode, const NodeId& sessionId, uint32_t requestedHandle)
{
  return file.try_open_handle(mode, sessionId, requestedHandle);
}

TemporaryFileTransferHelperResult TemporaryFileTransferHelper::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,
  TemporaryFileTransferConfig config) noexcept
{
  try
  {
    // DEF-7: an empty tempDir meant "the current directory" - wherever the process happened to be.
    // The directory is created owner-only: the transfer files hold what clients upload.
    if (config.tempDir.empty())
    {
      return TemporaryFileTransferHelperResult{StatusCode{Status::BadConfigurationError},
        make_error_detail("TemporaryFileTransferDirectoryUnset",
          "TemporaryFileTransferConfig::tempDir must name the directory for the transfer files",
          "TemporaryFileTransferHelper")};
    }
    std::error_code ec;
    // Owner-only for a directory this helper creates; a pre-existing directory is the operator's
    // choice and is left as it is (chmod-ing a shared directory such as /tmp would lock others out).
    security::create_directories_owner_only(config.tempDir, ec);

    auto transferResult = TemporaryFileTransfer::try_create_sync(addressSpace, parent, browseName, options);
    if (!transferResult.is_good())
      return transferResult.status_code();
    auto transferObject = std::move(transferResult).value();

    auto state = std::make_shared<State>(addressSpace, transferObject.node_id(), std::move(config));
    const auto weakState = std::weak_ptr<State>{state};
    // Part 20 section 4.4.1 ends a transfer file with the Session that generated it, so the helper
    // has to learn that a Session closed. The State is held weakly: it owns the subscription that
    // owns this handler, and a strong capture would be a cycle keeping every generated transfer
    // alive for the life of the address space.
    state->sessionCleanupRegistration = detail::AddressSpaceSessionEvents::add_handler(addressSpace,
      [weakState](const NodeId& sessionId)
      {
        if (auto lockedState = weakState.lock())
          lockedState->release_session(sessionId);
      });
    install_handlers(transferObject, state);
    return TemporaryFileTransferHelper{std::move(transferObject), std::move(state)};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

TemporaryFileTransferHelper TemporaryFileTransferHelper::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,
  TemporaryFileTransferConfig config)
{
  return ua::detail::good_value(
    try_create_sync(addressSpace, parent, browseName, options, std::move(config)));
}

const NodeId& TemporaryFileTransferHelper::node_id() const
{
  return mState->nodeId;
}

const TemporaryFileTransfer& TemporaryFileTransferHelper::transfer() const
{
  return mTransfer;
}

void TemporaryFileTransferHelper::release()
{
  mTransfer.release();
}

}  // namespace ua
