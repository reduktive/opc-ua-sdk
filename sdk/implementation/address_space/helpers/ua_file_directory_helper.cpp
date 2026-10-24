// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_route.h"
#include "ua_file_system_helpers.h"

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_file.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status_code.h"
#include "ua_string.h"
#include "ua_sync_wait.h"
#include "ua_to_string.h"
#include "ua_to_result.h"

#include <cerrno>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <atomic>
#include <optional>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace
{

/// A FileName / DirectoryName argument names one child of the directory: a single path component.
/// Separators, parent references, a root or an empty name would resolve outside the directory.
bool is_single_path_component(const std::string& name)
{
  if (name.empty() || name == "." || name == "..")
  {
    return false;
  }
  if (name.find_first_of("/\\") != std::string::npos || name.find('\0') != std::string::npos)
  {
    return false;
  }
#ifdef _WIN32
  // Win32 name rules: a drive or stream separator, the characters the API refuses, a control
  // character, a trailing dot or space (stripped on creation, so the file would not match the
  // node's BrowseName) and the reserved device names (opened through the Win32 namespace).
  if (name.find_first_of(":<>\"|?*") != std::string::npos ||
      std::any_of(name.begin(), name.end(), [](unsigned char c) { return c < 0x20; }) || name.back() == '.' ||
      name.back() == ' ')
  {
    return false;
  }
  std::string stem = name.substr(0, name.find('.'));
  std::transform(stem.begin(), stem.end(), stem.begin(), [](unsigned char c) { return std::toupper(c); });
  static constexpr std::string_view reserved[]{"CON", "PRN", "AUX", "NUL"};
  if (std::find(std::begin(reserved), std::end(reserved), stem) != std::end(reserved) ||
      (stem.size() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && std::isdigit(stem[3])))
  {
    return false;
  }
#endif
  const std::filesystem::path asPath{name};
  return !asPath.has_root_path() && asPath.filename() == asPath;
}

/// Creates the file at @p path exclusively: the existence check and the creation are one atomic
/// operation, so a pre-existing file, directory or symbolic link (dangling or not) is never adopted
/// or followed, and no local process can slip a link in between. Returns the errno of the failed
/// create, 0 on success.
int create_file_exclusively(const std::filesystem::path& path)
{
  // C11 "x": O_CREAT | O_EXCL on POSIX (fails with EEXIST on any existing path, including a
  // dangling symlink); the UCRT supports it too. The native path is used as-is: on Windows a
  // narrowed path would break names outside the active code page.
#ifdef _WIN32
  std::FILE* file = nullptr;
  const errno_t error = _wfopen_s(&file, path.c_str(), L"wbx");
  if (error != 0 || !file)
  {
    return error != 0 ? error : EINVAL;
  }
#else
  std::FILE* file = std::fopen(path.c_str(), "wbx");
  if (!file)
  {
    return errno;
  }
#endif
  std::fclose(file);
  return 0;
}

/// Removes a file this handler created but could not register as a node; best effort, because the
/// create has already failed and the original status is the one reported. Without this the name
/// stays occupied on disk with no node able to delete it, and every retry is refused as a duplicate.
void discard_created_file(const std::filesystem::path& path) noexcept
{
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}

/// A path rendered for an ErrorDetail context without a conversion that can throw (a narrowing
/// `string()` throws on Windows for names outside the active code page).
std::string path_for_detail(const std::filesystem::path& path)
{
#ifdef _WIN32
  const auto utf8 = path.u8string();
  return std::string{utf8.begin(), utf8.end()};
#else
  return path.native();
#endif
}

}  // namespace

namespace ua
{

struct FileDirectoryHelper::State
{
  State(AddressSpace as, NodeId id, std::filesystem::path path, bool w, uint16_t ns)
    : addressSpace(as.weak()), nodeId(std::move(id)), dirPath(std::move(path)), writable(w),
      namespaceIndex(ns)
  {}

  // Weak, NOT strong: this State is captured by the CreateDirectory/CreateFile/Delete
  // method handlers stored on the FileDirectory's method nodes inside the address space.
  // A strong AddressSpace here closes a reference cycle (AddressSpace -> method node ->
  // handler -> State -> AddressSpace) that leaks the entire node graph when the server is
  // destroyed. Handlers run only while the server is alive, so lock() succeeds at use.
  WeakAddressSpace addressSpace;
  NodeId nodeId;
  std::filesystem::path dirPath;
  bool writable{true};
  uint16_t namespaceIndex{0};

  std::mutex mutex;

  struct Child
  {
    std::filesystem::path path;
    bool isDirectory{false};

    /// The child's own state, weakly. OPC 10000-20 section 4.3.5 refuses a delete while anything under the
    /// object holds an open handle, and that fact lives in the child's handle table -- the directory
    /// keeps metadata only, so without this it has no way to ask. Weak because the child's state is
    /// held by the method handlers on its own nodes, and a strong reference here closes the cycle
    /// this helper releases its child accessors to avoid.
    std::weak_ptr<FileHelper::State> fileState;
    std::weak_ptr<FileDirectoryHelper::State> directoryState;
  };

  /// Whether this directory, or anything beneath it, holds an open file handle.
  ///
  /// Walked before anything is removed. A lock check on the handed-in node alone lets a directory
  /// lose its siblings before the walk reaches the locked file, leaving a half-deleted tree and an
  /// error naming none of it -- which is the failure section 4.3.5's whole-subtree wording exists to prevent.
  bool subtree_has_open_handle()
  {
    const std::lock_guard lock{mutex};
    for (const auto& [id, child] : children)
    {
      if (auto file = child.fileState.lock())
      {
        const std::lock_guard fileLock{file->mutex};
        if (!file->handles.empty())
          return true;
      }
      if (auto dir = child.directoryState.lock())
      {
        if (dir->subtree_has_open_handle())
          return true;
      }
    }
    return false;
  }

  /// Whether the single child @p id -- or, for a directory, anything beneath it -- is locked.
  bool child_has_open_handle(const NodeId& id)
  {
    std::weak_ptr<FileHelper::State> file;
    std::weak_ptr<FileDirectoryHelper::State> dir;
    {
      const std::lock_guard lock{mutex};
      auto it = children.find(id);
      if (it == children.end())
        return false;
      file = it->second.fileState;
      dir = it->second.directoryState;
    }
    if (auto locked = file.lock())
    {
      const std::lock_guard fileLock{locked->mutex};
      if (!locked->handles.empty())
        return true;
    }
    if (auto locked = dir.lock())
      return locked->subtree_has_open_handle();
    return false;
  }

  std::map<NodeId, Child> children;  // child node id -> on-disk backing
};

namespace
{

InstantiationOptions child_options(const FileDirectoryHelper::State& state)
{
  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::Organizes};
  options.nodeIdAllocator = {};  // auto-assign child node ids
  options.targetNamespaceIndex = state.namespaceIndex;
  return options;
}

/// Counts the four handler registrations down to one answer.
///
/// They are independent, so they are issued together rather than chained; the last one to land
/// reports. A failure is remembered rather than raced - whichever it was, the caller is told the
/// directory is not fully wired.
struct HandlerInstallTally
{
  std::atomic<int> remaining{4};
  std::atomic<bool> failed{false};
  std::function<void(VoidResult)> done;

  void one(const VoidResult& result)
  {
    if (result.is_bad())
    {
      failed.store(true, std::memory_order_relaxed);
    }
    if (remaining.fetch_sub(1, std::memory_order_acq_rel) == 1 && done)
    {
      done(failed.load(std::memory_order_relaxed)
             ? VoidResult{StatusCode{Status::BadInternalError,
                 ErrorDetail::build("FileDirectoryHandlerInstallFailed",
                   "One or more FileDirectoryType method handlers could not be installed",
                   "FileDirectoryHelper")}}
             : VoidResult{});
    }
  }
};

/// Installs the four FileDirectoryType method handlers and reports when all four are in.
///
/// The `*_async` setters, not the `*_sync` ones: a sync setter blocks waiting on the address
/// space's executor, which a thread OF that executor cannot do. Creation reaches here on both an
/// external thread (try_create_sync) and one of the executor's own (create_async's completion), and
/// only the async setters are usable on both.
void install_handlers_async(const FileDirectory& directory, std::shared_ptr<FileDirectoryHelper::State> state,
  std::function<void(VoidResult)> done)
{
  auto tally = std::make_shared<HandlerInstallTally>();
  tally->done = std::move(done);
  const auto installed = [tally](VoidResult result)
  {
    tally->one(result);
  };

  directory.set_create_directory_handler_async(
    [state](const MethodCall& /*call*/,
      const FileDirectory::CreateDirectoryInputArguments& in,
      MethodResultCallback<FileDirectory::CreateDirectoryOutputArguments>
        complete)
    {
      // Everything the create needs is gathered UNDER the lock, and the lock is released before the
      // call - the same shape the CreateFile handler below already uses, and for the same reason.
      // The shape this replaces held `state->mutex` across a blocking
      // `FileDirectoryHelper::try_create_sync`, on a server pool thread, waiting on work queued to
      // that same pool. The handler already takes a completion sink, so it was never obliged to
      // answer inline.
      // Copied out of `in` before the async hop: the arguments are a reference the caller owns and
      // does not keep alive past this handler returning.
      std::filesystem::path childPath;
      QualifiedName childName;
      InstantiationOptions options;
      NodeId parentId;
      bool writable = false;
      std::optional<AddressSpace> addressSpace;
      {
        const std::lock_guard lock{state->mutex};
        if (!state->writable)
        {
          complete(StatusCode{Status::BadUserAccessDenied});
          return;
        }
        try
        {
          const std::string name{static_cast<std::string_view>(in.directoryName)};
          if (!is_single_path_component(name))
          {
            complete(StatusCode{Status::BadBrowseNameInvalid});
            return;
          }

          childPath = state->dirPath / name;
          const auto duplicateStatus = [&]
          {
            return StatusCode{Status::BadBrowseNameDuplicated,
              ErrorDetail::build("FileDirectoryNameDuplicated",
                "Directory name already exists under this file directory",
                "FileDirectoryHelper")
                .context(ContextKeys::nodeBrowseName, QualifiedName{state->namespaceIndex, name})
                .context(ContextKeys::directory, childPath.string())};
          };

          std::error_code error;
          const bool alreadyExists = std::filesystem::exists(childPath, error);
          if (error)
          {
            complete(StatusCode{Status::BadUserAccessDenied});
            return;
          }
          if (alreadyExists)
          {
            complete(duplicateStatus());
            return;
          }

          const bool created = std::filesystem::create_directory(childPath, error);
          if (error)
          {
            complete(StatusCode{Status::BadUserAccessDenied});
            return;
          }
          if (!created)
          {
            complete(duplicateStatus());
            return;
          }

          addressSpace = state->addressSpace.lock();
          if (!addressSpace)
          {
            complete(StatusCode{Status::BadInvalidState});
            return;
          }
          childName = QualifiedName{state->namespaceIndex, name};
          options = child_options(*state);
          parentId = state->nodeId;
          writable = state->writable;
        }
        catch (...)
        {
          complete(ua::exception_to_status_code(std::current_exception()));
          return;
        }
      }

      FileDirectoryHelper::create_async(*addressSpace,
        parentId,
        childName,
        childPath,
        options,
        writable,
        [state, childPath, complete = std::move(complete)](FileDirectoryHelperResult childResult) mutable
        {
          try
          {
            if (!childResult.is_good())
            {
              complete(childResult.status_code());
              return;
            }
            auto child = std::move(childResult).value();
            const auto childId = child.node_id();
            auto childState = child.shared_state();
            child.release();

            FileDirectory::CreateDirectoryOutputArguments output;
            output.directoryNodeId = childId;
            {
              // Retaken only to record the child - the create itself ran without it held.
              const std::lock_guard lock{state->mutex};
              state->children.emplace(
                childId, FileDirectoryHelper::State::Child{childPath, true, {}, childState});
            }
            complete(std::move(output));
          }
          catch (...)
          {
            complete(ua::exception_to_status_code(std::current_exception()));
          }
        });
    },
    installed);

  directory.set_create_file_handler_async(
    [state](const MethodCall& call,
      const FileDirectory::CreateFileInputArguments& in,
      MethodResultCallback<FileDirectory::CreateFileOutputArguments>
        complete)
    {
      const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
      // Everything the create needs is gathered UNDER the lock, and the lock is released before the
      // call. The shape this replaces held `state->mutex` across a blocking
      // `FileHelper::try_create_sync` - on a server pool thread, waiting on work queued to that same
      // pool. On a multi-threaded pool that merely occupied a thread for a round trip; on a
      // single-threaded one, which this repo uses in several fixtures, it is a deadlock with a lock
      // held. The handler already takes a completion sink, so it was never obliged to answer inline.
      // Copied out of `in` before the async hop: the arguments are a reference the caller owns and
      // does not keep alive past this handler returning.
      const bool requestFileOpen = in.requestFileOpen;
      std::filesystem::path childPath;
      QualifiedName childName;
      InstantiationOptions options;
      NodeId parentId;
      bool writable = false;
      std::optional<AddressSpace> addressSpace;
      {
        const std::lock_guard lock{state->mutex};
        if (!state->writable)
        {
          complete(StatusCode{Status::BadUserAccessDenied});
          return;
        }
        bool created = false;
        try
        {
          const std::string name{static_cast<std::string_view>(in.fileName)};
          if (!is_single_path_component(name))
          {
            complete(StatusCode{Status::BadBrowseNameInvalid});
            return;
          }
          childPath = state->dirPath / name;
          {
            // Part 20 section 4.3.4: a file with the name already exists -> Bad_BrowseNameDuplicated.
            // Creating means creating, never adopting an existing file (or following a link planted
            // under the directory); the check and the create are one exclusive operation.
            const int createError = create_file_exclusively(childPath);
            if (createError == EEXIST)
            {
              complete(StatusCode{Status::BadBrowseNameDuplicated,
                ErrorDetail::build("FileNameDuplicated",
                  "File name already exists under this file directory",
                  "FileDirectoryHelper")
                  .context(ContextKeys::nodeBrowseName, QualifiedName{state->namespaceIndex, name})
                  .context(ContextKeys::directory, path_for_detail(childPath))});
              return;
            }
            if (createError != 0)
            {
              complete(StatusCode{Status::BadUserAccessDenied,
                ErrorDetail::build("FileCreateFailed",
                  "Could not create the file under this file directory",
                  "FileDirectoryHelper")
                  .context(ContextKeys::nodeBrowseName, QualifiedName{state->namespaceIndex, name})
                  .context(ContextKeys::directory, path_for_detail(childPath))
                  .context(ContextKeys::errorMessage, std::generic_category().message(createError))});
              return;
            }
            created = true;
          }
          addressSpace = state->addressSpace.lock();
          if (!addressSpace)
          {
            discard_created_file(childPath);
            complete(StatusCode{Status::BadInvalidState});
            return;
          }
          childName = QualifiedName{state->namespaceIndex, name};
          options = child_options(*state);
          parentId = state->nodeId;
          writable = state->writable;
        }
        catch (...)
        {
          if (created)
          {
            discard_created_file(childPath);
          }
          complete(ua::exception_to_status_code(std::current_exception()));
          return;
        }
      }

      FileHelper::create_async(*addressSpace,
        parentId,
        childName,
        childPath,
        options,
        writable,
        [state, childPath, context, requestFileOpen, complete = std::move(complete)](
          FileHelperResult childResult) mutable
        {
          try
          {
            if (!childResult.is_good())
            {
              // A FileHelper result that is not Good leaves no node: a Bad one registered none (the helper
              // rolls back a node whose handlers could not be installed), and the owning helper an Uncertain
              // one holds removes its node as it is destroyed here. Remove the file so the name is not
              // occupied for ever.
              discard_created_file(childPath);
              complete(childResult.status_code());
              return;
            }
            auto child = std::move(childResult).value();
            const auto childId = child.node_id();

            // OPC 10000-20 section 4.3.4: RequestFileOpen means the Method returns the file already
            // open, and the fileHandle it returns has to be one the new file's own Read and Write
            // will accept. Returning 0 unconditionally handed back a handle the file rejects, so the
            // TRUE branch opened nothing at all. The handle is taken before `release`, out of the
            // same table the file's Open Method issues from, and it survives the accessor because
            // the installed method handlers hold that state.
            uint32_t fileHandle = 0;
            if (requestFileOpen)
            {
              // Write | Read: a caller asking for the file it has just created to be open wants to
              // put something in it, and EraseExisting is meaningless on a file created empty.
              auto opened = child.try_open_handle(uint8_t{0x03}, context ? context->sessionId : NodeId{});
              if (!opened.is_good())
              {
                auto failedState = child.shared_state();
                child.release();
                const std::lock_guard lock{state->mutex};
                state->children.emplace(
                  childId, FileDirectoryHelper::State::Child{childPath, false, failedState, {}});
                complete(opened.status_code());
                return;
              }
              fileHandle = opened.value();
            }

            auto childState = child.shared_state();
            child.release();
            {
              const std::lock_guard lock{state->mutex};
              state->children.emplace(
                childId, FileDirectoryHelper::State::Child{childPath, false, childState, {}});
            }
            FileDirectory::CreateFileOutputArguments out;
            out.fileNodeId = childId;
            out.fileHandle = fileHandle;
            complete(out);
          }
          catch (...)
          {
            complete(ua::exception_to_status_code(std::current_exception()));
          }
        });
    },
    installed);

  directory.set_delete_file_system_object_handler_async(
    [state](const MethodCall& /*call*/,
      const FileDirectory::DeleteFileSystemObjectInputArguments& in,
      MethodResultCallback<>
        complete)
    {
      if (!state->writable)
      {
        complete(VoidResult{StatusCode{Status::BadUserAccessDenied}});
        return;
      }

      // OPC 10000-20 section 4.3.5: a locked object is refused with Bad_InvalidState, and "locked" means
      // any node *under* it holds an open handle, not just the node named. Asked before anything is
      // removed and outside the state lock, because the walk takes that lock itself: a check made
      // part-way through the removal leaves a half-deleted tree and an error naming none of it.
      if (state->child_has_open_handle(in.objectToDelete))
      {
        complete(VoidResult{StatusCode{Status::BadInvalidState}});
        return;
      }

      const std::lock_guard lock{state->mutex};
      try
      {
        auto it = state->children.find(in.objectToDelete);
        if (it == state->children.end())
        {
          complete(VoidResult{StatusCode{Status::BadNodeIdUnknown}});
          return;
        }
        std::error_code ec;
        std::filesystem::remove_all(it->second.path, ec);  // file or directory (recursive)
        state->children.erase(it);
        // Complete only once the node delete actually finishes, so a client never
        // sees Good while the file node is still browsable (the server address
        // space deletes asynchronously). The callback body is trivial: the
        // surrounding try/catch does not cover it (it may run on a worker thread).
        if (auto as = state->addressSpace.lock())
          as->delete_node_async(in.objectToDelete,
            /*deleteForwardHierarchicallyReferencedNodes=*/true,
            ReferenceHalves::Both,
            [complete = std::move(complete)](VoidResult deleteResult) mutable
            { complete(std::move(deleteResult)); });
        else
          complete(VoidResult{});
      }
      catch (...)
      {
        complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
      }
    },
    installed);

  // MoveOrCopy needs cross-directory coordination (resolving the target directory's helper); deferred.
  directory.set_move_or_copy_handler_async(
    [](const MethodCall& /*call*/,
      const FileDirectory::MoveOrCopyInputArguments&,
      MethodResultCallback<FileDirectory::MoveOrCopyOutputArguments>
        complete) {
      complete(MethodResult<FileDirectory::MoveOrCopyOutputArguments>{StatusCode{Status::BadNotSupported}});
    },
    installed);
}

}  // namespace

FileDirectoryHelper::FileDirectoryHelper(FileDirectory directory, std::shared_ptr<State> state)
  : mDirectory(std::move(directory)), mState(std::move(state))
{}

void FileDirectoryHelper::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, std::filesystem::path dirPath, const InstantiationOptions& options,
  bool writable, CreateCompleteCallback complete) noexcept
{
  try
  {
    std::error_code ec;
    std::filesystem::create_directories(dirPath, ec);

    // The completion holds the address space weakly (CALLS-21 rule 1).
    FileDirectory::create_async(addressSpace,
      parent,
      browseName,
      options,
      [handle = addressSpace.weak(), dirPath = std::move(dirPath), writable, complete = std::move(complete)](
        FileDirectoryResult dirResult) mutable
      {
        try
        {
          if (!dirResult.is_good())
          {
            complete(dirResult.status_code());
            return;
          }
          auto fileDirectory = std::move(dirResult).value();
          auto owner = handle.lock();
          if (!owner)
          {
            complete(::ua::detail::address_space_gone("FileDirectoryHelper"));
            return;
          }

          auto state = std::make_shared<State>(*owner,
            fileDirectory.node_id(),
            std::move(dirPath),
            writable,
            fileDirectory.node_id().namespace_index());

          // Answered from the install completion, not before it: a helper handed back with its
          // method handlers still landing would accept a CreateDirectory call it cannot serve.
          // FileDirectory is move-only, and the reference install_handlers_async registers through
          // has to stay valid while the completion below still owns the handle. Parking it in a
          // shared_ptr gives both, without depending on the order this call's arguments evaluate in.
          auto directory = std::make_shared<FileDirectory>(std::move(fileDirectory));
          install_handlers_async(*directory,
            state,
            [directory, state, complete = std::move(complete)](VoidResult installed) mutable
            {
              if (installed.is_bad())
              {
                complete(installed.status_code());
                return;
              }
              complete(FileDirectoryHelper{std::move(*directory), std::move(state)});
            });
        }
        catch (...)
        {
          complete(ua::exception_to_status_code(std::current_exception()));
        }
      });
  }
  catch (...)
  {
    // Declared noexcept: the error surface of an *_async function is its callback.
    detail::invoke_user_callback(
      complete, FileDirectoryHelperResult{ua::exception_to_status_code(std::current_exception())});
  }
}

FileDirectoryHelperResult FileDirectoryHelper::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, std::filesystem::path dirPath,
  const InstantiationOptions& options, bool writable) noexcept
{
  try
  {
    std::error_code ec;
    std::filesystem::create_directories(dirPath, ec);

    auto dirResult = FileDirectory::try_create_sync(addressSpace, parent, browseName, options);
    if (!dirResult.is_good())
      return dirResult.status_code();
    auto fileDirectory = std::move(dirResult).value();

    auto state = std::make_shared<State>(addressSpace,
      fileDirectory.node_id(),
      std::move(dirPath),
      writable,
      fileDirectory.node_id().namespace_index());

    auto installResult = ua::async::detail::blocking_call<VoidResult>(addressSpace.executor(),
      [&](std::function<void(VoidResult)> complete)
      { install_handlers_async(fileDirectory, state, std::move(complete)); });
    if (installResult.is_bad())
      return installResult.status_code();

    return FileDirectoryHelper{std::move(fileDirectory), std::move(state)};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

FileDirectoryHelper FileDirectoryHelper::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, std::filesystem::path dirPath, const InstantiationOptions& options,
  bool writable)
{
  return ua::detail::good_value(
    try_create_sync(addressSpace, parent, browseName, std::move(dirPath), options, writable));
}

FileDirectoryHelperResult FileDirectoryHelper::try_attach_sync(AddressSpace addressSpace,
  const NodeId& existingInstance, std::filesystem::path dirPath, bool writable) noexcept
{
  try
  {
    auto dirResult = FileDirectory::try_attach_sync(addressSpace, existingInstance);
    if (!dirResult.is_good())
      return dirResult.status_code();
    auto fileDirectory = std::move(dirResult).value();

    auto state = std::make_shared<State>(addressSpace,
      fileDirectory.node_id(),
      std::move(dirPath),
      writable,
      fileDirectory.node_id().namespace_index());

    auto installResult = ua::async::detail::blocking_call<VoidResult>(addressSpace.executor(),
      [&](std::function<void(VoidResult)> complete)
      { install_handlers_async(fileDirectory, state, std::move(complete)); });
    if (installResult.is_bad())
      return installResult.status_code();

    return FileDirectoryHelper{std::move(fileDirectory), std::move(state)};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

const NodeId& FileDirectoryHelper::node_id() const
{
  return mState->nodeId;
}

const FileDirectory& FileDirectoryHelper::directory() const
{
  return mDirectory;
}

void FileDirectoryHelper::release()
{
  mDirectory.release();
}

}  // namespace ua
