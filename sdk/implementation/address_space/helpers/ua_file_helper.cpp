// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_route.h"
#include "ua_whole_value_source.h"
#include "ua_sync_wait.h"
#include "ua_file_system_helpers.h"
#include "ua_file_helper_test_access.h"

#include "ua_address_space_session_events.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_file_handle_budget.h"
#include "ua_instance_utils.h"
#include "ua_method_call_authorization_internal.h"
#include "ua_node.h"
#include "ua_open_file_mode_bits.h"
#include "ua_self_owning_operation.h"
#include "ua_to_result.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <future>
#include <mutex>
#include <optional>
#include <utility>

namespace ua::detail::file_helper_tests
{

namespace
{

std::mutex& fault_mutex()
{
  static std::mutex mutex;
  return mutex;
}

std::optional<StatusCode>& fault_slot()
{
  static std::optional<StatusCode> slot;
  return slot;
}

}  // namespace

void set_handler_install_fault_for_tests(std::optional<StatusCode> fault)
{
  const std::lock_guard<std::mutex> lock{fault_mutex()};
  fault_slot() = std::move(fault);
}

std::optional<StatusCode> take_handler_install_fault_for_tests()
{
  const std::lock_guard<std::mutex> lock{fault_mutex()};
  return std::exchange(fault_slot(), std::nullopt);
}

}  // namespace ua::detail::file_helper_tests

namespace ua
{

namespace
{

// Subscribe @p state to Session closure on @p addressSpace, so handles opened by a Session that
// has ended are released with it (OPC 10000-20 section 4.2.2).
//
// The handler holds the State weakly: the State owns the subscription that owns the handler, and a
// strong capture would be a cycle that keeps every file's open streams alive for the life of the
// address space.
void subscribe_to_session_close(const std::shared_ptr<FileHelper::State>& state, AddressSpace& addressSpace)
{
  state->sessionClosedSubscription = detail::AddressSpaceSessionEvents::add_handler(addressSpace,
    [weak = std::weak_ptr<FileHelper::State>{state}](const NodeId& sessionId)
    {
      auto s = weak.lock();
      if (!s)
        return;

      // A null sessionId belongs to the direct/internal caller space, which no Session closure can
      // reach; refusing it here keeps an internally opened handle from being swept away by an
      // unrelated Client disconnecting.
      if (sessionId == NodeId{})
        return;

      const std::lock_guard lock{s->mutex};
      std::erase_if(
        s->handles, [&sessionId](const auto& entry) { return entry.second.sessionId == sessionId; });
    });
}

// OPC 10000-20 section 4.2.2 defines bits 0-3, reserves bits 4-7 as zero, and permits
// EraseExisting only when Write is set. Append is independent of Write.
StatusCode validate_file_open_mode(uint8_t mode, const std::filesystem::path& filePath)
{
  const bool read = detail::has_file_mode(mode, OpenFileMode::Read);
  const bool write = detail::has_file_mode(mode, OpenFileMode::Write);
  const bool eraseExisting = detail::has_file_mode(mode, OpenFileMode::EraseExisting);
  const bool reservedBitSet = (mode & detail::reservedFileModeBits) != 0;
  if ((!read && !write) || (eraseExisting && !write) || reservedBitSet)
  {
    return StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidFileOpenMode", "File open mode setting is invalid", "FileHelper")
        .context(ua::ContextKeys::filePath, filePath.string())
        .context(ua::ContextKeys::value, mode)};
  }
  return StatusCode{Status::Good};
}

/// A slot in the address space's FileType handle budget for one handle @p sessionId opens, taken before
/// the file is opened and kept in the handle's entry. Bad_TooManyOperations when the Session or the server
/// already holds the most handles it may have open; Bad_Shutdown when the address space has gone.
Result<std::shared_ptr<const void>> acquire_handle_slot(
  const FileHelper::State& state, const NodeId& sessionId)
{
  const auto addressSpace = state.addressSpace.lock();
  if (!addressSpace)
    return detail::address_space_gone("FileHelper");
  return detail::AddressSpaceFileHandles::budget(*addressSpace)->acquire(sessionId);
}

Result<uint32_t> open_handle(
  FileHelper::State& state, uint8_t mode, const NodeId& sessionId, std::optional<uint32_t> requestedHandle)
{
  const StatusCode modeStatus = validate_file_open_mode(mode, state.filePath);
  if (modeStatus.is_bad())
    return modeStatus;

  const bool read = detail::has_file_mode(mode, OpenFileMode::Read);
  const bool write = detail::has_file_mode(mode, OpenFileMode::Write);
  const bool eraseExisting = detail::has_file_mode(mode, OpenFileMode::EraseExisting);
  const bool append = detail::has_file_mode(mode, OpenFileMode::Append);
  if (write && !state.writable)
    return StatusCode{Status::BadNotWritable};

  {
    const std::lock_guard lock{state.mutex};
    if (write && !state.handles.empty())
      return StatusCode{Status::BadNotWritable};
    if (read && !write)
    {
      const bool writerOpen = std::any_of(state.handles.begin(),
        state.handles.end(),
        [](const auto& entry) { return detail::has_file_mode(entry.second.mode, OpenFileMode::Write); });
      if (writerOpen)
        return StatusCode{Status::BadNotReadable};
    }
    if (requestedHandle && (*requestedHandle == 0 || state.handles.contains(*requestedHandle)))
    {
      return StatusCode{Status::BadInvalidArgument,
        ErrorDetail::build("FileHandleAlreadyAllocated",
          "The requested FileType handle is zero or already allocated",
          "FileHelper")
          .context(ContextKeys::filePath, state.filePath.string())
          .context(ContextKeys::value, requestedHandle.value_or(0))};
    }
  }

  auto slot = acquire_handle_slot(state, sessionId);
  if (!slot.has_value())
    return slot.status_code();

  FileStream stream{state.filePath};
  const StatusCode opened = write ? stream.open_for_write(eraseExisting, append) : stream.open_for_read();
  if (opened.is_bad())
    return opened;

  const std::lock_guard lock{state.mutex};
  const uint32_t handle = requestedHandle.value_or(state.nextHandle);
  if (requestedHandle)
    state.nextHandle = std::max(state.nextHandle, handle + 1);
  else
    ++state.nextHandle;
  const bool inserted =
    state.handles
      .emplace(
        handle, FileHelper::State::OpenHandle{sessionId, std::move(stream), mode, std::move(slot).value()})
      .second;
  if (!inserted)
  {
    return StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("FileHandleAllocationRace",
        "The FileType handle became allocated before the open completed",
        "FileHelper")
        .context(ContextKeys::filePath, state.filePath.string())
        .context(ContextKeys::value, handle)};
  }
  return handle;
}

}  // namespace

FileHelper::FileHelper(File file, std::shared_ptr<State> state)
  : mFile(std::move(file)), mState(std::move(state))
{}

const NodeId& FileHelper::node_id() const
{
  return mFile.node_id();
}

Result<uint32_t> FileHelper::try_open_handle(uint8_t mode, const NodeId& sessionId)
{
  return open_handle(*mState, mode, sessionId, std::nullopt);
}

Result<uint32_t> FileHelper::try_open_handle(uint8_t mode, const NodeId& sessionId, uint32_t requestedHandle)
{
  return open_handle(*mState, mode, sessionId, requestedHandle);
}

const File& FileHelper::file() const
{
  return mFile;
}

void FileHelper::release()
{
  mFile.release();
}

void FileHelper::on_all_handles_closed(std::function<void()> callback)
{
  if (!mState)
    return;
  const std::lock_guard lock{mState->mutex};
  mState->onAllHandlesClosed = std::move(callback);
}

namespace
{

// The Session a call belongs to, or a null NodeId for a direct or internal call carrying no session
// context. Both are legitimate callers; what matters below is only that a handle stays reachable by
// the one that opened it.
NodeId calling_session(const shared_ptr<const MethodCallContext>& context)
{
  return context ? context->sessionId : NodeId{};
}

// Resolve a FileType handle for the caller, or `end()` when no such handle exists OR it belongs to
// another Session.
//
// Part 20 section 4.2.1: the fileHandle "is generated by the server and is unique for the Session. Clients
// cannot transfer the fileHandle to another Session but need to get a new fileHandle by calling the
// Open Method." The handle id is an index, not authority.
//
// A handle held by another Session is reported exactly as an unknown one -- Bad_InvalidArgument, the
// code section 4.2.3 gives for "Invalid file handle in call". Distinguishing the two would answer the
// question "does handle N exist?" for handles the caller does not own, turning the monotonic
// allocator into an oracle for enumerating other Sessions' open files.
std::map<uint32_t, FileHelper::State::OpenHandle>::iterator find_handle_for(
  FileHelper::State& s, uint32_t handle, const shared_ptr<const MethodCallContext>& context)
{
  const auto it = s.handles.find(handle);
  if (it != s.handles.end() && !(it->second.sessionId == calling_session(context)))
  {
    return s.handles.end();
  }
  return it;
}

// Build the open-method handler that consults the FileHelper::State.
File::OpenAsyncHandler make_open_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](const MethodCall& call,
           const File::OpenInputArguments& in,
           MethodResultCallback<File::OpenOutputArguments>
             complete)
  {
    const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
    const StatusCode modeStatus = validate_file_open_mode(in.mode, s->filePath);
    if (modeStatus.is_bad())
    {
      complete(modeStatus);
      return;
    }

    // OPC 10000-20 section 4.2.1's Server-wide MaxByteStringLength fallback is read here, once, rather than
    // when the handlers were installed: a FileType is routinely created while the server is still
    // being configured, and an address-space read issued then answers Bad_Shutdown. By the first Open
    // the server is necessarily running. A read that fails leaves the cap unset, which the Read
    // handler treats as unbounded -- the behaviour before the cap existed, not a refusal.
    bool needsCap = false;
    {
      const std::lock_guard lock{s->mutex};
      needsCap = !s->maxByteStringLengthResolved;
      s->maxByteStringLengthResolved = true;
    }
    if (needsCap && s->maxByteStringLength == 0)
    {
      if (auto addressSpace = s->addressSpace.lock())
      {
        instance_utils::read_variable_value_async(*addressSpace,
          NodeId{VariableId::Server_ServerCapabilities_MaxByteStringLength},
          [s, in, call, complete = std::move(complete)](DataValueResult r) mutable
          {
            if (r.is_good())
            {
              if (const auto* cap = r.value().value().try_as<uint32_t>(); cap != nullptr)
              {
                const std::lock_guard lock{s->mutex};
                s->maxByteStringLength = *cap;
              }
            }
            make_open_handler(s)(call, in, std::move(complete));
          });
        return;
      }
    }

    const uint8_t mode = in.mode;
    const bool read = detail::has_file_mode(mode, OpenFileMode::Read);
    const bool write = detail::has_file_mode(mode, OpenFileMode::Write);
    const bool eraseExisting = detail::has_file_mode(mode, OpenFileMode::EraseExisting);
    const bool append = detail::has_file_mode(mode, OpenFileMode::Append);

    if (write && !s->writable)
    {
      // value carries the raw OPC UA file open-mode bitmask; there is no dedicated
      // file-mode context key ([verify]: closest available key is value).
      complete(StatusCode{Status::BadNotWritable,
        ErrorDetail::build("FileNotWritable", "Write access requested on a non-writable file", "FileHelper")
          .context(ua::ContextKeys::filePath, s->filePath.string())
          .context(ua::ContextKeys::value, std::to_string(static_cast<unsigned>(mode)))});
      return;
    }

    if (write && context)
    {
      const auto authorization =
        ua::detail::MethodCallAuthorizationInternalAccess::authorize_object_write(*context);
      if (authorization.has_value() && authorization->is_bad())
      {
        auto detail = authorization->shared_detail();
        if (!detail)
        {
          detail = ErrorDetail::build(
            "FileWriteAccessDenied", "The calling user is not authorized to write this file", "FileHelper")
                     .context(ua::ContextKeys::filePath, s->filePath.string())
                     .context(ua::ContextKeys::value, std::to_string(static_cast<unsigned>(mode)));
        }
        complete(StatusCode{authorization->status_code().value(), std::move(detail)});
        return;
      }
    }

    std::optional<StatusCode> conflict;
    {
      // OPC 10000-20 section 4.2.1: writes are exclusive. A write Open is refused while ANY handle is open,
      // and a read Open is refused while a WRITER holds one -- but concurrent reads stay permitted,
      // which is what keeps the rule from degenerating into an exclusive lock. The status names the
      // operation that was requested rather than the one already held, which is the pair an
      // implementation inverts.
      const std::lock_guard lock{s->mutex};
      if (write && !s->handles.empty())
      {
        conflict = StatusCode{Status::BadNotWritable,
          ErrorDetail::build("FileWriteNotExclusive",
            "A write Open was requested while the file is already open",
            "FileHelper")
            .context(ua::ContextKeys::filePath, s->filePath.string())
            .context(ua::ContextKeys::countActual, std::to_string(s->handles.size()))};
      }
      if (read && !write)
      {
        const bool writerOpen = std::any_of(s->handles.begin(),
          s->handles.end(),
          [](const auto& entry) { return detail::has_file_mode(entry.second.mode, OpenFileMode::Write); });
        if (writerOpen)
        {
          conflict = StatusCode{Status::BadNotReadable,
            ErrorDetail::build("FileReadBlockedByWriter",
              "A read Open was requested while a writer holds a handle on the file",
              "FileHelper")
              .context(ua::ContextKeys::filePath, s->filePath.string())};
        }
      }
    }

    if (conflict)
    {
      complete(std::move(*conflict));
      return;
    }

    try
    {
      auto slot = acquire_handle_slot(*s, calling_session(context));
      if (!slot.has_value())
      {
        complete(slot.status_code());
        return;
      }

      FileStream stream{s->filePath};
      StatusCode stOpen;
      if (write)
      {
        stOpen = stream.open_for_write(eraseExisting, append);
      }
      else
      {
        stOpen = stream.open_for_read();
      }
      if (stOpen.is_bad())
      {
        complete(stOpen);
        return;
      }

      uint32_t handle = 0;
      {
        const std::lock_guard lock{s->mutex};
        handle = s->nextHandle++;
        // The opening Session is recorded with the stream: it is what every later call on this
        // handle is checked against, and the only place that fact is available.
        s->handles.emplace(handle,
          FileHelper::State::OpenHandle{
            calling_session(context), std::move(stream), mode, std::move(slot).value()});
      }
      complete(File::OpenOutputArguments{.fileHandle = handle});
    }
    catch (...)
    {
      complete(ua::exception_to_status_code(std::current_exception()));
    }
  };
}

File::CloseAsyncHandler make_close_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](
           const MethodCall& call, const File::CloseInputArguments& in, MethodResultCallback<> complete)
  {
    const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
    VoidResult result;
    std::function<void()> lastHandleClosed;
    {
      const std::lock_guard lock{s->mutex};
      auto it = find_handle_for(*s, in.fileHandle, context);
      if (it == s->handles.end())
      {
        result = StatusCode{Status::BadInvalidArgument};
      }
      else
      {
        s->handles.erase(it);
        if (s->handles.empty())
          lastHandleClosed = s->onAllHandlesClosed;
      }
    }
    // Fired with no lock held: the transfer helper's cleanup takes its own lock and touches the
    // address space (callback-safety rule).
    if (lastHandleClosed)
      lastHandleClosed();
    complete(std::move(result));
  };
}

File::ReadAsyncHandler make_read_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](const MethodCall& call,
           const File::ReadInputArguments& in,
           MethodResultCallback<File::ReadOutputArguments>
             complete)
  {
    const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
    Result<File::ReadOutputArguments> result = StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidFileHandle", "Read was called with an invalid file handle", "FileHelper")
        .context(ua::ContextKeys::filePath, s->filePath.string())
        .context(ua::ContextKeys::value, in.fileHandle)};
    {
      const std::lock_guard lock{s->mutex};
      auto it = find_handle_for(*s, in.fileHandle, context);
      if (it != s->handles.end() && in.length <= 0)
      {
        // OPC 10000-20 section 4.2.4 permits only positive Length values.
        result = StatusCode{Status::BadInvalidArgument,
          ErrorDetail::build("NonPositiveFileReadLength", "Read requires a positive length", "FileHelper")
            .context(ua::ContextKeys::filePath, s->filePath.string())
            .context(ua::ContextKeys::sizeActual, in.length)
            .context(ua::ContextKeys::sizeMin, int32_t{1})};
      }
      else if (it != s->handles.end() && !detail::has_file_mode(it->second.mode, OpenFileMode::Read))
      {
        // The handle exists and belongs to this Session, but it was not opened for reading.
        result = StatusCode{Status::BadInvalidState,
          ErrorDetail::build("FileHandleNotOpenedForRead",
            "Read was called on a handle whose open mode does not include Read",
            "FileHelper")
            .context(ua::ContextKeys::filePath, s->filePath.string())
            .context(ua::ContextKeys::value, std::to_string(static_cast<unsigned>(it->second.mode)))};
      }
      else if (it != s->handles.end())
      {
        try
        {
          // The client's positive Length is bounded before it is believed: unbounded, a single Read
          // can allocate 2 GB. The cap is the file's own MaxByteStringLength where it declares one
          // and the Server's advertised capability otherwise; shortening rather than refusing is
          // the accommodating half of what OPC 10000-20 section 4.2.1 permits.
          auto length = numeric_cast<size_t>(in.length);
          if (s->maxByteStringLength != 0)
            length = std::min(length, static_cast<size_t>(s->maxByteStringLength));
          ByteString buf(length, uint8_t{0});
          const size_t bytesRead = it->second.stream.read(buf);
          buf.resize(bytesRead);
          result = File::ReadOutputArguments{.data = std::move(buf)};
        }
        catch (...)
        {
          result = ua::exception_to_status_code(std::current_exception());
        }
      }
    }
    complete(std::move(result));
  };
}

File::WriteAsyncHandler make_write_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](
           const MethodCall& call, const File::WriteInputArguments& in, MethodResultCallback<> complete)
  {
    const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
    VoidResult result;
    {
      const std::lock_guard lock{s->mutex};
      auto it = find_handle_for(*s, in.fileHandle, context);
      if (it == s->handles.end())
      {
        result = StatusCode{Status::BadInvalidArgument};
      }
      else if (!detail::has_file_mode(it->second.mode, OpenFileMode::Write))
      {
        result = StatusCode{Status::BadInvalidState,
          ErrorDetail::build("FileHandleNotOpenedForWrite",
            "Write was called on a handle whose open mode does not include Write",
            "FileHelper")
            .context(ua::ContextKeys::filePath, s->filePath.string())
            .context(ua::ContextKeys::value, std::to_string(static_cast<unsigned>(it->second.mode)))};
      }
      else if (in.data.empty())
      {
        // OPC 10000-20 section 4.2.5: an empty or null ByteString is a Good no-op. The valid-handle
        // and Write-mode checks stay ahead of this branch so an empty payload cannot turn an invalid
        // or read-only handle into a successful operation.
      }
      else if (s->maxFileSize &&
               static_cast<uint64_t>(it->second.stream.get_position()) + in.data.size() > *s->maxFileSize)
      {
        // DEF-7: the file has a configured size ceiling (an upload quota); a Write that would grow it
        // past the ceiling is refused whole, nothing is written. Part 20 names no code for "file
        // full": Bad_OutOfRange names the position + length that does not fit.
        result = StatusCode{Status::BadOutOfRange,
          ErrorDetail::build("FileSizeLimitExceeded",
            "The Write would grow the file past its configured maximum size",
            "FileHelper")
            .context(ua::ContextKeys::filePath, s->filePath.string())
            .context(ua::ContextKeys::sizeMax, std::to_string(*s->maxFileSize))
            .context(ua::ContextKeys::sizeActual,
              std::to_string(static_cast<uint64_t>(it->second.stream.get_position()) + in.data.size()))};
      }
      else
      {
        try
        {
          it->second.stream.write_all(span<const byte>{in.data});
        }
        catch (...)
        {
          const StatusCode cause = ua::exception_to_status_code(std::current_exception());
          try
          {
            result = StatusCode{Status::BadNotWritable,
              ErrorDetail::build(
                "FileBackingStoreNotWritable", "The backing store refused a FileType Write", "FileHelper")
                .context(ua::ContextKeys::filePath, s->filePath.string())
                .cause(cause)};
          }
          catch (...)
          {
            result = ua::exception_to_status_code(std::current_exception());
          }
        }
      }
    }
    complete(std::move(result));
  };
}

File::GetPositionAsyncHandler make_get_position_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](const MethodCall& call,
           const File::GetPositionInputArguments& in,
           MethodResultCallback<File::GetPositionOutputArguments>
             complete)
  {
    const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
    Result<File::GetPositionOutputArguments> result = StatusCode{Status::BadInvalidArgument};
    {
      const std::lock_guard lock{s->mutex};
      auto it = find_handle_for(*s, in.fileHandle, context);
      if (it != s->handles.end())
      {
        try
        {
          const auto pos = it->second.stream.get_position();
          result = File::GetPositionOutputArguments{.position = numeric_cast<uint64_t>(pos)};
        }
        catch (...)
        {
          result = ua::exception_to_status_code(std::current_exception());
        }
      }
    }
    complete(std::move(result));
  };
}

File::SetPositionAsyncHandler make_set_position_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](
           const MethodCall& call, const File::SetPositionInputArguments& in, MethodResultCallback<> complete)
  {
    const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
    VoidResult result;
    {
      const std::lock_guard lock{s->mutex};
      auto it = find_handle_for(*s, in.fileHandle, context);
      if (it == s->handles.end())
      {
        result = StatusCode{Status::BadInvalidArgument};
      }
      else
      {
        try
        {
          // Compare in the request's UInt64 domain before narrowing. On 32-bit builds a large legal
          // UInt64 must clamp to the file length, not throw from numeric_cast before the clamp.
          const uint64_t length = numeric_cast<uint64_t>(it->second.stream.get_length());
          const uint64_t clampedPosition = std::min(in.position, length);
          it->second.stream.seek_from_start(numeric_cast<size_t>(clampedPosition));
        }
        catch (...)
        {
          result = ua::exception_to_status_code(std::current_exception());
        }
      }
    }
    complete(std::move(result));
  };
}

detail::WholeValueRead make_size_read_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](
           const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    std::error_code ec;
    const auto sz = std::filesystem::file_size(s->filePath, ec);
    DataValue dv;
    dv.source_timestamp() = DateTime::now();
    if (ec)
    {
      // OPC 10000-20 section 4.2.1 makes Size best-effort, and a Server that cannot give an authoritative
      // byte-count has to say so. Reporting the zero-initialised local as Good is indistinguishable
      // from an empty file, so a Client stops reading before it has read anything -- and it stops
      // silently, which is the worst of the available answers.
      dv.status() = StatusCode{Status::BadNotSupported};
      complete(std::move(dv));
      return;
    }
    dv.value() = Variant{numeric_cast<uint64_t>(sz)};
    complete(std::move(dv));
  };
}

/// LastModifiedTime, answered from the backing file on every read.
///
/// OPC 10000-20 section 4.2.1 requires the Property to track every server-observable mutation, and
/// SVR-FILE-006 additionally requires an externally-made change the Server can detect to show up.
/// Reading the filesystem's own modification time on demand satisfies both at once and cannot drift:
/// stamping the Property from the Write handler instead would catch the Server's own writes and miss
/// every change made underneath it, which is the half the obligation calls out.
detail::WholeValueRead make_last_modified_time_read_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](
           const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    DataValue dv;
    dv.source_timestamp() = DateTime::now();
    std::error_code ec;
    const auto written = std::filesystem::last_write_time(s->filePath, ec);
    if (ec)
    {
      // Same reasoning as Size: a time the Server cannot determine is reported as such rather than
      // as an epoch value a Client would read as a real timestamp.
      dv.status() = StatusCode{Status::BadNotSupported};
      complete(std::move(dv));
      return;
    }
    // NOT std::chrono::clock_cast: libstdc++ 12 does not provide it, and GCC 12 is the published
    // minimum supported compiler - so the SDK did not compile on its own documented floor. The
    // failure was invisible here because the primary toolchain is GCC 14.
    //
    // This is the portable conversion: measure the offset between the two clocks by reading both
    // now, and shift the file's timestamp by it. The offset is exact to within the time between
    // the two now() calls, which is nanoseconds - far below the resolution anything reports a
    // file modification time at.
    const auto systemTime = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
      written - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    dv.value() = Variant{DateTime{std::chrono::time_point_cast<datetime::OneHundredNanoSeconds>(systemTime)}};
    complete(std::move(dv));
  };
}

detail::WholeValueRead make_open_count_read_handler(std::shared_ptr<FileHelper::State> state)
{
  return [s = std::move(state)](
           const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    uint16_t count = 0;
    {
      const std::lock_guard lock{s->mutex};
      count = numeric_cast<uint16_t>(s->handles.size());
    }
    DataValue dv;
    dv.source_timestamp() = DateTime::now();
    dv.value() = Variant{count};
    complete(std::move(dv));
  };
}

/// Per-flow heap struct shared by FileHelper::create_async and
/// FileHelper::attach_async. Differs only in the first step (File::create
/// vs File::attach), parameterised by an init function.
/// Initialises a File node, then installs its handlers.
///
/// Its own strand, made over the address space's executor, because this belongs to no component and
/// @ref ua::async::await_callback keeps the task's generation and suspended handle on whatever it is
/// given. The address space is deliberately an executor, not a strand.
/// @see ua::async::SelfOwningOperation
class CreateOrAttachOperation final : public ua::async::SelfOwningOperation<CreateOrAttachOperation>
{
public:
  using Base = ua::async::SelfOwningOperation<CreateOrAttachOperation>;
  using InitFn = std::function<void(std::function<void(FileResult)>)>;

  /// @param rollBackNodeOnFailure the create path: a FileType node whose handlers cannot be installed
  ///        is removed again before the failure is reported, so a bad result means no node was
  ///        registered (the directory helper relies on that to discard the file it created). The
  ///        attach path leaves the caller's node alone.
  CreateOrAttachOperation(InitFn init, AddressSpace addressSpace, std::shared_ptr<FileHelper::State> state,
    FileHelper::CreateCompleteCallback onComplete, bool rollBackNodeOnFailure)
    : Base(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()), mInit(std::move(init)),
      mAddressSpace(addressSpace.weak()), mState(std::move(state)), mOnComplete(std::move(onComplete)),
      mRollBackNodeOnFailure(rollBackNodeOnFailure)
  {}

  static void start(InitFn init, AddressSpace addressSpace, std::shared_ptr<FileHelper::State> state,
    FileHelper::CreateCompleteCallback onComplete, bool rollBackNodeOnFailure)
  {
    Base::launch(std::make_shared<CreateOrAttachOperation>(std::move(init),
      std::move(addressSpace),
      std::move(state),
      std::move(onComplete),
      rollBackNodeOnFailure));
  }

private:
  friend class ua::async::SelfOwningOperation<CreateOrAttachOperation>;

  ua::async::Task<> run()
  {
    try
    {
      // The Step enum this replaced existed to reject a collaborator that answered twice or out of
      // order. Both collaborators below are awaited, so the suspension's own generation decides that
      // now and a second firing never reaches this body. R11.
      auto initialised =
        co_await await_step<FileResult>([this](auto completion) { mInit(std::move(completion)); });
      if (!initialised.is_good())
      {
        fail(initialised.status_code(), initialised.shared_detail());
        co_return;
      }

      // A frame local, so it is alive across the await below and destroyed with the frame - which is
      // what the `std::optional<File>` member and its has_value() guard were standing in for.
      File file = std::move(initialised).value();
      if (mRollBackNodeOnFailure)
      {
        mCreatedNode = file.node_id();
      }

      // --- the six mandatory Method handlers -------------------------------------------------
      //
      // Any one of these failing is the operation failing: a FileType node whose Open or Read cannot
      // be reached is not a usable file. The Step enum that sequenced these is gone with them - each
      // await resumes exactly once, and a second firing is rejected by its own generation (R11).
      {
        auto opened = co_await await_step<VoidResult>([this, &file](auto done)
          { file.set_open_handler_async(make_open_handler(mState), std::move(done)); });
        if (auto injected = detail::file_helper_tests::take_handler_install_fault_for_tests())
        {
          // A test-only, one-shot fault: the handler-install failure the production code cannot
          // otherwise be made to take deterministically.
          opened = VoidResult{*injected};
        }
        if (opened.is_bad())
        {
          fail_after_node(opened.status_code(), opened.shared_detail());
          co_return;
        }
        auto closed = co_await await_step<VoidResult>([this, &file](auto done)
          { file.set_close_handler_async(make_close_handler(mState), std::move(done)); });
        if (closed.is_bad())
        {
          fail_after_node(closed.status_code(), closed.shared_detail());
          co_return;
        }
        auto readSet = co_await await_step<VoidResult>([this, &file](auto done)
          { file.set_read_handler_async(make_read_handler(mState), std::move(done)); });
        if (readSet.is_bad())
        {
          fail_after_node(readSet.status_code(), readSet.shared_detail());
          co_return;
        }
        auto writeSet = co_await await_step<VoidResult>([this, &file](auto done)
          { file.set_write_handler_async(make_write_handler(mState), std::move(done)); });
        if (writeSet.is_bad())
        {
          fail_after_node(writeSet.status_code(), writeSet.shared_detail());
          co_return;
        }
        auto getPos = co_await await_step<VoidResult>([this, &file](auto done)
          { file.set_get_position_handler_async(make_get_position_handler(mState), std::move(done)); });
        if (getPos.is_bad())
        {
          fail_after_node(getPos.status_code(), getPos.shared_detail());
          co_return;
        }
        auto setPos = co_await await_step<VoidResult>([this, &file](auto done)
          { file.set_set_position_handler_async(make_set_position_handler(mState), std::move(done)); });
        if (setPos.is_bad())
        {
          fail_after_node(setPos.status_code(), setPos.shared_detail());
          co_return;
        }
      }

      // --- the optional Properties, all best-effort --------------------------------------------
      //
      // Size, OpenCount and LastModifiedTime are Optional on FileType, so an instance without one is
      // conforming. A resolution that fails skips ONLY its own read-handler install and continues to
      // the NEXT step - the chain this replaced once jumped from a missing LastModifiedTime straight
      // to the writable writes, which skipped MaxByteStringLength for every file that lacked it,
      // which is most of them. A linear body cannot make that mistake. The handler installs
      // themselves discard their result, as the code before the flow did.
      auto sizeProperty = co_await await_step<PropertyResult>(
        [&file](auto done) { file.size_property_async(std::move(done)); });
      if (sizeProperty.is_good())
      {
        auto& property = sizeProperty.value();
        (void)co_await await_step<VoidResult>(
          [this, &property](auto done)
          {
            property.set_value_source_async(
              detail::whole_value_source(make_size_read_handler(mState)), std::move(done));
          });
      }

      auto openCountProperty = co_await await_step<PropertyResult>(
        [&file](auto done) { file.open_count_property_async(std::move(done)); });
      if (openCountProperty.is_good())
      {
        auto& property = openCountProperty.value();
        (void)co_await await_step<VoidResult>(
          [this, &property](auto done)
          {
            property.set_value_source_async(
              detail::whole_value_source(make_open_count_read_handler(mState)), std::move(done));
          });
      }

      auto lastModifiedProperty = co_await await_step<PropertyResult>(
        [&file](auto done) { file.last_modified_time_property_async(std::move(done)); });
      if (lastModifiedProperty.is_good())
      {
        auto& property = lastModifiedProperty.value();
        (void)co_await await_step<VoidResult>(
          [this, &property](auto done)
          {
            property.set_value_source_async(
              detail::whole_value_source(make_last_modified_time_read_handler(mState)), std::move(done));
          });
      }

      // OPC 10000-20 section 4.2.1 makes the per-file Property the cap and the Server-wide
      // ServerCapabilities.MaxByteStringLength the fallback, "in that order". Both are resolved once,
      // here, because the Read handler is an ExternalValueSource callback with neither a node nor a
      // session in scope - it cannot consult either at call time. A Property that is absent, or
      // present but carrying nothing usable, is the same case: the Server-wide capability applies,
      // and it is read on the first Open rather than here.
      auto maxByteStringProperty = co_await await_step<PropertyResult>(
        [&file](auto done) { file.max_byte_string_length_property_async(std::move(done)); });
      if (maxByteStringProperty.is_good())
      {
        auto& property = maxByteStringProperty.value();
        auto declaredValue = co_await await_step<DataValueResult>(
          [&property](auto done) { property.read_value_async(std::move(done)); });
        if (declaredValue.is_good())
        {
          if (const auto* declared = declaredValue.value().value().try_as<uint32_t>();
              declared != nullptr && *declared != 0)
          {
            mState->maxByteStringLength = *declared;
          }
        }
      }

      // Best-effort, as before: the code this replaced checked neither result.
      (void)co_await await_step<VoidResult>(
        [this, &file](auto done) { file.write_writable_async(mState->writable, std::move(done)); });
      (void)co_await await_step<VoidResult>(
        [this, &file](auto done) { file.write_user_writable_async(mState->writable, std::move(done)); });

      auto onComplete = std::move(mOnComplete);
      if (!onComplete)
      {
        co_return;
      }
      // Route the terminal fire - and the FileHelperResult/FileHelper construction, which may
      // allocate - through invoke_user_callback, so neither a throwing application callback nor a
      // bad_alloc crosses this Asio-completion boundary into std::terminate. Matches the sibling
      // discipline in ua_instance_utils.cpp / ua_address_space.cpp. No Logger is in scope here.
      detail::invoke_user_callback(
        [&] { onComplete(FileHelperResult{FileHelper{std::move(file), std::move(mState)}}); });
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail_after_node(bad.status_code(), bad.shared_detail());
    }
  }

  /// A failure once the FileType node exists (create path): the node is removed again, then the
  /// ORIGINAL status is reported. Best effort, as the rollback's own result cannot improve on the
  /// failure being reported: a rollback that fails leaves the node, exactly as before this change.
  void fail_after_node(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    if (!mCreatedNode)
    {
      fail(status, std::move(detail));
      return;
    }
    // Build the completion first: once the node id is taken, nothing below may throw, or a second
    // fail_after_node from the catch(...) would report without rolling back (and a throw out of
    // that catch would lose the answer altogether).
    AddressSpace::DeleteNodeCompleteCallback onDeleted;
    try
    {
      // Owning, so the operation outlives the delete it waits on and still answers its caller.
      onDeleted = ua::async::post_owning(this,
        mStrand,
        mLogger,
        [status, detail](CreateOrAttachOperation& self, VoidResult) mutable
        { self.fail(status, std::move(detail)); });
    }
    catch (...)
    {
      // The rollback cannot be scheduled (allocation): still answer the caller; the node is
      // stranded, exactly as before this change.
      fail(status, std::move(detail));
      return;
    }
    const NodeId nodeId = *mCreatedNode;
    mCreatedNode.reset();
    // Released with the address space: the node went with it.
    auto addressSpace = mAddressSpace.lock();
    if (!addressSpace)
    {
      onDeleted(VoidResult{});
      return;
    }
    addressSpace->delete_node_async(nodeId,
      /*deleteForwardHierarchicallyReferencedNodes=*/true,
      ReferenceHalves::Both,
      std::move(onDeleted));
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    auto onComplete = std::move(mOnComplete);
    if (!onComplete)
    {
      return;
    }
    // See run(): contain a throwing user callback at this Asio-completion boundary.
    detail::invoke_user_callback([&] { onComplete(FileHelperResult{status, std::move(detail)}); });
  }

  InitFn mInit;
  WeakAddressSpace mAddressSpace;  // held weakly (CALLS-21 rule 1)
  std::shared_ptr<FileHelper::State> mState;
  FileHelper::CreateCompleteCallback mOnComplete;
  bool mRollBackNodeOnFailure{false};
  std::optional<NodeId> mCreatedNode;  ///< set on the create path once the node exists
};
}  // namespace

// --- Create ---

void FileHelper::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, std::filesystem::path filePath, const InstantiationOptions& options,
  bool writable, CreateCompleteCallback complete, std::optional<uint64_t> maxFileSize) noexcept
{
  auto state = std::make_shared<State>();
  state->maxFileSize = maxFileSize;
  state->addressSpace = addressSpace.weak();
  state->filePath = std::move(filePath);
  state->writable = writable;
  subscribe_to_session_close(state, addressSpace);

  // A weak handle (CALLS-21 rule 1): `addressSpace` itself is moved into the operation below, which
  // takes its strand from it.
  CreateOrAttachOperation::InitFn init = [as = addressSpace.weak(),
                                           parent = NodeId{parent},
                                           browseName = QualifiedName{browseName},
                                           options = InstantiationOptions{options}](
                                           std::function<void(FileResult)> cb) mutable
  {
    auto locked = as.lock();
    if (!locked)
    {
      cb(FileResult{::ua::detail::address_space_gone("FileHelper")});
      return;
    }
    File::create_async(std::move(*locked),
      parent,
      browseName,
      options,
      [cb = std::move(cb)](FileResult r) mutable { cb(std::move(r)); });
  };

  CreateOrAttachOperation::start(std::move(init),
    std::move(addressSpace),
    std::move(state),
    std::move(complete),
    /*rollBackNodeOnFailure=*/true);
}

FileHelperResult FileHelper::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, std::filesystem::path filePath, const InstantiationOptions& options,
  bool writable, std::optional<uint64_t> maxFileSize) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileHelperResult>(addressSpace.executor(),
      [&](std::function<void(FileHelperResult)> complete)
      {
        FileHelper::create_async(std::move(addressSpace),
          parent,
          browseName,
          std::move(filePath),
          options,
          writable,
          std::move(complete),
          maxFileSize);
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

FileHelper FileHelper::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, std::filesystem::path filePath, const InstantiationOptions& options,
  bool writable, std::optional<uint64_t> maxFileSize)
{
  return ua::detail::good_value(try_create_sync(
    std::move(addressSpace), parent, browseName, std::move(filePath), options, writable, maxFileSize));
}

// --- Attach ---

void FileHelper::attach_async(AddressSpace addressSpace, const NodeId& existingInstance,
  std::filesystem::path filePath, bool writable, AttachCompleteCallback complete) noexcept
{
  auto state = std::make_shared<State>();
  state->addressSpace = addressSpace.weak();
  state->filePath = std::move(filePath);
  state->writable = writable;
  subscribe_to_session_close(state, addressSpace);

  // A weak handle - see create_async.
  CreateOrAttachOperation::InitFn init =
    [as = addressSpace.weak(), existingInstance = NodeId{existingInstance}](
      std::function<void(FileResult)> cb) mutable
  {
    auto locked = as.lock();
    if (!locked)
    {
      cb(FileResult{::ua::detail::address_space_gone("FileHelper")});
      return;
    }
    File::attach_async(
      std::move(*locked), existingInstance, [cb = std::move(cb)](FileResult r) mutable { cb(std::move(r)); });
  };

  CreateOrAttachOperation::start(std::move(init),
    std::move(addressSpace),
    std::move(state),
    std::move(complete),
    /*rollBackNodeOnFailure=*/false);
}

FileHelperResult FileHelper::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance,
  std::filesystem::path filePath, bool writable) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<FileHelperResult>(addressSpace.executor(),
      [&](std::function<void(FileHelperResult)> complete)
      {
        FileHelper::attach_async(
          std::move(addressSpace), existingInstance, std::move(filePath), writable, std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

FileHelper FileHelper::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance, std::filesystem::path filePath, bool writable)
{
  return ua::detail::good_value(
    try_attach_sync(std::move(addressSpace), existingInstance, std::move(filePath), writable));
}

}  // namespace ua
