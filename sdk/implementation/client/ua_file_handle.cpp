// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_file_transfer_client.h"

#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_sync_wait.h"
#include "ua_connection_ops.h"
#include "ua_error_detail.h"
#include "ua_file_handle_state.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include "ua_on_strand.h"

namespace ua::client
{

namespace
{

// Source tags for the manufactured boundary failures (the design specification, CL-DIAG-002/-015).
constexpr std::string_view readSource = "client.tier2.file_transfer.read";
constexpr std::string_view writeSource = "client.tier2.file_transfer.write";
constexpr std::string_view getPositionSource = "client.tier2.file_transfer.get_position";
constexpr std::string_view setPositionSource = "client.tier2.file_transfer.set_position";
constexpr std::string_view closeSource = "client.tier2.file_transfer.close";

/// Posts @p result to @p executor for a callback (callbacks always run on the executor); inline when no
/// executor is set (a moved-from handle's inert path).
template<typename Result>
void deliver(
  const boost::asio::any_io_executor& executor, std::function<void(Result)> callback, Result result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// Builds a single-Method `CallRequest` for the resolved INSTANCE method node @p methodNode against the
/// FileType Object @p objectId with the given @p inputs (already Variant-boxed). The caller resolves the
/// instance node (OPC 10000-4 section 5.11.2 requires the methodId to be a Method component of the objectId)
/// and null-checks it before calling here; a null node never reaches this composer.
ua::CallRequest make_file_call(
  const ua::NodeId& objectId, const ua::NodeId& methodNode, std::vector<ua::Variant> inputs)
{
  ua::CallMethodRequest method;
  method.object_id() = objectId;
  method.method_id() = methodNode;
  for (auto& input : inputs)
  {
    method.input_arguments().push_back(std::move(input));
  }
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));
  return request;
}

/// Flattens a `CallResponse` down to the single-node `CallMethodResult` (or a bad Result carrying a
/// manufactured boundary detail on transport failure / empty results / per-call Bad). @p source is the
/// method-specific ErrorDetail source tag.
///
/// The Result holding the CallMethodResult carries the ServiceResult and the Method's statusCode combined
/// (@ref ua::detail::combined_status), so a Good subcode or an Uncertain code the server answers reaches the
/// operation's caller.
ua::Result<ua::CallMethodResult> flatten_call(ua::Result<ua::CallResponse> response, std::string_view source)
{
  if (!response.has_value())
  {
    // Single-wrap: propagate the funnel's service-level ErrorDetail unchanged.
    return ua::Result<ua::CallMethodResult>{response.status_code(), response.shared_detail()};
  }
  // Facade flatten: the tier-0 funnel returns the CallResponse verbatim; a bad ResponseHeader.serviceResult
  // is a service-level failure the facade surfaces as bad, preserving the exact service status + ErrorDetail.
  // Without this an empty results[] masks the fault as Bad_UnexpectedError (empty-results branch below) and a
  // non-empty results[] silently returns Good, dropping the fault entirely.
  const ua::StatusCode serviceResult = response.value().response_header().service_result();
  if (serviceResult.is_bad())
  {
    return ua::Result<ua::CallMethodResult>{serviceResult,
      ua::make_error_detail("FileCallServiceFault",
        "the FileType Call service returned a bad ResponseHeader.serviceResult",
        std::string{source},
        serviceResult)};
  }
  const auto& results = response.value().results();
  if (results.empty())
  {
    return ua::Result<ua::CallMethodResult>{ua::Status::BadUnexpectedError,
      ua::make_error_detail("FileCallEmptyResults",
        "the server returned a Good Call response with no result for the single method",
        std::string{source})};
  }
  ua::CallMethodResult result = results[0];
  if (result.status_code().is_bad())
  {
    // Surface the per-call StatusCode verbatim (chained on any server detail), source-tagged for this op.
    return ua::Result<ua::CallMethodResult>{result.status_code(),
      ua::make_error_detail("FileCallBad",
        "the server rejected the FileType method call",
        std::string{source},
        response.shared_detail())};
  }
  const ua::StatusCode answered = ua::detail::combined_status(serviceResult, result.status_code());
  return ua::detail::held(std::move(result), answered);
}

/// The typed answer of a FileType method's first output argument: a Result holding no CallMethodResult, or
/// an Uncertain one without output arguments, is answered with its code; otherwise the output decoded to `T`
/// (a decode failure stays Bad), with the call's code. @p noOutput is the failure for a Good call without an
/// output argument.
template<typename T>
ua::Result<T> first_output(const ua::Result<ua::CallMethodResult>& flat, ua::StatusCode noOutput)
{
  if (!flat.has_value())
  {
    return ua::Result<T>{flat.status_code(), flat.shared_detail()};
  }
  const auto& outputs = flat.value().output_arguments();
  if (outputs.empty())
  {
    if (flat.is_uncertain())
    {
      return ua::Result<T>{flat.status_code(), flat.shared_detail()};
    }
    return ua::Result<T>{std::move(noOutput)};
  }
  ua::Result<T> decoded = outputs[0].template to<T>();
  if (!decoded.has_value())
  {
    return decoded;
  }
  return ua::detail::held(std::move(decoded).value(), flat.status_code());
}

}  // namespace

namespace detail
{

namespace
{

bool session_changed(const detail::FileHandleState& state) noexcept
{
  return state.sessionGeneration &&
         state.sessionGeneration->load(std::memory_order_acquire) != state.openedSessionGeneration;
}

template<typename Result>
Result session_closed_result()
{
  return Result{ua::Status::BadSessionClosed,
    ua::make_error_detail("FileHandleSessionEnded",
      "the Session that owns this file handle has ended",
      "client.tier2.file_transfer.session_end")};
}

/// The shared per-op prologue for the read / write / get-position / set-position ops: validates the handle
/// and locks the wire interface, returning the locked interface (or delivering a manufactured boundary
/// failure and returning null). Templated on the op's `Result` so one moved-from / gone bail shape serves all
/// four. (Close has its own prologue  -  a gone Connection completes Good there, not Bad.)
template<typename Result>
std::shared_ptr<detail::WireOps> lock_wire_ops_or_fail(const std::shared_ptr<detail::FileHandleState>& state,
  std::string_view source, std::function<void(Result)>& callback)
{
  if (!state)
  {
    // Moved-from handle: no executor to hop through  -  complete inline.
    callback(Result{ua::Status::BadInvalidState,
      ua::make_error_detail(
        "FileHandleMovedFrom", "the operation was issued on a moved-from FileHandle", std::string{source})});
    return nullptr;
  }
  if (session_changed(*state))
  {
    deliver(state->executor, std::move(callback), session_closed_result<Result>());
    return nullptr;
  }
  auto lockedWireOps = state->wireOps.lock();
  if (!lockedWireOps)
  {
    deliver(state->executor,
      std::move(callback),
      Result{ua::Status::BadConnectionClosed,
        ua::make_error_detail("FileHandleConnectionGone",
          "the Connection was dropped before the file operation could be issued",
          std::string{source})});
    return nullptr;
  }
  return lockedWireOps;
}

}  // namespace

}  // namespace detail

void FileHandle::fire_close_if_owed() noexcept
{
  if (!mState || mState->closed)
  {
    return;  // moved-from or already explicitly closed: no Close owed (CL-FILE-001).
  }
  // Fire-and-forget Close (CL-FILE-001): the one documented fire-and-forget path in FileTransferClient. The
  // logger is captured by value so a bad Close is logged at the wire boundary rather than silently dropped.
  close_async(
    [logger = mState->logger](ua::VoidResult result)
    {
      if (result.is_bad())
      {
        logger.warning(
          "client.tier2.file_transfer.close: best-effort handle Close returned {} (advisory; "
          "server discards the handle on Session close)",
          static_cast<std::uint32_t>(result.status_code().value()));
      }
    });
}

FileHandle::~FileHandle()
{
  fire_close_if_owed();
}

FileHandle& FileHandle::operator=(FileHandle&& other) noexcept
{
  if (this != &other)
  {
    // Discharge the close-duty on the handle we are about to displace BEFORE adopting the source, else the
    // displaced server `fileHandle` would leak (the shared_ptr's default deleter never issues a Close). This
    // is what keeps the close-duty exactly-once on move-assignment as well as move-construction
    // (CL-FILE-001).
    fire_close_if_owed();
    mState = std::move(other.mState);
  }
  return *this;
}

bool FileHandle::is_valid() const noexcept
{
  return mState && !mState->closed;
}

ua::NodeId FileHandle::file_node() const noexcept
{
  return mState ? mState->fileNode : ua::NodeId{};
}

FileOpenMode FileHandle::mode() const noexcept
{
  return mState ? mState->mode : FileOpenMode{};
}

std::uint32_t FileHandle::max_byte_string_length() const noexcept
{
  return mState ? mState->effectiveMaxByteStringLength : 0;
}

void FileHandle::read_async(std::uint32_t maxBytes, std::function<void(ByteStringResult)> callback) noexcept
{
  // Caller-thread pre-flight: a zero-length read is a no-op (no wire round-trip); return an empty ByteString.
  if (maxBytes == 0)
  {
    deliver<ByteStringResult>(mState ? mState->executor : boost::asio::any_io_executor{},
      std::move(callback),
      ByteStringResult{ua::ByteString{}});
    return;
  }
  auto lockedWireOps = detail::lock_wire_ops_or_fail<ByteStringResult>(mState, readSource, callback);
  if (!lockedWireOps)
  {
    return;
  }
  if (mState->closed)
  {
    deliver<ByteStringResult>(mState->executor,
      std::move(callback),
      ByteStringResult{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "FileHandleClosed", "read issued on a closed FileHandle", std::string{readSource})});
    return;
  }
  // OPC 10000-4 section 5.11.2: the Call must target the resolved INSTANCE Read method (never the abstract
  // FileType declaration). A null node means the server did not expose one  to  fail locally, no wire Call.
  if (mState->methods.read.is_null())
  {
    deliver<ByteStringResult>(mState->executor,
      std::move(callback),
      ByteStringResult{ua::Status::BadMethodInvalid,
        ua::make_error_detail("FileReadMethodMissing",
          "the file object does not expose an instance Read method",
          std::string{readSource})});
    return;
  }
  // Cap the requested length at the resolved MaxByteStringLength (CL-FILE-002).
  const auto capped =
    static_cast<std::int32_t>(std::min<std::uint32_t>(maxBytes, mState->effectiveMaxByteStringLength));
  std::vector<ua::Variant> inputs;
  inputs.emplace_back(static_cast<std::uint32_t>(mState->fileHandle));
  inputs.emplace_back(capped);
  auto executor = mState->executor;
  std::weak_ptr<detail::FileHandleState> weak = mState;
  lockedWireOps->call_async(make_file_call(mState->fileNode, mState->methods.read, std::move(inputs)),
    [weak, executor, callback = std::move(callback)](ua::Result<ua::CallResponse> response) mutable
    {
      auto state = weak.lock();
      if (!state)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)  -  do not touch freed state
      }
      if (detail::session_changed(*state))
      {
        deliver<ByteStringResult>(
          executor, std::move(callback), detail::session_closed_result<ByteStringResult>());
        return;
      }
      auto flat = flatten_call(std::move(response), readSource);
      deliver<ByteStringResult>(executor,
        std::move(callback),
        first_output<ua::ByteString>(flat,
          ua::StatusCode{ua::Status::BadUnexpectedError,
            ua::make_error_detail("FileReadNoOutput",
              "FileType.Read returned Good with no output argument",
              std::string{readSource})}));
    });
}

void FileHandle::write_async(ua::ByteString data, std::function<void(ua::VoidResult)> callback) noexcept
{
  // Caller-thread pre-flight (CL-FILE-004): a Write on a handle opened read-only is a programming error;
  // reject it loudly with no wire op.
  if (mState &&
      !any_set(mState->mode, FileOpenMode::Write | FileOpenMode::EraseExisting | FileOpenMode::Append))
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "FileHandleReadOnly", "write issued on a FileHandle opened read-only", std::string{writeSource})});
    return;
  }
  auto lockedWireOps = detail::lock_wire_ops_or_fail<ua::VoidResult>(mState, writeSource, callback);
  if (!lockedWireOps)
  {
    return;
  }
  if (mState->closed)
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "FileHandleClosed", "write issued on a closed FileHandle", std::string{writeSource})});
    return;
  }
  // OPC 10000-4 section 5.11.2: Call the resolved INSTANCE Write method; null means the server omits it  to
  // fail locally, no wire Call.
  if (mState->methods.write.is_null())
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadMethodInvalid,
        ua::make_error_detail("FileWriteMethodMissing",
          "the file object does not expose an instance Write method",
          std::string{writeSource})});
    return;
  }
  std::vector<ua::Variant> inputs;
  inputs.emplace_back(static_cast<std::uint32_t>(mState->fileHandle));
  inputs.emplace_back(std::move(data));
  auto executor = mState->executor;
  std::weak_ptr<detail::FileHandleState> weak = mState;
  lockedWireOps->call_async(make_file_call(mState->fileNode, mState->methods.write, std::move(inputs)),
    [weak, executor, callback = std::move(callback)](ua::Result<ua::CallResponse> response) mutable
    {
      auto state = weak.lock();
      if (!state)
      {
        return;  // handle dropped mid-flight: bail (UAF guard, section 9.8.3)
      }
      if (detail::session_changed(*state))
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), detail::session_closed_result<ua::VoidResult>());
        return;
      }
      // The call's code (a Good subcode or an Uncertain code kept) is the write's result.
      auto flat = flatten_call(std::move(response), writeSource);
      deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{flat.status_code()});
    });
}

void FileHandle::get_position_async(std::function<void(UInt64Result)> callback) noexcept
{
  auto lockedWireOps = detail::lock_wire_ops_or_fail<UInt64Result>(mState, getPositionSource, callback);
  if (!lockedWireOps)
  {
    return;
  }
  if (mState->closed)
  {
    deliver<UInt64Result>(mState->executor,
      std::move(callback),
      UInt64Result{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "FileHandleClosed", "get_position issued on a closed FileHandle", std::string{getPositionSource})});
    return;
  }
  // OPC 10000-4 section 5.11.2: Call the resolved INSTANCE GetPosition method; null means the server omits it
  // to  fail locally, no wire Call.
  if (mState->methods.getPosition.is_null())
  {
    deliver<UInt64Result>(mState->executor,
      std::move(callback),
      UInt64Result{ua::Status::BadMethodInvalid,
        ua::make_error_detail("FileGetPositionMethodMissing",
          "the file object does not expose an instance GetPosition method",
          std::string{getPositionSource})});
    return;
  }
  std::vector<ua::Variant> inputs;
  inputs.emplace_back(static_cast<std::uint32_t>(mState->fileHandle));
  auto executor = mState->executor;
  std::weak_ptr<detail::FileHandleState> weak = mState;
  lockedWireOps->call_async(make_file_call(mState->fileNode, mState->methods.getPosition, std::move(inputs)),
    [weak, executor, callback = std::move(callback)](ua::Result<ua::CallResponse> response) mutable
    {
      auto state = weak.lock();
      if (!state)
      {
        return;
      }
      if (detail::session_changed(*state))
      {
        deliver<UInt64Result>(executor, std::move(callback), detail::session_closed_result<UInt64Result>());
        return;
      }
      auto flat = flatten_call(std::move(response), getPositionSource);
      deliver<UInt64Result>(executor,
        std::move(callback),
        first_output<std::uint64_t>(flat,
          ua::StatusCode{ua::Status::BadUnexpectedError,
            ua::make_error_detail("FileGetPositionNoOutput",
              "FileType.GetPosition returned Good with no output argument",
              std::string{getPositionSource})}));
    });
}

void FileHandle::set_position_async(
  std::uint64_t position, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto lockedWireOps = detail::lock_wire_ops_or_fail<ua::VoidResult>(mState, setPositionSource, callback);
  if (!lockedWireOps)
  {
    return;
  }
  if (mState->closed)
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "FileHandleClosed", "set_position issued on a closed FileHandle", std::string{setPositionSource})});
    return;
  }
  // OPC 10000-4 section 5.11.2: Call the resolved INSTANCE SetPosition method; null means the server omits it
  // to  fail locally, no wire Call.
  if (mState->methods.setPosition.is_null())
  {
    deliver<ua::VoidResult>(mState->executor,
      std::move(callback),
      ua::VoidResult{ua::Status::BadMethodInvalid,
        ua::make_error_detail("FileSetPositionMethodMissing",
          "the file object does not expose an instance SetPosition method",
          std::string{setPositionSource})});
    return;
  }
  std::vector<ua::Variant> inputs;
  inputs.emplace_back(static_cast<std::uint32_t>(mState->fileHandle));
  inputs.emplace_back(position);
  auto executor = mState->executor;
  std::weak_ptr<detail::FileHandleState> weak = mState;
  lockedWireOps->call_async(make_file_call(mState->fileNode, mState->methods.setPosition, std::move(inputs)),
    [weak, executor, callback = std::move(callback)](ua::Result<ua::CallResponse> response) mutable
    {
      auto state = weak.lock();
      if (!state)
      {
        return;
      }
      if (detail::session_changed(*state))
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), detail::session_closed_result<ua::VoidResult>());
        return;
      }
      // The call's code (a Good subcode or an Uncertain code kept) is the result.
      auto flat = flatten_call(std::move(response), setPositionSource);
      deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{flat.status_code()});
    });
}

void FileHandle::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail(
        "FileHandleMovedFrom", "close issued on a moved-from FileHandle", std::string{closeSource})});
    return;
  }
  // Idempotence (CL-FILE-001): a second close is Good and issues no wire op.
  if (mState->closed)
  {
    deliver<ua::VoidResult>(mState->executor, std::move(callback), ua::VoidResult{});
    return;
  }
  // Mark closed BEFORE issuing the wire Close so a read/write that races the in-flight Close returns
  // Bad_InvalidState (section 8.10.3 close path step 4).
  mState->closed = true;
  if (detail::session_changed(*mState))
  {
    // The Server discarded every Session-scoped fileHandle when the owning Session ended. Never send the
    // stale numeric handle on the replacement Session; local close is complete.
    deliver<ua::VoidResult>(mState->executor, std::move(callback), ua::VoidResult{});
    return;
  }
  // OPC 10000-4 section 5.11.2: Close must target the resolved INSTANCE Close method. If the server did not
  // expose one the fire-and-forget close becomes a safe local no-op  -  the handle is closed locally and the
  // server discards it on Session end  -  rather than Calling the abstract FileType.Close (which a conformant
  // server rejects). Log the omission at the wire boundary; the user still sees Good.
  if (mState->methods.close.is_null())
  {
    mState->logger.debug(
      "{}: the file object does not expose an instance Close method; treating close as a local no-op "
      "(the server discards the handle on Session close)",
      closeSource);
    deliver<ua::VoidResult>(mState->executor, std::move(callback), ua::VoidResult{});
    return;
  }
  auto lockedWireOps = mState->wireOps.lock();
  if (!lockedWireOps)
  {
    // Connection gone: the server already discarded the handle on Session-end. Report Good (best-effort).
    deliver<ua::VoidResult>(mState->executor, std::move(callback), ua::VoidResult{});
    return;
  }
  std::vector<ua::Variant> inputs;
  inputs.emplace_back(static_cast<std::uint32_t>(mState->fileHandle));
  auto executor = mState->executor;
  // Capture the logger by value (not the state): the handle may be dropped before the Close response lands,
  // so a bad wire Close is logged at the wire boundary rather than silently discarded (the design
  // specification).
  lockedWireOps->call_async(make_file_call(mState->fileNode, mState->methods.close, std::move(inputs)),
    [executor, logger = mState->logger, callback = std::move(callback)](
      ua::Result<ua::CallResponse> response) mutable
    {
      // The handle is closed locally regardless. section 8.10.3 close step 6 / section 8.10.6: a bad wire
      // Close (e.g. the server already discarded the handle on a Session-end race) is LOGGED at the wire
      // boundary and the user still sees a Good Result  -  from the user's perspective the handle is gone.
      auto flat = flatten_call(std::move(response), closeSource);
      if (flat.is_bad())
      {
        logger.warning(
          "{}: best-effort handle Close returned {} (advisory; the server discards the handle on Session "
          "close)",
          closeSource,
          static_cast<std::uint32_t>(flat.status_code().value()));
        deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{});
        return;
      }
      // A Good subcode or an Uncertain code the server answered the Close with is kept.
      deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{flat.status_code()});
    });
}

// ---- Sync bridges (section 7.0; MUST NOT run on the executor thread) ----

ua::ByteString FileHandle::read_sync(std::uint32_t maxBytes)
{
  return ua::detail::good_value(try_read_sync(maxBytes));
}

ByteStringResult FileHandle::try_read_sync(std::uint32_t maxBytes) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::ByteString>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, maxBytes](auto completion) { read_async(maxBytes, std::move(completion)); });
}

void FileHandle::write_sync(ua::ByteString data)
{
  try_write_sync(std::move(data)).value();
}

ua::VoidResult FileHandle::try_write_sync(ua::ByteString data) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, data = std::move(data)](auto completion) mutable
    { write_async(std::move(data), std::move(completion)); });
}

std::uint64_t FileHandle::get_position_sync()
{
  return ua::detail::good_value(try_get_position_sync());
}

UInt64Result FileHandle::try_get_position_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::uint64_t>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) { get_position_async(std::move(completion)); });
}

void FileHandle::set_position_sync(std::uint64_t position)
{
  try_set_position_sync(position).value();
}

ua::VoidResult FileHandle::try_set_position_sync(std::uint64_t position) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this, position](auto completion) { set_position_async(position, std::move(completion)); });
}

void FileHandle::close_sync()
{
  try_close_sync().value();
}

ua::VoidResult FileHandle::try_close_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) { close_async(std::move(completion)); });
}

}  // namespace ua::client
