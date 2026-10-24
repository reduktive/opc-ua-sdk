// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_file_transfer_client.h"

#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_attribute_id.h"
#include "ua_sync_wait.h"
#include "ua_connection_ops.h"
#include "ua_continuation_point.h"
#include "ua_browse_drain_guard.h"
#include "ua_client_answer_status.h"
#include "ua_error_detail.h"
#include "ua_file_handle_state.h"
#include "ua_file_method_resolution.h"
#include "ua_objecttype_id.h"
#include "ua_reference_description.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path_element.h"
#include "ua_status.h"
#include "ua_variant.h"
#include "ua_variable_id.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace
{

// Source tags for the manufactured boundary failures (the design specification, CL-DIAG-002/-015).
constexpr std::string_view openSource = "client.tier2.file_transfer.open";
constexpr std::string_view readAllSource = "client.tier2.file_transfer.read_all";
constexpr std::string_view directorySource = "client.tier2.file_transfer.directory";

template<typename Result>
void deliver(
  const boost::asio::any_io_executor& executor, std::function<void(Result)> callback, Result result);

using ReferenceList = std::vector<ua::ReferenceDescription>;

template<typename Result>
Result directory_failure(ua::StatusCode cause)
{
  return Result{ua::StatusCode{cause.as_uint32(),
    ua::make_error_detail("FileDirectoryOperationFailed",
      "A FileDirectoryType operation failed",
      std::string{directorySource},
      cause)}};
}

void resolve_directory_method(std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor,
  ua::NodeId directoryNode, std::string_view methodName, std::function<void(NodeIdResult)> callback)
{
  auto lockedWireOps = wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<NodeIdResult>(
      executor, std::move(callback), directory_failure<NodeIdResult>(ua::Status::BadConnectionClosed));
    return;
  }
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = std::move(directoryNode);
  browseDescription.browse_direction() = ua::BrowseDirection::Forward;
  browseDescription.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::HasComponent};
  browseDescription.include_subtypes() = true;
  browseDescription.node_class_mask() = static_cast<std::uint32_t>(ua::NodeClass::Method);
  browseDescription.result_mask() = static_cast<std::uint32_t>(ua::BrowseResultMask::TargetInfo);
  ua::BrowseRequest request;
  request.nodes_to_browse().push_back(std::move(browseDescription));
  lockedWireOps->browse_async(std::move(request),
    [executor, methodName = std::string{methodName}, callback = std::move(callback)](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      // The SDK calls the Method this Browse finds, so only a Good answer is used: an Uncertain one is
      // refused (ReferencesAnswerUncertain), as a Bad one fails the operation.
      if (response.is_uncertain())
      {
        deliver<NodeIdResult>(executor,
          std::move(callback),
          NodeIdResult{detail::uncertain_answer_refused(
            response.status_code(), "ReferencesAnswerUncertain", directorySource)});
        return;
      }
      if (!response.has_value())
      {
        deliver<NodeIdResult>(
          executor, std::move(callback), directory_failure<NodeIdResult>(response.status_code()));
        return;
      }
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      auto& results = response.value().results();
      const ua::StatusCode pageStatus =
        results.empty() ? ua::StatusCode{ua::Status::Good} : results[0].status_code();
      if (serviceResult.is_uncertain() || pageStatus.is_uncertain())
      {
        deliver<NodeIdResult>(executor,
          std::move(callback),
          NodeIdResult{
            detail::uncertain_answer_refused(serviceResult.is_uncertain() ? serviceResult : pageStatus,
              "ReferencesAnswerUncertain",
              directorySource)});
        return;
      }
      if (serviceResult.is_bad())
      {
        deliver<NodeIdResult>(executor, std::move(callback), directory_failure<NodeIdResult>(serviceResult));
        return;
      }
      if (results.empty() || results[0].status_code().is_bad())
      {
        deliver<NodeIdResult>(executor,
          std::move(callback),
          directory_failure<NodeIdResult>(
            results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code()));
        return;
      }
      for (const auto& reference : results[0].references())
      {
        if (reference.browse_name().namespace_index() == 0 && reference.browse_name().name() == methodName &&
            reference.node_id().is_local() && reference.node_id().is_index_based())
        {
          deliver<NodeIdResult>(executor, std::move(callback), NodeIdResult{reference.node_id().node_id()});
          return;
        }
      }
      deliver<NodeIdResult>(
        executor, std::move(callback), directory_failure<NodeIdResult>(ua::Status::BadMethodInvalid));
    });
}

ua::BrowseNextRequest make_directory_browse_next(const ua::ContinuationPoint& continuationPoint)
{
  ua::BrowseNextRequest request;
  request.release_continuation_points() = false;
  request.continuation_points().push_back(continuationPoint);
  return request;
}

/// Follows @p continuationPoint with BrowseNext until the directory's References are complete. @p answered is
/// the code the pages so far answered (each page's ServiceResult and status combined); the list is delivered
/// with it, so a Good subcode or an Uncertain code of any page reaches the caller.
void drain_directory(std::shared_ptr<detail::WireOps> lockedWireOps,
  std::shared_ptr<ReferenceList> references, ua::ContinuationPoint continuationPoint, ua::StatusCode answered,
  std::function<void(ua::Result<ReferenceList>)> callback,
  std::shared_ptr<detail::BrowseDrainGuard> guard = {})
{
  if (!guard)
  {
    guard = std::make_shared<detail::BrowseDrainGuard>(
      "client.file_transfer.directory_browse", detail::BrowseDrainLimits{}, references->size());
  }
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_next_async(make_directory_browse_next(continuationPoint),
    [lockedWireOps = std::move(lockedWireOps),
      references = std::move(references),
      answered = std::move(answered),
      callback = std::move(callback),
      guard](ua::Result<ua::BrowseNextResponse> response) mutable
    {
      if (!response.has_value())
      {
        callback(ua::Result<ReferenceList>{response.status_code(), response.shared_detail()});
        return;
      }
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<ReferenceList>{serviceResult});
        return;
      }
      auto& results = response.value().results();
      if (results.empty() || results[0].status_code().is_bad())
      {
        callback(ua::Result<ReferenceList>{
          results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code()});
        return;
      }
      // CL-VIEW-005: the page is admitted before its references are kept; a self-loop or an exhausted
      // budget ends the drain (a budget refusal releases the server's continuation point best-effort).
      if (auto admitted = guard->admit_page(results[0]); admitted.is_bad())
      {
        ua::client::detail::release_continuation_point_best_effort(
          *lockedWireOps, results[0].continuation_point());
        callback(ua::Result<ReferenceList>{admitted.status_code(), admitted.shared_detail()});
        return;
      }
      for (const auto& reference : results[0].references())
      {
        references->push_back(reference);
      }
      answered = ua::detail::combined_status(
        answered, ua::detail::combined_status(serviceResult, results[0].status_code()));
      if (!results[0].continuation_point().empty())
      {
        drain_directory(std::move(lockedWireOps),
          std::move(references),
          results[0].continuation_point(),
          std::move(answered),
          std::move(callback),
          guard);
        return;
      }
      callback(ua::detail::held(std::move(*references), std::move(answered)));
    });
}

void browse_directory(std::shared_ptr<detail::WireOps> lockedWireOps, ua::NodeId directoryNode,
  std::function<void(ua::Result<ReferenceList>)> callback)
{
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = std::move(directoryNode);
  browseDescription.browse_direction() = ua::BrowseDirection::Forward;
  browseDescription.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
  browseDescription.include_subtypes() = true;
  browseDescription.node_class_mask() = static_cast<std::uint32_t>(ua::NodeClass::Object);
  browseDescription.result_mask() = static_cast<std::uint32_t>(ua::BrowseResultMask::TargetInfo);
  ua::BrowseRequest request;
  request.nodes_to_browse().push_back(std::move(browseDescription));
  auto* lockedWireOpsRaw = lockedWireOps.get();
  lockedWireOpsRaw->browse_async(std::move(request),
    [lockedWireOps = std::move(lockedWireOps), callback = std::move(callback)](
      ua::Result<ua::BrowseResponse> response) mutable
    {
      if (!response.has_value())
      {
        callback(ua::Result<ReferenceList>{response.status_code(), response.shared_detail()});
        return;
      }
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<ReferenceList>{serviceResult});
        return;
      }
      auto& results = response.value().results();
      if (results.empty() || results[0].status_code().is_bad())
      {
        callback(ua::Result<ReferenceList>{
          results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code()});
        return;
      }
      auto references = std::make_shared<ReferenceList>();
      for (const auto& reference : results[0].references())
      {
        references->push_back(reference);
      }
      // The ServiceResult and the page's status combined: a Good subcode or an Uncertain code of either is
      // the status of the Result holding the list.
      ua::StatusCode answered = ua::detail::combined_status(serviceResult, results[0].status_code());
      if (!results[0].continuation_point().empty())
      {
        drain_directory(std::move(lockedWireOps),
          std::move(references),
          results[0].continuation_point(),
          std::move(answered),
          std::move(callback));
        return;
      }
      callback(ua::detail::held(std::move(*references), std::move(answered)));
    });
}

template<typename Result, typename Decode>
void call_directory_method(std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor,
  ua::NodeId directoryNode, ua::NodeId methodId, std::vector<ua::Variant> inputs,
  std::function<void(Result)> callback, Decode decode)
{
  auto lockedWireOps = wireOps.lock();
  if (!lockedWireOps)
  {
    deliver<Result>(
      executor, std::move(callback), directory_failure<Result>(ua::Status::BadConnectionClosed));
    return;
  }
  ua::CallMethodRequest method;
  method.object_id() = std::move(directoryNode);
  method.method_id() = std::move(methodId);
  for (auto& input : inputs)
  {
    method.input_arguments().push_back(std::move(input));
  }
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));
  lockedWireOps->call_async(std::move(request),
    [executor, callback = std::move(callback), decode = std::move(decode)](
      ua::Result<ua::CallResponse> response) mutable
    {
      if (!response.has_value())
      {
        deliver<Result>(executor, std::move(callback), directory_failure<Result>(response.status_code()));
        return;
      }
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver<Result>(executor, std::move(callback), directory_failure<Result>(serviceResult));
        return;
      }
      auto& results = response.value().results();
      if (results.empty() || results[0].status_code().is_bad())
      {
        deliver<Result>(executor,
          std::move(callback),
          directory_failure<Result>(
            results.empty() ? ua::StatusCode{ua::Status::BadUnexpectedError} : results[0].status_code()));
        return;
      }
      // The call's code: the ServiceResult and the Method's statusCode combined. An Uncertain call without
      // output arguments is answered with its code; otherwise the decoded outputs are answered with it, so a
      // Good subcode or an Uncertain code reaches the caller (a decode failure stays Bad).
      const ua::StatusCode answered = ua::detail::combined_status(serviceResult, results[0].status_code());
      if (answered.is_uncertain() && results[0].output_arguments().empty())
      {
        deliver<Result>(executor, std::move(callback), Result{answered});
        return;
      }
      deliver<Result>(executor, std::move(callback), ua::detail::carried(decode(results[0]), answered));
    });
}

/// Posts @p result to @p executor for a callback (callbacks always run on the executor); inline when no
/// executor is set (a moved-from facade's inert path).
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

class FileOpenFlow final : public std::enable_shared_from_this<FileOpenFlow>
{
public:
  FileOpenFlow(std::weak_ptr<detail::WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::Logger logger, ua::NodeId fileNode, FileOpenMode mode, std::uint32_t defaultCap,
    std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration,
    std::function<FileHandle(std::shared_ptr<detail::FileHandleState>)> makeHandle,
    std::function<void(FileHandleResult)> callback)
    : mWireOps(std::move(wireOps)), mExecutor(std::move(executor)), mLogger(std::move(logger)),
      mFileNode(std::move(fileNode)), mMode(mode), mEffectiveCap(defaultCap),
      mSessionGeneration(std::move(sessionGeneration)), mMakeHandle(std::move(makeHandle)),
      mCallback(std::move(callback))
  {}

  void start()
  {
    auto lockedWireOps = mWireOps.lock();
    if (!lockedWireOps)
    {
      fail_connection_gone();
      return;
    }
    auto request = ua::client::detail::build_file_method_browse_paths(mFileNode);
    lockedWireOps->translate_browse_paths_async(std::move(request),
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [](FileOpenFlow& self, ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> response)
        { self.on_methods(std::move(response)); }));
  }

private:
  void on_methods(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> response)
  {
    auto methods = ua::client::detail::interpret_file_method_resolution(std::move(response));
    if (!methods.is_good())
    {
      fail(methods.status_code(),
        ua::make_error_detail("FileOpenMethodResolveFailed",
          "resolving the FileType instance method nodes failed; the file cannot be opened",
          std::string{openSource},
          methods.shared_detail()));
      return;
    }
    mMethods = std::move(methods).value();
    mUsingServerCap = mMethods.maxByteStringLength.is_null();
    const ua::NodeId capNode = mUsingServerCap
                                 ? ua::NodeId{ua::VariableId::Server_ServerCapabilities_MaxByteStringLength}
                                 : mMethods.maxByteStringLength;
    ua::ReadValueId value;
    value.node_id() = capNode;
    value.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
    ua::ReadRequest request;
    request.nodes_to_read().push_back(std::move(value));
    mChecksUserWritable = any_set(mMode, FileOpenMode::Write);
    if (mChecksUserWritable)
    {
      if (mMethods.userWritable.is_null())
      {
        fail(ua::Status::BadNodeIdUnknown,
          ua::make_error_detail("FileUserWritableMissing",
            "the FileType instance does not expose its mandatory UserWritable Property",
            std::string{openSource}));
        return;
      }
      ua::ReadValueId writable;
      writable.node_id() = mMethods.userWritable;
      writable.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
      request.nodes_to_read().push_back(std::move(writable));
    }

    auto lockedWireOps = mWireOps.lock();
    if (!lockedWireOps)
    {
      fail_connection_gone();
      return;
    }
    lockedWireOps->read_async(std::move(request),
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [](FileOpenFlow& self, ua::Result<ua::ReadResponse> result) { self.on_cap(std::move(result)); }));
  }

  void on_cap(ua::Result<ua::ReadResponse> result)
  {
    // The SDK acts on MaxByteStringLength and UserWritable itself (the chunk size and the write check), so
    // only a Good answer is used: an Uncertain one is refused (ReadAnswerUncertain), as a Bad one fails the
    // open.
    if (result.is_uncertain())
    {
      fail_uncertain(result.status_code());
      return;
    }
    if (!result.has_value())
    {
      fail_cap(result.status_code());
      return;
    }
    const ua::StatusCode serviceResult = result.value().response_header().service_result();
    if (serviceResult.is_uncertain())
    {
      fail_uncertain(serviceResult);
      return;
    }
    if (serviceResult.is_bad())
    {
      fail_cap(serviceResult);
      return;
    }
    auto& values = result.value().results();
    const std::size_t expectedResults = mChecksUserWritable ? 2U : 1U;
    if (values.size() != expectedResults)
    {
      fail(ua::Status::BadUnexpectedError,
        ua::make_error_detail("FileMaxByteStringLengthResultCount",
          "the MaxByteStringLength Read returned an unexpected result count",
          std::string{openSource}));
      return;
    }
    const ua::StatusCode valueStatus = values[0].status().value_or(ua::StatusCode{});
    if (valueStatus.is_uncertain())
    {
      fail_uncertain(valueStatus);
      return;
    }
    if (valueStatus.is_bad())
    {
      if (mUsingServerCap && (valueStatus.as_status() == ua::Status::BadNodeIdUnknown ||
                               valueStatus.as_status() == ua::Status::BadAttributeIdInvalid))
      {
        // The optional server capability is absent: retain the configured safe default.
      }
      else
      {
        fail_cap(valueStatus);
        return;
      }
    }
    else
    {
      auto decoded = values[0].value().to<std::uint32_t>();
      if (!decoded.is_good())
      {
        fail(decoded.status_code(),
          ua::make_error_detail("FileMaxByteStringLengthDecode",
            "the MaxByteStringLength Property value was not a UInt32",
            std::string{openSource},
            decoded.shared_detail()));
        return;
      }
      if (decoded.value() == 0)
      {
        fail(ua::Status::BadOutOfRange,
          ua::make_error_detail("FileMaxByteStringLengthZero",
            "the MaxByteStringLength Property must be positive",
            std::string{openSource}));
        return;
      }
      mEffectiveCap = decoded.value();
    }
    if (mChecksUserWritable)
    {
      const ua::StatusCode writableStatus = values[1].status().value_or(ua::StatusCode{});
      if (writableStatus.is_uncertain())
      {
        fail_uncertain(writableStatus);
        return;
      }
      if (writableStatus.is_bad())
      {
        fail(writableStatus,
          ua::make_error_detail("FileUserWritableReadFailed",
            "reading the FileType UserWritable Property failed",
            std::string{openSource},
            writableStatus));
        return;
      }
      auto writable = values[1].value().to<bool>();
      if (!writable.is_good())
      {
        fail(writable.status_code(),
          ua::make_error_detail("FileUserWritableDecode",
            "the FileType UserWritable Property value was not Boolean",
            std::string{openSource},
            writable.shared_detail()));
        return;
      }
      if (!writable.value())
      {
        fail(ua::Status::BadUserAccessDenied,
          ua::make_error_detail("FileUserNotWritable",
            "the current user is not permitted to write this FileType Object",
            std::string{openSource}));
        return;
      }
    }
    issue_open();
  }

  void issue_open()
  {
    auto lockedWireOps = mWireOps.lock();
    if (!lockedWireOps)
    {
      fail_connection_gone();
      return;
    }
    ua::CallMethodRequest method;
    method.object_id() = mFileNode;
    method.method_id() = mMethods.open;
    method.input_arguments().push_back(ua::Variant{static_cast<std::uint8_t>(mMode)});
    ua::CallRequest request;
    request.methods_to_call().push_back(std::move(method));
    lockedWireOps->call_async(std::move(request),
      ua::async::post_owning(this,
        mExecutor,
        mLogger,
        [](FileOpenFlow& self, ua::Result<ua::CallResponse> result) { self.on_open(std::move(result)); }));
  }

  void on_open(ua::Result<ua::CallResponse> result)
  {
    if (!result.has_value())
    {
      fail(result.status_code(), result.shared_detail());
      return;
    }
    const ua::StatusCode serviceResult = result.value().response_header().service_result();
    if (serviceResult.is_bad())
    {
      fail(serviceResult,
        ua::make_error_detail("FileOpenServiceFault",
          "the FileType.Open Call service returned a bad serviceResult",
          std::string{openSource},
          serviceResult));
      return;
    }
    const auto& results = result.value().results();
    if (results.empty())
    {
      fail(ua::Status::BadUnexpectedError,
        ua::make_error_detail("FileOpenEmptyResults",
          "the server returned a Good Open response with no result",
          std::string{openSource}));
      return;
    }
    const ua::CallMethodResult& methodResult = results[0];
    if (methodResult.status_code().is_bad())
    {
      fail(methodResult.status_code(),
        ua::make_error_detail("FileOpenBad",
          "the server rejected the FileType.Open call",
          std::string{openSource},
          result.shared_detail()));
      return;
    }
    // The Open's code: the ServiceResult and the Method's statusCode combined, so a Good subcode or an
    // Uncertain code reaches the caller with the handle.
    const ua::StatusCode answered = ua::detail::combined_status(serviceResult, methodResult.status_code());
    if (methodResult.output_arguments().empty() && answered.is_uncertain())
    {
      complete(FileHandleResult{answered});
      return;
    }
    if (methodResult.output_arguments().empty())
    {
      fail(ua::Status::BadUnexpectedError,
        ua::make_error_detail("FileOpenNoHandle",
          "FileType.Open returned Good with no fileHandle output argument",
          std::string{openSource}));
      return;
    }
    auto decoded = methodResult.output_arguments()[0].to<std::uint32_t>();
    if (!decoded.is_good())
    {
      fail(decoded.status_code(),
        ua::make_error_detail("FileOpenHandleDecode",
          "the FileType.Open fileHandle output argument was not a UInt32",
          std::string{openSource},
          decoded.shared_detail()));
      return;
    }
    auto state = std::make_shared<detail::FileHandleState>();
    state->wireOps = mWireOps;
    state->executor = mExecutor;
    state->logger = std::move(mLogger);
    state->sessionGeneration = mSessionGeneration;
    state->openedSessionGeneration =
      mSessionGeneration ? mSessionGeneration->load(std::memory_order_acquire) : 0;
    state->fileNode = std::move(mFileNode);
    state->methods = std::move(mMethods);
    state->fileHandle = decoded.value();
    state->mode = mMode;
    state->effectiveMaxByteStringLength = mEffectiveCap;
    complete(ua::detail::held(mMakeHandle(std::move(state)), answered));
  }

  void fail_cap(ua::StatusCode cause)
  {
    fail(cause,
      ua::make_error_detail("FileMaxByteStringLengthReadFailed",
        "reading the effective MaxByteStringLength Property failed",
        std::string{openSource},
        cause));
  }

  /// Refuses the open on an Uncertain answer to the MaxByteStringLength / UserWritable Read, which the SDK
  /// acts on itself (ReadAnswerUncertain, the Uncertain code as the cause).
  void fail_uncertain(const ua::StatusCode& answer)
  {
    const ua::StatusCode refused =
      detail::uncertain_answer_refused(answer, "ReadAnswerUncertain", openSource);
    fail(refused, refused.shared_detail());
  }

  void fail_connection_gone()
  {
    fail(ua::Status::BadConnectionClosed,
      ua::make_error_detail("FileOpenConnectionGone",
        "the Connection was dropped before the file Open could be issued",
        std::string{openSource}));
  }

  void fail(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail)
  {
    complete(FileHandleResult{status, std::move(detail)});
  }

  void complete(FileHandleResult result)
  {
    auto callback = std::move(mCallback);
    deliver<FileHandleResult>(mExecutor, std::move(callback), std::move(result));
  }

  std::weak_ptr<detail::WireOps> mWireOps;
  boost::asio::any_io_executor mExecutor;
  ua::Logger mLogger;
  ua::NodeId mFileNode;
  FileOpenMode mMode;
  std::uint32_t mEffectiveCap;
  bool mUsingServerCap = false;
  bool mChecksUserWritable = false;
  detail::FileMethodNodes mMethods;
  std::shared_ptr<const std::atomic<std::uint64_t>> mSessionGeneration;
  std::function<FileHandle(std::shared_ptr<detail::FileHandleState>)> mMakeHandle;
  std::function<void(FileHandleResult)> mCallback;
};

/// Drives the `read_all` chunk loop (section 8.10.3): reads a chunk, honours the aggregate ceiling
/// (section 9.6.23.2), terminates on an empty chunk (EOF, CL-FILE-003), and otherwise recurses. The @p handle
/// is held by a copyable `shared_ptr<FileHandle>` so the completion can carry it forward; when the last
/// reference drops (on the terminal deliver) the FileHandle dtor fires the fire-and-forget Close
/// (CL-FILE-001). @p answered is the code the Open and the chunks so far answered, combined; the bytes are
/// delivered with it, so a Good subcode or an Uncertain code of any of them reaches the caller.
void read_all_loop(std::shared_ptr<FileHandle> handle, std::shared_ptr<ua::ByteString> accumulator,
  std::uint64_t ceiling, ua::StatusCode answered, boost::asio::any_io_executor executor,
  std::function<void(ByteStringResult)> callback)
{
  const std::uint32_t chunkCap = handle->max_byte_string_length();
  FileHandle& handleRef = *handle;
  handleRef.read_async(chunkCap,
    [handle = std::move(handle),
      accumulator,
      ceiling,
      answered = std::move(answered),
      executor,
      callback = std::move(callback)](ByteStringResult chunkResult) mutable
    {
      if (!chunkResult.has_value())
      {
        // The read failed; surface it verbatim. Close still fires from the handle dtor when the shared_ptr
        // captured here is dropped after this deliver returns.
        deliver<ByteStringResult>(executor,
          std::move(callback),
          ByteStringResult{chunkResult.status_code(), chunkResult.shared_detail()});
        return;
      }
      answered = ua::detail::combined_status(answered, chunkResult.status_code());
      ua::ByteString chunk = std::move(chunkResult).value();
      if (chunk.empty())
      {
        // CL-FILE-003 EOF: terminate and return the accumulated bytes.
        deliver<ByteStringResult>(
          executor, std::move(callback), ua::detail::held(std::move(*accumulator), std::move(answered)));
        return;
      }
      // section 9.6.23.2 aggregate ceiling: a file whose accumulated bytes would exceed the cap terminates
      // with a bad Result rather than reading unbounded into memory.
      if (accumulator->size() + chunk.size() > ceiling)
      {
        deliver<ByteStringResult>(executor,
          std::move(callback),
          ByteStringResult{ua::StatusCode{ua::Status::BadResponseTooLarge,
            ua::ErrorDetail::build("FileReadAllCeilingExceeded",
              "read_all aborted because the file exceeds the configured aggregate ceiling",
              std::string{readAllSource})
              .context(ua::ContextKeys::sizeMax, ceiling)}});
        return;
      }
      auto& sink = accumulator->payload();
      const auto& source = chunk.payload();
      sink.insert(sink.end(), source.begin(), source.end());
      // Trampolined recursion (section 8.10.3): this loop body runs on a fresh executor task on every chunk
      // because FileHandle::read_async delivers its completion via a post to the executor, so re-entering
      // read_all_loop here does NOT nest a stack frame under the previous chunk even when the wire interface
      // completes synchronously. If read_async ever stops posting its completion, an explicit
      // boost::asio::post(executor, ...) must wrap this call to preserve the bound.
      read_all_loop(std::move(handle),
        std::move(accumulator),
        ceiling,
        std::move(answered),
        executor,
        std::move(callback));
    });
}

/// Writes @p data from @p offset in chunks of the handle's MaxByteStringLength. @p answered is the code the
/// Open and the chunk writes so far answered, combined; the write completes with it, so a Good subcode or an
/// Uncertain code of any of them reaches the caller. A Bad chunk write stops the loop.
void write_all_loop(std::shared_ptr<FileHandle> handle, std::shared_ptr<ua::ByteString> data,
  std::size_t offset, ua::StatusCode answered, boost::asio::any_io_executor executor,
  std::function<void(ua::VoidResult)> callback)
{
  if (offset == data->size())
  {
    deliver<ua::VoidResult>(executor, std::move(callback), ua::VoidResult{std::move(answered)});
    return;
  }
  const std::size_t chunkSize =
    std::min<std::size_t>(handle->max_byte_string_length(), data->size() - offset);
  std::vector<std::uint8_t> payload;
  payload.reserve(chunkSize);
  const auto& source = data->payload();
  payload.insert(payload.end(),
    source.begin() + static_cast<std::ptrdiff_t>(offset),
    source.begin() + static_cast<std::ptrdiff_t>(offset + chunkSize));
  FileHandle& handleRef = *handle;
  handleRef.write_async(ua::ByteString{std::move(payload)},
    [handle = std::move(handle),
      data = std::move(data),
      offset,
      chunkSize,
      answered = std::move(answered),
      executor,
      callback = std::move(callback)](ua::VoidResult result) mutable
    {
      if (result.is_bad())
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), ua::VoidResult{result.status_code(), result.shared_detail()});
        return;
      }
      write_all_loop(std::move(handle),
        std::move(data),
        offset + chunkSize,
        ua::detail::combined_status(answered, result.status_code()),
        executor,
        std::move(callback));
    });
}

}  // namespace

FileTransferClient::FileTransferClient(std::weak_ptr<detail::WireOps> wireOps,
  boost::asio::any_io_executor executor, ua::Logger logger,
  std::shared_ptr<const std::atomic<std::uint64_t>> sessionGeneration)
  : mWireOps(std::move(wireOps)), mExecutor(std::move(executor)), mLogger(std::move(logger)),
    mSessionGeneration(std::move(sessionGeneration))
{}

void FileTransferClient::open_async(
  ua::NodeId fileNode, FileOpenMode mode, std::function<void(FileHandleResult)> callback) noexcept
{
  // Caller-thread pre-flight (CL-FILE-004): the mode must contain at least one of Read / Write.
  if (!any_set(mode, FileOpenMode::Read | FileOpenMode::Write))
  {
    deliver<FileHandleResult>(mExecutor,
      std::move(callback),
      FileHandleResult{ua::Status::BadInvalidArgument,
        ua::make_error_detail("FileOpenModeInvalid",
          "Open mode requires at least one of Read or Write",
          std::string{openSource})});
    return;
  }
  auto lockedWireOps = mWireOps.lock();
  if (!lockedWireOps)
  {
    deliver<FileHandleResult>(mExecutor,
      std::move(callback),
      FileHandleResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("FileOpenConnectionGone",
          "the Connection was dropped before the file Open could be issued",
          std::string{openSource})});
    return;
  }

  auto flow = std::make_shared<FileOpenFlow>(
    mWireOps,
    mExecutor,
    mLogger,
    std::move(fileNode),
    mode,
    mDefaultMaxByteStringLength,
    mSessionGeneration,
    [](std::shared_ptr<detail::FileHandleState> state) { return FileHandle{std::move(state)}; },
    std::move(callback));
  flow->start();
}

void FileTransferClient::read_all_async(
  ua::NodeId fileNode, std::function<void(ByteStringResult)> callback) noexcept
{
  const std::uint64_t ceiling = mMaxReadAllBytes;
  const boost::asio::any_io_executor executor = mExecutor;
  open_async(std::move(fileNode),
    FileOpenMode::Read,
    [ceiling, executor, callback = std::move(callback)](FileHandleResult handleResult) mutable
    {
      if (!handleResult.has_value())
      {
        deliver<ByteStringResult>(executor,
          std::move(callback),
          ByteStringResult{handleResult.status_code(), handleResult.shared_detail()});
        return;
      }
      ua::StatusCode opened = handleResult.status_code();
      auto handle = std::make_shared<FileHandle>(std::move(handleResult).value());
      auto accumulator = std::make_shared<ua::ByteString>(std::vector<std::uint8_t>{});
      read_all_loop(
        std::move(handle), std::move(accumulator), ceiling, std::move(opened), executor, std::move(callback));
    });
}

void FileTransferClient::write_all_async(
  ua::NodeId fileNode, ua::ByteString data, std::function<void(ua::VoidResult)> callback) noexcept
{
  const boost::asio::any_io_executor executor = mExecutor;
  open_async(std::move(fileNode),
    FileOpenMode::Write | FileOpenMode::EraseExisting,
    [data = std::make_shared<ua::ByteString>(std::move(data)), executor, callback = std::move(callback)](
      FileHandleResult result) mutable
    {
      if (!result.has_value())
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), ua::VoidResult{result.status_code(), result.shared_detail()});
        return;
      }
      ua::StatusCode opened = result.status_code();
      auto handle = std::make_shared<FileHandle>(std::move(result).value());
      write_all_loop(std::move(handle), std::move(data), 0, std::move(opened), executor, std::move(callback));
    });
}

void FileTransferClient::list_directory_async(
  ua::NodeId directoryNode, std::function<void(FileSystemEntryListResult)> callback) noexcept
{
  auto lockedWireOps = mWireOps.lock();
  if (!lockedWireOps)
  {
    deliver<FileSystemEntryListResult>(mExecutor,
      std::move(callback),
      directory_failure<FileSystemEntryListResult>(ua::Status::BadConnectionClosed));
    return;
  }
  const auto executor = mExecutor;
  browse_directory(std::move(lockedWireOps),
    std::move(directoryNode),
    [executor, callback = std::move(callback)](ua::Result<ReferenceList> references) mutable
    {
      if (!references.has_value())
      {
        deliver<FileSystemEntryListResult>(executor,
          std::move(callback),
          directory_failure<FileSystemEntryListResult>(references.status_code()));
        return;
      }
      std::vector<FileSystemEntry> entries;
      for (const auto& reference : references.value())
      {
        if (!reference.node_id().is_local() || !reference.node_id().is_index_based())
        {
          continue;
        }
        FileSystemEntryKind kind;
        const ua::NodeId& typeDefinition = reference.type_definition().node_id();
        if (typeDefinition == ua::NodeId{ua::ObjectTypeId::FileDirectoryType})
        {
          kind = FileSystemEntryKind::Directory;
        }
        else if (typeDefinition == ua::NodeId{ua::ObjectTypeId::FileType})
        {
          kind = FileSystemEntryKind::File;
        }
        else
        {
          continue;
        }
        entries.push_back(FileSystemEntry{
          reference.node_id().node_id(), reference.browse_name(), reference.display_name(), kind});
      }
      // The entries carry the Browse pages' code (a Good subcode or an Uncertain code kept).
      deliver<FileSystemEntryListResult>(
        executor, std::move(callback), ua::detail::held(std::move(entries), references.status_code()));
    });
}

void FileTransferClient::create_directory_async(
  ua::NodeId directoryNode, ua::String name, std::function<void(NodeIdResult)> callback) noexcept
{
  const auto executor = mExecutor;
  const auto wireOps = mWireOps;
  const ua::NodeId resolveNode = directoryNode;
  resolve_directory_method(mWireOps,
    executor,
    resolveNode,
    "CreateDirectory",
    [wireOps,
      executor,
      directoryNode = std::move(directoryNode),
      name = std::move(name),
      callback = std::move(callback)](NodeIdResult method) mutable
    {
      if (!method.is_good())
      {
        deliver<NodeIdResult>(
          executor, std::move(callback), NodeIdResult{method.status_code(), method.shared_detail()});
        return;
      }
      call_directory_method<NodeIdResult>(wireOps,
        executor,
        std::move(directoryNode),
        std::move(method).value(),
        {ua::Variant{std::move(name)}},
        std::move(callback),
        [](const ua::CallMethodResult& result) -> NodeIdResult
        {
          if (result.output_arguments().empty())
          {
            return directory_failure<NodeIdResult>(ua::Status::BadUnexpectedError);
          }
          return result.output_arguments()[0].to<ua::NodeId>();
        });
    });
}

void FileTransferClient::create_file_async(
  ua::NodeId directoryNode, ua::String name, std::function<void(NodeIdResult)> callback) noexcept
{
  const auto executor = mExecutor;
  const auto wireOps = mWireOps;
  const ua::NodeId resolveNode = directoryNode;
  resolve_directory_method(mWireOps,
    executor,
    resolveNode,
    "CreateFile",
    [wireOps,
      executor,
      directoryNode = std::move(directoryNode),
      name = std::move(name),
      callback = std::move(callback)](NodeIdResult method) mutable
    {
      if (!method.is_good())
      {
        deliver<NodeIdResult>(
          executor, std::move(callback), NodeIdResult{method.status_code(), method.shared_detail()});
        return;
      }
      call_directory_method<NodeIdResult>(wireOps,
        executor,
        std::move(directoryNode),
        std::move(method).value(),
        {ua::Variant{std::move(name)}, ua::Variant{false}},
        std::move(callback),
        [](const ua::CallMethodResult& result) -> NodeIdResult
        {
          if (result.output_arguments().empty())
          {
            return directory_failure<NodeIdResult>(ua::Status::BadUnexpectedError);
          }
          return result.output_arguments()[0].to<ua::NodeId>();
        });
    });
}

void FileTransferClient::delete_async(
  ua::NodeId directoryNode, ua::NodeId objectToDelete, std::function<void(ua::VoidResult)> callback) noexcept
{
  const auto executor = mExecutor;
  const auto wireOps = mWireOps;
  const ua::NodeId resolveNode = directoryNode;
  resolve_directory_method(mWireOps,
    executor,
    resolveNode,
    "Delete",
    [wireOps,
      executor,
      directoryNode = std::move(directoryNode),
      objectToDelete = std::move(objectToDelete),
      callback = std::move(callback)](NodeIdResult method) mutable
    {
      if (!method.is_good())
      {
        deliver<ua::VoidResult>(
          executor, std::move(callback), ua::VoidResult{method.status_code(), method.shared_detail()});
        return;
      }
      call_directory_method<ua::VoidResult>(wireOps,
        executor,
        std::move(directoryNode),
        std::move(method).value(),
        {ua::Variant{std::move(objectToDelete)}},
        std::move(callback),
        [](const ua::CallMethodResult&) { return ua::VoidResult{}; });
    });
}

void FileTransferClient::move_or_copy_async(ua::NodeId sourceDirectoryNode, ua::NodeId objectToMoveOrCopy,
  ua::NodeId targetDirectoryNode, bool createCopy, ua::String newName,
  std::function<void(NodeIdResult)> callback) noexcept
{
  const auto executor = mExecutor;
  const auto wireOps = mWireOps;
  const ua::NodeId resolveNode = sourceDirectoryNode;
  resolve_directory_method(mWireOps,
    executor,
    resolveNode,
    "MoveOrCopy",
    [wireOps,
      executor,
      sourceDirectoryNode = std::move(sourceDirectoryNode),
      objectToMoveOrCopy = std::move(objectToMoveOrCopy),
      targetDirectoryNode = std::move(targetDirectoryNode),
      createCopy,
      newName = std::move(newName),
      callback = std::move(callback)](NodeIdResult method) mutable
    {
      if (!method.is_good())
      {
        deliver<NodeIdResult>(
          executor, std::move(callback), NodeIdResult{method.status_code(), method.shared_detail()});
        return;
      }
      call_directory_method<NodeIdResult>(wireOps,
        executor,
        std::move(sourceDirectoryNode),
        std::move(method).value(),
        {ua::Variant{std::move(objectToMoveOrCopy)},
          ua::Variant{std::move(targetDirectoryNode)},
          ua::Variant{createCopy},
          ua::Variant{std::move(newName)}},
        std::move(callback),
        [](const ua::CallMethodResult& result) -> NodeIdResult
        {
          if (result.output_arguments().empty())
          {
            return directory_failure<NodeIdResult>(ua::Status::BadUnexpectedError);
          }
          return result.output_arguments()[0].to<ua::NodeId>();
        });
    });
}

// ---- Sync bridges (section 7.0; MUST NOT run on the executor thread) ----
//
// A throwing form returns the value of a Good answer of its try_ form (ua::detail::good_value); a Good
// subcode on the answer is returned only by the try_ form.

FileHandle FileTransferClient::open_sync(ua::NodeId fileNode, FileOpenMode mode)
{
  return ua::detail::good_value(try_open_sync(std::move(fileNode), mode));
}

FileHandleResult FileTransferClient::try_open_sync(ua::NodeId fileNode, FileOpenMode mode) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<FileHandle>>(mExecutor,
    [this, fileNode = std::move(fileNode), mode](auto completion) mutable
    { open_async(std::move(fileNode), mode, std::move(completion)); });
}

ua::ByteString FileTransferClient::read_all_sync(ua::NodeId fileNode)
{
  return ua::detail::good_value(try_read_all_sync(std::move(fileNode)));
}

ByteStringResult FileTransferClient::try_read_all_sync(ua::NodeId fileNode) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::ByteString>>(mExecutor,
    [this, fileNode = std::move(fileNode)](auto completion) mutable
    { read_all_async(std::move(fileNode), std::move(completion)); });
}

void FileTransferClient::write_all_sync(ua::NodeId fileNode, ua::ByteString data)
{
  try_write_all_sync(std::move(fileNode), std::move(data)).value();
}

ua::VoidResult FileTransferClient::try_write_all_sync(ua::NodeId fileNode, ua::ByteString data) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(mExecutor,
    [this, fileNode = std::move(fileNode), data = std::move(data)](auto completion) mutable
    { write_all_async(std::move(fileNode), std::move(data), std::move(completion)); });
}

std::vector<FileSystemEntry> FileTransferClient::list_directory_sync(ua::NodeId directoryNode)
{
  return ua::detail::good_value(try_list_directory_sync(std::move(directoryNode)));
}

FileSystemEntryListResult FileTransferClient::try_list_directory_sync(ua::NodeId directoryNode) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<FileSystemEntry>>>(mExecutor,
    [this, directoryNode = std::move(directoryNode)](auto completion) mutable
    { list_directory_async(std::move(directoryNode), std::move(completion)); });
}

ua::NodeId FileTransferClient::create_directory_sync(ua::NodeId directoryNode, ua::String name)
{
  return ua::detail::good_value(try_create_directory_sync(std::move(directoryNode), std::move(name)));
}

NodeIdResult FileTransferClient::try_create_directory_sync(ua::NodeId directoryNode, ua::String name) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::NodeId>>(mExecutor,
    [this, directoryNode = std::move(directoryNode), name = std::move(name)](auto completion) mutable
    { create_directory_async(std::move(directoryNode), std::move(name), std::move(completion)); });
}

ua::NodeId FileTransferClient::create_file_sync(ua::NodeId directoryNode, ua::String name)
{
  return ua::detail::good_value(try_create_file_sync(std::move(directoryNode), std::move(name)));
}

NodeIdResult FileTransferClient::try_create_file_sync(ua::NodeId directoryNode, ua::String name) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::NodeId>>(mExecutor,
    [this, directoryNode = std::move(directoryNode), name = std::move(name)](auto completion) mutable
    { create_file_async(std::move(directoryNode), std::move(name), std::move(completion)); });
}

void FileTransferClient::delete_sync(ua::NodeId directoryNode, ua::NodeId objectToDelete)
{
  try_delete_sync(std::move(directoryNode), std::move(objectToDelete)).value();
}

ua::VoidResult FileTransferClient::try_delete_sync(
  ua::NodeId directoryNode, ua::NodeId objectToDelete) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(mExecutor,
    [this, directoryNode = std::move(directoryNode), objectToDelete = std::move(objectToDelete)](
      auto completion) mutable
    { delete_async(std::move(directoryNode), std::move(objectToDelete), std::move(completion)); });
}

ua::NodeId FileTransferClient::move_or_copy_sync(ua::NodeId sourceDirectoryNode,
  ua::NodeId objectToMoveOrCopy, ua::NodeId targetDirectoryNode, bool createCopy, ua::String newName)
{
  return ua::detail::good_value(try_move_or_copy_sync(std::move(sourceDirectoryNode),
    std::move(objectToMoveOrCopy),
    std::move(targetDirectoryNode),
    createCopy,
    std::move(newName)));
}

NodeIdResult FileTransferClient::try_move_or_copy_sync(ua::NodeId sourceDirectoryNode,
  ua::NodeId objectToMoveOrCopy, ua::NodeId targetDirectoryNode, bool createCopy, ua::String newName) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::NodeId>>(mExecutor,
    [this,
      sourceDirectoryNode = std::move(sourceDirectoryNode),
      objectToMoveOrCopy = std::move(objectToMoveOrCopy),
      targetDirectoryNode = std::move(targetDirectoryNode),
      createCopy,
      newName = std::move(newName)](auto completion) mutable
    {
      move_or_copy_async(std::move(sourceDirectoryNode),
        std::move(objectToMoveOrCopy),
        std::move(targetDirectoryNode),
        createCopy,
        std::move(newName),
        std::move(completion));
    });
}

}  // namespace ua::client
