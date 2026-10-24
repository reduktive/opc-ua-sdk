// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_browse_service.h"
#include "ua_access_control.h"
#include "ua_on_strand.h"
#include "ua_address_space.h"
#include "ua_binary_codec.h"
#include "ua_callback_safety.h"
#include "ua_diagnostic_collector.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_log_exception.h"
#include "ua_memory_stream.h"
#include "ua_namespace.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_variant.h"
#include "ua_server.h"
#include "ua_server_encoding_limits.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_service_fault.h"
#include "ua_service_request_info.h"
#include "ua_stack_utilities.h"
#include "ua_status_routing.h"
#include "ua_subtype_facts.h"
#include "ua_structure_factory.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include "fmt/format.h"

#include <algorithm>
#include <array>
#include <bitset>
#include <boost/asio/post.hpp>
#include <chrono>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua::server
{

namespace
{

class NodeClassMask
{
public:
  using BitSet = std::bitset<utils::no_of_bits<uint32_t>()>;

  explicit NodeClassMask(uint32_t bitMask) : mBitMask(bitMask)
  {}

  bool is_set(NodeClass nodeClass)
  {
    if (!mBitMask.any())
    {
      return true;
    }

    const BitSet value{numeric_cast<uint32_t>(utils::to_underlying(nodeClass))};
    auto result = value & mBitMask;

    return result.any();
  }

private:
  BitSet mBitMask;
};

class ResultMask
{
public:
  enum class Bit : uint32_t
  {
    ReferenceType = 0,
    IsForward = 1,
    NodeClass = 2,
    BrowseName = 3,
    DisplayName = 4,
    TypeDefinition = 5
  };

  explicit ResultMask(uint32_t bitMask) : mBitMask(bitMask)
  {}

  bool is_set(Bit bit) const
  {
    return mBitMask.test(utils::to_underlying(bit));
  }

private:
  std::bitset<utils::no_of_bits<uint32_t>()> mBitMask;
};

}  // namespace

// =============================================================================================
// What one unit of work carries (private to this translation unit)
// =============================================================================================
//
// What one operation carries into the rounds that answer it: its own request, and where a BrowseNext
// resumes it. Everything a round learns about it lives in the rounds' own frame.

struct BrowseOperation
{
  size_t opIndex{0};
  /// The view this item browses under. Request-wide for a Browse; carried per continuation point for
  /// a BrowseNext, which is why it lives here and not on the service.
  ViewDescription view;
  uint32_t maxRefsPerNode{0};
  BrowseDescription nodeToBrowse;
  /// The namespace's position: the token of its last answer, passed back with the next read. A token
  /// the operation never passes back is released through the namespace that issued it.
  ua::detail::ResumeToken token;
  /// References read and not yet examined: the tail a continuation point carried, replayed before the
  /// namespace is read again.
  References tail;
  /// Whether the namespace has no more References for this operation: a BrowseNext of a point that holds
  /// no token, or an answer that gave none.
  bool exhausted{false};
  ua::EncodingLimits limits;
};

namespace browse_detail
{

/// What a paused Browse operation produced, kept until the BrowseNext that continues it takes it.
struct BrowseOutcome
{
  BrowseResult result;
  std::optional<BrowseContinuationPoint> continuationPoint;
  std::vector<shared_ptr<const ErrorDetail>> details;
};

/// A Browse operation answered for at the partial-result deadline and still running in the service that
/// started it. @see PausedOperation
using PausedBrowse = PausedResult<BrowseOutcome>;

}  // namespace browse_detail

using browse_detail::BrowseOutcome;
using browse_detail::PausedBrowse;

/// One item of the request: what its operation has written so far and where that goes when it ends.
struct BrowseService::StagedItem
{
  enum class State
  {
    /// Not an operation (answered while the request was prepared), or finished and delivered.
    Answered,
    /// Its operation is running and its result will go into the response.
    Running,
    /// Answered with a continuation point at the partial-result deadline; its operation's result goes
    /// to that point.
    Paused,
    /// Answered at the timeoutHint while still running; whatever it produces later is dropped.
    Abandoned,
  };

  State state{State::Answered};
  BrowseResult result;
  std::optional<BrowseContinuationPoint> continuationPoint;
  std::vector<shared_ptr<const ErrorDetail>> details;

  /// What a continuation point handed out for this item names.
  ViewDescription view;
  uint32_t maxRefsPerNode{0};
  BrowseDescription browseDescription;
  /// BrowseNext only: the earlier paused operation this item continues.
  shared_ptr<PausedBrowse> waitingOn;
  /// The paused operation a continuation point now holds for this item, when Paused.
  shared_ptr<PausedBrowse> paused;
  /// Whether this request's own operation produces that outcome (false when a BrowseNext pauses again
  /// an operation another request started).
  bool ownsPaused{false};
  /// Browse only: still running at the deadline with no continuation point left for it; awaited until
  /// the timeoutHint and then answered Bad_NoContinuationPoints (OPC 10000-4 section 7.9).
  bool awaitingContinuationPoint{false};

  /// Marks the item as running, with what a continuation point for it would carry.
  void begin(const ViewDescription& itemView, uint32_t itemMaxRefsPerNode,
    const BrowseDescription& itemBrowseDescription)
  {
    state = State::Running;
    view = itemView;
    maxRefsPerNode = itemMaxRefsPerNode;
    browseDescription = itemBrowseDescription;
  }
};

// =============================================================================================
// Construction / destruction
// =============================================================================================

shared_ptr<BrowseService> BrowseService::create(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, BrowseRequest&& browseRequest,
  boost::asio::any_io_executor executor, BrowseServiceCallComplete callback)
{
  struct Wrapper : public BrowseService
  {
    Wrapper(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
      BrowseRequest&& browseRequest, boost::asio::any_io_executor executor,
      BrowseServiceCallComplete callback)
      : BrowseService(
          sessionInfo, std::move(sessionLocales), requestId, std::move(browseRequest), executor, callback)
    {}
  };

  auto browseService = make_shared<Wrapper>(
    sessionInfo, sessionLocales, requestId, std::move(browseRequest), executor, callback);
  browseService->start();
  return browseService;
}

shared_ptr<BrowseService> BrowseService::create(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, BrowseNextRequest&& browseNextRequest,
  BrowseContinuationPoints& continuationPoints, boost::asio::any_io_executor executor,
  BrowseServiceCallComplete callback)
{
  struct Wrapper : public BrowseService
  {
    Wrapper(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
      BrowseNextRequest&& browseNextRequest, BrowseContinuationPoints& continuationPoints,
      boost::asio::any_io_executor executor, BrowseServiceCallComplete callback)
      : BrowseService(sessionInfo, sessionLocales, requestId, std::move(browseNextRequest),
          continuationPoints, executor, callback)
    {}
  };

  auto browseService = make_shared<Wrapper>(sessionInfo,
    sessionLocales,
    requestId,
    std::move(browseNextRequest),
    continuationPoints,
    executor,
    callback);
  browseService->start();
  return browseService;
}

BrowseService::BrowseService(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales,
  uint32_t requestId, BrowseRequest&& browseRequest, boost::asio::any_io_executor executor,
  BrowseServiceCallComplete callback)
  : ServiceBase(browseRequest.request_header().request_handle(), sessionInfo, executor),
    mSessionLocales(std::move(sessionLocales)), mRequestId(requestId),
    mBrowseRequest(std::move(browseRequest)), mServiceCallCompleteCallback(callback),
    mCancelled(std::make_shared<std::atomic_bool>(false))
{}

BrowseService::BrowseService(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales,
  uint32_t requestId, BrowseNextRequest&& browseNextRequest, BrowseContinuationPoints& continuationPoints,
  boost::asio::any_io_executor executor, BrowseServiceCallComplete callback)
  : ServiceBase(browseNextRequest.request_header().request_handle(), sessionInfo, executor),
    mSessionLocales(std::move(sessionLocales)), mRequestId(requestId),
    mBrowseNextRequest(std::move(browseNextRequest)), mServiceCallCompleteCallback(callback),
    mCancelled(std::make_shared<std::atomic_bool>(false))
{
  retrieve_continuation_points(continuationPoints);
}

BrowseService::~BrowseService() = default;

// =============================================================================================
// Top-level Browse flow
// =============================================================================================

void BrowseService::begin_processing()
{
  mBrowseMode = mBrowseRequest ? Mode::Browse : Mode::BrowseNext;
  mBrowseRequestTask = run_browse_request();
}

const RequestHeader& BrowseService::active_request_header() const
{
  // Exactly one of the two is engaged - the constructors guarantee it - and the caller is entitled
  // to a header, so the impossible case is the internal error it is rather than a silent default.
  if (mBrowseRequest)
  {
    return mBrowseRequest->request_header();
  }
  if (mBrowseNextRequest)
  {
    return mBrowseNextRequest->request_header();
  }
  throw UaException{Status::BadInternalError, nullptr};
}

Array<BrowseResult>& BrowseService::browse_results()
{
  return (mBrowseMode == Mode::Browse) ? mBrowseResponse->results() : mBrowseNextResponse->results();
}

ResponseHeader& BrowseService::browse_response_header()
{
  return (mBrowseMode == Mode::Browse) ? mBrowseResponse->response_header()
                                       : mBrowseNextResponse->response_header();
}

Array<DiagnosticInfo>& BrowseService::browse_diagnostic_infos()
{
  return (mBrowseMode == Mode::Browse) ? mBrowseResponse->diagnostic_infos()
                                       : mBrowseNextResponse->diagnostic_infos();
}

/// The operations and waits one request has to run.
struct BrowseService::BrowseWork
{
  std::vector<BrowseOperation> operations;
  /// BrowseNext items continuing an operation an earlier request paused.
  std::vector<BrowseWait> waits;
};

struct BrowseService::BrowseWait
{
  size_t index{0};
};

ua::async::Task<> BrowseService::run_browse_request()
{
  // This task is a root - nobody awaits it - so an exception that escapes is stored in the promise
  // and read by nobody, and the request never answers.
  try
  {
    co_await dispatch_browse_request();
    // Completed HERE, not inside the body: the body has several early exits - nothing to browse,
    // every continuation point invalid, a release-only BrowseNext - and every one of them still owes
    // the client a response.
    complete_browse();
  }
  catch (const ua::async::Abandoned&)
  {
    // The request was withdrawn while this was suspended: cancelled, timed out, or failed at the
    // service level by one of its own operations. Whoever withdrew it answered the client.
    ::ua::detail::ignore_expected_exception();
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        if (auto sessionInfo = mSessionInfo.lock())
        {
          log_exception(sessionInfo->logger().with_category("service"),
            LogLevel::Error,
            (mBrowseMode == Mode::Browse) ? "BrowseService" : "BrowseNextService",
            er);
        }
        fail_browse(VoidResult{er, er.shared_detail()});
      })();
  }
}

ua::async::Task<> BrowseService::dispatch_browse_request()
{
  BrowseWork work;

  // The session is locked, used and released BEFORE anything suspends: held across a co_await, it would
  // live in this frame for the request's whole life, and the session transitively owns this service.
  {
    auto sessionInfo = mSessionInfo.lock();

    // Built BEFORE the checks below, because a throw from any of them is answered with this collector.
    mBrowseCollector = DiagnosticCollector{active_request_header().return_diagnostics(),
      sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

    check(sessionInfo);
    set_timeout();
    // Browse answers part of a request at its partial-result deadline (OPC 10000-4 5.8.2.1), so every
    // namespace call carries that deadline as answerBy.
    mRequestInfo = service_request_info(std::chrono::steady_clock::now(),
      active_request_header().timeout_hint(),
      mPartialResultDeadline,
      mNamespaceCallsCancelled,
      mSessionLocales);

    mBrowseAddressSpace = sessionInfo->address_space();
    mBrowseAccessControl = SessionAccessControl::create(*sessionInfo);

    work = (mBrowseMode == Mode::Browse) ? prepare_browse_work(*sessionInfo)
                                         : prepare_browse_next_work(*sessionInfo);
  }

  if (work.operations.empty() && work.waits.empty())
  {
    // An empty request was already rejected. Invalid points have their operation results;
    // a release-only BrowseNext has its required empty response arrays.
    co_return;
  }

  // The waits start first: each only awaits the outcome of the operation it continues, which another
  // request is running, so they wait while this request's own operations are answered.
  std::vector<ua::async::Task<>> waitTasks;
  std::vector<size_t> waitIndexes;
  waitTasks.reserve(work.waits.size());
  for (const auto& wait : work.waits)
  {
    try
    {
      waitTasks.push_back(await_paused_outcome(wait));
      waitIndexes.push_back(wait.index);
    }
    catch (...)
    {
      // What the CALL itself threw - frame allocation, the push_back - never the body. Nothing is in
      // flight for this item, so it is settled here.
      record_browse_failure(wait.index, ua::exception_to_status_code(std::current_exception()));
    }
  }

  if (!work.operations.empty())
  {
    co_await browse_in_rounds(std::move(work.operations));
  }

  for (auto& task : waitTasks)
  {
    try
    {
      // `operator co_await` is &&-qualified, so awaiting the same task twice has to be written out
      // rather than happening by accident. The move hands over the handle; the vector still owns the
      // frame.
      co_await std::move(task);
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      // Each wait contains its own failures; nothing reaches here but a defect, which is logged rather
      // than allowed to answer for an item.
      log_exception(mLogger.with_category("service"),
        LogLevel::Error,
        "BrowseService",
        ua::exception_to_status_code(std::current_exception()));
    }
  }
  if (!waitIndexes.empty())
  {
    co_await reauthorize_waits(std::move(waitIndexes));
  }
  co_return;
}

void BrowseService::record_browse_failure(size_t opIndex, StatusCode status)
{
  if (opIndex >= mStaged.size())
  {
    return;
  }
  staged_result(opIndex).status_code() = status;
  if (status.shared_detail())
  {
    stage_detail(opIndex, status.shared_detail());
  }
  finish_item(opIndex);
}

// =============================================================================================
// Items: staging, finishing, and the partial-result deadline
// =============================================================================================

BrowseResult& BrowseService::staged_result(size_t index)
{
  return mStaged.at(index).result;
}

void BrowseService::stage_detail(size_t index, shared_ptr<const ErrorDetail> detail)
{
  if (detail && index < mStaged.size())
  {
    mStaged[index].details.push_back(std::move(detail));
  }
}

void BrowseService::stage_continuation_point(size_t index, BrowseContinuationPoint continuationPoint)
{
  if (index < mStaged.size())
  {
    mStaged[index].continuationPoint.emplace(std::move(continuationPoint));
  }
}

void BrowseService::finish_item(size_t index)
{
  if (index >= mStaged.size())
  {
    return;
  }
  auto& item = mStaged[index];
  switch (item.state)
  {
  case StagedItem::State::Running:
  {
    item.state = StagedItem::State::Answered;
    // Running and already answered happens only when the request failed or was cancelled as a
    // whole; the response that went out was a fault, and this item's result has nowhere to go.
    if (mFinished)
    {
      return;
    }
    browse_results()[index] = std::move(item.result);
    for (auto& detail : item.details)
    {
      mBrowseCollector.add_item_detail(index, std::move(detail));
    }
    item.details.clear();
    if (item.continuationPoint)
    {
      mBrowseServiceResponse.continuationPoints.emplace_back(std::move(*item.continuationPoint));
      item.continuationPoint.reset();
    }
    return;
  }
  case StagedItem::State::Paused:
  {
    item.state = StagedItem::State::Answered;
    if (item.ownsPaused && item.paused)
    {
      auto owner = item.paused->complete(
        BrowseOutcome{std::move(item.result), std::move(item.continuationPoint), std::move(item.details)});
      // The owner is this service. Letting it go here could destroy the frame this runs in, so the
      // last reference is dropped by a handler that runs after this one returns.
      if (owner)
      {
        boost::asio::post(mStrand, ua::async::guarded(mLogger, [owner = std::move(owner)] {}));
      }
    }
    item.paused.reset();
    return;
  }
  case StagedItem::State::Answered:
  case StagedItem::State::Abandoned:
    return;
  }
}

ua::async::Task<> BrowseService::await_paused_outcome(BrowseWait wait)
{
  const size_t index = wait.index;
  const auto paused = mStaged[index].waitingOn;
  if (!paused)
  {
    co_return;
  }
  // Resumed on this service's strand once the operation another request started has its outcome. The
  // outcome is left where it is: if this request's partial-result deadline comes first, the item is
  // handed to a new continuation point together with the operation it waits on.
  co_await await_step<bool>(
    [paused](auto completion)
    {
      auto shared = std::make_shared<decltype(completion)>(std::move(completion));
      paused->when_done([shared] { (*shared)(true); });
    });
}

ua::async::Task<> BrowseService::reauthorize_waits(std::vector<size_t> indexes)
{
  // Each outcome is taken by this request unless the partial-result deadline handed the item to a new
  // continuation point first, which then owns the outcome. From here the outcome is this request's: if the
  // deadline comes during the checks below, the item is paused with a point of its own, which finish_item
  // completes.
  std::vector<size_t> ready;
  ready.reserve(indexes.size());
  for (const size_t index : indexes)
  {
    auto& item = mStaged[index];
    if (item.state != StagedItem::State::Running)
    {
      continue;
    }
    auto paused = std::move(item.waitingOn);
    std::optional<BrowseOutcome> outcome;
    if (paused)
    {
      outcome = paused->take();
    }
    if (outcome)
    {
      item.result = std::move(outcome->result);
      item.continuationPoint = std::move(outcome->continuationPoint);
      item.details = std::move(outcome->details);
    }
    else
    {
      item.result.status_code() = StatusCode{Status::BadContinuationPointInvalid};
    }
    if (item.result.status_code().is_bad())
    {
      finish_item(index);
      continue;
    }
    ready.push_back(index);
  }
  if (ready.empty())
  {
    co_return;
  }

  // Authorized again, as every continuation is: the Session's identity, or the Node's permissions, may
  // have changed since the operation started. The source must still be browsable, and every Reference
  // must still pass Browse on its target (SVR-AUTHZ-010). The sources are looked up with one call per
  // namespace and authorized with one.
  std::vector<ua::detail::LookupItem> lookups;
  lookups.reserve(ready.size());
  for (const size_t index : ready)
  {
    lookups.push_back(ua::detail::LookupItem{mStaged[index].browseDescription.node_id(), std::nullopt});
  }
  const WeakAddressSpace weakAddressSpace = mBrowseAddressSpace->weak();
  auto sources = co_await await_step<BatchResult<NodeAccessorResult>>(
    [this, &weakAddressSpace, &lookups](auto completion)
    {
      ua::detail::NodeAccessorRoute::find_nodes(
        weakAddressSpace, mRequestInfo, lookups, std::move(completion));
    });

  std::vector<StatusCode> denials(ready.size(), StatusCode{Status::Good});
  std::vector<AccessControl::Item> subjects;
  std::vector<size_t> subjectOf;
  for (size_t k = 0; k < ready.size(); ++k)
  {
    if (sources.batchStatus.is_bad())
    {
      denials[k] = sources.batchStatus.status_code();
    }
    else if (k >= sources.items.size())
    {
      denials[k] = StatusCode{Status::BadInternalError};
    }
    else if (!sources.items[k].is_good())
    {
      denials[k] = sources.items[k].status_code();
    }
    else if (!mBrowseAccessControl)
    {
      denials[k] = StatusCode{Status::BadUserAccessDenied};
    }
    else
    {
      subjects.push_back(AccessControl::Item{sources.items[k].value(), AccessOperation::Browse});
      subjectOf.push_back(k);
    }
  }
  if (!subjects.empty())
  {
    auto verdicts =
      co_await await_step<std::vector<AccessControl::Verdict>>([this, &subjects](auto completion)
        { mBrowseAccessControl->authorize_async(mRequestInfo, subjects, std::move(completion)); });
    for (size_t s = 0; s < subjectOf.size(); ++s)
    {
      if (s >= verdicts.size())
      {
        // A short verdict list authorizes nothing (SVR-AUTHZ-015).
        denials[subjectOf[s]] = StatusCode{Status::BadInternalError};
      }
      else if (!verdicts[s].permitted)
      {
        denials[subjectOf[s]] = verdicts[s].cause;
      }
    }
  }

  std::vector<size_t> permitted;
  std::vector<Array<ReferenceDescription>> references;
  for (size_t k = 0; k < ready.size(); ++k)
  {
    const size_t index = ready[k];
    if (!denials[k].is_good())
    {
      auto& result = staged_result(index);
      result = BrowseResult{};
      result.status_code() = denials[k];
      stage_detail(index, denials[k].shared_detail());
      mStaged[index].continuationPoint.reset();  // released with it
      finish_item(index);
      continue;
    }
    permitted.push_back(index);
    references.push_back(std::move(staged_result(index).references()));
  }
  if (permitted.empty())
  {
    co_return;
  }

  auto kept = co_await reauthorize_targets(std::move(references));
  for (size_t k = 0; k < permitted.size(); ++k)
  {
    if (k < kept.size())
    {
      staged_result(permitted[k]).references() = std::move(kept[k]);
    }
    finish_item(permitted[k]);
  }
}

void BrowseService::answer_at_partial_result_deadline()
{
  if (mFinished)
  {
    return;
  }

  // Browse hands out continuation points within what the Session may hold (OPC 10000-4 section 7.9:
  // operations are processed until the maximum number of continuation points is used). BrowseNext
  // continues operations that already hold one, and section 7.9 forbids Bad_NoContinuationPoints when
  // continuing, so it is not limited here.
  size_t allowance = std::numeric_limits<size_t>::max();
  if (mBrowseMode == Mode::Browse)
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      const size_t maxContinuationPoints =
        sessionInfo->server_configuration().server_capabilities().maxBrowseContinuationPoints;
      const size_t held = mBrowseServiceResponse.continuationPoints.size();
      allowance = held < maxContinuationPoints ? maxContinuationPoints - held : 0;
    }
  }

  bool waitingForContinuationPoint = false;
  for (size_t index = 0; index < mStaged.size(); ++index)
  {
    auto& item = mStaged[index];
    if (item.state != StagedItem::State::Running)
    {
      continue;
    }
    if (allowance == 0)
    {
      item.awaitingContinuationPoint = true;
      waitingForContinuationPoint = true;
      continue;
    }
    pause_item(index);
    --allowance;
  }

  if (!waitingForContinuationPoint)
  {
    complete_browse();
  }
}

void BrowseService::pause_item(size_t index)
{
  auto& item = mStaged[index];
  shared_ptr<PausedBrowse> paused;
  if (item.waitingOn)
  {
    // A BrowseNext still waiting: the operation keeps running where it started; the new point takes
    // over the wait.
    paused = item.waitingOn;
    item.ownsPaused = false;
  }
  else
  {
    // The namespace calls this request makes are told to stop once nobody wants any of its paused
    // operations (API-10.4).
    mPausedCalls->add_paused_item();
    paused = std::make_shared<PausedBrowse>(
      shared_from_this(), [calls = mPausedCalls] { calls->release_paused_item(); });
    item.ownsPaused = true;
  }

  BrowseContinuationPoint continuationPoint{item.view, item.maxRefsPerNode, item.browseDescription, paused};
  auto bytes = continuationPoint.identifier().as_ua_binary();
  auto& slot = browse_results()[index];
  slot = BrowseResult{};
  slot.status_code() = StatusCode{Status::Good};
  slot.continuation_point() = ByteString{span<const byte>{bytes}};
  mBrowseServiceResponse.continuationPoints.emplace_back(std::move(continuationPoint));

  item.state = StagedItem::State::Paused;
  item.paused = std::move(paused);
}

void BrowseService::cancel_all_calls()
{
  if (mCancelled)
  {
    mCancelled->store(true);
  }
  mNamespaceCallsCancelled->store(true);
}

void BrowseService::release_unfinished_waits()
{
  for (auto& item : mStaged)
  {
    if (item.waitingOn && item.state != StagedItem::State::Paused)
    {
      item.waitingOn->release();
      item.waitingOn.reset();
    }
  }
}

namespace
{
/// SVC-12: the page size one operation (or continuation point) of a request may use once the
/// whole-request reference budget is split over its `operations`. 0 means "no client limit" on input
/// and is replaced by the share; a nullopt budget leaves the input unchanged.
uint32_t apply_request_reference_budget(
  uint32_t pageSize, size_t operations, const ua::server::SessionInfo& sessionInfo)
{
  const auto budget = sessionInfo.server_configuration().maxReferencesPerBrowseRequest;
  if (!budget || operations == 0)
    return pageSize;
  const auto share = std::max<uint32_t>(1, *budget / numeric_cast<uint32_t>(operations));
  return (pageSize == 0 || pageSize > share) ? share : pageSize;
}
}  // namespace

BrowseService::BrowseWork BrowseService::prepare_browse_work(SessionInfo& sessionInfo)
{
  auto& browseRequest = *mBrowseRequest;
  const size_t noOfOperations{browseRequest.nodes_to_browse().size()};
  if (noOfOperations == 0)
  {
    throw UaException{Status::BadNothingToDo,
      make_error_detail("EmptyBrowseRequest", "Browse request contains no nodes to browse", "BrowseService")};
  }

  auto& maxNodesPerBrowse =
    sessionInfo.server_configuration().server_capabilities().operationLimits.maxNodesPerBrowse;
  if (maxNodesPerBrowse && (noOfOperations > maxNodesPerBrowse.value()))
  {
    throw UaException{Status::BadTooManyOperations,
      ErrorDetail::build("TooManyNodesToBrowse",
        "Requested number of nodes to browse exceeds the server operation limit",
        "BrowseService")
        .context(ua::ContextKeys::sizeActual, std::to_string(noOfOperations))
        .context(ua::ContextKeys::sizeMax, std::to_string(maxNodesPerBrowse.value()))};
  }

  auto& view = browseRequest.view();
  if (view.view_version() != 0 && !view.timestamp().is_null())
  {
    throw UaException{Status::BadInvalidArgument,
      make_error_detail("InvalidViewDescription",
        "ViewDescription: view_version and timestamp are mutually exclusive",
        "BrowseService")};
  }

  mBrowseResponse = make_shared<BrowseResponse>();
  mBrowseResponse->results().resize(noOfOperations);
  mBrowseServiceResponse.response = std::pair(mRequestId, mBrowseResponse);
  mStaged.resize(noOfOperations);

  // Clamp the per-node reference page size to the server ceiling. The `requestedMaxReferencesPerNode
  // == 0` sentinel ("no Client limit") would otherwise return a node's entire reference list as one
  // page with no continuation point, bypassing the MaxBrowseContinuationPoints throttle and building
  // an unbounded outbound array. Treat 0 as "use the server ceiling" and clamp an over-large explicit
  // request down to it. A nullopt ceiling preserves the legacy unlimited behaviour.
  auto maxRefsPerNode = browseRequest.requested_max_references_per_node();
  if (const auto ceiling = sessionInfo.server_configuration().maxReferencesPerNode)
  {
    if (maxRefsPerNode == 0 || maxRefsPerNode > *ceiling)
    {
      maxRefsPerNode = *ceiling;
    }
  }
  // SVC-12: the per-node ceiling bounds one operation only; a request naming the same high-fan-in node
  // MaxNodesPerBrowse times multiplied it. The whole-request budget is split deterministically over the
  // operations (they run concurrently, so a shared running total would be order-dependent): each gets
  // budget / operations and the continuation-point path pages the rest. validate() keeps the budget at
  // or above MaxNodesPerBrowse, so the share is never below one; the floor is defensive. Cost: one
  // division.
  maxRefsPerNode = apply_request_reference_budget(maxRefsPerNode, noOfOperations, sessionInfo);

  const auto limits =
    ua::server::make_server_encoding_limits(sessionInfo.configuration(), sessionInfo.server_configuration());

  BrowseWork work;
  work.operations.reserve(noOfOperations);
  for (size_t idx = 0; idx < noOfOperations; ++idx)
  {
    BrowseOperation operation;
    operation.opIndex = idx;
    operation.view = view;
    operation.maxRefsPerNode = maxRefsPerNode;
    operation.nodeToBrowse = browseRequest.nodes_to_browse()[idx];
    operation.limits = limits;
    mStaged[idx].begin(view, maxRefsPerNode, operation.nodeToBrowse);
    work.operations.push_back(std::move(operation));
  }

  return work;
}

BrowseService::BrowseWork BrowseService::prepare_browse_next_work(SessionInfo& sessionInfo)
{
  auto& browseNextRequest = *mBrowseNextRequest;
  const size_t noOfOperations{browseNextRequest.continuation_points().size()};
  if (noOfOperations == 0)
  {
    throw UaException{Status::BadNothingToDo,
      make_error_detail(
        "EmptyBrowseNextRequest", "BrowseNext request contains no continuation points", "BrowseService")};
  }

  auto& maxNodesPerBrowse =
    sessionInfo.server_configuration().server_capabilities().operationLimits.maxNodesPerBrowse;
  if (maxNodesPerBrowse && (noOfOperations > maxNodesPerBrowse.value()))
  {
    throw UaException{Status::BadTooManyOperations,
      ErrorDetail::build("TooManyBrowseNextOperations",
        "Requested number of continuation points exceeds the server operation limit",
        "BrowseService")
        .context(ua::ContextKeys::sizeActual, std::to_string(noOfOperations))
        .context(ua::ContextKeys::sizeMax, std::to_string(maxNodesPerBrowse.value()))};
  }

  mBrowseNextResponse = make_shared<BrowseNextResponse>();
  mBrowseServiceResponse.response = std::pair(mRequestId, mBrowseNextResponse);

  BrowseWork work;

  if (browseNextRequest.release_continuation_points())
  {
    // Part 4 section 5.8.3.2 requires empty results and diagnosticInfos on release.
    // retrieve_continuation_points already removed known named points from the session store.
    // Unknown, malformed and duplicate points add no per-operation release results.
    // Released now: each point releases the resume token it holds through the namespace that issued it,
    // and the paused operation it holds.
    mContinuationPointsIn.clear();
    return work;
  }

  mBrowseNextResponse->results().resize(noOfOperations);
  mStaged.resize(noOfOperations);

  const auto limits =
    ua::server::make_server_encoding_limits(sessionInfo.configuration(), sessionInfo.server_configuration());

  work.operations.reserve(noOfOperations);

  for (size_t i = 0; i < noOfOperations; ++i)
  {
    Guid guid;
    try
    {
      guid.from_ua_binary(browseNextRequest.continuation_points()[i]);
    }
    catch (...)
    {
      // A point that fails to decode (e.g. not a 16-byte Guid) is an invalid continuation point -
      // Bad_ContinuationPointInvalid (Part 4 5.8.3), not the raw Bad_DecodingError. The decode detail
      // is kept for the server-side diagnostic trail.
      auto er = ua::exception_to_status_code(std::current_exception());
      mBrowseNextResponse->results()[i].status_code() = StatusCode{Status::BadContinuationPointInvalid};
      if (er.shared_detail())
      {
        mBrowseCollector.add_item_detail(i, er.shared_detail());
      }
      continue;
    }

    auto cp = std::ranges::find_if(mContinuationPointsIn,
      [&guid](const BrowseContinuationPoint& entry) { return entry.identifier() == guid; });
    if (cp == mContinuationPointsIn.end())
    {
      mBrowseNextResponse->results()[i].status_code() = StatusCode{Status::BadContinuationPointInvalid};
      continue;
    }

    // A point handed out at an earlier request's partial-result deadline: its operation is still
    // running (or has finished) there, and this item waits for its outcome.
    if (auto paused = cp->take_paused())
    {
      auto& item = mStaged[i];
      item.begin(cp->view_description(), cp->max_refs_per_node(), cp->browse_description());
      item.waitingOn = std::static_pointer_cast<PausedBrowse>(std::move(paused));
      work.waits.push_back(BrowseWait{i});
      continue;
    }

    // SVC-12: BrowseNext shares the request budget over its continuation points as Browse does over its
    // operations; a point replays the page size it was created with, capped by this request's share.
    const uint32_t nextPage =
      apply_request_reference_budget(cp->max_refs_per_node(), noOfOperations, sessionInfo);

    BrowseOperation operation;
    operation.opIndex = i;
    operation.view = cp->view_description();
    operation.maxRefsPerNode = nextPage;
    operation.nodeToBrowse = cp->browse_description();
    operation.exhausted = !cp->has_resume_token();
    operation.token = cp->take_resume_token();
    operation.tail = cp->buffered_references();
    operation.limits = limits;
    mStaged[i].begin(operation.view, nextPage, operation.nodeToBrowse);
    work.operations.push_back(std::move(operation));
  }

  return work;
}

// =============================================================================================
// The targets of a continued operation, authorized again
// =============================================================================================

ua::async::Task<std::vector<Array<ReferenceDescription>>> BrowseService::reauthorize_targets(
  std::vector<Array<ReferenceDescription>> references)
{
  auto addressSpace = *mBrowseAddressSpace;

  struct TargetOf
  {
    size_t item{0};
    size_t reference{0};
  };

  std::vector<ua::detail::LookupItem> lookups;
  std::vector<TargetOf> targetOf;
  for (size_t i = 0; i < references.size(); ++i)
  {
    for (size_t k = 0; k < references[i].size(); ++k)
    {
      auto& targetId = references[i][k].node_id();
      if (!targetId.is_local())
      {
        continue;
      }
      if (targetId.is_not_index_based())
      {
        // Normalised as when the Reference was first returned; a URI the server does not carry cannot
        // address a local Node, so the Reference is kept as it came.
        uint16_t nsIndex{0};
        try
        {
          nsIndex = addressSpace.namespace_array().get_namespace_index(targetId.namespace_uri());
        }
        catch (const UaException&)
        {
          continue;
        }
        targetId.namespace_uri().clear();
        targetId.node_id().namespace_index() = nsIndex;
      }
      lookups.push_back(ua::detail::LookupItem{targetId.node_id(), std::nullopt});
      targetOf.push_back(TargetOf{i, k});
    }
  }
  if (lookups.empty())
  {
    co_return references;
  }

  const WeakAddressSpace weakAddressSpace = addressSpace.weak();
  auto targetBatch = co_await await_step<BatchResult<NodeAccessorResult>>(
    [this, &weakAddressSpace, &lookups](auto completion)
    {
      ua::detail::NodeAccessorRoute::find_nodes(
        weakAddressSpace, mRequestInfo, lookups, std::move(completion));
    });

  std::vector<AccessControl::Item> subjects;
  std::vector<size_t> subjectOf;
  subjects.reserve(targetOf.size());
  subjectOf.reserve(targetOf.size());
  std::vector<std::vector<bool>> denied(references.size());
  for (size_t i = 0; i < references.size(); ++i)
    denied[i].assign(references[i].size(), false);
  for (size_t k = 0; k < targetOf.size(); ++k)
  {
    const auto& at = targetOf[k];
    denied[at.item][at.reference] = true;
    if (targetBatch.batchStatus.is_good() && k < targetBatch.items.size() && targetBatch.items[k].is_good())
    {
      subjects.push_back(AccessControl::Item{targetBatch.items[k].value(), AccessOperation::Browse});
      subjectOf.push_back(k);
      continue;
    }
    if (targetBatch.batchStatus.is_good() && k < targetBatch.items.size() &&
        targetBatch.items[k].status_code() == StatusCode{Status::BadNodeIdUnknown})
    {
      // A definitively absent target retains the documented dangling-reference fallback.
      denied[at.item][at.reference] = false;
      continue;
    }
    const auto status = !targetBatch.batchStatus.is_good() ? targetBatch.batchStatus.status_code()
                        : k < targetBatch.items.size() ? targetBatch.items[k].status_code()
                                                      : StatusCode{Status::BadInternalError,
                                                          ErrorDetail::build("BrowseTargetLookupIncomplete",
                                                            "The local reference target lookup did not return an answer",
                                                            "BrowseService")
                                                            .context(ua::ContextKeys::nodeId, lookups[k].nodeId)};
    log_exception(mLogger, LogLevel::Warning, "Browse continuation target lookup failed", status);
  }
  if (!subjects.empty())
  {
    auto verdicts =
      co_await await_step<std::vector<AccessControl::Verdict>>([this, &subjects](auto completion)
        { mBrowseAccessControl->authorize_async(mRequestInfo, subjects, std::move(completion)); });
    for (size_t s = 0; s < subjectOf.size(); ++s)
    {
      // A short verdict list authorizes nothing (SVR-AUTHZ-015).
      const auto& at = targetOf[subjectOf[s]];
      denied[at.item][at.reference] = s >= verdicts.size() || !verdicts[s].permitted;
    }
  }

  std::vector<Array<ReferenceDescription>> kept(references.size());
  for (size_t i = 0; i < references.size(); ++i)
  {
    for (size_t k = 0; k < references[i].size(); ++k)
    {
      if (!denied[i][k])
      {
        kept[i].push_back(std::move(references[i][k]));
      }
    }
  }
  co_return kept;
}

// =============================================================================================
// Completion
// =============================================================================================

void BrowseService::complete_browse()
{
  if (!try_finish())
  {
    return;
  }
  mAnswered.store(true);
  const size_t noOfOperations = browse_results().size();
  mBrowseCollector.apply_to(browse_response_header(), browse_diagnostic_infos(), noOfOperations);
  stack_utils::prepare_response_header(active_request_header(), browse_response_header());
  mServiceCallCompleteCallback(std::move(mBrowseServiceResponse));
}

void BrowseService::fail_browse(VoidResult error)
{
  // WITHDRAWN first, and then answered. Every operation still suspended unwinds at its next await
  // rather than computing a result into a response that is about to be handed away - which is the
  // whole of what the `!mRequestFlow` test at the top of nineteen handlers used to do, now stated
  // once, because withdrawal is asked around every await rather than at each handler's top.
  // Once answered - at the partial-result deadline, with continuation points that own operations
  // still running - nothing may withdraw those operations.
  if (mFinished)
  {
    return;
  }
  cancel_all_calls();
  release_unfinished_waits();

  if (!try_finish())
  {
    return;
  }
  mAnswered.store(true);
  mBrowseCollector.set_service_detail(error.status_code());

  auto serviceFault = stack_utils::create_service_fault(&active_request_header(), error.status_code());
  Array<DiagnosticInfo> unused;
  mBrowseCollector.apply_to(serviceFault->response_header(), unused, 0);

  BrowseServiceResponse serviceResponse;
  serviceResponse.response = std::pair(mRequestId, serviceFault);
  mServiceCallCompleteCallback(std::move(serviceResponse));
}

// =============================================================================================
// The operations, in rounds
// =============================================================================================

/// What the rounds learn about one operation.
struct OpenOperation
{
  BrowseOperation operation;
  std::optional<NodeAccessor> source;
  /// The View Node, when the operation browses in a View.
  std::optional<NodeAccessor> view;
  /// The first Reference of `operation.tail` not yet examined.
  size_t position{0};
  /// The answers in a row that held a resume token and no References (`ua::detail::maxEmptyReferencePages`).
  size_t emptyPages{0};
  bool open{true};
};

void BrowseService::finish_operation(OpenOperation& operation)
{
  operation.open = false;
  // A token the operation holds and will not pass back is released through the namespace that issued it.
  operation.operation.token.release();
  finish_item(operation.operation.opIndex);
}

void BrowseService::fail_operation(OpenOperation& operation, const StatusCode& status)
{
  staged_result(operation.operation.opIndex).status_code() = status;
  stage_detail(operation.operation.opIndex, status.shared_detail());
  finish_operation(operation);
}

void BrowseService::note_page_status(OpenOperation& operation, const StatusCode& code)
{
  auto& result = staged_result(operation.operation.opIndex);
  if (code == result.status_code())
  {
    return;
  }
  // The operation's status so far and the page's code share the BrowseResult's one status; a code with a
  // SubCode that is not answered is logged.
  const StatusCode combined = server::detail::combined_item_status(result.status_code(),
    code,
    mLogger,
    "BrowseService: the code of a page of References was not answered",
    operation.operation.nodeToBrowse.node_id());
  if (combined != result.status_code())
  {
    stage_detail(operation.operation.opIndex, combined.shared_detail());
    result.status_code() = combined;
  }
}

void BrowseService::halt_operation(OpenOperation& operation)
{
  auto& o = operation;
  auto& result = staged_result(o.operation.opIndex);
  const size_t size = o.operation.tail.size();
  const size_t rest = o.position < size ? size - o.position : 0;
  if (rest > 0 || !o.operation.token.empty())
  {
    References remaining;
    if (rest > 0)
    {
      remaining = o.operation.tail.slice(numeric_cast<uint32_t>(o.position), numeric_cast<uint32_t>(rest));
    }
    BrowseContinuationPoint point{o.operation.view,
      o.operation.maxRefsPerNode,
      o.operation.nodeToBrowse,
      std::move(o.operation.token),
      std::move(remaining)};
    auto bytes = point.identifier().as_ua_binary();
    result.continuation_point() = ByteString{span<const byte>{bytes}};
    stage_continuation_point(o.operation.opIndex, std::move(point));
  }
  finish_operation(o);
}

/// @par Why the request drives the operations
/// Every operation of the request is answered together, a step at a time, so that each step asks each
/// namespace once, whatever the request's width (NR-23 rule 2, NR-25): the sources are looked up,
/// authorized and checked against their View together, and then, round by round, the References of every
/// open operation are read with one call per namespace, the candidate targets checked against their View,
/// looked up and authorized together, and their TypeDefinitions read with one hinted call per namespace.
/// The rounds run per namespace of the sources, so a namespace that answers slowly holds back only the
/// operations whose sources it holds. An operation's item is finished the moment it is answered, so the
/// partial-result deadline and the timeoutHint see each operation as they did when each ran on its own.
///
/// What a round decides for an operation is what it decided page by page before: the same filters in the
/// same order, the same References in the same order, and the same continuation point. A round examines an
/// operation's References only up to the room its result has left; what a filter, the View or the
/// authorization leaves out frees room for the next round.
ua::async::Task<> BrowseService::browse_in_rounds(std::vector<BrowseOperation> operations)
{
  auto addressSpace = *mBrowseAddressSpace;
  const WeakAddressSpace weakAddressSpace = addressSpace.weak();
  constexpr size_t none = std::numeric_limits<size_t>::max();

  std::vector<OpenOperation> ops;
  ops.reserve(operations.size());
  for (auto& operation : operations)
  {
    OpenOperation opened;
    opened.operation = std::move(operation);
    ops.push_back(std::move(opened));
  }
  operations.clear();
  // The operations of each namespace of the sources, answered in rounds of their own. Held here rather than
  // by the rounds' tasks, so that what a task leaves open, failing to start or unwinding, is answered below.
  std::vector<std::pair<uint16_t, std::vector<OpenOperation>>> pipelines;

  try
  {
    // --- fail closed, and the browse direction: no namespace is asked about these ------------------
    //
    // No committed access identity means nothing can be authorized, so nothing is browsed and nothing is
    // even looked up. Part 4 section 5.8.2: a browseDirection outside the enumeration is a PER-OPERATION
    // fault; the request is well formed and its other operations still run.
    for (auto& o : ops)
    {
      const size_t opIndex = o.operation.opIndex;
      if (!mBrowseAccessControl)
      {
        stage_detail(opIndex,
          ErrorDetail::build("AuthorizationUnavailable",
            "Browse denied: no committed access identity is available",
            "BrowseService")
            .context(ua::ContextKeys::nodeId, to_string(o.operation.nodeToBrowse.node_id())));
        staged_result(opIndex).status_code() = StatusCode{Status::BadUserAccessDenied};
        finish_operation(o);
        continue;
      }
      switch (o.operation.nodeToBrowse.browse_direction())
      {
      case BrowseDirection::Forward:
      case BrowseDirection::Inverse:
      case BrowseDirection::Both:
        break;
      default:
        staged_result(opIndex).status_code() = StatusCode{Status::BadBrowseDirectionInvalid};
        finish_operation(o);
        break;
      }
    }

    // --- ONE lookup per namespace: the sources, the requested ReferenceTypes and the Views ----------
    std::vector<ua::detail::LookupItem> lookups;
    std::unordered_map<NodeId, size_t> lookupOf;
    const auto lookupFor = [&lookups, &lookupOf](const NodeId& nodeId)
    {
      const auto [entry, added] = lookupOf.try_emplace(nodeId, lookups.size());
      if (added)
      {
        lookups.push_back(ua::detail::LookupItem{nodeId, std::nullopt});
      }
      return entry->second;
    };
    std::vector<size_t> sourceLookup(ops.size(), none);
    std::vector<size_t> typeLookup(ops.size(), none);
    std::vector<size_t> viewLookup(ops.size(), none);
    for (size_t k = 0; k < ops.size(); ++k)
    {
      const auto& o = ops[k];
      if (!o.open)
      {
        continue;
      }
      sourceLookup[k] = lookupFor(o.operation.nodeToBrowse.node_id());
      if (!o.operation.nodeToBrowse.reference_type_id().is_null())
      {
        typeLookup[k] = lookupFor(o.operation.nodeToBrowse.reference_type_id());
      }
      if (!o.operation.view.view_id().is_null())
      {
        viewLookup[k] = lookupFor(o.operation.view.view_id());
      }
    }
    if (lookups.empty())
    {
      co_return;
    }
    auto found = co_await await_step<BatchResult<NodeAccessorResult>>(
      [this, &weakAddressSpace, &lookups](auto completion)
      {
        ua::detail::NodeAccessorRoute::find_nodes(
          weakAddressSpace, mRequestInfo, lookups, std::move(completion));
      });
    // A short batch is a namespace answering fewer items than it was asked about, which is a contract
    // breach rather than an outcome for the item, so it reads as an internal error; a batch status answers
    // every item.
    const auto answerAt = [&found](size_t l) -> NodeAccessorResult
    {
      if (found.batchStatus.is_bad())
      {
        return NodeAccessorResult{found.batchStatus.status_code()};
      }
      if (l >= found.items.size())
      {
        return NodeAccessorResult{StatusCode{Status::BadInternalError}};
      }
      return found.items[l];
    };

    // --- may this caller browse each source? ONE authorization per namespace ------------------------
    //
    // A value is taken only from an answer that holds one: a source answered Bad or Uncertain is the
    // operation's status, with no References (DL-67 (1)).
    {
      std::vector<AccessControl::Item> subjects;
      std::vector<size_t> subjectOp;
      for (size_t k = 0; k < ops.size(); ++k)
      {
        auto& o = ops[k];
        if (!o.open)
        {
          continue;
        }
        auto source = answerAt(sourceLookup[k]);
        if (!source.is_good())
        {
          fail_operation(o, source.status_code());
          continue;
        }
        o.source = source.value();
        subjects.push_back(AccessControl::Item{*o.source, AccessOperation::Browse});
        subjectOp.push_back(k);
      }
      if (!subjects.empty())
      {
        auto verdicts =
          co_await await_step<std::vector<AccessControl::Verdict>>([this, &subjects](auto completion)
            { mBrowseAccessControl->authorize_async(mRequestInfo, subjects, std::move(completion)); });
        for (size_t s = 0; s < subjectOp.size(); ++s)
        {
          auto& o = ops[subjectOp[s]];
          const auto verdict = s < verdicts.size()
                                 ? verdicts[s]
                                 : AccessControl::Verdict{.cause = StatusCode{Status::BadInternalError}};
          if (o.open && !verdict.permitted)
          {
            fail_operation(o, verdict.cause);
          }
        }
      }
    }

    // --- the requested ReferenceType, and the View ------------------------------------------------
    //
    // Part 4 5.8.2: a non-null referenceTypeId must name a ReferenceType Node. Part 4 5.8.2.2 makes the
    // ViewDescription a request-wide parameter, so an unknown View fails the WHOLE Browse - but only when an
    // operation reaches the View check (DL-67 (2)).
    std::vector<std::pair<size_t, std::vector<size_t>>> sourcesInView;  // view lookup, operations
    for (size_t k = 0; k < ops.size(); ++k)
    {
      auto& o = ops[k];
      if (!o.open)
      {
        continue;
      }
      const size_t opIndex = o.operation.opIndex;
      if (typeLookup[k] != none)
      {
        const auto& refTypeId = o.operation.nodeToBrowse.reference_type_id();
        auto refType = answerAt(typeLookup[k]);
        const bool isReferenceType =
          refType.is_good() && refType.value().get_node_class() == NodeClass::ReferenceType;
        if (!isReferenceType)
        {
          stage_detail(opIndex,
            ErrorDetail::build("InvalidReferenceTypeId",
              "referenceTypeId does not identify a ReferenceType node",
              "BrowseService")
              .context(ua::ContextKeys::nodeId, to_string(refTypeId))
              .cause(refType.shared_detail()));
          staged_result(opIndex).status_code() =
            StatusCode{Status::BadReferenceTypeIdInvalid, refType.shared_detail()};
          finish_operation(o);
          continue;
        }
      }
      if (viewLookup[k] == none)
      {
        continue;
      }
      const auto& viewId = o.operation.view.view_id();
      auto view = answerAt(viewLookup[k]);
      const bool isView = view.is_good() && view.value().get_node_class() == NodeClass::View;
      if (!isView)
      {
        if (!mFinished)
        {
          fail_browse(VoidResult{Status::BadViewIdUnknown, view.shared_detail()});
          co_return;
        }
        // The response was sent at the partial-result deadline, so the request can no longer fault: every
        // operation still open answers Bad_ViewIdUnknown, with no References and no continuation point, and a
        // BrowseNext of its point returns that (Part 4 7.39.2 lets Table 182's codes be operation results).
        const StatusCode unknownView{Status::BadViewIdUnknown, view.shared_detail()};
        for (auto& remaining : ops)
        {
          if (remaining.open)
          {
            fail_operation(remaining, unknownView);
          }
        }
        co_return;
      }
      if (!view.value().as<ViewAccessor>())
      {
        shared_ptr<const ErrorDetail> detail = ErrorDetail::build("ResolvedViewAccessorUnavailable",
          "The resolved View Node could not be accessed as a View",
          "BrowseService")
                                                 .context(ua::ContextKeys::nodeId, viewId);
        fail_operation(o, StatusCode{Status::BadInternalError, detail});
        continue;
      }
      o.view = view.value();
      const auto& sourceId = o.operation.nodeToBrowse.node_id();
      // The Server Object is part of no View (Part 3 5.4: "the Server Object [...] shall never be part of
      // any View"), whatever the View's namespace answers, so its namespace is not asked.
      if (sourceId == NodeId{ObjectId::Server})
      {
        shared_ptr<const ErrorDetail> detail = ErrorDetail::build(
          "ServerObjectInNoView", "The Server Object is not part of any View", "BrowseService")
                                                 .context(ua::ContextKeys::nodeId, sourceId);
        fail_operation(o, StatusCode{Status::BadNodeNotInView, detail});
        continue;
      }
      // A View Node is a member of its own View, whatever its namespace answers: every Node of a View is
      // reachable starting from the View Node (Part 3 5.4).
      if (sourceId == viewId)
      {
        continue;
      }
      auto entry =
        std::ranges::find_if(sourcesInView, [&](const auto& asked) { return asked.first == viewLookup[k]; });
      if (entry == sourcesInView.end())
      {
        sourcesInView.emplace_back(viewLookup[k], std::vector<size_t>{});
        entry = std::prev(sourcesInView.end());
      }
      entry->second.push_back(k);
    }

    // --- whether each source is in its View: ONE call per View -------------------------------------
    for (size_t v = 0; v < sourcesInView.size(); ++v)
    {
      const auto& members = sourcesInView[v].second;
      std::vector<ExpandedNodeId> candidates;
      candidates.reserve(members.size());
      for (const size_t k : members)
      {
        candidates.emplace_back(ops[k].operation.nodeToBrowse.node_id());
      }
      const NodeAccessor viewNode = *ops[members.front()].view;
      auto answers = co_await await_step<std::vector<BoolResult>>(
        [this, &viewNode, &candidates](auto completion)
        {
          ua::detail::NodeAccessorRoute::view_contains(
            mRequestInfo, viewNode, std::move(candidates), std::move(completion));
        });
      for (size_t i = 0; i < members.size(); ++i)
      {
        auto& o = ops[members[i]];
        if (!o.open)
        {
          continue;
        }
        if (i >= answers.size())
        {
          fail_operation(o, StatusCode{Status::BadInternalError});
          continue;
        }
        if (!answers[i].is_good())
        {
          fail_operation(o, answers[i].status_code());
          continue;
        }
        if (!answers[i].value())
        {
          shared_ptr<const ErrorDetail> detail =
            ErrorDetail::build("NodeNotInView",
              "The requested Browse starting Node is not a member of the supplied View",
              "BrowseService")
              .context(ua::ContextKeys::nodeId, o.operation.nodeToBrowse.node_id());
          fail_operation(o, StatusCode{Status::BadNodeNotInView, detail});
        }
      }
    }

    // --- the rounds: one pipeline per namespace of the sources -----------------------------------
    //
    // The operations whose sources one namespace holds are answered in rounds of their own, so a namespace
    // that answers slowly holds back only the operations that read it, as each operation was held back only
    // by its own namespace before: an operation answered by a fast namespace is answered before the
    // partial-result deadline whatever another namespace does.
    for (auto& o : ops)
    {
      if (!o.open)
      {
        continue;
      }
      const uint16_t namespaceIndex = o.operation.nodeToBrowse.node_id().namespace_index();
      auto pipeline = std::ranges::find_if(
        pipelines, [namespaceIndex](const auto& entry) { return entry.first == namespaceIndex; });
      if (pipeline == pipelines.end())
      {
        pipelines.emplace_back(namespaceIndex, std::vector<OpenOperation>{});
        pipeline = std::prev(pipelines.end());
      }
      pipeline->second.push_back(std::move(o));
      o.open = false;
    }
    std::vector<ua::async::Task<>> tasks;
    tasks.reserve(pipelines.size());
    for (auto& pipeline : pipelines)
    {
      try
      {
        tasks.push_back(browse_rounds(pipeline.second));
      }
      catch (...)
      {
        // What the CALL itself threw - frame allocation - never the body, which contains its own. Nothing
        // is in flight for these operations, so they are answered here; the other pipelines still run.
        const auto er = ua::exception_to_status_code(std::current_exception());
        for (auto& o : pipeline.second)
        {
          if (o.open)
          {
            fail_operation(o, er);
          }
        }
      }
    }
    for (auto& task : tasks)
    {
      try
      {
        co_await std::move(task);
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        // Each pipeline contains its own failures; nothing reaches here but a defect, which is logged rather
        // than allowed to answer for an operation.
        log_exception(mLogger.with_category("service"),
          LogLevel::Error,
          "BrowseService",
          ua::exception_to_status_code(std::current_exception()));
      }
    }
  }
  catch (const ua::async::Abandoned&)
  {
    throw;
  }
  catch (...)
  {
    // Each step contains what its own operations throw; what reaches here fails every operation still open,
    // those of the pipelines already started included: their tasks were destroyed while unwinding.
    const auto er = ua::exception_to_status_code(std::current_exception());
    for (auto& o : ops)
    {
      if (o.open)
      {
        fail_operation(o, er);
      }
    }
    for (auto& pipeline : pipelines)
    {
      for (auto& o : pipeline.second)
      {
        if (o.open)
        {
          fail_operation(o, er);
        }
      }
    }
  }
}

ua::async::Task<> BrowseService::browse_rounds(std::vector<OpenOperation>& ops)
{
  auto addressSpace = *mBrowseAddressSpace;
  const WeakAddressSpace weakAddressSpace = addressSpace.weak();
  constexpr size_t none = std::numeric_limits<size_t>::max();
  const size_t maxDepth = ops.empty() ? 0 : ops.front().operation.limits.execution.loopLimit;

  try
  {
    struct Candidate
    {
      size_t op{0};
      ExpandedNodeId targetId;
      std::optional<LocalizedText> displayName;
      bool isForward{false};
      NodeId refTypeId;
      /// Whether its View's namespace is asked about the target, and what it answered.
      bool askView{false};
      bool inView{true};
      std::optional<NodeAccessor> target;
      /// Left out by the operation's NodeClassMask, applied when the target is looked up (DL-67 (5)).
      bool masked{false};
      bool authorized{true};
      ExpandedNodeId typeDefinition;
    };

    for (;;)
    {
      // --- which operations are still open ----------------------------------------------------------
      std::vector<size_t> live;
      for (size_t k = 0; k < ops.size(); ++k)
      {
        auto& o = ops[k];
        if (!o.open)
        {
          continue;
        }
        const auto& staged = mStaged[o.operation.opIndex];
        if (staged.state == StagedItem::State::Abandoned ||
            (staged.state == StagedItem::State::Paused && staged.paused && staged.paused->released()))
        {
          // Answered at the timeoutHint, or paused and its continuation point released since (API-10.4):
          // what it would produce is dropped, so its namespace is not read again.
          o.open = false;
          o.operation.token.release();
          continue;
        }
        if (o.position >= o.operation.tail.size() && o.operation.exhausted)
        {
          finish_operation(o);  // every Reference read and examined
          continue;
        }
        live.push_back(k);
      }
      if (live.empty())
      {
        break;
      }

      // --- a. ONE read per namespace for the operations with nothing left to examine ------------------
      //
      // Each query carries the Browse's direction, the requested ReferenceType as the hint, the page size
      // and the token of the namespace's last answer. A token sent is consumed by the call whatever it
      // answers, so it is no longer this request's to release.
      {
        std::vector<size_t> reading;
        std::vector<ua::detail::ReferenceRead> reads;
        for (const size_t k : live)
        {
          auto& o = ops[k];
          if (o.position < o.operation.tail.size())
          {
            continue;
          }
          std::vector<NodeId> hint;
          if (!o.operation.nodeToBrowse.reference_type_id().is_null())
          {
            hint.push_back(o.operation.nodeToBrowse.reference_type_id());
          }
          reads.push_back(ua::detail::ReferenceRead{*o.source,
            o.operation.nodeToBrowse.browse_direction(),
            std::move(hint),
            o.operation.maxRefsPerNode,
            std::move(o.operation.token)});
          reading.push_back(k);
        }
        if (!reads.empty())
        {
          auto pages = co_await await_step<std::vector<ua::detail::ReferencePage>>(
            [this, &reads](auto completion) {
              ua::detail::NodeAccessorRoute::read_references(
                mRequestInfo, std::move(reads), std::move(completion));
            });
          for (size_t r = 0; r < reading.size(); ++r)
          {
            auto& o = ops[reading[r]];
            if (!o.open)
            {
              continue;
            }
            if (r >= pages.size())
            {
              // The pages could not be allocated.
              fail_operation(o, StatusCode{Status::BadOutOfMemory});
              continue;
            }
            auto& page = pages[r];
            // A page answered Bad, or Uncertain without References, holds none: its code is the operation's
            // status, with the References already returned and no continuation point (DL-67 (1)).
            if (!page.answer.has_value())
            {
              fail_operation(o, page.answer.status_code());
              continue;
            }
            // A page holding References with a Good subcode or an Uncertain code answers its References, and
            // its code is the operation's status (OPC 10000-4 7.39.1).
            note_page_status(o, page.answer.status_code());
            o.operation.token = std::move(page.resumeToken);
            o.emptyPages = page.answer.value().references.empty() ? o.emptyPages + 1 : 0;
            if (!o.operation.token.empty() && (o.emptyPages >= ua::detail::maxEmptyReferencePages))
            {
              // The namespace kept answering a token with no References: the operation fails, and its last
              // token is released. A page that holds a Reference starts the count again, so a long list
              // answered a Reference at a time is read to its end (DL-67 (8)).
              o.operation.token.release();
              fail_operation(o,
                StatusCode{Status::BadInternalError,
                  ErrorDetail::build("NamespacePagingDidNotEnd",
                    "The namespace kept answering resume tokens for the References of a Node",
                    "BrowseService")
                    .context(ua::ContextKeys::nodeId, to_string(o.operation.nodeToBrowse.node_id()))
                    .context(ua::ContextKeys::limit, std::to_string(ua::detail::maxEmptyReferencePages))});
              continue;
            }
            o.operation.exhausted = o.operation.token.empty();
            o.operation.tail = std::move(page.answer.value().references);
            o.position = 0;
          }
        }
      }

      std::vector<size_t> examining;
      for (const size_t k : live)
      {
        if (ops[k].open && ops[k].position < ops[k].operation.tail.size())
        {
          examining.push_back(k);
        }
      }
      if (examining.empty())
      {
        continue;
      }

      // --- b. the ReferenceType facts this round still lacks ------------------------------------------
      //
      // Symmetry decides the direction filter, so it has to be known before a Reference can be judged: ONE
      // lookup per namespace of the types not met before. Then, for the operations that include subtypes,
      // the supertype chains of the types not yet answered, walked together (DL-66 (6)).
      {
        std::vector<NodeId> unknownTypes;
        std::vector<std::pair<NodeId, NodeId>> questions;
        for (const size_t k : examining)
        {
          const auto& o = ops[k];
          const NodeId& requested = o.operation.nodeToBrowse.reference_type_id();
          const bool subtypes = !requested.is_null() && o.operation.nodeToBrowse.include_subtypes();
          const auto refs = o.operation.tail.span();
          for (size_t i = o.position; i < refs.size(); ++i)
          {
            const NodeId& typeId = refs[i].type_id();
            if (!mReferenceTypeSymmetry.contains(typeId) &&
                (std::ranges::find(unknownTypes, typeId) == unknownTypes.end()))
            {
              unknownTypes.push_back(typeId);
            }
            if (subtypes && (typeId != requested))
            {
              auto question = std::make_pair(typeId, requested);
              if (!mSubtypeAnswers.contains(question) &&
                  (std::ranges::find(questions, question) == questions.end()))
              {
                questions.push_back(std::move(question));
              }
            }
          }
        }

        if (!unknownTypes.empty())
        {
          std::vector<ua::detail::LookupItem> typeLookups;
          typeLookups.reserve(unknownTypes.size());
          for (const auto& typeId : unknownTypes)
          {
            typeLookups.push_back(ua::detail::LookupItem{typeId, std::nullopt});
          }
          auto typeBatch = co_await await_step<BatchResult<NodeAccessorResult>>(
            [this, &weakAddressSpace, &typeLookups](auto completion)
            {
              ua::detail::NodeAccessorRoute::find_nodes(
                weakAddressSpace, mRequestInfo, typeLookups, std::move(completion));
            });
          for (size_t t = 0; t < unknownTypes.size(); ++t)
          {
            NodeAccessorResult typeResult{StatusCode{Status::BadInternalError}};
            if (typeBatch.batchStatus.is_bad())
            {
              typeResult = NodeAccessorResult{typeBatch.batchStatus.status_code()};
            }
            else if (t < typeBatch.items.size())
            {
              typeResult = std::move(typeBatch.items[t]);
            }
            if (!typeResult.is_good())
            {
              auto fallback = StatusCode{typeResult.status_code().as_status(),
                ErrorDetail::build("ReferenceTypeMetadataUnavailable",
                  "Stored ReferenceType metadata could not be resolved; using the stored edge direction",
                  "BrowseService")
                  .context(ua::ContextKeys::nodeId, to_string(unknownTypes[t]))
                  .cause(typeResult.status_code())};
              log_exception(
                mLogger, LogLevel::Warning, "BrowseService.ReferenceTypeMetadataFallback", fallback);
              continue;  // not kept: the stored edge direction stands, and a later round may do better
            }
            auto referenceType = typeResult.value().as<ReferenceTypeAccessor>();
            if (!referenceType)
            {
              auto fallback = StatusCode{Status::BadReferenceTypeIdInvalid,
                ErrorDetail::build("StoredReferenceTypeInvalid",
                  "A stored reference names a Node that is not a ReferenceType; using the stored edge "
                  "direction",
                  "BrowseService")
                  .context(ua::ContextKeys::nodeId, to_string(unknownTypes[t]))};
              log_exception(
                mLogger, LogLevel::Warning, "BrowseService.ReferenceTypeMetadataFallback", fallback);
              continue;
            }
            mReferenceTypeSymmetry.emplace(unknownTypes[t], referenceType->get_symmetric());
          }
        }

        if (!questions.empty())
        {
          std::vector<bool> answers;
          try
          {
            answers = co_await await_step<std::vector<bool>>(
              [this, &addressSpace, &questions, maxDepth](auto completion)
              {
                SubtypeFacts::resolve_async(addressSpace,
                  mRequestInfo,
                  questions,
                  SubtypeFacts::Bounds{maxDepth,
                    [](const NodeId& type)
                    {
                      return type == NodeId{ReferenceTypeId::References};
                    }},
                  std::move(completion));
              });
          }
          catch (const ua::async::Abandoned&)
          {
            throw;
          }
          catch (...)
          {
            // What cannot be decided is not a match, which leaves out every Reference that needed it.
            answers.clear();
          }
          for (size_t q = 0; q < questions.size(); ++q)
          {
            mSubtypeAnswers.insert_or_assign(questions[q], q < answers.size() && answers[q]);
          }
        }
      }

      // --- c. the synchronous filters, per operation in page order, up to the room its result has ------
      std::vector<Candidate> candidates;
      for (const size_t k : examining)
      {
        auto& o = ops[k];
        const size_t firstCandidate = candidates.size();
        try
        {
          const size_t opIndex = o.operation.opIndex;
          auto& browseResult = staged_result(opIndex);
          const auto& nodeToBrowse = o.operation.nodeToBrowse;
          const uint32_t maxRefs = o.operation.maxRefsPerNode;
          if ((maxRefs > 0) && (browseResult.references().size() >= maxRefs))
          {
            halt_operation(o);
            continue;
          }
          const size_t budget = (maxRefs > 0) ? (maxRefs - browseResult.references().size()) : none;
          const NodeId& requested = nodeToBrowse.reference_type_id();
          const auto refs = o.operation.tail.span();
          size_t taken = 0;
          bool failed = false;
          while ((o.position < refs.size()) && (taken < budget))
          {
            const auto& reference = refs[o.position];
            ++o.position;
            Candidate candidate;
            candidate.op = k;
            candidate.targetId = reference.target_id();
            candidate.displayName = reference.target_display_name();
            candidate.isForward = reference.is_forward();
            candidate.refTypeId = reference.type_id();

            // Symmetric cannot be inferred from the stored edge direction: the far endpoint deliberately
            // stores the matching leg as inverse even though Part 4 requires Browse to report the
            // relationship as forward there. An unresolvable type falls back to the stored direction.
            bool isSymmetric = false;
            if (const auto known = mReferenceTypeSymmetry.find(candidate.refTypeId);
                known != mReferenceTypeSymmetry.end())
            {
              isSymmetric = known->second;
            }
            if (isSymmetric)
            {
              candidate.isForward = true;
              if (nodeToBrowse.browse_direction() == BrowseDirection::Inverse)
              {
                continue;
              }
            }
            else if (!node_utils::filter_reference_direction(nodeToBrowse.browse_direction(), reference))
            {
              continue;
            }

            if (!requested.is_null() && (candidate.refTypeId != requested))
            {
              if (!nodeToBrowse.include_subtypes())
              {
                continue;
              }
              const auto known = mSubtypeAnswers.find(std::make_pair(candidate.refTypeId, requested));
              if ((known == mSubtypeAnswers.end()) || !known->second)
              {
                continue;
              }
            }

            if (candidate.targetId.is_local() && candidate.targetId.is_not_index_based())
            {
              uint16_t nsIndex{0};
              try
              {
                nsIndex =
                  addressSpace.namespace_array().get_namespace_index(candidate.targetId.namespace_uri());
              }
              catch (const UaException&)
              {
                // A namespace URI the server does not hold fails the whole operation.
                stage_detail(opIndex,
                  ErrorDetail::build("InvalidReferenceTarget",
                    "Could not resolve the namespace URI for the reference target node",
                    "BrowseService")
                    .context(ua::ContextKeys::namespaceUri, std::string{candidate.targetId.namespace_uri()}));
                browseResult.status_code() = StatusCode{Status::BadNodeIdInvalid};
                failed = true;
                break;
              }
              candidate.targetId.namespace_uri().clear();
              candidate.targetId.node_id().namespace_index() = nsIndex;
            }

            // Checked after the namespace URI is resolved, so a target written with a URI is judged by its
            // index form.
            if (o.view)
            {
              // Membership is asked with a local NodeId, so no namespace can include a Node of another
              // Server in a View: a Reference to one is left out (DL-36).
              if (candidate.targetId.is_remote())
              {
                continue;
              }
              // The Server Object is part of no View (Part 3 5.4), so a Reference to it is omitted without
              // asking the View's namespace.
              if (candidate.targetId.node_id() == NodeId{ObjectId::Server})
              {
                continue;
              }
              // The View Node itself is a member of its View (Part 3 5.4), so a Reference to it is kept.
              candidate.askView = candidate.targetId.node_id() != o.operation.view.view_id();
            }

            candidates.push_back(std::move(candidate));
            ++taken;
          }
          if (failed)
          {
            candidates.resize(firstCandidate);
            finish_operation(o);
          }
        }
        catch (const ua::async::Abandoned&)
        {
          throw;
        }
        catch (...)
        {
          candidates.resize(firstCandidate);
          fail_operation(o, ua::exception_to_status_code(std::current_exception()));
        }
      }
      if (candidates.empty())
      {
        continue;
      }

      // --- d. whether each candidate target is in its View: ONE call per View -------------------------
      {
        std::vector<std::pair<NodeId, std::vector<size_t>>> byView;
        for (size_t c = 0; c < candidates.size(); ++c)
        {
          if (!candidates[c].askView)
          {
            continue;
          }
          const NodeId& viewId = ops[candidates[c].op].operation.view.view_id();
          auto entry =
            std::ranges::find_if(byView, [&viewId](const auto& asked) { return asked.first == viewId; });
          if (entry == byView.end())
          {
            byView.emplace_back(viewId, std::vector<size_t>{});
            entry = std::prev(byView.end());
          }
          entry->second.push_back(c);
        }
        for (size_t v = 0; v < byView.size(); ++v)
        {
          const auto& members = byView[v].second;
          std::vector<ExpandedNodeId> asked;
          std::unordered_map<NodeId, size_t> askedOf;
          std::vector<size_t> answerOf(members.size());
          for (size_t i = 0; i < members.size(); ++i)
          {
            const NodeId& targetId = candidates[members[i]].targetId.node_id();
            const auto [entry, added] = askedOf.try_emplace(targetId, asked.size());
            if (added)
            {
              asked.emplace_back(targetId);
            }
            answerOf[i] = entry->second;
          }
          const NodeAccessor viewNode = *ops[candidates[members.front()].op].view;
          auto answers = co_await await_step<std::vector<BoolResult>>(
            [this, &viewNode, &asked](auto completion)
            {
              ua::detail::NodeAccessorRoute::view_contains(
                mRequestInfo, viewNode, std::move(asked), std::move(completion));
            });
          for (size_t i = 0; i < members.size(); ++i)
          {
            auto& candidate = candidates[members[i]];
            const size_t a = answerOf[i];
            if ((a >= answers.size()) || !answers[a].is_good())
            {
              // Whether the Reference belongs to the View is unknown, so it is left out and the operation
              // says its References may be incomplete (Part 4 5.8.2.4, Table 36). The SDK does not act on
              // an Uncertain answer, with or without a value, so it is unknown too. The first such answer's
              // detail is the one reported, in the status and in the operation's diagnostics.
              candidate.inView = false;
              auto& o = ops[candidate.op];
              auto& result = staged_result(o.operation.opIndex);
              if (o.open && result.status_code().is_good())
              {
                shared_ptr<const ErrorDetail> detail =
                  a < answers.size() ? answers[a].shared_detail() : nullptr;
                stage_detail(o.operation.opIndex, detail);
                result.status_code() = StatusCode{Status::UncertainNotAllNodesAvailable, detail};
              }
              continue;
            }
            candidate.inView = answers[a].value();
          }
        }
      }

      // --- e. ONE lookup per namespace of the distinct local targets, then ONE authorization ------------
      //
      // A definitively absent target retains its NodeId-only reference. An operational lookup failure
      // cannot establish permission and omits the local target. The NodeClassMask is applied before the
      // authorization, so a target it leaves out costs no permission (DL-67 (5)). Part 3 4.8.3 + 8.55
      // (Browse permission, bit 0): a Reference whose local target the caller may not browse is omitted.
      {
        std::vector<ua::detail::LookupItem> targetLookups;
        std::unordered_map<NodeId, size_t> targetOf;
        std::vector<size_t> lookupAt(candidates.size(), none);
        for (size_t c = 0; c < candidates.size(); ++c)
        {
          const auto& candidate = candidates[c];
          if (!candidate.inView || !candidate.targetId.is_local() || !ops[candidate.op].open)
          {
            continue;
          }
          const auto [entry, added] =
            targetOf.try_emplace(candidate.targetId.node_id(), targetLookups.size());
          if (added)
          {
            targetLookups.push_back(ua::detail::LookupItem{candidate.targetId.node_id(), std::nullopt});
          }
          lookupAt[c] = entry->second;
        }
        if (!targetLookups.empty())
        {
          auto targetBatch = co_await await_step<BatchResult<NodeAccessorResult>>(
            [this, &weakAddressSpace, &targetLookups](auto completion)
            {
              ua::detail::NodeAccessorRoute::find_nodes(
                weakAddressSpace, mRequestInfo, targetLookups, std::move(completion));
            });
          for (size_t c = 0; c < candidates.size(); ++c)
          {
            const size_t l = lookupAt[c];
            if (l == none)
              continue;
            candidates[c].authorized = false;
            if (targetBatch.batchStatus.is_good() && (l < targetBatch.items.size()) &&
                targetBatch.items[l].is_good())
            {
              candidates[c].target = targetBatch.items[l].value();
              continue;
            }
            if (targetBatch.batchStatus.is_good() && l < targetBatch.items.size() &&
                targetBatch.items[l].status_code() == StatusCode{Status::BadNodeIdUnknown})
            {
              candidates[c].authorized = true;
              continue;
            }
            const auto status = !targetBatch.batchStatus.is_good() ? targetBatch.batchStatus.status_code()
                                : l < targetBatch.items.size() ? targetBatch.items[l].status_code()
                                                              : StatusCode{Status::BadInternalError,
                                                                  ErrorDetail::build("BrowseTargetLookupIncomplete",
                                                                    "The local reference target lookup did not return an answer",
                                                                    "BrowseService")
                                                                    .context(ua::ContextKeys::nodeId,
                                                                      candidates[c].targetId.node_id())};
            log_exception(mLogger, LogLevel::Warning, "Browse target lookup failed", status);
          }
        }

        std::vector<AccessControl::Item> subjects;
        std::unordered_map<NodeId, size_t> subjectOf;
        std::vector<size_t> subjectAt(candidates.size(), none);
        for (size_t c = 0; c < candidates.size(); ++c)
        {
          auto& candidate = candidates[c];
          if (!candidate.inView || !candidate.target)
          {
            continue;
          }
          NodeClassMask mask{ops[candidate.op].operation.nodeToBrowse.node_class_mask()};
          if (!mask.is_set(candidate.target->get_node_class()))
          {
            candidate.masked = true;
            continue;
          }
          const auto [entry, added] = subjectOf.try_emplace(candidate.target->get_node_id(), subjects.size());
          if (added)
          {
            subjects.push_back(AccessControl::Item{*candidate.target, AccessOperation::Browse});
          }
          subjectAt[c] = entry->second;
        }
        if (!subjects.empty())
        {
          auto verdicts =
            co_await await_step<std::vector<AccessControl::Verdict>>([this, &subjects](auto completion)
              { mBrowseAccessControl->authorize_async(mRequestInfo, subjects, std::move(completion)); });
          for (size_t c = 0; c < candidates.size(); ++c)
          {
            const size_t s = subjectAt[c];
            if (s != none)
            {
              // A short verdict list is a contract breach rather than an outcome, so it denies: this path
              // fails closed.
              candidates[c].authorized = (s < verdicts.size()) && verdicts[s].permitted;
            }
          }
        }
      }

      // --- f. TypeDefinitions: ONE read per namespace, hinted with HasTypeDefinition --------------------
      //
      // A target's TypeDefinition is its forward HasTypeDefinition Reference, which only its namespace can
      // read. Each distinct Object or Variable target the ResultMask asks it of is one query; a namespace
      // that pages although asked for every Reference is followed for those targets only.
      {
        std::vector<NodeAccessor> typedNodes;
        std::unordered_map<NodeId, size_t> typedOf;
        std::vector<size_t> typedAt(candidates.size(), none);
        for (size_t c = 0; c < candidates.size(); ++c)
        {
          const auto& candidate = candidates[c];
          if (!candidate.inView || candidate.masked || !candidate.authorized || !candidate.target ||
              !ops[candidate.op].open)
          {
            continue;
          }
          if (!ResultMask{ops[candidate.op].operation.nodeToBrowse.result_mask()}.is_set(
                ResultMask::Bit::TypeDefinition))
          {
            continue;
          }
          if (!candidate.target->is_object() && !candidate.target->is_variable())
          {
            continue;
          }
          const auto [entry, added] = typedOf.try_emplace(candidate.target->get_node_id(), typedNodes.size());
          if (added)
          {
            typedNodes.push_back(*candidate.target);
          }
          typedAt[c] = entry->second;
        }
        if (!typedNodes.empty())
        {
          const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
          std::vector<std::optional<ExpandedNodeId>> typeDefinitions(typedNodes.size());
          std::vector<std::optional<StatusCode>> failures(typedNodes.size());
          std::vector<ua::detail::ResumeToken> tokens(typedNodes.size());
          std::vector<size_t> emptyPages(typedNodes.size(), 0);
          std::vector<size_t> pending(typedNodes.size());
          for (size_t t = 0; t < pending.size(); ++t)
          {
            pending[t] = t;
          }
          while (!pending.empty())
          {
            std::vector<ua::detail::ReferenceRead> reads;
            reads.reserve(pending.size());
            for (const size_t t : pending)
            {
              reads.push_back(ua::detail::ReferenceRead{
                typedNodes[t], BrowseDirection::Forward, {hasTypeDefinition}, 0, std::move(tokens[t])});
            }
            auto pages = co_await await_step<std::vector<ua::detail::ReferencePage>>(
              [this, &reads](auto completion) {
                ua::detail::NodeAccessorRoute::read_references(
                  mRequestInfo, std::move(reads), std::move(completion));
              });
            std::vector<size_t> next;
            for (size_t p = 0; p < pending.size(); ++p)
            {
              const size_t t = pending[p];
              if (p >= pages.size())
              {
                failures[t] = StatusCode{Status::BadOutOfMemory};
                continue;
              }
              auto& page = pages[p];
              if (!page.answer.is_good())
              {
                failures[t] = page.answer.status_code();
                continue;
              }
              emptyPages[t] = page.answer.value().references.empty() ? emptyPages[t] + 1 : 0;
              for (const auto& reference : page.answer.value().references)
              {
                if (reference.is_forward() && (reference.type_id() == hasTypeDefinition))
                {
                  typeDefinitions[t] = reference.target_id();
                  break;
                }
              }
              // A token left in the page once the TypeDefinition is known is released with the page.
              if (typeDefinitions[t] || page.resumeToken.empty())
              {
                continue;
              }
              if (emptyPages[t] >= ua::detail::maxEmptyReferencePages)
              {
                failures[t] = StatusCode{Status::BadInternalError};
                continue;
              }
              tokens[t] = std::move(page.resumeToken);
              next.push_back(t);
            }
            pending = std::move(next);
          }
          for (size_t c = 0; c < candidates.size(); ++c)
          {
            const size_t t = typedAt[c];
            if (t == none)
            {
              continue;
            }
            if (!failures[t])
            {
              candidates[c].typeDefinition = typeDefinitions[t].value_or(ExpandedNodeId{});
              continue;
            }
            // The Reference is still returned; only its TypeDefinition is unknown. Say why rather than
            // return a null id that looks like "no type definition".
            mLogger.with_category("browse").warning(
              {{"node_id", to_string(candidates[c].targetId)}, {"status", to_string(*failures[t])}},
              "Could not read a browse target's TypeDefinition; the reference is returned without it");
          }
        }
      }

      // --- g. emit, in page order -----------------------------------------------------------------
      for (auto& candidate : candidates)
      {
        auto& o = ops[candidate.op];
        if (!o.open || !candidate.inView || candidate.masked || !candidate.authorized)
        {
          continue;
        }
        try
        {
          add_reference_description(addressSpace,
            candidate.target,
            candidate.targetId,
            candidate.displayName,
            candidate.refTypeId,
            candidate.isForward,
            o.operation.nodeToBrowse.result_mask(),
            candidate.typeDefinition,
            staged_result(o.operation.opIndex));
        }
        catch (...)
        {
          fail_operation(o, ua::exception_to_status_code(std::current_exception()));
        }
      }

      // --- h. a full result halts with a continuation point; the rest stay open ------------------
      for (const size_t k : examining)
      {
        auto& o = ops[k];
        const uint32_t maxRefs = o.operation.maxRefsPerNode;
        if (o.open && (maxRefs > 0) && (staged_result(o.operation.opIndex).references().size() >= maxRefs))
        {
          halt_operation(o);
        }
      }
    }
  }
  catch (const ua::async::Abandoned&)
  {
    throw;
  }
  catch (...)
  {
    // Each step contains what its own operations throw; what reaches here fails every operation still open.
    const auto er = ua::exception_to_status_code(std::current_exception());
    for (auto& o : ops)
    {
      if (o.open)
      {
        fail_operation(o, er);
      }
    }
  }
}

// =============================================================================================
// Cancel / timeout / set_timeout / continuation-points / helpers
// =============================================================================================

void BrowseService::abort(StatusCode reason)
{
  // A request answered at its partial-result deadline is no longer the client's to cancel: its
  // continuation points own the operations still running, and only releasing them stops those.
  if (mAnswered.load())
  {
    return;
  }
  if (mCancelled)
    mCancelled->store(true);

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](BrowseService& self)
    {
      if (self.mFinished)
      {
        return;
      }
      self.cancel_all_calls();
      self.release_unfinished_waits();
      DiagnosticCollector collector{0};
      self.send_service_fault(self.active_request_header(), reason, collector);
      self.mAnswered.store(true);
      // The operations stop on the token: each throws ua::async::Abandoned at its next resumption
      // and unwinds. Nothing here needs to reach into their state - there is none left outside their
      // own frames - and try_finish has already taken the right to answer, so a body that got a turn
      // before this one changes nothing.
      self.mBrowseResponse.reset();
      self.mBrowseNextResponse.reset();
    })();
}

void BrowseService::timeout()
{
  // The timeoutHint. Normally the partial-result deadline has already answered and this finds the
  // request finished. What can still be running is a Browse item that found no continuation point
  // left for it at the deadline (OPC 10000-4 section 7.9: Bad_NoContinuationPoints for the remaining
  // operations), or an item of a request with no partial-result deadline; each is answered on its own
  // and the request is not failed as a whole.
  if (mFinished)
  {
    return;
  }
  if (!browse_response_exists())
  {
    // Nothing was prepared yet, so nothing was started.
    cancel_all_calls();
    DiagnosticCollector collector{0};
    send_service_fault(active_request_header(), Status::BadTimeout, collector);
    mAnswered.store(true);
    return;
  }

  bool anyPaused = false;
  for (size_t index = 0; index < mStaged.size(); ++index)
  {
    auto& item = mStaged[index];
    if (item.state == StagedItem::State::Paused)
    {
      anyPaused = true;
      continue;
    }
    if (item.state != StagedItem::State::Running)
    {
      continue;
    }
    auto& slot = browse_results()[index];
    slot = BrowseResult{};
    slot.status_code() = item.awaitingContinuationPoint ? StatusCode{Status::BadNoContinuationPoints}
                                                        : StatusCode{Status::BadTimeout};
    item.state = StagedItem::State::Abandoned;
  }
  release_unfinished_waits();
  // Operations a continuation point now owns share this request's token, so it is set only when no
  // item was paused; abandoned items' operations then simply run out and their results are dropped.
  if (!anyPaused)
  {
    cancel_all_calls();
  }
  complete_browse();
}

void BrowseService::set_timeout()
{
  // Exactly one of the two request optionals is engaged for the lifetime of the service. Guard each
  // branch explicitly so the dereferenced request is provably engaged.
  uint32_t timeoutHint{0};
  if (mBrowseRequest)
  {
    timeoutHint = mBrowseRequest->request_header().timeout_hint();
  }
  else if (mBrowseNextRequest)
  {
    timeoutHint = mBrowseNextRequest->request_header().timeout_hint();
  }
  ServiceBase::set_timeout(timeoutHint);

  // The partial-result deadline (API-10.1, API-10.3).
  double fraction = 0.8;
  if (auto sessionInfo = mSessionInfo.lock())
  {
    fraction = sessionInfo->server_configuration().partialResultDeadlineFraction;
  }
  if (const auto delay = partial_result_delay(timeoutHint, fraction))
  {
    mPartialResultDeadline = std::chrono::steady_clock::now() + *delay;
    auto me = weak_from_this();
    mPartialResultTimer = Timer::schedule_after(mStrand,
      *delay,
      [me](boost::system::error_code ec)
      {
        if (ec)
        {
          return;
        }
        if (auto service = me.lock())
        {
          service->answer_at_partial_result_deadline();
        }
      });
  }
}

bool BrowseService::browse_response_exists() const
{
  return mBrowseResponse != nullptr || mBrowseNextResponse != nullptr;
}

void BrowseService::retrieve_continuation_points(BrowseContinuationPoints& continuationPoints)
{
  // Only ever called from the BrowseNext constructor, after mBrowseNextRequest is engaged. Guard the
  // access so engagement is provable to the checker.
  if (!mBrowseNextRequest)
    return;
  for (const auto& cp : mBrowseNextRequest->continuation_points())
  {
    Guid guid;
    try
    {
      guid.from_ua_binary(cp);
    }
    catch (...)
    {
      // A malformed continuation point (e.g. not 16 bytes) makes from_ua_binary
      // throw Bad_DecodingError. This runs in an async browse flow on a pool
      // thread with no exception barrier, so an escape would std::terminate the
      // whole server (a client could crash it with one bad BrowseNext). Skip the
      // entry here; the per-item validation loop reports Bad_ContinuationPointInvalid.
      continue;
    }

    auto result = continuationPoints.find(guid);
    if (result != continuationPoints.end())
    {
      mContinuationPointsIn.emplace_back(std::move(result->second));
      continuationPoints.erase(result);
    }
  }
}

void BrowseService::add_reference_description(AddressSpace addressSpace, const optional<NodeAccessor> target,
  const ExpandedNodeId& targetId, const std::optional<LocalizedText>& targetDisplayName,
  const NodeId& refType, bool isForward, uint32_t rawResultMask, const ExpandedNodeId& typeDefinition,
  BrowseResult& browseResult)
{
  ResultMask resultMask(rawResultMask);

  browseResult.references().payload().emplace_back();
  auto& refDesc = browseResult.references().payload().back();

  if (targetId.is_local())
  {
    if (targetId.is_index_based())
    {
      refDesc.node_id() = targetId;
    }
    else
    {
      try
      {
        auto index = addressSpace.namespace_array().get_namespace_index(targetId.namespace_uri());
        refDesc.node_id().node_id().namespace_index() = index;
        refDesc.node_id().node_id().identifier() = targetId.node_id().identifier();
      }
      catch (const UaException&)
      {
        // Namespace URI not found locally - keep the original URI-based ExpandedNodeId.
        refDesc.node_id() = targetId;
      }
    }
  }
  else
  {
    if (targetId.is_index_based())
    {
      try
      {
        auto uri = addressSpace.namespace_array().get_namespace_uri(targetId.node_id().namespace_index());
        refDesc.node_id().server_index() = targetId.server_index();
        refDesc.node_id().namespace_uri() = uri;
        refDesc.node_id().node_id().identifier() = targetId.node_id().identifier();
      }
      catch (const UaException&)
      {
        // Namespace index not resolvable to URI - keep the original index-based ExpandedNodeId.
        refDesc.node_id() = targetId;
      }
    }
    else
    {
      refDesc.node_id() = targetId;
    }
  }

  if (resultMask.is_set(ResultMask::Bit::ReferenceType))
  {
    refDesc.reference_type_id() = refType;
  }

  if (resultMask.is_set(ResultMask::Bit::IsForward))
  {
    refDesc.is_forward() = isForward;
  }

  if (target)
  {
    if (resultMask.is_set(ResultMask::Bit::NodeClass))
    {
      refDesc.node_class() = target->get_node_class();
    }

    if (resultMask.is_set(ResultMask::Bit::DisplayName))
    {
      // Resolve using server-wide default locale (preferred -> default -> front()).
      auto sessionInfo = mSessionInfo.lock();
      check(sessionInfo);
      const auto& defaultLocale = sessionInfo->configuration().defaultLocale;

      auto stored = target->read_attribute(AttributeId::DisplayName);
      if (!stored.empty() && stored.is_localized_text())
      {
        if (!defaultLocale.empty())
        {
          std::vector<LocaleId> combined(mSessionLocales.begin(), mSessionLocales.end());
          combined.push_back(defaultLocale);
          resolve_in_variant(stored, combined);
        }
        else
        {
          resolve_in_variant(stored, mSessionLocales);
        }
        refDesc.display_name() = stored.as<LocalizedText>();
      }
    }

    if (resultMask.is_set(ResultMask::Bit::BrowseName))
    {
      refDesc.browse_name() = target->get_browse_name();
    }

    if (resultMask.is_set(ResultMask::Bit::TypeDefinition) && (target->is_object() || target->is_variable()))
    {
      refDesc.type_definition() = typeDefinition;
    }
  }
  else if (!targetId.is_local() && targetDisplayName && resultMask.is_set(ResultMask::Bit::DisplayName))
  {
    auto sessionInfo = mSessionInfo.lock();
    check(sessionInfo);
    const auto& defaultLocale = sessionInfo->configuration().defaultLocale;
    refDesc.display_name() = defaultLocale.empty()
                               ? targetDisplayName->resolve(mSessionLocales)
                               : targetDisplayName->resolve(mSessionLocales, defaultLocale);
  }
}

void BrowseService::send_service_fault(
  const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector)
{
  if (!try_finish())
    return;

  auto serviceFault = stack_utils::create_service_fault(&requestHeader, status);
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault->response_header(), unused, 0);
  BrowseServiceResponse browseServiceResponse;
  browseServiceResponse.response = std::pair(mRequestId, serviceFault);
  mServiceCallCompleteCallback(std::move(browseServiceResponse));
}

void BrowseService::prepare_response_header(ResponseHeader& responseHeader)
{
  if (mBrowseRequest)
  {
    stack_utils::prepare_response_header(mBrowseRequest->request_header(), responseHeader);
  }
  else if (mBrowseNextRequest)
  {
    stack_utils::prepare_response_header(mBrowseNextRequest->request_header(), responseHeader);
  }
}

}  // namespace ua::server
