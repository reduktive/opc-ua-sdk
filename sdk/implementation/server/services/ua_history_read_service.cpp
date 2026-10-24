// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_read_service.h"

#include <limits>
#include <boost/asio/post.hpp>

#include <cmath>

#include <algorithm>
#include "ua_on_strand.h"
#include "ua_address_space.h"
#include "ua_namespace_route.h"
#include "ua_weak_address_space.h"
#include "ua_aggregate_configuration.h"
#include "ua_aggregate_engine.h"
#include "ua_aggregate_intervals.h"
#include "ua_aggregate_registry.h"
#include "ua_aggregate_types.h"
#include "ua_diagnostic_collector.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_compiled_event_filter.h"
#include "ua_event_type_model.h"
#include "ua_history_data.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_event.h"
#include "ua_history_modified_data.h"
#include "ua_history_read_validation.h"
#include "ua_node_accessor_route.h"
#include "ua_node_description.h"
#include "ua_service_request_info.h"
#include "ua_verdict_rules.h"
#include "ua_log_exception.h"
#include "ua_namespace.h"
#include "ua_read_annotation_data_details.h"
#include "ua_read_at_time_details.h"
#include "ua_read_event_details.h"
#include "ua_read_processed_details.h"
#include "ua_read_raw_modified_details.h"
#include "ua_server_session_info.h"
#include "ua_service_fault.h"
#include "ua_stack_utilities.h"
#include "ua_status_routing.h"
#include "ua_to_result.h"
#include "security/ua_access_control.h"
#include "ua_to_string.h"

#include "fmt/format.h"

#include <array>
#include <unordered_map>

namespace ua::server
{

// --- Per-flow state (private to this translation unit). Single-instance per service; the
// unique_ptr on the class is the flow root, dropped at completion / cancel / timeout. ---------

/// What one HistoryRead request is working with, for as long as it is working.
///
/// This is state, not a flow: no step saying where the request has got to, and no counters counting
/// its items or its namespaces down. Where the request has got to is where its body has got to, and
/// the counts are the two joins in @ref HistoryReadService::run_history_read. What remains is what
/// the request was given and what it is building - and something OTHER than the body reads it,
/// because a timeout or a cancellation has to answer a request whose body can no longer be asked.
struct HistoryReadState
{
  // Per-fresh-read entry awaiting node resolution and per-namespace dispatch.
  struct ItemEntry
  {
    size_t originalIndex{};
    NodeId nodeId;
    NumericRange indexRange;
    std::optional<NamespaceHistoryDelegate::Cursor> cursor;
    shared_ptr<NamespaceHistoryDelegate> delegate;  // delegate captured from CP (if continuation item)
    uint16_t namespaceIndex{};
    bool fromContinuation{false};  // true -> already grouped at start, no find_node needed
    // Set by this item's own body when it has decided the item may be read. Recorded on the entry
    // rather than acted on immediately, so the grouping can happen once, after the join, in request
    // order - see `run_history_read`.
    bool accepted{false};
    NodeId aggregateType;  // ReadProcessedDetails: the per-node aggregate function
    std::optional<NodeAccessor> resolvedNode;
    // The Node's Attributes, taken once when the item is resolved.
    std::optional<NodeDescription> description;
    // Set by the resolution when the item's Node may be read for history; its dataEncoding is decided next.
    bool authorized{false};
  };

  AddressSpace addressSpace;
  std::optional<SessionAccessControl> accessControl;
  shared_ptr<HistoryReadResponse> response;
  HistoryReadService::HistoryReadServiceResponse serviceResponse;
  DiagnosticCollector collector;
  // Exactly one of these is set; all are borrowed pointers into mRequest (lifetime guaranteed).
  ReadRawModifiedDetails* rawDetails{nullptr};
  ReadProcessedDetails* processedDetails{nullptr};
  ReadAnnotationDataDetails* annotationDetails{nullptr};
  ReadAtTimeDetails* atTimeDetails{nullptr};
  ReadEventDetails* eventDetails{nullptr};

  bool is_processed() const
  {
    return processedDetails != nullptr;
  }

  bool is_annotation() const
  {
    return annotationDetails != nullptr;
  }

  bool is_at_time() const
  {
    return atTimeDetails != nullptr;
  }

  bool is_events() const
  {
    return eventDetails != nullptr;
  }

  // Per-fresh-read items, keyed by originalIndex via vector index in freshReads.
  std::vector<ItemEntry> freshReads;
  std::vector<StatusCode> eventSelectClauseModelStatuses;

  // What each select clause's archived field may carry for this request's user, decided once per request
  // and applied to every Event returned. Parallel to the filter's select clauses.
  struct EventFieldRule
  {
    enum class Kind
    {
      Keep,  ///< the field is returned as the delegate answered it
      Deny,  ///< the field is replaced with `denial`
      DenyIfValue  ///< a null field stays null; any other field is replaced with `denial`
    };
    Kind kind{Kind::Deny};
    StatusCode denial{Status::BadUserAccessDenied,
      ErrorDetail::build("EventFieldAuthorizationVerdictMissing",
        "The Event field has no permitted associated authorization verdict", "HistoryReadService")};
  };

  std::vector<EventFieldRule> eventFieldRules;

  // Namespace-grouped items ready for delegate dispatch. Built after all node resolves complete.
  std::unordered_map<uint16_t, std::vector<ItemEntry>> itemsByNamespace;

  // The server's advertised per-node return caps (OPC 10000-11 5.2), captured once at the start of the
  // request: the same values published on the HistoryServerCapabilities MaxReturnDataValues /
  // MaxReturnEventValues nodes. 0 = no limit.
  uint32_t maxReturnDataValues{0};
  uint32_t maxReturnEventValues{0};

  // The aggregate values a request computed from raw reads may still produce, over all its nodes: the
  // per-node interval cap bounds one node, and a request names up to MaxNodesPerHistoryReadData of them.
  size_t processedValuesRemaining{aggregates::defaultMaxIntervals};

  HistoryReadState(AddressSpace initialAddressSpace, shared_ptr<HistoryReadResponse> initialResponse,
    HistoryReadService::HistoryReadServiceResponse initialServiceResponse,
    DiagnosticCollector initialCollector, ReadRawModifiedDetails* initialRawDetails,
    ReadProcessedDetails* initialProcessedDetails, ReadAnnotationDataDetails* initialAnnotationDetails)
    : addressSpace(std::move(initialAddressSpace)), response(std::move(initialResponse)),
      serviceResponse(std::move(initialServiceResponse)), collector(std::move(initialCollector)),
      rawDetails(initialRawDetails), processedDetails(initialProcessedDetails),
      annotationDetails(initialAnnotationDetails)
  {}
};

namespace history_detail
{

/// What a paused HistoryRead operation produced, kept until the HistoryRead that continues it takes it.
struct HistoryOutcome
{
  HistoryReadResult result;
  std::optional<HistoryContinuationPoint> continuationPoint;
  std::vector<shared_ptr<const ErrorDetail>> details;
};

/// A HistoryRead operation answered for at the partial-result deadline and still reading in the service
/// that started it. @see PausedOperation
using PausedHistory = PausedResult<HistoryOutcome>;

}  // namespace history_detail

using history_detail::HistoryOutcome;
using history_detail::PausedHistory;

struct HistoryReadService::StagedItem
{
  enum class State
  {
    /// Not an operation (answered while the request was prepared), or finished and delivered.
    Answered,
    /// Its read is running and its result will go into the response.
    Running,
    /// Answered with a continuation point at the partial-result deadline; its result goes to that point.
    Paused,
    /// Answered at the timeoutHint while still running; whatever it produces later is dropped.
    Abandoned,
  };

  State state{State::Answered};
  HistoryReadResult result;
  std::optional<HistoryContinuationPoint> continuationPoint;
  std::vector<shared_ptr<const ErrorDetail>> details;
  uint16_t namespaceIndex{0};
  /// Continues an earlier point, so it is never refused for want of a continuation point (OPC 10000-4
  /// section 7.9).
  bool continuing{false};
  /// The earlier paused operation this item continues, if any.
  shared_ptr<PausedHistory> waitingOn;
  /// The paused operation a continuation point now holds for this item, when Paused.
  shared_ptr<PausedHistory> paused;
  bool ownsPaused{false};
  bool awaitingContinuationPoint{false};
};

namespace
{

/// Puts Good_NoData, the code OPC 10000-11 asks for (@p clause) when a read finds no data, on @p status, the
/// store's code for the read, only when that code is plain Good: a Good code of the store's own stands, and
/// is logged at Warning, since the Server built with the SDK owes the clause; an Uncertain code stays
/// Uncertain.
void answer_no_data(StatusCode& status, const Logger& logger, const NodeId& nodeId, std::string_view clause)
{
  if (status.as_status() == Status::Good)
  {
    status = StatusCode{Status::GoodNoData, status.shared_detail()};
    return;
  }
  if (status.is_good() && logger.is_enabled(LogLevel::Warning))
  {
    const std::string node = ua::to_string(nodeId);
    const std::string code = ua::to_string(status);
    logger.warning(
      {{"node_id", std::string_view{node}}, {"status", std::string_view{code}}, {"clause", clause}},
      "A history read found no data and its store answered a Good code other than Good_NoData, which Part 11 "
      "asks for; the store's code is answered");
  }
}

// Map a request AggregateConfiguration onto the calculator's CalcConfig. When the
// configuration defers to the server capabilities the calculator defaults apply
// (TreatUncertainAsBad, 100/100 thresholds, stepped interpolation = false, 1 ms
// time resolution). Stepped / time-resolution are server/node properties, not part
// of AggregateConfiguration; v1 uses the calculator defaults.
aggregates::CalcConfig make_calc_config(const AggregateConfiguration& config)
{
  aggregates::CalcConfig cfg;
  if (!config.use_server_capabilities_defaults())
  {
    cfg.treatUncertainAsBad = config.treat_uncertain_as_bad();
    cfg.percentDataBad = config.percent_data_bad();
    cfg.percentDataGood = config.percent_data_good();
    cfg.useSlopedExtrapolation = config.use_sloped_extrapolation();
  }
  return cfg;
}

// Mask the timestamp(s) the client did not request (Part 4 7.6 TimestampsToReturn). A history
// delegate may populate both source and server timestamps; the service strips the unwanted one
// before returning so a Source-only request never carries a ServerTimestamp and vice versa
// (CTT Read Raw 001). Both/Neither are handled upstream (Neither is rejected).
void apply_timestamps_to_return(std::vector<DataValue>& values, TimestampsToReturn tsr)
{
  for (auto& dv : values)
  {
    if (tsr == TimestampsToReturn::Source)
      dv.server_timestamp() = std::nullopt;
    else if (tsr == TimestampsToReturn::Server)
      dv.source_timestamp() = std::nullopt;
  }
}

/// Determines whether a DataType is the named ancestor or one of its descendants.
///
/// This is a bounded, self-owning asynchronous walk. Address-space lookup and reference-read
/// failures remain rich BoolResult failures so HistoryRead retains their ErrorDetail instead of
/// misclassifying a broken hierarchy as a scalar DataType.
class DataTypeSubtypeWalk final : public std::enable_shared_from_this<DataTypeSubtypeWalk>
{
public:
  DataTypeSubtypeWalk(
    AddressSpace addressSpace, NodeId candidate, NodeId ancestor, std::function<void(BoolResult)> onComplete)
    : mAddressSpace(addressSpace.weak()), mExecutor(addressSpace.executor()), mLogger(addressSpace.logger()),
      mCandidate(std::move(candidate)), mAncestor(std::move(ancestor)), mOnComplete(std::move(onComplete))
  {}

  void start()
  {
    find_candidate();
  }

private:
  enum class Step
  {
    FindingCandidate,
    ReadingReferences,
    Done,
  };

  static constexpr size_t sMaxHierarchyDepth = 64;

  void find_candidate()
  {
    if (mStep == Step::Done)
      return;
    if (mCandidate == mAncestor)
    {
      complete(BoolResult{true});
      return;
    }
    if (std::ranges::find(mVisited, mCandidate) != mVisited.end())
    {
      complete(BoolResult{StatusCode{Status::BadTypeDefinitionInvalid,
        ErrorDetail::build(
          "DataTypeHierarchyCycle", "DataType hierarchy contains a cycle", "HistoryReadService")
          .context(ContextKeys::nodeId, mCandidate)}});
      return;
    }
    mVisited.push_back(mCandidate);
    if (mVisited.size() > sMaxHierarchyDepth)
    {
      complete(BoolResult{StatusCode{Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("DataTypeHierarchyTooDeep",
          "DataType hierarchy exceeded the bounded walk depth",
          "HistoryReadService")
          .context(ContextKeys::max, sMaxHierarchyDepth)
          .context(ContextKeys::nodeId, mCandidate)}});
      return;
    }

    mStep = Step::FindingCandidate;
    // Held weakly and locked for the lookup only: the completion given to the namespace owns this walk
    // (CALLS-21 rules 1 and 2).
    auto found = ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [](DataTypeSubtypeWalk& self, NodeAccessorResult result) mutable
      { self.on_candidate_found(std::move(result)); });
    if (auto addressSpace = mAddressSpace.lock())
    {
      addressSpace->find_node_async(mCandidate, std::move(found));
    }
    else
    {
      found(NodeAccessorResult{ua::detail::address_space_gone("HistoryReadService")});
    }
  }

  void on_candidate_found(NodeAccessorResult result)
  {
    if (mStep != Step::FindingCandidate)
    {
      complete(BoolResult{StatusCode{Status::BadInternalError,
        make_error_detail("DataTypeWalkStepMismatch",
          "DataType hierarchy walk reached an unexpected step",
          "HistoryReadService")}});
      return;
    }
    if (!result.is_good())
    {
      complete(
        BoolResult{::ua::detail::lookup_failure(mCandidate, result.status_code(), "HistoryReadService")});
      return;
    }
    if (result.value().get_node_class() != NodeClass::DataType)
    {
      complete(BoolResult{StatusCode{Status::BadTypeDefinitionInvalid,
        ErrorDetail::build("HierarchyNodeNotDataType",
          "DataType hierarchy walk resolved a non-DataType Node",
          "HistoryReadService")
          .context(ContextKeys::nodeId, mCandidate)}});
      return;
    }

    mStep = Step::ReadingReferences;
    result.value().get_references_async(ua::async::post_owning(this,
      mExecutor,
      mLogger,
      [](DataTypeSubtypeWalk& self, Result<References> references) mutable
      { self.on_references_read(std::move(references)); }));
  }

  void on_references_read(Result<References> result)
  {
    if (mStep != Step::ReadingReferences)
    {
      complete(BoolResult{StatusCode{Status::BadInternalError,
        make_error_detail("DataTypeWalkStepMismatch",
          "DataType hierarchy walk reached an unexpected step",
          "HistoryReadService")}});
      return;
    }
    if (!result.is_good())
    {
      complete(BoolResult{server::detail::not_acted_on(
        server::detail::referencesAnswerUncertain, result.status_code(), "HistoryReadService", mCandidate)});
      return;
    }

    for (const auto& reference : result.value())
    {
      if (reference.is_forward() || reference.type_id() != NodeId{ReferenceTypeId::HasSubtype})
        continue;
      if (!reference.target_id().is_local())
      {
        complete(BoolResult{StatusCode{Status::BadTypeDefinitionInvalid,
          ErrorDetail::build("RemoteDataTypeSupertype",
            "DataType hierarchy contains a remote supertype that cannot be validated locally",
            "HistoryReadService")
            .context(ContextKeys::nodeId, reference.target_id())}});
        return;
      }
      mCandidate = reference.target_id().node_id();
      find_candidate();
      return;
    }

    complete(BoolResult{false});
  }

  void complete(BoolResult result)
  {
    if (mStep == Step::Done)
      return;
    mStep = Step::Done;
    auto onComplete = std::move(mOnComplete);
    onComplete(std::move(result));
  }

  WeakAddressSpace mAddressSpace;
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;
  NodeId mCandidate;
  NodeId mAncestor;
  std::function<void(BoolResult)> mOnComplete;
  std::vector<NodeId> mVisited;
  Step mStep{Step::FindingCandidate};
};

void is_data_type_or_subtype_async(
  AddressSpace addressSpace, NodeId candidate, NodeId ancestor, std::function<void(BoolResult)> onComplete)
{
  auto walk = std::make_shared<DataTypeSubtypeWalk>(
    std::move(addressSpace), std::move(candidate), std::move(ancestor), std::move(onComplete));
  walk->start();
}

}  // namespace

shared_ptr<HistoryReadService> HistoryReadService::create(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, HistoryReadRequest&& request,
  HistoryContinuationPoints& sessionContinuationPoints, boost::asio::any_io_executor executor,
  CompleteCallback callback)
{
  struct Wrapper : public HistoryReadService
  {
    Wrapper(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
      HistoryReadRequest&& request, boost::asio::any_io_executor executor, CompleteCallback callback)
      : HistoryReadService(std::move(sessionInfo), std::move(sessionLocales), requestId, std::move(request),
          executor, std::move(callback))
    {}
  };

  auto service = make_shared<Wrapper>(
    sessionInfo, std::move(sessionLocales), requestId, std::move(request), executor, std::move(callback));
  service->retrieve_continuation_points(sessionContinuationPoints);
  service->start();
  return service;
}

HistoryReadService::HistoryReadService(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, HistoryReadRequest&& request,
  boost::asio::any_io_executor executor, CompleteCallback callback)
  : ServiceBase(request.request_header().request_handle(), std::move(sessionInfo), executor),
    mSessionLocales(std::move(sessionLocales)), mRequestId(requestId), mRequest(std::move(request)),
    mCallback(std::move(callback)), mCancelled(make_shared<std::atomic_bool>(false))
{}

HistoryReadService::~HistoryReadService() = default;

void HistoryReadService::begin_processing()
{
  start_history_read();
}

// =============================================================================================
// HistoryRead flow
// =============================================================================================
//
// ASCII flow:
//   start_history_read                           (entry from begin_processing, on mStrand)
//     [synchronous validation: SessionClosed / Empty / TooMany / NullDetails / not RawModified
//      / underspec / invalid timestamps / release_continuation_points fast-path]
//          rejects -> fail_history_read | early complete (release_cp)
//     -> start_request -> run_history_read
//     -> co_await resolve_items
//          one lookup of every item's Node -> classify each one's history access -> one authorization
//          [any refusal] write the per-item bad status; the entry stays unaccepted
//          [authorized]  mark the entry authorized
//     -> spawns classify_item_encoding(i) for every authorized item named with a dataEncoding, EAGERLY,
//          then co_awaits them all. The join IS the barrier; there is no counter.
//          [refusal]  write the per-item bad status and return; the entry stays unaccepted
//          [accepted] mark the entry accepted
//     -> after the join: group the accepted entries by namespace, in REQUEST order
//          then co_await validate_event_select_clause_model (events only)
//     -> co_await run_namespace_reads
//          spawns read_namespace_*(nsIndex) for every namespace, EAGERLY, in ASCENDING index order,
//          then co_awaits them all. The join IS the barrier; there is no counter.
//     -> read_namespace_raw(nsIndex) and its four siblings
//          [no-delegate]   mark all items BadHistoryOperationUnsupported and return
//          [delegate-path] co_await the batch, then on_namespace_read_complete
//     -> on_namespace_read_complete(nsIndex, BatchResult<ReadRawItemResult>)
//          [batchStatus.is_bad()] log + per-item batchStatus + collector detail
//          [success]              per-item map status / wrap HistoryData / register CP
//     -> complete_history_read, once, after the join
//     -> complete_history_read | fail_history_read

void HistoryReadService::start_history_read()
{
  auto sessionInfo = mSessionInfo.lock();
  DiagnosticCollector collector{mRequest.request_header().return_diagnostics(),
    sessionInfo ? sessionInfo->diagnostic_security_context() : DiagnosticSecurityContext{}};

  try
  {
    if (!sessionInfo)
    {
      throw UaException{Status::BadSessionClosed,
        make_error_detail(
          "SessionClosed", "Session expired during HistoryRead processing", "HistoryReadService")};
    }

    const auto arrival = std::chrono::steady_clock::now();
    set_timeout(mRequest.request_header().timeout_hint());
    arm_partial_result_deadline(mRequest.request_header().timeout_hint());
    mRequestInfo = service_request_info(
      arrival, mRequest.request_header().timeout_hint(), mPartialResultDeadline, mCancelled, mSessionLocales);

    auto addressSpace = sessionInfo->address_space();

    auto historyReadResponse = make_shared<HistoryReadResponse>();
    HistoryReadServiceResponse serviceResponse;
    serviceResponse.response = std::pair(mRequestId, historyReadResponse);

    // Whole-request validation failures are returned as a ServiceFault, not a normal
    // HistoryReadResponse carrying the bad code in its header (Part 4 7.34: a Bad ServiceResult
    // with no per-operation results is delivered as a ServiceFault). CTT Read Raw Err-001/003/026/027
    // explicitly check the message is a ServiceFault.
    auto finishWithServiceError = [&](StatusCode status)
    {
      collector.set_service_detail(status);
      send_service_fault(mRequest.request_header(), status, collector);
    };

    const size_t noOfOperations = mRequest.nodes_to_read().size();
    if (noOfOperations == 0)
    {
      finishWithServiceError(Status::BadNothingToDo);
      return;
    }

    const auto& opLimits = sessionInfo->server_configuration().server_capabilities().operationLimits;
    // Part 4 5.11 advertises SEPARATE ceilings for history data reads and history event reads, and a
    // client reads both from the OperationLimits nodes before sizing its requests. Pick the ceiling that
    // matches this request's details: applying the data ceiling to an event read would bound event reads
    // by a limit the server never advertised for them, and leave the advertised event ceiling inert.
    const auto& historyReadLimit =
      (dynamic_cast<const ReadEventDetails*>(mRequest.history_read_details().get()) != nullptr)
        ? opLimits.maxNodesPerHistoryReadEvents
        : opLimits.maxNodesPerHistoryReadData;
    if (historyReadLimit.has_value() && *historyReadLimit > 0 && noOfOperations > *historyReadLimit)
    {
      finishWithServiceError(Status::BadTooManyOperations);
      return;
    }

    auto* details = mRequest.history_read_details().get();
    if (!details)
    {
      finishWithServiceError(Status::BadHistoryOperationInvalid);
      return;
    }

    // releaseContinuationPoints fast-path (OPC 10000-11 6.3): the Server returns no data and
    // releases all continuation points passed in the request. Per item the status is *not* a
    // blanket Good - an operation whose continuation point is missing or invalid shall return
    // Bad_ContinuationPointInvalid; only a successfully-released (valid) point returns Good.
    // (retrieve_continuation_points already pulled the matching points out of the session, so a
    // Found entry has been released; a Fresh/Invalid item never had a live point to release.)
    if (mRequest.release_continuation_points())
    {
      historyReadResponse->results().resize(noOfOperations);
      for (size_t i = 0; i < noOfOperations; ++i)
      {
        const auto lookup = history_read_validation::lookup_continuation_point(
          mRequest.nodes_to_read()[i], mContinuationPointsIn);
        historyReadResponse->results()[i].status_code() =
          lookup.kind == history_read_validation::ContinuationKind::Found
            ? StatusCode{Status::Good}
            : StatusCode{Status::BadContinuationPointInvalid};
      }
      stack_utils::prepare_response_header(mRequest.request_header(), historyReadResponse->response_header());
      if (!try_finish())
        return;
      mCallback(std::move(serviceResponse));
      return;
    }

    auto* rawDetails = dynamic_cast<ReadRawModifiedDetails*>(details);
    auto* processedDetails = dynamic_cast<ReadProcessedDetails*>(details);
    auto* annotationDetails = dynamic_cast<ReadAnnotationDataDetails*>(details);
    auto* atTimeDetails = dynamic_cast<ReadAtTimeDetails*>(details);
    auto* eventDetails = dynamic_cast<ReadEventDetails*>(details);
    if (!rawDetails && !processedDetails && !annotationDetails && !atTimeDetails && !eventDetails)
    {
      // The five concrete types above are every standard HistoryReadDetails subtype dispatched to the
      // delegate. An extension object that is none of them is not a valid HistoryReadDetails for this
      // operation, so the whole request fails with Bad_HistoryOperationInvalid - mirroring the
      // HistoryUpdate path, which returns Invalid for a wrong-subtype details (HU-D). Unsupported is
      // reserved for a *valid* details type the delegate cannot service (e.g. ReadEventDetails with no
      // event history), which the delegate's default per-item hook reports.
      finishWithServiceError(Status::BadHistoryOperationInvalid);
      return;
    }

    const bool hasFreshReads = std::ranges::any_of(
      mRequest.nodes_to_read(), [](const auto& item) { return item.continuation_point().empty(); });

    if (rawDetails && hasFreshReads)
    {
      // ReadRawModifiedDetails spec: at least 2 of {startTime, endTime, numValuesPerNode} required
      // when there are fresh reads. Continuation requests may carry empty details.
      int specifiedCount = 0;
      if (!rawDetails->start_time().is_null())
        ++specifiedCount;
      if (!rawDetails->end_time().is_null())
        ++specifiedCount;
      if (rawDetails->num_values_per_node() > 0)
        ++specifiedCount;
      if (specifiedCount < 2)
      {
        finishWithServiceError(Status::BadHistoryOperationInvalid);
        return;
      }
    }

    if (processedDetails && hasFreshReads)
    {
      // ReadProcessedDetails requires a bounded window and one aggregate function per node.
      if (processedDetails->start_time().is_null() || processedDetails->end_time().is_null() ||
          !std::isfinite(processedDetails->processing_interval()) ||
          processedDetails->processing_interval() < 0.0)
      {
        finishWithServiceError(Status::BadHistoryOperationInvalid);
        return;
      }
      // startTime == endTime has no meaningful aggregate interval (Part 11 6.4.4.2 / SVR-HIST-AGG-025).
      if (processedDetails->start_time() == processedDetails->end_time())
      {
        finishWithServiceError(Status::BadInvalidArgument);
        return;
      }
      // ReadProcessed returns aggregate values stamped with the (computed) source timestamp; any other
      // TimestampsToReturn is invalid (Part 13 5.4.3.1 / SVR-HIST-AGG-027 - note the registered
      // identifier is the plural Bad_TimestampsToReturnInvalid, per 3.19.11 Q-H6).
      if (mRequest.timestamps_to_return() != TimestampsToReturn::Source)
      {
        finishWithServiceError(Status::BadTimestampsToReturnInvalid);
        return;
      }
      if (processedDetails->aggregate_type().size() != noOfOperations)
      {
        finishWithServiceError(Status::BadAggregateListMismatch);
        return;
      }
    }

    if (atTimeDetails && hasFreshReads && atTimeDetails->req_times().empty())
    {
      // ReadAtTimeDetails requires at least one requested timestamp (Part 11 6.4.4).
      finishWithServiceError(Status::BadHistoryOperationInvalid);
      return;
    }

    if (eventDetails && hasFreshReads)
    {
      if (eventDetails->filter().select_clauses().empty())
      {
        finishWithServiceError(StatusCode{Status::BadHistoryOperationInvalid,
          ErrorDetail::build("EventFilterSelectClausesEmpty",
            "ReadEventDetails requires at least one selected Event field",
            "HistoryReadService")
            .context(ua::ContextKeys::sizeActual, size_t{0})
            .context(ua::ContextKeys::sizeMin, size_t{1})});
        return;
      }

      // ReadEventDetails needs a bounded window: at least 2 of {startTime, endTime, numValuesPerNode}
      // (Part 11 6.4.2, same rule as raw).
      int specifiedCount = 0;
      if (!eventDetails->start_time().is_null())
        ++specifiedCount;
      if (!eventDetails->end_time().is_null())
        ++specifiedCount;
      if (eventDetails->num_values_per_node() > 0)
        ++specifiedCount;
      if (specifiedCount < 2)
      {
        finishWithServiceError(Status::BadHistoryOperationInvalid);
        return;
      }
    }

    // NEITHER is a valid enumerator that no HistoryRead of historical values can honour: a value
    // with no timestamp has no position in the history. The two parts disagree on the code. Part 4
    // 5.10.3.2 (Table 56) says Bad_InvalidTimestampArgument, a code Part 4 lists only at operation
    // level (Table 58); Part 11 4.5, the history-specific text, says "will be rejected with
    // Bad_TimestampsToReturnInvalid", the Service-level code of Table 57, and CTT Read Raw Err-002
    // accepts only that. The Service follows Part 11 (SVR-ATTR-HREAD-004). A separate branch keeps
    // the diagnostic distinct from a malformed out-of-range enumerator. Part 11 4.5 exempts Event
    // history from the parameter entirely.
    auto tsr = mRequest.timestamps_to_return();
    if (!eventDetails && tsr == TimestampsToReturn::Neither)
    {
      finishWithServiceError(StatusCode{Status::BadTimestampsToReturnInvalid,
        ErrorDetail::build("HistoryTimestampsToReturnNeither",
          "HistoryRead of historical values cannot omit both timestamps",
          "HistoryReadService")
          .context(ContextKeys::actual, utils::to_underlying(tsr))});
      return;
    }
    if (!eventDetails && utils::to_underlying(tsr) > utils::to_underlying(TimestampsToReturn::Neither))
    {
      finishWithServiceError(StatusCode{Status::BadTimestampsToReturnInvalid,
        ErrorDetail::build("HistoryTimestampsToReturnOutOfRange",
          "HistoryRead timestampsToReturn is outside the enumeration range",
          "HistoryReadService")
          .context(ContextKeys::actual, utils::to_underlying(tsr))});
      return;
    }

    historyReadResponse->results().resize(noOfOperations);
    mStaged.resize(noOfOperations);

    if (processedDetails && hasFreshReads &&
        !processedDetails->aggregate_configuration().use_server_capabilities_defaults())
    {
      const auto percentGood = processedDetails->aggregate_configuration().percent_data_good();
      const auto percentBad = processedDetails->aggregate_configuration().percent_data_bad();
      const bool percentagesInRange = percentGood <= 100 && percentBad <= 100;
      const bool relationshipValid =
        percentagesInRange && percentGood >= static_cast<uint8_t>(100 - percentBad);
      if (!relationshipValid)
      {
        const StatusCode status{Status::BadAggregateInvalidInputs,
          ErrorDetail::build("AggregateConfigurationInvalid",
            "AggregateConfiguration percentages violate the Part 13 validity invariant",
            "HistoryReadService")
            .context(ContextKeys::actual,
              "percentDataGood=" + std::to_string(percentGood) +
                ",percentDataBad=" + std::to_string(percentBad))
            .context(
              ContextKeys::expected, "both percentages <= 100 and percentDataGood >= 100 - percentDataBad")};
        for (size_t i = 0; i < noOfOperations; ++i)
        {
          historyReadResponse->results()[i].status_code() = status;
          collector.add_item_detail(i, status.shared_detail());
        }
        collector.apply_to(
          historyReadResponse->response_header(), historyReadResponse->diagnostic_infos(), noOfOperations);
        stack_utils::prepare_response_header(
          mRequest.request_header(), historyReadResponse->response_header());
        if (!try_finish())
          return;
        mCallback(std::move(serviceResponse));
        return;
      }
    }

    mFlow = std::make_unique<HistoryReadState>(std::move(addressSpace),
      historyReadResponse,
      std::move(serviceResponse),
      std::move(collector),
      rawDetails,
      processedDetails,
      annotationDetails);
    mFlow->atTimeDetails = atTimeDetails;
    mFlow->eventDetails = eventDetails;
    mFlow->accessControl = SessionAccessControl::create(*sessionInfo);
    // Capture the advertised per-node caps for this request. Read once here rather than per dispatch so
    // every namespace bucket of one request is bounded by the same numbers.
    const auto& historyConfig = sessionInfo->server_configuration().historyConfiguration;
    mFlow->maxReturnDataValues = historyConfig.maxReturnDataValues;
    mFlow->maxReturnEventValues = historyConfig.maxReturnEventValues;

    // Walk all items: continuation items grouped immediately, fresh items queued for find_node.
    for (size_t i = 0; i < noOfOperations; ++i)
    {
      auto& nodeToRead = mRequest.nodes_to_read()[i];
      auto& result = mFlow->response->results()[i];

      if (!nodeToRead.continuation_point().empty())
      {
        const auto lookup =
          history_read_validation::lookup_continuation_point(nodeToRead, mContinuationPointsIn);
        if (lookup.kind != history_read_validation::ContinuationKind::Found)
        {
          result.status_code() = Status::BadContinuationPointInvalid;
          continue;
        }

        HistoryReadState::ItemEntry entry;
        entry.originalIndex = i;
        entry.nodeId = nodeToRead.node_id();
        entry.indexRange = nodeToRead.index_range();
        entry.namespaceIndex = lookup.entry->namespace_index();
        entry.fromContinuation = true;
        auto& staged = mStaged[i];
        staged.state = StagedItem::State::Running;
        staged.namespaceIndex = entry.namespaceIndex;
        staged.continuing = true;
        if (auto paused = lookup.entry->take_paused())
        {
          // A point handed out at an earlier request's partial-result deadline: that read is still
          // running (or has finished) there. The item is authorized like any resume, then waits for it.
          staged.waitingOn = std::static_pointer_cast<PausedHistory>(std::move(paused));
        }
        else
        {
          entry.cursor = std::move(lookup.entry->cursor());
          entry.delegate = lookup.entry->delegate();
        }
        if (processedDetails && i < processedDetails->aggregate_type().size())
          entry.aggregateType = processedDetails->aggregate_type()[i];
        // Route continuation-point resumes through the same find_node -> classify -> HistoryRead authz
        // gate as fresh reads (resolve_items), re-authorizing against the CURRENT session identity
        // (Part 4 6.2.1). A stored continuation point carries no identity binding, so resuming it MUST be
        // re-checked - otherwise a session re-activated as a lower-privilege identity could inherit a
        // cursor created under a higher-privilege one and read history it can no longer access. The
        // entry's stored cursor/delegate/namespaceIndex are preserved across resolution (the body
        // does not overwrite them), so an authorized resume still reads via the bound delegate at the
        // saved position.
        mFlow->freshReads.push_back(std::move(entry));
      }
      else
      {
        if (nodeToRead.node_id().is_null())
        {
          result.status_code() = Status::BadNodeIdInvalid;
          continue;
        }

        HistoryReadState::ItemEntry entry;
        entry.originalIndex = i;
        entry.nodeId = nodeToRead.node_id();
        entry.indexRange = nodeToRead.index_range();
        entry.namespaceIndex = nodeToRead.node_id().namespace_index();
        entry.fromContinuation = false;
        mStaged[i].state = StagedItem::State::Running;
        mStaged[i].namespaceIndex = entry.namespaceIndex;
        if (processedDetails && i < processedDetails->aggregate_type().size())
          entry.aggregateType = processedDetails->aggregate_type()[i];
        mFlow->freshReads.push_back(std::move(entry));
      }
    }

    // An empty item list is not a special case any more: the body spawns nothing, joins nothing, and
    // falls through to the dispatch, which answers a request whose every row was already refused.
    start_request();
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "HistoryReadService", er);
    }
    if (mFlow)
    {
      fail_history_read(VoidResult{er, er.shared_detail()});
    }
    else
    {
      collector.set_service_detail(er);
      send_service_fault(mRequest.request_header(), er, collector);
    }
  }
}

void HistoryReadService::start_request()
{
  // A per-request service handles exactly ONE HistoryRead, so there is no next request to race the
  // slot - the generation guard a strand component needs has nothing to guard here. The body may
  // still finish entirely before this returns, which is why the service is kept alive across this
  // call by the posted handler that reached it.
  mRequestTask = run_history_read();
}

ua::async::Task<> HistoryReadService::run_history_read()
{
  // A ROOT task: nobody awaits `mRequestTask`, so an exception that escaped this body would be
  // stored in a promise nobody can read, and the client's HistoryRead would never be answered at
  // all - no response and no fault. The chain this replaces did not need to say so, because its
  // spawn loop ran inside `start_history_read`'s own try; moving the loop into a coroutine body
  // moved it out of that try's reach, and this is what puts it back.
  try
  {
    co_await resolve_items();
    if (!mFlow)
    {
      co_return;
    }

    // The item bodies are LOCALS of this frame. Unwinding this body destroys them and retires their
    // continuations without anything being told, which is why there is no vector of them on the
    // service and nothing that can free a frame from inside one.
    std::vector<ua::async::Task<>> items;
    const size_t freshReadCount = mFlow->freshReads.size();
    items.reserve(freshReadCount);

    // Started EAGERLY, all of them, before any is awaited: a task runs to its first suspension when
    // it is created, so this is what makes the request's wall time its slowest item rather than the
    // sum of all of them.
    for (size_t freshIndex = 0; freshIndex < freshReadCount; ++freshIndex)
    {
      if (!mFlow)
      {
        co_return;
      }
      auto& entry = mFlow->freshReads[freshIndex];
      if (!entry.authorized)
      {
        continue;
      }
      // An event read names no dataEncoding, so there is nothing to classify for one.
      if (mFlow->is_events() || mRequest.nodes_to_read()[entry.originalIndex].data_encoding().name().empty())
      {
        entry.accepted = true;
        continue;
      }

      // Each spawn is contained on its own, and it has to be: what can throw here is the frame
      // allocation or the vector's growth, and neither can be caught inside the body being started,
      // because if its frame could not be allocated its `try` does not exist. One item that cannot
      // be started answers its own row and the rest of the request carries on.
      try
      {
        items.push_back(classify_item_encoding(freshIndex));
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        const auto failure = ua::exception_to_status_code(std::current_exception());
        history_result(entry.originalIndex).status_code() = failure;
        stage_history_detail(entry.originalIndex, failure.shared_detail());
      }
    }

    // The join IS the barrier. Each item has already recorded its own verdict, so there is nothing
    // to collect here - only to wait.
    for (auto& item : items)
    {
      try
      {
        // Moved because a Task's `operator co_await` is rvalue-qualified. The awaiter only BORROWS
        // the frame handle - the Task in this vector still owns the frame, and still destroys it
        // when this frame unwinds.
        co_await std::move(item);
      }
      catch (const ua::async::Abandoned&)
      {
        // The whole request has been withdrawn and already answered; stop, and let the rest of the
        // items be destroyed with this frame.
        co_return;
      }
      catch (...)
      {
        // An item body contains its own failures, so reaching here means the containment itself
        // threw. Its row keeps whatever status it already had, and the items that can still answer
        // are still waited for.
        log_exception(mLogger,
          LogLevel::Error,
          "HistoryReadService: an item resolution's own containment threw",
          ua::exception_to_status_code(std::current_exception()));
      }
    }

    if (!mFlow)
    {
      co_return;
    }

    // Grouped AFTER the join, walking the items in REQUEST order. The chain grouped from inside each
    // item's last handler, so the order within a namespace's batch was the order the resolutions
    // COMPLETED. The response is keyed by `originalIndex` either way, so no client can tell - but a
    // delegate sees the batch it is handed, and callback order is not something to hand it on
    // purpose. This is a deliberate narrowing of what the old contract allowed, not a departure from
    // it.
    // Items the resolution refused are finished here; accepted items continuing a paused read wait
    // for it; the rest are grouped for one delegate call per namespace.
    std::vector<size_t> waitIndices;
    for (auto& entry : mFlow->freshReads)
    {
      auto& staged = mStaged[entry.originalIndex];
      if (!entry.accepted)
      {
        // A refused resume stops the read it was waiting for - unless the deadline already handed that
        // read to a new continuation point, whose own resume will be authorized again.
        if (staged.waitingOn && staged.state != StagedItem::State::Paused)
        {
          staged.waitingOn->release();
        }
        staged.waitingOn.reset();
        finish_history_item(entry.originalIndex);
        continue;
      }
      if (staged.waitingOn)
      {
        waitIndices.push_back(entry.originalIndex);
        continue;
      }
      mFlow->itemsByNamespace[entry.namespaceIndex].push_back(std::move(entry));
    }
    std::vector<ua::async::Task<>> waits;
    waits.reserve(waitIndices.size());
    for (const auto index : waitIndices)
    {
      waits.push_back(run_history_wait(index));
    }

    if (mFlow->is_events() && !mFlow->itemsByNamespace.empty())
    {
      co_await validate_event_select_clause_model();
    }

    if (!mFlow)
    {
      co_return;
    }
    co_await run_namespace_reads();
    for (auto& wait : waits)
    {
      co_await std::move(wait);
    }
    if (mFlow)
    {
      complete_history_read();
    }
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the request and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mFlow)
        {
          fail_history_read(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
  co_return;
}

namespace
{

// What a whole-lookup failure answers for each of its items.
NodeAccessorResult lookup_answer(const BatchResult<NodeAccessorResult>& found, size_t index, size_t count)
{
  if (found.batchStatus.is_bad())
  {
    return NodeAccessorResult{found.batchStatus.status_code()};
  }
  if (found.items.size() != count)
  {
    return NodeAccessorResult{StatusCode{Status::BadInternalError,
      ErrorDetail::build("LookupCountMismatch",
        "The lookup answered another number of items than it was asked for",
        "HistoryReadService")
        .context(ContextKeys::sizeExpected, std::to_string(count))
        .context(ContextKeys::sizeActual, std::to_string(found.items.size()))}};
  }
  return found.items[index];
}

}  // namespace

ua::async::Task<> HistoryReadService::resolve_items()
{
  if (!mFlow || mFlow->freshReads.empty())
  {
    co_return;
  }

  // One lookup for every item, fresh reads and resumes alike: a resume is re-authorized as a fresh read is.
  const size_t count = mFlow->freshReads.size();
  std::vector<ua::detail::LookupItem> lookups;
  lookups.reserve(count);
  for (const auto& entry : mFlow->freshReads)
  {
    lookups.push_back(ua::detail::LookupItem{entry.nodeId, std::nullopt});
  }
  auto found = co_await await_step<BatchResult<NodeAccessorResult>>(
    [this, &lookups](auto completion)
    {
      ua::detail::NodeAccessorRoute::find_nodes(
        mFlow->addressSpace.weak(), mRequestInfo, lookups, std::move(completion));
    });
  if (!mFlow || mFlow->freshReads.size() != count)
  {
    co_return;
  }

  const auto refuse = [this](size_t originalIndex, const StatusCode& status)
  {
    history_result(originalIndex).status_code() = status;
    if (auto detail = status.shared_detail())
    {
      stage_history_detail(originalIndex, std::move(detail));
    }
  };

  // Per item, in request order: the lookup's answer, then the history access its description allows.
  const auto requestedAccess = mFlow->is_events() ? history_read_validation::HistoryAccessKind::Events
                                                  : history_read_validation::HistoryAccessKind::Values;
  std::vector<AccessControl::Item> authorizationItems;
  std::vector<size_t> candidates;
  for (size_t freshIndex = 0; freshIndex < count; ++freshIndex)
  {
    auto& entry = mFlow->freshReads[freshIndex];
    NodeAccessorResult result = lookup_answer(found, freshIndex, count);
    if (!result.is_good())
    {
      refuse(entry.originalIndex,
        ::ua::detail::lookup_failure(entry.nodeId, result.status_code(), "HistoryReadService"));
      continue;
    }
    const NodeAccessor node = result.value();
    if (node->deleted())
    {
      refuse(entry.originalIndex,
        StatusCode{Status::BadNodeIdUnknown,
          ErrorDetail::build("NodeDeleted", "The node has been deleted", "HistoryReadService")
            .context(ContextKeys::nodeId, to_string(entry.nodeId))});
      continue;
    }
    std::optional<NodeDescription> nodeDescription;
    try
    {
      nodeDescription = node->attributes();
    }
    catch (...)
    {
      refuse(entry.originalIndex, ua::exception_to_status_code(std::current_exception()));
      continue;
    }
    const StatusCode access =
      history_read_validation::classify_history_access(*nodeDescription, requestedAccess);
    if (!access.is_good())
    {
      refuse(entry.originalIndex, access);
      continue;
    }
    entry.resolvedNode = node;
    entry.description = nodeDescription;
    authorizationItems.push_back(AccessControl::Item{
      .node = node, .operation = AccessOperation::HistoryRead, .description = std::move(nodeDescription)});
    candidates.push_back(freshIndex);
  }
  if (candidates.empty())
  {
    co_return;
  }

  // Failed closed: a request with no committed access identity is refused, never allowed through.
  if (!mFlow->accessControl)
  {
    for (const size_t freshIndex : candidates)
    {
      refuse(mFlow->freshReads[freshIndex].originalIndex, StatusCode{Status::BadUserAccessDenied});
    }
    co_return;
  }

  // One authorization for every item that can be read.
  auto verdicts =
    co_await await_step<std::vector<AccessControl::Verdict>>([this, &authorizationItems](auto completion)
      { mFlow->accessControl->authorize_async(mRequestInfo, authorizationItems, std::move(completion)); });
  if (!mFlow || mFlow->freshReads.size() != count)
  {
    co_return;
  }
  if (verdicts.size() != candidates.size())
  {
    const StatusCode mismatch{Status::BadInternalError,
      ErrorDetail::build("VerdictCountMismatch",
        "Access control answered another number of verdicts than the items it was asked about",
        "HistoryReadService")
        .context(ContextKeys::sizeExpected, std::to_string(candidates.size()))
        .context(ContextKeys::sizeActual, std::to_string(verdicts.size()))};
    for (const size_t freshIndex : candidates)
    {
      refuse(mFlow->freshReads[freshIndex].originalIndex, mismatch);
    }
    co_return;
  }
  for (size_t k = 0; k < candidates.size(); ++k)
  {
    auto& entry = mFlow->freshReads[candidates[k]];
    if (auto denial = detail::first_denial(std::span<const AccessControl::Verdict>{&verdicts[k], 1}, 1))
    {
      refuse(entry.originalIndex, *denial);
      continue;
    }
    entry.authorized = true;
  }
}

ua::async::Task<> HistoryReadService::classify_item_encoding(size_t freshIndex)
{
  // Re-indexed after EVERY suspension rather than held as a reference, because a reference into
  // `freshReads` is only as good as the moment it was taken. The vector is not resized while the
  // classification runs - the grouping happens after the join - but writing it this way is what makes
  // that a property of this function rather than of something a later change has to remember.
  if (!mFlow || freshIndex >= mFlow->freshReads.size())
  {
    co_return;
  }
  const size_t originalIndex = mFlow->freshReads[freshIndex].originalIndex;

  // A dataEncoding applies only to a Variable whose DataType is a subtype of Structure. Anything
  // else is "invalid" rather than "unsupported", and the two are different answers to the client.
  // A Variable whose description carries no DataType is not a Structure.
  BoolResult isStructureType{false};
  const auto& nodeDescription = mFlow->freshReads[freshIndex].description;
  if (const NodeId* dataType = nodeDescription && nodeDescription->node_class() == NodeClass::Variable
                                 ? nodeDescription->data_type()
                                 : nullptr;
      dataType != nullptr)
  {
    const NodeId dataTypeId = *dataType;
    isStructureType = co_await await_step<BoolResult>(
      [this, &dataTypeId](auto completion)
      {
        is_data_type_or_subtype_async(
          mFlow->addressSpace, dataTypeId, NodeId{DataTypeId::Structure}, std::move(completion));
      });

    if (!mFlow || freshIndex >= mFlow->freshReads.size())
    {
      co_return;
    }
  }

  if (!isStructureType.is_good())
  {
    history_result(originalIndex).status_code() = isStructureType.status_code();
    if (auto detail = isStructureType.shared_detail())
    {
      stage_history_detail(originalIndex, std::move(detail));
    }
    co_return;
  }

  const auto& requestedEncoding = mRequest.nodes_to_read()[originalIndex].data_encoding();
  StatusCode encodingStatus;
  if (!isStructureType.value())
  {
    encodingStatus = StatusCode{Status::BadDataEncodingInvalid,
      ErrorDetail::build("HistoryDataEncodingInvalid",
        "A history data encoding cannot be applied because the Variable DataType is not a subtype of "
        "Structure",
        "HistoryReadService")
        .context(ua::ContextKeys::nodeId, ua::to_string(mFlow->freshReads[freshIndex].nodeId))
        .context(ua::ContextKeys::encoding, std::string{requestedEncoding.name()})};
  }
  else if (requestedEncoding.name() != "Default Binary")
  {
    encodingStatus = StatusCode{Status::BadDataEncodingUnsupported,
      ErrorDetail::build("HistoryDataEncodingUnsupported",
        "The requested history data encoding is not provided",
        "HistoryReadService")
        .context(ua::ContextKeys::nodeId, ua::to_string(mFlow->freshReads[freshIndex].nodeId))
        .context(ua::ContextKeys::encoding, std::string{requestedEncoding.name()})};
  }

  if (encodingStatus.is_bad())
  {
    history_result(originalIndex).status_code() = encodingStatus;
    stage_history_detail(originalIndex, encodingStatus.shared_detail());
    co_return;
  }

  mFlow->freshReads[freshIndex].accepted = true;
  co_return;
}

ua::async::Task<> HistoryReadService::validate_event_select_clause_model()
{
  if (!mFlow || !mFlow->eventDetails)
  {
    co_return;
  }

  // A null typeDefinitionId evaluates the BrowsePath without regard to the type (OPC 10000-4 7.7.4.5,
  // Table 133), so live delivery finds its declaration from BaseEventType down; resolve it as
  // BaseEventType to authorize it the same way. The statuses handed to the delegate stay as the clause
  // was written: a null type is not checked against the model.
  EventFilter resolvable = mFlow->eventDetails->filter();
  for (auto& clause : resolvable.select_clauses())
  {
    // An empty BrowsePath names the type itself, which a null type does not name; live delivery has no
    // declaration for it either.
    if (clause.type_definition_id().is_null() && !clause.browse_path().empty())
      clause.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  }
  auto models = co_await await_step<event_type_model::SelectClauseModelsResult>(
    [this, &resolvable](auto completion)
    {
      event_type_model::resolve_select_clause_models_async(
        mFlow->addressSpace, std::move(resolvable), std::move(completion));
    });

  if (!mFlow || !mFlow->eventDetails)
  {
    co_return;
  }

  const auto& clauses = mFlow->eventDetails->filter().select_clauses();
  const bool modelResolved = models.is_good() && models.value().size() == clauses.size();
  if (modelResolved)
  {
    mFlow->eventSelectClauseModelStatuses.clear();
    mFlow->eventSelectClauseModelStatuses.reserve(clauses.size());
    for (size_t i = 0; i < clauses.size(); ++i)
    {
      mFlow->eventSelectClauseModelStatuses.push_back(
        clauses[i].type_definition_id().is_null() ? StatusCode{Status::Good} : models.value()[i].status);
    }
  }
  else
  {
    // EventType membership is advisory for projection: failure to establish membership means a
    // missing stored field remains null rather than being falsely reported as BadNoData. Preserve
    // the rich failure on every clause status until the delegate consumes the request metadata.
    mFlow->eventSelectClauseModelStatuses.assign(clauses.size(), models.status_code());

    // Scoped so the session reference ends with the statement that needs it. A body holds its locals
    // to the end of their scope, and a lock that outlived this would make every later "has the session
    // gone?" question unaskable (R7).
    {
      if (auto sessionInfo = mSessionInfo.lock())
      {
        log_exception(sessionInfo->logger().with_category("service"),
          LogLevel::Error,
          "HistoryReadService EventType model validation",
          models.status_code());
      }
    }
  }

  // An archived field is authorized as live delivery authorizes it (OPC 10000-4 7.22.3): on the clause's
  // InstanceDeclaration, here the one on the clause's typeDefinitionId, decided once for the request. An
  // archive holds field values whatever Attribute a clause names, so every clause needs Read on its
  // declaration, except the ConditionId operand (empty BrowsePath, NodeId), which live delivery
  // authorizes by Browse on the type. Failed closed: an unresolved model, a missing declaration that
  // the delegate answered with a value, or a missing verdict withholds the field.
  using Rule = HistoryReadState::EventFieldRule;
  auto& rules = mFlow->eventFieldRules;
  rules.assign(clauses.size(), Rule{});
  std::vector<AccessControl::Item> items;
  std::vector<size_t> itemClause;
  for (size_t i = 0; i < clauses.size(); ++i)
  {
    const auto& clause = clauses[i];
    ResolvedSelectClause resolved;
    resolved.browsePath.assign(clause.browse_path().begin(), clause.browse_path().end());
    if (CompiledEventFilter::is_inviolate_field(resolved))
    {
      rules[i].kind = Rule::Kind::Keep;
      continue;
    }
    if (!modelResolved)
    {
      rules[i].denial = StatusCode{Status::BadUserAccessDenied,
        ErrorDetail::build("EventFieldDeclarationModelUnavailable",
          "The EventType declaration model could not be resolved for authorization",
          "HistoryReadService")
          .cause(models.status_code())};
      continue;
    }
    const auto& model = models.value()[i];
    if (model.status.is_bad() || !model.declarationAccessor)
    {
      // No declaration to authorize against: an invalid clause, or a field declared only by a subtype.
      // The store answers by browse names alone, so a value here is withheld rather than trusted.
      rules[i].kind = Rule::Kind::DenyIfValue;
      rules[i].denial = StatusCode{Status::BadUserAccessDenied,
        ErrorDetail::build("EventFieldDeclarationUnavailable",
          "The Event field declaration could not be resolved for authorization",
          "HistoryReadService")};
      continue;
    }
    const auto attribute = clause.attribute_id() == 0
                             ? AttributeId::Value
                             : utils::from_underlying<AttributeId>(clause.attribute_id());
    const bool conditionId = clause.browse_path().empty() && attribute == AttributeId::NodeId;
    items.push_back(AccessControl::Item{.node = *model.declarationAccessor,
      .operation = conditionId ? AccessControl::attribute_read_operation(attribute) : AccessOperation::Read});
    itemClause.push_back(i);
  }
  if (items.empty() || !mFlow->accessControl)
  {
    co_return;
  }

  auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this, &items](auto completion)
    { mFlow->accessControl->authorize_async(mRequestInfo, items, std::move(completion)); });
  if (!mFlow || mFlow->eventFieldRules.size() != clauses.size() || verdicts.size() != items.size())
  {
    co_return;  // a short or mismatched answer leaves the affected fields at their default: withheld
  }
  for (size_t k = 0; k < verdicts.size(); ++k)
  {
    auto& rule = mFlow->eventFieldRules[itemClause[k]];
    const auto& verdict = verdicts[k];
    if (verdict.permitted)
    {
      rule.kind = Rule::Kind::Keep;
      continue;
    }
    if (verdict.cause.is_bad())
    {
      rule.denial = verdict.cause.as_status() == Status::BadUserAccessDenied
                      ? verdict.cause
                      : StatusCode{Status::BadUserAccessDenied,
                          ErrorDetail::build("EventFieldReadDenied",
                            "The current Session user may not read the selected Event field",
                            "HistoryReadService")
                            .cause(verdict.cause)};
    }
  }
}

ua::async::Task<> HistoryReadService::run_namespace_reads()
{
  if (!mFlow)
  {
    co_return;
  }

  // Visited in ASCENDING namespace order. `itemsByNamespace` is an unordered map, so the chain
  // visited its namespaces in hash order; nothing a client can observe depends on it, because every
  // row is keyed by `originalIndex` - but a delegate sees WHEN it is called, and hash order is not
  // something to hand it on purpose. A deliberate narrowing of what the old contract allowed.
  std::vector<uint16_t> namespaceIndices;
  namespaceIndices.reserve(mFlow->itemsByNamespace.size());
  for (const auto& [nsIndex, _] : mFlow->itemsByNamespace)
  {
    namespaceIndices.push_back(nsIndex);
  }
  std::sort(namespaceIndices.begin(), namespaceIndices.end());

  // The namespace bodies are LOCALS of this frame, and they are started EAGERLY - a task runs to
  // its first suspension when it is created - so the request's wall time is its slowest namespace
  // rather than the sum of all of them.
  std::vector<ua::async::Task<>> reads;
  reads.reserve(namespaceIndices.size());

  for (auto nsIndex : namespaceIndices)
  {
    if (!mFlow)
    {
      co_return;
    }

    // Contained per SPAWN: what can throw here is the frame allocation or the vector's growth, and
    // neither can be caught inside the body being started, because if its frame could not be
    // allocated its `try` does not exist. A namespace that cannot be started answers its own rows.
    try
    {
      reads.push_back(run_namespace_read(nsIndex));
    }
    catch (const ua::async::Abandoned&)
    {
      throw;
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      for (const auto& item : mFlow->itemsByNamespace.at(nsIndex))
      {
        history_result(item.originalIndex).status_code() = failure;
        stage_history_detail(item.originalIndex, failure.shared_detail());
        finish_history_item(item.originalIndex);
      }
    }
  }

  // The join IS the barrier. Each namespace has already written its own rows, so there is nothing to
  // collect here - only to wait. An empty request joins nothing and falls straight through to the
  // answer, which is what the chain needed a separate early-complete branch for.
  for (auto& read : reads)
  {
    try
    {
      co_await std::move(read);
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      log_exception(mLogger,
        LogLevel::Error,
        "HistoryReadService: a namespace read's own containment threw",
        ua::exception_to_status_code(std::current_exception()));
    }
  }

  // The request is completed by run_history_read, once the waits for paused reads are joined too.
}

ua::async::Task<> HistoryReadService::run_namespace_read(uint16_t namespaceIndex)
{
  std::vector<size_t> indices;
  for (const auto& item : mFlow->itemsByNamespace.at(namespaceIndex))
  {
    indices.push_back(item.originalIndex);
  }
  try
  {
    if (mFlow->is_processed())
      co_await read_namespace_processed(namespaceIndex);
    else if (mFlow->is_annotation())
      co_await read_namespace_annotations(namespaceIndex);
    else if (mFlow->is_at_time())
      co_await read_namespace_at_time(namespaceIndex);
    else if (mFlow->is_events())
      co_await read_namespace_events(namespaceIndex);
    else
      co_await read_namespace_raw(namespaceIndex);
  }
  catch (const ua::async::Abandoned&)
  {
    throw;
  }
  catch (...)
  {
    const auto failure = ua::exception_to_status_code(std::current_exception());
    for (const auto index : indices)
    {
      history_result(index).status_code() = failure;
      stage_history_detail(index, failure.shared_detail());
    }
  }
  for (const auto index : indices)
  {
    finish_history_item(index);
  }
}

ua::async::Task<> HistoryReadService::read_namespace_raw(uint16_t namespaceIndex)
{
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  shared_ptr<NamespaceHistoryDelegate> namespaceDelegate;
  if (ns)
  {
    namespaceDelegate = ns->history_delegate();
  }

  if (!namespaceDelegate && !items.front().delegate)
  {
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = Status::BadHistoryOperationUnsupported;
    }
    co_return;
  }

  // Continuation items carry their own delegate (the one that issued the cursor); fresh items use
  // the namespace's current delegate. Within one namespace bucket we use the delegate from the
  // first entry if it has one (CP-driven), otherwise the namespace delegate.
  auto delegateToUse = items.front().delegate ? items.front().delegate : namespaceDelegate;

  std::vector<NamespaceHistoryDelegate::ReadRawItem> rawItems;
  rawItems.reserve(items.size());
  for (auto& item : items)
  {
    NamespaceHistoryDelegate::ReadRawItem rawItem;
    rawItem.index = item.originalIndex;
    rawItem.nodeId = item.nodeId;
    rawItem.indexRange = item.indexRange;
    rawItem.startTime = flow.rawDetails->start_time();
    rawItem.endTime = flow.rawDetails->end_time();
    // OPC 10000-11 5.2 / 6.4.3: bound the client's numValuesPerNode by the server's advertised
    // MaxReturnDataValues. The cap is PER NODE, so it is applied to each item rather than as a budget
    // across the request. Where it bites, the delegate's cursor issues the continuation point, which 6.4.3
    // permits even when the client asked for everything.
    rawItem.maxValuesPerNode = history_read_validation::effective_max_values_per_node(
      flow.rawDetails->num_values_per_node(), flow.maxReturnDataValues);
    rawItem.returnBounds = flow.rawDetails->return_bounds();
    rawItem.isReadModified = flow.rawDetails->is_read_modified();
    rawItem.cursor = std::move(item.cursor);
    rawItems.push_back(std::move(rawItem));
  }

  NamespaceHistoryDelegate::ReadContext context;
  context.timestampsToReturn = mRequest.timestamps_to_return();
  context.sessionLocales = mSessionLocales;
  context.cancelled = call_flag_for(namespaceIndex);
  context.deadline = mPartialResultDeadline;

  auto batch =
    co_await await_step<BatchResult<NamespaceHistoryDelegate::ReadRawItemResult>>([&](auto completion)
      { delegateToUse->read_raw_async(context, std::move(rawItems), std::move(completion)); });

  if (!mFlow)
  {
    co_return;
  }
  on_namespace_read_complete(namespaceIndex, std::move(batch));
}

void HistoryReadService::on_namespace_read_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch)
{
  if (!mFlow)
    return;
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "HistoryReadService: delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = batchStatus;
      if (batchDetail)
      {
        stage_history_detail(item.originalIndex, batchDetail);
      }
    }
  }
  else
  {
    auto& results = batch.items;
    // Best-effort: if the delegate returned fewer items than requested, write what we got and
    // leave the rest at default. Best-effort skip for per-batch contracts.
    const size_t mappable = std::min(results.size(), items.size());
    for (size_t ri = 0; ri < mappable; ++ri)
    {
      auto& itemResult = results[ri];
      auto& sourceItem = items[ri];
      const size_t responseIndex = sourceItem.originalIndex;
      auto& responseResult = history_result(responseIndex);

      // The store's code, a Good subcode or an Uncertain code included, with the data it holds.
      responseResult.status_code() = itemResult.status_code();

      if (!itemResult.has_value())
      {
        if (itemResult.error_detail())
        {
          stage_history_detail(sourceItem.originalIndex, itemResult.shared_detail());
        }
        continue;
      }

      auto& success = itemResult.value();

      const auto timestampsToReturn = mRequest.timestamps_to_return();
      const bool missingRequestedTimestamp = std::ranges::any_of(success.values,
        [timestampsToReturn](const DataValue& value)
        {
          const bool needsSource = timestampsToReturn == TimestampsToReturn::Source ||
                                   timestampsToReturn == TimestampsToReturn::Both;
          const bool needsServer = timestampsToReturn == TimestampsToReturn::Server ||
                                   timestampsToReturn == TimestampsToReturn::Both;
          return (needsSource && !value.source_timestamp().has_value()) ||
                 (needsServer && !value.server_timestamp().has_value());
        });
      if (missingRequestedTimestamp)
      {
        responseResult.status_code() = Status::BadTimestampNotSupported;
        stage_history_detail(sourceItem.originalIndex,
          ErrorDetail::build("HistoryTimestampNotSupported",
            "The historical node cannot supply every requested timestamp",
            "HistoryReadService")
            .context(ua::ContextKeys::nodeId, ua::to_string(sourceItem.nodeId)));
        continue;
      }
      apply_timestamps_to_return(success.values, mRequest.timestamps_to_return());

      // Part 11 6.5.3.2: an empty raw interval with no bounding values requested yields Good_NoData.
      // (When bounds are requested the delegate returns the bound entries - possibly Bad_BoundNotFound
      // placeholders - and the operation status stays Good.) Only over the store's plain Good: a code of
      // its own stands.
      if (success.values.empty() && !success.cursor.has_value() && !flow.rawDetails->return_bounds())
      {
        answer_no_data(responseResult.status_code(), mLogger, sourceItem.nodeId, "6.5.3.2");
      }

      if (flow.rawDetails->is_read_modified() && !success.modificationInfos.empty())
      {
        auto histModData = std::make_unique<HistoryModifiedData>();
        histModData->data_values().payload() = std::move(success.values);
        histModData->modification_infos().payload() = std::move(success.modificationInfos);
        responseResult.history_data() = std::move(histModData);
      }
      else
      {
        auto histData = std::make_unique<HistoryData>();
        histData->data_values().payload() = std::move(success.values);
        responseResult.history_data() = std::move(histData);
      }

      if (success.cursor.has_value())
      {
        // Resolve the delegate to register the CP under: the per-bucket delegateToUse logic.
        auto delegateToUse = sourceItem.delegate;
        if (!delegateToUse)
        {
          auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
          if (ns)
          {
            delegateToUse = ns->history_delegate();
          }
        }
        HistoryContinuationPoint cp{namespaceIndex,
          std::move(*success.cursor),
          delegateToUse,
          mRequest.timestamps_to_return(),
          flow.rawDetails->is_read_modified() ? NamespaceHistoryDelegate::DetailKind::Modified
                                              : NamespaceHistoryDelegate::DetailKind::Raw};

        auto bytes = cp.identifier().as_ua_binary();
        responseResult.continuation_point() = ByteString{span<const byte>{bytes}};
        stage_history_continuation_point(responseIndex, std::move(cp));
      }
    }
  }
}

ua::async::Task<> HistoryReadService::read_namespace_processed(uint16_t namespaceIndex)
{
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  const shared_ptr<NamespaceHistoryDelegate> namespaceDelegate = ns ? ns->history_delegate() : nullptr;

  if (!namespaceDelegate && !items.front().delegate)
  {
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = Status::BadHistoryOperationUnsupported;
    }
    co_return;
  }

  auto delegateToUse = items.front().delegate ? items.front().delegate : namespaceDelegate;

  NamespaceHistoryDelegate::ReadContext context;
  context.timestampsToReturn = mRequest.timestamps_to_return();
  context.sessionLocales = mSessionLocales;
  context.cancelled = call_flag_for(namespaceIndex);
  context.deadline = mPartialResultDeadline;

  if (delegateToUse->capabilities().readProcessed)
  {
    // Native: the delegate computes the aggregates itself.
    std::vector<NamespaceHistoryDelegate::ReadProcessedItem> procItems;
    procItems.reserve(items.size());
    for (auto& item : items)
    {
      NamespaceHistoryDelegate::ReadProcessedItem procItem;
      procItem.index = item.originalIndex;
      procItem.nodeId = item.nodeId;
      procItem.indexRange = item.indexRange;
      procItem.startTime = flow.processedDetails->start_time();
      procItem.endTime = flow.processedDetails->end_time();
      procItem.processingInterval = flow.processedDetails->processing_interval();
      procItem.aggregateType = item.aggregateType;
      procItem.aggregateConfiguration = flow.processedDetails->aggregate_configuration();
      procItem.cursor = std::move(item.cursor);
      procItems.push_back(std::move(procItem));
    }

    auto batch =
      co_await await_step<BatchResult<NamespaceHistoryDelegate::ReadProcessedItemResult>>([&](auto completion)
        { delegateToUse->read_processed_async(context, std::move(procItems), std::move(completion)); });

    if (!mFlow)
    {
      co_return;
    }
    on_namespace_processed_complete(namespaceIndex, std::move(batch));
    co_return;
  }

  // Turnkey: read raw over the window (with bounds, so the calculator sees the
  // predecessor/successor it needs), then run the built-in Part-13 calculator.
  std::vector<NamespaceHistoryDelegate::ReadRawItem> rawItems;
  rawItems.reserve(items.size());
  for (auto& item : items)
  {
    NamespaceHistoryDelegate::ReadRawItem rawItem;
    rawItem.index = item.originalIndex;
    rawItem.nodeId = item.nodeId;
    rawItem.indexRange = item.indexRange;
    rawItem.startTime = flow.processedDetails->start_time();
    rawItem.endTime = flow.processedDetails->end_time();
    rawItem.maxValuesPerNode = 0;  // all values within the window
    rawItem.returnBounds = true;
    rawItem.isReadModified = false;
    rawItem.cursor = std::move(item.cursor);
    rawItems.push_back(std::move(rawItem));
  }

  auto turnkeyBatch =
    co_await await_step<BatchResult<NamespaceHistoryDelegate::ReadRawItemResult>>([&](auto completion)
      { delegateToUse->read_raw_async(context, std::move(rawItems), std::move(completion)); });

  if (!mFlow)
  {
    co_return;
  }
  on_namespace_turnkey_complete(namespaceIndex, std::move(turnkeyBatch));
}

void HistoryReadService::on_namespace_processed_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadProcessedItemResult> batch)
{
  if (!mFlow)
    return;
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "HistoryReadService: processed delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = batchStatus;
      if (batchDetail)
      {
        stage_history_detail(item.originalIndex, batchDetail);
      }
    }
  }
  else
  {
    auto& results = batch.items;
    const size_t mappable = std::min(results.size(), items.size());
    for (size_t ri = 0; ri < mappable; ++ri)
    {
      auto& itemResult = results[ri];
      auto& responseResult = history_result(items[ri].originalIndex);
      responseResult.status_code() = itemResult.status_code();
      if (!itemResult.has_value())
      {
        if (itemResult.error_detail())
        {
          stage_history_detail(items[ri].originalIndex, itemResult.shared_detail());
        }
        continue;
      }
      auto& success = itemResult.value();
      auto histData = std::make_unique<HistoryData>();
      histData->data_values().payload() = std::move(success.values);
      responseResult.history_data() = std::move(histData);
    }
  }
}

void HistoryReadService::on_namespace_turnkey_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch)
{
  if (!mFlow)
    return;
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "HistoryReadService: turnkey raw read batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = batchStatus;
      if (batchDetail)
      {
        stage_history_detail(item.originalIndex, batchDetail);
      }
    }
  }
  else
  {
    const aggregates::CalcConfig cfg = make_calc_config(flow.processedDetails->aggregate_configuration());
    auto& results = batch.items;
    const size_t mappable = std::min(results.size(), items.size());
    for (size_t ri = 0; ri < mappable; ++ri)
    {
      auto& itemResult = results[ri];
      auto& sourceItem = items[ri];
      const size_t responseIndex = sourceItem.originalIndex;
      auto& responseResult = history_result(responseIndex);

      if (!itemResult.has_value())
      {
        responseResult.status_code() = itemResult.status_code();
        if (itemResult.error_detail())
        {
          stage_history_detail(sourceItem.originalIndex, itemResult.shared_detail());
        }
        continue;
      }

      const aggregates::Aggregator* aggregator =
        aggregates::AggregatorRegistry::instance().find(sourceItem.aggregateType);
      if (!aggregator)
      {
        responseResult.status_code() = Status::BadAggregateNotSupported;
        continue;
      }

      auto& success = itemResult.value();
      const std::vector<aggregates::Sample> samples = aggregates::samples_from_data_values(success.values);
      // One value per interval. The cap is an allocation guard on a peer-driven count, not a paging
      // size: a node whose request would exceed it is refused rather than materialised. Paging
      // processed results under MaxReturnDataValues through continuation points is a queued
      // feature (D14), so the raw-read page size is deliberately NOT applied here. The cap is what is
      // left of the request's budget, so a Node past it is refused before its intervals are generated.
      const size_t intervalCap = std::min(aggregates::defaultMaxIntervals, flow.processedValuesRemaining);
      const aggregates::IntervalSet intervals =
        aggregates::generate_intervals(flow.processedDetails->start_time(),
          flow.processedDetails->end_time(),
          flow.processedDetails->processing_interval(),
          intervalCap);
      if (intervals.invalid)
      {
        responseResult.status_code() = Status::BadAggregateInvalidInputs;
        continue;
      }
      if (intervals.tooMany && intervalCap == aggregates::defaultMaxIntervals)
      {
        responseResult.status_code() = Status::BadTooManyOperations;
        continue;
      }
      // A single-interval request is generated without consulting the cap, so the size is checked too.
      if (intervals.tooMany || intervals.intervals.size() > flow.processedValuesRemaining)
      {
        responseResult.status_code() = StatusCode{Status::BadTooManyOperations,
          ErrorDetail::build("ProcessedValueBudgetExhausted",
            "The request's earlier nodes used the aggregate values one request may compute",
            "HistoryReadService")
            .context(ContextKeys::sizeMax, std::to_string(flow.processedValuesRemaining))};
        continue;
      }
      flow.processedValuesRemaining -= intervals.intervals.size();

      aggregates::AggregateContext ctx;
      ctx.cfg = cfg;
      ctx.sourceTemplate = aggregates::source_template(samples);
      std::vector<DataValue> aggregated = aggregates::run_aggregator(*aggregator, samples, intervals, ctx);

      auto histData = std::make_unique<HistoryData>();
      histData->data_values().payload() = std::move(aggregated);
      responseResult.history_data() = std::move(histData);
      // The SDK computed the values from the store's raw read, so the operation answers that read's code:
      // plain Good, a Good subcode or an Uncertain code.
      responseResult.status_code() = itemResult.status_code();
    }
  }
}

ua::async::Task<> HistoryReadService::read_namespace_annotations(uint16_t namespaceIndex)
{
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  const shared_ptr<NamespaceHistoryDelegate> namespaceDelegate = ns ? ns->history_delegate() : nullptr;

  if (!namespaceDelegate && !items.front().delegate)
  {
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = Status::BadHistoryOperationUnsupported;
    }
    co_return;
  }

  auto delegateToUse = items.front().delegate ? items.front().delegate : namespaceDelegate;

  // Annotations come only from the delegate (no built-in path). A delegate that does not support
  // annotations returns Bad_HistoryOperationUnsupported per item (the default), satisfying
  // SVR-HIST-ANN-004.
  std::vector<NamespaceHistoryDelegate::ReadAnnotationItem> annotationItems;
  annotationItems.reserve(items.size());
  for (auto& item : items)
  {
    NamespaceHistoryDelegate::ReadAnnotationItem annotationItem;
    annotationItem.index = item.originalIndex;
    annotationItem.nodeId = item.nodeId;
    annotationItem.reqTimes.reserve(flow.annotationDetails->req_times().size());
    for (const auto& reqTime : flow.annotationDetails->req_times())
    {
      annotationItem.reqTimes.push_back(reqTime);
    }
    annotationItem.cursor = std::move(item.cursor);
    annotationItems.push_back(std::move(annotationItem));
  }

  NamespaceHistoryDelegate::ReadContext context;
  context.timestampsToReturn = mRequest.timestamps_to_return();
  context.sessionLocales = mSessionLocales;
  context.cancelled = call_flag_for(namespaceIndex);
  context.deadline = mPartialResultDeadline;

  auto batch =
    co_await await_step<BatchResult<NamespaceHistoryDelegate::ReadAnnotationItemResult>>([&](auto completion)
      { delegateToUse->read_annotations_async(context, std::move(annotationItems), std::move(completion)); });

  if (!mFlow)
  {
    co_return;
  }
  on_namespace_annotations_complete(namespaceIndex, std::move(batch));
}

void HistoryReadService::on_namespace_annotations_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadAnnotationItemResult> batch)
{
  if (!mFlow)
    return;
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "HistoryReadService: annotation delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = batchStatus;
      if (batchDetail)
      {
        stage_history_detail(item.originalIndex, batchDetail);
      }
    }
  }
  else
  {
    auto& results = batch.items;
    const size_t mappable = std::min(results.size(), items.size());
    for (size_t ri = 0; ri < mappable; ++ri)
    {
      auto& itemResult = results[ri];
      auto& responseResult = history_result(items[ri].originalIndex);
      responseResult.status_code() = itemResult.status_code();
      if (!itemResult.has_value())
      {
        if (itemResult.error_detail())
        {
          stage_history_detail(items[ri].originalIndex, itemResult.shared_detail());
        }
        continue;
      }
      // The delegate returns the Annotation values in req_times order (SVR-HIST-ANN-003).
      auto& success = itemResult.value();
      auto histData = std::make_unique<HistoryData>();
      histData->data_values().payload() = std::move(success.values);
      responseResult.history_data() = std::move(histData);
    }
  }
}

ua::async::Task<> HistoryReadService::read_namespace_at_time(uint16_t namespaceIndex)
{
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  const shared_ptr<NamespaceHistoryDelegate> namespaceDelegate = ns ? ns->history_delegate() : nullptr;

  if (!namespaceDelegate && !items.front().delegate)
  {
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = Status::BadHistoryOperationUnsupported;
    }
    co_return;
  }

  auto delegateToUse = items.front().delegate ? items.front().delegate : namespaceDelegate;

  std::vector<NamespaceHistoryDelegate::ReadAtTimeItem> atTimeItems;
  atTimeItems.reserve(items.size());
  for (auto& item : items)
  {
    NamespaceHistoryDelegate::ReadAtTimeItem atTimeItem;
    atTimeItem.index = item.originalIndex;
    atTimeItem.nodeId = item.nodeId;
    atTimeItem.indexRange = item.indexRange;
    atTimeItem.timestamps.reserve(flow.atTimeDetails->req_times().size());
    for (const auto& reqTime : flow.atTimeDetails->req_times())
      atTimeItem.timestamps.push_back(reqTime);
    atTimeItem.useSimpleBounds = flow.atTimeDetails->use_simple_bounds();
    atTimeItem.cursor = std::move(item.cursor);
    atTimeItems.push_back(std::move(atTimeItem));
  }

  NamespaceHistoryDelegate::ReadContext context;
  context.timestampsToReturn = mRequest.timestamps_to_return();
  context.sessionLocales = mSessionLocales;
  context.cancelled = call_flag_for(namespaceIndex);
  context.deadline = mPartialResultDeadline;

  auto batch =
    co_await await_step<BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult>>([&](auto completion)
      { delegateToUse->read_at_time_async(context, std::move(atTimeItems), std::move(completion)); });

  if (!mFlow)
  {
    co_return;
  }
  on_namespace_at_time_complete(namespaceIndex, std::move(batch));
}

void HistoryReadService::on_namespace_at_time_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult> batch)
{
  if (!mFlow)
    return;
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "HistoryReadService: at-time delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = batchStatus;
      if (batchDetail)
      {
        stage_history_detail(item.originalIndex, batchDetail);
      }
    }
  }
  else
  {
    auto& results = batch.items;
    const size_t mappable = std::min(results.size(), items.size());
    for (size_t ri = 0; ri < mappable; ++ri)
    {
      auto& itemResult = results[ri];
      auto& sourceItem = items[ri];
      const size_t responseIndex = sourceItem.originalIndex;
      auto& responseResult = history_result(responseIndex);
      responseResult.status_code() = itemResult.status_code();
      if (!itemResult.has_value())
      {
        if (itemResult.error_detail())
        {
          stage_history_detail(sourceItem.originalIndex, itemResult.shared_detail());
        }
        continue;
      }
      auto& success = itemResult.value();
      apply_timestamps_to_return(success.values, mRequest.timestamps_to_return());
      auto histData = std::make_unique<HistoryData>();
      histData->data_values().payload() = std::move(success.values);
      responseResult.history_data() = std::move(histData);

      if (success.cursor.has_value())
      {
        auto delegateToUse = sourceItem.delegate;
        if (!delegateToUse)
        {
          auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
          if (ns)
            delegateToUse = ns->history_delegate();
        }
        HistoryContinuationPoint cp{namespaceIndex,
          std::move(*success.cursor),
          delegateToUse,
          mRequest.timestamps_to_return(),
          NamespaceHistoryDelegate::DetailKind::AtTime};
        auto bytes = cp.identifier().as_ua_binary();
        responseResult.continuation_point() = ByteString{span<const byte>{bytes}};
        stage_history_continuation_point(responseIndex, std::move(cp));
      }
    }
  }
}

ua::async::Task<> HistoryReadService::read_namespace_events(uint16_t namespaceIndex)
{
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
  const shared_ptr<NamespaceHistoryDelegate> namespaceDelegate = ns ? ns->history_delegate() : nullptr;

  if (!namespaceDelegate && !items.front().delegate)
  {
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = Status::BadHistoryOperationUnsupported;
    }
    co_return;
  }

  auto delegateToUse = items.front().delegate ? items.front().delegate : namespaceDelegate;

  std::vector<NamespaceHistoryDelegate::ReadEventsItem> eventItems;
  eventItems.reserve(items.size());
  for (auto& item : items)
  {
    NamespaceHistoryDelegate::ReadEventsItem eventItem;
    eventItem.index = item.originalIndex;
    eventItem.nodeId = item.nodeId;
    eventItem.startTime = flow.eventDetails->start_time();
    eventItem.endTime = flow.eventDetails->end_time();
    // Same per-node bound as the raw path, against the events capability (MaxReturnEventValues).
    eventItem.maxValuesPerNode = history_read_validation::effective_max_values_per_node(
      flow.eventDetails->num_values_per_node(), flow.maxReturnEventValues);
    eventItem.filter = flow.eventDetails->filter();
    eventItem.selectClauseModelStatuses = flow.eventSelectClauseModelStatuses;
    eventItem.cursor = std::move(item.cursor);
    eventItems.push_back(std::move(eventItem));
  }

  NamespaceHistoryDelegate::ReadContext context;
  context.timestampsToReturn = mRequest.timestamps_to_return();
  context.sessionLocales = mSessionLocales;
  context.cancelled = call_flag_for(namespaceIndex);
  context.deadline = mPartialResultDeadline;

  auto batch =
    co_await await_step<BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult>>([&](auto completion)
      { delegateToUse->read_events_async(context, std::move(eventItems), std::move(completion)); });

  if (!mFlow)
  {
    co_return;
  }
  co_await filter_events_by_receive_events(batch);
  if (!mFlow)
  {
    co_return;
  }
  withhold_unreadable_event_fields(batch);
  on_namespace_events_complete(namespaceIndex, std::move(batch));
}

ua::async::Task<> HistoryReadService::filter_events_by_receive_events(
  BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult>& batch)
{
  using EventOrigin = NamespaceHistoryDelegate::HistoryReadEventsSuccess::EventOrigin;
  if (batch.batchStatus.is_bad())
    co_return;

  // The distinct origin nodes of every returned event: one resolution and one authorization for all
  // of them, however many events share a source or a type.
  std::vector<NodeId> subjects;
  std::unordered_map<NodeId, size_t> subjectIndex;
  const auto note = [&](const NodeId& id)
  {
    if (id.is_null())
      return;
    if (subjectIndex.emplace(id, subjects.size()).second)
      subjects.push_back(id);
  };
  for (const auto& result : batch.items)
  {
    if (!result.has_value())
      continue;
    for (const auto& origin : result.value().origins)
    {
      note(origin.sourceNode);
      note(origin.eventType);
    }
  }
  if (subjects.empty())
    co_return;

  // Fail closed: an origin that cannot be resolved or authorized is not permitted.
  std::vector<bool> permitted(subjects.size(), false);
  if (mFlow->accessControl)
  {
    auto resolved = co_await await_step<BatchResult<NodeAccessorResult>>([this, &subjects](auto completion)
      { mFlow->addressSpace.find_nodes_async(subjects, std::move(completion)); });
    if (!mFlow)
      co_return;
    std::vector<AccessControl::Item> items;
    std::vector<size_t> itemSubject;
    if (resolved.batchStatus.is_good())
    {
      for (size_t i = 0; i < resolved.items.size() && i < subjects.size(); ++i)
      {
        if (!resolved.items[i].is_good())
          continue;
        items.push_back(AccessControl::Item{
          .node = resolved.items[i].value(), .operation = AccessOperation::ReceiveEvents});
        itemSubject.push_back(i);
      }
    }
    if (!items.empty())
    {
      // The events checked here may arrive after the partial-results deadline, for a continuation point that
      // outlives the client's wait, so the check carries the server's own RequestInfo, not the request's
      // deadlines and cancellation.
      auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this, &items](auto completion)
        { mFlow->accessControl->authorize_async(RequestInfo{}, items, std::move(completion)); });
      if (!mFlow)
        co_return;
      for (size_t i = 0; i < verdicts.size() && i < itemSubject.size(); ++i)
        permitted[itemSubject[i]] = verdicts[i].permitted;
    }
  }

  const auto allowed = [&](const NodeId& id)
  {
    if (id.is_null())
      return true;  // not recorded by the archive: nothing to decide on
    const auto found = subjectIndex.find(id);
    return found != subjectIndex.end() && permitted[found->second];
  };
  for (auto& result : batch.items)
  {
    if (!result.has_value())
      continue;
    auto& success = result.value();
    if (success.origins.empty())
      continue;
    std::vector<HistoryEventFieldList> kept;
    std::vector<EventOrigin> keptOrigins;
    kept.reserve(success.events.size());
    for (size_t i = 0; i < success.events.size(); ++i)
    {
      const bool known = i < success.origins.size();
      if (known && !(allowed(success.origins[i].sourceNode) && allowed(success.origins[i].eventType)))
        continue;
      kept.push_back(std::move(success.events[i]));
      if (known)
        keptOrigins.push_back(success.origins[i]);
    }
    success.events = std::move(kept);
    success.origins = std::move(keptOrigins);
  }
}

void HistoryReadService::withhold_unreadable_event_fields(
  BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult>& batch) const
{
  using Rule = HistoryReadState::EventFieldRule;
  if (batch.batchStatus.is_bad())
    return;
  const auto& rules = mFlow->eventFieldRules;
  const Rule beyondClauses{};  // a field the delegate returned beyond the select clauses is withheld
  for (auto& result : batch.items)
  {
    if (!result.has_value())
      continue;
    for (auto& event : result.value().events)
    {
      auto& fields = event.event_fields().payload();
      for (size_t i = 0; i < fields.size(); ++i)
      {
        const Rule& rule = i < rules.size() ? rules[i] : beyondClauses;
        if (rule.kind == Rule::Kind::Keep || (rule.kind == Rule::Kind::DenyIfValue && fields[i].empty()))
          continue;
        fields[i] = Variant{rule.denial};
      }
    }
  }
}

void HistoryReadService::on_namespace_events_complete(
  uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch)
{
  if (!mFlow)
    return;
  auto& flow = *mFlow;
  auto& items = flow.itemsByNamespace.at(namespaceIndex);

  if (batch.batchStatus.is_bad())
  {
    if (auto sessionInfo = mSessionInfo.lock())
    {
      log_batch_failure(sessionInfo->logger().with_category("service"),
        "HistoryReadService: events delegate batch failure",
        batch.batchStatus);
    }
    auto batchStatus = batch.batchStatus.status_code();
    auto batchDetail = batch.batchStatus.shared_detail();
    for (const auto& item : items)
    {
      history_result(item.originalIndex).status_code() = batchStatus;
      if (batchDetail)
      {
        stage_history_detail(item.originalIndex, batchDetail);
      }
    }
  }
  else
  {
    auto& results = batch.items;
    const size_t mappable = std::min(results.size(), items.size());
    for (size_t ri = 0; ri < mappable; ++ri)
    {
      auto& itemResult = results[ri];
      auto& sourceItem = items[ri];
      const size_t responseIndex = sourceItem.originalIndex;
      auto& responseResult = history_result(responseIndex);
      responseResult.status_code() = itemResult.status_code();
      if (!itemResult.has_value())
      {
        if (itemResult.error_detail())
        {
          stage_history_detail(sourceItem.originalIndex, itemResult.shared_detail());
        }
        continue;
      }
      auto& success = itemResult.value();
      // Part 11 6.5.2.2: a successful event-history read whose range contains no Events reports
      // Good_NoData at the operation level. A continuation cursor means more rows remain and is
      // therefore not the empty-range outcome. Only over the store's plain Good: a code of its own stands.
      if (success.events.empty() && !success.cursor.has_value())
      {
        answer_no_data(responseResult.status_code(), mLogger, sourceItem.nodeId, "6.5.2.2");
      }
      auto histEvent = std::make_unique<HistoryEvent>();
      histEvent->events().payload() = std::move(success.events);
      responseResult.history_data() = std::move(histEvent);

      if (success.cursor.has_value())
      {
        auto delegateToUse = sourceItem.delegate;
        if (!delegateToUse)
        {
          auto ns = flow.addressSpace.namespace_array().get_namespace(namespaceIndex);
          if (ns)
            delegateToUse = ns->history_delegate();
        }
        HistoryContinuationPoint cp{namespaceIndex,
          std::move(*success.cursor),
          delegateToUse,
          mRequest.timestamps_to_return(),
          NamespaceHistoryDelegate::DetailKind::Events};
        auto bytes = cp.identifier().as_ua_binary();
        responseResult.continuation_point() = ByteString{span<const byte>{bytes}};
        stage_history_continuation_point(responseIndex, std::move(cp));
      }
    }
  }
}

// =============================================================================================
// Items, and the partial-result deadline (item 10)
// =============================================================================================

HistoryReadResult& HistoryReadService::history_result(size_t index)
{
  return mStaged.at(index).result;
}

void HistoryReadService::stage_history_detail(size_t index, shared_ptr<const ErrorDetail> detail)
{
  if (detail && index < mStaged.size())
  {
    mStaged[index].details.push_back(std::move(detail));
  }
}

void HistoryReadService::stage_history_continuation_point(
  size_t index, HistoryContinuationPoint continuationPoint)
{
  if (index < mStaged.size())
  {
    mStaged[index].continuationPoint.emplace(std::move(continuationPoint));
  }
}

void HistoryReadService::finish_history_item(size_t index)
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
    // Running and already answered happens only when the request failed or was cancelled as a whole.
    if (mFinished || !mFlow)
    {
      return;
    }
    mFlow->response->results()[index] = std::move(item.result);
    for (auto& detail : item.details)
    {
      mFlow->collector.add_item_detail(index, std::move(detail));
    }
    item.details.clear();
    if (item.continuationPoint)
    {
      mFlow->serviceResponse.continuationPoints.emplace_back(std::move(*item.continuationPoint));
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
        HistoryOutcome{std::move(item.result), std::move(item.continuationPoint), std::move(item.details)});
      // The owner is this service: dropped by a handler that runs after this one, never here.
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

ua::async::Task<> HistoryReadService::run_history_wait(size_t index)
{
  const auto paused = mStaged[index].waitingOn;
  if (!paused)
  {
    history_result(index).status_code() = StatusCode{Status::BadContinuationPointInvalid};
    finish_history_item(index);
    co_return;
  }

  co_await await_step<bool>(
    [paused](auto completion)
    {
      auto shared = std::make_shared<decltype(completion)>(std::move(completion));
      paused->when_done([shared] { (*shared)(true); });
    });

  auto& item = mStaged[index];
  if (item.state != StagedItem::State::Running)
  {
    // This request reached its own partial-result deadline first and handed the read to a new point.
    co_return;
  }
  if (auto outcome = paused->take())
  {
    item.result = std::move(outcome->result);
    item.continuationPoint = std::move(outcome->continuationPoint);
    item.details = std::move(outcome->details);
  }
  else
  {
    item.result.status_code() = StatusCode{Status::BadContinuationPointInvalid};
  }
  item.waitingOn.reset();
  finish_history_item(index);
}

shared_ptr<std::atomic_bool> HistoryReadService::call_flag_for(uint16_t namespaceIndex)
{
  auto found = mCalls.find(namespaceIndex);
  if (found == mCalls.end())
  {
    auto flag = std::make_shared<std::atomic_bool>(false);
    auto call = std::make_shared<SharedCallCancellation>(flag);
    found = mCalls.emplace(namespaceIndex, std::make_pair(std::move(flag), std::move(call))).first;
  }
  return found->second.first;
}

void HistoryReadService::arm_partial_result_deadline(uint32_t timeoutHint)
{
  double fraction = 0.8;
  if (auto sessionInfo = mSessionInfo.lock())
  {
    fraction = sessionInfo->server_configuration().partialResultDeadlineFraction;
  }
  const auto delay = partial_result_delay(timeoutHint, fraction);
  if (!delay)
  {
    return;
  }
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

void HistoryReadService::answer_at_partial_result_deadline()
{
  if (mFinished || !mFlow)
  {
    return;
  }

  // New reads get continuation points within the Session's maximum (0: no maximum); reads continuing a
  // point never count against it (OPC 10000-4 section 7.9).
  size_t allowance = std::numeric_limits<size_t>::max();
  if (auto sessionInfo = mSessionInfo.lock())
  {
    const size_t maxContinuationPoints =
      sessionInfo->server_configuration().server_capabilities().maxHistoryContinuationPoints;
    if (maxContinuationPoints > 0)
    {
      const size_t held = mFlow->serviceResponse.continuationPoints.size();
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
    if (!item.continuing)
    {
      if (allowance == 0)
      {
        item.awaitingContinuationPoint = true;
        waitingForContinuationPoint = true;
        continue;
      }
      --allowance;
    }
    pause_history_item(index);
  }

  if (!waitingForContinuationPoint)
  {
    send_partial_response();
  }
}

void HistoryReadService::pause_history_item(size_t index)
{
  auto& item = mStaged[index];
  shared_ptr<PausedHistory> paused;
  if (item.waitingOn)
  {
    paused = item.waitingOn;
    item.ownsPaused = false;
  }
  else
  {
    call_flag_for(item.namespaceIndex);
    auto call = mCalls.at(item.namespaceIndex).second;
    call->add_paused_item();
    paused = std::make_shared<PausedHistory>(shared_from_this(), [call] { call->release_paused_item(); });
    item.ownsPaused = true;
  }

  NamespaceHistoryDelegate::DetailKind detailKind = NamespaceHistoryDelegate::DetailKind::Raw;
  if (mFlow->is_events())
    detailKind = NamespaceHistoryDelegate::DetailKind::Events;
  else if (mFlow->is_processed())
    detailKind = NamespaceHistoryDelegate::DetailKind::Processed;
  else if (mFlow->is_annotation())
    detailKind = NamespaceHistoryDelegate::DetailKind::Annotation;
  else if (mFlow->is_at_time())
    detailKind = NamespaceHistoryDelegate::DetailKind::AtTime;
  else if (mFlow->rawDetails && mFlow->rawDetails->is_read_modified())
    detailKind = NamespaceHistoryDelegate::DetailKind::Modified;

  HistoryContinuationPoint continuationPoint{
    item.namespaceIndex, mRequest.timestamps_to_return(), detailKind, paused};
  auto bytes = continuationPoint.identifier().as_ua_binary();
  auto& slot = mFlow->response->results()[index];
  slot = HistoryReadResult{};
  slot.status_code() = StatusCode{Status::Good};
  slot.continuation_point() = ByteString{span<const byte>{bytes}};
  // Zero results, in the structure the request's details call for (OPC 10000-11 section 6.3).
  if (mFlow->is_events())
  {
    slot.history_data() = std::make_unique<HistoryEvent>();
  }
  else
  {
    slot.history_data() = std::make_unique<HistoryData>();
  }
  mFlow->serviceResponse.continuationPoints.emplace_back(std::move(continuationPoint));

  item.state = StagedItem::State::Paused;
  item.paused = std::move(paused);
}

void HistoryReadService::send_partial_response()
{
  if (!mFlow || !try_finish())
  {
    return;
  }
  mAnswered.store(true);
  auto& flow = *mFlow;
  const size_t noOfOperations = mRequest.nodes_to_read().size();
  flow.collector.apply_to(
    flow.response->response_header(), flow.response->diagnostic_infos(), noOfOperations);
  prepare_response_header(flow.response->response_header());
  // The flow stays: the reads the continuation points own go on and finish into those points.
  HistoryReadServiceResponse serviceResponse;
  serviceResponse.response = flow.serviceResponse.response;
  serviceResponse.continuationPoints = std::move(flow.serviceResponse.continuationPoints);
  flow.serviceResponse.continuationPoints.clear();
  mCallback(std::move(serviceResponse));
}

void HistoryReadService::cancel_all_calls()
{
  mCancelled->store(true, std::memory_order_relaxed);
  for (auto& [namespaceIndex, call] : mCalls)
  {
    (void)namespaceIndex;
    if (call.first)
    {
      call.first->store(true);
    }
  }
}

void HistoryReadService::release_unfinished_waits()
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

void HistoryReadService::complete_history_read()
{
  if (!try_finish())
  {
    mFlow.reset();
    return;
  }
  mAnswered.store(true);
  auto& flow = *mFlow;
  const size_t noOfOperations = mRequest.nodes_to_read().size();
  flow.collector.apply_to(
    flow.response->response_header(), flow.response->diagnostic_infos(), noOfOperations);
  prepare_response_header(flow.response->response_header());
  auto serviceResponse = std::move(flow.serviceResponse);
  mFlow.reset();
  mCallback(std::move(serviceResponse));
}

void HistoryReadService::fail_history_read(VoidResult error)
{
  if (mFinished)
  {
    // Answered at the partial-result deadline: the request's reads have failed, so each paused one
    // delivers the failure to its continuation point instead of leaving the point waiting.
    for (size_t index = 0; index < mStaged.size(); ++index)
    {
      auto& item = mStaged[index];
      if (item.state == StagedItem::State::Paused)
      {
        item.result = HistoryReadResult{};
        item.result.status_code() = error.status_code();
        item.continuationPoint.reset();
        finish_history_item(index);
      }
    }
    mFlow.reset();
    return;
  }
  cancel_all_calls();
  release_unfinished_waits();
  if (!try_finish())
  {
    mFlow.reset();
    return;
  }
  mAnswered.store(true);
  auto& flow = *mFlow;
  flow.collector.set_service_detail(error.status_code());
  auto serviceFault = stack_utils::create_service_fault(&mRequest.request_header(), error.status_code());
  Array<DiagnosticInfo> unused;
  flow.collector.apply_to(serviceFault->response_header(), unused, 0);
  HistoryReadServiceResponse serviceResponse;
  serviceResponse.response = std::pair(mRequestId, serviceFault);
  mFlow.reset();
  mCallback(std::move(serviceResponse));
}

void HistoryReadService::abort(StatusCode reason)
{
  // Answered at the partial-result deadline: the continuation points own the reads still running.
  if (mAnswered.load())
  {
    return;
  }
  mCancelled->store(true, std::memory_order_relaxed);

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](HistoryReadService& self)
    {
      if (self.mFinished)
      {
        return;
      }
      self.cancel_all_calls();
      self.release_unfinished_waits();
      self.mAnswered.store(true);
      self.mFlow.reset();
      // Destroying the request's body destroys every item body with it, in order, because they are
      // its frame's own locals. Released HERE rather than left to the destructor: a withdrawn
      // request has already answered its client, and a suspended body that outlives that answer is
      // a frame held for no reason - and one whose next resume would have to be told to stop.
      self.mRequestTask = {};
      DiagnosticCollector collector{0};
      self.send_service_fault(self.mRequest.request_header(), reason, collector);
    })();
}

void HistoryReadService::timeout()
{
  // The timeoutHint. Normally the partial-result deadline has answered already. What can still be
  // running is a new read that found no continuation point left (OPC 10000-4 section 7.9:
  // Bad_NoContinuationPoints for the remaining operations) or a read of a request with no
  // partial-result deadline; each is answered on its own, and the request is not failed as a whole.
  if (mFinished)
  {
    return;
  }
  if (!mFlow)
  {
    cancel_all_calls();
    mRequestTask = {};
    DiagnosticCollector collector{0};
    send_service_fault(mRequest.request_header(), Status::BadTimeout, collector);
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
    auto& slot = mFlow->response->results()[index];
    slot = HistoryReadResult{};
    slot.status_code() = item.awaitingContinuationPoint ? StatusCode{Status::BadNoContinuationPoints}
                                                        : StatusCode{Status::BadTimeout};
    item.state = StagedItem::State::Abandoned;
  }
  release_unfinished_waits();
  if (anyPaused)
  {
    // Paused reads share this request's token, so it stays clear; the abandoned ones simply run out.
    send_partial_response();
    return;
  }
  cancel_all_calls();
  send_partial_response();
  mFlow.reset();
  mRequestTask = {};
}

void HistoryReadService::retrieve_continuation_points(HistoryContinuationPoints& sessionCPs)
{
  for (const auto& nodeToRead : mRequest.nodes_to_read().payload())
  {
    if (nodeToRead.continuation_point().empty())
      continue;

    Guid guid;
    try
    {
      guid.from_ua_binary(nodeToRead.continuation_point());
    }
    catch (...)
    {
      continue;  // Will be caught as invalid during start_history_read
    }

    auto result = sessionCPs.find(guid);
    if (result != sessionCPs.end())
    {
      mContinuationPointsIn.emplace_back(std::move(result->second));
      sessionCPs.erase(result);
    }
  }
}

void HistoryReadService::send_service_fault(
  const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector)
{
  if (!try_finish())
    return;

  auto serviceFault = stack_utils::create_service_fault(&requestHeader, status);
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault->response_header(), unused, 0);
  HistoryReadServiceResponse serviceResponse;
  serviceResponse.response = std::pair(mRequestId, serviceFault);
  mCallback(std::move(serviceResponse));
}

void HistoryReadService::prepare_response_header(ResponseHeader& responseHeader)
{
  stack_utils::prepare_response_header(mRequest.request_header(), responseHeader);
}

}  // namespace ua::server
