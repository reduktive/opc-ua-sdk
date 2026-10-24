// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BROWSE_SERVICE_H
#define UA_BROWSE_SERVICE_H

#include <atomic>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

#include "ua_continuation_points.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_locale_id.h"
#include "ua_node_accessor.h"
#include "ua_request_info.h"
#include "ua_access_control.h"
#include "ua_await_callback.h"
#include "ua_diagnostic_collector.h"
#include "ua_paused_operation.h"
#include "ua_service_base.h"

namespace ua
{

namespace server
{

class DiagnosticCollector;

using BrowseContinuationPoints = std::unordered_map<Guid, BrowseContinuationPoint>;

struct BrowseOperation;
struct OpenOperation;

class BrowseService : public ServiceBase<BrowseService>
{
  friend class ServiceBase<BrowseService>;

public:
  BrowseService(const BrowseService&) = delete;
  BrowseService& operator=(const BrowseService&) = delete;
  BrowseService(BrowseService&&) = delete;
  BrowseService& operator=(BrowseService&&) = delete;

  void abort(StatusCode reason) override;

  /// This request's withdrawal flag, for the coroutines that belong to it.
  ///
  /// Read by @ref ua::async::detail::PromiseBase, which builds every promise from the coroutine's own
  /// argument list - and for a member coroutine the first of those is `*this`. So every task this
  /// service starts adopts the token with nothing written at any call site. Renaming or removing this
  /// silently unhooks cancellation from the whole service.
  [[nodiscard]] std::shared_ptr<const std::atomic_bool> cancellation_token() const noexcept
  {
    return mCancelled;
  }

  struct BrowseServiceResponse
  {
    Response response;
    std::vector<BrowseContinuationPoint> continuationPoints;
  };

  using BrowseServiceCallComplete = std::function<void(BrowseServiceResponse)>;

  static shared_ptr<BrowseService> create(weak_ptr<SessionInfo> sessionInfo,
    std::vector<LocaleId> sessionLocales, uint32_t requestId, BrowseRequest&& browseRequest,
    boost::asio::any_io_executor executor, BrowseServiceCallComplete callback);

  static shared_ptr<BrowseService> create(weak_ptr<SessionInfo> sessionInfo,
    std::vector<LocaleId> sessionLocales, uint32_t requestId, BrowseNextRequest&& browseNextRequest,
    BrowseContinuationPoints& continuationPoints, boost::asio::any_io_executor executor,
    BrowseServiceCallComplete callback);

  ~BrowseService();

private:
  std::vector<LocaleId> mSessionLocales;
  uint32_t mRequestId;
  optional<BrowseRequest> mBrowseRequest;
  optional<BrowseNextRequest> mBrowseNextRequest;
  BrowseServiceCallComplete mServiceCallCompleteCallback;
  std::vector<BrowseContinuationPoint> mContinuationPointsIn;
  shared_ptr<std::atomic_bool> mCancelled;
  // Facts about ReferenceTypes for this request, so a type met again in a later round or by another operation
  // is not asked about again: whether it is symmetric, and whether a type is a requested type or a subtype of
  // it. Touched only on the strand.
  std::unordered_map<NodeId, bool> mReferenceTypeSymmetry;
  std::map<std::pair<NodeId, NodeId>, bool> mSubtypeAnswers;

  /// Which of the two requests this service is running. Fixed at @ref begin_processing.
  enum class Mode
  {
    Browse,
    BrowseNext,
  };

  // Request state. This service is constructed PER REQUEST, so these members ARE the request's
  // state - there is nothing for a struct to group and nothing for a pointer to disengage. What an
  // operation uses on its own lives in its own coroutine frame; see BrowseOperation.
  Mode mBrowseMode{Mode::Browse};
  std::optional<AddressSpace> mBrowseAddressSpace;  // optional only because AddressSpace has no default
  shared_ptr<BrowseResponse> mBrowseResponse;  // engaged when mBrowseMode == Browse
  shared_ptr<BrowseNextResponse> mBrowseNextResponse;  // engaged when mBrowseMode == BrowseNext
  BrowseServiceResponse mBrowseServiceResponse;
  DiagnosticCollector mBrowseCollector{0};
  std::optional<SessionAccessControl> mBrowseAccessControl;

  /// What each item has produced so far, and whether it was answered, is still running, or was handed
  /// to a continuation point at the partial-result deadline. One per item of the request; an item's
  /// operation writes here, never into the response, so a response sent at the deadline is never
  /// written to again. Defined in the .cpp.
  struct StagedItem;
  std::vector<StagedItem> mStaged;

  /// Fires at the request's partial-result deadline (`partialResultDeadlineFraction` of its
  /// timeoutHint); see @ref answer_at_partial_result_deadline.
  Timer mPartialResultTimer;
  /// When that deadline falls, for the namespace calls this request makes (API-10.2). Empty when the
  /// request asked for no timeout.
  std::optional<std::chrono::steady_clock::time_point> mPartialResultDeadline;
  /// Set when this request has sent its response, read by @ref cancel on another thread so a late
  /// Cancel cannot stop operations a continuation point now owns.
  std::atomic_bool mAnswered{false};
  /// The cancellation flag of every namespace call this request makes (@ref mRequestInfo): set by this
  /// request's cancel and timeout paths, and once every operation of it handed to a continuation point
  /// at the partial-result deadline has been released (API-10.4).
  shared_ptr<std::atomic_bool> mNamespaceCallsCancelled{std::make_shared<std::atomic_bool>(false)};
  /// Counts the operations of this request handed to a continuation point; the last one released sets
  /// @ref mNamespaceCallsCancelled.
  shared_ptr<SharedCallCancellation> mPausedCalls{
    std::make_shared<SharedCallCancellation>(mNamespaceCallsCancelled)};
  /// The request every namespace call carries: its deadline, its partial-result deadline as `answerBy`,
  /// the flag above and the Session's locales.
  RequestInfo mRequestInfo;

  /// The request's own coroutine - the batched head. Held here for the same reason the per-operation
  /// tasks are: it must outlive the frame that started it.
  ua::async::Task<> mBrowseRequestTask;

  BrowseService(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
    BrowseRequest&& browseRequest, boost::asio::any_io_executor executor, BrowseServiceCallComplete callback);

  BrowseService(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
    BrowseNextRequest&& browseNextRequest, BrowseContinuationPoints& continuationPoints,
    boost::asio::any_io_executor executor, BrowseServiceCallComplete callback);

  void begin_processing();

  // ----- The request -----

  /// Contains whatever the body throws, and completes the request exactly once.
  ua::async::Task<> run_browse_request();

  /// Validates, builds the work, spawns every unit and joins them.
  ua::async::Task<> dispatch_browse_request();

  /// The operations and waits one request has to run. Defined in the .cpp.
  struct BrowseWork;

  BrowseWork prepare_browse_work(SessionInfo& sessionInfo);
  BrowseWork prepare_browse_next_work(SessionInfo& sessionInfo);

  void complete_browse();

  /// Answers the client with a service fault AND withdraws the request, so operations still
  /// suspended unwind rather than writing into a response that has been handed away.
  void fail_browse(VoidResult error);

  /// Records a per-item failure the item's own body never got to record, and finishes the item.
  void record_browse_failure(size_t opIndex, StatusCode status);

  // ----- Items, and the partial-result deadline -----

  /// A BrowseNext item that continues an operation paused by an earlier request. Defined in the .cpp.
  struct BrowseWait;

  /// The item's staging slot: what its operation has written so far.
  BrowseResult& staged_result(size_t index);
  /// Records an item diagnostic for the item, delivered with its result.
  void stage_detail(size_t index, shared_ptr<const ErrorDetail> detail);
  /// Records the continuation point the item's result names.
  void stage_continuation_point(size_t index, BrowseContinuationPoint continuationPoint);

  /// The item's operation has finished: its staged result goes into the response, or, if the item
  /// was handed to a continuation point, into that point for the BrowseNext that continues it.
  void finish_item(size_t index);

  /// Waits for the outcome of the paused operation a BrowseNext item continues; the outcome is taken
  /// and authorized again by @ref reauthorize_waits.
  ua::async::Task<> await_paused_outcome(BrowseWait wait);
  /// Delivers the outcomes the waits of @p indexes awaited, authorized again together: the sources looked
  /// up and authorized with one call per namespace, and the References' targets once (@ref
  /// reauthorize_targets).
  ua::async::Task<> reauthorize_waits(std::vector<size_t> indexes);

  /// At the partial-result deadline: every finished item keeps its result; every item still running
  /// is answered with no references and a continuation point that owns its running operation; the
  /// response is sent. Browse only hands out as many continuation points as the Session may hold;
  /// the rest are waited for until the timeoutHint (OPC 10000-4 section 7.9).
  void answer_at_partial_result_deadline();
  /// Hands one running item to a continuation point.
  void pause_item(size_t index);

  /// Sets this request's cancellation flags: the token its operations stop on and its namespace calls'
  /// flag.
  void cancel_all_calls();
  /// Releases the paused operations this request was still waiting for and will not deliver.
  void release_unfinished_waits();

  /// Whichever of the two requests is engaged. @throws UaException if neither is, which cannot happen.
  const RequestHeader& active_request_header() const;

  Array<BrowseResult>& browse_results();
  ResponseHeader& browse_response_header();
  Array<DiagnosticInfo>& browse_diagnostic_infos();

  /// Awaits one collaborator call.
  ///
  /// Every suspension in a Browse has the same shape - hand the collaborator a completion, resume
  /// with what it produced - and the lifetime rule is identical for all of them: the answer hops to
  /// this service's strand and the suspension's generation is re-checked before the frame is touched.
  /// Naming it once keeps that rule in one place rather than restated at each await.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(mStrand, mLogger, weak_from_this(), std::forward<Initiate>(initiate));
  }

  /// SVR-AUTHZ-010: the target authorization a Browse applies, for the References of operations it
  /// continues. The local targets of every item of @p references are looked up together with one call per
  /// namespace and authorized for Browse with one call per namespace; a denied target's Reference is
  /// dropped, and a short verdict list denies (fail closed). Unresolvable or remote targets are kept.
  ua::async::Task<std::vector<Array<ReferenceDescription>>> reauthorize_targets(
    std::vector<Array<ReferenceDescription>> references);

  // ----- The operations -----

  /// Answers every operation of @p operations in rounds (NR-25): their sources looked up, authorized and
  /// checked against their View together, then the operations of each namespace of the sources in rounds
  /// of their own (@ref browse_rounds). Each operation's item is finished as soon as it is answered.
  ua::async::Task<> browse_in_rounds(std::vector<BrowseOperation> operations);
  /// The rounds of the operations whose sources one namespace holds, each operation open and its source
  /// authorized and in its View: while any is open, one read of References per namespace, the round's
  /// candidate targets checked against their View, looked up and authorized with one call each per
  /// namespace, and their TypeDefinitions read with one hinted call per namespace. @p ops is held by
  /// @ref browse_in_rounds, which outlives the task, so an operation the task leaves open when it fails to
  /// start or is destroyed is still there to be answered.
  ua::async::Task<> browse_rounds(std::vector<OpenOperation>& ops);
  /// The operation is answered: its item is finished, and a resume token it holds is released.
  void finish_operation(OpenOperation& operation);
  /// The operation answers @p status, with its detail and the References it has already returned.
  void fail_operation(OpenOperation& operation, const StatusCode& status);
  /// A page of the operation's References was answered @p code, a Good subcode, an Uncertain code or plain
  /// Good, with the References: the operation's status becomes the code
  /// @ref ua::detail::combined_status gives for its status so far and @p code, so the code the namespace
  /// gave reaches the client with the References (OPC 10000-4 7.39.1); the detail of a code that becomes the
  /// status joins the operation's diagnostics.
  void note_page_status(OpenOperation& operation, const StatusCode& code);
  /// The operation's result is full: a continuation point holds the References not yet examined and the
  /// namespace's resume token, if there is either; then the operation is answered.
  void halt_operation(OpenOperation& operation);

  void retrieve_continuation_points(BrowseContinuationPoints& continuationPoints);

  void add_reference_description(AddressSpace addressSpace, const optional<NodeAccessor> target,
    const ExpandedNodeId& targetId, const std::optional<LocalizedText>& targetDisplayName,
    const NodeId& refType, bool isForward, uint32_t resultMask, const ExpandedNodeId& typeDefinition,
    BrowseResult& browseResult);

  void set_timeout();

  /// Whether the request has built its response (it has, once its work is prepared).
  bool browse_response_exists() const;

  void timeout();

  void send_service_fault(
    const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector);

  void prepare_response_header(ResponseHeader& responseHeader);
};

}  // namespace server

}  // namespace ua

#endif  // !UA_BROWSE_SERVICE_H
