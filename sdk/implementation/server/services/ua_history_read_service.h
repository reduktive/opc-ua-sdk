// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_READ_SERVICE_H
#define UA_HISTORY_READ_SERVICE_H

#include <atomic>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ua_access_control.h"
#include "ua_result.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_continuation_points.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_locale_id.h"
#include "ua_await_callback.h"
#include "ua_coro.h"
#include "ua_node_accessor.h"
#include "ua_paused_operation.h"
#include "ua_request_info.h"
#include "ua_service_base.h"

namespace ua::server
{

class DiagnosticCollector;
struct HistoryReadState;

class HistoryReadService : public ServiceBase<HistoryReadService>
{
  friend class ServiceBase<HistoryReadService>;

public:
  HistoryReadService(const HistoryReadService&) = delete;
  HistoryReadService& operator=(const HistoryReadService&) = delete;
  HistoryReadService(HistoryReadService&&) = delete;
  HistoryReadService& operator=(HistoryReadService&&) = delete;

  struct HistoryReadServiceResponse
  {
    Response response;
    std::vector<HistoryContinuationPoint> continuationPoints;
  };

  using CompleteCallback = std::function<void(HistoryReadServiceResponse)>;

  void abort(StatusCode reason) override;

  /// The token every body of this request adopts, so a cancelled HistoryRead stops where it is
  /// suspended rather than carrying on against a client that has already been answered (R16).
  [[nodiscard]] std::shared_ptr<const std::atomic_bool> cancellation_token() const noexcept
  {
    return mCancelled;
  }

  static shared_ptr<HistoryReadService> create(weak_ptr<SessionInfo> sessionInfo,
    std::vector<LocaleId> sessionLocales, uint32_t requestId, HistoryReadRequest&& request,
    HistoryContinuationPoints& sessionContinuationPoints, boost::asio::any_io_executor executor,
    CompleteCallback callback);

  ~HistoryReadService();

private:
  HistoryReadService(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales,
    uint32_t requestId, HistoryReadRequest&& request, boost::asio::any_io_executor executor,
    CompleteCallback callback);

  // Kick-off hook called by ServiceBase::start(). Invokes start_history_read().
  void begin_processing();

  void start_history_read();

  /// Starts the request's resolution body once the item list is built.
  void start_request();

  /// Resolves every fresh item, joins them, then moves the request on.
  ///
  /// The join IS the barrier. What it replaces was a `nodeResolvesRemaining` count that each item's
  /// last handler decremented, with whichever reached zero deciding what happened next.
  ua::async::Task<> run_history_read();

  /// Every item at once: one lookup of their Nodes, the history access of each from its description, and
  /// one authorization of those that can be read. Records each refusal on its own row, and marks each
  /// authorized entry.
  ua::async::Task<> resolve_items();

  /// One authorized item named with a dataEncoding: decides whether that encoding can be provided for it.
  /// Records its verdict on its own entry; the grouping happens after the join, so that nothing here
  /// depends on the order the items finished in.
  ua::async::Task<> classify_item_encoding(size_t freshIndex);

  /// Establishes EventType membership for the request's select clauses, and decides which archived
  /// fields the session may read: one batched authorization of each clause's InstanceDeclaration, as
  /// live event delivery authorizes it (SVR-AUTHZ-001). One await for the whole request, not one per
  /// item, and only asked when the request is a ReadEventDetails that has something left to read.
  ua::async::Task<> validate_event_select_clause_model();

  /// Reads every namespace that has surviving items, and answers the request.
  ///
  /// The join IS the barrier. What it replaces was a `namespacesRemaining` count that each
  /// namespace's completion decremented, with whichever reached zero sending the response.
  ua::async::Task<> run_namespace_reads();

  ua::async::Task<> read_namespace_raw(uint16_t namespaceIndex);
  void on_namespace_read_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch);
  // ReadProcessedDetails: a delegate that natively computes aggregates
  // (capabilities().read_processed) handles the read directly; otherwise the
  // service reads raw over the window and runs the built-in Part-13 calculator.
  ua::async::Task<> read_namespace_processed(uint16_t namespaceIndex);
  void on_namespace_processed_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadProcessedItemResult> batch);
  void on_namespace_turnkey_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch);
  // ReadAnnotationDataDetails: annotations are read from the delegate at the requested
  // timestamps (order-preserving); there is no built-in/turnkey path.
  ua::async::Task<> read_namespace_annotations(uint16_t namespaceIndex);
  void on_namespace_annotations_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadAnnotationItemResult> batch);
  // ReadAtTimeDetails: interpolated/raw values at the requested timestamps; delegate-only.
  ua::async::Task<> read_namespace_at_time(uint16_t namespaceIndex);
  void on_namespace_at_time_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadAtTimeItemResult> batch);
  // ReadEventDetails: historical events matching the filter over the window; delegate-only.
  ua::async::Task<> read_namespace_events(uint16_t namespaceIndex);
  /// SVC-17: keeps only the archived events whose SourceNode and EventType the session may ReceiveEvents
  /// from, as live delivery does (SVR-AUTHZ-016); events without a reported origin are left to the
  /// ReadHistory gate on the notifier. One find batch and one authorize batch over the distinct origins.
  ua::async::Task<> filter_events_by_receive_events(
    BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult>& batch);
  /// Replaces, in place, each returned field the session may not read with Bad_UserAccessDenied, by the
  /// per-clause decisions @ref validate_event_select_clause_model took. Field positions are preserved.
  void withhold_unreadable_event_fields(
    BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult>& batch) const;
  void on_namespace_events_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::ReadEventsItemResult> batch);
  void complete_history_read();

  // ----- Items, and the partial-result deadline (item 10) -----

  /// One item of the request: what its read has written so far, and whether it was answered, is still
  /// running, or was handed to a continuation point at the partial-result deadline. Defined in the .cpp.
  struct StagedItem;

  /// The item's staging slot. Every write made while the request runs goes here, never into the
  /// response, so a response sent at the deadline is never written to again.
  HistoryReadResult& history_result(size_t index);
  /// Records an item diagnostic, delivered with the item's result.
  void stage_history_detail(size_t index, shared_ptr<const ErrorDetail> detail);
  /// Records the continuation point the item's result names.
  void stage_history_continuation_point(size_t index, HistoryContinuationPoint continuationPoint);
  /// The item's read has finished: its staged result goes into the response, or to the continuation
  /// point it was handed to.
  void finish_history_item(size_t index);
  /// Waits for an operation an earlier request paused and delivers its outcome as this item's result.
  ua::async::Task<> run_history_wait(size_t index);
  /// Reads one namespace and finishes its items.
  ua::async::Task<> run_namespace_read(uint16_t namespaceIndex);

  /// The cancellation flag of this request's call to @p namespaceIndex 's history delegate.
  shared_ptr<std::atomic_bool> call_flag_for(uint16_t namespaceIndex);
  /// Starts the partial-result deadline timer (API-10.1).
  void arm_partial_result_deadline(uint32_t timeoutHint);
  /// At the partial-result deadline: finished items keep their results, running ones get a continuation
  /// point that owns their read, and the response is sent while the reads go on (OPC 10000-4 section
  /// 5.10.3.1, OPC 10000-11 section 6.3).
  void answer_at_partial_result_deadline();
  /// Hands one running item to a continuation point.
  void pause_history_item(size_t index);
  /// Sends the response now without ending the request's reads.
  void send_partial_response();
  /// Sets the token and every delegate call's flag.
  void cancel_all_calls();
  /// Releases the paused operations this request was waiting for and will not deliver.
  void release_unfinished_waits();
  void fail_history_read(VoidResult error);

  void timeout();

  void retrieve_continuation_points(HistoryContinuationPoints& sessionCPs);

  void send_service_fault(
    const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector);

  void prepare_response_header(ResponseHeader& responseHeader);

  std::vector<LocaleId> mSessionLocales;
  /// The request as the namespaces are told it: the deadline from its timeoutHint, the partial-result
  /// deadline when armed, this request's cancellation flag and the Session's locales.
  RequestInfo mRequestInfo;
  uint32_t mRequestId;
  HistoryReadRequest mRequest;
  CompleteCallback mCallback;
  shared_ptr<std::atomic_bool> mCancelled;

  // CPs extracted from session at create() time
  std::vector<HistoryContinuationPoint> mContinuationPointsIn;

  std::vector<StagedItem> mStaged;
  Timer mPartialResultTimer;
  std::optional<std::chrono::steady_clock::time_point> mPartialResultDeadline;
  /// Set once the response is sent; read by cancel() on another thread.
  std::atomic_bool mAnswered{false};
  /// One cancellation flag per namespace delegate call, and the shared release count of its items.
  std::unordered_map<uint16_t, std::pair<shared_ptr<std::atomic_bool>, shared_ptr<SharedCallCancellation>>>
    mCalls;

  /// The request's own body. The per-item and per-namespace bodies it spawns are LOCALS of its frame,
  /// so destroying this destroys them too, in order, and there is no vector of frames for anything
  /// to free from inside one of them.
  ua::async::Task<> mRequestTask;

  /// Awaits one collaborator call of one of this request's own bodies, on its strand.
  ///
  /// The answer is POSTED rather than dispatched, and that post is the only thing bounding the
  /// strand turn (R18). `await_callback` resumes INLINE when the answer arrives on the strand it is
  /// already running on, and on this path every collaborator can answer there - a namespace that
  /// keeps its nodes in the SDK's own store resolves inline, and an access decision whose
  /// permissions are already known is decided inline. Without the post, a HistoryRead naming N nodes
  /// would run all of its resolutions and decisions inside ONE strand turn: the request's own
  /// timeout timer is armed on that strand, so `timeoutHint` could not fire. The chain this replaces
  /// posted after every step, for exactly that reason.
  ///
  /// `post_borrowing`, not `post_owning`: this service owns the bodies, so a request that has gone
  /// has taken them with it and there is nothing left to answer.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(mStrand,
      mLogger,
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          mStrand,
          mLogger,
          [completion = std::move(completion)](HistoryReadService&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  std::unique_ptr<HistoryReadState> mFlow;
};

}  // namespace ua::server

#endif  // !UA_HISTORY_READ_SERVICE_H
