// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_UPDATE_SERVICE_H
#define UA_HISTORY_UPDATE_SERVICE_H

#include "ua_access_control.h"
#include "ua_result.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_event_validation.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_await_callback.h"
#include "ua_coro.h"
#include "ua_node_accessor.h"
#include "ua_request_info.h"
#include "ua_service_base.h"

namespace ua::server
{

class DiagnosticCollector;

struct HistoryUpdateState;

class HistoryUpdateService : public ServiceBase<HistoryUpdateService>
{
  friend class ServiceBase<HistoryUpdateService>;

public:
  HistoryUpdateService(const HistoryUpdateService&) = delete;
  HistoryUpdateService& operator=(const HistoryUpdateService&) = delete;
  HistoryUpdateService(HistoryUpdateService&&) = delete;
  HistoryUpdateService& operator=(HistoryUpdateService&&) = delete;

  using CompleteCallback = std::function<void(Response)>;

  void abort(StatusCode reason) override;

  /// The token every body of this request adopts, so a cancelled HistoryUpdate stops where it is
  /// suspended rather than carrying on against a client that has already been answered (R16).
  [[nodiscard]] std::shared_ptr<const std::atomic_bool> cancellation_token() const noexcept
  {
    return mCancelled;
  }

  static shared_ptr<HistoryUpdateService> create(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId,
    HistoryUpdateRequest&& request, boost::asio::any_io_executor executor, CompleteCallback callback);

  ~HistoryUpdateService();

private:
  HistoryUpdateService(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId, HistoryUpdateRequest&& request,
    boost::asio::any_io_executor executor, CompleteCallback callback);

  // Kick-off hook called by ServiceBase::start(). Invokes start_history_update().
  void begin_processing();

  void start_history_update();

  /// Starts the request's body once the entry list is classified.
  void start_request();

  /// The whole request: resolve, validate the Event details, dispatch the groups, answer.
  ///
  /// Three joins replace three counters. Where the request has got to is where this body has got
  /// to, which is why the state it works on no longer carries a step.
  ua::async::Task<> run_history_update();

  /// Every classified entry at once: one lookup of their Nodes, whether each can carry history and be
  /// written, from its description, and one authorization of those that can. Records each entry's
  /// verdict on the entry; the grouping happens afterwards.
  ua::async::Task<> run_resolution();

  /// Validates every accepted UpdateEvent against OPC 10000-11 6.8.4.2, then joins them and groups
  /// the rows that survived - in `classified` order, because the splice back is positional.
  ua::async::Task<> run_event_validations();
  ua::async::Task<> walk_event_validation(size_t classifiedIndex);

  /// Hands each group to its namespace's historian and joins them, then answers the request.
  ua::async::Task<> run_groups();
  ua::async::Task<> run_group(uint16_t namespaceIndex, int kind);
  void on_update_data_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::UpdateDataItemResult> batch);
  void on_update_events_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::UpdateEventsItemResult> batch);
  void on_update_structure_data_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::UpdateStructureDataItemResult> batch);
  void on_delete_raw_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch);
  void on_delete_at_time_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch);
  void on_delete_events_complete(
    uint16_t namespaceIndex, BatchResult<NamespaceHistoryDelegate::DeleteItemResult> batch);
  void complete_history_update();
  void fail_history_update(VoidResult error);

  void timeout();

  void send_service_fault(
    const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector);

  void prepare_response_header(ResponseHeader& responseHeader);

  uint32_t mRequestId;
  HistoryUpdateRequest mRequest;
  CompleteCallback mCallback;
  shared_ptr<std::atomic_bool> mCancelled;
  /// The request as the namespaces are told it: the deadline from its timeoutHint and this request's
  /// cancellation flag.
  RequestInfo mRequestInfo;

  std::unique_ptr<HistoryUpdateState> mFlow;

  /// The request's own body. Every body it spawns is a LOCAL of its frame, so destroying this
  /// destroys them too, in order, and there is no vector of frames for anything to free from inside
  /// one of them.
  ua::async::Task<> mRequestTask;

  /// Awaits one collaborator call of one of this request's own bodies, on its strand.
  ///
  /// The answer is POSTED rather than dispatched, and that post is the only thing bounding the
  /// strand turn (R18): without it a HistoryUpdate whose collaborators all answer inline would run
  /// every resolution, validation and dispatch in ONE turn, with its own timeout timer armed on that
  /// strand and unable to fire. The chain this replaces posted after every step, for that reason.
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
          [completion = std::move(completion)](HistoryUpdateService&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }
};

}  // namespace ua::server

#endif  // !UA_HISTORY_UPDATE_SERVICE_H
