// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_METHOD_SERVICE_SET_H
#define UA_METHOD_SERVICE_SET_H

#include "ua_access_control.h"
#include "ua_await_callback.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_method_argument_validation.h"
#include "ua_method_response_correlation.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_locale_id.h"

#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_utilities.h"
#include "ua_reference.h"
#include "ua_request_info.h"
#include "ua_result.h"
#include "ua_service_base.h"
#include "ua_subtype_facts.h"

#include <atomic>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace ua
{

class Node;

namespace server
{

class DiagnosticCollector;

struct CallRequestState;
struct CallFlow;
struct CallFlowItem;
struct CallInbox;

class MethodServiceSet : public ServiceBase<MethodServiceSet>
{
public:
  MethodServiceSet(const MethodServiceSet&) = delete;
  MethodServiceSet& operator=(const MethodServiceSet&) = delete;
  MethodServiceSet(MethodServiceSet&&) = delete;
  MethodServiceSet& operator=(MethodServiceSet&&) = delete;

  void abort(StatusCode reason) override;

  /// The token every body of this request adopts, so a cancelled Call stops where it is suspended
  /// rather than carrying on against a client that has already been answered (R16).
  [[nodiscard]] std::shared_ptr<const std::atomic_bool> cancellation_token() const noexcept
  {
    return mCancelled;
  }

  ~MethodServiceSet();

  using CallServiceCallComplete = std::function<void(Response)>;

  static shared_ptr<MethodServiceSet> create(weak_ptr<SessionInfo> sessionInfo,
    std::vector<LocaleId> sessionLocales, uint32_t requestId, CallRequest&& callRequest,
    boost::asio::any_io_executor executor, CallServiceCallComplete callback,
    std::optional<MethodResponseCorrelation> responseCorrelation = std::nullopt);

private:
  friend class ServiceBase<MethodServiceSet>;

  std::vector<LocaleId> mSessionLocales;
  uint32_t mRequestId;
  const CallRequest mCallRequest;
  CallServiceCallComplete mServiceCallCompleteCallback;
  std::optional<MethodResponseCorrelation> mResponseCorrelation;
  shared_ptr<std::atomic_bool> mCancelled;

  /// The request the namespaces are asked for: its deadline from the timeoutHint, the cancellation flag and
  /// the Session's locales.
  RequestInfo mRequestInfo;

  /// What this one request is working with. Per-request state belongs to the per-request service,
  /// which is what this class is - so it stays a member. What LEFT it is what made it a flow: the
  /// step enum, and the `pendingUnits` barrier that counted its units down.
  std::unique_ptr<CallRequestState> mRequestState;

  /// The request's own body. The unit bodies it spawns are LOCALS of that body's frame, so
  /// destroying this destroys them too, in order, and there is no vector of frames for anything to
  /// free from inside one of them.
  ua::async::Task<> mCallTask;

  MethodServiceSet(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales,
    uint32_t requestId, CallRequest&& callRequest, boost::asio::any_io_executor executor,
    CallServiceCallComplete callback, std::optional<MethodResponseCorrelation> responseCorrelation);

  // Kick-off hook called by ServiceBase::start(). Invokes start_call().
  void begin_processing();

  // Top-level Call flow.
  void start_call();

  /// Starts the request's body once the plan is settled.
  void start_dispatch(std::vector<size_t> indices, ua::EncodingLimits limits);

  /// Spawns one body per unit and joins them, then answers.
  ///
  /// The join IS the barrier. What it replaces was a `pendingUnits` count that every unit decremented
  /// and whichever reached zero acted on - which meant the request was completed from inside one of
  /// its own units, and the vectors holding those units could not be cleared without freeing the
  /// frame doing the clearing.
  ua::async::Task<> run_dispatch(std::vector<size_t> indices, ua::EncodingLimits limits);

  /// Answers rows whose body could not be started at all, and audits them like any other answer.
  void answer_unstarted_rows(std::span<const size_t> rows, StatusCode failure);

  void complete_call();

  /// Answers the request with a fault. Reached only from @ref run_dispatch's root catch - the one
  /// place a Call can fail as a whole after its units have started.
  void fail_call(StatusCode error);

  // One existing flow processes every request item: resolve Methods, Objects, type facts and
  // InputArguments together, with one call of each kind per namespace, then use the namespace Call route.

  /// Contains whatever the flow throws, so a failure answers the flow's unanswered items rather than the
  /// request.
  ua::async::Task<> run_call_flow(std::vector<size_t> indices, ua::EncodingLimits limits);

  /// Answers each item that fails a check before its Method is called, in the order of today's checks per
  /// item (OPC 10000-4 5.11.2), and leaves the others unanswered for their call.
  ua::async::Task<> resolve_call_flow(CallFlow& flow);

  /// Looks up the NodeIds of @p nodeIds the flow has not looked up yet: one lookup per namespace.
  ua::async::Task<> look_up(CallFlow& flow, std::vector<NodeId> nodeIds);

  /// Reads the References of @p reads: one read per namespace per round.
  ua::async::Task<std::vector<Result<std::vector<Reference>>>> read_flow_references(
    CallFlow& flow, std::vector<namespace_calls::ReferenceRead> reads);

  /// Decides whether each live item's Method is a component of its Object, of the Object's type or of a
  /// supertype of that type (OPC 10000-4 5.11.2.2 Table 65), reading each level once for the request, and
  /// reads the InputArguments of the Methods @p methods names together with the Objects' first level.
  ua::async::Task<> pair_and_read_arguments(CallFlow& flow, std::vector<NodeId> methods);

  /// Calls the Methods of the items that passed every check, together through the call route, and answers
  /// each item as its namespace answers it (DL-75 (C5)).
  ua::async::Task<> call_flow_items(CallFlow& flow);

  /// Awaits one item's answer, which @p inbox delivers at @p slot - the answer of the StateMachine transition
  /// its call started, when it started one - and answers the item.
  ua::async::Task<> run_call(CallFlow& flow, size_t position, shared_ptr<CallInbox> inbox, size_t slot);

  /// The answer, for @ref run_call.
  ua::async::Task<VoidResult> call_item(
    const shared_ptr<CallInbox>& inbox, size_t slot, optional<CallMethodResult>& callResult);

  /// Answers @p item: finalizes its operation once.
  void answer_item(CallFlowItem& item, VoidResult terminalStatus, optional<CallMethodResult> callResult = {});

  void finalize_operation(size_t opIndex, const CallMethodRequest& methodToCall, VoidResult terminalStatus,
    optional<CallMethodResult> callResult);

  /// Awaits one collaborator call of one of this request's own bodies, on its strand.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    // The answer is POSTED rather than dispatched, and that post is the only thing bounding the
    // strand turn. `await_callback` resumes INLINE when the answer arrives on the strand it is
    // already running on, and on this path every collaborator can answer on the calling stack - a
    // namespace that keeps its nodes in the SDK's own store resolves inline, and an access decision
    // whose permissions are all already known is decided inline. Without the post, a Call naming N
    // methods in one namespace would run all 3N of its resolutions and decisions inside ONE strand
    // turn: the request's own timeout timer is armed on that strand, so `timeoutHint` could not
    // fire, and the pool thread would be unavailable to every other session sharing the executor for
    // as long as the client's method count. The chain this replaces posted after every step, for
    // exactly that reason (R18).
    //
    // `post_borrowing`, not `post_owning`: this service owns the bodies, so a request that has gone
    // has taken them with it and there is nothing left to answer.
    return ua::async::await_callback<T>(mStrand,
      mLogger,
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          mStrand,
          mLogger,
          [completion = std::move(completion)](MethodServiceSet&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  // Audit-event helper (synchronous).
  void emit_audit_event(const CallMethodRequest& methodToCall, const CallMethodResult& result);

  void set_timeout();

  void timeout();

  void send_service_fault(
    const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector);
};

}  // namespace server

}  // namespace ua

#endif  // !UA_METHOD_SERVICE_SET_H
