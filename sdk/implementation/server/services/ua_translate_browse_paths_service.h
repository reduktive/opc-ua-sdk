// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TRANSLATE_BROWSE_PATHS_SERVICE_H
#define UA_TRANSLATE_BROWSE_PATHS_SERVICE_H

#include <atomic>
#include <optional>
#include <vector>

#include "ua_access_control.h"
#include "ua_address_space.h"
#include "ua_await_callback.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_diagnostic_collector.h"
#include "ua_encoding_limits.h"
#include "ua_locale_id.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_reference.h"
#include "ua_request_info.h"
#include "ua_result.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_service_base.h"

namespace ua
{

namespace server
{

class TranslateBrowsePathsService : public ServiceBase<TranslateBrowsePathsService>
{
public:
  TranslateBrowsePathsService(const TranslateBrowsePathsService&) = delete;
  TranslateBrowsePathsService& operator=(const TranslateBrowsePathsService&) = delete;
  TranslateBrowsePathsService(TranslateBrowsePathsService&&) = delete;
  TranslateBrowsePathsService& operator=(TranslateBrowsePathsService&&) = delete;

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

  ~TranslateBrowsePathsService();

  using ServiceCallComplete = std::function<void(Response)>;

  static shared_ptr<TranslateBrowsePathsService> create(weak_ptr<SessionInfo> sessionInfo,
    std::vector<LocaleId> sessionLocales, uint32_t requestId, TranslateBrowsePathsToNodeIdsRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

private:
  friend class ServiceBase<TranslateBrowsePathsService>;

  std::vector<LocaleId> mSessionLocales;
  uint32_t mRequestId;
  const TranslateBrowsePathsToNodeIdsRequest mRequest;
  ServiceCallComplete mServiceCallCompleteCallback;
  shared_ptr<std::atomic_bool> mCancelled;

  // Request state. This service is constructed PER REQUEST, so these members ARE the request's
  // state - there is nothing for a struct to group and nothing for a pointer to disengage. What one
  // path needs for itself lives in a TranslateWalk, owned by the request's own coroutine frame.
  std::optional<AddressSpace> mTranslateAddressSpace;  // optional only because AddressSpace has no default
  shared_ptr<TranslateBrowsePathsToNodeIdsResponse> mTranslateResponse;
  DiagnosticCollector mTranslateCollector{0};
  std::optional<SessionAccessControl> mTranslateAccessControl;
  ua::EncodingLimits mTranslateLimits;
  /// Part 4 5.8.4: the per-path references-examined cap. 0 means unlimited.
  uint32_t mMaxWalkReferences{0};
  /// The request every namespace call carries: its deadline, its cancellation flag and the Session's locales.
  RequestInfo mRequestInfo;

  /// The request's own coroutine. Held here because it must outlive the frame that started it, and
  /// declared LAST so that destroying this service destroys the task - and with it every walk and
  /// every suspended step - before the state those bodies reference.
  ua::async::Task<> mTranslateRequestTask;

  TranslateBrowsePathsService(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales,
    uint32_t requestId, TranslateBrowsePathsToNodeIdsRequest&& request, boost::asio::any_io_executor executor,
    ServiceCallComplete callback);

  /// Kick-off hook called by ServiceBase::start().
  void begin_processing();

  // ----- The request -----

  /// Contains whatever the body throws, and completes the request exactly once.
  ua::async::Task<> run_translate_request();

  /// Validates, looks every starting node up with one call per namespace, authorizes them with one call
  /// per namespace, and then walks every path in step - one relative-path element at a time, all paths
  /// together, each element in rounds: one References read, one lookup and one authorization per
  /// namespace per round, and a further round for References a namespace answered with a resume token.
  ua::async::Task<> dispatch_translate_request();

  /// One path's walk: its own data, and where it has got to. Defined in the .cpp.
  struct TranslateWalk;

  /// Builds one walk per BrowsePath, answering in place the ones a synchronous check rejects.
  std::vector<TranslateWalk> prepare_translate_walks();

  /// Settles what one relative-path element did to a path's status, once the element is over.
  void apply_element_status(TranslateWalk& walk);

  /// Writes one path's answer into the response and takes it out of the walk.
  void finish_walk(TranslateWalk& walk, VoidResult terminalStatus);

  /// Answers a path that has run out of elements with the targets it reached.
  void finish_walked_out(TranslateWalk& walk);

  void complete_translate();

  /// Answers the client with a service fault AND withdraws the request, so walks still suspended
  /// unwind rather than writing into a response that has been handed away.
  void fail_translate(VoidResult error);

  /// Awaits one collaborator call.
  ///
  /// Every suspension in a Translate has the same shape - hand the collaborator a completion, resume
  /// with what it produced - and the lifetime rule is identical for all of them: the answer hops to
  /// this service's strand and the suspension's generation is re-checked before the frame is touched.
  /// Naming it once keeps that rule in one place rather than restated at each await.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(mStrand, mLogger, weak_from_this(), std::forward<Initiate>(initiate));
  }

  /// Ends this strand turn and resumes on the next one.
  ua::async::Task<> yield_strand();

  void set_timeout();

  void timeout();

  void send_service_fault(
    const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector);
};

}  // namespace server

}  // namespace ua

#endif  // !UA_TRANSLATE_BROWSE_PATHS_SERVICE_H
