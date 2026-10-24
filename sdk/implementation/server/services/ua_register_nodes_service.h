// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REGISTER_NODES_SERVICE_H
#define UA_REGISTER_NODES_SERVICE_H

#include "ua_result.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_await_callback.h"
#include "ua_coro.h"
#include "ua_service_base.h"
#include "ua_service_fault.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"

namespace ua
{

class Node;

namespace server
{

struct RegisterRequestState;
struct UnregisterRequestState;

class RegisterNodesServiceSet : public ServiceBase<RegisterNodesServiceSet>
{
public:
  RegisterNodesServiceSet(const RegisterNodesServiceSet&) = delete;
  RegisterNodesServiceSet& operator=(const RegisterNodesServiceSet&) = delete;
  RegisterNodesServiceSet(RegisterNodesServiceSet&&) = delete;
  RegisterNodesServiceSet& operator=(RegisterNodesServiceSet&&) = delete;

  void abort(StatusCode reason) override;

  using ResponseOrServiceFault = std::variant<ServiceFault, RegisterNodesResponse, UnregisterNodesResponse>;
  using ServiceCallComplete = std::function<void(ResponseOrServiceFault&&)>;

  static shared_ptr<RegisterNodesServiceSet> create(weak_ptr<SessionInfo> sessionInfo,
    RegisterNodesRequest&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback);

  static shared_ptr<RegisterNodesServiceSet> create(weak_ptr<SessionInfo> sessionInfo,
    UnregisterNodesRequest&& request, boost::asio::any_io_executor executor, ServiceCallComplete callback);

  ~RegisterNodesServiceSet();

private:
  friend class ServiceBase<RegisterNodesServiceSet>;

  optional<RegisterNodesRequest> mRegisterRequest;
  optional<UnregisterNodesRequest> mUnregisterRequest;
  ServiceCallComplete mServiceCallCompleteCallback;
  std::unique_ptr<RegisterRequestState> mRegisterFlow;
  std::unique_ptr<UnregisterRequestState> mUnregisterFlow;

  /// The request's own body. One service handles one request, register or unregister, so one task
  /// covers both; the per-namespace bodies it spawns are LOCALS of its frame.
  ua::async::Task<> mRequestTask;

  RegisterNodesServiceSet(weak_ptr<SessionInfo> sessionInfo, RegisterNodesRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  RegisterNodesServiceSet(weak_ptr<SessionInfo> sessionInfo, UnregisterNodesRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  // Kick-off hook called by ServiceBase::start(). Dispatches to
  // start_register or start_unregister based on which constructor was used.
  void begin_processing();

  void start_register();

  /// Registers every namespace the request named and answers it.
  ///
  /// The join IS the barrier. What it replaces was an `operationsRemaining` count that each
  /// namespace's completion decremented, with whichever reached zero sending the response.
  ua::async::Task<> run_register(std::vector<uint16_t> namespaceIndices);
  ua::async::Task<> register_namespace(uint16_t namespaceIndex);
  void on_register_namespace_complete(uint16_t namespaceIndex, BatchResult<NodeId> batch);
  void complete_register();
  void fail_register(VoidResult error);

  void start_unregister();
  ua::async::Task<> run_unregister(std::vector<uint16_t> namespaceIndices);
  ua::async::Task<> unregister_namespace(uint16_t namespaceIndex);
  void on_unregister_namespace_complete(uint16_t namespaceIndex, VoidResult result);
  void complete_unregister();
  void fail_unregister(VoidResult error);

  /// Awaits one collaborator call of one of this request's own bodies, on its strand. The answer is
  /// POSTED, which is what bounds the strand turn to one namespace (R18).
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
          [completion = std::move(completion)](RegisterNodesServiceSet&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  void set_timeout();

  void timeout();
};

}  // namespace server

}  // namespace ua

#endif  // !UA_REGISTER_NODES_SERVICE_H
