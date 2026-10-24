// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODE_MANAGEMENT_SERVICE_H
#define UA_NODE_MANAGEMENT_SERVICE_H

#include <atomic>
#include <optional>
#include <unordered_map>

#include "ua_access_control.h"
#include "ua_await_callback.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_result.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_namespace_delegates.h"
#include "ua_service_base.h"

namespace ua::server
{

class NodeManagementDelegate;

struct AddNodesState;
struct AddReferencesState;
struct DeleteNodesState;
struct DeleteReferencesState;

class NodeManagementService : public ServiceBase<NodeManagementService>
{
public:
  NodeManagementService(const NodeManagementService&) = delete;
  NodeManagementService& operator=(const NodeManagementService&) = delete;
  NodeManagementService(NodeManagementService&&) = delete;
  NodeManagementService& operator=(NodeManagementService&&) = delete;

  void cancel() override;
  void abort(StatusCode reason) override;

  using ServiceCallComplete = std::function<void(Response)>;

  // AddNodes factory
  static shared_ptr<NodeManagementService> create(weak_ptr<SessionInfo> sessionInfo,
    std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, AddNodesRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  // AddReferences factory
  static shared_ptr<NodeManagementService> create(weak_ptr<SessionInfo> sessionInfo,
    std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, AddReferencesRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  // DeleteNodes factory
  static shared_ptr<NodeManagementService> create(weak_ptr<SessionInfo> sessionInfo,
    std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, DeleteNodesRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  // DeleteReferences factory
  static shared_ptr<NodeManagementService> create(weak_ptr<SessionInfo> sessionInfo,
    std::shared_ptr<NodeManagementDelegate> handler, uint32_t requestId, DeleteReferencesRequest&& request,
    boost::asio::any_io_executor executor, ServiceCallComplete callback);

  ~NodeManagementService();

private:
  friend class ServiceBase<NodeManagementService>;

  uint32_t mRequestId;
  std::shared_ptr<NodeManagementDelegate> mHandler;

  optional<AddNodesRequest> mAddNodesRequest;
  optional<AddReferencesRequest> mAddReferencesRequest;
  optional<DeleteNodesRequest> mDeleteNodesRequest;
  optional<DeleteReferencesRequest> mDeleteReferencesRequest;

  ServiceCallComplete mServiceCallCompleteCallback;
  shared_ptr<std::atomic_bool> mCancelled;

  std::unique_ptr<AddNodesState> mAddNodesState;
  /// The AddNodes body. Lives on the request, so it dies with it.
  ua::async::Task<> mAddNodesTask;
  std::unique_ptr<AddReferencesState> mAddReferencesState;
  /// The AddReferences body. Lives on the request, so it dies with it.
  ua::async::Task<> mAddReferencesTask;
  std::unique_ptr<DeleteNodesState> mDeleteNodesState;
  /// The DeleteNodes body. Lives on the request, so it dies with it.
  ua::async::Task<> mDeleteNodesTask;
  std::unique_ptr<DeleteReferencesState> mDeleteReferencesState;
  /// The DeleteReferences body. Lives on the request, so it dies with it.
  ua::async::Task<> mDeleteReferencesTask;

  // AddNodes constructor
  NodeManagementService(weak_ptr<SessionInfo> sessionInfo, std::shared_ptr<NodeManagementDelegate> handler,
    uint32_t requestId, AddNodesRequest&& request, boost::asio::any_io_executor executor,
    ServiceCallComplete callback);

  // AddReferences constructor
  NodeManagementService(weak_ptr<SessionInfo> sessionInfo, std::shared_ptr<NodeManagementDelegate> handler,
    uint32_t requestId, AddReferencesRequest&& request, boost::asio::any_io_executor executor,
    ServiceCallComplete callback);

  // DeleteNodes constructor
  NodeManagementService(weak_ptr<SessionInfo> sessionInfo, std::shared_ptr<NodeManagementDelegate> handler,
    uint32_t requestId, DeleteNodesRequest&& request, boost::asio::any_io_executor executor,
    ServiceCallComplete callback);

  // DeleteReferences constructor
  NodeManagementService(weak_ptr<SessionInfo> sessionInfo, std::shared_ptr<NodeManagementDelegate> handler,
    uint32_t requestId, DeleteReferencesRequest&& request, boost::asio::any_io_executor executor,
    ServiceCallComplete callback);

  // Kick-off hook called by ServiceBase::start(). Dispatches to the
  // appropriate start_* method based on which request constructor was used.
  void begin_processing();

  // ----- AddNodes -----
  void start_add_nodes();

  /// The whole AddNodes request, in the three phases the chain spelled out with three counters:
  /// choose a destination namespace for every item and ask whether this session may write there,
  /// validate each surviving item, then resolve the parent each one wants to hang from. Each phase
  /// spawns its units eagerly into a vector local to this frame and awaits them; the join is the
  /// barrier.
  ua::async::Task<> run_add_nodes();

  /// Applies what the delegate answered about destinations, and groups the survivors by namespace.
  std::unordered_map<uint16_t, std::vector<size_t>> accept_prepared_destinations(
    BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch);

  /// One destination namespace: may this session add nodes there? Answers for the whole group.
  ua::async::Task<> authorize_destination_unit(uint16_t namespaceIndex, std::vector<size_t> itemIndices);

  /// The checks decidable from one item alone. Returns false when the item is already answered.
  bool screen_add_nodes_item(size_t itemIndex);

  /// One item's TypeDefinition and attaching ReferenceType.
  ua::async::Task<> validate_add_nodes_unit(size_t itemIndex);

  /// One item's parent, the rules that parent imposes, and the BrowseName it would take under it.
  ua::async::Task<> add_nodes_parent_unit(size_t itemIndex);

  ua::async::Task<> call_add_nodes_delegate();
  void complete_add_nodes();
  void fail_add_nodes(VoidResult error);

  // ----- AddReferences -----
  void start_add_references();

  /// The whole AddReferences request. @see run_delete_nodes for what the join replaces.
  ua::async::Task<> run_add_references();

  /// One item, the long way: the source and the access decision, then what the source already
  /// carries, then whichever of the three ReferenceTypes with rules of their own this is, then the
  /// target and the class the client declared for it, then the No Loops constraint.
  ua::async::Task<> add_references_unit(size_t itemIndex);

  /// Records one item's verdict, letting the declared-class comparison decide an item that every
  /// data-model check passed.
  void finish_add_references_item_validation(size_t itemIndex, StatusCode status = {});

  ua::async::Task<> call_add_references_delegate();
  void complete_add_references();
  void fail_add_references(VoidResult error);

  // ----- DeleteNodes -----
  void start_delete_nodes();

  /// The whole DeleteNodes request: authorize every item, hand the survivors to the delegate, answer.
  ///
  /// The per-item units are spawned eagerly into a vector local to this frame and then awaited, so
  /// the join IS the barrier the chain spelled out with a `pendingAuthorizations` countdown.
  ua::async::Task<> run_delete_nodes();

  /// One item: resolve its node, then ask whether this session may delete it.
  ua::async::Task<> delete_nodes_unit(size_t itemIndex);

  ua::async::Task<> call_delete_nodes_delegate();
  void complete_delete_nodes();
  void fail_delete_nodes(VoidResult error);

  // ----- DeleteReferences -----
  void start_delete_references();

  /// The whole DeleteReferences request. @see run_delete_nodes for what the join replaces.
  ua::async::Task<> run_delete_references();

  /// One item: the reference type, the target, the source, then the access decision. The two
  /// structural screens - a foreign server index, a null target - are decided before a unit exists.
  ua::async::Task<> delete_references_unit(size_t itemIndex);

  ua::async::Task<> call_delete_references_delegate();
  void complete_delete_references();
  void fail_delete_references(VoidResult error);

  /// Awaits one collaborator call of one of this request's own bodies, on its strand.
  ///
  /// The answer is POSTED rather than dispatched, and that post is the only thing bounding the
  /// strand turn: `await_callback` resumes INLINE when the answer arrives on the strand it is
  /// already running on, and every collaborator here can answer on the calling stack - a namespace
  /// keeping its nodes in the SDK's own store resolves inline, and an access decision whose
  /// permissions are already known is decided inline. Without the post, a request naming N nodes
  /// would run all of its resolutions and decisions in ONE strand turn: the request's own timeout
  /// timer is armed on that strand, so `timeoutHint` could not fire, and the pool thread would be
  /// unavailable to every other session sharing the executor for as long as the client's item count.
  /// The chain this replaces posted after every step, for exactly that reason (R18).
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
          [completion = std::move(completion)](NodeManagementService&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  void set_timeout();
  void timeout();
  void finish(Response response);

  void send_service_fault(const RequestHeader& requestHeader, StatusCode status);
};

}  // namespace ua::server

#endif  // !UA_NODE_MANAGEMENT_SERVICE_H
