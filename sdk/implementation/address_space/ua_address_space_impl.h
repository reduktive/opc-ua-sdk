// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ADDRESS_SPACE_IMPL_H
#define UA_ADDRESS_SPACE_IMPL_H

#include "ua_error_detail.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_namespace_array.h"
#include "ua_namespace_metadata_options.h"
#include "ua_reference_halves.h"
#include "ua_result.h"
#include "ua_role_permission_type.h"
#include "ua_server_array.h"
#include "ua_execution_limits.h"
#include "ua_service_operation_limits.h"
#include "ua_weak_address_space.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace ua
{

namespace default_ns
{
class Namespace;
}  // namespace default_ns

namespace detail
{
class SessionResourceRegistry;
class FileHandleBudget;
class NamespaceRegistrationCoordinator;
struct NamespaceRegistrationRoute;
struct LookupItem;
struct AddressSpaceChange;
class NodeAccessorRoute;
class NodeDeletion;
}  // namespace detail

class WeakAddressSpace;

class AddressSpaceImpl : public std::enable_shared_from_this<AddressSpaceImpl>
{
public:
  const ExecutionLimits& limits() const;

  void set_limits(ExecutionLimits limits);
  void set_operation_limits(ServiceOperationLimits limits);

  boost::asio::any_io_executor executor() const;

  /// Returns the logger for async work done on this address space's behalf (e.g. the instantiation
  /// flows that post to @ref executor()). A @ref ua::Logger is a value handle that survives this
  /// impl's destruction; default-constructed it is a silent no-op. Seeded via @ref set_logger.
  ua::Logger logger() const;

  uint64_t model_generation() const noexcept;

  /// Advances the generation @ref model_generation answers, once, saturating at `UINT64_MAX` (NR-27 rule 1).
  /// Called when a create, delete, Reference add or remove, or BrowseName or DataType write completes through
  /// the address space with a change in any namespace (NR-68 item 1). Any thread; lock-free.
  void model_changed() noexcept;

  /// @ref model_changed when any of @p answers is not Bad: some change was made.
  template<typename Answer>
  void model_changed_if_any(const std::vector<Answer>& answers) noexcept
  {
    if (std::ranges::any_of(answers, [](const Answer& answer) { return !answer.is_bad(); }))
    {
      model_changed();
    }
  }

  /// The `maxNodesPerBrowse` operation limit, which bounds each References read of the event-graph check.
  std::optional<uint32_t> max_nodes_per_browse() const noexcept;

  /// Seeds the logger returned by @ref logger(). Called once by the owner (the server) right after
  /// construction, before any async work runs; mirrors @ref set_limits.
  void set_logger(ua::Logger logger);

  /// Registers a handler to run when a Session closes; the returned token keeps it registered.
  ///
  /// Spelled with the underlying types rather than AddressSpace's aliases: the public header
  /// includes this one's siblings, not this one, so naming AddressSpace here would invert that.
  std::shared_ptr<const void> add_session_closed_handler(std::function<void(const NodeId&)> handler);

  /// Runs every live session-closed handler for @p sessionId.
  void notify_session_closed(const NodeId& sessionId);

  /// The FileType handle budget of this address space (`ua_file_handle_budget.h`).
  shared_ptr<detail::FileHandleBudget> file_handle_budget() const;

  void set_change_handler(std::function<void(const detail::AddressSpaceChange&)> handler);
  /// Raises the model change of one operation (NR-46): posted to the executor, where the change handler
  /// receives it, then @p done runs. Counted until it has run, for @ref when_posted_steps_done. Any thread.
  void raise_model_change(detail::AddressSpaceChange change, std::function<void()> done) noexcept;
  /// Runs @p then once every model change posted before this call has run, and every step counted by
  /// @ref start_posted_step has finished (NR-67 step 2); at once when none is outstanding. Any thread.
  void when_posted_steps_done(std::function<void()> then) noexcept;

  /// The model changes posted and not yet run, the other steps started and not yet finished, and who waits
  /// for them. Shared with each step, which may finish after this address space is gone.
  struct PostedSteps
  {
    std::mutex mutex;
    std::size_t outstanding{0};
    std::vector<std::function<void()>> waiters;

    /// Ends one step; the waiters run when it was the last. Any thread.
    void finish(const ua::Logger& logger) noexcept;
  };

  /// Counts a step that @ref when_posted_steps_done waits for, such as a ConfigurationVersion advance (NR-67
  /// step 2). The step calls `finish` on the answer once, when it is done. Any thread.
  shared_ptr<PostedSteps> start_posted_step() noexcept;

  shared_ptr<Namespace> create_namespace(string_view uri);

  shared_ptr<Namespace> create_namespace(string_view uri, std::vector<RolePermissionType> rolePermissions,
    std::optional<AccessRestrictionType> accessRestrictions);

  void find_node_async(const NodeId& nodeId, AddressSpace::FindNodeCompleteCallback callback,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  void find_nodes_async(std::span<const NodeId> nodeIds, AddressSpace::FindNodesCompleteCallback callback,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  /// Looks up @p items for @p request through the namespaces' members taking a RequestInfo: per item the
  /// immediate lookup first; the items it declines grouped by namespace and maxAge, in the order they first
  /// appear, one `find_nodes_async` per group split by `maxNodesPerRead`. One answer per item, in item order,
  /// bound to this address space; a Good answer without a Node is `Bad_InternalError`, an unknown namespace
  /// index `Bad_NodeIdUnknown`. A supplied @p requiredAddressSpace is the composed caller's optional
  /// weak-owner precondition for each unissued operation-limit chunk.
  void find_nodes_async(const RequestInfo& request, std::span<const detail::LookupItem> items,
    AddressSpace::FindNodesCompleteCallback callback,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr,
    std::optional<WeakAddressSpace> requiredAddressSpace = std::nullopt) noexcept;

  void enumerate_nodes_async(uint16_t namespaceIndex, AddressSpace::EnumerateNodesCallback callback,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  NodeAccessorResult try_find_node_sync(const NodeId& nodeId,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  NodeAccessor find_node_sync(
    const NodeId& nodeId, shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr);

  void create_node_async(const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes,
    AddressSpace::CreateNodeCompleteCallback callback,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  /// Creates @p creations for @p request (NR-17, NR-31 rule 5): grouped by the namespace of each NodeId, in
  /// the order the namespaces first appear, one `create_nodes_async` per namespace split by
  /// `maxNodesPerNodeManagement`. One answer per creation, in creation order, bound to this address space; a
  /// Good answer without a Node is `Bad_InternalError`, an unknown namespace index `Bad_NodeIdUnknown`
  /// (`NamespaceNotFound`), not sent. @p callback is called once.
  void create_nodes_async(const RequestInfo& request, shared_ptr<const std::vector<NodeCreation>> creations,
    std::function<void(std::vector<NodeAccessorResult>)> callback,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  NodeAccessorResult try_create_node_sync(const NodeId& nodeId, NodeClass nodeClass,
    InitialAttributes initialAttributes = {},
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  NodeAccessor create_node_sync(const NodeId& nodeId, NodeClass nodeClass,
    InitialAttributes initialAttributes = {},
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr);

  using DeleteNodeCompleteCallback = std::function<void(VoidResult)>;
  void delete_node_async(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
    ReferenceHalves halves, WeakAddressSpace selfHandle, DeleteNodeCompleteCallback callback,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  VoidResult try_delete_node_sync(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
    ReferenceHalves halves, WeakAddressSpace selfHandle,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr) noexcept;

  void delete_node_sync(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
    ReferenceHalves halves, WeakAddressSpace selfHandle,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr);

  void add_namespace_async(shared_ptr<Namespace> nameSpace, NamespaceMetadataOptions metadata,
    std::function<void(Result<uint16_t>)> callback) noexcept;

  detail::NamespaceRegistrationCoordinator& namespace_registration_coordinator();

  /// Sets the Role permission defaults of namespaces 0 and 1, the two this address space creates.
  ///
  /// @param rolePermissions The defaults both namespaces apply to Nodes that carry no RolePermissions.
  /// @throws UaException Bad_InvalidState when the address space was not initialised.
  void set_server_namespace_defaults(const std::vector<RolePermissionType>& rolePermissions);

  NamespaceArray& namespace_array();

  ServerArray& server_array();

  static shared_ptr<AddressSpaceImpl> create(String applicationUri, boost::asio::any_io_executor executor);

private:
  friend class detail::NamespaceRegistrationCoordinator;
  // Resolves the namespace of an accessor's operation (NR-2).
  friend class detail::NodeAccessorRoute;
  // Resolves the namespaces of a delete and reads the operation limits (NR-70 B7a).
  friend class detail::NodeDeletion;

  NamespaceArray mNamespaceArray;
  ServerArray mServerArray;
  ExecutionLimits mLimits;
  // Unset until the owner passes its limits: an address space used without a server does not split its calls.
  std::optional<ServiceOperationLimits> mOperationLimits;
  /// The changes counted by @ref model_changed.
  std::atomic<uint64_t> mModelGeneration{0};
  /// The handler @ref set_change_handler installed, which @ref raise_model_change calls.
  std::mutex mChangeHandlerMutex;
  std::function<void(const detail::AddressSpaceChange&)> mChangeHandler;

  shared_ptr<PostedSteps> mPostedSteps{std::make_shared<PostedSteps>()};
  boost::asio::any_io_executor mExecutor;
  ua::Logger mLogger;

  /// Backs @ref add_session_closed_handler and @ref notify_session_closed.
  ///
  /// Registrations are observed weakly, so a subscriber that has gone away needs no explicit
  /// unsubscribe from a destructor that may run on any thread, and an address space outliving its
  /// subscribers does not accumulate them. Callbacks run with no registry mutex held, and a
  /// throwing one is contained and logged rather than escaping into the Session teardown that
  /// published the closure.
  shared_ptr<detail::SessionResourceRegistry> mSessionResourceRegistry;

  /// Backs @ref file_handle_budget: the FileType handles open in this address space, per Session and in
  /// total, against the limits the server sets.
  shared_ptr<detail::FileHandleBudget> mFileHandleBudget;

  shared_ptr<detail::NamespaceRegistrationCoordinator> mNamespaceRegistrationCoordinator;

  /// Namespaces 0 and 1, as this address space created them; set by @ref initialise.
  std::array<shared_ptr<default_ns::Namespace>, 2> mServerNamespaces;

  AddressSpaceImpl() = default;

  void initialise(String applicationUri, boost::asio::any_io_executor executor);

  shared_ptr<Namespace> resolve_namespace(uint16_t namespaceIndex,
    const shared_ptr<const detail::NamespaceRegistrationRoute>& registrationRoute) const noexcept;
};

}  // namespace ua

#endif  // UA_ADDRESS_SPACE_IMPL_H
