// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_address_space.h"
#include "ua_address_space_impl.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_node_deletion.h"
#include "ua_address_space_change_events.h"
#include "ua_address_space_session_events.h"
#include "ua_default_namespace.h"
#include "ua_namespace_registration_coordinator.h"
#include "ua_namespace_zero.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_event_graph_check.h"
#include "ua_callback_safety.h"
#include "ua_node_utilities.h"
#include "ua_on_strand.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_session_resource_registry.h"
#include "ua_file_handle_budget.h"
#include "ua_timer.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_sync_wait.h"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <exception>
#include <future>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua
{

// ---------------------------------------------------------------------------
// AddressSpaceImpl
// ---------------------------------------------------------------------------

const ExecutionLimits& AddressSpaceImpl::limits() const
{
  return mLimits;
}

void AddressSpaceImpl::set_limits(ExecutionLimits limits)
{
  mLimits = limits;
}

void AddressSpaceImpl::set_operation_limits(ServiceOperationLimits limits)
{
  // OPC 10000-5 6.3.11: "Any operational limits Property that is provided shall have a non zero value".
  if (const auto zero = limits.first_zero_limit(); !zero.empty())
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("OperationLimitZero",
        "An operation limit that is set must be greater than zero (OPC 10000-5 6.3.11)",
        "AddressSpace")
        .context(ua::ContextKeys::fieldName, std::string{zero})};
  }
  mOperationLimits = limits;
}

boost::asio::any_io_executor AddressSpaceImpl::executor() const
{
  return mExecutor;
}

ua::Logger AddressSpaceImpl::logger() const
{
  return mLogger;
}

uint64_t AddressSpaceImpl::model_generation() const noexcept
{
  return mModelGeneration.load(std::memory_order_acquire);
}

void AddressSpaceImpl::model_changed() noexcept
{
  uint64_t generation = mModelGeneration.load(std::memory_order_relaxed);
  while (generation != UINT64_MAX &&
         !mModelGeneration.compare_exchange_weak(
           generation, generation + 1, std::memory_order_acq_rel, std::memory_order_relaxed))
  {
  }
}

std::optional<uint32_t> AddressSpaceImpl::max_nodes_per_browse() const noexcept
{
  return mOperationLimits ? mOperationLimits->maxNodesPerBrowse : std::nullopt;
}

void AddressSpaceImpl::set_logger(ua::Logger logger)
{
  mLogger = std::move(logger);
  mSessionResourceRegistry->set_logger(mLogger.with_category("session-resources"));
  if (mNamespaceRegistrationCoordinator)
  {
    mNamespaceRegistrationCoordinator->set_logger(mLogger.with_category("namespace-registration"));
  }
}

std::shared_ptr<const void> AddressSpaceImpl::add_session_closed_handler(
  std::function<void(const NodeId&)> handler)
{
  if (!handler)
    return nullptr;

  // The Registration IS the token: the subscriber owns it, the registry only observes it, and its
  // destructor unregisters. Handing it back as shared_ptr<const void> is what keeps the registry
  // type out of the interface a subscriber has to name.
  return mSessionResourceRegistry->register_cleanup(std::move(handler));
}

void AddressSpaceImpl::notify_session_closed(const NodeId& sessionId)
{
  mSessionResourceRegistry->release_session(sessionId);
}

shared_ptr<detail::FileHandleBudget> AddressSpaceImpl::file_handle_budget() const
{
  return mFileHandleBudget;
}

void AddressSpaceImpl::set_change_handler(std::function<void(const detail::AddressSpaceChange&)> handler)
{
  const std::lock_guard lock{mChangeHandlerMutex};
  mChangeHandler = std::move(handler);
}

void AddressSpaceImpl::raise_model_change(
  detail::AddressSpaceChange change, std::function<void()> done) noexcept
{
  std::function<void(const detail::AddressSpaceChange&)> handler;
  {
    const std::lock_guard lock{mChangeHandlerMutex};
    handler = mChangeHandler;
  }
  auto steps = start_posted_step();
  // The step owns itself (NR-46 rule 3): it holds neither the address space nor a namespace, and calls no
  // namespace.
  auto step = [handler = std::move(handler),
                change = std::move(change),
                done = std::move(done),
                steps,
                logger = mLogger]() mutable
  {
    if (handler)
    {
      detail::invoke_user_callback(logger, handler, change);
    }
    if (done)
    {
      detail::invoke_user_callback(logger, done);
    }
    steps->finish(logger);
  };
  // Shared so that a post that throws leaves the step to run here: one allocation per model change, beside
  // the post's own. Posting the step itself would cost none, but a throw would then take it with it.
  auto shared = std::make_shared<decltype(step)>(std::move(step));
  try
  {
    boost::asio::post(mExecutor, ua::async::guarded(mLogger, [shared] { (*shared)(); }));
  }
  catch (...)
  {
    // Nothing to run it on: it runs here, as no namespace lock is held by a step's caller.
    detail::ignore_expected_exception();
    (*shared)();
  }
}

shared_ptr<AddressSpaceImpl::PostedSteps> AddressSpaceImpl::start_posted_step() noexcept
{
  const std::lock_guard lock{mPostedSteps->mutex};
  ++mPostedSteps->outstanding;
  return mPostedSteps;
}

void AddressSpaceImpl::PostedSteps::finish(const ua::Logger& logger) noexcept
{
  // The waiters that were waiting for the last step run.
  std::vector<std::function<void()>> ready;
  {
    const std::lock_guard lock{mutex};
    if (--outstanding == 0)
    {
      ready.swap(waiters);
    }
  }
  for (auto& waiter : ready)
  {
    detail::invoke_user_callback(logger, waiter);
  }
}

void AddressSpaceImpl::when_posted_steps_done(std::function<void()> then) noexcept
{
  {
    const std::lock_guard lock{mPostedSteps->mutex};
    if (mPostedSteps->outstanding != 0)
    {
      try
      {
        mPostedSteps->waiters.push_back(std::move(then));
        return;
      }
      catch (...)
      {
        detail::ignore_expected_exception();
      }
    }
  }
  if (then)
  {
    detail::invoke_user_callback(mLogger, then);
  }
}

shared_ptr<Namespace> AddressSpaceImpl::create_namespace(string_view uri)
{
  return default_ns::Namespace::create(uri, mExecutor);
}

shared_ptr<Namespace> AddressSpaceImpl::create_namespace(string_view uri,
  std::vector<RolePermissionType> rolePermissions, std::optional<AccessRestrictionType> accessRestrictions)
{
  auto nameSpace = default_ns::Namespace::create(uri, mExecutor);
  nameSpace->set_namespace_defaults(std::move(rolePermissions), accessRestrictions);
  return nameSpace;
}

shared_ptr<Namespace> AddressSpaceImpl::resolve_namespace(uint16_t namespaceIndex,
  const shared_ptr<const detail::NamespaceRegistrationRoute>& registrationRoute) const noexcept
{
  if (registrationRoute && registrationRoute->namespaceIndex == namespaceIndex)
  {
    // An expired candidate is not a route to a later namespace at the same index.
    return registrationRoute->namespaceObject.lock();
  }
  return mNamespaceArray.get_namespace(namespaceIndex);
}

namespace
{

// The completion of a single call into a namespace, accepted once (NR-23 rule 4): a second completion, or the
// failure a throw is answered with after the namespace has completed, does not reach the caller.
template<typename Answer>
std::function<void(Answer)> accepted_once(std::function<void(Answer)> callback)
{
  return
    [answered = std::make_shared<std::atomic<bool>>(false), callback = std::move(callback)](Answer answer)
  {
    if (!answered->exchange(true, std::memory_order_acq_rel))
    {
      callback(std::move(answer));
    }
  };
}

// What a throw from a namespace's member answers (NR-23 rule 4).
StatusCode namespace_call_threw(std::exception_ptr thrown) noexcept
{
  return StatusCode{Status::BadInternalError,
    ErrorDetail::build("NamespaceCallThrew", "The namespace's member threw", "AddressSpace")
      .cause(exception_to_status_code(std::move(thrown)))};
}

}  // namespace

// The lookups without a request are the server's own calls through the route that takes a RequestInfo (NR-1
// rule 3): the same immediate form first and the same batched member, without a maxAge.
void AddressSpaceImpl::find_nodes_async(std::span<const NodeId> nodeIds,
  AddressSpace::FindNodesCompleteCallback callback,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  std::vector<detail::LookupItem> items;
  try
  {
    items.reserve(nodeIds.size());
    for (const NodeId& nodeId : nodeIds)
    {
      items.push_back(detail::LookupItem{nodeId, std::nullopt});
    }
  }
  catch (...)
  {
    BatchResult<NodeAccessorResult> failed;
    failed.batchStatus = VoidResult{exception_to_status_code(std::current_exception())};
    callback(std::move(failed));
    return;
  }
  find_nodes_async(RequestInfo{}, items, std::move(callback), std::move(registrationRoute));
}

namespace
{

using NodeLookupRoute = detail::NamespaceRoute<NodeResult>;

// The immediate lookup taking maxAge, asked first; a throw is that item's Bad_InternalError.
std::optional<NodeResult> answer_inline(
  Namespace& nameSpace, const NodeId& nodeId, std::optional<Duration> maxAge) noexcept
{
  try
  {
    return nameSpace.find_node(nodeId, maxAge);
  }
  catch (...)
  {
    return NodeResult{namespace_call_threw(std::current_exception())};
  }
}

// A namespace's answer as the accessor the address space hands out, bound to it, with the namespace's code: a
// Good subcode, or an Uncertain code with the Node it holds, reaches the caller.
NodeAccessorResult bound_answer(NodeResult answer, const NodeId& nodeId,
  const weak_ptr<AddressSpaceImpl>& addressSpace,
  const shared_ptr<const detail::NamespaceRegistrationRoute>& registrationRoute) noexcept
{
  try
  {
    if (!answer.has_value())
    {
      return NodeAccessorResult{answer.status_code()};
    }
    if (!answer.value())
    {
      if (answer.is_uncertain())
      {
        return NodeAccessorResult{answer.status_code()};
      }
      return NodeAccessorResult{StatusCode{Status::BadInternalError,
        ErrorDetail::build(
          "NamespaceAnsweredWithoutNode", "The namespace answered Good without a Node", "AddressSpace")
          .context(ua::ContextKeys::nodeId, to_string(nodeId))}};
    }
    const StatusCode answered = answer.status_code();
    return NodeAccessorResult{
      detail::NodeAccessorRoute::bound(std::move(answer).value(), addressSpace, registrationRoute), answered};
  }
  catch (...)
  {
    return NodeAccessorResult{exception_to_status_code(std::current_exception())};
  }
}

}  // namespace

// A one-item lookup builds no batch state when the namespace answers it immediately (NR-2 rule 4): the
// namespace is asked as the batched lookup asks it first, and is not held while the caller's completion runs.
// A namespace that is not registered, or that asks to be asked through its batched member, takes the batched
// lookup.
void AddressSpaceImpl::find_node_async(const NodeId& nodeId, AddressSpace::FindNodeCompleteCallback callback,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  std::optional<NodeResult> answer;
  if (const shared_ptr<Namespace> nameSpace = resolve_namespace(nodeId.namespace_index(), registrationRoute))
  {
    answer = answer_inline(*nameSpace, nodeId, std::nullopt);
  }
  if (answer)
  {
    callback(bound_answer(std::move(*answer), nodeId, weak_from_this(), registrationRoute));
    return;
  }
  const detail::LookupItem item{nodeId, std::nullopt};
  find_nodes_async(
    RequestInfo{},
    std::span<const detail::LookupItem>{&item, 1},
    [done = std::move(callback)](BatchResult<NodeAccessorResult> found)
    {
      if (found.batchStatus.is_bad())
      {
        done(NodeAccessorResult{found.batchStatus.status_code()});
        return;
      }
      done(std::move(found.items.front()));
    },
    std::move(registrationRoute));
}

void AddressSpaceImpl::find_nodes_async(const RequestInfo& request, std::span<const detail::LookupItem> items,
  AddressSpace::FindNodesCompleteCallback callback,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute,
  std::optional<WeakAddressSpace> requiredAddressSpace) noexcept
{
  const std::size_t count = items.size();
  std::vector<std::optional<NodeResult>> answers;
  std::vector<NodeLookupRoute::Part> routed;
  shared_ptr<const std::vector<detail::LookupItem>> requested;
  shared_ptr<const RequestInfo> served;
  // The NodeIds of the answers, for the ErrorDetail of a Good answer without a Node.
  std::vector<NodeId> nodeIds;
  try
  {
    if (count == 0)
    {
      callback(BatchResult<NodeAccessorResult>{});
      return;
    }
    answers.resize(count);
    nodeIds.reserve(count);
    for (const auto& item : items)
    {
      nodeIds.push_back(item.nodeId);
    }
    // The namespace of each index, resolved once; and per index the routed parts, one per maxAge.
    std::unordered_map<uint16_t, shared_ptr<Namespace>> namespaces;
    std::unordered_map<uint16_t, std::vector<std::size_t>> partsOfNamespace;
    for (std::size_t i = 0; i < count; ++i)
    {
      const detail::LookupItem& item = items[i];
      const auto namespaceIndex = item.nodeId.namespace_index();
      auto [known, added] = namespaces.try_emplace(namespaceIndex);
      if (added)
      {
        known->second = resolve_namespace(namespaceIndex, registrationRoute);
      }
      if (!known->second)
      {
        answers[i] = NodeResult{StatusCode{Status::BadNodeIdUnknown,
          ErrorDetail::build("NamespaceNotFound", "Namespace index does not exist", "AddressSpace")
            .context(ua::ContextKeys::namespaceIndex, std::to_string(namespaceIndex))}};
        continue;
      }
      // The immediate form, asked per item before anything is dispatched, as the lookup without a request
      // does.
      if (auto answer = answer_inline(*known->second, item.nodeId, item.maxAge))
      {
        answers[i] = std::move(answer);
        continue;
      }
      auto& parts = partsOfNamespace[namespaceIndex];
      const auto part = std::find_if(parts.begin(),
        parts.end(),
        [&](std::size_t partIndex)
        { return items[routed[partIndex].positions.front()].maxAge == item.maxAge; });
      if (part != parts.end())
      {
        routed[*part].positions.push_back(i);
        continue;
      }
      parts.push_back(routed.size());
      routed.push_back(NodeLookupRoute::Part{known->second, {i}});
    }
    // Copied when a part is routed: a namespace may complete after this call has returned, and the inputs are
    // valid only until then.
    if (!routed.empty())
    {
      requested = std::make_shared<const std::vector<detail::LookupItem>>(items.begin(), items.end());
      served = std::make_shared<const RequestInfo>(request);
    }
  }
  catch (...)
  {
    BatchResult<NodeAccessorResult> failed;
    failed.batchStatus = VoidResult{exception_to_status_code(std::current_exception())};
    callback(std::move(failed));
    return;
  }

  NodeLookupRoute::run(
    std::move(answers),
    std::move(routed),
    mOperationLimits ? mOperationLimits->maxNodesPerRead : std::nullopt,
    [requested, served](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<NodeResult>)>
        answer)
    {
      std::vector<NodeId> asked;
      asked.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        asked.push_back((*requested)[position].nodeId);
      }
      // Every item of a part has the same maxAge.
      nameSpace.find_nodes_async(*served, asked, (*requested)[positions.front()].maxAge, std::move(answer));
    },
    [done = std::move(callback),
      nodeIds = std::move(nodeIds),
      addressSpace = weak_from_this(),
      registrationRoute](std::vector<NodeResult> found)
    {
      BatchResult<NodeAccessorResult> result;
      result.items.reserve(found.size());
      for (std::size_t i = 0; i < found.size(); ++i)
      {
        result.items.push_back(
          bound_answer(std::move(found[i]), nodeIds[i], addressSpace, registrationRoute));
      }
      done(std::move(result));
    },
    std::move(requiredAddressSpace));
}

void AddressSpaceImpl::enumerate_nodes_async(uint16_t namespaceIndex,
  AddressSpace::EnumerateNodesCallback callback,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  auto ns = resolve_namespace(namespaceIndex, registrationRoute);
  if (!ns)
  {
    callback(Result<std::vector<NodeId>>{Status::BadNodeIdUnknown,
      ErrorDetail::build("NamespaceNotFound", "Namespace index does not exist", "AddressSpace")
        .context(ua::ContextKeys::namespaceIndex, std::to_string(namespaceIndex))});
    return;
  }
  auto complete = accepted_once(std::move(callback));
  try
  {
    ns->enumerate_nodes_async(RequestInfo{}, complete);
  }
  catch (...)
  {
    complete(Result<std::vector<NodeId>>{namespace_call_threw(std::current_exception())});
  }
}

NodeAccessorResult AddressSpaceImpl::try_find_node_sync(
  const NodeId& nodeId, shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  try
  {
    // Refused rather than entered: a thread of this executor may be the thread that would run the
    // answer being waited for. Use the *_async overload from inside a handler or callback.
    return ua::async::detail::blocking_call<NodeAccessorResult>(mExecutor,
      [&](std::function<void(NodeAccessorResult)> complete)
      { find_node_async(nodeId, std::move(complete), std::move(registrationRoute)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

NodeAccessor AddressSpaceImpl::find_node_sync(
  const NodeId& nodeId, shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute)
{
  return ua::detail::good_value(try_find_node_sync(nodeId, std::move(registrationRoute)));
}

NamespaceArray& AddressSpaceImpl::namespace_array()
{
  return mNamespaceArray;
}

void AddressSpaceImpl::set_server_namespace_defaults(const std::vector<RolePermissionType>& rolePermissions)
{
  for (const auto& serverNamespace : mServerNamespaces)
  {
    if (!serverNamespace)
    {
      throw UaException{Status::BadInvalidState,
        ErrorDetail::build("ServerNamespaceNotConfigurable",
          "The address space has not created namespaces 0 and 1",
          "AddressSpace")};
    }
    serverNamespace->set_namespace_defaults(rolePermissions, std::nullopt);
  }
}

detail::NamespaceRegistrationCoordinator& AddressSpaceImpl::namespace_registration_coordinator()
{
  return *mNamespaceRegistrationCoordinator;
}

void AddressSpaceImpl::add_namespace_async(shared_ptr<Namespace> nameSpace, NamespaceMetadataOptions metadata,
  std::function<void(Result<uint16_t>)> callback) noexcept
{
  mNamespaceRegistrationCoordinator->add_namespace_async(
    std::move(nameSpace), std::move(metadata), std::move(callback));
}

ServerArray& AddressSpaceImpl::server_array()
{
  return mServerArray;
}

void AddressSpaceImpl::initialise(String applicationUri, boost::asio::any_io_executor executor)
{
  mExecutor = executor;
  mNamespaceRegistrationCoordinator =
    detail::NamespaceRegistrationCoordinator::create(weak_from_this(), executor);
  mServerNamespaces = {
    default_ns::NamespaceZero::create(executor), default_ns::Namespace::create(applicationUri, mExecutor)};
  for (const auto& serverNamespace : mServerNamespaces)
  {
    mNamespaceRegistrationCoordinator->bootstrap_namespace(serverNamespace);
  }
  mServerArray.add_server_uri(applicationUri);
}

void AddressSpaceImpl::create_node_async(const NodeId& nodeId, NodeClass nodeClass,
  InitialAttributes initialAttributes, AddressSpace::CreateNodeCompleteCallback callback,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  // One NodeCreation of create_nodes_async (NR-31 rule 3).
  shared_ptr<const std::vector<NodeCreation>> creation;
  try
  {
    creation = std::make_shared<const std::vector<NodeCreation>>(
      std::vector<NodeCreation>{NodeCreation{nodeId, nodeClass, std::move(initialAttributes)}});
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(
      callback, NodeAccessorResult{exception_to_status_code(std::current_exception())});
    return;
  }
  auto complete = std::make_shared<AddressSpace::CreateNodeCompleteCallback>(std::move(callback));
  create_nodes_async(
    RequestInfo{},
    std::move(creation),
    [complete](std::vector<NodeAccessorResult> created)
    {
      ua::detail::invoke_user_callback(*complete,
        created.empty() ? NodeAccessorResult{StatusCode{Status::BadInternalError}}
                        : std::move(created.front()));
    },
    std::move(registrationRoute));
}

void AddressSpaceImpl::create_nodes_async(const RequestInfo& request,
  shared_ptr<const std::vector<NodeCreation>> creations,
  std::function<void(std::vector<NodeAccessorResult>)> callback,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  using CreateRoute = detail::NamespaceRoute<NodeResult>;
  shared_ptr<std::function<void(std::vector<NodeAccessorResult>)>> complete;
  std::vector<std::optional<NodeResult>> answers;
  std::vector<CreateRoute::Part> parts;
  shared_ptr<const RequestInfo> heldRequest;
  try
  {
    complete = std::make_shared<std::function<void(std::vector<NodeAccessorResult>)>>(std::move(callback));
    heldRequest = std::make_shared<const RequestInfo>(request);
    const std::size_t count = creations ? creations->size() : 0;
    answers.resize(count);
    // The part of each namespace, in the order the namespaces first appear.
    std::unordered_map<const Namespace*, std::size_t> partOf;
    for (std::size_t i = 0; i < count; ++i)
    {
      const NodeId& nodeId = (*creations)[i].nodeId;
      auto ns = resolve_namespace(nodeId.namespace_index(), registrationRoute);
      if (!ns)
      {
        answers[i] = NodeResult{StatusCode{Status::BadNodeIdUnknown,
          ErrorDetail::build("NamespaceNotFound", "Namespace index does not exist", "AddressSpace")
            .context(ua::ContextKeys::namespaceIndex, std::to_string(nodeId.namespace_index()))}};
        continue;
      }
      const auto [entry, added] = partOf.try_emplace(ns.get(), parts.size());
      if (added)
      {
        parts.push_back(CreateRoute::Part{std::move(ns), {}});
      }
      parts[entry->second].positions.push_back(i);
    }
  }
  catch (...)
  {
    const StatusCode failed = exception_to_status_code(std::current_exception());
    std::vector<NodeAccessorResult> all;
    try
    {
      all.assign(creations ? creations->size() : 0, NodeAccessorResult{failed});
    }
    catch (...)
    {
      all.clear();
    }
    ua::detail::invoke_user_callback(complete ? *complete : callback, std::move(all));
    return;
  }
  CreateRoute::run(
    std::move(answers),
    std::move(parts),
    mOperationLimits ? mOperationLimits->maxNodesPerNodeManagement : std::nullopt,
    [creations, heldRequest](Namespace& nameSpace,
      std::span<const std::size_t>
        positions,
      std::function<void(BatchResult<NodeResult>)>
        answer)
    {
      // A namespace's chunk is consecutive creations when it is the only namespace: sent without copying.
      if (positions.back() - positions.front() + 1 == positions.size())
      {
        nameSpace.create_nodes_async(*heldRequest,
          std::span<const NodeCreation>{creations->data() + positions.front(), positions.size()},
          std::move(answer));
        return;
      }
      std::vector<NodeCreation> items;
      items.reserve(positions.size());
      for (const std::size_t position : positions)
      {
        items.push_back((*creations)[position]);
      }
      nameSpace.create_nodes_async(*heldRequest, items, std::move(answer));
    },
    [complete, creations, addressSpace = weak_from_this(), registrationRoute](std::vector<NodeResult> created)
    {
      if (const auto owner = addressSpace.lock())
      {
        owner->model_changed_if_any(created);
      }
      std::vector<NodeAccessorResult> results;
      try
      {
        results.reserve(created.size());
        for (std::size_t i = 0; i < created.size(); ++i)
        {
          results.push_back(
            bound_answer(std::move(created[i]), (*creations)[i].nodeId, addressSpace, registrationRoute));
        }
      }
      catch (...)
      {
        results.assign(
          created.size(), NodeAccessorResult{exception_to_status_code(std::current_exception())});
      }
      ua::detail::invoke_user_callback(*complete, std::move(results));
    });
}

NodeAccessorResult AddressSpaceImpl::try_create_node_sync(const NodeId& nodeId, NodeClass nodeClass,
  InitialAttributes initialAttributes,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  try
  {
    // Refused rather than entered: a thread of this executor may be the thread that would run the
    // answer being waited for. Use the *_async overload from inside a handler or callback.
    return ua::async::detail::blocking_call<NodeAccessorResult>(mExecutor,
      [&](std::function<void(NodeAccessorResult)> complete)
      {
        create_node_async(
          nodeId, nodeClass, std::move(initialAttributes), std::move(complete), std::move(registrationRoute));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

NodeAccessor AddressSpaceImpl::create_node_sync(const NodeId& nodeId, NodeClass nodeClass,
  InitialAttributes initialAttributes, shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute)
{
  return ua::detail::good_value(
    try_create_node_sync(nodeId, nodeClass, std::move(initialAttributes), std::move(registrationRoute)));
}

void AddressSpaceImpl::delete_node_async(const NodeId& nodeId,
  bool deleteForwardHierarchicallyReferencedNodes, ReferenceHalves halves, WeakAddressSpace selfHandle,
  DeleteNodeCompleteCallback callback,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  // With Both, every namespace removes the References that target the deleted Nodes (NR-17 rule 3); with
  // ThisHalfOnly they are left unresolved (OPC 10000-4 5.7.4.1).
  auto self = weak_from_this().lock();
  if (!self)
  {
    ua::detail::invoke_user_callback(callback, VoidResult{detail::address_space_gone("delete_node_async")});
    return;
  }
  detail::NodeDeletion::run(self,
    std::move(selfHandle),
    nodeId,
    deleteForwardHierarchicallyReferencedNodes,
    halves,
    std::move(registrationRoute),
    std::move(callback));
}

VoidResult AddressSpaceImpl::try_delete_node_sync(const NodeId& nodeId,
  bool deleteForwardHierarchicallyReferencedNodes, ReferenceHalves halves, WeakAddressSpace selfHandle,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute) noexcept
{
  try
  {
    // Refused rather than entered: a thread of this executor may be the thread that would run the
    // answer being waited for. Use the *_async overload from inside a handler or callback.
    return ua::async::detail::blocking_call<VoidResult>(mExecutor,
      [&](std::function<void(VoidResult)> complete)
      {
        auto callback = std::move(complete);

        delete_node_async(nodeId,
          deleteForwardHierarchicallyReferencedNodes,
          halves,
          std::move(selfHandle),
          std::move(callback),
          std::move(registrationRoute));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void AddressSpaceImpl::delete_node_sync(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
  ReferenceHalves halves, WeakAddressSpace selfHandle,
  shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute)
{
  try_delete_node_sync(nodeId,
    deleteForwardHierarchicallyReferencedNodes,
    halves,
    std::move(selfHandle),
    std::move(registrationRoute))
    .value();
}

shared_ptr<AddressSpaceImpl> AddressSpaceImpl::create(
  String applicationUri, boost::asio::any_io_executor executor)
{
  class Wrapper : public AddressSpaceImpl
  {};

  auto impl = make_shared<Wrapper>();
  impl->mSessionResourceRegistry = make_shared<detail::SessionResourceRegistry>();
  impl->mFileHandleBudget = make_shared<detail::FileHandleBudget>();
  impl->initialise(std::move(applicationUri), std::move(executor));
  return impl;
}

// ---------------------------------------------------------------------------
// AddressSpace (handle)
// ---------------------------------------------------------------------------

AddressSpace::AddressSpace(
  shared_ptr<AddressSpaceImpl> impl, shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute)
  : mImpl(std::move(impl)), mRegistrationRoute(std::move(registrationRoute))
{}

AddressSpace AddressSpace::create(String applicationUri, boost::asio::any_io_executor executor)
{
  return AddressSpace{AddressSpaceImpl::create(std::move(applicationUri), std::move(executor))};
}

const ExecutionLimits& AddressSpace::limits() const
{
  return mImpl->limits();
}

void AddressSpace::set_limits(ExecutionLimits limits)
{
  mImpl->set_limits(limits);
}

void AddressSpace::set_operation_limits(ServiceOperationLimits limits)
{
  mImpl->set_operation_limits(limits);
}

boost::asio::any_io_executor AddressSpace::executor() const
{
  return mImpl->executor();
}

ua::Logger AddressSpace::logger() const
{
  return mImpl->logger();
}

void AddressSpace::validate_event_graph_async(std::function<void(VoidResult)> complete) const noexcept
{
  detail::check_event_graph(*this, mImpl->max_nodes_per_browse(), std::move(complete));
}

VoidResult AddressSpace::try_validate_event_graph_sync() const noexcept
{
  try
  {
    // Refused rather than entered on a thread of this executor, which may be the thread the answer needs.
    return ua::async::detail::blocking_call<VoidResult>(mImpl->executor(),
      [this](std::function<void(VoidResult)> complete) { validate_event_graph_async(std::move(complete)); });
  }
  catch (...)
  {
    return VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

void AddressSpace::validate_event_graph_sync() const
{
  try_validate_event_graph_sync().value();
}

uint64_t AddressSpace::model_generation() const noexcept
{
  return mImpl->model_generation();
}

void AddressSpace::set_logger(ua::Logger logger)
{
  mImpl->set_logger(std::move(logger));
}

std::shared_ptr<const void> detail::AddressSpaceSessionEvents::add_handler(
  AddressSpace& addressSpace, std::function<void(const NodeId&)> handler)
{
  return addressSpace.mImpl->add_session_closed_handler(std::move(handler));
}

void detail::AddressSpaceSessionEvents::notify_closed(AddressSpace& addressSpace, const NodeId& sessionId)
{
  addressSpace.mImpl->notify_session_closed(sessionId);
}

void detail::AddressSpaceChangeEvents::set_handler(AddressSpace& addressSpace, Handler handler)
{
  addressSpace.mImpl->set_change_handler(std::move(handler));
}

shared_ptr<Namespace> AddressSpace::create_namespace(string_view uri,
  std::vector<RolePermissionType> rolePermissions, std::optional<AccessRestrictionType> accessRestrictions)
{
  return mImpl->create_namespace(uri, std::move(rolePermissions), accessRestrictions);
}

void AddressSpace::add_namespace_async(
  shared_ptr<Namespace> namespaceToAdd, AddNamespaceCallback callback) noexcept
{
  mImpl->add_namespace_async(std::move(namespaceToAdd), NamespaceMetadataOptions{}, std::move(callback));
}

void AddressSpace::add_namespace_async(shared_ptr<Namespace> namespaceToAdd,
  NamespaceMetadataOptions metadata, AddNamespaceCallback callback) noexcept
{
  mImpl->add_namespace_async(std::move(namespaceToAdd), std::move(metadata), std::move(callback));
}

Result<uint16_t> AddressSpace::try_add_namespace_sync(
  shared_ptr<Namespace> namespaceToAdd, NamespaceMetadataOptions metadata) noexcept
{
  try
  {
    const auto targetExecutor = executor();

    return ua::async::detail::blocking_call<Result<uint16_t>>(targetExecutor,
      [&](std::function<void(Result<uint16_t>)> complete)
      { add_namespace_async(std::move(namespaceToAdd), std::move(metadata), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

uint16_t AddressSpace::add_namespace_sync(
  shared_ptr<Namespace> namespaceToAdd, NamespaceMetadataOptions metadata)
{
  return ua::detail::good_value(try_add_namespace_sync(std::move(namespaceToAdd), std::move(metadata)));
}

void AddressSpace::find_node_async(
  const NodeId& nodeId, AddressSpace::FindNodeCompleteCallback callback) noexcept
{
  mImpl->find_node_async(nodeId, std::move(callback), mRegistrationRoute);
}

void AddressSpace::find_nodes_async(
  std::span<const NodeId> nodeIds, AddressSpace::FindNodesCompleteCallback callback) noexcept
{
  mImpl->find_nodes_async(nodeIds, std::move(callback), mRegistrationRoute);
}

void AddressSpace::enumerate_nodes_async(
  uint16_t namespaceIndex, AddressSpace::EnumerateNodesCallback callback) noexcept
{
  mImpl->enumerate_nodes_async(namespaceIndex, std::move(callback), mRegistrationRoute);
}

NodeAccessorResult AddressSpace::try_find_node_sync(const NodeId& nodeId) noexcept
{
  return mImpl->try_find_node_sync(nodeId, mRegistrationRoute);
}

NodeAccessor AddressSpace::find_node_sync(const NodeId& nodeId)
{
  return mImpl->find_node_sync(nodeId, mRegistrationRoute);
}

void AddressSpace::create_node_async(const NodeId& nodeId, NodeClass nodeClass,
  InitialAttributes initialAttributes, AddressSpace::CreateNodeCompleteCallback callback) noexcept
{
  mImpl->create_node_async(
    nodeId, nodeClass, std::move(initialAttributes), std::move(callback), mRegistrationRoute);
}

void AddressSpace::create_node_async(
  const NodeId& nodeId, NodeClass nodeClass, AddressSpace::CreateNodeCompleteCallback callback) noexcept
{
  create_node_async(nodeId, nodeClass, {}, std::move(callback));
}

NodeAccessorResult AddressSpace::try_create_node_sync(
  const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes) noexcept
{
  return mImpl->try_create_node_sync(nodeId, nodeClass, std::move(initialAttributes), mRegistrationRoute);
}

NodeAccessor AddressSpace::create_node_sync(
  const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes)
{
  return mImpl->create_node_sync(nodeId, nodeClass, std::move(initialAttributes), mRegistrationRoute);
}

void AddressSpace::delete_node_async(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
  ReferenceHalves halves, DeleteNodeCompleteCallback callback) noexcept
{
  mImpl->delete_node_async(nodeId,
    deleteForwardHierarchicallyReferencedNodes,
    halves,
    weak(),
    std::move(callback),
    mRegistrationRoute);
}

VoidResult AddressSpace::try_delete_node_sync(
  const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes, ReferenceHalves halves) noexcept
{
  return mImpl->try_delete_node_sync(
    nodeId, deleteForwardHierarchicallyReferencedNodes, halves, weak(), mRegistrationRoute);
}

void AddressSpace::delete_node_sync(
  const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes, ReferenceHalves halves)
{
  mImpl->delete_node_sync(
    nodeId, deleteForwardHierarchicallyReferencedNodes, halves, weak(), mRegistrationRoute);
}

void AddressSpace::shutdown_async(std::function<void(VoidResult)> callback) noexcept
{
  mImpl->namespace_registration_coordinator().shutdown_async(std::move(callback));
}

const NamespaceArray& AddressSpace::namespace_array() const
{
  return mImpl->namespace_array();
}

ServerArray& AddressSpace::server_array()
{
  return mImpl->server_array();
}

const ServerArray& AddressSpace::server_array() const
{
  return mImpl->server_array();
}

CodecNamespaceContext AddressSpace::codec_namespace_context() const
{
  return CodecNamespaceContext{namespace_array_utils::get_index_lookup_function(weak())};
}

WeakAddressSpace AddressSpace::weak() const
{
  return WeakAddressSpace{*this};
}

// ---------------------------------------------------------------------------
// WeakAddressSpace
// ---------------------------------------------------------------------------

WeakAddressSpace::WeakAddressSpace(const AddressSpace& addressSpace)
  : mImpl(addressSpace.mImpl), mRegistrationRoute(addressSpace.mRegistrationRoute)
{}

WeakAddressSpace::WeakAddressSpace(
  weak_ptr<AddressSpaceImpl> impl, shared_ptr<const detail::NamespaceRegistrationRoute> route)
  : mImpl(std::move(impl)), mRegistrationRoute(std::move(route))
{}

optional<AddressSpace> WeakAddressSpace::lock() const
{
  auto impl = mImpl.lock();
  if (!impl)
    return std::nullopt;
  return AddressSpace{std::move(impl), mRegistrationRoute};
}

}  // namespace ua
