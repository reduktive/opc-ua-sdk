// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sampling_interval_diagnostics_node_manager.h"
#include "ua_whole_value_source.h"

#include "ua_callback_safety.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_expanded_node_id.h"
#include "ua_instance_utils.h"
#include "ua_instantiation_options.h"
#include "ua_instantiation_service.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_namespace_items.h"
#include "ua_namespace_route.h"
#include "ua_node_class.h"
#include "ua_node_subtree.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_self_owning_operation.h"
#include "ua_string.h"
#include "ua_subscription.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include "fmt/format.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <array>
#include <optional>
#include <set>
#include <string>

namespace ua::server
{

std::vector<SamplingIntervalDiagnosticsDataType> aggregate_sampling_interval_diagnostics(
  const std::vector<SubscriptionDiagnosticsEntry>& subscriptions)
{
  std::vector<SamplingIntervalDiagnosticsDataType> aggregates;
  for (const auto& entry : subscriptions)
  {
    if (!entry.info)
      continue;
    for (const auto& si : entry.info->samplingIntervals)
    {
      auto it = std::find_if(aggregates.begin(),
        aggregates.end(),
        [&si](const SamplingIntervalDiagnosticsDataType& a)
        { return a.sampling_interval() == si.samplingInterval; });
      if (it == aggregates.end())
      {
        SamplingIntervalDiagnosticsDataType d;
        d.sampling_interval() = si.samplingInterval;
        aggregates.push_back(std::move(d));
        it = std::prev(aggregates.end());
      }
      it->monitored_item_count() += si.monitoredItemCount;
      it->disabled_monitored_item_count() += si.disabledMonitoredItemCount;
    }
  }
  // No per-interval high-water mark is kept across the life of the server; the maximum reported is the
  // current count.
  for (auto& d : aggregates)
    d.max_monitored_item_count() = d.monitored_item_count();
  return aggregates;
}

namespace
{

using Extract = Variant (*)(const SamplingIntervalDiagnosticsDataType&);

/// The components of SamplingIntervalDiagnosticsType, each wired to read its field live.
struct FieldEntry
{
  const char* browseName;
  Extract extract;
};

constexpr std::array<FieldEntry, 4> fieldTable{{
  {"SamplingInterval",
    [](const SamplingIntervalDiagnosticsDataType& d)
    {
      return Variant{d.sampling_interval()};
    }},
  {"SampledMonitoredItemsCount",
    [](const SamplingIntervalDiagnosticsDataType& d)
    {
      return Variant{d.monitored_item_count()};
    }},
  {"MaxSampledMonitoredItemsCount",
    [](const SamplingIntervalDiagnosticsDataType& d)
    {
      return Variant{d.max_monitored_item_count()};
    }},
  {"DisabledMonitoredItemsSamplingCount",
    [](const SamplingIntervalDiagnosticsDataType& d)
    {
      return Variant{d.disabled_monitored_item_count()};
    }},
}};

/// The node's BrowseName: the interval in milliseconds, as a number a client can parse back.
std::string interval_browse_name(Duration interval)
{
  return fmt::format("{}", interval);
}

/// Answers the node for @p interval from the live MonitoredItems: the whole record when @p extract is
/// null, one field otherwise; Bad_NoData once no MonitoredItem uses the interval any more.
detail::WholeValueRead make_handler(
  SubscriptionDiagnosticsProvider provider, Duration interval, Extract extract)
{
  return [provider = std::move(provider), interval, extract](
           const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    DataValue dv;
    for (auto& d : aggregate_sampling_interval_diagnostics(
           provider ? provider() : std::vector<SubscriptionDiagnosticsEntry>{}))
    {
      if (d.sampling_interval() != interval)
        continue;
      dv.source_timestamp() = DateTime::now();
      dv.value() = extract ? extract(d) : Variant{std::move(d)};
      complete(std::move(dv));
      return;
    }
    dv.status() = StatusCode{Status::BadNoData};
    complete(std::move(dv));
  };
}

}  // namespace

/// One reconciliation: removes the nodes of intervals no MonitoredItem uses any more and builds one for
/// each interval that has none. A node is instantiated under the hidden staging holder, has its read
/// handlers wired, and only then is linked into the array, so a client never finds it half built.
///
/// Holds the manager strongly for its duration: at most one runs at a time, it is short, and the
/// manager's node map is the state it works on. The manager holds the address space weakly, and each step
/// locks it for its own call only: a step that finds it gone is answered AddressSpaceGone. It always ends by
/// handing the manager back the completions it was started for, whatever became of the nodes.
class SamplingIntervalDiagnosticsNodeManager::ReconcileOperation final
  : public ua::async::SelfOwningOperation<ReconcileOperation>
{
public:
  static void start(std::shared_ptr<SamplingIntervalDiagnosticsNodeManager> manager,
    std::vector<std::function<void()>> completions)
  {
    launch(std::make_shared<ReconcileOperation>(std::move(manager), std::move(completions)));
  }

  ReconcileOperation(std::shared_ptr<SamplingIntervalDiagnosticsNodeManager> manager,
    std::vector<std::function<void()>> completions)
    : SelfOwningOperation(boost::asio::make_strand(manager->mExecutor), manager->mLogger),
      mManager(std::move(manager)), mCompletions(std::move(completions))
  {}

private:
  friend class ua::async::SelfOwningOperation<ReconcileOperation>;

  /// The address space, locked for one step's call; nullopt, with @p completion answered AddressSpaceGone,
  /// when it is gone.
  template<typename Answer, typename Completion>
  std::optional<AddressSpace> owner_or_gone(Completion& completion)
  {
    auto owner = mManager->mAddressSpace.lock();
    if (!owner)
      completion(Answer{::ua::detail::address_space_gone("SamplingIntervalDiagnostics")});
    return owner;
  }

  /// Links @p root into the array: HasComponent, both halves in one call (NR-30).
  auto link_into_array(NodeId root)
  {
    return await_step<std::vector<VoidResult>>(
      [this, root = std::move(root)](auto completion)
      {
        const auto pair =
          ReferenceChange::both_halves(mManager->mArrayNodeId, NodeId{ReferenceTypeId::HasComponent}, root);
        ::ua::detail::NodeAccessorRoute::add_references(mManager->mAddressSpace,
          RequestInfo{},
          std::make_shared<const std::vector<ReferenceChange>>(pair.begin(), pair.end()),
          std::move(completion));
      });
  }

  auto attach_whole_value_source(NodeId nodeId, detail::WholeValueRead handler)
  {
    return await_step<VoidResult>(
      [this, nodeId = std::move(nodeId), handler = std::move(handler)](auto completion) mutable
      {
        if (auto owner = owner_or_gone<VoidResult>(completion))
          instance_utils::resolve_and_set_value_source_async(
            std::move(*owner), nodeId, detail::whole_value_source(std::move(handler)), std::move(completion));
      });
  }

  ua::async::Task<> run()
  {
    try
    {
      auto& manager = *mManager;
      const auto inUse = manager.mRouter.sampling_intervals_in_use();
      const bool enabled = !manager.mEnabled || manager.mEnabled->load(std::memory_order_acquire);
      mTarget = Target{enabled, inUse.generation};
      bool failed = false;
      std::set<Duration> wanted;
      if (enabled)
        wanted.insert(inUse.intervals.begin(), inUse.intervals.end());

      for (auto it = manager.mNodes.begin(); it != manager.mNodes.end();)
      {
        if (wanted.count(it->first) != 0)
        {
          ++it;
          continue;
        }
        // A cascade delete of the node and its components, awaited so the node is gone by the time the
        // service that asked for this reconciliation answers.
        const NodeId root = it->second;
        it = manager.mNodes.erase(it);
        (void)co_await await_step<VoidResult>(
          [this, root](auto completion)
          {
            if (auto owner = owner_or_gone<VoidResult>(completion))
              owner->delete_node_async(root,
                /*deleteForwardHierarchicallyReferencedNodes=*/true,
                ReferenceHalves::Both,
                std::move(completion));
          });
      }

      for (const Duration interval : wanted)
      {
        if (manager.mNodes.count(interval) != 0)
          continue;
        if (auto root = co_await build(interval))
          manager.mNodes.emplace(interval, *root);
        else
          failed = true;
      }
      // A node that could not be built leaves the nodes short of the target: the next request retries.
      if (failed)
        mTarget.reset();
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
      mTarget.reset();
    }
    catch (...)
    {
      ua::async::guarded(mLogger, [] { throw; })();
      mTarget.reset();
    }
    finish();
  }

  void fail_to_start(StatusCode)
  {
    finish();
  }

  /// @return The node's root, or nullopt when it could not be created.
  ua::async::Task<std::optional<NodeId>> build(Duration interval)
  {
    auto& manager = *mManager;
    InstantiationOptions options;
    options.nodeIdAllocator = guid_node_id_allocator();
    auto result = co_await await_step<NodeSubtreeResult>(
      [this, &manager, &options, interval](auto completion)
      {
        auto owner = owner_or_gone<NodeSubtreeResult>(completion);
        if (!owner)
          return;
        InstantiationService service{*owner};
        service.instantiate_variable_async(manager.mStagingNodeId,
          QualifiedName{0, interval_browse_name(interval)},
          NodeId{VariableTypeId::SamplingIntervalDiagnosticsType},
          options,
          VariableInstantiationAttributes{},
          std::move(completion));
      });
    if (!result.is_good())
      co_return std::nullopt;

    // Released before any suspension: NodeSubtree's destructor deletes synchronously, which must not
    // run on a strand. The node is removed explicitly when its interval goes.
    auto subtree = std::move(result).value();
    subtree.release();
    const NodeId root = subtree.root();

    co_await attach_whole_value_source(root, make_handler(manager.mProvider, interval, nullptr));
    for (const auto& field : fieldTable)
    {
      auto child = co_await await_step<NodeIdResult>(
        [this, &root, &field](auto completion)
        {
          auto owner = owner_or_gone<NodeIdResult>(completion);
          if (!owner)
            return;
          instance_utils::find_child_id_by_browse_name_async(std::move(*owner),
            root,
            NodeId{ReferenceTypeId::HasComponent},
            QualifiedName{0, field.browseName},
            std::move(completion));
        });
      if (child.is_good())
        co_await attach_whole_value_source(
          child.value(), make_handler(manager.mProvider, interval, field.extract));
    }

    // Array --HasComponent--> node makes it browseable; the inverse lets the cascade delete of the node
    // remove the array's edge with it. A refused half leaves the node built but not listed, as a missing
    // array did before.
    (void)co_await link_into_array(root);
    co_return root;
  }

  void finish()
  {
    if (auto manager = std::move(mManager))
      manager->finish_run(std::move(mCompletions), mTarget);
  }

  std::shared_ptr<SamplingIntervalDiagnosticsNodeManager> mManager;
  std::vector<std::function<void()>> mCompletions;
  std::optional<Target> mTarget;  // set once the run has read what it reconciles to
};

std::shared_ptr<SamplingIntervalDiagnosticsNodeManager> SamplingIntervalDiagnosticsNodeManager::create(
  AddressSpace addressSpace, NodeId arrayNodeId, SubscriptionDiagnosticsProvider provider,
  const SubscriptionRouter& router, std::shared_ptr<const std::atomic<bool>> enabled)
{
  // Created once during server startup, off any strand, so a synchronous create is safe here.
  NodeId stagingNodeId{uint16_t{1}, String{"__SamplingIntervalDiagnosticsStaging"}};
  (void)addressSpace.try_create_node_sync(stagingNodeId,
    NodeClass::Object,
    InitialAttributes{
      {AttributeId::BrowseName, Variant{QualifiedName{1, "__SamplingIntervalDiagnosticsStaging"}}}});
  return std::shared_ptr<SamplingIntervalDiagnosticsNodeManager>(
    new SamplingIntervalDiagnosticsNodeManager(std::move(addressSpace),
      std::move(arrayNodeId),
      std::move(stagingNodeId),
      std::move(provider),
      router,
      std::move(enabled)));
}

SamplingIntervalDiagnosticsNodeManager::SamplingIntervalDiagnosticsNodeManager(AddressSpace addressSpace,
  NodeId arrayNodeId, NodeId stagingNodeId, SubscriptionDiagnosticsProvider provider,
  const SubscriptionRouter& router, std::shared_ptr<const std::atomic<bool>> enabled)
  : mAddressSpace(addressSpace.weak()), mExecutor(addressSpace.executor()), mLogger(addressSpace.logger()),
    mArrayNodeId(std::move(arrayNodeId)), mStagingNodeId(std::move(stagingNodeId)),
    mProvider(std::move(provider)), mRouter(router), mEnabled(std::move(enabled))
{}

SamplingIntervalDiagnosticsNodeManager::Target SamplingIntervalDiagnosticsNodeManager::current_target() const
{
  return Target{
    !mEnabled || mEnabled->load(std::memory_order_acquire), mRouter.sampling_intervals_in_use().generation};
}

void SamplingIntervalDiagnosticsNodeManager::reconcile_async(std::function<void()> completion)
{
  // Most MonitoredItem changes leave the set of intervals as it was - another item at an interval already
  // in use - and then the nodes are already right: answer at once, with no run and no address-space work.
  const auto target = current_target();
  {
    const std::lock_guard lock(mMutex);
    if (mRunning || !mWaiting.empty() || mReconciled != target)
    {
      mWaiting.push_back(std::move(completion));
      completion = nullptr;
    }
  }
  if (completion)
  {
    completion();
    return;
  }
  start_next_run();
}

void SamplingIntervalDiagnosticsNodeManager::start_next_run()
{
  std::vector<std::function<void()>> completions;
  {
    const std::lock_guard lock(mMutex);
    if (mRunning || mWaiting.empty())
      return;
    mRunning = true;
    completions.swap(mWaiting);
  }
  try
  {
    ReconcileOperation::start(shared_from_this(), completions);
  }
  catch (...)
  {
    // The operation could not even be allocated: release its callers rather than leave them waiting.
    finish_run(std::move(completions), std::nullopt);
  }
}

void SamplingIntervalDiagnosticsNodeManager::finish_run(
  std::vector<std::function<void()>> completions, std::optional<Target> reconciled)
{
  {
    const std::lock_guard lock(mMutex);
    mRunning = false;
    mReconciled = reconciled;
  }
  for (const auto& completion : completions)
  {
    if (completion)
      completion();
  }
  start_next_run();
}

}  // namespace ua::server
