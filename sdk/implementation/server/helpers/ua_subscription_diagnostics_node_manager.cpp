// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_subscription_diagnostics_node_manager.h"
#include "ua_whole_value_source.h"

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
#include "ua_weak_address_space.h"
#include "ua_node_class.h"
#include "ua_node_subtree.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_self_owning_operation.h"
#include "ua_string.h"
#include "ua_server_session.h"
#include "ua_subscription.h"
#include "ua_subscription_diagnostics_data_type.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <vector>

namespace ua::server
{

SubscriptionDiagnosticsDataType build_subscription_diagnostics(
  const SubscriptionInfo& info, const NodeId& sessionId)
{
  SubscriptionDiagnosticsDataType d;
  d.session_id() = sessionId;
  d.subscription_id() = info.id;
  d.priority() = info.priority;
  d.publishing_interval() = info.publishingInterval;
  d.max_keep_alive_count() = info.maxKeepAliveCount;
  d.max_lifetime_count() = info.maxLifetimeCount;
  d.max_notifications_per_publish() = info.maxNotificationsPerPublish;
  d.publishing_enabled() = info.publishingEnabled;
  d.modify_count() = info.modifyCount;
  d.enable_count() = info.enableCount;
  d.disable_count() = info.disableCount;
  d.republish_request_count() = info.republishRequestCount;
  d.republish_message_request_count() = info.republishMessageRequestCount;
  d.republish_message_count() = info.republishMessageCount;
  d.transfer_request_count() = info.transferRequestCount;
  d.transferred_to_alt_client_count() = info.transferredToAltClientCount;
  d.transferred_to_same_client_count() = info.transferredToSameClientCount;
  d.publish_request_count() = info.publishRequestCount;
  d.data_change_notifications_count() = info.dataChangeNotificationsCount;
  d.event_notifications_count() = info.eventNotificationsCount;
  d.notifications_count() = info.notificationsCount;
  d.late_publish_request_count() = info.latePublishRequestCount;
  d.current_keep_alive_count() = info.currentKeepAliveCount;
  d.current_lifetime_count() = info.currentLifetimeCount;
  d.unacknowledged_message_count() = info.unacknowledgedMessageCount;
  d.discarded_message_count() = info.discardedMessageCount;
  d.monitored_item_count() = info.monitoredItemCount;
  d.disabled_monitored_item_count() = info.disabledMonitoredItemCount;
  d.monitoring_queue_overflow_count() = info.monitoringQueueOverflowCount;
  d.next_sequence_number() = info.peekSequenceNumber;
  d.event_queue_overflow_count() = info.eventQueueOverflowCount;
  return d;
}

namespace
{

/// Snapshot source for a single subscription's diagnostics record; nullopt once the subscription is
/// gone (read handlers then report Bad_NoData until the node is removed).
using ValueProvider = std::function<std::optional<SubscriptionDiagnosticsDataType>()>;

/// Field children of SubscriptionDiagnosticsType wired with live read handlers. The root node's own
/// Value carries the full struct; these expose the individually-readable fields the UACTT walks to
/// via TranslateBrowsePath (Base Info Diagnostics 011-015). BrowseName -> field extractor.
struct FieldEntry
{
  const char* browseName;
  Variant (*extract)(const SubscriptionDiagnosticsDataType&);
};

constexpr std::array<FieldEntry, 31> fieldTable{{
  {"SubscriptionId",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.subscription_id()};
    }},
  {"SessionId",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.session_id()};
    }},
  {"Priority",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.priority()};
    }},
  {"PublishingInterval",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.publishing_interval()};
    }},
  {"MaxKeepAliveCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.max_keep_alive_count()};
    }},
  {"MaxLifetimeCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.max_lifetime_count()};
    }},
  {"MaxNotificationsPerPublish",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.max_notifications_per_publish()};
    }},
  {"PublishingEnabled",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.publishing_enabled()};
    }},
  {"ModifyCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.modify_count()};
    }},
  {"RepublishRequestCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.republish_request_count()};
    }},
  {"RepublishMessageRequestCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.republish_message_request_count()};
    }},
  {"RepublishMessageCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.republish_message_count()};
    }},
  {"PublishRequestCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.publish_request_count()};
    }},
  {"DataChangeNotificationsCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.data_change_notifications_count()};
    }},
  {"NotificationsCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.notifications_count()};
    }},
  {"MonitoredItemCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.monitored_item_count()};
    }},
  {"DisabledMonitoredItemCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.disabled_monitored_item_count()};
    }},
  {"MonitoringQueueOverflowCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.monitoring_queue_overflow_count()};
    }},
  {"NextSequenceNumber",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.next_sequence_number()};
    }},
  // Every SubscriptionDiagnosticsType field child is a mandatory component and must reflect its live
  // diagnostic value (OPC 10000-5 6.3.7). build_subscription_diagnostics sources all of them from
  // SubscriptionInfo, so each field browsed here is wired to a live read handler.
  {"EnableCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.enable_count()};
    }},
  {"DisableCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.disable_count()};
    }},
  {"TransferRequestCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.transfer_request_count()};
    }},
  {"TransferredToSameClientCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.transferred_to_same_client_count()};
    }},
  {"TransferredToAltClientCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.transferred_to_alt_client_count()};
    }},
  {"EventNotificationsCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.event_notifications_count()};
    }},
  {"UnacknowledgedMessageCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.unacknowledged_message_count()};
    }},
  {"LatePublishRequestCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.late_publish_request_count()};
    }},
  {"DiscardedMessageCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.discarded_message_count()};
    }},
  {"EventQueueOverflowCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.event_queue_overflow_count()};
    }},
  {"CurrentKeepAliveCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.current_keep_alive_count()};
    }},
  {"CurrentLifetimeCount",
    [](const SubscriptionDiagnosticsDataType& d)
    {
      return Variant{d.current_lifetime_count()};
    }},
}};

detail::WholeValueRead make_struct_handler(ValueProvider provider)
{
  return [provider = std::move(provider)](
           const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    auto record = provider();
    DataValue dv;
    if (!record)
    {
      dv.status() = StatusCode{Status::BadNoData};
      complete(std::move(dv));
      return;
    }
    dv.source_timestamp() = DateTime::now();
    dv.value() = Variant{std::move(*record)};
    complete(std::move(dv));
  };
}

detail::WholeValueRead make_field_handler(
  ValueProvider provider, Variant (*extract)(const SubscriptionDiagnosticsDataType&))
{
  return [provider = std::move(provider), extract](
           const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    auto record = provider();
    DataValue dv;
    if (!record)
    {
      dv.status() = StatusCode{Status::BadNoData};
      complete(std::move(dv));
      return;
    }
    dv.source_timestamp() = DateTime::now();
    dv.value() = extract(*record);
    complete(std::move(dv));
  };
}

}  // namespace

/// Builds one subscription's diagnostic node: instantiates it under the hidden staging holder,
/// wires the root node's Value, links it into the SubscriptionDiagnosticsArray, then wires the
/// per-field live read handlers. Ends by releasing the manager's pending bookkeeping, whether it
/// got that far or not - a create that never finalises hangs every `when_ready_async` waiter.
///
/// The manager is held WEAKLY and re-locked after every await: it is owned by ServerImpl and can be
/// torn down mid-instantiation. Everything the operation needs from it that cannot change - the
/// address space, the two node ids - is copied in at construction so a lost manager only costs the
/// bookkeeping, not the flow.
///
/// The strand is minted per create and belongs to that create alone. SubscriptionRouter drives this
/// from arbitrary subscription strands; the manager's own bookkeeping stays mutex-guarded, and this
/// strand serialises nothing beyond this one operation's own state.
class SubscriptionDiagnosticsNodeManager::CreateOperation final
  : public ua::async::SelfOwningOperation<CreateOperation>
{
public:
  static void start(SubscriptionDiagnosticsNodeManager& manager, IntegerId id, ValueProvider provider)
  {
    launch(std::make_shared<CreateOperation>(manager, id, std::move(provider)));
  }

  CreateOperation(SubscriptionDiagnosticsNodeManager& manager, IntegerId id, ValueProvider provider)
    : SelfOwningOperation(boost::asio::make_strand(manager.mAddressSpace.executor()), Logger{}),
      mManager(manager.weak_from_this()), mId(id), mAddressSpace(manager.mAddressSpace.weak()),
      mStagingNodeId(manager.mStagingNodeId), mArrayNodeId(manager.mArrayNodeId),
      mProvider(std::move(provider))
  {}

private:
  friend class ua::async::SelfOwningOperation<CreateOperation>;

  // Defined ahead of the bodies that co_await them: an `auto` return type has to be deduced
  // before a caller can name it.
  /// The address space, locked for one step's call; nullopt, with @p completion answered AddressSpaceGone,
  /// when it is gone. The operation holds it weakly (CALLS-21 rule 1).
  template<typename Answer, typename Completion>
  std::optional<AddressSpace> owner_or_gone(Completion& completion)
  {
    auto owner = mAddressSpace.lock();
    if (!owner)
      completion(Answer{::ua::detail::address_space_gone("SubscriptionDiagnostics")});
    return owner;
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
      if (!co_await instantiate())
      {
        fail();
        co_return;
      }

      // Wire the root node's Value (the full struct) FIRST, then link the node into the array. The
      // node + its (instantiation-created) field children thus become visible quickly and with a
      // valid struct value; the per-field live handlers are wired afterwards (a client's first read
      // of a freshly-created counter is its instantiated 0, which matches the expected initial
      // value).
      co_await attach_whole_value_source(mRootId, make_struct_handler(mProvider));

      if (co_await link_into_array())
      {
        co_await wire_field_handlers();
      }
      // A node that could not be linked is finalised all the same: it exists, it may simply be
      // unreachable, and the pending bookkeeping has to be released either way.
      finalize();
    }
    catch (const ua::async::Abandoned&)
    {
      // Nobody wants this node any more, but a waiter may still be parked on it.
      fail();
    }
    catch (...)
    {
      ua::async::guarded(mLogger, [] { throw; })();
      fail();
    }
  }

  void fail_to_start(StatusCode)
  {
    // The body never ran, so nothing else will release the id.
    fail();
  }

  /// @return false when the instance could not be created.
  ua::async::Task<bool> instantiate()
  {
    InstantiationOptions options;
    options.nodeIdAllocator = guid_node_id_allocator();

    auto result = co_await await_step<NodeSubtreeResult>(
      [this, &options](auto completion)
      {
        auto owner = owner_or_gone<NodeSubtreeResult>(completion);
        if (!owner)
          return;
        InstantiationService service{*owner};
        service.instantiate_variable_async(mStagingNodeId,
          QualifiedName{0, std::to_string(mId)},
          NodeId{VariableTypeId::SubscriptionDiagnosticsType},
          options,
          VariableInstantiationAttributes{},
          std::move(completion));
      });

    if (!result.is_good())
    {
      co_return false;
    }

    // Keep the instantiated nodes alive past the handle; they are removed explicitly (and
    // asynchronously) on subscription teardown. NodeSubtree's destructor deletes SYNCHRONOUSLY,
    // which must never run on a strand - and this body runs on one - so the handle is released
    // before anything can carry it across a suspension.
    auto subtree = std::move(result).value();
    subtree.release();
    mRootId = subtree.root();
    co_return true;
  }

  /// Adds SubscriptionDiagnosticsArray --HasComponent--> root (forward, makes the node browseable) and
  /// root --HasComponent--> array (inverse, so delete_node on the root later cleans the array's forward
  /// edge), both halves in one call (NR-30). Only when both are in place is the node "created".
  /// @return false when either half was not added.
  ua::async::Task<bool> link_into_array()
  {
    const auto added = co_await await_step<std::vector<VoidResult>>(
      [this](auto completion)
      {
        const auto pair =
          ReferenceChange::both_halves(mArrayNodeId, NodeId{ReferenceTypeId::HasComponent}, mRootId);
        ::ua::detail::NodeAccessorRoute::add_references(mAddressSpace,
          RequestInfo{},
          std::make_shared<const std::vector<ReferenceChange>>(pair.begin(), pair.end()),
          std::move(completion));
      });
    co_return std::ranges::none_of(added, [](const VoidResult& half) { return !half.is_good(); });
  }

  /// Wires every field child's live read handler. All of them are issued before any is awaited -
  /// a Task starts eagerly, so building the vector starts each one and it runs to its own first
  /// suspension. That is the concurrency the pendingWires countdown used to provide.
  ua::async::Task<> wire_field_handlers()
  {
    std::vector<ua::async::Task<>> wires;
    wires.reserve(fieldTable.size());
    for (const auto& field : fieldTable)
    {
      wires.push_back(wire_one_field(field));
    }
    for (auto& wire : wires)
    {
      co_await std::move(wire);
    }
  }

  /// @param field By value: a reference parameter is not copied into the frame (R8), and this one
  ///              outlives every suspension below it.
  ua::async::Task<> wire_one_field(FieldEntry field)
  {
    auto childResult = co_await await_step<NodeIdResult>(
      [this, &field](auto completion)
      {
        auto owner = owner_or_gone<NodeIdResult>(completion);
        if (!owner)
          return;
        instance_utils::find_child_id_by_browse_name_async(std::move(*owner),
          mRootId,
          NodeId{ReferenceTypeId::HasComponent},
          QualifiedName{0, field.browseName},
          std::move(completion));
      });
    if (!childResult.is_good())
    {
      co_return;  // one missing field child does not fail the node
    }
    co_await attach_whole_value_source(childResult.value(), make_field_handler(mProvider, field.extract));
  }

  void finalize()
  {
    if (auto manager = mManager.lock())
    {
      manager->finalize_create(mId, mRootId);
    }
  }

  void fail()
  {
    if (auto manager = mManager.lock())
    {
      manager->fail_create(mId);
    }
  }

  std::weak_ptr<SubscriptionDiagnosticsNodeManager> mManager;
  IntegerId mId{0};
  WeakAddressSpace mAddressSpace;
  NodeId mStagingNodeId;
  NodeId mArrayNodeId;
  ValueProvider mProvider;
  NodeId mRootId;
};

std::shared_ptr<SubscriptionDiagnosticsNodeManager> SubscriptionDiagnosticsNodeManager::create(
  AddressSpace addressSpace, NodeId arrayNodeId)
{
  // Hidden holder (ns=1, not reachable from the address-space root) the per-subscription instances
  // are built under. Created once during server startup - off any strand, so a sync create is safe.
  NodeId stagingNodeId{uint16_t{1}, String{"__SubscriptionDiagnosticsStaging"}};
  (void)addressSpace.try_create_node_sync(stagingNodeId,
    NodeClass::Object,
    InitialAttributes{
      {AttributeId::BrowseName, Variant{QualifiedName{1, "__SubscriptionDiagnosticsStaging"}}}});
  return std::shared_ptr<SubscriptionDiagnosticsNodeManager>(new SubscriptionDiagnosticsNodeManager(
    std::move(addressSpace), std::move(arrayNodeId), std::move(stagingNodeId)));
}

SubscriptionDiagnosticsNodeManager::SubscriptionDiagnosticsNodeManager(
  AddressSpace addressSpace, NodeId arrayNodeId, NodeId stagingNodeId)
  : mAddressSpace(std::move(addressSpace)), mArrayNodeId(std::move(arrayNodeId)),
    mStagingNodeId(std::move(stagingNodeId))
{}

void SubscriptionDiagnosticsNodeManager::on_subscription_added(
  IntegerId id, std::weak_ptr<Subscription> subscription, std::weak_ptr<Session> owner)
{
  {
    const std::lock_guard lock(mMutex);
    if (mNodes.count(id) || mPending.count(id))
      return;  // Already present or being created (idempotent; tolerates transfer churn).
    mPending.insert(id);
  }

  ValueProvider provider = [subscription = std::move(subscription),
                             owner = std::move(owner)]() -> std::optional<SubscriptionDiagnosticsDataType>
  {
    auto sub = subscription.lock();
    if (!sub)
      return std::nullopt;
    NodeId sessionId;
    if (auto session = owner.lock())
      sessionId = session->session_id();
    return build_subscription_diagnostics(sub->get_info(), sessionId);
  };

  CreateOperation::start(*this, id, std::move(provider));
}

std::vector<std::function<void()>> SubscriptionDiagnosticsNodeManager::take_ready_completions(IntegerId id)
{
  std::vector<std::function<void()>> completions;
  auto it = mPendingReady.find(id);
  if (it != mPendingReady.end())
  {
    completions = std::move(it->second);
    mPendingReady.erase(it);
  }
  return completions;
}

void SubscriptionDiagnosticsNodeManager::finalize_create(IntegerId id, NodeId rootId)
{
  bool removeNow = false;
  std::vector<std::function<void()>> ready;
  {
    const std::lock_guard lock(mMutex);
    mPending.erase(id);
    if (mRemovedWhilePending.erase(id) > 0)
    {
      removeNow = true;  // Subscription was deleted while the node was still being built.
    }
    else
    {
      mNodes.emplace(id, rootId);
    }
    ready = take_ready_completions(id);
  }
  if (removeNow)
    remove_node(rootId);
  // The node is now visible (or has been scheduled for removal) - release any CreateSubscription
  // responses waiting on it.
  for (const auto& completion : ready)
    completion();
}

void SubscriptionDiagnosticsNodeManager::fail_create(IntegerId id)
{
  std::vector<std::function<void()>> ready;
  {
    const std::lock_guard lock(mMutex);
    mPending.erase(id);
    mRemovedWhilePending.erase(id);
    ready = take_ready_completions(id);
  }
  // Creation failed - still release waiters so CreateSubscription does not hang (the diagnostics node
  // simply will not be present).
  for (const auto& completion : ready)
    completion();
}

void SubscriptionDiagnosticsNodeManager::when_ready_async(IntegerId id, std::function<void()> completion)
{
  {
    const std::lock_guard lock(mMutex);
    if (!mNodes.count(id) && mPending.count(id))
    {
      // Not yet created but a create is in flight - wait for it. The create
      // completion drains mPendingReady; do not fire now.
      mPendingReady[id].push_back(std::move(completion));
      return;
    }
    // Either already created, or an unknown id (never started or already
    // finished+removed): fall through and fire now so callers never hang.
  }
  completion();
}

void SubscriptionDiagnosticsNodeManager::on_subscription_removed(IntegerId id)
{
  NodeId rootId;
  bool removeNow = false;
  {
    const std::lock_guard lock(mMutex);
    auto it = mNodes.find(id);
    if (it != mNodes.end())
    {
      rootId = it->second;
      mNodes.erase(it);
      removeNow = true;
    }
    else if (mPending.count(id))
    {
      mRemovedWhilePending.insert(id);  // Defer until creation finishes.
    }
  }
  if (removeNow)
    remove_node(rootId);
}

void SubscriptionDiagnosticsNodeManager::remove_node(NodeId rootId)
{
  // Async cascade delete of the instance subtree (root + forward hierarchical children). Safe from
  // any thread, unlike the synchronous NodeSubtree destructor.
  mAddressSpace.delete_node_async(
    rootId, /*deleteForwardHierarchicallyReferencedNodes=*/true, ReferenceHalves::Both, [](VoidResult) {});
}

}  // namespace ua::server
