// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief What each service costs a namespace, counted rather than argued.
///
/// `find_nodes` is the only resolution interface, so counting calls to it counts the round trips a
/// namespace that answers remotely would pay. These tests assert TODAY'S numbers. That is
/// deliberate: when a service is converted to resolve in batches, the test goes red, and the
/// improvement has to be ratified with its new number rather than claimed.
///
/// The numbers matter because the chains are SEQUENTIAL - a cursor advanced by the previous
/// completion - so the cost is additive in latency, not merely in call count. A namespace fronting a
/// remote server pays one network round trip per call counted here.

#include <future>
#include <numeric>

#include <gtest/gtest.h>

#include <span>
#include <boost/asio/thread_pool.hpp>

#include "ua_attribute_id.h"
#include "ua_browse_path.h"
#include "ua_browse_service.h"
#include "ua_default_namespace.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_server.h"
#include "ua_create_monitored_items_request.h"
#include "ua_state_machine_runtime.h"
#include "ua_subscription.h"
#include "ua_to_string.h"
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

#include "stubs.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

/// An in-memory namespace that counts what a remote one would pay for.
class CountingNamespace final : public default_ns::Namespace
{
public:
  CountingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    if (mCounting)
    {
      ++mCalls;
      mIds += nodeIds.size();
      mLargestBatch = std::max(mLargestBatch.load(), nodeIds.size());
    }
    default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  /// Declines the synchronous form, so every resolution this service performs goes through the interface
  /// above and is counted. That is also the namespace this measurement is ABOUT: a local store
  /// answers immediately and pays none of what is counted here, while a namespace fronting a remote
  /// server pays a round trip for each of these calls.
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    (void)nodeId;
    (void)maxAge;
    return std::nullopt;
  }

  /// Starts counting. Registration and node creation resolve through this interface too, and those are
  /// the fixture's cost rather than the service's.
  void count_from_now()
  {
    mCounting = true;
  }

  size_t calls() const
  {
    return mCalls.load();
  }

  size_t ids() const
  {
    return mIds.load();
  }

  size_t largest_batch() const
  {
    return mLargestBatch.load();
  }

private:
  std::atomic_bool mCounting{false};
  std::atomic_size_t mCalls{0};
  std::atomic_size_t mIds{0};
  std::atomic_size_t mLargestBatch{0};
};

ua::server::Server make_server(boost::asio::any_io_executor executor)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  return ua::server::Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
}

}  // namespace

// A Browse resolves the nodes it was asked about in ONE call, and then every reference target of
// every item in ONE more, however many there are. The reference is still the unit of WORK - each
// target's BrowseName, DisplayName, NodeClass and TypeDefinition has to be filled in - but it is no
// longer the unit of COST.
//
// RATIFIED CHANGE, 2026-09-15. This test asserted 13 resolutions with a largest batch of 1, which is
// what the per-reference continuation chain cost. Measured here after the batching: 2 and 12. The
// numbers below are the new measurement, and they keep the same job - a service that goes back to
// resolving reference by reference turns this red again.
TEST(ResolutionRoundTrips, BrowseCostsTwoResolutionsHoweverManyReferences)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<CountingNamespace>("uri://round-trips-browse", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  constexpr size_t children = 12;
  const NodeId folder{nsIndex, 5000u};
  ns->create_node(folder, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto folderAccessor = addressSpace.try_find_node_sync(folder);
  ASSERT_TRUE(folderAccessor.is_good());
  for (size_t i = 0; i < children; ++i)
  {
    const NodeId child{nsIndex, static_cast<uint32_t>(6000 + i)};
    ns->create_node(child, NodeClass::Object);
    folderAccessor.value().try_add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{child}, /*isForward=*/true);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  BrowseRequest browseRequest;
  browseRequest.nodes_to_browse().resize(1);
  browseRequest.nodes_to_browse()[0].node_id() = folder;
  browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;

  std::promise<void> done;
  ns->count_from_now();
  auto service = BrowseService::create(sessionInfo,
    {"en"},
    0,
    std::move(browseRequest),
    executor,
    [&done](BrowseService::BrowseServiceResponse) { done.set_value(); });

  ASSERT_EQ(done.get_future().wait_for(5s), std::future_status::ready);

  // TWO, whatever children is: one for the request's source nodes, one for every reference target
  // of the page. The Organizes reference type is resolved too, but NS0 owns it, so it is not this
  // namespace's cost.
  EXPECT_EQ(ns->calls(), 2u) << "a browse of one node with " << children << " references cost " << ns->calls()
                             << " round trips";
  EXPECT_EQ(ns->largest_batch(), children)
    << "every reference target of the page must be resolved in ONE call";
  EXPECT_EQ(ns->ids(), children + 1) << "and every id is still asked about exactly once";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// TranslateBrowsePaths walks every path of a request in step, one relative-path element at a time,
// so that the candidate targets of an element - across every path still walking - are resolved in ONE
// call. The cost is the path DEPTH plus one, whatever the request's width and however many references
// each element examines.
//
// TWO paths over two separate chains, not one path over one, because a request of width one cannot
// tell a batched resolution from an unbatched one: with a single live target per element, both shapes
// resolve one id per call. Two chains make the width visible in `largest_batch`.
//
// RATIFIED CHANGE, 2026-09-15. This test asserted 10 resolutions with a largest batch of 1, which is
// what walking each path on its own, reference by reference, cost. Measured here after the batching:
// 4 and 4, from the same 10 ids. The numbers below are the new measurement, and they keep the same
// job - a service that goes back to resolving one target at a time turns this red again.
TEST(ResolutionRoundTrips, TranslateCostsResolutionsPerPathElement)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<CountingNamespace>("uri://round-trips-translate", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  constexpr size_t pathDepth = 3;
  const NodeId root{nsIndex, 7000u};
  ns->create_node(root, NodeClass::Object);
  auto addressSpace = server.address_space();

  // Two chains of depth pathDepth hanging off one root, with distinct BrowseNames - so at every hop
  // each path has its own live target and its own candidate, and the two are resolvable together.
  const auto makeChain = [&](uint32_t baseId, const std::string& prefix)
  {
    std::vector<QualifiedName> names;
    NodeId previous = root;
    for (size_t depth = 0; depth < pathDepth; ++depth)
    {
      const NodeId child{nsIndex, static_cast<uint32_t>(baseId + depth)};
      ns->create_node(child, NodeClass::Object);

      QualifiedName name{nsIndex, prefix + std::to_string(depth)};
      auto childAccessor = addressSpace.try_find_node_sync(child);
      EXPECT_TRUE(childAccessor.is_good());
      childAccessor.value().set_browse_name(name);
      names.push_back(name);

      auto previousAccessor = addressSpace.try_find_node_sync(previous);
      EXPECT_TRUE(previousAccessor.is_good());
      previousAccessor.value().try_add_reference_sync(
        NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{child}, /*isForward=*/true);
      previous = child;
    }
    return names;
  };

  const std::vector<std::vector<QualifiedName>> chains{makeChain(7100u, "step"), makeChain(7200u, "other")};

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  TranslateBrowsePathsToNodeIdsRequest request;
  request.request_header().request_handle() = 1;
  for (const auto& names : chains)
  {
    BrowsePath browsePath;
    browsePath.starting_node() = root;
    RelativePath relativePath;
    for (const auto& name : names)
    {
      RelativePathElement element;
      element.reference_type_id() = NodeId{0, static_cast<uint32_t>(ReferenceTypeId::Organizes)};
      element.is_inverse() = false;
      element.include_subtypes() = true;
      element.target_name() = name;
      relativePath.elements().payload().push_back(std::move(element));
    }
    browsePath.relative_path() = std::move(relativePath);
    request.browse_paths().payload().push_back(std::move(browsePath));
  }

  std::promise<Response> promise;
  ns->count_from_now();
  auto service = TranslateBrowsePathsService::create(sessionInfo,
    {"en"},
    1,
    std::move(request),
    executor,
    [&promise](Response r) { promise.set_value(std::move(r)); });
  auto future = promise.get_future();
  ASSERT_EQ(future.wait_for(5s), std::future_status::ready);

  std::cout << "[ translate ] " << ns->calls() << " resolutions, " << ns->ids() << " ids, largest batch "
            << ns->largest_batch() << "\n";

  // ONE for the starting nodes of both paths, then ONE per relative-path element. The elements are
  // genuinely serial - an element's candidates are the previous element's answers - so the depth is
  // the floor, and the width costs nothing. The Organizes reference type is resolved too, but NS0
  // owns it, so it is not this namespace's cost.
  EXPECT_EQ(ns->calls(), 1u + pathDepth)
    << "two paths of depth " << pathDepth << " cost " << ns->calls() << " round trips";

  // TWO: at the first element both paths examine the root's two forward references, and an element's
  // distinct targets are looked up once however many paths reach them (NR-23 rule 2, NR-70 B2a), so the
  // two paths' four candidates are two NodeIds in one call.
  EXPECT_EQ(ns->largest_batch(), 2u) << "every candidate target of an element must be resolved in ONE call";

  // SEVEN: the shared root once, then each element's two distinct targets (NR-23 rule 2). Before B2a each
  // path's candidates were looked up separately, ten ids in all.
  EXPECT_EQ(ns->ids(), 7u) << "and every distinct id is asked about exactly once per element";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// What the asynchronous interface costs when the store is local, measured against the synchronous lookup
// into the same map. This is the number that decides whether a `try_` fast path is worth its
// interface surface: it is paid on EVERY resolution, and the browse test above shows a browse of
// twelve children paying it thirteen times.
//
// Not a pass/fail threshold - machines differ. It asserts only that both paths answer, and reports
// the ratio for the record.
TEST(ResolutionRoundTrips, AsynchronousResolutionCostsMoreThanTheSynchronousLookupBehindIt)
{
  boost::asio::thread_pool threadPool{1};
  auto executor = threadPool.get_executor();

  auto addressSpace = AddressSpace::create("urn:test:resolution-cost-host", executor);
  auto ns = default_ns::Namespace::create("uri://resolution-cost", executor);
  const auto registered = addressSpace.try_add_namespace_sync(ns);
  ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());

  constexpr size_t nodes = 200;
  constexpr size_t repeats = 50;
  std::vector<NodeId> ids;
  ids.reserve(nodes);
  for (size_t i = 0; i < nodes; ++i)
  {
    NodeId id{registered.value(), static_cast<uint32_t>(9000 + i)};
    ns->create_node(id, NodeClass::Object);
    ids.push_back(id);
  }

  // The synchronous interface: a map hit and a shared_ptr copy, answered on this stack.
  size_t syncHits = 0;
  const auto syncStart = std::chrono::steady_clock::now();
  for (size_t r = 0; r < repeats; ++r)
  {
    for (const auto& id : ids)
    {
      if (ns->find_node<Node>(id))
      {
        ++syncHits;
      }
    }
  }
  const auto syncNanos =
    std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - syncStart);

  // The same answers through the asynchronous interface, one id at a time - which is what a namespace
  // that DECLINES the synchronous form costs the caller for every node it is asked about. It is also
  // what every resolution in this SDK cost before the synchronous form existed.
  size_t asyncHits = 0;
  const auto asyncStart = std::chrono::steady_clock::now();
  for (size_t r = 0; r < repeats; ++r)
  {
    for (const auto& id : ids)
    {
      ns->find_nodes_async(RequestInfo{},
        std::span<const NodeId>{&id, 1},
        std::nullopt,
        [&asyncHits](BatchResult<NodeResult> batch)
        {
          if (!batch.items.empty() && batch.items.front().is_good())
          {
            ++asyncHits;
          }
        });
    }
  }
  const auto asyncNanos =
    std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - asyncStart);

  ASSERT_EQ(syncHits, nodes * repeats);
  ASSERT_EQ(asyncHits, nodes * repeats);

  const double perSync = static_cast<double>(syncNanos.count()) / (nodes * repeats);
  const double perAsync = static_cast<double>(asyncNanos.count()) / (nodes * repeats);
  std::cout << "[ resolution ] synchronous " << perSync << " ns/op, through the async interface " << perAsync
            << " ns/op, ratio " << (perAsync / perSync) << "x\n";
}

// Resolving one state-machine transition walks the machine, its type, every component of that type
// and the two states the transition names. The cost is dominated by the COMPONENT COUNT of the
// machine type - which the address space decides, not the caller - so it is the number worth holding
// still.
//
// RATIFIED CHANGE, 2026-09-15. This test asserted 46 resolutions with a largest batch of 1, which is
// what resolving component by component cost. Measured here after batching the three list-shaped
// scans - every component of the machine type, every cause of a transition, and the transition's two
// ends: 38 and 8, from the SAME 46 ids. The numbers below are the new measurement.
//
// The 38 that remain are not this component's to remove. Three of every four are inside
// `instance_utils::find_child_variable_accessor_by_browse_name_async`, which resolves the parent,
// then each candidate child to read its BrowseName, then the match - and that is item 11's
// `FindChildIdFlow`, where fixing it improves every caller in the SDK rather than this one walk.
TEST(ResolutionRoundTrips, ResolvingATransitionCostsResolutionsPerMachineTypeComponent)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto addressSpace = AddressSpace::create("urn:round-trips-state-machine", executor);
  auto ns = make_shared<CountingNamespace>("uri://round-trips-state-machine", executor);
  const uint16_t nsIndex = addressSpace.add_namespace_sync(ns);

  const auto node = [&](uint32_t id, NodeClass nodeClass, std::string_view browseName)
  {
    ns->create_node(NodeId{nsIndex, id}, nodeClass);
    auto accessor = addressSpace.try_find_node_sync(NodeId{nsIndex, id});
    EXPECT_TRUE(accessor.is_good());
    accessor.value().set_browse_name(QualifiedName{0, std::string{browseName}});
    accessor.value().set_display_name(LocalizedText{"", std::string{browseName}});
    return accessor.value();
  };
  const auto property = [&](NodeAccessor& parent, uint32_t id, std::string_view browseName, Variant value)
  {
    auto child = node(id, NodeClass::Variable, browseName);
    auto variable = *child.as<VariableAccessor>();
    variable.write_value_sync(DataValue{std::move(value)});
    parent.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, variable.get_node_id());
  };

  // A machine type with a handful of state components, one of which the transition names.
  constexpr size_t states = 6;
  auto type = node(100, NodeClass::ObjectType, "MachineType");
  auto instance = node(101, NodeClass::Object, "Machine");
  auto declaredMethod = node(102, NodeClass::Method, "Advance");
  auto instanceMethod = node(103, NodeClass::Method, "Advance");
  auto currentState = node(104, NodeClass::Variable, "CurrentState");
  auto transition = node(105, NodeClass::Object, "FirstToSecond");

  instance.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, type.get_node_id());
  instance.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, currentState.get_node_id());
  instance.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, instanceMethod.get_node_id());
  instanceMethod.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, instance.get_node_id(), false);

  type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, declaredMethod.get_node_id());
  declaredMethod.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, type.get_node_id(), false);
  type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, transition.get_node_id());

  std::vector<NodeId> stateIds;
  for (size_t i = 0; i < states; ++i)
  {
    auto state = node(static_cast<uint32_t>(200 + i), NodeClass::Object, "State" + std::to_string(i));
    property(state, static_cast<uint32_t>(300 + i), "StateNumber", Variant{static_cast<uint32_t>(i)});
    type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, state.get_node_id());
    stateIds.push_back(state.get_node_id());
  }

  property(currentState, 106, "Id", Variant{stateIds.front()});
  transition.add_reference_sync(NodeId{ReferenceTypeId::HasCause}, declaredMethod.get_node_id());
  transition.add_reference_sync(NodeId{ReferenceTypeId::FromState}, stateIds[0]);
  transition.add_reference_sync(NodeId{ReferenceTypeId::ToState}, stateIds[1]);

  auto model = make_address_space_state_machine_model(addressSpace);

  std::promise<StateMachineTransitionResolutionResult> promise;
  ns->count_from_now();
  model->resolve_transition_async(instance.get_node_id(),
    instanceMethod.get_node_id(),
    [&promise](StateMachineTransitionResolutionResult result) { promise.set_value(std::move(result)); });

  auto future = promise.get_future();
  ASSERT_EQ(future.wait_for(10s), std::future_status::ready);
  auto resolution = future.get();
  ASSERT_TRUE(resolution.is_good()) << ua::to_string(resolution.status_code());
  ASSERT_TRUE(resolution.value().enabledTransition.has_value())
    << "the fixture must resolve a transition, or the numbers below count the wrong walk";

  std::cout << "[ state-machine ] " << ns->calls() << " resolutions, " << ns->ids() << " ids, largest batch "
            << ns->largest_batch() << "\n";

  // The three scans that know their whole list before they start now ask once each. The transition's
  // TransitionNumber Property, which its Events carry, is one lookup more.
  EXPECT_EQ(ns->calls(), 39u) << "a transition resolve over " << states << " declared states cost "
                              << ns->calls() << " round trips";
  EXPECT_EQ(ns->largest_batch(), 8u) << "every component of the machine type must be resolved in ONE call";
  EXPECT_EQ(ns->ids(), 47u) << "and every id is still asked about exactly once";

  ns.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// CreateMonitoredItems asks about every item's node ONCE: one call for the whole request, whatever
// its width, finds both the subject it must authorize and the Node it reads the item's initial value
// from, so the cost is ONE round trip however many items are being created. The registration after
// it is one call per namespace, and has always been.
//
// RATIFIED CHANGE, 2026-09-16. This test asserted 16 resolutions with a largest batch of 1, which is
// what walking each item on its own cost: the next item's resolution was issued by the previous
// one's completion, so a namespace fronting a remote server paid two round trips PER ITEM, in
// series, added to the client's latency. Batching each walk brought it to 2 and 8, from 16 ids.
//
// RE-EXPRESSED, B4a (NR-26, DL-69 (D1)): the request looks each Node up once, before registration,
// and that one answer serves the authorization and the initial value: 1 call and 8 ids. The test
// keeps the same job - a service that resolves an item more than once, or one item at a time, turns
// this red again.
TEST(ResolutionRoundTrips, CreatingMonitoredItemsCostsOneResolutionHoweverManyItems)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto addressSpace = server.address_space();
  auto ns = make_shared<CountingNamespace>("uri://round-trips-create-monitored-items", executor);
  const uint16_t nsIndex = addressSpace.add_namespace_sync(ns);

  constexpr size_t items = 8;
  std::vector<NodeId> subjects;
  for (size_t i = 0; i < items; ++i)
  {
    const NodeId nodeId{nsIndex, static_cast<uint32_t>(1000 + i)};
    ns->create_node(nodeId, NodeClass::Variable);
    auto accessor = addressSpace.try_find_node_sync(nodeId);
    ASSERT_TRUE(accessor.is_good()) << ua::to_string(accessor.status_code());
    accessor.value().set_browse_name(QualifiedName{nsIndex, "Item" + std::to_string(i)});
    auto variable = accessor.value().as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->write_value_sync(DataValue{Variant{static_cast<int32_t>(i)}});
    subjects.push_back(nodeId);
  }

  auto sessionInfo = std::make_shared<SessionInfoStub>(std::move(server), executor);

  auto subscription = Subscription::create(/*subscriptionId=*/
    1,
    /*publishingInterval=*/1'000'000.0,
    /*lifetimeCount=*/100,
    /*maxKeepAliveCount=*/3,
    /*maxNotificationsPerPublish=*/0,
    /*publishingEnabled=*/true,
    /*priority=*/0,
    executor,
    [](IntegerId) {},
    [](IntegerId) {});

  CreateMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  for (size_t i = 0; i < items; ++i)
  {
    MonitoredItemCreateRequest itemRequest;
    itemRequest.item_to_monitor().node_id() = subjects[i];
    itemRequest.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    itemRequest.monitoring_mode() = MonitoringMode::Reporting;
    itemRequest.requested_parameters().client_handle() = static_cast<uint32_t>(i);
    itemRequest.requested_parameters().sampling_interval() = 1000;
    itemRequest.requested_parameters().queue_size() = 5;
    itemRequest.requested_parameters().discard_oldest() = true;
    request.items_to_create().push_back(std::move(itemRequest));
  }

  std::promise<std::vector<MonitoredItemCreateResult>> promise;
  auto future = promise.get_future();

  ns->count_from_now();
  subscription->create_monitored_items_async(std::move(request),
    addressSpace,
    ServerConfig::ServerCapabilities{},
    ServerConfig::SubscriptionLimits{},
    sessionInfo,
    std::weak_ptr<EventBus>{},
    nullptr,
    [&promise](std::vector<MonitoredItemCreateResult> results) { promise.set_value(std::move(results)); });

  ASSERT_EQ(future.wait_for(10s), std::future_status::ready);
  auto results = future.get();
  ASSERT_EQ(results.size(), items);
  for (size_t i = 0; i < items; ++i)
  {
    ASSERT_EQ(results[i].status_code(), StatusCode{Status::Good})
      << "item " << i << ": " << ua::to_string(results[i].status_code())
      << " - every item must be created, or the numbers below count a walk that gave up early";
  }

  std::cout << "[ create-monitored-items ] " << ns->calls() << " resolutions, " << ns->ids() << " ids, "
            << "largest batch " << ns->largest_batch() << "\n";

  EXPECT_EQ(ns->calls(), 1u) << "creating " << items << " monitored items cost " << ns->calls()
                             << " round trips - one lookup for the whole request serves the authorization "
                                "and the initial values";
  EXPECT_EQ(ns->largest_batch(), items) << "the lookup must ask about every item in ONE call";
  EXPECT_EQ(ns->ids(), items) << "and every id is asked about exactly once";

  // Registration armed a sampler per item inside the namespace, so the items have to be released
  // before the pool can drain. Counted or not makes no difference: the numbers were read above.
  std::vector<IntegerId> createdIds;
  createdIds.reserve(results.size());
  for (const auto& result : results)
  {
    createdIds.push_back(result.monitored_item_id());
  }
  std::promise<std::vector<StatusCode>> deleted;
  auto deletedFuture = deleted.get_future();
  subscription->delete_monitored_items_async(std::move(createdIds),
    addressSpace,
    std::weak_ptr<EventBus>{},
    nullptr,
    [&deleted](std::vector<StatusCode> statuses) { deleted.set_value(std::move(statuses)); });
  ASSERT_EQ(deletedFuture.wait_for(10s), std::future_status::ready);

  subscription.reset();
  sessionInfo.reset();
  ns.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
