// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_address_space.h"
#include "ua_create_monitored_items_request.h"
#include "ua_default_namespace.h"
#include "ua_data_change_filter.h"
#include "ua_event_filter.h"
#include "ua_range.h"
#include "ua_simple_attribute_operand.h"
#include "ua_event_notifier_type.h"
#include "ua_objecttype_id.h"
#include <boost/asio/post.hpp>
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_server_counters.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = SubscriptionTestAccess;

namespace
{

class CreateDeleteMonitoredItemsTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();

    mAddressSpace = AddressSpace::create("urn:test", mExecutor);

    // Create variable nodes to monitor.
    mAddressSpace->create_node_sync(NodeId{0, 1000}, NodeClass::Variable);
    mAddressSpace->create_node_sync(NodeId{0, 1001}, NodeClass::Variable);
  }

  void TearDown() override
  {
    mSubscription.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// Call create_monitored_items_async and block on the main test thread for
  /// the callback to fire. The private coroutine was retired by the 4.11b
  /// CreateMonitoredItemsFlow flip; tests use the public async surface.
  std::vector<MonitoredItemCreateResult> create_blocking(CreateMonitoredItemsRequest request)
  {
    std::promise<std::vector<MonitoredItemCreateResult>> p;
    mSubscription->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      nullptr,
      std::weak_ptr<EventBus>{},
      nullptr,
      [&p](std::vector<MonitoredItemCreateResult> results) { p.set_value(std::move(results)); });
    return p.get_future().get();
  }

  std::shared_ptr<Subscription> create_subscription()
  {
    mSubscription =
      Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
    return mSubscription;
  }

  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  optional<AddressSpace> mAddressSpace;
  std::shared_ptr<Subscription> mSubscription;

  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
};

CreateMonitoredItemsRequest make_create_request(
  IntegerId subscriptionId, std::vector<std::pair<NodeId, uint32_t>> items)
{
  CreateMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  for (auto& [nodeId, clientHandle] : items)
  {
    MonitoredItemCreateRequest itemReq;
    itemReq.item_to_monitor().node_id() = std::move(nodeId);
    itemReq.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    itemReq.monitoring_mode() = MonitoringMode::Reporting;
    itemReq.requested_parameters().client_handle() = clientHandle;
    itemReq.requested_parameters().sampling_interval() = 1000;
    itemReq.requested_parameters().queue_size() = 5;
    itemReq.requested_parameters().discard_oldest() = true;
    request.items_to_create().push_back(std::move(itemReq));
  }

  return request;
}

}  // namespace

TEST_F(CreateDeleteMonitoredItemsTest, SingleItemSuccess)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{0, 1000}, 42}});

  auto results = create_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
}

// Without a server-wide cap there is nothing to refuse, but the gauge still counts every live item:
// every later release (delete, orphan, close) subtracts from it, so a create that did not add would
// drive it below zero (the gauge is unsigned) and every summary reader would see garbage.
// @relation(AC-SVR-SUB-GEN-032-ORPHANS-RELEASE-MONITORED-ITEM-SLOTS, scope=function)
TEST_F(CreateDeleteMonitoredItemsTest, GaugeCountsEveryLiveItemWithoutAServerWideCap)
{
  auto counters = std::make_shared<ServerSummaryCounters>();
  mCapabilities.maxMonitoredItems = std::nullopt;
  mCapabilities.maxMonitoredItemsPerSubscription = 1000;

  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{0, 1000}, 1}, {NodeId{0, 1000}, 2}, {NodeId{0, 1000}, 3}});
  std::promise<std::vector<MonitoredItemCreateResult>> created;
  sub->create_monitored_items_async(std::move(request),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    nullptr,
    std::weak_ptr<EventBus>{},
    counters,
    [&created](std::vector<MonitoredItemCreateResult> r) { created.set_value(std::move(r)); });
  auto results = created.get_future().get();
  ASSERT_EQ(results.size(), 3u);
  std::vector<IntegerId> ids;
  for (const auto& r : results)
  {
    ASSERT_TRUE(r.status_code().is_good());
    ids.push_back(r.monitored_item_id());
  }
  EXPECT_EQ(counters->currentMonitoredItemCount.load(), 3u)
    << "the gauge counts the committed items whether or not a server-wide cap is configured";

  std::promise<std::vector<StatusCode>> deleted;
  sub->delete_monitored_items_async(std::vector<IntegerId>{ids[0], ids[1]},
    *mAddressSpace,
    std::weak_ptr<EventBus>{},
    counters,
    [&deleted](std::vector<StatusCode> r) { deleted.set_value(std::move(r)); });
  for (const auto& status : deleted.get_future().get())
  {
    EXPECT_TRUE(status.is_good());
  }
  EXPECT_EQ(counters->currentMonitoredItemCount.load(), 1u) << "and releases exactly the deleted ones";
}

// Stage 3c #1: the server-wide MaxMonitoredItems cap is claimed ATOMICALLY at the create gate (not a
// load-then-deferred-add), so the overflow is rejected and the shared gauge reflects exactly the
// committed count - never the rejected items. (Pre-fix the gauge was incremented only at
// complete_create, so concurrent batches read a stale value and overshot.)
TEST_F(CreateDeleteMonitoredItemsTest, ServerWideMaxMonitoredItemsCapEnforcedAndGaugeExact)
{
  auto counters = std::make_shared<ServerSummaryCounters>();
  mCapabilities.maxMonitoredItems = 3;
  mCapabilities.maxMonitoredItemsPerSubscription = 1000;

  auto sub = create_subscription();
  auto request = make_create_request(1,
    {{NodeId{0, 1000}, 1},
      {NodeId{0, 1000}, 2},
      {NodeId{0, 1000}, 3},
      {NodeId{0, 1000}, 4},
      {NodeId{0, 1000}, 5}});

  std::promise<std::vector<MonitoredItemCreateResult>> p;
  sub->create_monitored_items_async(std::move(request),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    nullptr,
    std::weak_ptr<EventBus>{},
    counters,
    [&p](std::vector<MonitoredItemCreateResult> r) { p.set_value(std::move(r)); });
  auto results = p.get_future().get();

  ASSERT_EQ(results.size(), 5u);
  int good = 0;
  int tooMany = 0;
  for (const auto& r : results)
  {
    if (r.status_code().is_good())
      ++good;
    else if (r.status_code() == StatusCode{Status::BadTooManyMonitoredItems})
    {
      ++tooMany;
      // Enriched: the over-cap rejection carries the configured limit + current count.
      const auto detail = r.status_code().shared_detail();
      ASSERT_NE(detail, nullptr);
      const bool hasLimit = std::any_of(detail->context.begin(),
        detail->context.end(),
        [](const NamedValue& entry) { return entry.key == ContextKeys::limit.value(); });
      EXPECT_TRUE(hasLimit);
    }
  }
  EXPECT_EQ(good, 3);
  EXPECT_EQ(tooMany, 2);
  EXPECT_EQ(counters->currentMonitoredItemCount.load(), 3u)
    << "the global gauge must reflect exactly the committed count, not the rejected overflow";
}

// Stage 3c #1: concurrent CreateMonitoredItems flows on different subscriptions that share one
// ServerSummaryCounters must never overshoot the server-wide cap, and the gauge must equal the total
// committed count (no drift). The atomic reservation at the gate is the serialization point.
TEST_F(CreateDeleteMonitoredItemsTest, ConcurrentCreatesNeverExceedServerWideCap)
{
  auto counters = std::make_shared<ServerSummaryCounters>();
  constexpr uint32_t cap = 20;
  mCapabilities.maxMonitoredItems = cap;
  mCapabilities.maxMonitoredItemsPerSubscription = 1000;

  constexpr int subscriptionCount = 8;
  constexpr int itemsEach = 10;  // 8 * 10 = 80 requested >> cap 20

  std::vector<std::shared_ptr<Subscription>> subs;
  for (int s = 0; s < subscriptionCount; ++s)
  {
    subs.push_back(Subscription::create(
      static_cast<IntegerId>(s + 1),
      1000,
      100,
      3,
      0,
      true,
      0,
      mExecutor,
      [](IntegerId) {},
      [](IntegerId) {}));
  }

  std::vector<std::promise<std::vector<MonitoredItemCreateResult>>> promises(subscriptionCount);
  std::vector<std::future<std::vector<MonitoredItemCreateResult>>> futures;
  futures.reserve(subscriptionCount);
  for (int s = 0; s < subscriptionCount; ++s)
  {
    futures.push_back(promises[s].get_future());
  }

  for (int s = 0; s < subscriptionCount; ++s)
  {
    std::vector<std::pair<NodeId, uint32_t>> items;
    for (int k = 0; k < itemsEach; ++k)
    {
      items.emplace_back(NodeId{0, 1000}, static_cast<uint32_t>(s * itemsEach + k));
    }
    auto request = make_create_request(static_cast<IntegerId>(s + 1), std::move(items));
    subs[s]->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      nullptr,
      std::weak_ptr<EventBus>{},
      counters,
      [&promises, s](std::vector<MonitoredItemCreateResult> r) { promises[s].set_value(std::move(r)); });
  }

  uint32_t totalGood = 0;
  for (auto& f : futures)
  {
    for (const auto& r : f.get())
    {
      if (r.status_code().is_good())
        ++totalGood;
    }
  }

  EXPECT_LE(counters->currentMonitoredItemCount.load(), cap)
    << "concurrent creates must never overshoot the server-wide cap";
  EXPECT_LE(totalGood, cap) << "no more than 'cap' items may be admitted in total";
  EXPECT_EQ(counters->currentMonitoredItemCount.load(), totalGood)
    << "the gauge must equal the committed count (reservation reconciled, no drift)";

  subs.clear();  // destroy subscriptions before the pool drain in TearDown
}

TEST_F(CreateDeleteMonitoredItemsTest, InvalidMonitoringModeRejectedBeforeNamespaceCall)
{
  auto sub = create_subscription();
  auto request = make_create_request(1, {{NodeId{0, 1000}, 42}});
  request.items_to_create()[0].monitoring_mode() = static_cast<MonitoringMode>(99);

  auto results = create_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::BadMonitoringModeInvalid});
}

TEST_F(CreateDeleteMonitoredItemsTest, InvalidAttributeIdRejectedBeforeNamespaceCall)
{
  auto sub = create_subscription();

  CreateMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemCreateRequest itemReq;
  itemReq.item_to_monitor().node_id() = NodeId{0, 1000};
  itemReq.item_to_monitor().attribute_id() = 0;  // Invalid
  itemReq.monitoring_mode() = MonitoringMode::Reporting;
  itemReq.requested_parameters().sampling_interval() = 1000;
  itemReq.requested_parameters().queue_size() = 1;
  request.items_to_create().push_back(std::move(itemReq));

  auto results = create_blocking(std::move(request));

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::BadAttributeIdInvalid});
}

TEST_F(CreateDeleteMonitoredItemsTest, MultiItemMixedResults)
{
  auto sub = create_subscription();

  CreateMonitoredItemsRequest request;
  request.subscription_id() = 1;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  // Item 0: valid
  MonitoredItemCreateRequest item0;
  item0.item_to_monitor().node_id() = NodeId{0, 1000};
  item0.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  item0.monitoring_mode() = MonitoringMode::Reporting;
  item0.requested_parameters().sampling_interval() = 1000;
  item0.requested_parameters().queue_size() = 5;
  item0.requested_parameters().discard_oldest() = true;
  request.items_to_create().push_back(std::move(item0));

  // Item 1: invalid monitoring mode
  MonitoredItemCreateRequest item1;
  item1.item_to_monitor().node_id() = NodeId{0, 1001};
  item1.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  item1.monitoring_mode() = static_cast<MonitoringMode>(99);
  item1.requested_parameters().sampling_interval() = 1000;
  item1.requested_parameters().queue_size() = 1;
  request.items_to_create().push_back(std::move(item1));

  auto results = create_blocking(std::move(request));

  ASSERT_EQ(results.size(), 2u);
  // Item 0: valid - monitoring succeeds
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  // Item 1: invalid mode, rejected at validation
  EXPECT_EQ(results[1].status_code(), StatusCode{Status::BadMonitoringModeInvalid});
}

// Build a single-item create request with an explicit requested queue size.
static CreateMonitoredItemsRequest make_create_request_with_queue(
  IntegerId subscriptionId, const NodeId& nodeId, uint32_t queueSize)
{
  CreateMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;

  MonitoredItemCreateRequest itemReq;
  itemReq.item_to_monitor().node_id() = nodeId;
  itemReq.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  itemReq.monitoring_mode() = MonitoringMode::Reporting;
  itemReq.requested_parameters().client_handle() = 1;
  itemReq.requested_parameters().sampling_interval() = 1000;
  itemReq.requested_parameters().queue_size() = queueSize;
  itemReq.requested_parameters().discard_oldest() = true;
  request.items_to_create().push_back(std::move(itemReq));

  return request;
}

TEST_F(CreateDeleteMonitoredItemsTest, DurableQueueCeilingHonoursConfiguredKnob)
{
  auto sub = create_subscription();

  // A non-default durable ceiling proves the cap comes from config, not the former hard-coded 100'000.
  mCapabilities.maxMonitoredItemsQueueSize = 1000;  // non-durable ceiling
  mSubscriptionLimits.maxDurableMonitoredItemQueueSize = 5000;  // durable ceiling

  // Make the subscription durable (must happen before any monitored items exist).
  StatusCode durableStatus{Status::Bad};
  STA::on_strand(*sub,
    [&](auto& g)
    { g.set_durable(1, mSubscriptionLimits, [&](StatusCode s, uint32_t) { durableStatus = s; }); });
  ASSERT_TRUE(durableStatus.is_good()) << "0x" << std::hex << durableStatus.as_uint32();

  // Request a queue far larger than both ceilings; the durable knob (5000) must be the cap.
  auto results = create_blocking(make_create_request_with_queue(1, NodeId{0, 1000}, 50000));
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_EQ(results[0].revised_queue_size(), 5000u);
}

TEST_F(CreateDeleteMonitoredItemsTest, NonDurableQueueCeilingUsesConfiguredMax)
{
  auto sub = create_subscription();

  mCapabilities.maxMonitoredItemsQueueSize = 1000;
  mSubscriptionLimits.maxDurableMonitoredItemQueueSize = 5000;

  // Not durable: the durable ceiling must NOT apply - a large request is capped at the non-durable max.
  auto results = create_blocking(make_create_request_with_queue(1, NodeId{0, 1000}, 50000));
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_EQ(results[0].revised_queue_size(), 1000u);
}

TEST_F(CreateDeleteMonitoredItemsTest, DeleteNonExistentReturnsInvalid)
{
  auto sub = create_subscription();

  std::vector<IntegerId> ids{999};

  // delete_monitored_items_async is the public callback-canonical surface. Block
  // on the main test thread via promise/future - never on a pool thread.
  std::promise<std::vector<StatusCode>> p;
  sub->delete_monitored_items_async(ids,
    *mAddressSpace,
    std::weak_ptr<EventBus>{},
    nullptr,
    [&p](std::vector<StatusCode> r) { p.set_value(std::move(r)); });
  auto results = p.get_future().get();

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::BadMonitoredItemIdInvalid});
}

TEST_F(CreateDeleteMonitoredItemsTest, DeleteExistingItemSucceeds)
{
  auto sub = create_subscription();

  // Add a monitored item directly.
  auto itemId = STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->queueSize = 1;
      return g.add_monitored_item(std::move(item));
    });

  auto miCount = STA::on_strand(*sub, [](auto& g) { return g.monitored_items().size(); });
  EXPECT_EQ(miCount, 1u);

  std::vector<IntegerId> ids{itemId};
  std::promise<std::vector<StatusCode>> p;
  sub->delete_monitored_items_async(ids,
    *mAddressSpace,
    std::weak_ptr<EventBus>{},
    nullptr,
    [&p](std::vector<StatusCode> r) { p.set_value(std::move(r)); });
  auto results = p.get_future().get();

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});

  auto count = STA::on_strand(*sub, [](auto& g) { return g.monitored_items().size(); });
  EXPECT_EQ(count, 0u);
}

// A delete's body holds the address space it was given, the ids it was asked about and the
// server-wide counters it has to decrement, and it holds them for as long as its own frame lives.
// The frame outlives the body: a coroutine's parameters are released when its state is destroyed,
// not when it runs off the end, and the subscription holds that state in a member so an outstanding
// namespace answer has something to resume into. Nothing else would ever ask for it back - a
// subscription that is deleted from once is usually never deleted from again - so the body asks, on
// its way out, for its own frame to be released on a later turn.
TEST_F(CreateDeleteMonitoredItemsTest, AFinishedDeleteReleasesWhatItsBodyWasHolding)
{
  auto sub = create_subscription();

  auto counters = std::make_shared<ServerSummaryCounters>();
  std::weak_ptr<ServerSummaryCounters> countersLifetime = counters;

  std::promise<std::vector<StatusCode>> p;
  sub->delete_monitored_items_async(std::vector<IntegerId>{999},
    *mAddressSpace,
    std::weak_ptr<EventBus>{},
    std::move(counters),
    [&p](std::vector<StatusCode> r) { p.set_value(std::move(r)); });
  auto results = p.get_future().get();
  ASSERT_EQ(results.size(), 1u);

  // The answer fires from inside the body, so the release it asked for has been queued behind it
  // but has not run. One round trip through the strand is what runs it.
  STA::on_strand(*sub, [](auto&) { return 0; });

  EXPECT_TRUE(countersLifetime.expired())
    << "a finished delete still holds the counters it was given, so its frame was never released";
}

// The gate the other item flows ask about is the delete's own running flag, and a delete that has
// answered is not running. What used to say so was a `unique_ptr` being reset at the one place the
// answer was fired from; a body that ends in more than one place has to say so in all of them.
TEST_F(CreateDeleteMonitoredItemsTest, ASecondDeleteIsAcceptedOnceTheFirstHasFinished)
{
  auto sub = create_subscription();

  auto deleteOnce = [&]
  {
    std::promise<std::vector<StatusCode>> p;
    sub->delete_monitored_items_async(std::vector<IntegerId>{999},
      *mAddressSpace,
      std::weak_ptr<EventBus>{},
      nullptr,
      [&p](std::vector<StatusCode> r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  };

  auto first = deleteOnce();
  ASSERT_EQ(first.size(), 1u);
  EXPECT_EQ(first[0], StatusCode{Status::BadMonitoredItemIdInvalid});

  auto second = deleteOnce();
  ASSERT_EQ(second.size(), 1u);
  EXPECT_EQ(second[0], StatusCode{Status::BadMonitoredItemIdInvalid})
    << "the second delete was refused, so the first left the single-flight gate closed";
}

// The gate the next create asks about is the create's own running flag, and a create that has
// answered is not running. What used to say so was a `unique_ptr` being reset at the one place the
// answer was fired from; a body that ends in more than one place has to say so in all of them, and
// this one ends after four separate suspensions.
TEST_F(CreateDeleteMonitoredItemsTest, ASecondCreateIsAcceptedOnceTheFirstHasFinished)
{
  auto sub = create_subscription();

  auto first = create_blocking(make_create_request(1, {{NodeId{0, 1000}, 42}}));
  ASSERT_EQ(first.size(), 1u);
  ASSERT_EQ(first[0].status_code(), StatusCode{Status::Good});

  auto second = create_blocking(make_create_request(1, {{NodeId{0, 1001}, 43}}));
  ASSERT_EQ(second.size(), 1u);
  EXPECT_EQ(second[0].status_code(), StatusCode{Status::Good})
    << "the create after a suspending one was refused, so that one left the gate closed";
}

// The server-wide item count is claimed for a whole batch at once, before anything is known about
// whether the individual items will survive. Every slot claimed for an item that then fails has to
// go back, and it has to go back BEFORE the client is answered: a client told "one of your two items
// was created" and then reading the server's monitored-item count must not see the other one still
// counted. A slot that never comes back is permanent - the gauge only ever drifts upward, into a
// BadTooManyMonitoredItems for everybody.
TEST_F(CreateDeleteMonitoredItemsTest, ACreateGivesBackTheSlotsOfItemsThatFailedBeforeItAnswers)
{
  auto counters = std::make_shared<ServerSummaryCounters>();
  mCapabilities.maxMonitoredItems = 10;
  mCapabilities.maxMonitoredItemsPerSubscription = 10;

  auto sub = create_subscription();
  // One node that exists and one that does not: both are validated and both claim a slot, and only
  // the first survives its namespace registration.
  auto request = make_create_request(1, {{NodeId{0, 1000}, 1}, {NodeId{0, 9999}, 2}});

  std::promise<uint32_t> gaugeWhenAnswered;
  std::promise<std::vector<MonitoredItemCreateResult>> resultsPromise;
  sub->create_monitored_items_async(std::move(request),
    *mAddressSpace,
    mCapabilities,
    mSubscriptionLimits,
    nullptr,
    std::weak_ptr<EventBus>{},
    counters,
    [&](std::vector<MonitoredItemCreateResult> r)
    {
      gaugeWhenAnswered.set_value(counters->currentMonitoredItemCount.load());
      resultsPromise.set_value(std::move(r));
    });

  auto results = resultsPromise.get_future().get();
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(results[1].status_code().is_bad())
    << "the second item must fail its registration, or there is no unreturned slot to test for";

  EXPECT_EQ(gaugeWhenAnswered.get_future().get(), 1u)
    << "the slot claimed for the item that failed was still counted when the client was answered";
}

// --- SVC-10: CreateMonitoredItems never blocks the Subscription strand on a synchronous lookup -------

namespace
{
/// A namespace whose lookups complete on the pool, never inline: exactly the shape that deadlocks a
/// strand which waits synchronously for its own executor. If the strand has not yielded within the
/// watchdog delay the test thread runs the parked completion itself, so the test stays finite; the arm
/// then asserts that the pool, not the watchdog, delivered it.
class PostingNamespace final : public default_ns::Namespace
{
public:
  PostingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, executor), mExecutor(std::move(executor))
  {}

  std::optional<NodeResult> find_node(const NodeId&, std::optional<Duration>) override
  {
    return std::nullopt;  // always through the asynchronous batch path
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    std::vector<NodeId> ids(nodeIds.begin(), nodeIds.end());
    auto pending = std::make_shared<std::function<void()>>(
      [this, request, ids = std::move(ids), maxAge, callback = std::move(callback)]() mutable
      { default_ns::Namespace::find_nodes_async(request, ids, maxAge, std::move(callback)); });
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mParked.push_back(pending);
    }
    boost::asio::post(mExecutor,
      [this, pending]()
      {
        if (take(pending))
        {
          ++deliveredByPool;
          (*pending)();
        }
      });
  }

  /// The watchdog's escape hatch: runs every parked completion on the calling thread.
  void run_parked_directly()
  {
    std::vector<std::shared_ptr<std::function<void()>>> parked;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      parked.swap(mParked);
    }
    for (auto& completion : parked)
    {
      ++deliveredByWatchdog;
      (*completion)();
    }
  }

  std::atomic<size_t> deliveredByPool{0};
  std::atomic<size_t> deliveredByWatchdog{0};

private:
  bool take(const std::shared_ptr<std::function<void()>>& pending)
  {
    std::lock_guard<std::mutex> lock(mMutex);
    auto it = std::find(mParked.begin(), mParked.end(), pending);
    if (it == mParked.end())
      return false;
    mParked.erase(it);
    return true;
  }

  boost::asio::any_io_executor mExecutor;
  std::mutex mMutex;
  std::vector<std::shared_ptr<std::function<void()>>> mParked;
};
}  // namespace

class NonBlockingCreateTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace = AddressSpace::create("urn:test", mExecutor);
    mNamespace = std::make_shared<PostingNamespace>("urn:test:posting", mExecutor);
    mNsIndex = mAddressSpace->add_namespace_sync(mNamespace);
    // A Variable with an EURange Property (Part 8), the PercentDeadband prerequisite.
    auto variable = mAddressSpace->create_node_sync(variable_id(), NodeClass::Variable);
    auto range = mAddressSpace->create_node_sync(range_id(), NodeClass::Variable);
    auto rangeVariable = range.as<VariableAccessor>();
    ASSERT_TRUE(rangeVariable.has_value());
    rangeVariable->set_browse_name(QualifiedName{0, "EURange"});
    Range euRange;
    euRange.low() = 0.0;
    euRange.high() = 100.0;
    rangeVariable->write_value_sync(Variant{euRange});
    variable.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, range_id());
    // An event notifier Object.
    auto object = mAddressSpace->create_node_sync(object_id(), NodeClass::Object);
    auto objectAccessor = object.as<ObjectAccessor>();
    ASSERT_TRUE(objectAccessor.has_value());
    objectAccessor->set_event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
    // The event filter's select clause resolves BaseEventType/Message (as the access-control fixture builds).
    auto baseEventType =
      mAddressSpace->try_create_node_sync(NodeId{ObjectTypeId::BaseEventType}, NodeClass::ObjectType).value();
    baseEventType.set_browse_name(QualifiedName{0, String{"BaseEventType"}});
    auto message = mAddressSpace->try_create_node_sync(NodeId{mNsIndex, 3003u}, NodeClass::Variable).value();
    message.set_browse_name(QualifiedName{0, String{"Message"}});
    baseEventType.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, message.get_node_id(), true);
    mSubscription =
      Subscription::create(1, 1000, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  }

  void TearDown() override
  {
    mSubscription.reset();
    mNamespace.reset();  // released BEFORE the drain: a live namespace keeps the address space busy
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeId variable_id() const
  {
    return NodeId{mNsIndex, 3000};
  }

  NodeId range_id() const
  {
    return NodeId{mNsIndex, 3001};
  }

  NodeId object_id() const
  {
    return NodeId{mNsIndex, 3002};
  }

  /// Runs the create with a watchdog: if it has not finished within 2 s the parked completions are run
  /// on this thread so the test terminates, and the arm's assertion on deliveredByPool goes red.
  std::vector<MonitoredItemCreateResult> create_with_watchdog(CreateMonitoredItemsRequest request)
  {
    std::promise<std::vector<MonitoredItemCreateResult>> p;
    auto future = p.get_future();
    mSubscription->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      nullptr,
      std::weak_ptr<EventBus>{},
      nullptr,
      [&p](std::vector<MonitoredItemCreateResult> results) { p.set_value(std::move(results)); });
    for (int round = 0; round < 3 && future.wait_for(std::chrono::seconds{2}) != std::future_status::ready;
         ++round)
    {
      mNamespace->run_parked_directly();
    }
    EXPECT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "the create never completed";
    return future.valid() && future.wait_for(std::chrono::seconds{0}) == std::future_status::ready
             ? future.get()
             : std::vector<MonitoredItemCreateResult>{};
  }

  boost::asio::thread_pool mThreadPool{1};  // ONE thread: a synchronous wait on it can never be served
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<PostingNamespace> mNamespace;
  uint16_t mNsIndex{0};
  std::shared_ptr<Subscription> mSubscription;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
};

// @verifies AC-SVR-DA-022-THE-EURANGE-LOOKUP-NEVER-BLOCKS-THE-SUBSCRIPTION-STRAND
TEST_F(NonBlockingCreateTest, PercentDeadbandEuRangeLookupNeverBlocksTheStrand)
{
  CreateMonitoredItemsRequest request;
  request.subscription_id() = 1;
  MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = variable_id();
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = 1;
  item.requested_parameters().queue_size() = 1;
  DataChangeFilter filter;
  filter.deadband_type() = static_cast<uint32_t>(DeadbandType::Percent);
  filter.deadband_value() = 10.0;
  item.requested_parameters().filter().inner_unique_ptr() =
    std::make_unique<DataChangeFilter>(std::move(filter));
  request.items_to_create().push_back(std::move(item));

  auto results = create_with_watchdog(std::move(request));
  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].status_code().is_good())
    << "the EURange was found: " << to_string(results[0].status_code());
  EXPECT_EQ(mNamespace->deliveredByWatchdog.load(), 0u)
    << "a lookup completion had to be run by the watchdog: the strand was blocked waiting for its own "
       "executor";
  EXPECT_GE(mNamespace->deliveredByPool.load(), 1u);
}

// @verifies AC-SVR-DA-022-THE-EURANGE-LOOKUP-NEVER-BLOCKS-THE-SUBSCRIPTION-STRAND
TEST_F(NonBlockingCreateTest, EventItemNotifierLookupNeverBlocksTheStrand)
{
  CreateMonitoredItemsRequest request;
  request.subscription_id() = 1;
  MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = object_id();
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = 2;
  item.requested_parameters().queue_size() = 1;
  EventFilter filter;
  SimpleAttributeOperand operand;
  operand.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  operand.browse_path().push_back(QualifiedName{0, String{"Message"}});
  operand.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(operand));
  item.requested_parameters().filter().inner_unique_ptr() = std::make_unique<EventFilter>(std::move(filter));
  request.items_to_create().push_back(std::move(item));

  auto results = create_with_watchdog(std::move(request));
  ASSERT_EQ(results.size(), 1u);
  EXPECT_TRUE(results[0].status_code().is_good()) << to_string(results[0].status_code());
  EXPECT_EQ(mNamespace->deliveredByWatchdog.load(), 0u)
    << "a lookup completion had to be run by the watchdog: the strand was blocked waiting for its own "
       "executor";
}
