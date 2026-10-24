// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11 (Subscription) - DeleteMonitoredItems cluster.
//
// Production: sdk/implementation/server/subscription/ua_subscription.cpp:1240-1320.
//
// These pins drive the public `delete_monitored_items_async` entry point so
// the per-namespace `co_await` boundary is exercised through the FakeNamespace
// parked-callback queue. Each pin pre-populates `mMonitoredItems` directly
// (via the test-access friend) so the delete path can be examined in
// isolation from CreateMonitoredItems.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_namespace.h"
#include "ua_address_space.h"
#include "ua_event_bus.h"
#include "ua_monitored_item.h"
#include "ua_server_counters.h"
#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = ::ua::server::SubscriptionTestAccess;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
//
// Mirrors the SubscriptionPin fixture pattern. Adds an AddressSpace built from
// a FakeNamespace so the production `delete_monitored_items` body can resolve
// `addressSpace.namespace_array().get_namespace(nsIndex)` for items with a
// non-zero namespaceIndex/namespaceHandle. The fake is at index 1 (index 0 is
// the default namespace inserted by AddressSpace::initialise()).

class DeleteMonitoredItemsPin : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<test_helpers::FakeNamespace> mFakeNs;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<Subscription> mSubscription;

  std::thread::id mTestThreadId;

  static constexpr uint16_t sFakeNsIndex = 2;

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mTestThreadId = std::this_thread::get_id();

    mFakeNs = test_helpers::FakeNamespace::create("urn:test:fake-ns");
    mAddressSpace.emplace(test_helpers::make_address_space_with_fake_namespace(mExecutor, mFakeNs));
    ASSERT_EQ(mFakeNs->index(), sFakeNsIndex)
      << "FakeNamespace must be at index 1 (default ns occupies index 0).";
  }

  void TearDown() override
  {
    mSubscription.reset();
    mThreadPool.join();
  }

  std::shared_ptr<Subscription> create_subscription()
  {
    mSubscription = Subscription::create(/*subscriptionId=*/
      1,
      /*publishingInterval=*/1'000'000.0,
      /*lifetimeCount=*/100,
      /*maxKeepAliveCount=*/3,
      /*maxNotificationsPerPublish=*/0,
      /*publishingEnabled=*/true,
      /*priority=*/0,
      mExecutor,
      [](IntegerId) {},
      [](IntegerId) {});
    return mSubscription;
  }

  /// Add a monitored item directly to the subscription's strand-owned map.
  /// Bypasses CreateMonitoredItems - used by the delete pins to lock the
  /// delete path in isolation.
  IntegerId add_variable_item(MonitoringHandle nsHandle, uint16_t nsIndex = sFakeNsIndex)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->clientHandle = 100 + static_cast<uint32_t>(g.monitored_items().size());
        item->queueSize = 10;
        item->namespaceHandle = nsHandle;
        item->namespaceIndex = nsIndex;
        return g.add_monitored_item(std::move(item));
      });
  }

  IntegerId add_event_item(uint64_t eventBusHandle)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->clientHandle = 100 + static_cast<uint32_t>(g.monitored_items().size());
        item->queueSize = 10;
        item->isEventItem = true;
        item->eventBusHandle = eventBusHandle;
        return g.add_monitored_item(std::move(item));
      });
  }

  /// Convenience: drive `delete_monitored_items_async` and synchronously
  /// receive the per-id status vector. The promise is set on the
  /// subscription strand thread (a pool thread); the test thread blocks
  /// on the future on the main test thread ("no blocking on
  /// pool" rule).
  std::vector<StatusCode> drive_delete_async(std::vector<IntegerId> ids,
    std::weak_ptr<EventBus> eventBus = {}, std::shared_ptr<ServerSummaryCounters> summaryCounters = nullptr)
  {
    std::promise<std::vector<StatusCode>> p;
    auto fut = p.get_future();
    mSubscription->delete_monitored_items_async(std::move(ids),
      *mAddressSpace,
      std::move(eventBus),
      std::move(summaryCounters),
      [&p](std::vector<StatusCode> r) mutable { p.set_value(std::move(r)); });
    return fut.get();
  }
};

}  // namespace

// ===========================================================================
// DEL-A - Unknown monitored-item id yields BadMonitoredItemIdInvalid.
// ===========================================================================
//
// Runbook section 4.2 DEL-A; ua_subscription.cpp:1257.
// `mMonitoredItems.find()` returns end() -> result entry is set to
// BadMonitoredItemIdInvalid. No namespace deletion is dispatched.

TEST_F(DeleteMonitoredItemsPin, DeleteUnknownMonitoredItemIdYieldsBadMonitoredItemIdInvalid)
{
  create_subscription();
  // Note: NO items added - every requested id is unknown.

  auto results = drive_delete_async({/*unknownId=*/42u});

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::BadMonitoredItemIdInvalid})
    << "unknown monitored-item id must surface BadMonitoredItemIdInvalid (cpp:1257)";

  // No namespace deletion should have been dispatched for an unknown id.
  EXPECT_EQ(mFakeNs->pending_delete_monitoring_count(), 0u)
    << "unknown id must not invoke namespace delete_monitoring";
}

// ===========================================================================
// DEL-B - Event-item delete deregisters from the EventBus.
// ===========================================================================
//
// Runbook section 4.2 DEL-B; ua_subscription.cpp:1264-1266.
// Event items take a different branch from variable items: they call
// `eventBus->deregister_event_item(handle)` and DO NOT enqueue a
// namespace deletion. We observe via EventBus::has_event_interest() -
// register a real handle, drive the delete, and confirm the bus reports
// no remaining interest.

TEST_F(DeleteMonitoredItemsPin, DeleteEventItemDeregistersFromEventBus)
{
  create_subscription();
  auto eventBus = std::make_shared<EventBus>(*mAddressSpace);

  // Register a real event item to obtain a non-zero EventMonitoringHandle.
  auto handle = eventBus->register_event_item(/*monitoredNode=*/NodeId{1, "ServerNode"},
    /*monitoredItemId=*/1u,
    /*subscriptionId=*/1u,
    [](IntegerId, std::shared_ptr<const BaseEvent>) {});
  ASSERT_NE(handle, 0u);
  ASSERT_TRUE(eventBus->has_event_interest());

  auto miId = add_event_item(handle);

  auto results = drive_delete_async({miId}, eventBus);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});
  // deregister_event_item posts the registry erase + interest-flag reconcile to the EventBus
  // dispatch strand, so has_event_interest() clears ASYNCHRONOUSLY. Wait for it rather than assuming
  // the delete cleared interest synchronously - that timing assumption raced and failed under
  // ASan/shuffle in CI (the strand post hadn't been processed when the assertion ran).
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (eventBus->has_event_interest() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(1ms);
  }
  EXPECT_FALSE(eventBus->has_event_interest())
    << "event item delete must deregister from the EventBus (cpp:1522)";

  // Event items do NOT route through namespace delete_monitoring.
  EXPECT_EQ(mFakeNs->pending_delete_monitoring_count(), 0u);
}

// ===========================================================================
// DEL-C - Variable-item delete dispatches Namespace::delete_monitoring.
// ===========================================================================
//
// Runbook section 4.2 DEL-C; ua_subscription.cpp:1270, 1296.
// A non-zero namespaceHandle on a non-event item means the per-namespace
// dispatch loop calls `delete_monitoring_coro(mStrand, [handle])` - observed
// here as a parked entry on the FakeNamespace, identified by handle value.
// The pin then drives the parked callback to completion and asserts the
// per-id result is Good.

TEST_F(DeleteMonitoredItemsPin, DeleteVariableItemCallsNamespaceDeleteMonitoring)
{
  create_subscription();
  constexpr MonitoringHandle handle = 7u;
  auto miId = add_variable_item(handle);

  // Drive delete on a worker thread so the test thread can drain the parked
  // callback queue. We do NOT call drive_delete_async() here because the
  // production body parks the namespace call before the user callback fires.
  std::promise<std::vector<StatusCode>> resultPromise;
  auto resultFut = resultPromise.get_future();
  mSubscription->delete_monitored_items_async({miId},
    *mAddressSpace,
    /*eventBus=*/std::weak_ptr<EventBus>{},
    /*summaryCounters=*/nullptr,
    [&resultPromise](std::vector<StatusCode> r) mutable { resultPromise.set_value(std::move(r)); });

  // Wait for the namespace delete_monitoring to be parked. The body posts to
  // the subscription strand, which then awaits delete_monitoring_coro, so we
  // poll briefly.
  for (int i = 0; i < 200 && mFakeNs->pending_delete_monitoring_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_EQ(mFakeNs->pending_delete_monitoring_count(), 1u)
    << "production body must park exactly one namespace delete_monitoring (cpp:1296)";

  auto record = mFakeNs->pending_delete_monitoring_at(0);
  ASSERT_EQ(record.handles.size(), 1u);
  EXPECT_EQ(record.handles[0], handle) << "namespace must receive the item's namespaceHandle (cpp:1270)";

  // Complete the parked namespace call so the coroutine resumes.
  ua::BatchResult<ua::VoidResult> ok;
  ok.batchStatus = ua::VoidResult{};
  ok.items.push_back(ua::VoidResult{});
  mFakeNs->complete_pending_delete_monitoring(0, std::move(ok));

  auto results = resultFut.get();
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});
}

// ===========================================================================
// DEL-F - Threading affinity: user callback fires on the subscription strand.
// ===========================================================================
//
// Runbook section 4.2 DEL-F (same shape as CMI-Q). The `delete_monitored_items_async`
// callback must NOT run on the test/main thread - it runs on the strand
// (which is dispatched on a pool thread). Pin captures the executing thread
// inside the user callback and asserts it differs from the test thread id.

TEST_F(DeleteMonitoredItemsPin, DeleteCallbackOnSubscriptionStrand)
{
  create_subscription();
  add_variable_item(/*nsHandle=*/0);  // namespaceHandle=0 -> no namespace dispatch

  std::promise<std::thread::id> tidPromise;
  auto tidFut = tidPromise.get_future();
  mSubscription->delete_monitored_items_async({/*item*/ 1u},
    *mAddressSpace,
    /*eventBus=*/std::weak_ptr<EventBus>{},
    /*summaryCounters=*/nullptr,
    [&tidPromise](std::vector<StatusCode>) mutable { tidPromise.set_value(std::this_thread::get_id()); });

  auto callbackTid = tidFut.get();
  EXPECT_NE(callbackTid, mTestThreadId)
    << "delete_monitored_items_async callback must fire on the subscription "
       "strand thread (a pool thread), not the test thread";
  EXPECT_NE(callbackTid, std::thread::id{}) << "callback thread id must be a real (joined) pool thread";
}

}  // namespace ua::test::behaviour_pins
