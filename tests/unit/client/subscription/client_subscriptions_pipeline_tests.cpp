// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::SubscriptionsPipeline (section 8.4) - slice 1: the strand component that
// wires the PublishPump + AckQueue + per-Subscription SequenceTracker into a running publish loop.
//
// Falsifiability: a stub that never pumps fails StartPumpsPublishes; one that never registers a
// Subscription fails AddSubscriptionRegisters; one that never acks fails PublishResponseAcksSubscription.

#include "ua_client_subscriptions_pipeline.h"
#include "ua_client_subscriptions_pipeline_test_access.h"

#include "fake_connection_ops.h"

#include "ua_ack_queue.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_deadband_type.h"
#include "ua_read_response.h"
#include "ua_error_detail.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_read_value_id.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using ua::client::detail::MonitoredItemDescriptor;
using ua::client::detail::PumpState;
using ua::client::detail::RecoveryDescriptor;
using ua::client::detail::SequenceClass;
using ua::client::detail::should_deliver;
using ua::client::detail::SubscriptionAcknowledgement;
using ua::client::detail::SubscriptionsPipeline;
using ua::test_helpers::FakeSupportOps;
using ua::test_helpers::FakeWireOps;

// The Publish/Republish send interface recorder (the renamed former SubscriptionsPipelineHost).
using RecordingHost = ua::test_helpers::FakeSubscriptionOps;

// Captures the messages the pipeline logs, so tests can assert the DISTINCT terminator handling (not just
// that the drain ended).
struct RecordingLogSink : public ua::LogSink
{
  std::vector<std::string> messages;

  void log(const ua::LogEntry& entry) override
  {
    messages.push_back(entry.message);
  }

  [[nodiscard]] bool has_message_containing(std::string_view needle) const
  {
    for (const auto& message : messages)
      if (message.find(needle) != std::string::npos)
        return true;
    return false;
  }
};

struct Fixture
{
  struct RecoverySignal
  {
    std::uint32_t subscriptionId = 0;
    ua::StatusCode failure;
    std::uint32_t proposed = 0;
  };

  boost::asio::io_context ctx;
  std::shared_ptr<RecordingHost> host = std::make_shared<RecordingHost>();
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<FakeSupportOps> support = std::make_shared<FakeSupportOps>();
  std::shared_ptr<RecordingLogSink> logSink = std::make_shared<RecordingLogSink>();
  // Records the Subscription ids the pipeline signals as event-loss (Finding 2 / CL-AC-003). The callback
  // fires on the pipeline strand, which the single-threaded ctx.run() dispatches on the test thread, so a
  // plain vector needs no lock.
  std::vector<std::uint32_t> lossSignals;
  // Records the nodes the pipeline routes into the in-band SemanticsChanged invalidation interface
  // (CL-DA-010). Fires on the pipeline strand, dispatched on the test thread by the single-threaded
  // ctx.run().
  std::vector<ua::NodeId> semanticChangeSignals;
  std::vector<std::pair<std::uint32_t, ua::StatusCode>> terminationSignals;
  std::vector<RecoverySignal> recoverySignals;

  std::shared_ptr<SubscriptionsPipeline> make()
  {
    support->executor = ctx.get_executor();
    auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
    return SubscriptionsPipeline::create(
      ctx.get_executor(),
      host,
      wireOps,
      support,
      ua::Logger{logSink, level, "test"},
      [this](std::uint32_t subscriptionId) { lossSignals.push_back(subscriptionId); },
      [this](ua::NodeId node) { semanticChangeSignals.push_back(std::move(node)); },
      [this](std::uint32_t subscriptionId, ua::StatusCode reason)
      { terminationSignals.emplace_back(subscriptionId, std::move(reason)); },
      [this](std::uint32_t subscriptionId, ua::StatusCode failure, std::uint32_t proposed)
      { recoverySignals.push_back(RecoverySignal{subscriptionId, std::move(failure), proposed}); });
  }
};

// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST(SubscriptionsPipeline, OversizedPublishAdjustsEveryServerBackedSubscription)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, 100.0, 100);
  pipeline->add_subscription_async(8, 200.0, 40);
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadResponseTooLarge});
  f.ctx.run();

  ASSERT_EQ(f.host->adjustments.size(), 2u);
  const auto adjustment7 = std::find_if(f.host->adjustments.begin(),
    f.host->adjustments.end(),
    [](const RecordingHost::Adjustment& adjustment) { return adjustment.subscriptionId == 7; });
  const auto adjustment8 = std::find_if(f.host->adjustments.begin(),
    f.host->adjustments.end(),
    [](const RecordingHost::Adjustment& adjustment) { return adjustment.subscriptionId == 8; });
  ASSERT_NE(adjustment7, f.host->adjustments.end());
  ASSERT_NE(adjustment8, f.host->adjustments.end());
  EXPECT_DOUBLE_EQ(adjustment7->publishingInterval, 100.0);
  EXPECT_EQ(adjustment7->maxNotificationsPerPublish, 50u);
  EXPECT_DOUBLE_EQ(adjustment8->publishingInterval, 200.0);
  EXPECT_EQ(adjustment8->maxNotificationsPerPublish, 20u);
  EXPECT_TRUE(f.recoverySignals.empty());
}

// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST(SubscriptionsPipeline, OversizedRepublishAdjustsOnlyItsSubscription)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, 100.0, 64);
  pipeline->add_subscription_async(8, 200.0, 32);
  f.ctx.run();
  f.ctx.restart();

  // Sequence 3 reveals a gap at 1 and starts a Republish for Subscription 7.
  pipeline->on_publish_response_async(7, 3, true, true, false, [](SequenceClass) {});
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->republishes, (std::vector<std::pair<std::uint32_t, std::uint32_t>>{{7, 1}}));

  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::BadResponseTooLarge});
  f.ctx.run();

  ASSERT_EQ(f.host->adjustments.size(), 1u);
  EXPECT_EQ(f.host->adjustments.front().subscriptionId, 7u);
  EXPECT_EQ(f.host->adjustments.front().maxNotificationsPerPublish, 32u);
}

// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST(SubscriptionsPipeline, NonOversizedFailuresNeverAdjustNotificationLimit)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, 100.0, 64);
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadTimeout});
  f.ctx.run();
  f.ctx.restart();
  pipeline->on_publish_response_async(7, 3, true, true, false, [](SequenceClass) {});
  f.ctx.run();
  f.ctx.restart();
  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();

  EXPECT_TRUE(f.host->adjustments.empty());
  EXPECT_TRUE(f.recoverySignals.empty());
}

// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST(SubscriptionsPipeline, OversizedRecoveryHalvesThreeTimesThenHandsOffAtCap)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, 100.0, 16);
  f.ctx.run();

  for (int attempt = 0; attempt < 4; ++attempt)
  {
    f.ctx.restart();
    pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadResponseTooLarge});
    f.ctx.run();
  }

  ASSERT_EQ(f.host->adjustments.size(), 3u);
  EXPECT_EQ(f.host->adjustments[0].maxNotificationsPerPublish, 8u);
  EXPECT_EQ(f.host->adjustments[1].maxNotificationsPerPublish, 4u);
  EXPECT_EQ(f.host->adjustments[2].maxNotificationsPerPublish, 2u);
  ASSERT_EQ(f.recoverySignals.size(), 1u);
  EXPECT_EQ(f.recoverySignals.front().subscriptionId, 7u);
  EXPECT_EQ(f.recoverySignals.front().failure.as_status(), ua::Status::BadResponseTooLarge);
  EXPECT_EQ(f.recoverySignals.front().proposed, 1u);
}

// The automatic ModifySubscription answered Uncertain with its response: the server holds the new cap, as the
// Connection's retained tuning records, so the pipeline applies it too and the next oversized failure halves
// from it; nothing is handed to the observer.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(SubscriptionsPipeline, AnUncertainAdjustmentAnswerAppliesTheNewCap)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, 100.0, 16);
  f.ctx.run();
  f.host->adjustmentOutcomes.push_back(ua::StatusCode{ua::Status::UncertainLastUsableValue});

  for (int attempt = 0; attempt < 2; ++attempt)
  {
    f.ctx.restart();
    pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadResponseTooLarge});
    f.ctx.run();
  }

  ASSERT_EQ(f.host->adjustments.size(), 2u);
  EXPECT_EQ(f.host->adjustments[0].maxNotificationsPerPublish, 8u);
  EXPECT_EQ(f.host->adjustments[1].maxNotificationsPerPublish, 4u)
    << "the second step halves the applied cap";
  EXPECT_TRUE(f.recoverySignals.empty());
}

// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST(SubscriptionsPipeline, UnboundedRecoveryMovesToOneThenHandsOffWithoutZero)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, 100.0, 0);
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadResponseTooLarge});
  f.ctx.run();
  f.ctx.restart();
  pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadResponseTooLarge});
  f.ctx.run();
  f.ctx.restart();
  pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadResponseTooLarge});
  f.ctx.run();

  ASSERT_EQ(f.host->adjustments.size(), 1u);
  EXPECT_EQ(f.host->adjustments.front().maxNotificationsPerPublish, 1u);
  ASSERT_EQ(f.recoverySignals.size(), 1u);
  EXPECT_EQ(f.recoverySignals.front().proposed, 1u);
}

// @verifies CL-SUB-005
// @relation(CL-SUB-005, scope=function)
TEST(SubscriptionsPipeline, FailedAutomaticModifyPreservesOriginalOversizeDetailForObserver)
{
  Fixture f;
  auto pipeline = f.make();
  const ua::StatusCode original{ua::Status::BadResponseTooLarge,
    ua::make_error_detail("OversizedPublish", "the Publish response exceeded the message limit", "wire")};
  f.host->adjustmentOutcomes.push_back(ua::StatusCode{ua::Status::BadTimeout,
    ua::make_error_detail("ModifyRejected", "the automatic ModifySubscription failed", "wire")});
  pipeline->add_subscription_async(7, 100.0, 64);
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_failure_async(original);
  f.ctx.run();

  ASSERT_EQ(f.host->adjustments.size(), 1u);
  ASSERT_EQ(f.recoverySignals.size(), 1u);
  EXPECT_EQ(f.recoverySignals.front().failure.as_status(), ua::Status::BadResponseTooLarge);
  EXPECT_EQ(f.recoverySignals.front().failure.shared_detail(), original.shared_detail());
  EXPECT_EQ(f.recoverySignals.front().proposed, 32u);
  EXPECT_TRUE(f.logSink->has_message_containing("automatic oversized-message ModifySubscription failed"));
}

TEST(SubscriptionsPipeline, StartsIdle)
{
  Fixture f;
  auto pipeline = f.make();
  ASSERT_NE(pipeline->info(), nullptr);
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Idle);
  EXPECT_EQ(pipeline->info()->subscriptionCount, 0u);
}

TEST(SubscriptionsPipeline, AddSubscriptionRegisters)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(42, /*publishingInterval=*/500.0);
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->subscriptionCount, 1u);
}

// @verifies CL-SUB-008
// @relation(CL-SUB-008, scope=function)
TEST(SubscriptionsPipeline, BadTimeoutStatusChangeAtomicallyTerminatesOnlyTargetSubscription)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<ua::DataValue> terminatedItems;
  std::vector<ua::DataValue> survivingItems;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_subscription_async(8, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(7,
    /*clientHandle=*/70,
    ua::NodeId{2, 70},
    [&terminatedItems](ua::DataValue value) { terminatedItems.push_back(std::move(value)); });
  pipeline->add_monitored_item_async(8,
    /*clientHandle=*/80,
    ua::NodeId{2, 80},
    [&survivingItems](ua::DataValue value) { survivingItems.push_back(std::move(value)); });
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // Queue an acknowledgement and begin a Republish drain for the target. Termination must release both.
  pipeline->on_publish_response_async(7,
    /*sequenceNumber=*/1,
    /*hasNotifications=*/true,
    /*hasAvailableSequenceNumbers=*/true,
    /*tooManyPublishRequests=*/false);
  pipeline->on_publish_response_async(7,
    /*sequenceNumber=*/3,
    /*hasNotifications=*/true,
    /*hasAvailableSequenceNumbers=*/true,
    /*tooManyPublishRequests=*/false);
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->republishes, (std::vector<std::pair<std::uint32_t, std::uint32_t>>{{7, 2}}));

  const ua::StatusCode timeout{ua::Status::BadTimeout,
    ua::make_error_detail("ServerSubscriptionLifetimeExpired", "server closed subscription 7", "wire")};
  pipeline->on_publish_response_async(7,
    /*sequenceNumber=*/2,
    /*hasNotifications=*/true,
    /*hasAvailableSequenceNumbers=*/true,
    /*tooManyPublishRequests=*/false,
    {},
    timeout);
  f.ctx.run();
  f.ctx.restart();

  ASSERT_EQ(terminatedItems.size(), 1u);
  ASSERT_TRUE(terminatedItems.front().status().has_value());
  EXPECT_EQ(terminatedItems.front().status()->as_status(), ua::Status::BadSubscriptionIdInvalid);
  ASSERT_NE(terminatedItems.front().status()->shared_detail(), nullptr);
  EXPECT_EQ(terminatedItems.front().status()->shared_detail()->innerStatus, timeout.value())
    << "the manufactured monitored-item failure chains the server's terminal status";
  EXPECT_TRUE(survivingItems.empty()) << "termination is scoped to the target Subscription";
  EXPECT_EQ(pipeline->info()->subscriptionCount, 1u);
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 1u);
  ASSERT_EQ(f.terminationSignals.size(), 1u);
  EXPECT_EQ(f.terminationSignals.front().first, 7u);
  EXPECT_EQ(f.terminationSignals.front().second.as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(f.terminationSignals.front().second.shared_detail(), timeout.shared_detail())
    << "the observer receives the original rich terminal reason";

  // A completion from the pre-termination Republish is now stale and cannot revive or mutate the dead id.
  pipeline->on_republish_response_async(7, /*sequenceNumber=*/2, ua::StatusCode{ua::Status::Good});
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->subscriptionCount, 1u);

  // The stale pending acknowledgement was purged. Exactly one final acknowledgement remains: the terminal
  // NotificationMessage itself, as required when availableSequenceNumbers is non-empty.
  std::size_t terminalAcknowledgements = 0;
  for (const auto& batch : f.host->publishes)
    for (const auto& acknowledgement : batch)
      if (acknowledgement.subscriptionId == 7u && acknowledgement.sequenceNumber == 2u)
      {
        ++terminalAcknowledgements;
      }
  EXPECT_EQ(terminalAcknowledgements, 1u);
}

// A StatusChangeNotification of Good_SubscriptionTransferred says the Subscription no longer exists on this
// Session: it ends exactly as Bad_Timeout does, and the termination carries the server's Good code unchanged.
// @relation(AC-CL-STATUS-ROUTING-01-SUBSCRIPTION-TRANSFERRED-REACHES-THE-APPLICATION, scope=function)
TEST(SubscriptionsPipeline, SubscriptionTransferredStatusChangeTerminatesOnlyTargetSubscription)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<ua::DataValue> transferredItems;
  std::vector<ua::DataValue> survivingItems;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_subscription_async(8, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(7,
    /*clientHandle=*/70,
    ua::NodeId{2, 70},
    [&transferredItems](ua::DataValue value) { transferredItems.push_back(std::move(value)); });
  pipeline->add_monitored_item_async(8,
    /*clientHandle=*/80,
    ua::NodeId{2, 80},
    [&survivingItems](ua::DataValue value) { survivingItems.push_back(std::move(value)); });
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  const ua::StatusCode transferred{ua::Status::GoodSubscriptionTransferred};
  pipeline->on_publish_response_async(7,
    /*sequenceNumber=*/1,
    /*hasNotifications=*/true,
    /*hasAvailableSequenceNumbers=*/false,
    /*tooManyPublishRequests=*/false,
    {},
    transferred);
  f.ctx.run();
  f.ctx.restart();

  ASSERT_EQ(f.terminationSignals.size(), 1u) << "the transferred Subscription ends on this Session";
  EXPECT_EQ(f.terminationSignals.front().first, 7u);
  EXPECT_EQ(f.terminationSignals.front().second.value(), transferred.value())
    << "the observer receives the server's Good code, not a Bad one";
  EXPECT_EQ(pipeline->info()->subscriptionCount, 1u);
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 1u);
  EXPECT_TRUE(survivingItems.empty()) << "termination is scoped to the target Subscription";
}

// @verifies CL-SUB-008
// @relation(CL-SUB-008, scope=function)
TEST(SubscriptionsPipeline, BadTimeoutForLastSubscriptionHoldsPublishPump)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->publishes.size(), 2u);

  pipeline->on_publish_response_async(7,
    /*sequenceNumber=*/1,
    /*hasNotifications=*/true,
    /*hasAvailableSequenceNumbers=*/true,
    /*tooManyPublishRequests=*/false,
    {},
    ua::StatusCode{ua::Status::BadTimeout});
  f.ctx.run();

  EXPECT_EQ(pipeline->info()->subscriptionCount, 0u);
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Idle);
  ASSERT_EQ(f.host->publishes.size(), 3u)
    << "the terminal response emits one final Publish for its required acknowledgement, then holds";
  ASSERT_EQ(f.host->publishes.back().size(), 1u);
  EXPECT_EQ(f.host->publishes.back().front().subscriptionId, 7u);
  EXPECT_EQ(f.host->publishes.back().front().sequenceNumber, 1u);
}

// A server over its Publish queue limit answers with a ServiceFault carrying Bad_TooManyPublishRequests,
// which reaches the pipeline as a failed Publish, not as a typed PublishResponse. OPC 10000-4 5.14.5.1: the
// Client shall not issue another Publish until an outstanding one returns. Replacing the faulted Publish at
// once makes the server evict the next one, which is answered at once, and so on at round-trip rate.
// @relation(AC-CL-SUB-004-SERVICE-FAULT-PAUSES-THE-PUMP, scope=function)
TEST(SubscriptionsPipeline, ATooManyPublishRequestsServiceFaultPausesThePump)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->publishes.size(), 2u);

  pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadTooManyPublishRequests});
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Paused);
  EXPECT_EQ(f.host->publishes.size(), 2u) << "a Publish was issued while one was still outstanding";

  // Any other failed Publish is still replaced.
  pipeline->on_publish_failure_async(ua::StatusCode{ua::Status::BadTimeout});
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Running);
  EXPECT_EQ(f.host->publishes.size(), 4u) << "the returned Publish ends the pause and the pump refills";
}

// @verifies CL-SUB-018
// @relation(CL-SUB-018, scope=function)
TEST(SubscriptionsPipeline, StartPumpsPublishesToTarget)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->start_async();
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Running);
  ASSERT_EQ(f.host->publishes.size(), 2u) << "always-on pipelining keeps target=2 Publishes outstanding";
  EXPECT_TRUE(f.host->publishes[0].empty()) << "the first Publishes carry no acks";
}

// CL-SUB-015: the SINGLE per-Connection Publish pump sizes on the TOTAL monitored-item count across ALL
// subscriptions - target = max(2, ceil(total / 100)). Spreading 250 items over two subscriptions must yield
// ceil(250/100) = 3; a per-Subscription pump would instead compute max(2, ceil(100/100)) = 2 for sub 7 and
// max(2, ceil(150/100)) = 2 for sub 8 and never reach 3, so 3 is the value that discriminates single-pump
// TOTAL sizing from per-Sub sizing. Deleting the 150-item subscription drops the total to 100, so the target
// returns to the floor of 2. @verifies CL-SUB-015
TEST(SubscriptionsPipeline, PumpSizeScalesWithTotalMonitoredItemsAcrossSubscriptions)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_subscription_async(8, /*publishingInterval=*/500.0);
  for (std::uint32_t clientHandle = 1; clientHandle <= 100; ++clientHandle)
  {
    pipeline->add_monitored_item_async(7, clientHandle, ua::NodeId{2, clientHandle}, [](ua::DataValue) {});
  }
  for (std::uint32_t clientHandle = 101; clientHandle <= 250; ++clientHandle)
  {
    pipeline->add_monitored_item_async(8, clientHandle, ua::NodeId{2, clientHandle}, [](ua::DataValue) {});
  }
  pipeline->start_async();
  f.ctx.run();

  ASSERT_EQ(pipeline->info()->monitoredItemCount, 250u) << "all 250 items registered on the single pipeline";
  EXPECT_EQ(pipeline->info()->pumpTarget, 3u)
    << "one shared pump sizes on the TOTAL 250 items: max(2, ceil(250/100)) = 3";
  EXPECT_EQ(pipeline->info()->outstandingPublishes, 3u) << "a Running pump fills to the sized target";

  f.ctx.restart();
  pipeline->remove_subscription_async(8);  // cascade-drops its 150 items -> 100 remain
  f.ctx.run();
  ASSERT_EQ(pipeline->info()->monitoredItemCount, 100u) << "the 150-item subscription's items were purged";
  EXPECT_EQ(pipeline->info()->pumpTarget, 2u) << "100 items -> max(2, ceil(100/100)) = 2 (the floor)";
}

// CL-SUB-015: the SINGLE-item removal path (remove_monitored_item_async) must also re-size the pump. 201
// items sit at target ceil(201/100)=3; removing exactly one item crosses back to 200 -> ceil(200/100)=2, so a
// single-item remove that failed to re-size would leave the target stuck at 3. Its completion is also the
// rollback boundary used by AC-CL-MI-012: it must observe the published post-removal state.
// @verifies CL-SUB-015
// @relation(AC-CL-MI-012-NO-LOCAL-DATATYPE-PRE-FLIGHT, scope=function)
TEST(SubscriptionsPipeline, SingleItemRemovalResizesPump)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  for (std::uint32_t clientHandle = 1; clientHandle <= 201; ++clientHandle)
  {
    pipeline->add_monitored_item_async(7, clientHandle, ua::NodeId{2, clientHandle}, [](ua::DataValue) {});
  }
  pipeline->start_async();
  f.ctx.run();
  ASSERT_EQ(pipeline->info()->monitoredItemCount, 201u);
  EXPECT_EQ(pipeline->info()->pumpTarget, 3u) << "201 items -> max(2, ceil(201/100)) = 3";

  std::optional<ua::VoidResult> removalResult;
  std::size_t countAtCompletion = 201;
  std::size_t targetAtCompletion = 3;
  f.ctx.restart();
  pipeline->remove_monitored_item_async(201,
    [&pipeline, &removalResult, &countAtCompletion, &targetAtCompletion](ua::VoidResult result)
    {
      const auto info = pipeline->info();
      countAtCompletion = info->monitoredItemCount;
      targetAtCompletion = info->pumpTarget;
      removalResult.emplace(std::move(result));
    });
  f.ctx.run();

  ASSERT_TRUE(removalResult.has_value());
  EXPECT_TRUE(removalResult->is_good());
  EXPECT_EQ(countAtCompletion, 200u) << "completion must follow monitored-item snapshot publication";
  EXPECT_EQ(targetAtCompletion, 2u) << "completion must follow resized-pump snapshot publication";
  ASSERT_EQ(pipeline->info()->monitoredItemCount, 200u);
  EXPECT_EQ(pipeline->info()->pumpTarget, 2u)
    << "a single-item removal must re-size: 200 items -> max(2, ceil(200/100)) = 2";
}

// @verifies CL-SUB-006
// @verifies CL-SUB-018
// @relation(CL-SUB-006, CL-SUB-018, scope=function)
TEST(SubscriptionsPipeline, PublishResponseRefillsAndAcksSubscription)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->publishes.size(), 2u);

  // A response for sub 7 at seq 1 (server has a retransmission queue) refills the pump and queues an ack
  // that rides the next Publish.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();

  ASSERT_EQ(f.host->publishes.size(), 3u) << "the response refills the pump to target";
  ASSERT_EQ(f.host->publishes[2].size(), 1u) << "the refill Publish carries the queued ack";
  EXPECT_EQ(f.host->publishes[2][0].subscriptionId, 7u);
  EXPECT_EQ(f.host->publishes[2][0].sequenceNumber, 1u);
}

// CL-SUB-002 / CL-RECONN-004: a sequence gap starts a Republish drain from nextExpected, acking each
// recovered message and stepping forward until Bad_MessageNotAvailable ends it.
// @verifies CL-RECONN-004
// @relation(CL-RECONN-004, scope=function)
TEST(SubscriptionsPipeline, GapStartsRepublishDrain)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // A Publish for sub 7 at seq 3 (expected 1) is a gap: drain [1..] via Republish.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->on_republish_response_async(/*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(/*sub=*/7, /*seq=*/2, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(/*sub=*/7, /*seq=*/3, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/4, ua::StatusCode{ua::Status::BadMessageNotAvailable});  // terminator
  f.ctx.run();

  // Republish walked 1,2,3 (recovered) then 4 (not available -> drain ends).
  const std::vector<std::pair<std::uint32_t, std::uint32_t>> expected{{7, 1}, {7, 2}, {7, 3}, {7, 4}};
  EXPECT_EQ(f.host->republishes, expected);
}

// section 3.1 F5: Bad_SubscriptionIdInvalid (the Subscription is gone server-side) ends the drain distinctly
// - it must NOT be treated as a clean drain that continues; the drain stops with no further Republish.
TEST(SubscriptionsPipeline, RepublishBadSubscriptionIdEndsDrain)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::BadSubscriptionIdInvalid});
  f.ctx.run();

  // Only the initial gap-triggered Republish (seq 1) was issued; the drain stopped on the fault.
  const std::vector<std::pair<std::uint32_t, std::uint32_t>> expected{{7, 1}};
  EXPECT_EQ(f.host->republishes, expected);
  // Handled DISTINCTLY (not as the clean Bad_MessageNotAvailable terminator): the sub-gone case is logged.
  EXPECT_TRUE(f.logSink->has_message_containing("Bad_SubscriptionIdInvalid"));
}

// section 3.1 F6: a non-terminator fault mid-drain (e.g. the channel blips again) ends the drain rather than
// looping or being mistaken for the Bad_MessageNotAvailable terminator.
TEST(SubscriptionsPipeline, RepublishTransportFaultEndsDrain)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::BadConnectionClosed});
  f.ctx.run();

  const std::vector<std::pair<std::uint32_t, std::uint32_t>> expected{{7, 1}};
  EXPECT_EQ(f.host->republishes, expected);
  // Surfaced (not silently discarded) and NOT as the clean terminator: logged as a non-terminator status.
  EXPECT_TRUE(f.logSink->has_message_containing("non-terminator status"));
}

// section 3.1 F4: a non-conforming server that always returns a retained message (never
// Bad_MessageNotAvailable) must not drive an unbounded Republish loop - the per-drain iteration budget stops
// it.
TEST(SubscriptionsPipeline, RepublishDrainIsBounded)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  for (std::uint32_t seq = 1; seq <= 5000; ++seq)
  {
    pipeline->on_republish_response_async(/*sub=*/7, seq, ua::StatusCode{ua::Status::Good});
  }
  f.ctx.run();

  // The drain terminated at its budget well before consuming all 5000 always-good responses.
  EXPECT_GT(f.host->republishes.size(), 0u);
  EXPECT_LT(f.host->republishes.size(), 5000u) << "an always-good server must not spin Republish forever";
}

// ============================================================================================
// Subscription-event-loss signal (Finding 2 / CL-AC-003): a REACTIVE Republish drain that terminates with
// an UNRECOVERED sequence gap (dropped messages - possibly a lost ConditionRefresh RefreshEnd) or hits its
// iteration cap fires the loss callback with the Subscription id, so the Connection can re-sync the A&C
// tracker (whose mRefreshInProgress would otherwise wedge forever). The signal is ORTHOGONAL to the drain's
// clean/bad terminator decision (F6/N3 unchanged).
// ============================================================================================

// A lossy Bad_MessageNotAvailable terminal (an unrecovered gap survives the drain) fires the event-loss
// signal exactly once, and does NOT disturb the drain's clean-terminator handling.
// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST(SubscriptionsPipeline, LossyGapSignalsEventLoss)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // fresh tracker -> expects seq 1
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // A live Publish at seq 3 (expected 1) reveals a gap: gapTarget = 3, drain from next_expected = 1.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  // The retransmission queue is already drained past the hole: seq 1 is not available. next_expected is still
  // 1, so classify(gapTarget = 3) is Gap -> the gap was NEVER recovered -> event loss.
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();

  EXPECT_EQ(f.lossSignals, (std::vector<std::uint32_t>{7}))
    << "a Bad_MessageNotAvailable terminal with an unrecovered gap must signal event loss for the sub";
  // Orthogonality (F6/N3): Bad_MessageNotAvailable is still the CLEAN terminator - it must NOT be logged as a
  // fault. The loss signal rides alongside, it does not change the terminator classification.
  EXPECT_FALSE(f.logSink->has_message_containing("non-terminator status"))
    << "the loss signal must not turn the clean Bad_MessageNotAvailable terminator into a fault";
}

// A CLEAN catch-up drain (every missed message recovered before Bad_MessageNotAvailable) must NOT signal
// loss - the gap was fully closed, so classify(gapTarget) at the terminal is Duplicate, not Gap. Control for
// LossyGapSignalsEventLoss: guards against over-firing on the normal recovery path.
TEST(SubscriptionsPipeline, CleanCatchUpDoesNotSignalLoss)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // Gap at seq 3 (gapTarget = 3), then the server retransmits 1, 2, 3 (fully recovered) before 4 is not
  // available. At the terminal next_expected = 4, so classify(gapTarget = 3) is Duplicate -> no loss.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->on_republish_response_async(/*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(/*sub=*/7, /*seq=*/2, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(/*sub=*/7, /*seq=*/3, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/4, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();

  EXPECT_TRUE(f.lossSignals.empty()) << "a fully-recovered gap (clean catch-up) must NOT signal event loss";
}

// A drain that hits its iteration cap (a non-conforming server that never returns the terminator) forfeits
// sequence trust and signals loss unconditionally - exactly once, even though a flood of Good responses
// follows.
// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST(SubscriptionsPipeline, RepublishCapHitSignalsLoss)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  // Feed always-Good responses well past the drain cap: the drain terminates on the cap-hit (a Good status),
  // which fires the loss signal once; the responses after republishing is cleared are ignored.
  for (std::uint32_t seq = 1; seq <= 5000; ++seq)
  {
    pipeline->on_republish_response_async(/*sub=*/7, seq, ua::StatusCode{ua::Status::Good});
  }
  f.ctx.run();

  EXPECT_EQ(f.lossSignals, (std::vector<std::uint32_t>{7}))
    << "a cap-hit drain forfeits sequence trust and signals loss exactly once";
}

// A transient/other Bad status mid-drain (a channel blip) is RETRYABLE: it must NOT signal loss (the drain
// stops, the barrier keeps it Bad so the FSM re-drains). Control for the loss signal being orthogonal to the
// retryable-fault path.
TEST(SubscriptionsPipeline, TransientBadDoesNotSignalLoss)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  // A transient transport fault ends the drain - retryable, not a confirmed loss.
  pipeline->on_republish_response_async(/*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::BadTimeout});
  f.ctx.run();

  EXPECT_TRUE(f.lossSignals.empty()) << "a retryable transient Bad must NOT signal event loss";
  EXPECT_TRUE(f.logSink->has_message_containing("non-terminator status"))
    << "the transient fault is still surfaced as a non-terminator status (retryable)";
}

// After a lossy terminal fires once, the drain advances past the gap target so the next live Publish is
// InOrder - pinning the flood-control advance_past(gapTarget). Without it next_expected stays behind the
// hole, every subsequent live Publish re-classifies Gap and re-fires (and re-issues Republish), which would
// abort the in-flight resync ConditionRefresh on every message so it never settles.
// @verifies CL-AC-003
// @relation(CL-AC-003, scope=function)
TEST(SubscriptionsPipeline, RepeatedLiveAfterLossSignalsOnce)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // Lossy terminal: gap at seq 3, then Bad_MessageNotAvailable with the hole unrecovered -> one fire +
  // advance_past(gapTarget = 3), so next_expected becomes 4.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  // Live publishing resumes at increasing sequence numbers past the advanced tracker: 4, 5 are InOrder, so no
  // new drain and no re-fire. (Without advance_past, next_expected would still be 1, so seq 4 would re-open a
  // gap and re-fire.)
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/4, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/5, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  // A stray Bad_MessageNotAvailable (would terminate a re-opened buggy drain) must be ignored on the correct
  // path (not draining) - so it cannot manufacture a second fire.
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();

  EXPECT_EQ(f.lossSignals, (std::vector<std::uint32_t>{7}))
    << "exactly one loss signal per episode: advance_past keeps subsequent live Publishes InOrder";
  EXPECT_EQ(f.host->republishes, (std::vector<std::pair<std::uint32_t, std::uint32_t>>{{7, 1}}))
    << "the post-loss InOrder Publishes must not re-open a gap or re-issue Republish (advance_past)";
}

// The RECOVERY drain (recover_subscriptions_async) blindly walks next_expected with no server-progress
// knowledge, so it can NEVER decide loss - its gapTarget is reset to 0. A recovery drain that terminates on
// Bad_MessageNotAvailable while a reactive gapTarget was previously set must NOT false-fire, and the recovery
// still reports Good (R2). Falsifies a missing gapTarget reset in recover_subscriptions_async /
// clear_recovery (which would let the stale reactive gapTarget classify Gap and fire under recovery).
TEST(SubscriptionsPipeline, RecoveryDrainDoesNotSignalLoss)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  f.ctx.run();
  f.ctx.restart();

  // Set a reactive gapTarget = 3 (a live gap), so if the reset were missing it would survive into recovery.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  f.ctx.restart();

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  // The recovery drain terminates on Bad_MessageNotAvailable. gapTarget was reset to 0 for the recovery, so
  // classify(0) is Invalid -> no loss fire, and the recovery reports Good.
  pipeline->on_republish_response_async(
    /*sub=*/7, /*seq=*/1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();

  EXPECT_TRUE(f.lossSignals.empty())
    << "the recovery drain must never false-fire event loss (gapTarget reset)";
  ASSERT_TRUE(recoverResult.has_value());
  EXPECT_TRUE(recoverResult->is_good()) << "a clean recovery terminal reports Good";
}

TEST(SubscriptionsPipeline, DuplicatePublishIsNotAcked)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);  // dup
  pipeline->start_async();
  f.ctx.run();
  // The first Publish issued carries only the single ack for the in-order seq 1 (the duplicate is dropped).
  ASSERT_FALSE(f.host->publishes.empty());
  EXPECT_EQ(f.host->publishes[0].size(), 1u) << "the duplicate seq must not be acknowledged again";
}

// Keep-alive data-loss defect (OPC UA 10000-4 section 5.13.5): a keep-alive is an EMPTY NotificationMessage
// that carries the sequence number of the NEXT NotificationMessage to be sent (the server peeks, it does not
// allocate). So an in-order keep-alive must NOT be acknowledged - acking (and advancing) it would consume
// the number the next REAL message reuses, which would then classify Duplicate and be dropped (silent loss).
//
// Falsifiable core: the refill Publish issued immediately after the keep-alive must carry NO ack. The buggy
// pre-fix path acked the keep-alive (advancing the tracker past the peeked number), so its refill Publish
// carried an ack for the keep-alive's seq - this test fails against that. The follow-up real message at the
// SAME sequence number is then still in-order (delivered + acked), which the corroborating clauses assert.
TEST(SubscriptionsPipeline, KeepAliveAtNextExpectedIsNotAckedThenRealMessageAtSameSeqDelivered)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // fresh tracker -> expects seq 1
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();
  const auto afterStart = f.host->publishes.size();
  ASSERT_EQ(afterStart, 2u);

  // A KEEP-ALIVE (empty NotificationMessage, hasNotifications=false) at the expected seq 1. It refills the
  // pump; the refill Publish it triggers must carry NO ack (the keep-alive is not acknowledged).
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/false, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  f.ctx.restart();

  ASSERT_GT(f.host->publishes.size(), afterStart) << "the keep-alive refills the pump";
  EXPECT_TRUE(f.host->publishes.back().empty())
    << "a keep-alive must NOT be acknowledged: its refill Publish carries no ack (buggy path acked the "
       "peeked seq, consuming the next real message's number)";
  EXPECT_TRUE(f.host->republishes.empty()) << "an in-order keep-alive is no gap: no Republish";

  // The next REAL message reuses the peeked sequence number (seq 1). Because the keep-alive did not advance
  // the tracker, this is still in-order: it is delivered to the monitored item and acknowledged.
  const auto beforeReal = f.host->publishes.size();
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  pipeline->deliver_notification_async(/*clientHandle=*/5, ua::DataValue{ua::Status::Good});
  f.ctx.run();

  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5}))
    << "the real message that reuses the keep-alive's seq must still be delivered (not dropped as Duplicate)";
  ASSERT_GT(f.host->publishes.size(), beforeReal) << "the real message refills the pump";
  ASSERT_EQ(f.host->publishes.back().size(), 1u)
    << "the real message at the reused seq is in-order and acknowledged (proves the tracker was not advanced "
       "by the keep-alive)";
  EXPECT_EQ(f.host->publishes.back()[0].subscriptionId, 7u);
  EXPECT_EQ(f.host->publishes.back()[0].sequenceNumber, 1u);
}

// CL-DA-010 / CL-ADDRSP-008: a delivered DataChange carrying the in-band SemanticsChanged StatusCode bit
// routes the monitored node into the invalidation interface (so a DA typed accessor re-resolves fresh
// Properties on its next read - the CL-ADDRSP-008 property-refresh trigger, whose Connection->cache wiring is
// covered end-to-end by ClientSubscription.SemanticsChangedBitTriggersPropertyRefresh), while the value is
// STILL delivered to the user callback (the bit is advisory metadata, never suppresses delivery).
// @verifies CL-DA-010
// @verifies CL-ADDRSP-008
// @relation(CL-ADDRSP-008, CL-DA-010, scope=function)
TEST(SubscriptionsPipeline, SemanticsChangedBitRoutesNodeToInvalidation)
{
  Fixture f;
  auto pipeline = f.make();
  const ua::NodeId monitoredNode{2, 4242};
  std::vector<ua::DataValue> delivered;
  pipeline->add_monitored_item_async(7,
    /*clientHandle=*/5,
    monitoredNode,
    [&delivered](ua::DataValue v) { delivered.push_back(std::move(v)); });

  ua::StatusCode status{ua::Status::Good};
  status.semantics_changed(true);
  pipeline->deliver_notification_async(/*clientHandle=*/5, ua::DataValue{status});
  f.ctx.run();

  ASSERT_EQ(f.semanticChangeSignals.size(), 1u)
    << "a SemanticsChanged DataChange must route its node into the invalidation interface";
  EXPECT_EQ(f.semanticChangeSignals[0], monitoredNode)
    << "the interface receives the monitored node's NodeId";
  EXPECT_EQ(delivered.size(), 1u) << "the value is still delivered to the user callback (bit is advisory)";
}

// CL-DA-010 negative: a plain DataChange (no SemanticsChanged bit) does NOT trigger invalidation - the
// interface is gated on the bit, not merely on delivery. @verifies CL-DA-010
TEST(SubscriptionsPipeline, DataChangeWithoutSemanticsChangedDoesNotInvalidate)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<ua::DataValue> delivered;
  pipeline->add_monitored_item_async(7,
    /*clientHandle=*/5,
    ua::NodeId{2, 4242},
    [&delivered](ua::DataValue v) { delivered.push_back(std::move(v)); });

  pipeline->deliver_notification_async(/*clientHandle=*/5, ua::DataValue{ua::Status::Good});  // no bit
  f.ctx.run();

  EXPECT_TRUE(f.semanticChangeSignals.empty())
    << "a plain DataChange (no SemanticsChanged bit) must not trigger invalidation";
  EXPECT_EQ(delivered.size(), 1u) << "the value is still delivered";
}

// CL-SUB-009 / Part 4 section 5.13.8.1: a Publish returning Bad_NoSubscription (the last Subscription was
// deleted and the server de-queued the outstanding Publishes) drain-and-HOLDS the pump - it stops issuing
// (not a fault, no retry) and further stale responses do NOT refill it - until a new Subscription is created,
// which resumes publishing. @verifies CL-SUB-009
TEST(SubscriptionsPipeline, BadNoSubscriptionHoldsPumpUntilNewSubscription)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->start_async();  // always-on pipelining fills to target=2 even before a Subscription exists
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->publishes.size(), 2u);
  ASSERT_EQ(pipeline->info()->pumpState, PumpState::Running);

  // The last Subscription was deleted; a Publish returns Bad_NoSubscription -> drain-and-hold.
  pipeline->on_publish_no_subscription_async();
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Idle) << "Bad_NoSubscription must HOLD (stop) the pump";
  const auto afterHold = f.host->publishes.size();

  // A further de-queued Publish response must NOT refill the held pump (no retry of doomed Publishes).
  pipeline->on_publish_response_async(/*sub=*/0,
    /*seq=*/0,
    /*hasNotifications=*/false,
    /*hasAvailable=*/false,
    /*tooMany=*/false);
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(f.host->publishes.size(), afterHold)
    << "a held pump must issue no further Publishes on a late/stale response";

  // Creating a new Subscription lifts the hold and resumes publishing.
  pipeline->add_subscription_async(9, /*publishingInterval=*/500.0);
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Running) << "a new Subscription must resume the pump";
  EXPECT_GT(f.host->publishes.size(), afterHold) << "the resumed pump refills to target";
}

// CL-SUB-009 regression (section 3.1 CRITICAL): a STALE Bad_NoSubscription - an old de-queued Publish from a
// prior last-delete that reorders past a fresh CreateSubscription (the hold and the add/start posts originate
// on different strands, so asio gives no ordering) - must NOT hold the pump while a LIVE Subscription exists,
// else that Subscription is permanently, silently starved. The hold is gated on mSubscriptions.empty().
// @verifies CL-SUB-009
// @relation(CL-SUB-009, scope=function)
TEST(SubscriptionsPipeline, StaleBadNoSubscriptionWithLiveSubscriptionDoesNotStallPump)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // The last Subscription was deleted -> Bad_NoSubscription holds the pump (mSubscriptions empty).
  pipeline->on_publish_no_subscription_async();
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(pipeline->info()->pumpState, PumpState::Idle);

  // A new Subscription is created -> the pump resumes and pumps for it.
  pipeline->add_subscription_async(9, /*publishingInterval=*/500.0);
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(pipeline->info()->pumpState, PumpState::Running);
  const auto afterResume = f.host->publishes.size();

  // A STALE Bad_NoSubscription (the OTHER old de-queued Publish) now arrives AFTER the new Subscription.
  // mSubscriptions is non-empty, so it must NOT hold - the live Subscription keeps pumping.
  pipeline->on_publish_no_subscription_async();
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Running)
    << "a stale Bad_NoSubscription while a live Subscription exists must NOT stall the pump";
  EXPECT_GT(f.host->publishes.size(), afterResume)
    << "the live Subscription keeps pumping (the response is accounted + refilled, not held)";
}

// Second, independent proof that a keep-alive does NOT advance the sequence tracker: after an in-order
// keep-alive at seq 1, a subsequent REAL message at seq 2 must reveal a GAP (next_expected is still 1, so
// seq 1 was skipped) and drive a Republish from seq 1. The buggy path advanced next_expected to 2 on the
// keep-alive, so it would classify seq 2 as in-order and issue NO Republish - which this falsifies.
TEST(SubscriptionsPipeline, KeepAliveDoesNotAdvanceTrackerRevealedByLaterGap)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // Keep-alive at seq 1 (hasNotifications=false): must leave next_expected at 1.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/false, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  f.ctx.restart();
  ASSERT_TRUE(f.host->republishes.empty()) << "the in-order keep-alive is no gap";

  // A REAL message at seq 2 now (next_expected still 1) is a gap: seq 1 was missed -> Republish from 1.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/2, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();

  const std::vector<std::pair<std::uint32_t, std::uint32_t>> expected{{7, 1}};
  EXPECT_EQ(f.host->republishes, expected)
    << "a keep-alive must not advance the tracker: the later seq-2 real message must reveal the seq-1 gap "
       "and drive Republish from 1 (the buggy path advanced past 1 on the keep-alive and saw no gap)";
}

// ============================================================================================
// Publish-delivery decoupled from sequence classification (CL-SUB-002): on_publish_response_async
// reports the SequenceClass, and the delivery site gates dispatch on it (deliver only InOrder / Gap;
// drop Duplicate / Invalid / unknown subscription).
// ============================================================================================

// on_publish_response_async must REPORT the demuxed SequenceClass to onClassified for every case, so the
// delivery site can honour the "Duplicate / Invalid -> no dispatch" contract. Drives one Subscription
// (fresh -> expects 1) through InOrder, Duplicate (a replay), Invalid (seq 0), Gap (ahead), then an unknown
// subscriptionId (default Invalid). Falsifies a reporter that always says InOrder, that omits the default
// Invalid for an unknown subscriptionId, or that reports the POST-advance class for the in-order message.
// @verifies CL-SUB-002
// @relation(CL-SUB-002, scope=function)
TEST(SubscriptionsPipeline, OnPublishResponseReportsSequenceClass)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // fresh tracker -> expects seq 1

  std::vector<SequenceClass> classes;
  auto record = [&classes](SequenceClass classification)
  {
    classes.push_back(classification);
  };

  // seq 1 (InOrder) advances next_expected to 2; seq 1 again is now a Duplicate; seq 0 is Invalid; seq 5 is a
  // Gap (ahead of 2); an unknown subscriptionId (999) matches no Subscription -> default Invalid.
  pipeline->on_publish_response_async(7, 1, /*hasNotif=*/true, /*avail=*/true, /*tooMany=*/false, record);
  pipeline->on_publish_response_async(7, 1, /*hasNotif=*/true, /*avail=*/true, /*tooMany=*/false, record);
  pipeline->on_publish_response_async(7, 0, /*hasNotif=*/true, /*avail=*/true, /*tooMany=*/false, record);
  pipeline->on_publish_response_async(7, 5, /*hasNotif=*/true, /*avail=*/true, /*tooMany=*/false, record);
  pipeline->on_publish_response_async(999, 1, /*hasNotif=*/true, /*avail=*/true, /*tooMany=*/false, record);
  f.ctx.run();

  const std::vector<SequenceClass> expected{SequenceClass::InOrder,
    SequenceClass::Duplicate,
    SequenceClass::Invalid,
    SequenceClass::Gap,
    SequenceClass::Invalid};
  EXPECT_EQ(classes, expected)
    << "on_publish_response_async must report the demuxed class (InOrder, Duplicate, Invalid, Gap, Invalid)";
}

// Mirrors ConnectionImpl::feed_publish_response's delivery gate at the unit boundary: classify via
// on_publish_response_async, then deliver each notification item ONLY when should_deliver(classification).
// hasNotifications is items-non-empty exactly as feed_publish_response derives it, so a keep-alive (no items)
// is modelled by an empty item list.
void feed_and_gate_delivery(SubscriptionsPipeline& pipeline, std::uint32_t subscriptionId,
  std::uint32_t sequenceNumber, std::vector<std::pair<std::uint32_t, ua::DataValue>> items)
{
  const bool hasNotifications = !items.empty();
  pipeline.on_publish_response_async(subscriptionId,
    sequenceNumber,
    hasNotifications,
    /*hasAvailable=*/true,
    /*tooMany=*/false,
    [&pipeline, items = std::move(items)](SequenceClass classification) mutable
    {
      if (!should_deliver(classification))
      {
        return;  // Duplicate / Invalid / unknown subscription -> no user dispatch
      }
      for (auto& [clientHandle, value] : items)
      {
        pipeline.deliver_notification_async(clientHandle, std::move(value));
      }
    });
}

// InOrder delivers its items (regression guard for the gate).
TEST(SubscriptionsPipeline, PublishDeliveryGate_InOrderDelivers)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });

  std::vector<std::pair<std::uint32_t, ua::DataValue>> items;
  items.emplace_back(5, ua::DataValue{ua::Status::Good});
  feed_and_gate_delivery(*pipeline, 7, /*seq=*/1, std::move(items));
  f.ctx.run();

  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5})) << "an in-order message must deliver its items";
}

// Gap delivers its items (Tier-A keeps the live gap payload delivering as today).
TEST(SubscriptionsPipeline, PublishDeliveryGate_GapDelivers)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });

  // seq 3 while expecting 1 is a Gap: it still delivers its live payload (the in-order refinement is Tier B).
  std::vector<std::pair<std::uint32_t, ua::DataValue>> items;
  items.emplace_back(5, ua::DataValue{ua::Status::Good});
  feed_and_gate_delivery(*pipeline, 7, /*seq=*/3, std::move(items));
  f.ctx.run();

  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5})) << "a gap message's live payload must still deliver";
  EXPECT_FALSE(f.host->republishes.empty()) << "a gap must also drive Republish (behaviour unchanged)";
}

// A Duplicate (a re-sent message the client already processed) must deliver NOTHING - the pre-fix delivery
// site dispatched unconditionally and double-delivered it (CL-SUB-002).
TEST(SubscriptionsPipeline, PublishDeliveryGate_DuplicateDropsDelivery)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });

  // seq 1 (InOrder) delivers once and advances to 2; the replayed seq 1 is a Duplicate and must NOT deliver.
  std::vector<std::pair<std::uint32_t, ua::DataValue>> first;
  first.emplace_back(5, ua::DataValue{ua::Status::Good});
  feed_and_gate_delivery(*pipeline, 7, /*seq=*/1, std::move(first));
  std::vector<std::pair<std::uint32_t, ua::DataValue>> replay;
  replay.emplace_back(5, ua::DataValue{ua::Status::Good});
  feed_and_gate_delivery(*pipeline, 7, /*seq=*/1, std::move(replay));
  f.ctx.run();

  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5}))
    << "a duplicate (already-processed) message must not double-deliver: exactly one delivery";
}

// An Invalid sequence number (0, never valid per CL-SUB-002) must deliver NOTHING - the pre-fix delivery site
// spoof-delivered a seq-0 payload to the user callback.
TEST(SubscriptionsPipeline, PublishDeliveryGate_InvalidSeqZeroDropsDelivery)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });

  std::vector<std::pair<std::uint32_t, ua::DataValue>> items;
  items.emplace_back(5, ua::DataValue{ua::Status::Good});
  feed_and_gate_delivery(*pipeline, 7, /*seq=*/0, std::move(items));
  f.ctx.run();

  EXPECT_TRUE(delivered.empty()) << "a seq-0 (Invalid) message must not spoof-deliver";
}

// An unknown/spoofed subscriptionId matches no Subscription -> default Invalid -> deliver NOTHING, even
// though the (spoofed) clientHandle is registered. Closes the by-clientHandle spoof hole (CL-SUB-002).
TEST(SubscriptionsPipeline, PublishDeliveryGate_UnknownSubscriptionDropsDelivery)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });

  // The Publish claims an unregistered subscriptionId (999) but a REGISTERED clientHandle (5): the gate must
  // drop it on the classification (default Invalid), never routing by clientHandle behind a spoofed sub id.
  std::vector<std::pair<std::uint32_t, ua::DataValue>> items;
  items.emplace_back(5, ua::DataValue{ua::Status::Good});
  feed_and_gate_delivery(*pipeline, /*subscriptionId=*/999, /*seq=*/1, std::move(items));
  f.ctx.run();

  EXPECT_TRUE(delivered.empty())
    << "an unknown subscriptionId classifies Invalid (default) and must not deliver by clientHandle";
}

// A keep-alive (InOrder, empty NotificationMessage) delivers nothing (naturally: no items) and does not
// advance the tracker - a subsequent real message at the reused sequence number is still InOrder and
// delivers.
TEST(SubscriptionsPipeline, PublishDeliveryGate_KeepAliveDeliversNothingAndDoesNotAdvance)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });

  // Keep-alive at seq 1: InOrder but no items -> the delivery loop is empty, so nothing is delivered.
  feed_and_gate_delivery(*pipeline, 7, /*seq=*/1, /*items=*/{});
  f.ctx.run();
  f.ctx.restart();
  EXPECT_TRUE(delivered.empty()) << "a keep-alive carries no items: nothing is delivered";
  EXPECT_TRUE(f.host->republishes.empty()) << "an in-order keep-alive is no gap: no Republish";

  // The next REAL message reuses seq 1 (the keep-alive did not advance the tracker): still InOrder ->
  // delivers.
  std::vector<std::pair<std::uint32_t, ua::DataValue>> items;
  items.emplace_back(5, ua::DataValue{ua::Status::Good});
  feed_and_gate_delivery(*pipeline, 7, /*seq=*/1, std::move(items));
  f.ctx.run();
  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5}))
    << "the real message reusing the keep-alive's seq is still InOrder and delivers (keep-alive did not "
       "advance)";
}

// CL-MI-003 / CL-MI-016: a notification is demuxed to its monitored item's callback by client handle.
// @verifies CL-MI-003, CL-MI-016
// @relation(CL-MI-003, CL-MI-016, scope=function)
TEST(SubscriptionsPipeline, MonitoredItemNotificationDispatchedByHandle)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_monitored_item_async(
    7, 5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });
  pipeline->deliver_notification_async(5, ua::DataValue{ua::Status::Good});
  f.ctx.run();
  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5}));
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 1u);
}

// The pipeline applies no local DataChangeFilter to native Publish notifications. In particular, the first
// sample is dispatched exactly as received even when it is NaN, which would be suppressed by an incorrectly
// applied deadband comparison. The server owns first-sample generation; this proves the client's reciprocal
// obligation to accept and deliver it.
// @verifies CL-MI-004
// @relation(CL-MI-004, scope=function)
TEST(SubscriptionsPipeline, FirstNativeSampleIsDispatchedWithoutLocalFiltering)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<double> delivered;
  pipeline->add_monitored_item_async(7,
    5,
    ua::NodeId{},
    [&delivered](ua::DataValue value)
    {
      const auto number = value.value().to<double>();
      ASSERT_TRUE(number.is_good());
      delivered.push_back(number.value());
    });

  pipeline->deliver_notification_async(
    5, ua::DataValue{ua::Variant{std::numeric_limits<double>::quiet_NaN()}});
  f.ctx.run();

  ASSERT_EQ(delivered.size(), 1u);
  EXPECT_TRUE(std::isnan(delivered.front())) << "the first native sample must be delivered unchanged";
}

// CL-MI-003: a notification for an unregistered handle is dropped and counted (advisory), not dispatched.
TEST(SubscriptionsPipeline, UnknownHandleNotificationDropped)
{
  Fixture f;
  auto pipeline = f.make();
  bool called = false;
  pipeline->add_monitored_item_async(7, 5, ua::NodeId{}, [&called](ua::DataValue) { called = true; });
  pipeline->deliver_notification_async(99, ua::DataValue{ua::Status::Good});
  f.ctx.run();
  EXPECT_FALSE(called);
  EXPECT_EQ(pipeline->info()->unknownHandleDrops, 1u);
}

// CL-MI-026: notifications are delivered in arrival order.
// @verifies CL-MI-026
// @relation(CL-MI-026, scope=function)
TEST(SubscriptionsPipeline, NotificationsDeliveredInArrivalOrder)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_monitored_item_async(
    7, 5, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(5); });
  pipeline->add_monitored_item_async(
    7, 6, ua::NodeId{}, [&delivered](ua::DataValue) { delivered.push_back(6); });
  pipeline->deliver_notification_async(5, ua::DataValue{ua::Status::Good});
  pipeline->deliver_notification_async(6, ua::DataValue{ua::Status::Good});
  pipeline->deliver_notification_async(5, ua::DataValue{ua::Status::Good});
  f.ctx.run();
  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5, 6, 5}));
}

// CL-SUB-008 / CL-MI-008: removing a Subscription / monitored item drops it from the registry so later
// notifications for the removed item are no longer dispatched (they become unknown-handle drops).
TEST(SubscriptionsPipeline, RemoveSubscriptionAndItemDeregister)
{
  Fixture f;
  auto pipeline = f.make();
  bool called = false;
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(7, 5, ua::NodeId{}, [&called](ua::DataValue) { called = true; });
  pipeline->remove_subscription_async(7);
  pipeline->remove_monitored_item_async(5);
  pipeline->deliver_notification_async(5, ua::DataValue{ua::Status::Good});  // now unknown
  f.ctx.run();

  EXPECT_EQ(pipeline->info()->subscriptionCount, 0u);
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 0u);
  EXPECT_FALSE(called) << "a notification for a removed item must not be dispatched";
  EXPECT_EQ(pipeline->info()->unknownHandleDrops, 1u);
}

// CL-SUB-008: deleting a Subscription implicitly deletes all its monitored items (OPC UA 10000-4
// section 5.13.8), so remove_subscription cascades to drop its items - but only its own, not another sub's.
TEST(SubscriptionsPipeline, RemoveSubscriptionCascadesToItsMonitoredItems)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(7, 5, ua::NodeId{}, [](ua::DataValue) {});
  pipeline->add_monitored_item_async(7, 6, ua::NodeId{}, [](ua::DataValue) {});
  pipeline->add_subscription_async(8, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(8, 9, ua::NodeId{}, [](ua::DataValue) {});
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(pipeline->info()->monitoredItemCount, 3u);

  pipeline->remove_subscription_async(7);  // cascades to items 5 + 6; sub 8's item 9 stays
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->subscriptionCount, 1u) << "subscription 8 remains";
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 1u)
    << "only the deleted subscription's items cascade away; another subscription's item remains";
}

TEST(SubscriptionsPipeline, TooManyPublishRequestsPausesPump)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();
  const auto afterStart = f.host->publishes.size();

  pipeline->on_publish_response_async(
    /*sub=*/0, /*seq=*/0, /*hasNotifications=*/false, /*hasAvailable=*/false, /*tooMany=*/true);
  f.ctx.run();

  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Paused);
  EXPECT_EQ(f.host->publishes.size(), afterStart) << "a paused pump issues no new Publish";
}

// CL-RECONN-004: on a reconnect the Connection stops the pump (Reconnecting) then resumes it (Active).
// resume clears the stale outstanding count (the pre-drop Publishes never come back) and refills, so a
// subscription keeps publishing on the rebound session.
TEST(SubscriptionsPipeline, ResumeAfterStopRefillsWhenSubscriptionsExist)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();
  const auto afterStart = f.host->publishes.size();
  ASSERT_EQ(afterStart, 2u);

  pipeline->stop_async();  // the Connection entered Reconnecting
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Idle);

  pipeline->resume_async();  // the Connection returned to Active
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Running);
  EXPECT_EQ(f.host->publishes.size(), afterStart + 2u)
    << "resume refills the pump to target on the fresh channel";
}

// resume with no registered subscription leaves the pump idle (nothing to publish for).
TEST(SubscriptionsPipeline, ResumeIsNoOpWithoutSubscriptions)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->resume_async();
  f.ctx.run();
  EXPECT_TRUE(f.host->publishes.empty()) << "no subscriptions -> resume leaves the pump idle";
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Idle);
}

// The last Subscription is deleted while its Publishes are outstanding, the link drops before the server
// answers them, and the Connection resumes with no Subscriptions. Those Publishes died with the dropped
// channel, so a Subscription created afterwards must still get a full pipeline of Publishes. Counting them
// as outstanding left start() with nothing to send and the new Subscription silently delivered nothing.
TEST(SubscriptionsPipeline, SubscriptionCreatedAfterAnEmptyResumeGetsPublishes)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->publishes.size(), 2u);

  pipeline->remove_subscription_async(7);  // the last Subscription; its two Publishes are unanswered
  pipeline->stop_async();                  // the link dropped: the Connection entered Reconnecting
  pipeline->resume_async();                // Active again, with no Subscriptions to resume
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->publishes.size(), 2u) << "nothing to publish for while there are no Subscriptions";

  pipeline->add_subscription_async(8, /*publishingInterval=*/500.0);  // CreateSubscription on the new channel
  pipeline->start_async();
  f.ctx.run();
  EXPECT_EQ(pipeline->info()->pumpState, PumpState::Running);
  EXPECT_EQ(f.host->publishes.size(), 4u) << "the new Subscription gets a full pipeline on the new channel";
}

// ============================================================================================
// Republish-on-reconnect recovery barrier - recover_subscriptions_async (section 6.7 / CL-RECONN-004)
// ============================================================================================

using RepublishList = std::vector<std::pair<std::uint32_t, std::uint32_t>>;

// The recover step starts a drain from each Subscription's nextExpected and its barrier fires `done` only
// AFTER the drain reaches a terminal - not mid-drain.
// Falsifies: a `done` that fires before the drain terminates (e.g. the moment recover is called), and a
// drain that starts from the wrong sequence number (anything other than the expected seq 1).
TEST(SubscriptionsPipeline, RecoverDrainsFromNextExpectedThenFiresDoneGood)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // fresh tracker -> expects seq 1
  f.ctx.run();
  f.ctx.restart();

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  // The recover step issued exactly one Republish, from the next expected sequence number (1), and the
  // barrier has NOT fired - the drain has not reached a terminal yet.
  EXPECT_EQ(f.host->republishes, (RepublishList{{7, 1}}));
  EXPECT_FALSE(recoverResult.has_value()) << "the barrier must not fire mid-drain";

  // Recover seq 1 (steps to seq 2), then the clean terminator ends the drain and fires the barrier.
  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(7, 2, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();

  ASSERT_TRUE(recoverResult.has_value());
  EXPECT_TRUE(recoverResult->is_good());
  EXPECT_EQ(f.host->republishes, (RepublishList{{7, 1}, {7, 2}}));
}

// With no registered Subscription the recover step succeeds immediately (nothing to drain).
// Falsifies: a barrier that hangs on zero Subscriptions (mRecoveryPending stuck at 0 but mRecoveryDone
// never fired), which would leave the FSM recover step blocked forever.
TEST(SubscriptionsPipeline, RecoverEmptySubscriptionsFiresGoodImmediately)
{
  Fixture f;
  auto pipeline = f.make();

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();

  ASSERT_TRUE(recoverResult.has_value()) << "empty recovery must complete immediately";
  EXPECT_TRUE(recoverResult->is_good());
  EXPECT_TRUE(f.host->republishes.empty());
}

// The barrier fires only once EVERY Subscription's drain has reached a terminal, not on the first.
// Falsifies: a barrier that fires on the first drain's terminal (decrement-to-fire without counting all
// participants) - it would fire `done` while sub 8 is still draining.
TEST(SubscriptionsPipeline, RecoverBarrierWaitsForAllSubscriptions)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_subscription_async(8, /*publishingInterval=*/500.0);
  f.ctx.run();
  f.ctx.restart();

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  // Drive ONLY sub 7 to its clean terminal - sub 8 is still draining, so the barrier must not fire.
  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();
  f.ctx.restart();
  EXPECT_FALSE(recoverResult.has_value()) << "the barrier must wait for sub 8 too";

  // Now drive sub 8 to its terminal: the barrier completes.
  pipeline->on_republish_response_async(8, 1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();
  ASSERT_TRUE(recoverResult.has_value());
  EXPECT_TRUE(recoverResult->is_good());
}

// A second recover_subscriptions_async cancels the prior in-flight recovery: it discards the prior `done`
// WITHOUT firing it and starts a fresh barrier (a clean worst-status accumulator). Two Subscriptions are
// used so the prior recovery can record a Bad terminal on one sub WITHOUT completing (sub 8 still pending),
// which is what makes the F2 cancel interface (clear_recovery) observable: without it the stale Bad
// worst-status bleeds into the fresh recovery and makes doneB report Bad. Falsifies: the missing F2 cancel
// interface (clear_recovery) - the prior recovery's Bad worst-status would survive into the superseding
// recovery, so doneB would fire Bad instead of Good. Also pins that the superseded doneA is discarded without
// ever firing.
TEST(SubscriptionsPipeline, RecoverCancelPriorDiscardsItsDone)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_subscription_async(8, /*publishingInterval=*/500.0);
  f.ctx.run();
  f.ctx.restart();

  std::optional<ua::VoidResult> resultA;
  pipeline->recover_subscriptions_async([&resultA](ua::VoidResult r) { resultA = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  // The prior recovery records a Bad (non-clean) terminal on sub 7 but does NOT complete (sub 8 pending).
  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::BadTimeout});
  f.ctx.run();
  f.ctx.restart();
  ASSERT_FALSE(resultA.has_value()) << "the prior recovery is still in flight (sub 8 not drained)";

  // A superseding recovery cancels the prior one and starts fresh.
  std::optional<ua::VoidResult> resultB;
  pipeline->recover_subscriptions_async([&resultB](ua::VoidResult r) { resultB = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  // Drive both Subscriptions to CLEAN terminals under the fresh recovery.
  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  pipeline->on_republish_response_async(8, 1, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();

  EXPECT_FALSE(resultA.has_value()) << "the superseded recovery's done must be discarded WITHOUT firing";
  ASSERT_TRUE(resultB.has_value());
  EXPECT_TRUE(resultB->is_good()) << "the fresh recovery starts clean: the prior Bad worst-status is reset";
}

// A Subscription already draining a gap REACTIVELY (from a pre-drop Publish gap) is ADOPTED by recover -
// recover must NOT issue a second Republish for it; it folds the existing drain into the barrier.
// Falsifies: recover forking a SECOND Republish for an already-draining Subscription (the H2 fork) - the
// republish list would then contain a duplicate {7,1} instead of the single reactive one.
// A1 (the HIGH the section 3.1 panel caught): recover must NOT "adopt" an in-flight reactive drain. That
// drain's Republish was issued under the pre-drop channel, so the connection-strand epoch guard drops its
// response - an adopted drain's terminal would never arrive and the recovery barrier would STALL forever,
// failing the reconnect against a healthy server. recover must RESET the drain and issue a FRESH,
// current-epoch Republish per Subscription. Falsifies the removed adopt branch (which issued no fresh
// Republish and relied on an epoch-doomed terminal to fire the barrier).
TEST(SubscriptionsPipeline, RecoverReissuesFreshDrainForInFlightReactiveSubscription)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  f.ctx.run();
  f.ctx.restart();

  // Start a REACTIVE drain: a Publish at seq 3 (expected 1) is a gap -> Republish from seq 1.
  pipeline->on_publish_response_async(
    7, /*seq=*/3, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  f.ctx.restart();
  ASSERT_EQ(f.host->republishes, (RepublishList{{7, 1}})) << "the reactive gap started one Republish";

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();
  f.ctx.restart();
  // recover RESETS the in-flight drain and issues a FRESH Republish (from next_expected, still 1 - the
  // reactive Republish has not been answered): a SECOND {7,1}, not an adoption.
  EXPECT_EQ(f.host->republishes, (RepublishList{{7, 1}, {7, 1}}))
    << "recover must re-issue a fresh Republish, not adopt the epoch-doomed in-flight one";
  EXPECT_FALSE(recoverResult.has_value());

  // Driving the fresh recovery drain to its terminal fires the barrier - proving it did NOT stall.
  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(7, 2, ua::StatusCode{ua::Status::BadMessageNotAvailable});
  f.ctx.run();
  ASSERT_TRUE(recoverResult.has_value()) << "the fresh recovery drain's terminal must fire the barrier";
  EXPECT_TRUE(recoverResult->is_good());
}

// A transient (non-terminator, non-SubscriptionIdInvalid) Bad status mid-drain makes the WHOLE recovery
// report Bad, so the FSM recover step backs off and retries rather than treating an incomplete drain as
// success (no-loss, section 6.7).
// Falsifies: the F6 worst-status thread reporting Good on an incomplete drain (v1's F6 bug) - the drain
// ended on Bad_Timeout, not the clean terminator, so recovery must be Bad.
TEST(SubscriptionsPipeline, RecoverTransientBadMidDrainReportsBad)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  f.ctx.run();
  f.ctx.restart();

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  // Recover seq 1, then a transient Bad (a channel blip) ends the drain WITHOUT the clean terminator.
  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::Good});
  pipeline->on_republish_response_async(7, 2, ua::StatusCode{ua::Status::BadTimeout});
  f.ctx.run();

  ASSERT_TRUE(recoverResult.has_value());
  EXPECT_TRUE(recoverResult->is_bad()) << "an incomplete drain must make recovery report Bad (F6)";
}

// N3: a GOOD-status terminal (an iteration-cap-hit, or a Good-but-off-sequence reply) ends the drain
// CLEAN-for-recovery (recovery reports Good, proceed to Active) - NOT a synthesised Bad that would make the
// FSM re-drain forever against a non-conforming server (a DoS-into-Failed). Only a genuinely BAD status
// makes recovery report Bad (see RecoverTransientBadMidDrainReportsBad). Falsifies the earlier
// synthesise-BadConnectionClosed-on-any-non-clean-terminal behavior.
TEST(SubscriptionsPipeline, RecoverGoodStatusTerminalProceedsCleanNotRetried)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);  // expects seq 1
  f.ctx.run();
  f.ctx.restart();

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  // A Good response that is off-sequence for the drain (seq 5 while expecting 1) ends the drain with a
  // Good status - the server returned no fault, just not the requested next-in-order message.
  pipeline->on_republish_response_async(7, 5, ua::StatusCode{ua::Status::Good});
  f.ctx.run();

  ASSERT_TRUE(recoverResult.has_value());
  EXPECT_TRUE(recoverResult->is_good())
    << "a Good-status terminal is clean-for-recovery (proceed), not a retryable failure";
}

// Bad_SubscriptionIdInvalid is a CLEAN terminal for recovery: the Subscription is gone server-side, which
// does not fail the whole reconnect recovery (recreate is a separate concern, section 6.7).
// Falsifies: conflating Bad_SubscriptionIdInvalid with a recovery failure - it would make `done` report
// Bad even though a gone Subscription is an expected, clean drain outcome.
TEST(SubscriptionsPipeline, RecoverBadSubscriptionIdIsCleanForRecovery)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/500.0);
  pipeline->add_monitored_item_async(7, /*clientHandle=*/5, ua::NodeId{}, [](ua::DataValue) {});
  f.ctx.run();
  f.ctx.restart();

  std::optional<ua::VoidResult> recoverResult;
  pipeline->recover_subscriptions_async([&recoverResult](ua::VoidResult r) { recoverResult = std::move(r); });
  f.ctx.run();
  f.ctx.restart();

  pipeline->on_republish_response_async(7, 1, ua::StatusCode{ua::Status::BadSubscriptionIdInvalid});
  f.ctx.run();

  ASSERT_TRUE(recoverResult.has_value());
  EXPECT_TRUE(recoverResult->is_good())
    << "a gone Subscription is a clean recovery terminal, not a recovery failure";
  // A3: the dead Subscription must be REMOVED - otherwise the pump keeps Publishing against it, the counts
  // stay inflated, and a dead Subscription is reported as "recovered". The removal cascades to its monitored
  // items (mirror the delete cascade). (Falsifies leaving it in place.)
  EXPECT_EQ(pipeline->info()->subscriptionCount, 0u)
    << "Bad_SubscriptionIdInvalid must remove the dead Subscription from the pipeline";
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 0u)
    << "removing the gone Subscription must cascade-drop its monitored-item callbacks";
}

// ============================================================================================
// Session-CHANGED recovery FOUNDATION (piece 2): retained recreate params + descriptor query + re-key
// ============================================================================================

// Q5 single-owner query: recovery_descriptors_async snapshots the retained recreate params - the
// Subscription's publishing interval and each owned monitored item's node + client handle - CALLBACK-FREE
// (the descriptor struct has no callback field, so callbacks structurally never cross the strand).
// Falsifies: a descriptor that drops the retained interval/node/handle, or omits the monitored item.
TEST(SubscriptionsPipeline, RecoveryDescriptorsSnapshotRetainedRecreateParams)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/250.0);
  pipeline->add_monitored_item_async(7, /*clientHandle=*/5, ua::NodeId{2, 100}, [](ua::DataValue) {});
  f.ctx.run();
  f.ctx.restart();

  std::optional<std::vector<RecoveryDescriptor>> snapshot;
  pipeline->recovery_descriptors_async(
    [&snapshot](std::vector<RecoveryDescriptor> descriptors) { snapshot = std::move(descriptors); });
  f.ctx.run();

  ASSERT_TRUE(snapshot.has_value());
  ASSERT_EQ(snapshot->size(), 1u);
  const RecoveryDescriptor& descriptor = (*snapshot)[0];
  EXPECT_EQ(descriptor.subscriptionId, 7u);
  EXPECT_DOUBLE_EQ(descriptor.publishingInterval, 250.0)
    << "the retained create interval must be snapshotted";
  ASSERT_EQ(descriptor.monitoredItems.size(), 1u);
  EXPECT_EQ(descriptor.monitoredItems[0].clientHandle, 5u);
  EXPECT_EQ(descriptor.monitoredItems[0].nodeId, (ua::NodeId{2, 100}))
    << "the retained monitored-item node must be snapshotted for recreate";
}

// Q3 (recreate path): apply_recreate_rekeys with oldId != newId moves the Subscription to the new id,
// repoints its monitored items (so a later notification for the item's handle still reaches its callback),
// and RESETS the tracker to a fresh sequence space - a Publish at seq 1 on the new id classifies InOrder
// (acked), not Duplicate (dropped).
// Falsifies: a re-key that loses the monitored item's callback (delivered stays empty), or that fails to
// reset the tracker (seq 1 would be a Duplicate -> no ack -> silent stall).
TEST(SubscriptionsPipeline, ApplyRecreateRekeysMovesRepointsAndResetsTracker)
{
  Fixture f;
  auto pipeline = f.make();
  std::vector<std::uint32_t> delivered;
  pipeline->add_subscription_async(7, /*publishingInterval=*/250.0);
  pipeline->add_monitored_item_async(
    7, /*clientHandle=*/5, ua::NodeId{2, 100}, [&delivered](ua::DataValue) { delivered.push_back(5); });
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // Advance sub 7's tracker: an in-order seq 1 acks and steps next_expected to 2.
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  f.ctx.restart();

  // Re-key 7 -> 42 (recreated with a fresh server id).
  pipeline->apply_recreate_rekeys_async({{/*oldId=*/7, /*newId=*/42}});
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(pipeline->info()->subscriptionCount, 1u) << "the Subscription moved, not duplicated or dropped";
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 1u) << "the monitored item is preserved across the re-key";

  // The monitored item's callback still fires (its owning-subscription id was repointed, handle preserved).
  pipeline->deliver_notification_async(/*clientHandle=*/5, ua::DataValue{ua::Status::Good});
  f.ctx.run();
  f.ctx.restart();
  EXPECT_EQ(delivered, (std::vector<std::uint32_t>{5})) << "the re-key preserved the item's callback";

  // The tracker was RESET: a Publish at seq 1 for the NEW id 42 is InOrder, so it is acknowledged (a
  // non-reset tracker, still expecting 2, would classify seq 1 as a Duplicate and queue no ack).
  const auto beforePublishes = f.host->publishes.size();
  pipeline->on_publish_response_async(
    /*sub=*/42, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  ASSERT_GT(f.host->publishes.size(), beforePublishes) << "the response refills the pump";
  ASSERT_EQ(f.host->publishes.back().size(), 1u)
    << "a reset tracker classifies seq 1 as InOrder and acks it (proves next_expected == 1)";
  EXPECT_EQ(f.host->publishes.back()[0].subscriptionId, 42u);
  EXPECT_EQ(f.host->publishes.back()[0].sequenceNumber, 1u);
}

// section 3.1 (#24 review, HIGH): a RECREATE whose fresh Session handed back the SAME id (the old id was
// freed when the old Session died, and a lowest-free-id server reassigns it) STILL restarts the server
// sequence space, so the tracker MUST reset even when newId == oldId. Transferred subs never stage a re-key,
// so every entry in apply_recreate_rekeys is a recreate -> always reset. Falsifies: inferring
// transfer-vs-recreate from id equality and skipping the reset on newId == oldId (then seq 1 is a Duplicate
// -> dropped -> the recreated Subscription silently delivers nothing).
TEST(SubscriptionsPipeline, ApplyRecreateRekeysSameIdStillResetsTracker)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(7, /*publishingInterval=*/250.0);
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // Advance the tracker to next_expected == 2 (seq 1 in-order, its ack drained here).
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  f.ctx.restart();

  // Recreate that got the same id back: MUST reset the tracker to next_expected == 1.
  pipeline->apply_recreate_rekeys_async({{/*oldId=*/7, /*newId=*/7}});
  f.ctx.run();
  f.ctx.restart();

  const auto beforePublishes = f.host->publishes.size();
  pipeline->on_publish_response_async(
    /*sub=*/7, /*seq=*/1, /*hasNotifications=*/true, /*hasAvailable=*/true, /*tooMany=*/false);
  f.ctx.run();
  ASSERT_GT(f.host->publishes.size(), beforePublishes) << "the response refills the pump";
  ASSERT_EQ(f.host->publishes.back().size(), 1u)
    << "a recreate must reset the tracker even when the id is unchanged: seq 1 is InOrder and acked (a "
       "non-reset tracker still expecting 2 would classify it Duplicate and drop it - silent loss)";
  EXPECT_EQ(f.host->publishes.back()[0].subscriptionId, 7u);
  EXPECT_EQ(f.host->publishes.back()[0].sequenceNumber, 1u);
}

// section 3.1 (#24 review, MEDIUM): applying re-keys must be COLLISION-SAFE. A recreated Subscription's newId
// can equal another still-pending Subscription's oldId (all old ids were freed with the old Session), so a
// naive one-at-a-time move (mSubscriptions[newId] = moved) would clobber a pristine entry not yet re-keyed
// and scoop up the wrong items. apply_recreate_rekeys extracts every old state against the PRE-IMAGE before
// inserting any new id, and repoints each item once by its ORIGINAL owning id.
// Falsifies: a sequential apply of {1->2},{2->3} that loses sub 2's state or misroutes items.
TEST(SubscriptionsPipeline, ApplyRecreateRekeysCollidingNewIdsRemapAtomically)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(1, /*publishingInterval=*/100.0);
  pipeline->add_monitored_item_async(1, /*clientHandle=*/10, ua::NodeId{2, 10}, [](ua::DataValue) {});
  pipeline->add_subscription_async(2, /*publishingInterval=*/200.0);
  pipeline->add_monitored_item_async(2, /*clientHandle=*/20, ua::NodeId{2, 20}, [](ua::DataValue) {});
  pipeline->start_async();
  f.ctx.run();
  f.ctx.restart();

  // Recreate BOTH: sub 1 -> 2 (collides with the still-pending old sub 2), sub 2 -> 3.
  pipeline->apply_recreate_rekeys_async({{1, 2}, {2, 3}});
  f.ctx.run();
  f.ctx.restart();

  EXPECT_EQ(pipeline->info()->subscriptionCount, 2u) << "both Subscriptions survive the colliding remap";
  EXPECT_EQ(pipeline->info()->monitoredItemCount, 2u) << "both monitored items survive the colliding remap";

  std::optional<std::vector<RecoveryDescriptor>> snapshot;
  pipeline->recovery_descriptors_async(
    [&snapshot](std::vector<RecoveryDescriptor> descriptors) { snapshot = std::move(descriptors); });
  f.ctx.run();
  ASSERT_TRUE(snapshot.has_value());
  ASSERT_EQ(snapshot->size(), 2u);

  // Old sub 1 (interval 100, item handle 10) must now live under id 2; old sub 2 (interval 200, item handle
  // 20) under id 3 - each with its OWN item, not the other's (the clobber would misroute them).
  auto byId = [&snapshot](std::uint32_t id) -> const RecoveryDescriptor*
  {
    for (const auto& descriptor : *snapshot)
      if (descriptor.subscriptionId == id)
        return &descriptor;
    return nullptr;
  };
  const RecoveryDescriptor* subTwo = byId(2);
  const RecoveryDescriptor* subThree = byId(3);
  ASSERT_NE(subTwo, nullptr) << "old sub 1 must be re-keyed to id 2";
  ASSERT_NE(subThree, nullptr) << "old sub 2 must be re-keyed to id 3";
  EXPECT_DOUBLE_EQ(subTwo->publishingInterval, 100.0) << "id 2 must hold old sub 1's state, not sub 2's";
  EXPECT_DOUBLE_EQ(subThree->publishingInterval, 200.0) << "id 3 must hold old sub 2's state";
  ASSERT_EQ(subTwo->monitoredItems.size(), 1u);
  EXPECT_EQ(subTwo->monitoredItems[0].clientHandle, 10u) << "id 2 must own old sub 1's item (handle 10)";
  ASSERT_EQ(subThree->monitoredItems.size(), 1u);
  EXPECT_EQ(subThree->monitoredItems[0].clientHandle, 20u) << "id 3 must own old sub 2's item (handle 20)";
}

// --- Polled-Read fallback (section 8.4, CL-SUB-019..022): the pipeline consumes the WireOps role handle. ---

// The bulk Read is paged at WireOps::max_nodes_per_read and stitched back in request order (CL-SUB-020).
// @verifies CL-SUB-020
// @relation(CL-SUB-020, scope=function)
TEST(SubscriptionsPipeline, PollReadPagesBulkReadPerMaxNodesPerRead)
{
  Fixture f;
  f.wireOps->maxNodesPerRead = 2;  // force multi-page paging for a 5-node read
  auto pipeline = f.make();

  std::vector<ua::ReadValueId> reads(5);  // 5 nodes -> ceil(5/2) = 3 pages

  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  pipeline->poll_read_async(std::move(reads),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << "a paged fallback over a healthy WireOps must succeed";
  EXPECT_EQ(captured->value().size(), 5u) << "every node's DataValue is stitched back";
  EXPECT_EQ(f.wireOps->readCalls, 3u) << "5 nodes at page size 2 => 3 Reads reach WireOps::read_async";
  EXPECT_GE(f.wireOps->maxNodesPerReadCalls, 1u) << "the fallback must consult WireOps::max_nodes_per_read";
  ASSERT_EQ(f.wireOps->readRequests.size(), 3u);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 2u) << "page 1 holds max_nodes_per_read nodes";
  EXPECT_EQ(f.wireOps->readRequests[1].nodes_to_read().size(), 2u) << "page 2 holds max_nodes_per_read nodes";
  EXPECT_EQ(f.wireOps->readRequests[2].nodes_to_read().size(), 1u) << "page 3 holds the remainder";
}

// CL-SUB-019: an ENGAGED fallback Subscription's driver polls its Reporting monitored items (via
// poll_read_async) and delivers each recovered DataValue to that item's callback. Falsifiable: a driver that
// never polls issues no Read and delivers nothing (asserted by the readCalls + delivered counts).
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverPollsReportingItemsAndDelivers)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;

  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);
  std::vector<ua::DataValue> delivered;
  pipeline->add_monitored_item_async(fallbackSubId,
    /*clientHandle=*/7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value) { delivered.push_back(std::move(value)); });
  // poll() (NOT run()): the engaged periodic timer never fires within the drained work, so run() would hang.
  f.ctx.poll();
  EXPECT_TRUE(SubscriptionsPipelineTestAccess::is_fallback_subscription(*pipeline, fallbackSubId))
    << "engage must register the Subscription as a fallback";

  // Drive exactly one poll cycle deterministically.
  SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
  f.ctx.poll();

  ASSERT_EQ(f.wireOps->readCalls, 1u) << "the tick must issue exactly one bulk Read for the Reporting item";
  ASSERT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 1u);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read()[0].node_id(), (ua::NodeId{2, 42}))
    << "the Read targets the monitored item's node";
  ASSERT_EQ(delivered.size(), 1u) << "the polled value must be delivered to the item's callback";
}

// CL-SUB-019: removing a fallback Subscription cancels its driver - a subsequent tick is inert (no Read).
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverStopsAfterRemoval)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;

  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);
  pipeline->add_monitored_item_async(fallbackSubId, 7, ua::NodeId{2, 42}, [](ua::DataValue) {});
  f.ctx.poll();

  pipeline->remove_subscription_async(fallbackSubId);
  f.ctx.poll();
  EXPECT_FALSE(SubscriptionsPipelineTestAccess::is_fallback_subscription(*pipeline, fallbackSubId))
    << "removal must drop the fallback Subscription";

  SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
  f.ctx.poll();
  EXPECT_EQ(f.wireOps->readCalls, 0u) << "a removed fallback Subscription must not poll";
}

// CL-SUB-019: only Reporting items are polled - a Disabled item is not read (no server-side monitoring
// exists, so the monitoring mode is honoured client-side).
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverPollsOnlyReportingItems)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;

  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);
  pipeline->add_monitored_item_async(
    fallbackSubId,
    /*clientHandle=*/7,
    ua::NodeId{2, 42},
    [](ua::DataValue) {},
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Disabled);  // NOT Reporting
  f.ctx.poll();

  SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
  f.ctx.poll();
  EXPECT_EQ(f.wireOps->readCalls, 0u) << "a Disabled item must not be polled";
}

// CL-SUB-019: a fallback Subscription is EXCLUDED from reconnect recovery - it gets NO Republish drain and NO
// recreate descriptor (there is no server counterpart; its polling driver resumes instead). A regression here
// would issue real wire ops (Republish / Transfer / CreateSubscription) for a server-less Subscription.
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST(SubscriptionsPipeline, FallbackExcludedFromReconnectRecovery)
{
  Fixture f;
  auto pipeline = f.make();
  pipeline->add_subscription_async(77, 100.0);  // a REAL server-backed Subscription
  pipeline->engage_fallback_subscription_async(0x80000000u, 100.0, /*publishingEnabled=*/true);  // a fallback
  f.ctx.poll();

  // recovery_descriptors_async: only the real Subscription yields a transfer/recreate descriptor.
  std::optional<std::vector<ua::client::detail::RecoveryDescriptor>> descriptors;
  pipeline->recovery_descriptors_async(
    [&descriptors](std::vector<ua::client::detail::RecoveryDescriptor> d) { descriptors = std::move(d); });
  f.ctx.poll();
  ASSERT_TRUE(descriptors.has_value());
  ASSERT_EQ(descriptors->size(), 1u) << "the fallback Subscription must NOT get a recreate descriptor";
  EXPECT_EQ((*descriptors)[0].subscriptionId, 77u);

  // recover_subscriptions_async: only the real Subscription is Republished; the fallback is skipped.
  pipeline->recover_subscriptions_async([](ua::Result<void>) {});
  f.ctx.poll();
  ASSERT_EQ(f.host->republishes.size(), 1u)
    << "only the server-backed Subscription is Republished on recovery; the fallback is skipped";
  EXPECT_EQ(f.host->republishes[0].first, 77u);
}

// CL-SUB-019: a fallback Subscription SURVIVES a reconnect. stop_async cancels its poll timer but RETAINS the
// entry (it is not swept into recovery - it lives in a separate map); resume_async re-arms it so polling
// continues on the fresh channel.
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST(SubscriptionsPipeline, FallbackSurvivesStopResume)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);
  pipeline->add_monitored_item_async(fallbackSubId, 7, ua::NodeId{2, 42}, [](ua::DataValue) {});
  f.ctx.poll();
  f.ctx
    .restart();  // the single io_context drains to "stopped" after each poll(); restart before the next phase

  pipeline->stop_async();
  f.ctx.poll();
  f.ctx.restart();
  EXPECT_TRUE(SubscriptionsPipelineTestAccess::is_fallback_subscription(*pipeline, fallbackSubId))
    << "stop retains the fallback entry (it only cancels the timer)";

  pipeline->resume_async();
  f.ctx.poll();
  f.ctx.restart();
  SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
  f.ctx.poll();
  EXPECT_EQ(f.wireOps->readCalls, 1u)
    << "the fallback driver resumes polling on the fresh channel after a reconnect resume";
}

// CL-SUB-020: the fallback driver's polling tick pages its bulk Read at WireOps::max_nodes_per_read - 25
// Reporting items at a page size of 10 issue 3 Reads (10, 10, 5), never one over-limit 25-node Read the
// server would reject. Falsifiable: a driver that did not page would issue a single Read of 25.
// @verifies CL-SUB-020
// @relation(CL-SUB-020, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverPagesPollAtMaxNodesPerRead)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  f.wireOps->maxNodesPerRead = 10;  // force multi-page paging for a 25-item poll
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);
  for (std::uint32_t handle = 1; handle <= 25; ++handle)
  {
    pipeline->add_monitored_item_async(fallbackSubId, handle, ua::NodeId{2, handle}, [](ua::DataValue) {});
  }
  f.ctx.poll();

  SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
  f.ctx.poll();

  EXPECT_EQ(f.wireOps->readCalls, 3u) << "25 items at MaxNodesPerRead=10 must page into 3 Reads (10, 10, 5)";
  ASSERT_EQ(f.wireOps->readRequests.size(), 3u);
  EXPECT_EQ(f.wireOps->readRequests[0].nodes_to_read().size(), 10u);
  EXPECT_EQ(f.wireOps->readRequests[1].nodes_to_read().size(), 10u);
  EXPECT_EQ(f.wireOps->readRequests[2].nodes_to_read().size(), 5u);
}

// A polled value has no notification of its own, so the code of the Read page that answered it (its
// ServiceResult, a Good subcode or an Uncertain code) becomes the status of each value it outranks; a Bad
// ServiceResult fails the poll.

/// A scripted poll page: ServiceResult @p serviceResult over @p values.
ua::Result<ua::ReadResponse> make_poll_page(ua::StatusCode serviceResult, std::vector<ua::DataValue> values)
{
  ua::ReadResponse response;
  response.response_header().service_result() = std::move(serviceResult);
  for (auto& value : values)
  {
    response.results().push_back(std::move(value));
  }
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

/// The status code of @p value, plain Good when it carries none.
ua::StatusCodeValue status_of(const ua::DataValue& value)
{
  return value.status().value_or(ua::StatusCode{ua::Status::Good}).value();
}

/// Runs poll_read_async for @p count nodes and returns its result.
ua::Result<std::vector<ua::DataValue>> poll_read(
  Fixture& f, SubscriptionsPipeline& pipeline, std::size_t count)
{
  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  pipeline.poll_read_async(std::vector<ua::ReadValueId>(count),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  f.ctx.run();
  EXPECT_TRUE(captured.has_value()) << "the poll's callback must run";
  return captured.value_or(
    ua::Result<std::vector<ua::DataValue>>{ua::StatusCode{ua::Status::BadInternalError}});
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(SubscriptionsPipeline, PollReadPutsAPagesGoodSubcodeOnItsPlainGoodValues)
{
  Fixture f;
  auto pipeline = f.make();
  f.wireOps->scriptedReadResponses.push_back(
    make_poll_page(ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete},
      {ua::DataValue{ua::Variant{std::int32_t{1}}},
        ua::DataValue{ua::Variant{std::int32_t{2}}, ua::StatusCode{ua::Status::GoodLocalOverride}},
        ua::DataValue{ua::Variant{std::int32_t{3}}, ua::StatusCode{ua::Status::UncertainInitialValue}}}));

  const auto result = poll_read(f, *pipeline, 3);

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(result.value().size(), 3u);
  EXPECT_EQ(status_of(result.value()[0]), ua::StatusCode{ua::Status::GoodResultsMayBeIncomplete}.value())
    << "a plain Good value takes the page's Good subcode";
  EXPECT_EQ(status_of(result.value()[1]), ua::StatusCode{ua::Status::GoodLocalOverride}.value())
    << "a value's own Good subcode is kept";
  EXPECT_EQ(status_of(result.value()[2]), ua::StatusCode{ua::Status::UncertainInitialValue}.value())
    << "a worse value status is kept";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(SubscriptionsPipeline, PollReadPutsAPagesUncertainCodeOnEachValueItOutranks)
{
  Fixture f;
  auto pipeline = f.make();
  f.wireOps->scriptedReadResponses.push_back(
    make_poll_page(ua::StatusCode{ua::Status::UncertainLastUsableValue},
      {ua::DataValue{ua::Variant{std::int32_t{1}}},
        ua::DataValue{ua::Variant{std::int32_t{2}}, ua::StatusCode{ua::Status::GoodLocalOverride}},
        ua::DataValue{ua::Variant{std::int32_t{3}}, ua::StatusCode{ua::Status::UncertainInitialValue}},
        ua::DataValue{ua::StatusCode{ua::Status::BadNodeIdUnknown}}}));

  const auto result = poll_read(f, *pipeline, 4);

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(result.value().size(), 4u);
  EXPECT_EQ(status_of(result.value()[0]), ua::StatusCode{ua::Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(status_of(result.value()[1]), ua::StatusCode{ua::Status::UncertainLastUsableValue}.value())
    << "the page's Uncertain code outranks a value's Good subcode";
  EXPECT_EQ(status_of(result.value()[2]), ua::StatusCode{ua::Status::UncertainInitialValue}.value())
    << "of two Uncertain subcodes the value's own is kept";
  EXPECT_EQ(status_of(result.value()[3]), ua::StatusCode{ua::Status::BadNodeIdUnknown}.value())
    << "a Bad value status is kept";
  EXPECT_EQ(result.value()[0].value(), ua::Variant{std::int32_t{1}}) << "the value is kept with the code";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(SubscriptionsPipeline, PollReadFailsWithABadPagesServiceResult)
{
  Fixture f;
  f.wireOps->maxNodesPerRead = 1;  // two pages
  auto pipeline = f.make();
  f.wireOps->scriptedReadResponses.push_back(make_poll_page(
    ua::StatusCode{ua::Status::BadTooManyOperations}, {ua::DataValue{ua::Variant{std::int32_t{1}}}}));

  const auto result = poll_read(f, *pipeline, 2);

  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadTooManyOperations);
  EXPECT_EQ(f.wireOps->readCalls, 1u) << "the poll stops at the failed page";
}

// The fallback driver delivers the polled value with the page's Uncertain code to the item's callback.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverDeliversThePagesUncertainCodeOnThePolledValue)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);
  std::vector<ua::DataValue> delivered;
  pipeline->add_monitored_item_async(fallbackSubId,
    /*clientHandle=*/7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value) { delivered.push_back(std::move(value)); });
  f.ctx.poll();
  f.ctx.restart();
  f.wireOps->scriptedReadResponses.push_back(make_poll_page(
    ua::StatusCode{ua::Status::UncertainLastUsableValue}, {ua::DataValue{ua::Variant{std::int32_t{5}}}}));

  SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
  f.ctx.poll();

  ASSERT_EQ(delivered.size(), 1u);
  EXPECT_EQ(status_of(delivered.front()), ua::StatusCode{ua::Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(delivered.front().value(), ua::Variant{std::int32_t{5}});
}

// Builds a scripted single-result ReadResponse for a fallback poll (one item -> one DataValue).
ua::Result<ua::ReadResponse> make_poll_response(ua::DataValue value)
{
  ua::ReadResponse response;
  response.results().push_back(std::move(value));
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

// CL-SUB-021: the fallback driver applies an AbsoluteDeadband client-side - a polled Value within the
// deadband of the last DISPATCHED value is not delivered. Reads 1.0, 1.2, 1.6, 1.6 at deadband 0.5 dispatch
// only 1.0 and 1.6 (1.2 is +0.2 within band; the repeat 1.6 is +0.0). Falsifiable: no filtering delivers all
// four.
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverAppliesAbsoluteDeadband)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);

  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Absolute);
  filter.deadband_value() = 0.5;
  std::vector<double> delivered;
  pipeline->add_monitored_item_async(
    fallbackSubId,
    7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value)
    {
      if (auto number = value.value().to<double>(); number.is_good())
        delivered.push_back(number.value());
    },
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Reporting,
    true,
    filter);
  f.ctx.poll();
  f.ctx.restart();

  for (double sample : {1.0, 1.2, 1.6, 1.6})
  {
    f.wireOps->scriptedReadResponses.push_back(make_poll_response(ua::DataValue{ua::Variant{sample}}));
    SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
    f.ctx.poll();
    f.ctx.restart();
  }
  EXPECT_EQ(delivered, (std::vector<double>{1.0, 1.6}))
    << "the AbsoluteDeadband must drop the within-band 1.2 and the repeated 1.6";
}

// CL-SUB-021: the AbsoluteDeadband must apply to EVERY built-in numeric type, not just Double.
// `Variant::to<T>()` is exact-type extraction, so a Float-typed value (the dominant analog type) must be
// widened before the deadband math or the band is silently inert. Reads Float 1.0, 1.2, 1.6, 1.6 at deadband
// 0.5 dispatch only 1.0 and 1.6. Falsifiable: a to<double>()-only evaluator delivers all four (Float never
// matches Double).
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverAppliesAbsoluteDeadbandToFloat)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);

  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Absolute);
  filter.deadband_value() = 0.5;
  std::vector<float> delivered;
  pipeline->add_monitored_item_async(
    fallbackSubId,
    7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value)
    {
      if (auto number = value.value().to<float>(); number.is_good())
        delivered.push_back(number.value());
    },
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Reporting,
    true,
    filter);
  f.ctx.poll();
  f.ctx.restart();

  for (float sample : {1.0F, 1.2F, 1.6F, 1.6F})
  {
    f.wireOps->scriptedReadResponses.push_back(make_poll_response(ua::DataValue{ua::Variant{sample}}));
    SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
    f.ctx.poll();
    f.ctx.restart();
  }
  EXPECT_EQ(delivered, (std::vector<float>{1.0F, 1.6F}))
    << "the AbsoluteDeadband must widen and filter Float values, not just Double";
}

// CL-SUB-021: a Good-status NaN sample must NOT latch the item into permanent silence. With a naive
// `abs(x - NaN) > deadband` (always false) a NaN first sample would suppress every later value forever. A NaN
// EXIT (NaN -> finite) is a change and must dispatch. Sequence: NaN (first->dispatch), 5.0 (NaN->real is a
// change->dispatch), 5.1 (within 0.5->drop). Falsifiable: an unguarded evaluator delivers only the NaN and
// never the 5.0.
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverNaNSampleDoesNotLatchDeadband)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);

  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Absolute);
  filter.deadband_value() = 0.5;
  std::vector<double> delivered;
  pipeline->add_monitored_item_async(
    fallbackSubId,
    7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value)
    {
      if (auto number = value.value().to<double>(); number.is_good())
        delivered.push_back(number.value());
    },
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Reporting,
    true,
    filter);
  f.ctx.poll();
  f.ctx.restart();

  for (double sample : {std::numeric_limits<double>::quiet_NaN(), 5.0, 5.1})
  {
    f.wireOps->scriptedReadResponses.push_back(make_poll_response(ua::DataValue{ua::Variant{sample}}));
    SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
    f.ctx.poll();
    f.ctx.restart();
  }
  ASSERT_EQ(delivered.size(), 2u) << "NaN then 5.0 must both dispatch; a NaN must not latch the item silent";
  EXPECT_TRUE(std::isnan(delivered[0]));
  EXPECT_DOUBLE_EQ(delivered[1], 5.0);
}

// CL-SUB-021 (section 3.1 MEDIUM regression): a STUCK NaN must be reported ONCE, then stay silent - an
// AbsoluteDeadband item whose value is repeatedly NaN must NOT re-deliver the identical NaN every poll
// (notification amplification the server would never emit). NaN->NaN is UNCHANGED. Sequence: NaN
// (enter->dispatch), NaN (unchanged->drop), NaN (unchanged->drop), 6.0 (exit->dispatch). Falsifiable: a "any
// NaN is a change" evaluator delivers 4 values (re-reports each stuck NaN).
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverStuckNaNReportedOnceNotEveryPoll)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);

  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Absolute);
  filter.deadband_value() = 0.5;
  std::vector<double> delivered;
  pipeline->add_monitored_item_async(
    fallbackSubId,
    7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value)
    {
      if (auto number = value.value().to<double>(); number.is_good())
        delivered.push_back(number.value());
    },
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Reporting,
    true,
    filter);
  f.ctx.poll();
  f.ctx.restart();

  const double nan = std::numeric_limits<double>::quiet_NaN();
  for (double sample : {nan, nan, nan, 6.0})
  {
    f.wireOps->scriptedReadResponses.push_back(make_poll_response(ua::DataValue{ua::Variant{sample}}));
    SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
    f.ctx.poll();
    f.ctx.restart();
  }
  ASSERT_EQ(delivered.size(), 2u)
    << "a stuck NaN must be reported once (enter) then stay silent until the value changes (exit)";
  EXPECT_TRUE(std::isnan(delivered[0]));
  EXPECT_DOUBLE_EQ(delivered[1], 6.0);
}

// CL-SUB-021 (section 3.1 LOW regression): a non-finite AbsoluteDeadband value (NaN - e.g. a mis-computed
// band that slips past attach-time validation) must NOT latch the item silent (`|delta| > NaN` is always
// false). Treated as no deadband: every value change dispatches. Sequence 1.0, 2.0, 3.0 all dispatch.
// Falsifiable: a `return |delta| > deadband` with a NaN band delivers only the first sample and then goes
// silent forever.
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverNonFiniteDeadbandDoesNotLatch)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);

  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Absolute);
  filter.deadband_value() = std::numeric_limits<double>::quiet_NaN();
  std::vector<double> delivered;
  pipeline->add_monitored_item_async(
    fallbackSubId,
    7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value)
    {
      if (auto number = value.value().to<double>(); number.is_good())
        delivered.push_back(number.value());
    },
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Reporting,
    true,
    filter);
  f.ctx.poll();
  f.ctx.restart();

  for (double sample : {1.0, 2.0, 3.0})
  {
    f.wireOps->scriptedReadResponses.push_back(make_poll_response(ua::DataValue{ua::Variant{sample}}));
    SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
    f.ctx.poll();
    f.ctx.restart();
  }
  EXPECT_EQ(delivered, (std::vector<double>{1.0, 2.0, 3.0}))
    << "a non-finite deadband must not latch the item; every change dispatches";
}

// CL-SUB-021 (section 3.1 re-review MEDIUM regression): a NEGATIVE AbsoluteDeadband value must NOT
// over-report an UNCHANGED value. `|delta| > deadband` with a negative band is always true (even `|0| > -1`),
// so an unchanged value would dispatch every poll (a dedup violation a conformant server rejects with
// Bad_DeadbandFilterInvalid). A server-less fallback has no server to reject it, so an unusable (negative)
// band is treated as no deadband: unchanged stays silent, changed dispatches. Sequence 5.0, 5.0, 6.0 ->
// [5.0, 6.0] (the repeat 5.0 suppressed). Falsifiable: `return |delta| > deadband` with a negative band
// delivers all three (re-reports the unchanged 5.0).
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverNegativeDeadbandDoesNotOverReport)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);

  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::Absolute);
  filter.deadband_value() = -1.0;
  std::vector<double> delivered;
  pipeline->add_monitored_item_async(
    fallbackSubId,
    7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value)
    {
      if (auto number = value.value().to<double>(); number.is_good())
        delivered.push_back(number.value());
    },
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Reporting,
    true,
    filter);
  f.ctx.poll();
  f.ctx.restart();

  for (double sample : {5.0, 5.0, 6.0})
  {
    f.wireOps->scriptedReadResponses.push_back(make_poll_response(ua::DataValue{ua::Variant{sample}}));
    SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
    f.ctx.poll();
    f.ctx.restart();
  }
  EXPECT_EQ(delivered, (std::vector<double>{5.0, 6.0}))
    << "a negative deadband must not re-report an unchanged value; unchanged stays silent";
}

// CL-SUB-021: a Trigger=StatusValue filter dispatches on a Value or StatusCode change, NOT a
// SourceTimestamp-only change. Falsifiable: a timestamp-only change would be delivered without the trigger
// gate.
// @verifies CL-SUB-021
// @relation(CL-SUB-021, scope=function)
TEST(SubscriptionsPipeline, FallbackDriverTriggerStatusValueIgnoresTimestampOnlyChange)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/true);

  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = static_cast<std::uint32_t>(ua::DeadbandType::None);
  std::vector<std::int32_t> delivered;
  pipeline->add_monitored_item_async(
    fallbackSubId,
    7,
    ua::NodeId{2, 42},
    [&delivered](ua::DataValue value)
    {
      if (auto number = value.value().to<std::int32_t>(); number.is_good())
        delivered.push_back(number.value());
    },
    ua::AttributeId::Value,
    std::nullopt,
    0.0,
    1,
    ua::MonitoringMode::Reporting,
    true,
    filter);
  f.ctx.poll();
  f.ctx.restart();

  const ua::StatusCode good{ua::Status::Good};
  // (value, sourceTimestamp-seconds): 10@t1 (first->dispatch), 10@t2 (timestamp-only->drop), 20@t3
  // (value->dispatch).
  const std::vector<std::pair<std::int32_t, std::int64_t>> samples{{10, 100}, {10, 200}, {20, 300}};
  for (const auto& [sampleValue, timestampSeconds] : samples)
  {
    ua::DataValue dataValue{
      ua::Variant{sampleValue}, good, ua::DateTime{2024, 1, 1, 0, 0, static_cast<double>(timestampSeconds)}};
    f.wireOps->scriptedReadResponses.push_back(make_poll_response(std::move(dataValue)));
    SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
    f.ctx.poll();
    f.ctx.restart();
  }
  EXPECT_EQ(delivered, (std::vector<std::int32_t>{10, 20}))
    << "StatusValue must dispatch on a value change but NOT on a timestamp-only change";
}

// CL-SUB-019: a fallback Subscription created with publishingEnabled=false polls nothing (no Reads).
// @verifies CL-SUB-019
// @relation(CL-SUB-019, scope=function)
TEST(SubscriptionsPipeline, FallbackDisabledPublishingPollsNothing)
{
  using ua::client::detail::SubscriptionsPipelineTestAccess;
  Fixture f;
  auto pipeline = f.make();
  constexpr std::uint32_t fallbackSubId = 0x80000000u;
  pipeline->engage_fallback_subscription_async(fallbackSubId, 100.0, /*publishingEnabled=*/false);
  pipeline->add_monitored_item_async(fallbackSubId, 7, ua::NodeId{2, 42}, [](ua::DataValue) {});
  f.ctx.poll();

  SubscriptionsPipelineTestAccess::poll_fallback_tick_once(*pipeline, fallbackSubId);
  f.ctx.poll();
  EXPECT_EQ(f.wireOps->readCalls, 0u) << "a publishing-disabled fallback Subscription must not poll";
}

// An empty read set delivers an empty result WITHOUT issuing a Read.
TEST(SubscriptionsPipeline, PollReadEmptyIssuesNoRead)
{
  Fixture f;
  auto pipeline = f.make();

  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  pipeline->poll_read_async(
    {}, [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good());
  EXPECT_TRUE(captured->value().empty());
  EXPECT_EQ(f.wireOps->readCalls, 0u) << "no nodes => no Read is issued";
}

// A page failure short-circuits the fallback and propagates the bad status (its ErrorDetail is preserved).
TEST(SubscriptionsPipeline, PollReadPropagatesPageFailure)
{
  Fixture f;
  f.wireOps->readStatus = ua::StatusCode{ua::Status::BadTimeout};
  auto pipeline = f.make();

  std::vector<ua::ReadValueId> reads(3);
  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  pipeline->poll_read_async(std::move(reads),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().value(), ua::StatusCode{ua::Status::BadTimeout}.value());
  EXPECT_EQ(f.wireOps->readCalls, 1u) << "the first bad page short-circuits the remaining pages";
}

// section 3.1 sub-note (M1): the bad-page short-circuit must PRESERVE the page's full ErrorDetail chain, not
// just a bare status - the detail rides inside the StatusCode. A page whose failure carried a source-tagged
// detail must reach the caller with that detail intact. Falsifies: a short-circuit that reconstructs a bare
// StatusCode and drops the wire failure's ErrorDetail.
TEST(SubscriptionsPipeline, PollReadAsync_PageFailure_PreservesErrorDetailChain)
{
  Fixture f;
  f.wireOps->readStatus = ua::StatusCode{ua::Status::BadTimeout,
    ua::make_error_detail("WireReadTimeout", "the Read wire op timed out", "test.wire_read")};
  auto pipeline = f.make();

  std::vector<ua::ReadValueId> reads(3);
  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  pipeline->poll_read_async(std::move(reads),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad());
  ASSERT_NE(captured->shared_detail(), nullptr)
    << "the failing page's ErrorDetail must not be dropped at the short-circuit";
  EXPECT_EQ(captured->shared_detail()->source, "test.wire_read");
  EXPECT_EQ(captured->shared_detail()->code, "WireReadTimeout");
}

// M1 (section 3.1, medium): the paged Read stitcher must VALIDATE that each page returned exactly as many
// DataValues as ReadValueIds it sent (OPC UA 10000-4 section 5.10.2: results.size() == nodesToRead.size()). A
// service-Good response with a mismatched count would misalign values to the wrong nodes (positional
// results[i] <-> reads[i]) and leave the stitched vector length != reads.size(). With 3 reads at page size
// 2, a first page that under-returns by one must short-circuit the whole fallback to a source-tagged Bad -
// NOT a Good vector of size 2.
// Falsifies: the pre-fix blind append (delivers Good with a misaligned/short vector).
TEST(SubscriptionsPipeline, PollReadAsync_ShortPageResultCount_DeliversBadNotMisalignedGood)
{
  Fixture f;
  f.wireOps->maxNodesPerRead = 2;  // 3 nodes -> first page requests 2 nodes
  f.wireOps->resultsPerReadDelta = -1;  // ...but the server under-returns by one DataValue per page
  auto pipeline = f.make();

  std::vector<ua::ReadValueId> reads(3);
  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  pipeline->poll_read_async(std::move(reads),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(captured.has_value());
  EXPECT_TRUE(captured->is_bad())
    << "a per-page result-count mismatch must short-circuit to Bad, not deliver a misaligned Good vector";
  EXPECT_EQ(captured->status_code().value(), ua::StatusCode{ua::Status::BadUnexpectedError}.value());
  ASSERT_NE(captured->shared_detail(), nullptr);
  EXPECT_EQ(
    captured->shared_detail()->source, "client.tier1.subscriptions_pipeline.poll_read.result_count_mismatch")
    << "the manufactured mismatch failure must be source-tagged (error_handling.md)";
  EXPECT_EQ(f.wireOps->readCalls, 1u) << "the mismatched first page short-circuits the remaining pages";
}

// M1 guard (stays GREEN, defends against over-fitting): when every page returns EXACTLY its requested count,
// the fallback delivers a Good vector of the full length, stitched in request order. The fake fills a
// monotonically increasing Int32 per DataValue in page/request order, so [A,B,C] == [0,1,2].
TEST(SubscriptionsPipeline, PollReadAsync_ExactPageCounts_StitchesInRequestOrder)
{
  Fixture f;
  f.wireOps->maxNodesPerRead = 2;  // 3 nodes -> pages of {2, 1}, each returning its exact requested count
  auto pipeline = f.make();

  std::vector<ua::ReadValueId> reads(3);
  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  pipeline->poll_read_async(std::move(reads),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });
  f.ctx.run();

  ASSERT_TRUE(captured.has_value());
  ASSERT_TRUE(captured->is_good()) << "exact per-page counts must stitch to a full Good vector";
  ASSERT_EQ(captured->value().size(), 3u) << "the stitched vector length must equal reads.size()";
  const std::int32_t* first = captured->value()[0].value().try_as<std::int32_t>();
  const std::int32_t* second = captured->value()[1].value().try_as<std::int32_t>();
  const std::int32_t* third = captured->value()[2].value().try_as<std::int32_t>();
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  ASSERT_NE(third, nullptr);
  EXPECT_EQ(*first, 0) << "request order must be preserved across pages: [A,B,C]";
  EXPECT_EQ(*second, 1);
  EXPECT_EQ(*third, 2);
}

// M2 (section 3.1, low): the poll-read gone path (the pipeline destroyed between the post and its strand
// turn) must complete a SOURCE-TAGGED Bad_ConnectionClosed, not a bare status. Post poll_read_async, destroy
// the pipeline before draining the strand, then run the executor: the completion-owning post fires its owed
// goneResult.
// Falsifies: the pre-fix bare `Result{BadConnectionClosed}` (no ErrorDetail).
TEST(SubscriptionsPipeline, PollReadAsync_PipelineGoneBeforeStrandTurn_FailureIsSourceTagged)
{
  Fixture f;
  auto pipeline = f.make();

  std::optional<ua::Result<std::vector<ua::DataValue>>> captured;
  std::vector<ua::ReadValueId> reads(2);
  pipeline->poll_read_async(std::move(reads),
    [&captured](ua::Result<std::vector<ua::DataValue>> result) { captured = std::move(result); });

  // Destroy the pipeline BEFORE the strand turn runs: the posted work's weak_from_this() will fail to lock
  // and the completion-owning post must fire its owed goneResult.
  pipeline.reset();
  f.ctx.run();

  ASSERT_TRUE(captured.has_value()) << "the owed completion must fire exactly once on the gone path";
  EXPECT_TRUE(captured->is_bad());
  EXPECT_EQ(captured->status_code().value(), ua::StatusCode{ua::Status::BadConnectionClosed}.value());
  ASSERT_NE(captured->shared_detail(), nullptr) << "the gone-path failure must carry an ErrorDetail";
  EXPECT_EQ(captured->shared_detail()->source, "client.tier1.subscriptions_pipeline.poll_read.pipeline_gone")
    << "the gone-path failure must identify the pipeline poll-read boundary";
}

// @verifies CL-MI-026
// Per-item notification delivery must be serialized AND in arrival order even when the connection executor is
// MULTI-THREADED. The pipeline processes notifications in order on its processing strand, then hops the user
// callback onto a dedicated DELIVERY STRAND (not the bare executor), so a multi-threaded thread_pool can
// neither reorder the callbacks nor re-enter one concurrently. Without the delivery strand (a bare post of
// each callback to the shared multi-threaded pool) this fails both ways: the second callback runs
// concurrently with the first (maxInFlight == 2) and, being un-held, completes first (order [2,1]) - the
// exact CL-MI-026 violation, whose stated "the executor preserves enqueue order" assumption is false for a
// multi-threaded executor (the reference client configures a two-thread Runtime).
// [neg: bare-post to a multi-threaded executor -> concurrent re-entry + out-of-order delivery]
// @relation(CL-MI-026, scope=function)
TEST(SubscriptionsPipeline, PerItemDeliverySerializedAndOrderedUnderMultiThreadedExecutor)
{
  boost::asio::thread_pool pool{4};
  auto host = std::make_shared<RecordingHost>();
  auto wireOps = std::make_shared<FakeWireOps>();
  auto support = std::make_shared<FakeSupportOps>();
  support->executor = pool.get_executor();
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  auto logSink = std::make_shared<RecordingLogSink>();
  auto pipeline = SubscriptionsPipeline::create(
    pool.get_executor(), host, wireOps, support, ua::Logger{logSink, level, "test"});

  std::atomic<int> inFlight{0};
  std::atomic<int> maxInFlight{0};
  std::atomic<int> delivered{0};
  std::mutex orderMutex;
  std::vector<std::int32_t> order;

  pipeline->add_monitored_item_async(7,
    /*clientHandle=*/5,
    ua::NodeId{},
    [&](ua::DataValue value)
    {
      const int now = inFlight.fetch_add(1) + 1;
      for (int observed = maxInFlight.load(); now > observed;)
        if (maxInFlight.compare_exchange_weak(observed, now))
          break;
      const auto seq = value.value().to<std::int32_t>().value();
      if (seq == 1)
      {
        // Hold the FIRST callback until a second is concurrently in flight OR a bounded cap elapses. With the
        // delivery strand the second callback cannot start until this one returns, so this waits the full cap
        // (then proceeds, serialized); with a bare multi-threaded post the second runs concurrently and we
        // observe inFlight == 2 at once. Bounded wait, no asio timer (shard-flake rule).
        const auto cap = std::chrono::steady_clock::now() + std::chrono::milliseconds{300};
        while (inFlight.load() < 2 && std::chrono::steady_clock::now() < cap)
          std::this_thread::sleep_for(std::chrono::milliseconds{1});
      }
      {
        const std::lock_guard<std::mutex> lock{orderMutex};
        order.push_back(seq);
      }
      inFlight.fetch_sub(1);
      delivered.fetch_add(1);
    });

  pipeline->deliver_notification_async(5, ua::DataValue{ua::Variant{std::int32_t{1}}});
  pipeline->deliver_notification_async(5, ua::DataValue{ua::Variant{std::int32_t{2}}});

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (delivered.load() < 2 && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  pool.join();  // flush all posted work before asserting

  ASSERT_EQ(delivered.load(), 2) << "both notifications must be delivered";
  EXPECT_EQ(maxInFlight.load(), 1)
    << "per-item callbacks must never run concurrently - the delivery strand serializes them";
  EXPECT_EQ(order, (std::vector<std::int32_t>{1, 2}))
    << "same-handle notifications must be delivered in arrival order (CL-MI-026), not reordered by a "
       "multi-threaded executor";
}

}  // namespace
