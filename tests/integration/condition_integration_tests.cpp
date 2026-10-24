// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// ConditionPayload & Alarm Integration Tests
///
/// Integration tests for the Alarms & Conditions subsystem. These tests use the real
/// Conditions + ConditionInstance with a real boost::asio::thread_pool and strand-serialized
/// components, but substitute a FakeEventSink to capture emitted events without a full TCP transport.
///
/// Tests verify multi-component interaction through the strand-serialized component system:
///   1. Conditions registry (create, find, deregister, factories)
///   2. Enable/Disable lifecycle with event emission
///   3. Alarm activate/deactivate with severity tracking
///   4. Acknowledge/Confirm with EventId validation
///   5. ConditionRefresh protocol (RefreshStart + conditions + RefreshEnd)
///   6. Full end-to-end alarm lifecycle
///   7. Event emission correctness (source, EventId, counts)
///   8. Shutdown/close_all behavior

#include "ua_audit_event_payload.h"
#include "ua_condition_instance.h"
#include "ua_conditions.h"
#include "ua_conditions_test_access.h"

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_acknowledgeable_condition_logic.h"
#include "ua_alarm_condition_payload.h"
#include "ua_alarm_condition_logic.h"
#include "ua_condition_payload.h"
#include "ua_condition_logic.h"
#include "ua_data_value.h"
#include "ua_sinks.h"
#include "ua_objecttype_id.h"
#include "ua_refresh_end_event_payload.h"
#include "ua_refresh_start_event_payload.h"
#include "ua_status.h"
#include <boost/asio/thread_pool.hpp>

// ConditionRefresh takes a SubscriptionId, so its Session/Subscription obligations (sections 16 and
// 17 below) can only be driven over a real Session against a real Subscription. Those two tests use
// the shared compliance server/session harness; everything above them stays on the strand-level
// Conditions component.
#include "compliance_helpers.h"
#include "subscription.h"

#include "ua_attribute_id.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_server.h"
#include "ua_session_method_services.h"
#include "ua_simple_attribute_operand.h"
#include "ua_variant.h"

#include "matchers.h"
#include "test_utilities.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <mutex>

#include "test_components.h"

namespace ua::test
{

// ===========================================================================
// Test EventSink that records all emitted events with thread safety
// ===========================================================================

class RecordingEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    std::lock_guard lock(mMutex);

    // Auto-assign a unique EventId if not already set, mimicking EventBus behavior.
    if (event.eventId.empty())
    {
      ++mNextId;
      event.eventId = ByteString{std::vector<uint8_t>{
        static_cast<uint8_t>(mNextId & 0xFF), static_cast<uint8_t>((mNextId >> 8) & 0xFF)}};
    }

    // Condition audit Events reach this sink alongside the Condition Events, and nothing in this
    // file is about them: every test here indexes `mEvents` or reads its last EventId, and folding
    // the audits in renumbers all of it. They are recorded separately so an audit-specific test
    // could still read them.
    if (dynamic_cast<ua::AuditEventPayload*>(&event) != nullptr)
    {
      mAuditEvents.push_back(event.clone());
      return;
    }

    mEvents.push_back(event.clone());
  }

  size_t audit_event_count() const
  {
    std::lock_guard lock(mMutex);
    return mAuditEvents.size();
  }

  size_t event_count() const
  {
    std::lock_guard lock(mMutex);
    return mEvents.size();
  }

  std::unique_ptr<BaseEvent> event_at(size_t index) const
  {
    std::lock_guard lock(mMutex);
    if (index < mEvents.size())
    {
      return mEvents[index]->clone();
    }
    return nullptr;
  }

  ByteString last_event_id() const
  {
    std::lock_guard lock(mMutex);
    if (mEvents.empty())
    {
      return {};
    }
    return mEvents.back()->eventId;
  }

  NodeId last_source_node() const
  {
    std::lock_guard lock(mMutex);
    if (mEvents.empty())
    {
      return {};
    }
    return mEvents.back()->sourceNode;
  }

  String last_source_name() const
  {
    std::lock_guard lock(mMutex);
    if (mEvents.empty())
    {
      return {};
    }
    return mEvents.back()->sourceName;
  }

  void clear()
  {
    std::lock_guard lock(mMutex);
    mEvents.clear();
    mNextId = 0;
  }

  /// Get all events as clones for inspection.
  std::vector<std::unique_ptr<BaseEvent>> all_events() const
  {
    std::lock_guard lock(mMutex);
    std::vector<std::unique_ptr<BaseEvent>> result;
    result.reserve(mEvents.size());
    for (const auto& event : mEvents)
    {
      result.push_back(event->clone());
    }
    return result;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::unique_ptr<BaseEvent>> mEvents;
  std::vector<std::unique_ptr<BaseEvent>> mAuditEvents;
  uint16_t mNextId{0};
};

// ===========================================================================
// Test fixture
// ===========================================================================

class ConditionIntegrationTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // shared_ptr ownership is mandatory: Conditions is strand-serialised and
    // uses weak_from_this() throughout. With unique_ptr the weak_ptr would
    // always be empty and every async entry would silently no-op.
    mManager = ConditionsTestAccess::create(mPool.get_executor(), mSink);
  }

  void TearDown() override
  {
    if (mManager)
    {
      ConditionsTestAccess::close_sync(*mManager);
    }
    mManager.reset();
    ::ua::test_utils::stop_pool_in_teardown(mPool, "condition");
  }

  /// Create a base ConditionLogic instance via the manager.
  std::shared_ptr<ConditionInstance> create_basic_condition(
    uint32_t id = 1000, uint32_t sourceId = 100, const char* sourceName = "TestSource")
  {
    return mManager->create_condition_sync(
      NodeId{1, id}, NodeId{1, sourceId}, String{sourceName}, std::make_unique<ConditionLogic>());
  }

  /// Create an AlarmConditionLogic instance via the manager.
  std::shared_ptr<ConditionInstance> create_alarm_condition(
    uint32_t id = 2000, uint32_t sourceId = 200, const char* sourceName = "AlarmSource")
  {
    return mManager->create_condition_sync(
      NodeId{1, id}, NodeId{1, sourceId}, String{sourceName}, std::make_unique<AlarmConditionLogic>());
  }

  /// Create an AcknowledgeableConditionLogic instance via the manager.
  std::shared_ptr<ConditionInstance> create_ack_condition(
    uint32_t id = 3000, uint32_t sourceId = 300, const char* sourceName = "AckSource")
  {
    return mManager->create_condition_sync(NodeId{1, id},
      NodeId{1, sourceId},
      String{sourceName},
      std::make_unique<AcknowledgeableConditionLogic>());
  }

  boost::asio::thread_pool mPool{2};
  std::shared_ptr<RecordingEventSink> mSink = std::make_shared<RecordingEventSink>();
  std::shared_ptr<Conditions> mManager;
};

// ===========================================================================
// 1. Conditions registry integration
// ===========================================================================

// @relation(SVR-AC-001, SVR-AC-085, scope=function)
TEST_F(ConditionIntegrationTest, ManagerCreatesConditionThatIsFindable)
{
  auto instance = create_basic_condition();
  ASSERT_NE(instance, nullptr);

  auto found = mManager->find_condition_sync(NodeId{1, 1000u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->condition_id(), instance->condition_id());
}

TEST_F(ConditionIntegrationTest, ManagerMultipleConditionsCoexistIndependently)
{
  auto basic = create_basic_condition(1000);
  auto alarm = create_alarm_condition(2000);

  EXPECT_NE(mManager->find_condition_sync(NodeId{1, 1000u}), nullptr);
  EXPECT_NE(mManager->find_condition_sync(NodeId{1, 2000u}), nullptr);
  EXPECT_EQ(mManager->find_condition_sync(NodeId{1, 9999u}), nullptr);
}

TEST_F(ConditionIntegrationTest, ManagerDeregisterRemovesCondition)
{
  create_basic_condition(1000);

  mManager->deregister_condition_sync(NodeId{1, 1000u});

  EXPECT_EQ(mManager->find_condition_sync(NodeId{1, 1000u}), nullptr);
}

TEST_F(ConditionIntegrationTest, ManagerRegisterPreCreatedInstanceIsFindable)
{
  auto instance = ConditionInstance::create(mPool.get_executor(),
    std::make_unique<ConditionLogic>(),
    NodeId{1, 5000u},
    NodeId{1, 500u},
    String{"External"},
    mSink);

  mManager->register_condition_sync(instance);

  auto found = mManager->find_condition_sync(NodeId{1, 5000u});
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->condition_id(), NodeId(1, 5000u));
}

TEST_F(ConditionIntegrationTest, ManagerFactoryRegistrationAndLookup)
{
  bool factoryCalled = false;
  mManager->register_factory_sync(NodeId{ObjectTypeId::ConditionType},
    [&factoryCalled]() -> std::unique_ptr<ConditionLogic>
    {
      factoryCalled = true;
      return std::make_unique<AlarmConditionLogic>();
    });

  auto factory = mManager->find_factory_sync(NodeId{ObjectTypeId::ConditionType});
  ASSERT_NE(factory, nullptr);

  auto logic = factory();
  EXPECT_TRUE(factoryCalled);
  EXPECT_NE(logic, nullptr);
}

// ===========================================================================
// 2. Enable/Disable lifecycle
// ===========================================================================

// @relation(SVR-AC-010, SVR-AC-085, scope=function)
TEST_F(ConditionIntegrationTest, EnableSetsSnapshotToEnabledAndRetained)
{
  auto instance = create_basic_condition();

  instance->enable_sync();

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->enabled());
  EXPECT_TRUE(snapshot->retained());
}

TEST_F(ConditionIntegrationTest, DisableAfterEnableSetsSnapshotToDisabledAndNotRetained)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  instance->disable_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_FALSE(snapshot->retained());
}

// @relation(SVR-AC-007, scope=function)
TEST_F(ConditionIntegrationTest, DoubleEnableReturnsBadConditionAlreadyEnabled)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  auto result = instance->try_enable_sync();
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadConditionAlreadyEnabled));
}

// @relation(SVR-AC-004, scope=function)
TEST_F(ConditionIntegrationTest, DoubleDisableReturnsBadConditionAlreadyDisabled)
{
  auto instance = create_basic_condition();

  auto result = instance->try_disable_sync();
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadConditionAlreadyDisabled));
}

// @relation(SVR-AC-010, scope=function)
TEST_F(ConditionIntegrationTest, EnableEmitsEventWithCorrectSource)
{
  auto instance = create_basic_condition(1000, 100, "MySource");

  instance->enable_sync();

  ASSERT_GE(mSink->event_count(), 1u);
  EXPECT_EQ(mSink->last_source_node(), NodeId(1, 100u));
  EXPECT_EQ(mSink->last_source_name(), String{"MySource"});
}

TEST_F(ConditionIntegrationTest, EnableEmitsEventWithAutoAssignedEventId)
{
  auto instance = create_basic_condition();

  instance->enable_sync();

  ASSERT_GE(mSink->event_count(), 1u);
  EXPECT_FALSE(mSink->last_event_id().empty());
}

// ===========================================================================
// 3. Alarm activate/deactivate lifecycle
// ===========================================================================

TEST_F(ConditionIntegrationTest, ActivateOnAlarmSetsActiveAndSeverity)
{
  auto instance = create_alarm_condition();
  instance->enable_sync();

  instance->activate_sync(750);

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->active());
  EXPECT_EQ(snapshot->severity(), 750);
}

TEST_F(ConditionIntegrationTest, DeactivateOnAlarmClearsActive)
{
  auto instance = create_alarm_condition();
  instance->enable_sync();
  instance->activate_sync(500);

  instance->deactivate_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->active());
}

TEST_F(ConditionIntegrationTest, ActivateOnBaseConditionReturnsBadNotSupported)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  auto result = instance->try_activate_sync(500);
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadNotSupported));
}

TEST_F(ConditionIntegrationTest, DeactivateOnBaseConditionReturnsBadNotSupported)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  auto result = instance->try_deactivate_sync();
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadNotSupported));
}

TEST_F(ConditionIntegrationTest, ActivateResetsAckedStateToUnacknowledged)
{
  auto instance = create_alarm_condition();
  instance->enable_sync();
  instance->activate_sync(500);

  // Acknowledge the alarm.
  auto eventId = mSink->last_event_id();
  ASSERT_FALSE(eventId.empty());
  instance->acknowledge_sync(eventId, LocalizedText{"", "Acked"});

  auto snapshotAfterAck = instance->snapshot();
  EXPECT_TRUE(snapshotAfterAck->acked());

  // Activate again should reset AckedState.
  instance->activate_sync(600);

  auto snapshotAfterReactivate = instance->snapshot();
  EXPECT_FALSE(snapshotAfterReactivate->acked());
}

// ===========================================================================
// 4. Acknowledge/Confirm
// ===========================================================================

// @relation(SVR-AC-026, scope=function)
TEST_F(ConditionIntegrationTest, AcknowledgeWithValidEventIdSucceeds)
{
  auto instance = create_alarm_condition();
  instance->enable_sync();
  instance->activate_sync(500);

  auto eventId = mSink->last_event_id();
  ASSERT_FALSE(eventId.empty());

  auto result = instance->try_acknowledge_sync(eventId, LocalizedText{"", "Acknowledged"});
  EXPECT_THAT(result, ::ua::test_helpers::Good());
}

// @relation(SVR-AC-028, scope=function)
TEST_F(ConditionIntegrationTest, AcknowledgeWithInvalidEventIdReturnsBadEventIdUnknown)
{
  auto instance = create_alarm_condition();
  instance->enable_sync();
  instance->activate_sync(500);

  ByteString wrongId{std::vector<uint8_t>{0xFF, 0xFF, 0xFF}};
  auto result = instance->try_acknowledge_sync(wrongId, LocalizedText{"", "Bad ack"});
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadEventIdUnknown));
}

TEST_F(ConditionIntegrationTest, AcknowledgeOnBaseConditionReturnsBadNotSupported)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  auto eventId = mSink->last_event_id();
  auto result = instance->try_acknowledge_sync(eventId, LocalizedText{"", "Ack"});
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadNotSupported));
}

// @relation(SVR-AC-027, SVR-AC-085, scope=function)
TEST_F(ConditionIntegrationTest, AcknowledgeSetsSnapshotAckedState)
{
  auto instance = create_alarm_condition();
  instance->enable_sync();
  instance->activate_sync(500);

  auto eventId = mSink->last_event_id();
  instance->acknowledge_sync(eventId, LocalizedText{"", "Acked"});

  auto snapshot = instance->snapshot();
  EXPECT_TRUE(snapshot->acked());
}

// @relation(SVR-AC-033, scope=function)
TEST_F(ConditionIntegrationTest, ConfirmOnBaseConditionReturnsBadNotSupported)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  auto eventId = mSink->last_event_id();
  auto result = instance->try_confirm_sync(eventId, LocalizedText{"", "Confirm"});
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadNotSupported));
}

// ===========================================================================
// 5. ConditionRefresh protocol
// ===========================================================================

TEST_F(ConditionIntegrationTest, RefreshWithNoRetainedConditionsEmitsStartAndEndOnly)
{
  // Create a condition but leave it disabled (not retained).
  create_basic_condition();

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  auto events = refreshSink.all_events();
  ASSERT_GE(events.size(), 2u);

  auto* startEvent = dynamic_cast<RefreshStartEventPayload*>(events.front().get());
  EXPECT_NE(startEvent, nullptr);

  auto* endEvent = dynamic_cast<RefreshEndEventPayload*>(events.back().get());
  EXPECT_NE(endEvent, nullptr);
}

// @relation(SVR-AC-085, scope=function)
TEST_F(ConditionIntegrationTest, RefreshWithRetainedConditionsEmitsStartAndEnd)
{
  auto instance = create_basic_condition();
  instance->enable_sync();  // Makes it retained.

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  auto events = refreshSink.all_events();
  ASSERT_GE(events.size(), 2u);

  // First event must be RefreshStartEventPayload.
  auto* startEvent = dynamic_cast<RefreshStartEventPayload*>(events.front().get());
  EXPECT_NE(startEvent, nullptr);

  // Last event must be RefreshEndEventPayload.
  auto* endEvent = dynamic_cast<RefreshEndEventPayload*>(events.back().get());
  EXPECT_NE(endEvent, nullptr);
}

TEST_F(ConditionIntegrationTest, RetainedConditionsReturnsOnlyEnabledConditions)
{
  auto enabled = create_basic_condition(1000);
  create_basic_condition(2000);  // Left disabled.

  enabled->enable_sync();

  auto retained = mManager->retained_conditions_sync();
  ASSERT_EQ(retained.size(), 1u);
  EXPECT_EQ(retained[0]->condition_id(), NodeId(1, 1000u));
}

// ===========================================================================
// 6. Full end-to-end alarm lifecycle
// ===========================================================================

TEST_F(ConditionIntegrationTest, FullAlarmLifecycle_CreateEnableActivateAckDeactivate)
{
  auto alarm = create_alarm_condition();

  // Initial state: disabled, not retained.
  {
    auto snapshot = alarm->snapshot();
    EXPECT_FALSE(snapshot->enabled());
    EXPECT_FALSE(snapshot->retained());
    EXPECT_FALSE(snapshot->active());
  }

  // Enable.
  alarm->enable_sync();
  {
    auto snapshot = alarm->snapshot();
    EXPECT_TRUE(snapshot->enabled());
    EXPECT_TRUE(snapshot->retained());
    EXPECT_FALSE(snapshot->active());
  }

  // Activate with severity 800.
  alarm->activate_sync(800);
  {
    auto snapshot = alarm->snapshot();
    EXPECT_TRUE(snapshot->active());
    EXPECT_EQ(snapshot->severity(), 800);
    EXPECT_FALSE(snapshot->acked());
  }

  // Acknowledge.
  auto eventId = mSink->last_event_id();
  ASSERT_FALSE(eventId.empty());
  alarm->acknowledge_sync(eventId, LocalizedText{"", "Operator acknowledged"});
  {
    auto snapshot = alarm->snapshot();
    EXPECT_TRUE(snapshot->acked());
    EXPECT_TRUE(snapshot->active());  // Still active.
  }

  // Deactivate.
  alarm->deactivate_sync();
  {
    auto snapshot = alarm->snapshot();
    EXPECT_FALSE(snapshot->active());
    EXPECT_TRUE(snapshot->acked());
  }
}

TEST_F(ConditionIntegrationTest, FullAlarmLifecycle_CreateEnableActivateDeactivateDisable)
{
  auto alarm = create_alarm_condition();

  alarm->enable_sync();
  alarm->activate_sync(500);
  alarm->deactivate_sync();
  alarm->disable_sync();

  auto snapshot = alarm->snapshot();
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_FALSE(snapshot->active());
  EXPECT_FALSE(snapshot->retained());
}

TEST_F(ConditionIntegrationTest, FullAlarmLifecycle_DeactivateAndAckMakesRetainFalse)
{
  auto alarm = create_alarm_condition();
  alarm->enable_sync();
  alarm->activate_sync(500);

  // Acknowledge first.
  auto eventId = mSink->last_event_id();
  alarm->acknowledge_sync(eventId, LocalizedText{"", "Ack"});

  // Now deactivate: condition is enabled + acked + inactive -> retain should be false.
  alarm->deactivate_sync();

  auto snapshot = alarm->snapshot();
  EXPECT_TRUE(snapshot->enabled());
  EXPECT_FALSE(snapshot->active());
  EXPECT_TRUE(snapshot->acked());
  // For AlarmConditionLogic: retain = enabled && (active || !acked)
  // enabled=true, active=false, acked=true -> retain = true && (false || false) = false
  EXPECT_FALSE(snapshot->retained());
}

// ===========================================================================
// 7. Event emission correctness
// ===========================================================================

TEST_F(ConditionIntegrationTest, EnableAndActivateEmitMultipleEvents)
{
  auto alarm = create_alarm_condition();

  alarm->enable_sync();
  size_t countAfterEnable = mSink->event_count();
  EXPECT_GE(countAfterEnable, 1u);

  alarm->activate_sync(500);
  size_t countAfterActivate = mSink->event_count();
  EXPECT_GT(countAfterActivate, countAfterEnable);
}

TEST_F(ConditionIntegrationTest, EventSourceMatchesConditionSourceNode)
{
  auto instance = create_basic_condition(1000, 777, "SpecificSource");

  instance->enable_sync();

  EXPECT_EQ(mSink->last_source_node(), NodeId(1, 777u));
  EXPECT_EQ(mSink->last_source_name(), String{"SpecificSource"});
}

TEST_F(ConditionIntegrationTest, EachEventGetsUniqueEventId)
{
  auto alarm = create_alarm_condition();
  alarm->enable_sync();

  auto enableEventId = mSink->last_event_id();
  ASSERT_FALSE(enableEventId.empty());

  alarm->activate_sync(500);

  auto activateEventId = mSink->last_event_id();
  ASSERT_FALSE(activateEventId.empty());

  EXPECT_NE(enableEventId, activateEventId);
}

// @relation(SVR-AC-009, scope=function)
TEST_F(ConditionIntegrationTest, DisableEmitsEventWithRetainFalse)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  size_t countBefore = mSink->event_count();
  instance->disable_sync();

  // Disable should emit an event (with retain=false).
  EXPECT_GT(mSink->event_count(), countBefore);

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->retained());
}

// ===========================================================================
// 8. Close/Shutdown
// ===========================================================================

TEST_F(ConditionIntegrationTest, CloseDisablesEnabledCondition)
{
  auto instance = create_basic_condition();
  instance->enable_sync();
  ASSERT_TRUE(instance->snapshot()->enabled());

  instance->close_sync();

  auto snapshot = instance->snapshot();
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_FALSE(snapshot->retained());
}

TEST_F(ConditionIntegrationTest, CloseAllClosesAllRegisteredConditions)
{
  auto instance1 = create_basic_condition(1000);
  auto instance2 = create_alarm_condition(2000);

  instance1->enable_sync();
  instance2->enable_sync();
  instance2->activate_sync(500);

  ConditionsTestAccess::close_sync(*mManager);

  EXPECT_FALSE(instance1->snapshot()->enabled());
  EXPECT_FALSE(instance2->snapshot()->enabled());
}

TEST_F(ConditionIntegrationTest, CloseAllClearsRegistry)
{
  create_basic_condition(1000);
  create_alarm_condition(2000);

  ConditionsTestAccess::close_sync(*mManager);

  // After close, the strand is shut down. find_condition_sync would throw
  // BadShutdown - use try_*_sync to observe the post-close state directly.
  auto r1 = mManager->try_find_condition_sync(NodeId{1, 1000u});
  auto r2 = mManager->try_find_condition_sync(NodeId{1, 2000u});
  EXPECT_EQ(r1.status_code(), StatusCode{Status::BadShutdown});
  EXPECT_EQ(r2.status_code(), StatusCode{Status::BadShutdown});
}

// ===========================================================================
// 9. Add comment
// ===========================================================================

// @relation(SVR-AC-013, scope=function)
TEST_F(ConditionIntegrationTest, AddCommentWithValidEventIdSucceeds)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  auto eventId = mSink->last_event_id();
  ASSERT_FALSE(eventId.empty());

  auto result = instance->try_add_comment_sync(eventId, LocalizedText{"", "This is a comment"});
  EXPECT_THAT(result, ::ua::test_helpers::Good());
}

// @relation(SVR-AC-015, scope=function)
TEST_F(ConditionIntegrationTest, AddCommentWithInvalidEventIdReturnsBadEventIdUnknown)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  ByteString wrongId{std::vector<uint8_t>{0xFF, 0xFF}};
  auto result = instance->try_add_comment_sync(wrongId, LocalizedText{"", "Comment"});
  EXPECT_THAT(result, ::ua::test_helpers::HasStatus(Status::BadEventIdUnknown));
}

// @relation(SVR-AC-016, SVR-AC-051, SVR-AC-054, SVR-AC-085, scope=function)
TEST_F(ConditionIntegrationTest, AddCommentUpdatesSnapshotComment)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  auto eventId = mSink->last_event_id();
  instance->add_comment_sync(eventId, LocalizedText{"en", "Operator note"});

  auto snapshot = instance->snapshot();
  EXPECT_EQ(snapshot->comment().text(), "Operator note");
}

// ===========================================================================
// 10. Concurrent condition operations (multi-instance stress)
// ===========================================================================

TEST_F(ConditionIntegrationTest, MultipleConcurrentConditionsOperateIndependently)
{
  // Create multiple conditions and operate on them concurrently via async.
  constexpr int count = 5;
  std::vector<std::shared_ptr<ConditionInstance>> instances;
  for (int i = 0; i < count; ++i)
  {
    instances.push_back(
      create_alarm_condition(static_cast<uint32_t>(4000 + i), static_cast<uint32_t>(400 + i)));
  }

  // Enable all.
  for (auto& inst : instances)
  {
    inst->enable_sync();
  }

  // Activate all with different severities.
  for (int i = 0; i < count; ++i)
  {
    instances[i]->activate_sync(static_cast<uint16_t>(100 + i * 100));
  }

  // Verify each has correct severity.
  for (int i = 0; i < count; ++i)
  {
    auto snapshot = instances[i]->snapshot();
    EXPECT_TRUE(snapshot->enabled());
    EXPECT_TRUE(snapshot->active());
    EXPECT_EQ(snapshot->severity(), static_cast<uint16_t>(100 + i * 100));
  }
}

// ===========================================================================
// 11. ConditionRefresh emits retained condition events
// ===========================================================================

// @relation(SVR-AC-021, scope=function)
TEST_F(ConditionIntegrationTest, RefreshEmitsRetainedConditionEventsBetweenStartAndEnd)
{
  auto instance = create_alarm_condition();
  instance->enable_sync();
  instance->activate_sync(500);

  // Verify the condition is retained before refreshing.
  auto snapshot = instance->snapshot();
  ASSERT_TRUE(snapshot->retained());

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  auto events = refreshSink.all_events();
  ASSERT_GE(events.size(), 3u);

  // First must be RefreshStartEventPayload.
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(events.front().get()), nullptr);

  // Last must be RefreshEndEventPayload.
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(events.back().get()), nullptr);

  // At least one middle event must be a ConditionPayload event (not start/end).
  bool foundConditionEvent = false;
  for (size_t i = 1; i + 1 < events.size(); ++i)
  {
    if (dynamic_cast<ConditionPayload*>(events[i].get()) != nullptr)
    {
      foundConditionEvent = true;
      break;
    }
  }
  EXPECT_TRUE(foundConditionEvent);
}

TEST_F(ConditionIntegrationTest, RefreshSkipsNonRetainedConditions)
{
  // Create a condition but leave it disabled (not retained).
  auto instance = create_basic_condition();
  auto snapshot = instance->snapshot();
  ASSERT_FALSE(snapshot->retained());

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  auto events = refreshSink.all_events();
  // Should have exactly 2 events: RefreshStart + RefreshEnd, no condition events.
  ASSERT_EQ(events.size(), 2u);
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(events[0].get()), nullptr);
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(events[1].get()), nullptr);
}

TEST_F(ConditionIntegrationTest, RefreshConditionEventCarriesCorrectSourceNode)
{
  auto instance = create_alarm_condition(2000, 777, "SpecificAlarm");
  instance->enable_sync();
  instance->activate_sync(600);

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  auto events = refreshSink.all_events();
  ASSERT_GE(events.size(), 3u);

  // Find the condition event and verify its source node.
  for (size_t i = 1; i + 1 < events.size(); ++i)
  {
    auto* condEvent = dynamic_cast<ConditionPayload*>(events[i].get());
    if (condEvent != nullptr)
    {
      EXPECT_EQ(condEvent->sourceNode, NodeId(1, 777u));
      break;
    }
  }
}

TEST_F(ConditionIntegrationTest, RefreshMultipleRetainedConditionsEmitsAll)
{
  auto alarm1 = create_alarm_condition(2001, 201, "Alarm1");
  auto alarm2 = create_alarm_condition(2002, 202, "Alarm2");
  alarm1->enable_sync();
  alarm1->activate_sync(300);
  alarm2->enable_sync();
  alarm2->activate_sync(400);

  RecordingEventSink refreshSink;
  mManager->condition_refresh_sync(refreshSink);

  auto events = refreshSink.all_events();
  // Start + 2 condition events + End = 4.
  ASSERT_GE(events.size(), 4u);

  size_t conditionEventCount = 0;
  for (size_t i = 1; i + 1 < events.size(); ++i)
  {
    if (dynamic_cast<ConditionPayload*>(events[i].get()) != nullptr)
    {
      ++conditionEventCount;
    }
  }
  EXPECT_EQ(conditionEventCount, 2u);
}

// ===========================================================================
// 12. ConditionRefresh2 filters by source node
// ===========================================================================

// @relation(SVR-AC-025, SVR-AC-085, scope=function)
TEST_F(ConditionIntegrationTest, Refresh2FiltersBySourceNode)
{
  auto alarm1 = create_alarm_condition(3001, 100, "Source100");
  auto alarm2 = create_alarm_condition(3002, 200, "Source200");
  alarm1->enable_sync();
  alarm1->activate_sync(500);
  alarm2->enable_sync();
  alarm2->activate_sync(600);

  // Refresh2 filtering to source node 100 only.
  RecordingEventSink refreshSink;
  mManager->condition_refresh2_sync(refreshSink, NodeId{1, 100u});

  auto events = refreshSink.all_events();
  ASSERT_GE(events.size(), 3u);  // Start + 1 condition + End

  // First must be RefreshStartEventPayload, last must be RefreshEndEventPayload.
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(events.front().get()), nullptr);
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(events.back().get()), nullptr);

  // Only one condition event, and it must have source node 100.
  size_t conditionEventCount = 0;
  for (size_t i = 1; i + 1 < events.size(); ++i)
  {
    auto* condEvent = dynamic_cast<ConditionPayload*>(events[i].get());
    if (condEvent != nullptr)
    {
      ++conditionEventCount;
      EXPECT_EQ(condEvent->sourceNode, NodeId(1, 100u));
    }
  }
  EXPECT_EQ(conditionEventCount, 1u);
}

// @relation(SVR-AC-025, scope=function)
TEST_F(ConditionIntegrationTest, Refresh2WithNoMatchingSourceEmitsOnlyStartAndEnd)
{
  auto alarm = create_alarm_condition(3003, 100, "Source100");
  alarm->enable_sync();
  alarm->activate_sync(500);

  // Refresh2 with a source node that no condition matches.
  RecordingEventSink refreshSink;
  mManager->condition_refresh2_sync(refreshSink, NodeId{1, 999u});

  auto events = refreshSink.all_events();
  ASSERT_EQ(events.size(), 2u);
  EXPECT_NE(dynamic_cast<RefreshStartEventPayload*>(events[0].get()), nullptr);
  EXPECT_NE(dynamic_cast<RefreshEndEventPayload*>(events[1].get()), nullptr);
}

TEST_F(ConditionIntegrationTest, Refresh2SkipsNonRetainedConditionsForMatchingSource)
{
  // Create two conditions with same source. Enable only one.
  auto retained = create_alarm_condition(3004, 100, "Source100");
  auto notRetained = create_basic_condition(3005, 100, "Source100");

  retained->enable_sync();
  retained->activate_sync(500);
  // notRetained is left disabled (not retained).

  RecordingEventSink refreshSink;
  mManager->condition_refresh2_sync(refreshSink, NodeId{1, 100u});

  auto events = refreshSink.all_events();
  ASSERT_GE(events.size(), 3u);  // Start + 1 retained condition + End

  size_t conditionEventCount = 0;
  for (size_t i = 1; i + 1 < events.size(); ++i)
  {
    if (dynamic_cast<ConditionPayload*>(events[i].get()) != nullptr)
    {
      ++conditionEventCount;
    }
  }
  EXPECT_EQ(conditionEventCount, 1u);
}

// ===========================================================================
// 13. ConditionId identity on emitted events
// ===========================================================================

// Part 9 section 5.5.2: the ConditionId reported on a Condition Event is the NodeId of the Condition Object
// itself. A plausible implementation stamps a synthetic per-event identity there, which still looks
// well-formed to a client but resolves to nothing when that client turns round and addresses the
// Condition by the id it was handed.
// @verifies AC-SVR-AC-001-CONDITIONID-IS-NODEID
TEST_F(ConditionIntegrationTest, EmittedEventReportsConditionObjectNodeIdAsConditionId)
{
  auto instance = create_basic_condition(1000, 100, "TestSource");

  instance->enable_sync();

  const size_t count = mSink->event_count();
  ASSERT_GE(count, 1u);
  auto emitted = mSink->event_at(count - 1);
  ASSERT_NE(emitted, nullptr);

  // Conjunct 1: the ConditionId carried by the event is the Condition Object's NodeId.
  ASSERT_TRUE(emitted->conditionNodeId.has_value());
  EXPECT_EQ(*emitted->conditionNodeId, NodeId(1, 1000u));
  EXPECT_EQ(*emitted->conditionNodeId, instance->condition_id());

  // Conjunct 2: that id, taken from the event and nowhere else, resolves back to this same
  // Condition - the lookup every ConditionId-addressed method call depends on.
  auto resolved = mManager->find_condition_sync(*emitted->conditionNodeId);
  ASSERT_NE(resolved, nullptr);
  EXPECT_EQ(resolved->condition_id(), instance->condition_id());
}

// ===========================================================================
// 14. Comment changes raise events
// ===========================================================================

// Part 9 section 5.5.2: every change to a Condition's Comment raises a new Event, the clearing of a Comment
// included. Comment is not a state transition, so an implementation that emits only on state changes
// - or that treats "new value is empty" as nothing to report - leaves the operator's own annotation,
// and its retraction, invisible to every other client.
// @verifies AC-SVR-AC-054-COMMENT-CHANGE-EVENT
TEST_F(ConditionIntegrationTest, EveryCommentChangeRaisesAnEventIncludingTheClearing)
{
  auto instance = create_basic_condition();
  instance->enable_sync();

  const size_t countAfterEnable = mSink->event_count();
  ASSERT_GE(countAfterEnable, 1u);

  // First change: record a comment.
  auto firstTargetId = mSink->last_event_id();
  ASSERT_FALSE(firstTargetId.empty());
  instance->add_comment_sync(firstTargetId, LocalizedText{"en", "First note"});

  const size_t countAfterFirst = mSink->event_count();
  EXPECT_GT(countAfterFirst, countAfterEnable);
  EXPECT_EQ(instance->snapshot()->comment().text(), String{"First note"});

  auto firstEvent = mSink->event_at(countAfterFirst - 1);
  ASSERT_NE(firstEvent, nullptr);
  auto* firstCondition = dynamic_cast<ConditionPayload*>(firstEvent.get());
  ASSERT_NE(firstCondition, nullptr);
  const auto* firstComment = firstCondition->comment.value.try_as<LocalizedText>();
  ASSERT_NE(firstComment, nullptr);
  EXPECT_EQ(firstComment->text(), String{"First note"});

  // Second change: clear the comment. The EventId moved on with the emit above, so the clearing
  // must target the newest event.
  auto secondTargetId = mSink->last_event_id();
  ASSERT_FALSE(secondTargetId.empty());
  ASSERT_NE(secondTargetId, firstTargetId);
  // Part 9 section 5.5.6 distinguishes a null LocalizedText (ignored) from reset: reset is empty
  // text carrying a locale.
  instance->add_comment_sync(secondTargetId, LocalizedText{"en", ""});

  const size_t countAfterClearing = mSink->event_count();
  EXPECT_GT(countAfterClearing, countAfterFirst);
  EXPECT_EQ(instance->snapshot()->comment().text(), String{""});

  auto clearingEvent = mSink->event_at(countAfterClearing - 1);
  ASSERT_NE(clearingEvent, nullptr);
  auto* clearingCondition = dynamic_cast<ConditionPayload*>(clearingEvent.get());
  ASSERT_NE(clearingCondition, nullptr);
  const auto* clearedComment = clearingCondition->comment.value.try_as<LocalizedText>();
  ASSERT_NE(clearedComment, nullptr);
  EXPECT_EQ(clearedComment->text(), String{""});
}

// ===========================================================================
// 15. Quality, Severity and Comment changes each raise a Condition Event
// ===========================================================================

// Part 9 section 5.5.2: while a Condition is Enabled, a change to Quality, to Severity and to Comment shall
// each cause a ConditionType Event Notification. None of the three is a state transition, so an
// implementation that emits only when the state machine moves (Enabled / Active / Acked) leaves a
// degraded quality, a re-ranked severity and the operator's own annotation invisible to every other
// client until some unrelated transition happens to flush them.
//
// Quality and Severity have no shell-level entry point - the only production path that moves them is
// the input binding, which requires an address space this fixture deliberately does not build - so
// they are driven on the component the obligation's design coverage names, the ConditionLogic
// setters, and read back off the event those setters build. The Comment leg is driven end to end
// through the live ConditionInstance and observed on the sink, which is what establishes that the
// shell does emit when the logic reports a change worth an event.
// @verifies AC-SVR-AC-051-QUALITY-SEVERITY-COMMENT-EVENTS
TEST_F(ConditionIntegrationTest, QualitySeverityAndCommentChangesEachRaiseAConditionEvent)
{
  // --- Comment: driven through the real shell, observed on the sink. ---
  auto instance = create_basic_condition(1000, 100, "QualitySource");
  instance->enable_sync();

  const size_t countAfterEnable = mSink->event_count();
  ASSERT_GE(countAfterEnable, 1u);

  auto targetId = mSink->last_event_id();
  ASSERT_FALSE(targetId.empty());
  instance->add_comment_sync(targetId, LocalizedText{"en", "Comment change"});

  const size_t countAfterComment = mSink->event_count();
  EXPECT_GT(countAfterComment, countAfterEnable) << "a Comment change must raise a Condition Event";

  auto commentEvent = mSink->event_at(countAfterComment - 1);
  ASSERT_NE(commentEvent, nullptr);
  auto* commentCondition = dynamic_cast<ConditionPayload*>(commentEvent.get());
  ASSERT_NE(commentCondition, nullptr) << "the raised event must be a ConditionType Event";
  const auto* commentValue = commentCondition->comment.value.try_as<LocalizedText>();
  ASSERT_NE(commentValue, nullptr);
  EXPECT_EQ(commentValue->text(), String{"Comment change"});

  // --- Quality and Severity: driven on the production ConditionLogic. ---
  ConditionLogic logic;
  logic.set_source(NodeId{1, 100u}, String{"QualitySource"});

  // Enabled is the antecedent the obligation is conditional on, and it is set by the production
  // transition, not by hand.
  const auto enableTransition = logic.enable();
  ASSERT_TRUE(enableTransition.emitEvent);

  const auto qualityTransition = logic.set_quality(StatusCode{Status::BadNoCommunication});
  EXPECT_TRUE(qualityTransition.changed);
  EXPECT_TRUE(qualityTransition.emitEvent) << "a Quality change must raise a Condition Event";

  auto qualityEvent = logic.build_event();
  ASSERT_NE(qualityEvent, nullptr);
  auto* qualityCondition = dynamic_cast<ConditionPayload*>(qualityEvent.get());
  ASSERT_NE(qualityCondition, nullptr) << "the raised event must be a ConditionType Event";
  const auto* qualityValue = qualityCondition->quality.value.try_as<StatusCode>();
  ASSERT_NE(qualityValue, nullptr);
  EXPECT_EQ(*qualityValue, StatusCode{Status::BadNoCommunication});

  const auto severityTransition = logic.set_severity(uint16_t{640});
  EXPECT_TRUE(severityTransition.changed);
  EXPECT_TRUE(severityTransition.emitEvent) << "a Severity change must raise a Condition Event";

  auto severityEvent = logic.build_event();
  ASSERT_NE(severityEvent, nullptr);
  auto* severityCondition = dynamic_cast<ConditionPayload*>(severityEvent.get());
  ASSERT_NE(severityCondition, nullptr) << "the raised event must be a ConditionType Event";
  EXPECT_EQ(severityCondition->severity, uint16_t{640});
}

}  // namespace ua::test

// ===========================================================================
// 16-17. ConditionRefresh: Subscription ownership and per-refusal result codes
//
// ConditionRefresh is addressed with a SubscriptionId, and both obligations below are decisions the
// Server makes about a Subscription that only a live Session owns. The strand-level fixture above
// has no Session, no Subscription and no address space, so these two stand up the real server, real
// Sessions and a real Subscription from the shared compliance harness and drive the Method through
// the Call service - the same path a client takes.
// ===========================================================================

namespace
{

SimpleAttributeOperand make_refresh_select_clause(const String& fieldName,
  NodeId typeDefId = NodeId{ObjectTypeId::BaseEventType},
  uint32_t attrId = static_cast<uint32_t>(AttributeId::Value))
{
  SimpleAttributeOperand clause;
  clause.type_definition_id() = std::move(typeDefId);
  clause.browse_path().push_back(QualifiedName{0, fieldName});
  clause.attribute_id() = attrId;
  return clause;
}

/// Select clauses in the order the extractors below index: EventId, EventType, SourceNode, ...
EventFilter make_refresh_event_filter()
{
  EventFilter filter;
  filter.select_clauses().push_back(make_refresh_select_clause("EventId"));
  filter.select_clauses().push_back(make_refresh_select_clause("EventType"));
  filter.select_clauses().push_back(make_refresh_select_clause("SourceNode"));
  filter.select_clauses().push_back(make_refresh_select_clause("SourceName"));
  filter.select_clauses().push_back(make_refresh_select_clause("Time"));
  filter.select_clauses().push_back(make_refresh_select_clause("Message"));
  filter.select_clauses().push_back(make_refresh_select_clause("Severity"));
  return filter;
}

CallRequest make_refresh_call(const NodeId& objectId, const NodeId& methodId, Array<Variant> inputArgs = {})
{
  CallMethodRequest methodReq;
  methodReq.object_id() = objectId;
  methodReq.method_id() = methodId;
  methodReq.input_arguments() = std::move(inputArgs);

  CallRequest req;
  req.methods_to_call().push_back(std::move(methodReq));
  return req;
}

NodeId refresh_event_type_of(const EventFieldList& efl)
{
  if (efl.event_fields().size() > 1)
  {
    if (const auto* id = efl.event_fields()[1].try_as<NodeId>())
    {
      return *id;
    }
  }
  return {};
}

NodeId refresh_source_node_of(const EventFieldList& efl)
{
  if (efl.event_fields().size() > 2)
  {
    if (const auto* id = efl.event_fields()[2].try_as<NodeId>())
    {
      return *id;
    }
  }
  return {};
}

}  // namespace

/// Server carrying one retainable Alarm, one Session, and one Subscription owned by that Session.
/// The Alarm's SourceNode is the Objects folder, which is what identifies a replayed Condition Event
/// in the assertions below (the Call-service audit Event sources the ConditionType node instead).
class ConditionRefreshOwnershipTest : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto& conditions = mServer.server().conditions();
    mAlarm = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"RefreshOwnershipAlarm"},
      std::make_unique<AlarmConditionLogic>(),
      NodeId{ObjectTypeId::AlarmConditionType});
    ASSERT_NE(mAlarm, nullptr);
  }

  void SetUp() override
  {
    ComplianceWithSession::SetUp();
    mSubscriptionId =
      ::ua::test_helpers::create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 60});
    ASSERT_NE(mSubscriptionId, 0u);
  }

  void TearDown() override
  {
    if (mSession && mSubscriptionId != 0)
    {
      ::ua::test_helpers::delete_subscription(*mSession, mSubscriptionId);
    }
    ComplianceWithSession::TearDown();
  }

  std::shared_ptr<ConditionInstance> mAlarm;
  uint32_t mSubscriptionId{0};
};

// Part 9 section 5.5.7: ConditionRefresh cross-checks that the SubscriptionId it is handed belongs to the
// Session that called it. A plausible implementation looks the SubscriptionId up in the server-wide
// Subscription map - where it is found, because it exists - and refreshes it, so any Session can
// force a full replay of every retained Condition into a Subscription owned by somebody else: a
// burst that Session never asked for, on a link it is metering.
// @verifies AC-SVR-AC-019-REFRESH-SESSION-CHECK
TEST_F(ConditionRefreshOwnershipTest, RefreshOfAnotherSessionsSubscriptionIsRefusedAndSendsItNothing)
{
  // A retained Condition exists, so a refresh that wrongly ran would have something to replay.
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  ASSERT_TRUE(mAlarm->snapshot()->retained());

  boost::asio::thread_pool intruderPool;
  {
    // The intruding Session is opened BEFORE the monitored item so that its own session-audit Events
    // cannot land inside the window the negative assertion reads. This second Session rides a None
    // channel, which the client refuses unless the application opts in; create_test_config() carries
    // that opt-in.
    auto intruderClient = CoreClient::create(intruderPool.get_executor(),
      ua::client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()});
    auto intruderChannel = intruderClient.open_channel_sync({.endpointUrl = mEndpointUrl});
    auto intruderSession = intruderChannel.create_session_sync({.sessionName = "RefreshOwnershipOther"});
    intruderSession.activate_sync();

    ::ua::test_helpers::create_event_monitored_item(*mSession,
      mSubscriptionId,
      NodeId{ObjectId::Server},
      make_refresh_event_filter(),
      {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 50});

    // Conjunct 1: the call is refused.
    auto crossSession = make_refresh_call(NodeId{ObjectTypeId::ConditionType},
      NodeId{MethodId::ConditionType_ConditionRefresh},
      Array<Variant>{Variant{mSubscriptionId}});
    auto refused = intruderSession.methods().try_call_sync(std::move(crossSession));
    ASSERT_TRUE(refused.is_good()) << "Call service failed: " << refused.status_code().as_uint32();
    ASSERT_FALSE(refused.value().results().empty());
    EXPECT_TRUE(refused.value().results()[0].status_code().is_bad())
      << "ConditionRefresh must refuse a SubscriptionId owned by a different Session; got "
      << refused.value().results()[0].status_code().as_uint32();

    // Conjunct 2: nothing a refresh produces reached the owning Subscription. minCount is set beyond
    // anything this Subscription can deliver so the helper polls the whole window instead of
    // returning on the first unrelated Event (the Call-service audit Event legitimately arrives
    // here); the assertions are scoped to what a refresh - and only a refresh - would carry.
    auto collected = ::ua::test_helpers::collect_events(
      *mSession, mSubscriptionId, {.minCount = 1000, .timeout = std::chrono::milliseconds{1500}});
    for (const auto& efl : collected)
    {
      EXPECT_NE(refresh_event_type_of(efl), NodeId{ObjectTypeId::RefreshStartEventType})
        << "a refresh was started on a Subscription the caller does not own";
      EXPECT_NE(refresh_event_type_of(efl), NodeId{ObjectTypeId::RefreshEndEventType})
        << "a refresh was completed on a Subscription the caller does not own";
      EXPECT_NE(refresh_source_node_of(efl), NodeId{ObjectId::ObjectsFolder})
        << "a retained Condition was replayed into a Subscription the caller does not own";
    }

    (void)intruderSession.try_close_sync();
    (void)intruderChannel.try_close_sync();
  }  // Session/channel/client destroyed before the pool stops so the cert-store timer is cancelled.
  intruderPool.join();

  // Control: the same Subscription, refreshed by the Session that DOES own it, must carry the
  // refresh through to this monitored item. Without this, an event pipeline that delivered nothing
  // at all would pass the assertions above for the wrong reason.
  auto ownCall = make_refresh_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto accepted = mSession->methods().try_call_sync(std::move(ownCall));
  ASSERT_TRUE(accepted.is_good());
  ASSERT_FALSE(accepted.value().results().empty());
  ASSERT_TRUE(accepted.value().results()[0].status_code().is_good())
    << "control: the owning Session's own ConditionRefresh was refused: "
    << accepted.value().results()[0].status_code().as_uint32();

  bool sawStart = false;
  bool sawEnd = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawEnd && std::chrono::steady_clock::now() < deadline)
  {
    auto ownEvents = ::ua::test_helpers::collect_events(
      *mSession, mSubscriptionId, {.minCount = 1000, .timeout = std::chrono::milliseconds{200}});
    for (const auto& efl : ownEvents)
    {
      const auto type = refresh_event_type_of(efl);
      if (type == NodeId{ObjectTypeId::RefreshStartEventType})
      {
        sawStart = true;
      }
      if (type == NodeId{ObjectTypeId::RefreshEndEventType})
      {
        sawEnd = true;
      }
    }
  }
  EXPECT_TRUE(sawStart) << "control: the owner's own refresh delivered no RefreshStart, so the "
                           "cross-session assertions above proved nothing";
  EXPECT_TRUE(sawEnd) << "control: the owner's own refresh delivered no RefreshEnd, so the "
                         "cross-session assertions above proved nothing";
}

// Part 9 section 5.5.7 gives ConditionRefresh a distinct code per refusal. The second is the one worth
// distinguishing: a Subscription that exists, belongs to the caller, and holds no event
// MonitoredItem has nothing to refresh, and that is a client configuration error - Bad_NothingToDo -
// not a stale id. A plausible implementation validates the SubscriptionId, finds it, and then
// happily runs a refresh whose Events have no MonitoredItem to be delivered to, reporting Good and
// leaving the client to conclude from silence that the Server simply has no retained Conditions.
// @verifies AC-SVR-AC-024-REFRESH-CODES
TEST_F(ConditionRefreshOwnershipTest, RefreshReportsItsOwnCodeForAnUnknownSubscriptionAndForNothingToDo)
{
  // A retained Condition exists, so "nothing to refresh" can only be about the missing MonitoredItem.
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  ASSERT_TRUE(mAlarm->snapshot()->retained());

  // Conjunct 1: a SubscriptionId this Server never issued.
  auto unknownCall = make_refresh_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{uint32_t{0xFFFFFFF0}}});
  auto unknown = mSession->methods().try_call_sync(std::move(unknownCall));
  ASSERT_TRUE(unknown.is_good()) << "Call service failed: " << unknown.status_code().as_uint32();
  ASSERT_FALSE(unknown.value().results().empty());
  EXPECT_EQ(unknown.value().results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid})
    << "an unknown SubscriptionId must be reported as Bad_SubscriptionIdInvalid";

  // Conjunct 2: this Session's own Subscription, which holds no event MonitoredItem - the fixture
  // creates the Subscription and this test adds nothing to it.
  auto emptyCall = make_refresh_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto empty = mSession->methods().try_call_sync(std::move(emptyCall));
  ASSERT_TRUE(empty.is_good()) << "Call service failed: " << empty.status_code().as_uint32();
  ASSERT_FALSE(empty.value().results().empty());
  EXPECT_EQ(empty.value().results()[0].status_code(), StatusCode{Status::BadNothingToDo})
    << "a Subscription with no event MonitoredItem has nothing to refresh and must be told so, "
       "rather than being given a Good result for a refresh nobody can receive";
}
