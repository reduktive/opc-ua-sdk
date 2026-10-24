// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_condition_state_snapshot.h"

#include "ua_acknowledgeable_condition_payload.h"
#include "ua_alarm_condition_payload.h"
#include "ua_byte_string.h"
#include "ua_condition_payload.h"
#include "ua_data_value.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_string.h"

#include <gtest/gtest.h>

#include <vector>

namespace ua::test
{

// --- Default state ---

TEST(ConditionStateSnapshot, DefaultsToAllZeroFalse)
{
  ConditionStateSnapshot snapshot;

  EXPECT_FALSE(snapshot.enabled());
  EXPECT_FALSE(snapshot.retained());
  EXPECT_EQ(snapshot.severity(), 0);
  EXPECT_TRUE(snapshot.quality().is_good());
  EXPECT_FALSE(snapshot.acked());
  EXPECT_FALSE(snapshot.confirmed());
  EXPECT_FALSE(snapshot.active());
  EXPECT_EQ(snapshot.last_severity(), 0);
}

// --- update_from(ConditionPayload) ---

TEST(ConditionStateSnapshot, UpdateFromConditionCopiesEnabledAndRetain)
{
  ConditionStateSnapshot snapshot;

  ConditionPayload event;
  event.enabledState.id = true;
  event.enabledState.currentState = LocalizedText{"", "Enabled"};
  event.retain = true;
  event.severity = 500;
  event.quality.value = Variant{StatusCode{Status::UncertainLastUsableValue}};
  event.quality.sourceTimestamp = DateTime::now();

  snapshot.update_from(event);

  EXPECT_TRUE(snapshot.enabled());
  EXPECT_TRUE(snapshot.retained());
  EXPECT_EQ(snapshot.severity(), 500);
  EXPECT_EQ(snapshot.quality(), StatusCode{Status::UncertainLastUsableValue});
  EXPECT_EQ(snapshot.enabled_current_state().text(), "Enabled");
}

TEST(ConditionStateSnapshot, UpdateFromConditionCopiesBaseEventAndConditionClassFields)
{
  ConditionStateSnapshot snapshot;

  ConditionPayload event;
  event.eventId = ByteString{std::vector<uint8_t>{1, 2, 3, 4}};
  event.eventType = NodeId{ObjectTypeId::ExclusiveLimitAlarmType};
  event.sourceNode = NodeId{2, 100};
  event.sourceName = String{"AlarmSource"};
  event.time = DateTime::now();
  event.receiveTime = event.time;
  event.message = LocalizedText{"en", "limit exceeded"};
  event.conditionClassId = NodeId{ObjectTypeId::BaseConditionClassType};
  event.conditionClassName = LocalizedText{"", "BaseConditionClassType"};
  event.conditionName = String{"ExclusiveLimitAlarm"};

  snapshot.update_from(event);

  // These mandatory BaseEventType / ConditionType fields back the condition node's readable property
  // variables; without them an attribute Read returns BadAttributeIdInvalid (F65).
  EXPECT_EQ(snapshot.event_id(), (ByteString{std::vector<uint8_t>{1, 2, 3, 4}}));
  EXPECT_EQ(snapshot.event_type(), NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  EXPECT_EQ(snapshot.source_node(), (NodeId{2, 100}));
  EXPECT_EQ(snapshot.source_name(), String{"AlarmSource"});
  EXPECT_EQ(snapshot.time(), event.time);
  EXPECT_EQ(snapshot.receive_time(), event.time);
  EXPECT_EQ(snapshot.message().text(), "limit exceeded");
  EXPECT_EQ(snapshot.condition_class_id(), NodeId{ObjectTypeId::BaseConditionClassType});
  EXPECT_EQ(snapshot.condition_class_name().text(), "BaseConditionClassType");
  EXPECT_EQ(snapshot.condition_name(), String{"ExclusiveLimitAlarm"});
}

// BranchId and ClientUserId are ConditionType fields that back the condition node's BranchId /
// ClientUserId property variables. update_from must mirror them into the snapshot so the wired nodes
// read the real values (F86 quality follow-up) rather than null. BranchId is null for the main branch.
TEST(ConditionStateSnapshot, UpdateFromConditionCopiesBranchIdAndClientUserId)
{
  ConditionStateSnapshot snapshot;

  // Default: no branch (null NodeId), no attributed user.
  EXPECT_TRUE(snapshot.branch_id().is_null());
  EXPECT_TRUE(snapshot.client_user_id().empty());

  ConditionPayload event;
  event.branchId = NodeId{3, "branch-42"};
  event.clientUserId = String{"operator-jane"};

  snapshot.update_from(event);

  EXPECT_EQ(snapshot.branch_id(), (NodeId{3, "branch-42"}));
  EXPECT_EQ(snapshot.client_user_id(), String{"operator-jane"});
}

// ShelvingState.CurrentState is derived (not payload-carried), so the snapshot exposes a dedicated
// setter the ConditionInstance drives from the alarm logic's ShelveState. Round-trip name + state Id.
TEST(ConditionStateSnapshot, SetShelveStateRoundTrips)
{
  ConditionStateSnapshot snapshot;

  // Default: empty until the owning instance derives it.
  EXPECT_TRUE(snapshot.shelve_state_name().text().empty());
  EXPECT_TRUE(snapshot.shelve_state_id().is_null());

  snapshot.set_shelve_state(
    LocalizedText{"", "TimedShelved"}, NodeId{ObjectId::ShelvedStateMachineType_TimedShelved});

  EXPECT_EQ(snapshot.shelve_state_name().text(), "TimedShelved");
  EXPECT_EQ(snapshot.shelve_state_id(), NodeId{ObjectId::ShelvedStateMachineType_TimedShelved});
}

TEST(ConditionStateSnapshot, UpdateFromConditionCopiesCommentAndLastSeverity)
{
  ConditionStateSnapshot snapshot;

  ConditionPayload event;
  event.enabledState.id = true;
  event.retain = true;
  event.comment.value = Variant{LocalizedText{"", "Test comment"}};
  event.comment.sourceTimestamp = DateTime::now();
  event.lastSeverity.value = Variant{uint16_t{200}};
  event.lastSeverity.sourceTimestamp = DateTime::now();

  snapshot.update_from(event);

  EXPECT_EQ(snapshot.comment().text(), "Test comment");
  EXPECT_EQ(snapshot.last_severity(), 200);
}

// --- update_from(AcknowledgeableConditionPayload) ---

TEST(ConditionStateSnapshot, UpdateFromAcknowledgeableConditionCopiesAckedState)
{
  ConditionStateSnapshot snapshot;

  AcknowledgeableConditionPayload event;
  event.enabledState.id = true;
  event.retain = true;
  event.severity = 300;
  event.ackedState.id = true;
  event.ackedState.currentState = LocalizedText{"", "Acknowledged"};
  event.ackedState.transitionTime = DateTime::now();
  event.confirmedState = TwoStateVariableState{};
  event.confirmedState->id = true;

  snapshot.update_from(event);

  EXPECT_TRUE(snapshot.acked());
  EXPECT_EQ(snapshot.acked_current_state().text(), "Acknowledged");
  EXPECT_TRUE(snapshot.confirmed());
}

// --- update_from(AlarmConditionPayload) ---

TEST(ConditionStateSnapshot, UpdateFromAlarmConditionCopiesActiveState)
{
  ConditionStateSnapshot snapshot;

  AlarmConditionPayload event;
  event.enabledState.id = true;
  event.retain = true;
  event.severity = 800;
  event.ackedState.id = false;
  event.activeState.id = true;
  event.activeState.currentState = LocalizedText{"", "Active"};
  event.activeState.transitionTime = DateTime::now();

  snapshot.update_from(event);

  EXPECT_TRUE(snapshot.active());
  EXPECT_EQ(snapshot.active_current_state().text(), "Active");
  EXPECT_TRUE(snapshot.enabled());
  EXPECT_EQ(snapshot.severity(), 800);
}

// --- Thread-safe concurrent read+write (smoke test for data races) ---

TEST(ConditionStateSnapshot, SmokeTest_ConcurrentReadWriteDoesNotCrash)
{
  auto snapshot = std::make_shared<ConditionStateSnapshot>();

  std::atomic<bool> done{false};

  // Writer thread: repeatedly updates the snapshot with varying state
  std::thread writer(
    [&snapshot, &done]()
    {
      for (int i = 0; i < 200; ++i)
      {
        ConditionPayload event;
        event.enabledState.id = (i % 2 == 0);
        event.retain = (i % 3 != 0);
        event.severity = static_cast<uint16_t>(i);
        snapshot->update_from(event);
      }
      done.store(true, std::memory_order_release);
    });

  // Reader threads: concurrently read while writes are happening
  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i)
  {
    readers.emplace_back(
      [&snapshot, &done]()
      {
        while (!done.load(std::memory_order_acquire))
        {
          (void)snapshot->enabled();
          (void)snapshot->retained();
          (void)snapshot->severity();
          (void)snapshot->quality();
          (void)snapshot->acked();
          (void)snapshot->active();
        }
      });
  }

  writer.join();
  for (auto& thread : readers)
  {
    thread.join();
  }

  // Verify final state is consistent with the last write (i=199: enabled=false, retain=true, severity=199)
  EXPECT_FALSE(snapshot->enabled());
  EXPECT_TRUE(snapshot->retained());
  EXPECT_EQ(snapshot->severity(), 199);
}

}  // namespace ua::test
