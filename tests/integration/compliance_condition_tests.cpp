// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase D: Alarms & Conditions Compliance Integration Tests
///
/// Tests for condition method dispatch, audit events, and end-to-end flows.
/// Includes subscription-based event delivery tests (items 22/23).

#include "concrete_condition_type.h"
#include "compliance_helpers.h"
#include "sanitizer_budget.h"
#include "subscription.h"

#include "ua_session_method_services.h"
#include "ua_session_view_services.h"

#include "ua_conditions.h"
#include "ua_method_id.h"
#include "ua_condition_instance.h"
#include "ua_condition_logic.h"
#include "ua_acknowledgeable_condition_logic.h"
#include "ua_alarm_condition_logic.h"
#include "ua_dialog_condition_logic.h"
#include "ua_discrepancy_alarm_logic.h"
#include "ua_limit_alarm_logic.h"
#include "ua_off_normal_alarm_logic.h"

#include "ua_instantiation_options.h"
#include "ua_instantiation_service.h"
#include "ua_node_subtree.h"

#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_condition_payload.h"
#include "ua_content_filter.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_event_filter.h"
#include "ua_event_field_list.h"
#include "ua_event_notification_list.h"
#include "ua_generic_event.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitoring_mode.h"
#include "ua_monitoring_parameters.h"
#include "ua_notification_message.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_content_filter_element.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_session_attribute_services.h"
#include "ua_referencetype_id.h"
#include "ua_simple_attribute_operand.h"
#include "ua_utilities.h"
#include "ua_status.h"
#include "ua_timestamps_to_return.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <future>
#include <thread>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// ===========================================================================
// Helpers
// ===========================================================================

static CallRequest make_condition_call(
  const NodeId& objectId, const NodeId& methodId, Array<Variant> inputArgs = {})
{
  CallMethodRequest methodReq;
  methodReq.object_id() = objectId;
  methodReq.method_id() = methodId;
  methodReq.input_arguments() = std::move(inputArgs);

  CallRequest req;
  req.methods_to_call().push_back(std::move(methodReq));
  return req;
}

/// Get EventId server-side via build_refresh_events_async.
static ByteString get_event_id(std::shared_ptr<ConditionInstance>& instance)
{
  std::promise<std::vector<std::unique_ptr<BaseEvent>>> p;
  instance->build_refresh_events_async([&p](auto events) { p.set_value(std::move(events)); });
  auto refreshEvents = p.get_future().get();
  if (refreshEvents.empty() || refreshEvents[0]->eventId.empty())
  {
    return {};
  }
  return refreshEvents[0]->eventId;
}

// ===========================================================================
// Fixture
// ===========================================================================

class ComplianceConditionTest : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto& server = mServer.server();
    auto& conditions = server.conditions();

    // ConditionType is abstract (OPC 10000-3 section 5.5.2): a plain Condition is an instance of a concrete
    // subtype that adds nothing to it.
    auto addressSpace = server.address_space();
    mCondition = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"TestCondition"},
      std::make_unique<ConditionLogic>(),
      ::ua::test_helpers::concrete_condition_type(addressSpace, 1));
    mConditionId = mCondition->condition_id();

    auto alarmLogic = std::make_unique<AlarmConditionLogic>();
    alarmLogic->set_supports_confirm(true);
    mAlarm = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"TestAlarm"},
      std::move(alarmLogic),
      NodeId{ObjectTypeId::AlarmConditionType});
    mAlarmId = mAlarm->condition_id();

    auto ackLogic = std::make_unique<AcknowledgeableConditionLogic>();
    ackLogic->set_supports_confirm(true);
    mAckCondition = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"TestAckCondition"},
      std::move(ackLogic),
      NodeId{ObjectTypeId::AcknowledgeableConditionType});
    mAckConditionId = mAckCondition->condition_id();

    // Full-featured alarm: all optional features enabled
    auto fullLogic = std::make_unique<AlarmConditionLogic>();
    fullLogic->set_supports_confirm(true);
    fullLogic->set_supports_suppressed(true);
    fullLogic->set_supports_out_of_service(true);
    fullLogic->set_supports_silence(true);
    fullLogic->set_supports_latched(true);
    mFullAlarm = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"FullAlarm"},
      std::move(fullLogic),
      NodeId{ObjectTypeId::AlarmConditionType});
    mFullAlarmId = mFullAlarm->condition_id();

    // Dialog condition for Respond tests
    auto dialogLogic = std::make_unique<DialogConditionLogic>();
    dialogLogic->set_response_options(3);
    dialogLogic->set_default_response(0);
    mDialog = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"TestDialog"},
      std::move(dialogLogic),
      NodeId{ObjectTypeId::DialogConditionType});
    mDialogId = mDialog->condition_id();

    // Limit alarms with all four limits configured - for the instance type-definition compliance
    // tests (limit/severity/deadband property groups + the NonExclusive per-limit state variables).
    auto makeLimitLogic = [](bool exclusive)
    {
      auto logic = std::make_unique<LimitAlarmLogic>();
      logic->set_exclusive(exclusive);
      LimitConfig c;
      c.highHighLimit = 90.0;
      c.highLimit = 70.0;
      c.lowLimit = 30.0;
      c.lowLowLimit = 10.0;
      logic->set_limits(c);
      return logic;
    };
    mExclusiveLimit = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"ExclusiveLimit"},
      makeLimitLogic(true),
      NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
    mExclusiveLimitId = mExclusiveLimit->condition_id();
    mNonExclusiveLimit = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"NonExclusiveLimit"},
      makeLimitLogic(false),
      NodeId{ObjectTypeId::NonExclusiveLimitAlarmType});
    mNonExclusiveLimitId = mNonExclusiveLimit->condition_id();

    // OffNormal alarm - its NormalState (Mandatory, DataType NodeId) exercises the type-specific
    // mandatory-property DataType path the UACTT "A & C Instances" CU checks.
    auto offNormalLogic = std::make_unique<OffNormalAlarmLogic>();
    offNormalLogic->set_normal_state(Variant{false});
    mOffNormal = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"OffNormal"},
      std::move(offNormalLogic),
      NodeId{ObjectTypeId::OffNormalAlarmType});
    mOffNormalId = mOffNormal->condition_id();
  }

  NodeId find_method_via_browse(const NodeId& conditionId, const String& methodName)
  {
    BrowseDescription desc;
    desc.node_id() = conditionId;
    desc.browse_direction() = BrowseDirection::Forward;
    desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    desc.include_subtypes() = true;
    desc.node_class_mask() = 4;
    desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);

    BrowseRequest req;
    req.nodes_to_browse().push_back(std::move(desc));

    auto result = mSession->view().try_browse_sync(std::move(req));
    if (result.is_bad() || result.value().results().empty())
      return {};

    for (const auto& ref : result.value().results()[0].references())
    {
      if (ref.browse_name().name() == methodName)
        return ref.node_id().node_id();
    }
    return {};
  }

  /// Find a child node (any class) by browse name under HasComponent.
  NodeId find_child_via_browse(const NodeId& parentId, const String& childName)
  {
    BrowseDescription desc;
    desc.node_id() = parentId;
    desc.browse_direction() = BrowseDirection::Forward;
    desc.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    desc.include_subtypes() = true;
    desc.node_class_mask() = 0;  // All node classes
    desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);

    BrowseRequest req;
    req.nodes_to_browse().push_back(std::move(desc));

    auto result = mSession->view().try_browse_sync(std::move(req));
    if (result.is_bad() || result.value().results().empty())
      return {};

    for (const auto& ref : result.value().results()[0].references())
    {
      if (ref.browse_name().name() == childName)
        return ref.node_id().node_id();
    }
    return {};
  }

  /// Call a method under a child object (e.g., ShelvingState/TimedShelve).
  StatusCode call_child_method(
    const NodeId& conditionId, const String& childName, const String& methodName, Array<Variant> args = {})
  {
    auto childId = find_child_via_browse(conditionId, childName);
    if (childId.is_null())
      return StatusCode{Status::BadMethodInvalid};

    auto methodId = find_method_via_browse(childId, methodName);
    if (methodId.is_null())
      return StatusCode{Status::BadMethodInvalid};

    auto req = make_condition_call(childId, methodId, std::move(args));
    auto result = mSession->methods().try_call_sync(std::move(req));
    if (result.is_bad())
      return result.status_code();

    auto& resp = result.value();
    if (resp.results().empty())
      return StatusCode{Status::BadUnexpectedError};

    return resp.results()[0].status_code();
  }

  StatusCode call_condition_method(
    const NodeId& conditionId, const String& methodName, Array<Variant> args = {})
  {
    auto methodId = find_method_via_browse(conditionId, methodName);
    if (methodId.is_null())
      return StatusCode{Status::BadMethodInvalid};

    auto req = make_condition_call(conditionId, methodId, std::move(args));
    auto result = mSession->methods().try_call_sync(std::move(req));
    if (result.is_bad())
      return result.status_code();

    auto& resp = result.value();
    if (resp.results().empty())
      return StatusCode{Status::BadUnexpectedError};

    return resp.results()[0].status_code();
  }

  NodeId mConditionId;
  NodeId mAlarmId;
  NodeId mAckConditionId;
  NodeId mFullAlarmId;
  NodeId mDialogId;
  NodeId mExclusiveLimitId;
  NodeId mNonExclusiveLimitId;
  NodeId mOffNormalId;
  std::shared_ptr<ConditionInstance> mCondition;
  std::shared_ptr<ConditionInstance> mAlarm;
  std::shared_ptr<ConditionInstance> mAckCondition;
  std::shared_ptr<ConditionInstance> mFullAlarm;
  std::shared_ptr<ConditionInstance> mDialog;
  std::shared_ptr<ConditionInstance> mExclusiveLimit;
  std::shared_ptr<ConditionInstance> mNonExclusiveLimit;
  std::shared_ptr<ConditionInstance> mOffNormal;
};

// ===========================================================================
// Method Dispatch Tests
// ===========================================================================

// COND-100: Enable via client Call service
// @relation(SVR-AC-006, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Enable_ViaClientCall_Succeeds)
{
  auto status = call_condition_method(mConditionId, "Enable");
  EXPECT_TRUE(status.is_good());
  EXPECT_TRUE(mCondition->snapshot()->enabled());
}

// COND-110: Disable via client Call service
// @relation(SVR-AC-003, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Disable_ViaClientCall_Succeeds)
{
  mCondition->enable_sync();
  auto status = call_condition_method(mConditionId, "Disable");
  EXPECT_TRUE(status.is_good());
  EXPECT_FALSE(mCondition->snapshot()->enabled());
}

// COND-102: Disable using ConditionId as ObjectId
// @relation(SVR-AC-002, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Disable_UsingConditionIdAsObjectId_Succeeds)
{
  mAlarm->enable_sync();
  auto status = call_condition_method(mAlarmId, "Disable");
  EXPECT_TRUE(status.is_good());
  EXPECT_FALSE(mAlarm->snapshot()->enabled());
}

// COND-100: Enable already-enabled returns BadConditionAlreadyEnabled
// @relation(AC-SVR-AC-007-ALREADY-ENABLED, scope=function)
TEST_F(ComplianceConditionTest, Enable_AlreadyEnabled_ReturnsBadConditionAlreadyEnabled)
{
  mCondition->enable_sync();
  auto status = call_condition_method(mConditionId, "Enable");
  EXPECT_EQ(status, StatusCode{Status::BadConditionAlreadyEnabled});
}

// COND-110: Disable already-disabled returns BadConditionAlreadyDisabled
// @relation(AC-SVR-AC-004-ALREADY-DISABLED, scope=function)
TEST_F(ComplianceConditionTest, Disable_AlreadyDisabled_ReturnsBadConditionAlreadyDisabled)
{
  auto status = call_condition_method(mConditionId, "Disable");
  EXPECT_EQ(status, StatusCode{Status::BadConditionAlreadyDisabled});
}

// COND-121: AddComment without arguments returns BadArgumentsMissing
// @relation(SVR-AC-015, scope=function)
TEST_F(ComplianceConditionTest, AddComment_MissingArgs_ReturnsBadArgumentsMissing)
{
  mCondition->enable_sync();
  auto status = call_condition_method(mConditionId, "AddComment");
  EXPECT_EQ(status, StatusCode{Status::BadArgumentsMissing});
}

// COND-125: AddComment with valid EventId succeeds
// @relation(SVR-AC-013, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, AddComment_WithValidEventId_Succeeds)
{
  mCondition->enable_sync();
  auto eventId = get_event_id(mCondition);
  ASSERT_FALSE(eventId.empty());

  auto status = call_condition_method(
    mConditionId, "AddComment", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Test comment"}}});
  EXPECT_TRUE(status.is_good());
}

// COND-126: AddComment on alarm with missing arguments
TEST_F(ComplianceConditionTest, AlarmAddComment_MissingArgs_ReturnsBadArgumentsMissing)
{
  mAlarm->enable_sync();
  auto status = call_condition_method(mAlarmId, "AddComment");
  EXPECT_EQ(status, StatusCode{Status::BadArgumentsMissing});
}

// COND-211: Acknowledge with invalid EventId returns BadEventIdUnknown
// @relation(SVR-AC-028, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Acknowledge_InvalidEventId_ReturnsBadEventIdUnknown)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);

  ByteString bogusId{std::vector<uint8_t>{0xFF, 0xFE}};
  auto status = call_condition_method(
    mAlarmId, "Acknowledge", Array<Variant>{Variant{bogusId}, Variant{LocalizedText{"", "Ack"}}});
  EXPECT_EQ(status, StatusCode{Status::BadEventIdUnknown});
}

// COND-215: Acknowledge with valid EventId via Call service
// @relation(AC-SVR-AC-026-ACKNOWLEDGE-CONDITIONID, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Acknowledge_WithValidEventId_Succeeds)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  ASSERT_FALSE(mAlarm->snapshot()->acked());

  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  auto status = call_condition_method(
    mAlarmId, "Acknowledge", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack via Call"}}});
  EXPECT_TRUE(status.is_good());
  EXPECT_TRUE(mAlarm->snapshot()->acked());
}

// COND-224: Confirm with invalid EventId returns error
// @relation(SVR-AC-033, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Confirm_InvalidEventId_ReturnsError)
{
  mAckCondition->enable_sync();

  ByteString bogusId{std::vector<uint8_t>{0xAA, 0xBB}};
  auto status = call_condition_method(
    mAckConditionId, "Confirm", Array<Variant>{Variant{bogusId}, Variant{LocalizedText{"", "Confirm"}}});
  EXPECT_EQ(status, StatusCode{Status::BadEventIdUnknown});
}

// COND-225: Confirm with valid EventId via Call service
// Confirm is an optional method - may not exist on all AcknowledgeableConditionPayload instances.
// @relation(SVR-AC-031, SVR-AC-032, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Confirm_WithValidEventId_Succeeds)
{
  mAckCondition->enable_sync();

  auto confirmMethodId = find_method_via_browse(mAckConditionId, "Confirm");
  ASSERT_FALSE(confirmMethodId.is_null()) << "Confirm method should be instantiated";

  auto eventId = get_event_id(mAckCondition);
  ASSERT_FALSE(eventId.empty());

  auto status = call_condition_method(
    mAckConditionId, "Confirm", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Confirm"}}});
  EXPECT_TRUE(status.is_good() || status == StatusCode{Status::BadConditionBranchAlreadyConfirmed})
    << "Confirm should dispatch; got: " << status.as_uint32();
}

// COND-101: Call with non-existent MethodId returns error
// @relation(SVR-AC-035, scope=function)
TEST_F(ComplianceConditionTest, CallWithNonExistentMethodId_ReturnsError)
{
  auto req = make_condition_call(mConditionId, NodeId{1, uint32_t{99999}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_TRUE(result.value().results()[0].status_code().is_bad());
}

// COND-217: Call on non-condition object returns error
// @relation(SVR-AC-035, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, CallMethodOnNonConditionObject_ReturnsError)
{
  auto req = make_condition_call(NodeId{ObjectId::ObjectsFolder}, NodeId{1, uint32_t{99999}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_TRUE(result.value().results()[0].status_code().is_bad());
}

// ===========================================================================
// Browse Tests
// ===========================================================================

TEST_F(ComplianceConditionTest, BrowseCondition_FindsMandatoryMethods)
{
  EXPECT_FALSE(find_method_via_browse(mConditionId, "Enable").is_null());
  EXPECT_FALSE(find_method_via_browse(mConditionId, "Disable").is_null());
  EXPECT_FALSE(find_method_via_browse(mConditionId, "AddComment").is_null());
}

TEST_F(ComplianceConditionTest, BrowseAlarm_FindsAcknowledgeMethod)
{
  EXPECT_FALSE(find_method_via_browse(mAlarmId, "Acknowledge").is_null());
}

TEST_F(ComplianceConditionTest, BrowseAckCondition_HasAcknowledgeMethod)
{
  EXPECT_FALSE(find_method_via_browse(mAckConditionId, "Acknowledge").is_null());
}

// COND-1802: ConditionRefresh method is discoverable
// @relation(SVR-AC-018, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, ConditionRefresh_MethodExistsOnConditionType)
{
  EXPECT_FALSE(find_method_via_browse(NodeId{ObjectTypeId::ConditionType}, "ConditionRefresh").is_null());
}

// ===========================================================================
// ConditionPayload Node Existence
// ===========================================================================

TEST_F(ComplianceConditionTest, ConditionNode_ExistsInAddressSpace)
{
  ReadValueId rv;
  rv.node_id() = mConditionId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::NodeClass);
  ReadRequest readReq;
  readReq.nodes_to_read().push_back(std::move(rv));
  auto readResult = mSession->attributes().try_read_sync(std::move(readReq));
  ASSERT_TRUE(readResult.is_good());
  ASSERT_EQ(readResult.value().results().size(), 1u);
  auto& dv = readResult.value().results()[0];
  EXPECT_TRUE(!dv.status().has_value() || dv.status().value().is_good());
}

// ===========================================================================
// End-to-End State Lifecycle Tests
// ===========================================================================

// COND-1800: Alarm activation produces correct state
// @relation(SVR-AC-143, scope=function)
TEST_F(ComplianceConditionTest, AlarmActivation_ProducesCorrectState)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(750);

  auto snapshot = mAlarm->snapshot();
  EXPECT_TRUE(snapshot->enabled());
  EXPECT_TRUE(snapshot->active());
  EXPECT_EQ(snapshot->severity(), 750);
  EXPECT_TRUE(snapshot->retained());
  EXPECT_FALSE(snapshot->acked());
}

// COND-1805: Active alarm is retained
// @relation(SVR-AC-143, scope=function)
TEST_F(ComplianceConditionTest, AlarmLifecycle_ActiveAlarmIsRetained)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);

  EXPECT_TRUE(mAlarm->snapshot()->active());
  EXPECT_FALSE(mAlarm->snapshot()->acked());
  EXPECT_TRUE(mAlarm->snapshot()->retained());
}

// COND-1806: Disable stops retain
// @relation(SVR-AC-009, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionTest, Disable_StopsRetain)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  ASSERT_TRUE(mAlarm->snapshot()->retained());

  mAlarm->disable_sync();
  EXPECT_FALSE(mAlarm->snapshot()->retained());
}

// COND-1807: Full alarm lifecycle
TEST_F(ComplianceConditionTest, FullLifecycle_EnableActivateAcknowledgeDeactivateDisable)
{
  // Step 1: Enable
  mAlarm->enable_sync();
  EXPECT_TRUE(mAlarm->snapshot()->enabled());
  EXPECT_FALSE(mAlarm->snapshot()->active());

  // Step 2: Activate
  mAlarm->activate_sync(600);
  EXPECT_TRUE(mAlarm->snapshot()->active());
  EXPECT_FALSE(mAlarm->snapshot()->acked());
  EXPECT_TRUE(mAlarm->snapshot()->retained());
  EXPECT_EQ(mAlarm->snapshot()->severity(), 600);

  // Step 3: Acknowledge
  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  auto ackStatus = call_condition_method(
    mAlarmId, "Acknowledge", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Lifecycle ack"}}});
  EXPECT_TRUE(ackStatus.is_good());
  EXPECT_TRUE(mAlarm->snapshot()->acked());

  // Step 4: Deactivate
  mAlarm->deactivate_sync();
  EXPECT_FALSE(mAlarm->snapshot()->active());

  // Step 5: Disable
  mAlarm->disable_sync();
  EXPECT_FALSE(mAlarm->snapshot()->enabled());
  EXPECT_FALSE(mAlarm->snapshot()->retained());
}

// ===========================================================================
// Shelving Method Dispatch Tests
// ===========================================================================

// COND-610: TimedShelve via client Call service
// @relation(SVR-AC-111, SVR-AC-143, scope=function)
TEST_F(ComplianceConditionTest, TimedShelve_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  auto status =
    call_child_method(mFullAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{5000.0}});
  EXPECT_TRUE(status.is_good()) << "TimedShelve failed: " << status.as_uint32();
}

// COND-616: Unshelve via client Call service
// @relation(SVR-AC-111, SVR-AC-143, scope=function)
TEST_F(ComplianceConditionTest, Unshelve_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);
  mFullAlarm->timed_shelve_sync(5000.0);

  auto status = call_child_method(mFullAlarmId, "ShelvingState", "Unshelve");
  EXPECT_TRUE(status.is_good()) << "Unshelve failed: " << status.as_uint32();
}

// ===========================================================================
// Suppress / Out-of-Service Method Dispatch Tests
// ===========================================================================

// COND-703: Suppress via client Call service
// @relation(SVR-AC-112, SVR-AC-143, scope=function)
TEST_F(ComplianceConditionTest, Suppress_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  auto status = call_condition_method(mFullAlarmId, "Suppress");
  EXPECT_TRUE(status.is_good()) << "Suppress failed: " << status.as_uint32();
}

// COND-705: Unsuppress via client Call service
// @relation(SVR-AC-112, SVR-AC-143, scope=function)
TEST_F(ComplianceConditionTest, Unsuppress_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  mFullAlarm->suppress_sync();

  auto status = call_condition_method(mFullAlarmId, "Unsuppress");
  EXPECT_TRUE(status.is_good()) << "Unsuppress failed: " << status.as_uint32();
}

// COND-713: RemoveFromService via client Call service
// @relation(SVR-AC-112, scope=function)
TEST_F(ComplianceConditionTest, RemoveFromService_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  auto status = call_condition_method(mFullAlarmId, "RemoveFromService");
  EXPECT_TRUE(status.is_good()) << "RemoveFromService failed: " << status.as_uint32();
}

// COND-714c: PlaceInService via client Call service
// @relation(SVR-AC-112, scope=function)
TEST_F(ComplianceConditionTest, PlaceInService_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  mFullAlarm->remove_from_service_sync();

  auto status = call_condition_method(mFullAlarmId, "PlaceInService");
  EXPECT_TRUE(status.is_good()) << "PlaceInService failed: " << status.as_uint32();
}

// ===========================================================================
// Silence / Reset / Respond Method Dispatch Tests
// ===========================================================================

// COND-333: Silence via client Call service
// @relation(SVR-AC-103, SVR-AC-112, SVR-AC-143, scope=function)
TEST_F(ComplianceConditionTest, Silence_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  auto status = call_condition_method(mFullAlarmId, "Silence");
  EXPECT_TRUE(status.is_good()) << "Silence failed: " << status.as_uint32();
}

// COND-354a: Reset via client Call service
// @relation(SVR-AC-112, scope=function)
TEST_F(ComplianceConditionTest, Reset_ViaClientCall_Succeeds)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);
  // Latching: active sets latched. Deactivate, ack, then reset.
  mFullAlarm->deactivate_sync();
  auto eventId = get_event_id(mFullAlarm);
  mFullAlarm->acknowledge_sync(eventId, LocalizedText{"", "ack"});

  auto status = call_condition_method(mFullAlarmId, "Reset");
  EXPECT_TRUE(status.is_good()) << "Reset failed: " << status.as_uint32();
}

// COND-805: Dialog Respond method exists and validates state
TEST_F(ComplianceConditionTest, Respond_WhenDialogNotActive_ReturnsBadDialogNotActive)
{
  mDialog->enable_sync();

  auto status = call_condition_method(mDialogId, "Respond", Array<Variant>{Variant{int32_t{0}}});
  EXPECT_EQ(status.as_uint32(), StatusCode{Status::BadDialogNotActive}.as_uint32());
}

// A negative SelectedResponse is refused and answered. The audit step runs for a refused Call too, and its
// UInt32 field records the Int32 without throwing, so the Call does not wait for its timeoutHint.
TEST_F(ComplianceConditionTest, Respond_NegativeSelectedResponse_IsAnswered)
{
  mDialog->enable_sync();

  auto status = call_condition_method(mDialogId, "Respond", Array<Variant>{Variant{int32_t{-1}}});
  EXPECT_EQ(status.as_uint32(), StatusCode{Status::BadDialogNotActive}.as_uint32());
}

// COND-805b: Dialog Respond with missing args returns BadArgumentsMissing
TEST_F(ComplianceConditionTest, Respond_MissingArgs_ReturnsBadArgumentsMissing)
{
  mDialog->enable_sync();

  auto status = call_condition_method(mDialogId, "Respond");
  EXPECT_EQ(status.as_uint32(), StatusCode{Status::BadArgumentsMissing}.as_uint32());
}

// ===========================================================================
// Event Subscription Helpers
// ===========================================================================

static SimpleAttributeOperand make_select_clause(const String& fieldName,
  NodeId typeDefId = NodeId{ObjectTypeId::BaseEventType},
  uint32_t attrId = static_cast<uint32_t>(AttributeId::Value))
{
  SimpleAttributeOperand clause;
  clause.type_definition_id() = std::move(typeDefId);
  clause.browse_path().push_back(QualifiedName{0, fieldName});
  clause.attribute_id() = attrId;
  return clause;
}

static EventFilter make_condition_event_filter()
{
  EventFilter filter;
  filter.select_clauses().push_back(make_select_clause("EventId"));
  filter.select_clauses().push_back(make_select_clause("EventType"));
  filter.select_clauses().push_back(make_select_clause("SourceNode"));
  filter.select_clauses().push_back(make_select_clause("SourceName"));
  filter.select_clauses().push_back(make_select_clause("Time"));
  filter.select_clauses().push_back(make_select_clause("Message"));
  filter.select_clauses().push_back(make_select_clause("Severity"));
  filter.select_clauses().push_back(make_select_clause("EnabledState", NodeId{ObjectTypeId::ConditionType}));
  filter.select_clauses().push_back(make_select_clause("Retain", NodeId{ObjectTypeId::ConditionType}));
  filter.select_clauses().push_back(
    make_select_clause("AckedState", NodeId{ObjectTypeId::AcknowledgeableConditionType}));
  filter.select_clauses().push_back(
    make_select_clause("ActiveState", NodeId{ObjectTypeId::AlarmConditionType}));
  return filter;
}

static EventFilter make_of_type_filter(const NodeId& typeId)
{
  EventFilter filter = make_condition_event_filter();

  LiteralOperand operand;
  operand.value() = Variant{typeId};

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::OfType;
  RefStructure<Structure> operandRef;
  operandRef = std::unique_ptr<Structure>(std::make_unique<LiteralOperand>(std::move(operand)));
  element.filter_operands().push_back(std::move(operandRef));

  filter.where_clause().elements().push_back(std::move(element));
  return filter;
}

/// The condition filter with the where clause `InList(ConditionId, [conditionId])`, the form the UACTT
/// A & C units monitor with. An Event without a ConditionId, such as each refresh Event, never satisfies it.
static EventFilter make_condition_id_filter(const NodeId& conditionId)
{
  EventFilter filter = make_condition_event_filter();

  SimpleAttributeOperand conditionIdOperand;  // Part 4 section 7.7.4.5: empty browse path + NodeId
  conditionIdOperand.type_definition_id() = NodeId{ObjectTypeId::ConditionType};
  conditionIdOperand.attribute_id() = utils::to_underlying(AttributeId::NodeId);
  LiteralOperand listed;
  listed.value() = Variant{conditionId};

  ContentFilterElement inList;
  inList.filter_operator() = FilterOperator::InList;
  RefStructure<Structure> first;
  first = std::unique_ptr<Structure>(std::make_unique<SimpleAttributeOperand>(std::move(conditionIdOperand)));
  RefStructure<Structure> second;
  second = std::unique_ptr<Structure>(std::make_unique<LiteralOperand>(std::move(listed)));
  inList.filter_operands().push_back(std::move(first));
  inList.filter_operands().push_back(std::move(second));
  filter.where_clause().elements().push_back(std::move(inList));
  return filter;
}

// ===========================================================================
// Subscription Fixture
// ===========================================================================

class ComplianceConditionSubscriptionTest : public ComplianceConditionTest
{
protected:
  void SetUp() override
  {
    ComplianceConditionTest::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 60});
  }

  void TearDown() override
  {
    if (mSession && mSubscriptionId != 0)
    {
      delete_subscription(*mSession, mSubscriptionId);
    }
    ComplianceConditionTest::TearDown();
  }

  // Fixture-method wrappers (named to match the pre-migration API for the
  // ~25 test-body call sites in this file). Delegate to the free helpers in
  // `helpers/subscription.h`; we call them via fully-qualified names because
  // unqualified lookup picks the fixture method itself.
  void create_event_monitored_item(EventFilter filter, const NodeId& nodeId = NodeId{ObjectId::Server})
  {
    (void)::ua::test_helpers::create_event_monitored_item(*mSession,
      mSubscriptionId,
      nodeId,
      std::move(filter),
      {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 50});
  }

  /// Collect events from Publish responses. Returns all EventFieldLists received.
  std::vector<EventFieldList> collect_events(int maxAttempts = 20)
  {
    return ::ua::test_helpers::collect_events(*mSession,
      mSubscriptionId,
      {.minCount = 1,
        .timeout = std::chrono::milliseconds{maxAttempts * 50},
        .pollInterval = std::chrono::milliseconds{50}});
  }

  /// Extract EventType NodeId from an EventFieldList (field index 1 in our select clauses).
  NodeId event_type_from(const EventFieldList& efl)
  {
    if (efl.event_fields().size() > 1)
      return efl.event_fields()[1].as<NodeId>();
    return {};
  }

  /// Extract SourceNode from an EventFieldList (field index 2).
  NodeId source_node_from(const EventFieldList& efl)
  {
    if (efl.event_fields().size() > 2)
      return efl.event_fields()[2].as<NodeId>();
    return {};
  }

  uint32_t mSubscriptionId{0};
};

// ===========================================================================
// Item 22: Audit Event Subscription Tests (COND-1200 series)
// ===========================================================================

// COND-1200: Enable method emits AuditConditionEnableEventPayload via subscription
// @relation(AC-SVR-AC-008-ENABLE-AUDIT, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_EnableEmitsAuditConditionEnableEvent)
{
  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionEnableEventType}));

  call_condition_method(mConditionId, "Enable");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionEnableEventType});
}

// COND-1201: Disable method emits AuditConditionEnableEventPayload via subscription
// @relation(AC-SVR-AC-005-DISABLE-AUDIT, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_DisableEmitsAuditConditionEnableEvent)
{
  mCondition->enable_sync();
  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionEnableEventType}));

  call_condition_method(mConditionId, "Disable");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionEnableEventType});
}

// COND-1202: AddComment method emits AuditConditionCommentEventPayload via subscription
// @relation(SVR-AC-016, SVR-AC-017, SVR-AC-066, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_AddCommentEmitsAuditConditionCommentEvent)
{
  mCondition->enable_sync();
  auto eventId = get_event_id(mCondition);
  ASSERT_FALSE(eventId.empty());

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionCommentEventType}));

  call_condition_method(
    mConditionId, "AddComment", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Test"}}});

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionCommentEventType});
}

// COND-1203: Acknowledge method emits AuditConditionAcknowledgeEventPayload via subscription
// @relation(AC-SVR-AC-029-ACKNOWLEDGE-AUDIT, SVR-AC-067, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_AcknowledgeEmitsAuditConditionAcknowledgeEvent)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionAcknowledgeEventType}));

  call_condition_method(
    mAlarmId, "Acknowledge", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack"}}});

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionAcknowledgeEventType});
}

// COND-1204: Confirm method emits AuditConditionConfirmEventPayload via subscription
// @relation(SVR-AC-034, SVR-AC-068, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_ConfirmEmitsAuditConditionConfirmEvent)
{
  auto confirmMethodId = find_method_via_browse(mAlarmId, "Confirm");
  ASSERT_FALSE(confirmMethodId.is_null()) << "Alarm with supports_confirm should have Confirm method";

  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionConfirmEventType}));

  call_condition_method(
    mAlarmId, "Confirm", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Confirm"}}});

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionConfirmEventType});
}

// COND-1205, corrected: a Condition audit Event's SourceNode is the ConditionId, not the Server
// Object. The original assertion said "audit events are server-scoped", which is true of the channel
// and session audit families and not of this one - Part 9 section 5.10 (part9.txt:5054) says in as many
// words that "the inherited Property SourceNode shall be filled with the ConditionId". The test
// carried no coverage marker and was pinning the behaviour the SDK happened to have; the obligation
// it contradicts is `AC-SVR-AC-063-AUDIT-SOURCENODE-CONDITIONID`.
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_SourceNodeIsTheConditionId)
{
  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionEnableEventType}));

  call_condition_method(mConditionId, "Enable");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(source_node_from(events[0]), mConditionId);
  EXPECT_NE(source_node_from(events[0]), NodeId{ObjectId::Server});
}

// ===========================================================================
// Item 23: E2E Subscription Tests (COND-1800 series)
// ===========================================================================

// COND-1800: Alarm activation event delivered via subscription
TEST_F(ComplianceConditionSubscriptionTest, Subscription_AlarmActivationDelivered)
{
  mAlarm->enable_sync();

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AlarmConditionType}));

  mAlarm->activate_sync(600);

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);

  // EventType should be AlarmConditionType (or subtype)
  auto eventType = event_type_from(events[0]);
  EXPECT_EQ(eventType, NodeId{ObjectTypeId::AlarmConditionType});

  // SourceNode should be the condition's source node (ObjectsFolder in this fixture)
  EXPECT_EQ(source_node_from(events[0]), NodeId{ObjectId::ObjectsFolder});

  // EventId must be present and non-empty (field 0)
  EXPECT_FALSE(events[0].event_fields()[0].empty());
  auto eventId = events[0].event_fields()[0].as<ByteString>();
  EXPECT_FALSE(eventId.empty());

  // Severity (field 6) should match what we set
  EXPECT_EQ(events[0].event_fields()[6].as<uint16_t>(), 600);
}

// COND-1801: Enable event delivered via subscription with Retain=true
TEST_F(ComplianceConditionSubscriptionTest, Subscription_EnableEventDeliveredWithRetain)
{
  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::ConditionType}));

  mCondition->enable_sync();

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);

  // Retain field (index 8) should be true after enable
  EXPECT_TRUE(events[0].event_fields()[8].as<bool>());
}

// COND-1802: Disable produces Retain=false event via subscription
TEST_F(ComplianceConditionSubscriptionTest, Subscription_DisableEventHasRetainFalse)
{
  mCondition->enable_sync();

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::ConditionType}));

  mCondition->disable_sync();

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);

  // Retain (index 8) should be false after disable
  EXPECT_FALSE(events[0].event_fields()[8].as<bool>());
}

// COND-1803: Acknowledge event delivered via subscription with AckedState
// @relation(SVR-AC-027, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, Subscription_AcknowledgeEventShowsAckedState)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AlarmConditionType}));

  call_condition_method(
    mAlarmId, "Acknowledge", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack"}}});

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);

  // AckedState (index 9) should reflect acknowledged
  auto ackedState = events[0].event_fields()[9];
  EXPECT_FALSE(ackedState.empty());
}

// COND-1804: Full lifecycle events delivered in order via subscription
TEST_F(ComplianceConditionSubscriptionTest, Subscription_FullLifecycleEventsDelivered)
{
  create_event_monitored_item(make_condition_event_filter());

  // Enable -> Activate -> Deactivate -> Disable
  mAlarm->enable_sync();
  mAlarm->activate_sync(700);
  mAlarm->deactivate_sync();
  mAlarm->disable_sync();

  // Collect all events (may need multiple publish rounds)
  std::vector<EventFieldList> allEvents;
  for (int round = 0; round < 30; ++round)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    if (result.is_bad())
      continue;
    auto& resp = result.value();
    if (!resp.response_header().service_result().is_good())
      continue;
    for (const auto& nd : resp.notification_message().notification_data())
    {
      auto* enl = dynamic_cast<const EventNotificationList*>(nd.get());
      if (enl)
      {
        for (const auto& efl : enl->events())
          allEvents.push_back(efl);
      }
    }
    // We expect at least 4 condition events + audit events. ConditionPayload events
    // alone: enable, activate, deactivate, disable = 4 minimum.
    if (allEvents.size() >= 4)
      break;
  }

  // Should have received at least the 4 condition state-change events
  ASSERT_GE(allEvents.size(), 4u)
    << "Expected at least 4 lifecycle events (enable, activate, deactivate, disable)";

  // Each event should have a non-empty EventId
  for (size_t i = 0; i < allEvents.size(); ++i)
  {
    EXPECT_FALSE(allEvents[i].event_fields()[0].empty())
      << "Event " << i << " should have a non-empty EventId";
  }
}

// ===========================================================================
// Phase F: Audit Event Tests for Shelving, Suppress, Silence, Reset, Respond
// ===========================================================================

// COND-650: TimedShelve emits AuditConditionShelvingEventPayload
// @relation(AC-SVR-AC-139-TIMEDSHELVE-AUDIT, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_TimedShelveEmitsAuditConditionShelvingEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionShelvingEventType}));

  call_child_method(mFullAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{5000.0}});

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionShelvingEventType});
}

// COND-651: OneShotShelve emits AuditConditionShelvingEventPayload
// @relation(SVR-AC-142, SVR-AC-143, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_OneShotShelveEmitsAuditConditionShelvingEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionShelvingEventType}));

  call_child_method(mFullAlarmId, "ShelvingState", "OneShotShelve");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionShelvingEventType});
}

// COND-652: Unshelve emits AuditConditionShelvingEventPayload
// @relation(SVR-AC-137, SVR-AC-143, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_UnshelveEmitsAuditConditionShelvingEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);
  mFullAlarm->timed_shelve_sync(5000.0);

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionShelvingEventType}));

  call_child_method(mFullAlarmId, "ShelvingState", "Unshelve");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionShelvingEventType});
}

// COND-704: Suppress emits AuditConditionSuppressionEventPayload
// @verifies AC-SVR-AC-127-SUPPRESS-AUDIT
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_SuppressEmitsAuditConditionSuppressionEvent)
{
  mFullAlarm->enable_sync();

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionSuppressionEventType}));

  call_condition_method(mFullAlarmId, "Suppress");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionSuppressionEventType});
}

// COND-706: Unsuppress emits AuditConditionSuppressionEventPayload
// @verifies AC-SVR-AC-129-UNSUPPRESS-AUDIT
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_UnsuppressEmitsAuditConditionSuppressionEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->suppress_sync();

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionSuppressionEventType}));

  call_condition_method(mFullAlarmId, "Unsuppress");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionSuppressionEventType});
}

// COND-714b: RemoveFromService emits AuditConditionOutOfServiceEventPayload
// Covers SVR-AC-132 (coverage-audit retag).
// @verifies AC-SVR-AC-132-REMOVEFROMSERVICE-AUDIT
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_RemoveFromServiceEmitsAuditConditionOutOfServiceEvent)
{
  mFullAlarm->enable_sync();

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType}));

  call_condition_method(mFullAlarmId, "RemoveFromService");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType});
}

// COND-714d: PlaceInService emits AuditConditionOutOfServiceEventPayload
// @verifies AC-SVR-AC-135-PLACEINSERVICE-AUDIT
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_PlaceInServiceEmitsAuditConditionOutOfServiceEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->remove_from_service_sync();

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType}));

  call_condition_method(mFullAlarmId, "PlaceInService");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType});
}

// COND-334: Silence emits AuditConditionSilenceEventPayload
// Covers SVR-AC-126 (coverage-audit retag).
// @verifies AC-SVR-AC-126-SILENCE-AUDIT
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_SilenceEmitsAuditConditionSilenceEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionSilenceEventType}));

  call_condition_method(mFullAlarmId, "Silence");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionSilenceEventType});
}

// COND-354d: Reset emits AuditConditionResetEventPayload
// Covers SVR-AC-124 (coverage-audit retag).
TEST_F(ComplianceConditionSubscriptionTest, AuditEvent_ResetEmitsAuditConditionResetEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);
  mFullAlarm->deactivate_sync();
  auto eventId = get_event_id(mFullAlarm);
  mFullAlarm->acknowledge_sync(eventId, LocalizedText{"", "ack"});

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionResetEventType}));

  call_condition_method(mFullAlarmId, "Reset");

  auto events = collect_events();
  ASSERT_GE(events.size(), 1u);
  EXPECT_EQ(event_type_from(events[0]), NodeId{ObjectTypeId::AuditConditionResetEventType});
}

// ===========================================================================
// ConditionRefresh via Call Service (COND-130 series)
// ===========================================================================

// COND-130: ConditionRefresh delivers RefreshStart, retained conditions, RefreshEnd
// @relation(SVR-AC-020, SVR-AC-022, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh_ViaCallService_DeliversCorrectSequence)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);  // Alarm is now retained

  create_event_monitored_item(make_condition_event_filter());

  // Call ConditionRefresh via the Call service
  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Call failed: " << result.status_code().as_uint32();
  ASSERT_FALSE(result.value().results().empty());
  EXPECT_TRUE(result.value().results()[0].status_code().is_good())
    << "ConditionRefresh failed: " << result.value().results()[0].status_code().as_uint32();

  // Collect until the RefreshEnd terminator arrives. A ConditionRefresh is a
  // bounded sequence (RefreshStart -> retained conditions -> RefreshEnd); under
  // load these split across multiple Publish responses, so poll until RefreshEnd
  // is observed (or a generous deadline) rather than assuming one fixed window
  // captures all of them. (The old minCount=1 + fixed-window collect truncated
  // the refresh under load -> spurious size<3 failures.)
  const NodeId refreshStartType{ObjectTypeId::RefreshStartEventType};
  const NodeId refreshEndType{ObjectTypeId::RefreshEndEventType};
  std::vector<EventFieldList> events;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    bool sawEnd = false;
    while (!sawEnd && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool isEnd = (event_type_from(e) == refreshEndType);
        events.push_back(std::move(e));
        if (isEnd)
          sawEnd = true;
      }
    }
    ASSERT_TRUE(sawEnd) << "RefreshEnd was not delivered within the deadline (collected " << events.size()
                        << " events)";
  }

  // Assert the refresh SEQUENCE by locating its bounds, tolerating any non-refresh
  // event that legitimately interleaves (e.g. a concurrent alarm state-change
  // delivered around the refresh): RefreshStart must precede RefreshEnd, with at
  // least one retained condition strictly between them. (The old positional
  // events[0]/events.back() assertion failed when such an event interleaved.)
  std::optional<size_t> startIdx;
  std::optional<size_t> endIdx;
  for (size_t i = 0; i < events.size(); ++i)
  {
    const auto type = event_type_from(events[i]);
    if (!startIdx && type == refreshStartType)
      startIdx = i;
    if (type == refreshEndType)
      endIdx = i;
  }
  ASSERT_TRUE(startIdx.has_value()) << "no RefreshStart event delivered";
  ASSERT_TRUE(endIdx.has_value()) << "no RefreshEnd event delivered";
  EXPECT_LT(*startIdx, *endIdx) << "RefreshStart must precede RefreshEnd";

  size_t conditionsBetween = 0;
  for (size_t i = *startIdx + 1; i < *endIdx; ++i)
  {
    const auto type = event_type_from(events[i]);
    if (type != refreshStartType && type != refreshEndType)
      ++conditionsBetween;
  }
  EXPECT_GE(conditionsBetween, 1u)
    << "expected at least one retained condition between RefreshStart and RefreshEnd";
}

// OPC 10000-9 section 4.5: RefreshStart and RefreshEnd "ignore the Event content filtering associated with a
// Subscription and will always be delivered to the Client". The UACTT A&C Refresh monitor filters with
// InList(ConditionId, [...]); here the list names no Condition of this server, so the where clause excludes
// the retained alarm (nothing between the two) while the refresh bracket is still delivered.
// @relation(AC-SVR-AC-220-REFRESH-BRACKET-IGNORES-WHERE, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh_TheRefreshEventsIgnoreTheWhereClause)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);  // retained: a refresh replays it unless the where clause excludes it

  // The list names no Condition of this server, so the where clause excludes every Condition Event.
  create_event_monitored_item(make_condition_id_filter(NodeId{1, "NotAConditionOfThisServer"}));

  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
  ASSERT_FALSE(result.value().results().empty());
  ASSERT_TRUE(result.value().results()[0].status_code().is_good())
    << ua::to_string(result.value().results()[0].status_code());

  const NodeId refreshStartType{ObjectTypeId::RefreshStartEventType};
  const NodeId refreshEndType{ObjectTypeId::RefreshEndEventType};
  std::vector<NodeId> types;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (std::chrono::steady_clock::now() < deadline &&
         std::find(types.begin(), types.end(), refreshEndType) == types.end())
  {
    for (const auto& event : collect_events(10))
      types.push_back(event_type_from(event));
  }
  const auto start = std::find(types.begin(), types.end(), refreshStartType);
  const auto end = std::find(types.begin(), types.end(), refreshEndType);
  ASSERT_NE(start, types.end()) << "RefreshStart was not delivered (" << types.size() << " events)";
  ASSERT_NE(end, types.end()) << "RefreshEnd was not delivered (" << types.size() << " events)";
  EXPECT_LT(start, end);
  EXPECT_EQ(std::distance(start, end), 1) << "the where clause still excludes the retained alarm";
}

// COND-132: Only retained conditions in refresh
// @relation(SVR-AC-021, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh_OnlyRetainedConditions)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);  // Retained
  // mCondition is disabled (not retained)

  create_event_monitored_item(make_condition_event_filter());

  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good());
  EXPECT_TRUE(result.value().results()[0].status_code().is_good());

  // Collect until the RefreshEnd terminator arrives (same pattern as
  // ConditionRefresh_ViaCallService_DeliversCorrectSequence): a ConditionRefresh
  // is a bounded RefreshStart -> retained conditions -> RefreshEnd sequence that
  // splits across multiple Publish responses under load, so poll until RefreshEnd
  // rather than assuming one fixed window captures all of it. (The old
  // collect_events(30) + ASSERT_GE(size, 3) truncated the refresh under load ->
  // spurious size==2 failures on the small-stack runner.)
  const NodeId refreshEndType{ObjectTypeId::RefreshEndEventType};
  std::vector<EventFieldList> events;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    bool sawEnd = false;
    while (!sawEnd && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool isEnd = (event_type_from(e) == refreshEndType);
        events.push_back(std::move(e));
        if (isEnd)
          sawEnd = true;
      }
    }
    ASSERT_TRUE(sawEnd) << "RefreshEnd was not delivered within the deadline (collected " << events.size()
                        << " events)";
  }

  // Count condition events (exclude RefreshStart and RefreshEnd)
  size_t conditionCount = 0;
  for (const auto& e : events)
  {
    auto type = event_type_from(e);
    if (type != NodeId{ObjectTypeId::RefreshStartEventType} &&
        type != NodeId{ObjectTypeId::RefreshEndEventType})
    {
      ++conditionCount;
    }
  }
  // Only the activated alarm should be in the refresh (not the disabled condition)
  EXPECT_GE(conditionCount, 1u);
}

// COND-134: BadSubscriptionIdInvalid for non-existent subscription ID
// @relation(SVR-AC-019, SVR-AC-024, SVR-AC-085, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh_BadSubscriptionIdInvalid)
{
  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{uint32_t{99999}}});  // Non-existent subscription
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
}

// ===========================================================================
// End-to-End Integration Tests (COND-1805, 1806)
// ===========================================================================

// COND-1805: Alarm deactivates after ack + return-to-normal -> Retain=False
// Uses the basic alarm (mAlarm, which has supports_confirm=true), so both ack
// and confirm are needed for full resolution. Server-side confirm is used
// since we need the correct EventId for the confirm call.
TEST_F(ComplianceConditionSubscriptionTest, E2E_AlarmDeactivatesAndRetainFalse)
{
  // Subscribe first so we catch all events
  create_event_monitored_item(make_condition_event_filter());

  mAlarm->enable_sync();
  mAlarm->activate_sync(500);

  // Acknowledge and confirm server-side (avoids EventId coordination issues)
  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());
  mAlarm->acknowledge_sync(eventId, LocalizedText{"", "Ack"});
  eventId = get_event_id(mAlarm);
  auto confirmResult = mAlarm->try_confirm_sync(eventId, LocalizedText{"", "Confirm"});
  ASSERT_TRUE(confirmResult.is_good()) << "Confirm failed: " << confirmResult.status_code().as_uint32();

  // Deactivate - with acked + confirmed + deactivated, Retain should go False
  mAlarm->deactivate_sync();

  // Verify server-side state
  auto snap = mAlarm->snapshot();
  ASSERT_FALSE(snap->active()) << "Alarm should be inactive";
  ASSERT_TRUE(snap->acked()) << "Alarm should be acked";
  EXPECT_FALSE(snap->retained()) << "Alarm should not be retained after ack+confirm+deactivate";

  // Collect events - keep polling until we see a Retain=False event
  bool foundRetainFalse = false;
  size_t totalEvents = 0;
  for (int round = 0; round < 30; ++round)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto result = mSession->subscriptions().try_publish_sync(PublishRequest{});
    if (result.is_bad())
      continue;
    auto& resp = result.value();
    if (!resp.response_header().service_result().is_good())
      continue;
    for (const auto& nd : resp.notification_message().notification_data())
    {
      auto* enl = dynamic_cast<const EventNotificationList*>(nd.get());
      if (enl)
      {
        for (const auto& efl : enl->events())
        {
          ++totalEvents;
          if (efl.event_fields().size() > 8 && !efl.event_fields()[8].empty() &&
              !efl.event_fields()[8].as<bool>())
          {
            foundRetainFalse = true;
          }
        }
      }
    }
    if (foundRetainFalse)
      break;
  }
  EXPECT_TRUE(foundRetainFalse) << "No Retain=False event in " << totalEvents << " events";
}

// COND-1806: Client shelves and unshelves alarm via Call service
TEST_F(ComplianceConditionSubscriptionTest, E2E_ShelveAndUnshelveViaClient)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  // Shelve via client
  auto shelveStatus =
    call_child_method(mFullAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{60000.0}});
  EXPECT_TRUE(shelveStatus.is_good()) << "TimedShelve failed: " << shelveStatus.as_uint32();

  // Verify shelved state via snapshot
  EXPECT_TRUE(mFullAlarm->snapshot()->suppressed_or_shelved());

  // Unshelve via client
  auto unshelveStatus = call_child_method(mFullAlarmId, "ShelvingState", "Unshelve");
  EXPECT_TRUE(unshelveStatus.is_good()) << "Unshelve failed: " << unshelveStatus.as_uint32();

  // Verify unshelved
  EXPECT_FALSE(mFullAlarm->snapshot()->suppressed_or_shelved());
}

// ===========================================================================
// G1: ClientUserId, Cross-Session Validation, Concurrent Refresh
// ===========================================================================

static EventFilter make_condition_filter_with_client_user_id()
{
  EventFilter filter = make_condition_event_filter();
  filter.select_clauses().push_back(make_select_clause("ClientUserId", NodeId{ObjectTypeId::ConditionType}));
  return filter;
}

// G1-1 / COND-077: ClientUserId propagation - client-triggered method sets ClientUserId on event
TEST_F(ComplianceConditionSubscriptionTest, ConditionMethod_ClientUserIdSetOnEvent)
{
  create_event_monitored_item(make_condition_filter_with_client_user_id());

  auto status = call_condition_method(mAlarmId, "Enable");
  ASSERT_TRUE(status.is_good()) << "Enable failed: " << status.as_uint32();

  auto events = collect_events();
  ASSERT_FALSE(events.empty()) << "No events received after Enable";

  // Find a condition event (skip RefreshStart/End markers)
  const EventFieldList* conditionEvent = nullptr;
  for (const auto& efl : events)
  {
    auto type = event_type_from(efl);
    if (type != NodeId{ObjectTypeId::RefreshStartEventType} &&
        type != NodeId{ObjectTypeId::RefreshEndEventType})
    {
      conditionEvent = &efl;
      break;
    }
  }
  ASSERT_NE(conditionEvent, nullptr) << "No condition event found (only refresh markers)";

  // ClientUserId is at index 11 (the 12th select clause, 0-based)
  ASSERT_GT(conditionEvent->event_fields().size(), 11u);
  auto clientUserId = conditionEvent->event_fields()[11].as<String>();
  EXPECT_EQ(clientUserId, String{"anonymous"})
    << "ClientUserId should be 'anonymous' for AnonymousAuthenticator";
}

// G1-2 / COND-135: Cross-session validation - ConditionRefresh rejects subscription from wrong session
// clang-format off  -- this declaration must stay on ONE line: the requirements gate matches
// the JUnit test name against the tree-sitter function name, and a wrapped TEST_F cannot be
// matched (it fails the whole export, not just this test). Exceeds ColumnLimit by a few chars.
// clang-format off
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh_CrossSessionValidation_ReturnsBadSubscriptionIdInvalid)
// clang-format on
{
  // mSubscriptionId belongs to mSession (via mChannel).
  // Create a second client + channel + session to the same server.
  boost::asio::thread_pool clientPool2;
  {
    // The long form: this second session rides a None channel, which the client refuses unless
    // the application opts in. create_test_config() carries that opt-in.
    auto client2 = CoreClient::create(clientPool2.get_executor(),
      ua::client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()});
    auto channel2 = client2.open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session2 = channel2.create_session_sync({.sessionName = "CrossSessionTest"});
    session2.activate_sync();

    // From session2, call ConditionRefresh with mSubscriptionId that belongs to session1
    auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
      NodeId{MethodId::ConditionType_ConditionRefresh},
      Array<Variant>{Variant{mSubscriptionId}});
    auto result = session2.methods().try_call_sync(std::move(req));
    ASSERT_TRUE(result.is_good());
    EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid})
      << "ConditionRefresh should reject subscription belonging to a different session";

    (void)session2.try_close_sync();
    (void)channel2.try_close_sync();
  }  // session2/channel2/client2 destroyed before pool stop so cert store timer is cancelled.
  clientPool2.join();
}

// G1-3 / COND-136: BadRefreshInProgress - concurrent ConditionRefresh calls are handled correctly
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh_ConcurrentCallsHandled)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  create_event_monitored_item(make_condition_event_filter());

  // Fire two concurrent ConditionRefresh calls from separate threads
  auto callRefresh = [this]()
  {
    auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
      NodeId{MethodId::ConditionType_ConditionRefresh},
      Array<Variant>{Variant{mSubscriptionId}});
    return mSession->methods().try_call_sync(std::move(req));
  };

  auto f1 = std::async(std::launch::async, callRefresh);
  auto f2 = std::async(std::launch::async, callRefresh);

  auto r1 = f1.get();
  auto r2 = f2.get();

  // Both service-level calls should succeed (method was found and dispatched)
  ASSERT_TRUE(r1.is_good());
  ASSERT_TRUE(r2.is_good());

  bool firstGood = r1.value().results()[0].status_code().is_good();
  bool secondGood = r2.value().results()[0].status_code().is_good();

  // At least one must succeed
  EXPECT_TRUE(firstGood || secondGood) << "At least one ConditionRefresh should succeed";

  // If one failed, it must be BadRefreshInProgress (not some other error)
  if (!firstGood)
  {
    EXPECT_EQ(r1.value().results()[0].status_code(), StatusCode{Status::BadRefreshInProgress});
  }
  if (!secondGood)
  {
    EXPECT_EQ(r2.value().results()[0].status_code(), StatusCode{Status::BadRefreshInProgress});
  }
}

// ===========================================================================
// COND-060: Enable evaluates bound input
// ===========================================================================

class ComplianceLimitAlarmTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto& server = mServer.server();
    auto addressSpace = server.address_space();
    auto& conditions = server.conditions();

    // Create an input variable with an initial value below the limit
    mInputNodeId = NodeId{0, uint32_t{50001}};
    auto inputNode = addressSpace.create_node_sync(mInputNodeId, NodeClass::Variable);
    auto inputVar = inputNode.as<VariableAccessor>();
    ASSERT_TRUE(inputVar.has_value());
    inputVar->set_browse_name(QualifiedName{0, "TestLimitInput"});
    inputVar->set_display_name(LocalizedText{"", "TestLimitInput"});
    inputVar->set_data_type(NodeId{DataTypeId::Double});
    inputVar->write_value_sync(50.0);
    inputVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    // Add to Objects folder so the address space can find it
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mInputNodeId);

    // HighHigh is supplied; High exists in the underlying system but its actual value is unavailable.
    auto limitLogic = std::make_unique<LimitAlarmLogic>();
    LimitConfig limits;
    limits.highHighLimit = 90.0;
    limits.highLimit = ConfiguredLimit::unavailable();
    limitLogic->set_limits(limits);

    mLimitAlarm = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"TestLimitAlarm"},
      std::move(limitLogic),
      NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
    mLimitAlarmId = mLimitAlarm->condition_id();

    // Bind the alarm to the input variable (1 second sampling interval)
    mLimitAlarm->bind_input_sync(mInputNodeId, 1000.0);
  }

  NodeId mInputNodeId;
  NodeId mLimitAlarmId;
  std::shared_ptr<ConditionInstance> mLimitAlarm;
};

// COND-060: When a limit alarm with a bound input is disabled, the input changes
// to violate a limit, and the alarm is re-enabled, the alarm should auto-activate
// immediately (not wait for the next sampling interval).
TEST_F(ComplianceLimitAlarmTest, EnableEvaluatesInput_LimitViolationTriggersActivation)
{
  // 1. Enable the alarm, verify it starts inactive (input=50.0 < HighHigh=90.0)
  mLimitAlarm->enable_sync();
  // Give the fire-and-forget evaluation coroutine time to complete
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  ASSERT_FALSE(mLimitAlarm->snapshot()->active()) << "Alarm should be inactive with input below limit";

  // 2. Disable the alarm
  mLimitAlarm->disable_sync();
  ASSERT_FALSE(mLimitAlarm->snapshot()->enabled());

  // 3. Write the input variable to a value above HighHigh (95.0 > 90.0)
  auto addressSpace = mServer.server().address_space();
  auto inputNode = addressSpace.find_node_sync(mInputNodeId);
  auto inputVar = inputNode.as<VariableAccessor>();
  ASSERT_TRUE(inputVar.has_value());
  inputVar->write_value_sync(95.0);

  // 4. Re-enable the alarm via client Call service
  auto status = call_condition_method(mLimitAlarmId, "Enable");
  EXPECT_TRUE(status.is_good()) << "Enable should succeed, got: " << status.as_uint32();

  // 5. Poll the snapshot for activation. The evaluation is a fire-and-forget
  //    coroutine that reads from the address space asynchronously after enable
  //    returns, so we need a short polling loop.
  bool activated = false;
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    if (mLimitAlarm->snapshot()->active())
    {
      activated = true;
      break;
    }
  }
  EXPECT_TRUE(activated) << "Alarm should auto-activate when enabled with input violating HighHigh limit";
}

// COND-1102: bind_input sets quality to Bad_WaitingForInitialData until the first
// sample arrives from the sampling timer.
// Covers SVR-AC-079 (coverage-audit retag).
TEST_F(ComplianceLimitAlarmTest, BindInput_SetsQualityToWaitingForInitialData)
{
  auto& server = mServer.server();
  auto& conditions = server.conditions();

  // Create a new limit alarm (separate from mLimitAlarm which was already bound
  // during configure_server and may have had its first sample by now).
  auto limitLogic = std::make_unique<LimitAlarmLogic>();
  LimitConfig limits;
  limits.highHighLimit = 90.0;
  limitLogic->set_limits(limits);

  auto alarm = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
    NodeId{ObjectId::ObjectsFolder},
    String{"WaitingAlarm"},
    std::move(limitLogic),
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});

  alarm->enable_sync();

  // Before binding, quality should be Good (default).
  auto snap = alarm->snapshot();
  EXPECT_TRUE(snap->quality().is_good()) << "Quality should be Good before bind_input";

  // Bind to input with a very long sampling interval so the timer won't fire
  // before we inspect the snapshot.
  alarm->bind_input_sync(mInputNodeId, 10000.0);

  snap = alarm->snapshot();
  EXPECT_EQ(snap->quality(), StatusCode{Status::BadWaitingForInitialData})
    << "Quality should be Bad_WaitingForInitialData after bind_input before first sample";
}

// ===========================================================================
// Seeded OffNormalAlarm (mirrors the compliance_test_server A&C seed)
// ===========================================================================
//
// The compliance_test_server seeds a single OffNormalAlarm sourced from a browsable AlarmSource
// Object so the UACTT "Alarms & Conditions" CUs (A&C Enable / Acknowledge / Confirm / Comment /
// Refresh / Basic / Instances) have a live condition to exercise. These tests pin that seeding shape:
// the source object, the OffNormalAlarmType instance with its HasCondition link, the mandatory
// ConditionType properties, ConditionRefresh, and Enable / Acknowledge over the wire.

class SeededOffNormalAlarmTest : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto& server = mServer.server();
    auto addressSpace = server.address_space();

    mNamespace = default_ns::Namespace::create("urn:test:ac-seed", mServer.thread_pool().executor());
    mNamespaceIndex = addressSpace.add_namespace_sync(mNamespace);

    // Browsable source Object (BaseObjectType) under the Objects folder - the node the CTT follows
    // HasCondition / HasEventSource from. Mirrors AddressSpaceSeed::seed_conditions.
    mSourceId = NodeId{mNamespaceIndex, std::string{"AlarmSource"}};
    auto sourceNode = addressSpace.create_node_sync(mSourceId, NodeClass::Object);
    sourceNode.set_browse_name(QualifiedName{mNamespaceIndex, "AlarmSource"});
    sourceNode.set_display_name(LocalizedText{"", "AlarmSource"});
    sourceNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSourceId);
    sourceNode.add_reference_sync(NodeId{ReferenceTypeId::Organizes},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    auto logic = std::make_unique<OffNormalAlarmLogic>();
    logic->set_supports_confirm(true);
    logic->set_normal_state(Variant{false});

    mAlarm = server.conditions().create_condition_sync(NodeId{mNamespaceIndex, uint32_t{0}},
      mSourceId,
      String{"OffNormalAlarm"},
      std::move(logic),
      NodeId{ObjectTypeId::OffNormalAlarmType});
    mAlarmId = mAlarm->condition_id();
    mAlarm->enable_sync();
  }

  // Browse references of one direction/type from a node and return the target matching browseName,
  // or a null NodeId.
  NodeId browse_target(const NodeId& nodeId, const NodeId& referenceType, const String& browseName,
    BrowseDirection direction = BrowseDirection::Forward)
  {
    BrowseDescription desc;
    desc.node_id() = nodeId;
    desc.browse_direction() = direction;
    desc.reference_type_id() = referenceType;
    desc.include_subtypes() = true;
    desc.node_class_mask() = 0;
    desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);

    BrowseRequest req;
    req.nodes_to_browse().push_back(std::move(desc));

    auto result = mSession->view().try_browse_sync(std::move(req));
    if (result.is_bad() || result.value().results().empty())
      return {};
    for (const auto& ref : result.value().results()[0].references())
    {
      if (ref.browse_name().name() == browseName)
        return ref.node_id().node_id();
    }
    return {};
  }

  NodeId find_method(const NodeId& conditionId, const String& methodName)
  {
    return browse_target(conditionId, NodeId{ReferenceTypeId::HasComponent}, methodName);
  }

  StatusCode call_method(const NodeId& conditionId, const String& methodName, Array<Variant> args = {})
  {
    auto methodId = find_method(conditionId, methodName);
    if (methodId.is_null())
      return StatusCode{Status::BadMethodInvalid};
    auto req = make_condition_call(conditionId, methodId, std::move(args));
    auto result = mSession->methods().try_call_sync(std::move(req));
    if (result.is_bad())
      return result.status_code();
    if (result.value().results().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.value().results()[0].status_code();
  }

  uint16_t mNamespaceIndex{0};
  std::shared_ptr<Namespace> mNamespace;
  NodeId mSourceId;
  NodeId mAlarmId;
  std::shared_ptr<ConditionInstance> mAlarm;
};

// The condition node is browsable from its source: HasCondition source -> alarm, and the alarm is a
// HasComponent child of the source (instantiation default parent edge). A&C Instances/Basic discover
// conditions this way.
TEST_F(SeededOffNormalAlarmTest, ConditionIsBrowsableFromSource)
{
  auto viaHasCondition = browse_target(mSourceId, NodeId{ReferenceTypeId::HasCondition}, "OffNormalAlarm");
  EXPECT_FALSE(viaHasCondition.is_null()) << "HasCondition source->alarm should be browsable";
  EXPECT_EQ(viaHasCondition, mAlarmId);

  auto asChild = browse_target(mSourceId, NodeId{ReferenceTypeId::HasComponent}, "OffNormalAlarm");
  EXPECT_FALSE(asChild.is_null()) << "alarm should be a browsable HasComponent child of its source";
  EXPECT_EQ(asChild, mAlarmId);
}

// The seeded condition is an OffNormalAlarmType instance (HasTypeDefinition).
TEST_F(SeededOffNormalAlarmTest, ConditionHasOffNormalAlarmTypeDefinition)
{
  auto typeDef = browse_target(mAlarmId, NodeId{ReferenceTypeId::HasTypeDefinition}, "OffNormalAlarmType");
  EXPECT_FALSE(typeDef.is_null()) << "alarm should carry HasTypeDefinition -> OffNormalAlarmType";
  EXPECT_EQ(typeDef, NodeId{ObjectTypeId::OffNormalAlarmType});
}

// Mandatory ConditionType / AcknowledgeableConditionType / AlarmConditionType members are present.
TEST_F(SeededOffNormalAlarmTest, MandatoryMembersArePresent)
{
  // Mandatory methods.
  EXPECT_FALSE(find_method(mAlarmId, "Enable").is_null());
  EXPECT_FALSE(find_method(mAlarmId, "Disable").is_null());
  EXPECT_FALSE(find_method(mAlarmId, "AddComment").is_null());
  EXPECT_FALSE(find_method(mAlarmId, "Acknowledge").is_null());
  // Confirm is materialised because the logic supports confirm.
  EXPECT_FALSE(find_method(mAlarmId, "Confirm").is_null());

  // Mandatory state/property variables (reached via HasComponent / HasProperty).
  EXPECT_FALSE(browse_target(mAlarmId, NodeId{ReferenceTypeId::HasComponent}, "EnabledState").is_null());
  EXPECT_FALSE(browse_target(mAlarmId, NodeId{ReferenceTypeId::HasComponent}, "AckedState").is_null());
  EXPECT_FALSE(browse_target(mAlarmId, NodeId{ReferenceTypeId::HasComponent}, "ActiveState").is_null());
  EXPECT_FALSE(browse_target(mAlarmId, NodeId{ReferenceTypeId::HasProperty}, "Retain").is_null());
}

// Enable/Disable transition over the wire via the Call service and reflect in the snapshot.
TEST_F(SeededOffNormalAlarmTest, EnableDisableTransitionsOverTheWire)
{
  // configure_server() already enabled it; disabling then re-enabling exercises both transitions.
  ASSERT_TRUE(mAlarm->snapshot()->enabled());

  auto disableStatus = call_method(mAlarmId, "Disable");
  EXPECT_TRUE(disableStatus.is_good()) << "Disable failed: " << disableStatus.as_uint32();
  EXPECT_FALSE(mAlarm->snapshot()->enabled());

  auto enableStatus = call_method(mAlarmId, "Enable");
  EXPECT_TRUE(enableStatus.is_good()) << "Enable failed: " << enableStatus.as_uint32();
  EXPECT_TRUE(mAlarm->snapshot()->enabled());
}

// Acknowledge transitions AckedState over the wire for an active, unacknowledged alarm.
TEST_F(SeededOffNormalAlarmTest, AcknowledgeTransitionsOverTheWire)
{
  mAlarm->activate_sync(600);
  ASSERT_TRUE(mAlarm->snapshot()->active());
  ASSERT_FALSE(mAlarm->snapshot()->acked());

  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  auto status = call_method(
    mAlarmId, "Acknowledge", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack via wire"}}});
  EXPECT_TRUE(status.is_good()) << "Acknowledge failed: " << status.as_uint32();
  EXPECT_TRUE(mAlarm->snapshot()->acked());
}

// ConditionRefresh emits a RefreshStart, the retained alarm, and a RefreshEnd via subscription.
class SeededOffNormalAlarmSubscriptionTest : public SeededOffNormalAlarmTest
{
protected:
  void SetUp() override
  {
    SeededOffNormalAlarmTest::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 60});
  }

  void TearDown() override
  {
    if (mSession && mSubscriptionId != 0)
      delete_subscription(*mSession, mSubscriptionId);
    SeededOffNormalAlarmTest::TearDown();
  }

  uint32_t mSubscriptionId{0};
};

TEST_F(SeededOffNormalAlarmSubscriptionTest, ConditionRefreshEmitsRetainedAlarm)
{
  // Make the seeded alarm retained so the refresh has something to replay.
  mAlarm->activate_sync(600);

  (void)::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_condition_event_filter(),
    {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 50});

  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto callResult = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(callResult.is_good()) << "ConditionRefresh call failed: "
                                    << callResult.status_code().as_uint32();
  ASSERT_FALSE(callResult.value().results().empty());
  ASSERT_TRUE(callResult.value().results()[0].status_code().is_good())
    << "ConditionRefresh result bad: " << callResult.value().results()[0].status_code().as_uint32();

  const NodeId refreshStartType{ObjectTypeId::RefreshStartEventType};
  const NodeId refreshEndType{ObjectTypeId::RefreshEndEventType};

  auto eventTypeFrom = [](const EventFieldList& efl) -> NodeId
  {
    if (efl.event_fields().size() > 1)
      return efl.event_fields()[1].as<NodeId>();
    return {};
  };

  std::vector<EventFieldList> events;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  bool sawEnd = false;
  while (!sawEnd && std::chrono::steady_clock::now() < deadline)
  {
    auto batch = ::ua::test_helpers::collect_events(*mSession,
      mSubscriptionId,
      {.minCount = 1,
        .timeout = std::chrono::milliseconds{500},
        .pollInterval = std::chrono::milliseconds{50}});
    for (auto& e : batch)
    {
      const bool isEnd = (eventTypeFrom(e) == refreshEndType);
      events.push_back(std::move(e));
      if (isEnd)
        sawEnd = true;
    }
  }
  ASSERT_TRUE(sawEnd) << "RefreshEnd not delivered (collected " << events.size() << " events)";

  std::optional<size_t> startIdx;
  std::optional<size_t> endIdx;
  for (size_t i = 0; i < events.size(); ++i)
  {
    const auto type = eventTypeFrom(events[i]);
    if (!startIdx && type == refreshStartType)
      startIdx = i;
    if (type == refreshEndType)
      endIdx = i;
  }
  ASSERT_TRUE(startIdx.has_value()) << "no RefreshStart event";
  ASSERT_TRUE(endIdx.has_value()) << "no RefreshEnd event";
  EXPECT_LT(*startIdx, *endIdx) << "RefreshStart must precede RefreshEnd";

  size_t conditionsBetween = 0;
  for (size_t i = *startIdx + 1; i < *endIdx; ++i)
  {
    const auto type = eventTypeFrom(events[i]);
    if (type != refreshStartType && type != refreshEndType)
      ++conditionsBetween;
  }
  EXPECT_GE(conditionsBetween, 1u)
    << "expected the retained OffNormalAlarm between RefreshStart and RefreshEnd";
}

// ===========================================================================
// Instance type-definition compliance (mirrors UACTT "A & C Instances")
//
// The CTT walks each condition instance and checks every nested property against
// the ConditionType definition: each mandatory event field must be present with
// the correct DataType, and the optional properties the type advertises must be
// materialised. These reproduce the three "A & C Instances" failures:
//   - EventId/EventType/Time/ReceiveTime read DataType Null(0) instead of their type;
//   - SupportsFilteredRetain is missing;
//   - EnabledState.TransitionTime / ActiveState.TransitionTime are missing.
// Covers SVR-AC-INSTANCES (CTT Alarms and Conditions/A and C Instances/Test_001,002,006)
// ===========================================================================

// Find a hierarchical child (property OR component) of a node by browse name.
static NodeId find_hier_child(ua::client::Session& session, const NodeId& parentId, const String& name)
{
  BrowseDescription desc;
  desc.node_id() = parentId;
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
  desc.include_subtypes() = true;
  desc.node_class_mask() = 0;  // any node class
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  BrowseRequest req;
  req.nodes_to_browse().push_back(std::move(desc));
  auto result = session.view().try_browse_sync(std::move(req));
  if (result.is_bad() || result.value().results().empty())
    return {};
  for (const auto& ref : result.value().results()[0].references())
    if (ref.browse_name().name() == name)
      return ref.node_id().node_id();
  return {};
}

// Read a node's DataType attribute (the NodeId of its data type), or null on failure.
static NodeId read_data_type(ua::client::Session& session, const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::DataType);
  req.nodes_to_read().push_back(std::move(rv));
  auto resp = session.attributes().try_read_sync(std::move(req));
  if (resp.is_bad() || resp.value().results().empty())
    return {};
  const auto& dv = resp.value().results()[0];
  if (dv.status().has_value() && dv.status().value().is_bad())
    return {};
  return dv.value().as<NodeId>();
}

// Read a node's Value attribute as a DataValue (status + value), for value-consistency checks.
static DataValue read_value_dv(ua::client::Session& session, const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  auto resp = session.attributes().try_read_sync(std::move(req));
  if (resp.is_bad() || resp.value().results().empty())
    return {};
  return resp.value().results()[0];
}

TEST_F(ComplianceConditionTest, Instances_MandatoryEventFieldsHaveCorrectDataType)
{
  // Each mandatory BaseEventType field node must carry its spec DataType, not Null(0).
  struct Field
  {
    const char* name;
    uint32_t expected;
  };

  const Field fields[] = {
    {"EventId", static_cast<uint32_t>(DataTypeId::ByteString)},
    {"EventType", static_cast<uint32_t>(DataTypeId::NodeId)},
    {"SourceNode", static_cast<uint32_t>(DataTypeId::NodeId)},
  };
  for (const auto& f : fields)
  {
    auto fieldId = find_hier_child(*mSession, mFullAlarmId, String{f.name});
    ASSERT_FALSE(fieldId.is_null()) << f.name << " not present on the instance";
    auto dataType = read_data_type(*mSession, fieldId);
    EXPECT_FALSE(dataType.is_null()) << f.name << " has Null DataType (expected i=" << f.expected << ")";
    EXPECT_EQ(dataType, (NodeId{uint32_t{0}, f.expected})) << f.name << " DataType mismatch";
  }
  // Time / ReceiveTime are UtcTime (a DateTime subtype) - accept either, but never Null.
  for (const char* name : {"Time", "ReceiveTime"})
  {
    auto fieldId = find_hier_child(*mSession, mFullAlarmId, String{name});
    ASSERT_FALSE(fieldId.is_null()) << name << " not present";
    auto dataType = read_data_type(*mSession, fieldId);
    EXPECT_FALSE(dataType.is_null()) << name << " has Null DataType";
    EXPECT_TRUE((dataType == NodeId{uint32_t{0}, static_cast<uint32_t>(DataTypeId::DateTime)} ||
                 dataType == NodeId{uint32_t{0}, static_cast<uint32_t>(DataTypeId::UtcTime)}))
      << name << " DataType is neither DateTime nor UtcTime";
  }

  // OffNormalAlarmType.NormalState is a Mandatory NodeId-typed property - its DataType must survive
  // instantiation (the CTT read it as Null on the SUT's OffNormal alarm).
  auto normalStateId = find_hier_child(*mSession, mOffNormalId, String{"NormalState"});
  ASSERT_FALSE(normalStateId.is_null()) << "NormalState not present on OffNormal alarm";
  auto normalStateDt = read_data_type(*mSession, normalStateId);
  EXPECT_FALSE(normalStateDt.is_null()) << "NormalState has Null DataType (expected NodeId)";
  EXPECT_EQ(normalStateDt, (NodeId{uint32_t{0}, static_cast<uint32_t>(DataTypeId::NodeId)}))
    << "NormalState DataType is not NodeId";
}

// Diagnostic: the standard NS0 CertificateExpired alarm (i=19450) is IMPORTED from the embedded
// NodeSet; its EventId (i=19451) is DataType=ByteString there. The CTT read it as 0, so this pins
// whether the XML importer drops the attribute on imported condition-instance nodes.
TEST_F(ComplianceConditionTest, Diag_ImportedConditionInstanceEventIdDataType)
{
  const NodeId eventId{uint32_t{0}, uint32_t{19451}};  // CertificateExpired.EventId
  ReadRequest probe;
  ReadValueId rv;
  rv.node_id() = eventId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::NodeClass);
  probe.nodes_to_read().push_back(std::move(rv));
  auto pr = mSession->attributes().try_read_sync(std::move(probe));
  const bool present =
    pr.is_good() && !pr.value().results().empty() &&
    !(pr.value().results()[0].status().has_value() && pr.value().results()[0].status().value().is_bad());
  ASSERT_TRUE(present) << "missing precondition: CertificateExpired.EventId (i=19451) is not in this "
                          "server's address space, but the embedded standard NodeSet imports it";
  auto dt = read_data_type(*mSession, eventId);
  EXPECT_EQ(dt, (NodeId{uint32_t{0}, static_cast<uint32_t>(DataTypeId::ByteString)}))
    << "imported EventId DataType is not ByteString (importer dropped it?)";
}

TEST_F(ComplianceConditionTest, Instances_LimitAlarmPropertiesMaterialised)
{
  // LimitAlarmType optional property groups for each configured limit - required on both the
  // Exclusive and NonExclusive limit alarms by the UACTT "A & C Instances" CU.
  for (const char* prop : {"HighHighLimit",
         "HighLimit",
         "LowLimit",
         "LowLowLimit",
         "SeverityHighHigh",
         "SeverityHigh",
         "SeverityLow",
         "SeverityLowLow",
         "HighHighDeadband",
         "HighDeadband",
         "LowDeadband",
         "LowLowDeadband"})
  {
    EXPECT_FALSE(find_hier_child(*mSession, mExclusiveLimitId, String{prop}).is_null())
      << "ExclusiveLimit missing " << prop;
    EXPECT_FALSE(find_hier_child(*mSession, mNonExclusiveLimitId, String{prop}).is_null())
      << "NonExclusiveLimit missing " << prop;
  }
  // NonExclusiveLimitAlarmType per-limit state TwoStateVariables, each with Id + TransitionTime.
  for (const char* state : {"HighHighState", "HighState", "LowState", "LowLowState"})
  {
    auto stateId = find_hier_child(*mSession, mNonExclusiveLimitId, String{state});
    ASSERT_FALSE(stateId.is_null()) << "NonExclusiveLimit missing " << state;
    EXPECT_FALSE(find_hier_child(*mSession, stateId, String{"Id"}).is_null()) << state << ".Id missing";
    EXPECT_FALSE(find_hier_child(*mSession, stateId, String{"TransitionTime"}).is_null())
      << state << ".TransitionTime missing";
  }

  // The helper wires the configured threshold VALUES, so a direct Read returns the same value the
  // event carries (the fixture configured 90/70/30/10). Without wiring these read Null.
  struct ValCheck
  {
    const char* prop;
    double expected;
  };

  const ValCheck thresholds[] = {
    {"HighHighLimit", 90.0}, {"HighLimit", 70.0}, {"LowLimit", 30.0}, {"LowLowLimit", 10.0}};
  for (const auto& v : thresholds)
  {
    auto id = find_hier_child(*mSession, mExclusiveLimitId, String{v.prop});
    ASSERT_FALSE(id.is_null()) << v.prop << " missing";
    auto dv = read_value_dv(*mSession, id);
    ASSERT_FALSE(dv.status().has_value() && dv.status().value().is_bad())
      << v.prop << " read failed (not wired to a value)";
    EXPECT_DOUBLE_EQ(dv.value().as<double>(), v.expected) << v.prop << " value mismatch";
  }
  // Severity (UInt16) must read its configured value too (default 900 for the outer limits).
  auto sevId = find_hier_child(*mSession, mExclusiveLimitId, String{"SeverityHighHigh"});
  ASSERT_FALSE(sevId.is_null());
  auto sevDv = read_value_dv(*mSession, sevId);
  ASSERT_FALSE(sevDv.status().has_value() && sevDv.status().value().is_bad())
    << "SeverityHighHigh not wired to a value";
  EXPECT_EQ(sevDv.value().as<uint16_t>(), uint16_t{900}) << "SeverityHighHigh value mismatch";
}

TEST_F(ComplianceConditionTest, Instances_SupportsFilteredRetainReadsTypedValue)
{
  // The helper wires SupportsFilteredRetain through the payload's resolve_field() (the snapshot does
  // not carry it), so a Read returns the typed Boolean the event carries - not a null/BadAttributeId.
  auto id = find_hier_child(*mSession, mFullAlarmId, String{"SupportsFilteredRetain"});
  ASSERT_FALSE(id.is_null()) << "SupportsFilteredRetain not present";
  auto dv = read_value_dv(*mSession, id);
  ASSERT_FALSE(dv.status().has_value() && dv.status().value().is_bad())
    << "SupportsFilteredRetain reads bad status (not wired to a value)";
  EXPECT_FALSE(dv.value().empty()) << "SupportsFilteredRetain reads an empty Variant";
  EXPECT_EQ(dv.value().as<bool>(), false) << "SupportsFilteredRetain should be a (default-false) Boolean";
}

TEST_F(ComplianceConditionTest, Instances_OptionalConditionPropertiesMaterialised)
{
  // SupportsFilteredRetain (Optional on ConditionType, 1.05) must be instantiated.
  EXPECT_FALSE(find_hier_child(*mSession, mFullAlarmId, String{"SupportsFilteredRetain"}).is_null())
    << "SupportsFilteredRetain missing on the alarm instance";

  // EnabledState.TransitionTime and ActiveState.TransitionTime must be present.
  for (const char* state : {"EnabledState", "ActiveState"})
  {
    auto stateId = find_hier_child(*mSession, mFullAlarmId, String{state});
    ASSERT_FALSE(stateId.is_null()) << state << " missing";
    EXPECT_FALSE(find_hier_child(*mSession, stateId, String{"TransitionTime"}).is_null())
      << state << ".TransitionTime missing";
  }
}

// ===========================================================================
// ConditionBranch retention cap, driven over the wire
// ===========================================================================

// A branch is forked whenever an alarm re-activates while its previous event is still unacknowledged
// (OPC 10000-9 4.5), so an unattended alarm that toggles indefinitely would retain branches without bound.
// `ResourceLimits::conditionBranchesPerCondition` is the deployment's bound on that: when the live set is
// at the cap the oldest branch is retracted with `Retain=False` before the new one is added, which is what
// tells a client to drop it from its view.
//
// Branching is opt-in per condition (OPC 10000-9 4.2), so the alarm is seeded with it enabled - the
// server's own sample alarms leave it off, which is why no existing row reaches this path.
class SeededBranchingAlarmTest : public ComplianceWithSession
{
protected:
  /// The configured cap. Overridden by the roomy-cap control below, which is otherwise identical.
  virtual uint32_t branch_cap() const
  {
    return 2;
  }

  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.resourceLimits.conditionBranchesPerCondition = branch_cap();
  }

  void configure_server() override
  {
    auto& server = mServer.server();
    auto addressSpace = server.address_space();

    mNamespace = default_ns::Namespace::create("urn:test:branch-cap", mServer.thread_pool().executor());
    mNamespaceIndex = addressSpace.add_namespace_sync(mNamespace);

    // The alarm needs a source the server routes events through, linked to the Server Object by
    // HasNotifier: without that link every piece works and the client still receives nothing.
    mSourceId = NodeId{mNamespaceIndex, std::string{"BranchAlarmSource"}};
    auto sourceNode = addressSpace.create_node_sync(mSourceId, NodeClass::Object);
    sourceNode.set_browse_name(QualifiedName{mNamespaceIndex, "BranchAlarmSource"});
    sourceNode.set_display_name(LocalizedText{"", "BranchAlarmSource"});
    sourceNode.as<ua::ObjectAccessor>()->set_event_notifier(
      ua::EventNotifierType{ua::EventNotifierType::Bit::SubscribeToEvents});
    sourceNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSourceId);
    addressSpace.find_node_sync(NodeId{ObjectId::Server})
      .add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, mSourceId);

    auto logic = std::make_unique<AlarmConditionLogic>();
    logic->set_supports_branches(true);

    mAlarm = server.conditions().create_condition_sync(NodeId{mNamespaceIndex, uint32_t{0}},
      mSourceId,
      String{"BranchingAlarm"},
      std::move(logic),
      NodeId{ObjectTypeId::AlarmConditionType});
    mAlarm->enable_sync();
  }

  void SetUp() override
  {
    ComplianceWithSession::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 60});
    (void)::ua::test_helpers::create_event_monitored_item(*mSession,
      mSubscriptionId,
      NodeId{ObjectId::Server},
      branch_event_filter(),
      {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 100});
  }

  void TearDown() override
  {
    if (mSession && mSubscriptionId != 0)
    {
      delete_subscription(*mSession, mSubscriptionId);
    }
    ComplianceWithSession::TearDown();
  }

  /// The shared condition filter plus BranchId, which is what distinguishes a branch event from a trunk
  /// one (OPC 10000-9: BranchId is null on the trunk).
  static EventFilter branch_event_filter()
  {
    EventFilter filter = make_condition_event_filter();
    filter.select_clauses().push_back(make_select_clause("BranchId", NodeId{ObjectTypeId::ConditionType}));
    return filter;
  }

  static constexpr size_t sRetainIndex = 8;  // per make_condition_event_filter's select order
  static constexpr size_t sBranchIdIndex = 11;

  /// Re-activates the alarm without acknowledging, forking one branch per call after the first.
  void drive_unacknowledged_toggles(int count)
  {
    for (int i = 0; i < count; ++i)
    {
      mAlarm->activate_sync(static_cast<uint16_t>(500 + i));
      mAlarm->deactivate_sync();
    }
  }

  /// Every BranchId retracted with Retain=False - the eviction signal the cap produces.
  ///
  /// Drains until a retraction appears rather than until *an event* appears. collect_events returns
  /// the moment its minCount is met, so a single call only ever sees the first Publish to land -
  /// routinely the trunk event or a Retain=True branch, with the retraction following in a later one.
  /// That made the capped case depend on every notification arriving inside one poll window, which it
  /// does under a plain build and does not under a sanitizer's slowdown, and it left the roomy-cap
  /// control concluding "nothing was evicted" after inspecting a single event. Polling to a deadline
  /// serves both: the capped case returns as soon as it has its evidence, and the roomy case looks at
  /// the whole window before reporting none.
  std::vector<NodeId> collect_retracted_branch_ids()
  {
    std::vector<NodeId> retracted;
    const auto deadline =
      std::chrono::steady_clock::now() + ua::test_utils::scaled(std::chrono::milliseconds{3000});
    while (retracted.empty() && std::chrono::steady_clock::now() < deadline)
    {
      const auto events = ::ua::test_helpers::collect_events(*mSession,
        mSubscriptionId,
        {.minCount = 1,
          .timeout = std::chrono::milliseconds{500},
          .pollInterval = std::chrono::milliseconds{50}});
      for (const auto& event : events)
      {
        if (event.event_fields().size() <= sBranchIdIndex)
        {
          continue;
        }
        const NodeId branchId = event.event_fields()[sBranchIdIndex].as<NodeId>();
        if (branchId.is_null())
        {
          continue;  // trunk event
        }
        const auto retain = event.event_fields()[sRetainIndex].as<bool>();
        if (!retain)
        {
          retracted.push_back(branchId);
        }
      }
    }
    return retracted;
  }

  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mNamespaceIndex{0};
  NodeId mSourceId;
  std::shared_ptr<ua::ConditionInstance> mAlarm;
  uint32_t mSubscriptionId{0};
};

/// The roomy control. Identical drive, identical assertions available - only the configured cap differs, so
/// an eviction seen here would mean something other than the cap produced it.
class SeededBranchingAlarmRoomyCapTest : public SeededBranchingAlarmTest
{
protected:
  uint32_t branch_cap() const override
  {
    return 100;
  }
};

TEST_F(SeededBranchingAlarmTest, ConfiguredBranchCapRetractsTheOldestBranchOverTheWire)
{
  drive_unacknowledged_toggles(5);

  const auto retracted = collect_retracted_branch_ids();
  EXPECT_FALSE(retracted.empty())
    << "with a cap of " << branch_cap()
    << " and five unacknowledged toggles the oldest branch must be retracted with Retain=False";
}

TEST_F(SeededBranchingAlarmRoomyCapTest, NoBranchIsRetractedWhileTheCapIsRoomy)
{
  drive_unacknowledged_toggles(5);

  const auto retracted = collect_retracted_branch_ids();
  EXPECT_TRUE(retracted.empty())
    << "five toggles are far below a cap of " << branch_cap()
    << ", so a retraction here would mean something other than the cap evicted the branch";
}

// ===========================================================================
// Well-known type-level MethodIds addressed by ConditionId
// ===========================================================================

// OPC 10000-9 5.5.5: "all Servers shall allow Clients to call the Enable Method by specifying
// ConditionId as the ObjectId ... the MethodId ... shall be the NodeId of the Enable Method on the
// ConditionType." A plausible implementation only wires the per-instance Enable node it materialised
// during instantiation, so the type-level i=9027 pairing - the only one a Client is guaranteed to be
// able to encode when the Server does not expose Condition instances - is never routed.
// @verifies AC-SVR-AC-006-ENABLE-CONDITIONID
// @relation(AC-SVR-METH-CALL-013-TYPE-DECLARED-METHOD, scope=function)
TEST_F(ComplianceConditionTest, Enable_AcceptsTheConditionIdAsObjectIdWithTheTypeLevelMethodId)
{
  ASSERT_FALSE(mCondition->snapshot()->enabled()) << "the condition must start disabled for Enable to bite";

  auto req = make_condition_call(mConditionId, NodeId{MethodId::ConditionType_Enable});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Call failed: " << result.status_code().as_uint32();
  ASSERT_FALSE(result.value().results().empty());

  const auto status = result.value().results()[0].status_code();
  EXPECT_TRUE(status.is_good()) << "Enable(ConditionId, ConditionType.Enable) refused: "
                                << status.as_uint32();
  EXPECT_TRUE(mCondition->snapshot()->enabled())
    << "the call was accepted but the Condition did not become enabled";
}

// OPC 10000-9 5.7.4: "Servers shall allow Clients to call the Confirm Method by specifying ConditionId
// as the ObjectId." As with Enable, an implementation that only binds the instance's own Confirm node
// leaves the well-known AcknowledgeableConditionType.Confirm (i=9113) pairing unrouted, which is the
// form a Client must use when the Condition instance is not exposed in the AddressSpace.
// @verifies AC-SVR-AC-031-CONFIRM-CONDITIONID
TEST_F(ComplianceConditionTest, Confirm_AcceptsTheConditionIdAsObjectIdWithTheTypeLevelMethodId)
{
  // Drive the alarm to the only state in which a Confirm is legitimately outstanding: active and
  // acknowledged. Acknowledging server-side keeps the EventId coordination out of the assertion.
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  auto ackEventId = get_event_id(mAlarm);
  ASSERT_FALSE(ackEventId.empty());
  mAlarm->acknowledge_sync(ackEventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(mAlarm->snapshot()->acked());
  ASSERT_FALSE(mAlarm->snapshot()->confirmed()) << "a Confirm must still be outstanding";

  auto confirmEventId = get_event_id(mAlarm);
  ASSERT_FALSE(confirmEventId.empty());

  auto req = make_condition_call(mAlarmId,
    NodeId{MethodId::AcknowledgeableConditionType_Confirm},
    Array<Variant>{Variant{confirmEventId}, Variant{LocalizedText{"", "Confirm by ConditionId"}}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Call failed: " << result.status_code().as_uint32();
  ASSERT_FALSE(result.value().results().empty());

  const auto status = result.value().results()[0].status_code();
  EXPECT_TRUE(status.is_good()) << "Confirm(ConditionId, AcknowledgeableConditionType.Confirm) refused: "
                                << status.as_uint32();
  EXPECT_TRUE(mAlarm->snapshot()->confirmed())
    << "the call was accepted but ConfirmedState did not transition";
}

// OPC 10000-9 5.5.6 Table: AddComment surfaces Bad_MethodInvalid when "the MethodId provided does not
// correspond to the ObjectId provided", and Bad_EventIdUnknown when the EventId identifies no known
// Event. Both are easy to collapse into one generic Bad_* - but Bad_EventIdUnknown is the code a
// Client meets in normal operation (a newer branch superseded the Event between read and comment) and
// it must be distinguishable from a malformed call.
// @verifies AC-SVR-AC-015-ADDCOMMENT-CODES
TEST_F(ComplianceConditionTest, AddComment_RefusesAForeignMethodIdAndAnUnknownEventIdWithTheirOwnCodes)
{
  mCondition->enable_sync();
  mAlarm->enable_sync();

  // (a) A real AddComment Method node that belongs to a DIFFERENT Condition is not a valid pairing
  //     with this ObjectId.
  auto foreignMethodId = find_method_via_browse(mAlarmId, "AddComment");
  ASSERT_FALSE(foreignMethodId.is_null()) << "the alarm should expose its own AddComment Method";
  auto ownMethodId = find_method_via_browse(mConditionId, "AddComment");
  ASSERT_FALSE(ownMethodId.is_null()) << "the condition should expose its own AddComment Method";
  ASSERT_FALSE(foreignMethodId == ownMethodId)
    << "the two Conditions must expose distinct AddComment nodes for this to be a foreign methodId";

  auto eventId = get_event_id(mCondition);
  ASSERT_FALSE(eventId.empty());

  auto foreignReq = make_condition_call(mConditionId,
    foreignMethodId,
    Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "wrong method for this object"}}});
  auto foreignResult = mSession->methods().try_call_sync(std::move(foreignReq));
  ASSERT_TRUE(foreignResult.is_good()) << "Call failed: " << foreignResult.status_code().as_uint32();
  ASSERT_FALSE(foreignResult.value().results().empty());
  EXPECT_EQ(foreignResult.value().results()[0].status_code(), StatusCode{Status::BadMethodInvalid})
    << "AddComment with a methodId belonging to another Condition should be Bad_MethodInvalid, got: "
    << foreignResult.value().results()[0].status_code().as_uint32();

  // (b) The correct pairing, but an EventId this Condition never emitted.
  ByteString unknownEventId{std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04}};
  auto unknownStatus = call_condition_method(mConditionId,
    "AddComment",
    Array<Variant>{Variant{unknownEventId}, Variant{LocalizedText{"", "comment on a stale event"}}});
  EXPECT_EQ(unknownStatus, StatusCode{Status::BadEventIdUnknown})
    << "AddComment with an unknown EventId should be Bad_EventIdUnknown, got: " << unknownStatus.as_uint32();
}

// ===========================================================================
// Comment / Acknowledge event content, and the ConditionRefresh ObjectId rule
// ===========================================================================

/// The shared condition filter plus the Comment ConditionVariable, which is the field the comment
/// obligations are about. Appended last, so Comment is select-clause index 11.
static EventFilter make_condition_filter_with_comment(const NodeId& ofType)
{
  EventFilter filter = make_of_type_filter(ofType);
  filter.select_clauses().push_back(make_select_clause("Comment", NodeId{ObjectTypeId::ConditionType}));
  return filter;
}

/// The shared condition filter plus AckedState/Id (the Boolean the spec names, not the
/// TwoStateVariable's display text) and Comment: indices 11 and 12.
static EventFilter make_alarm_filter_with_acked_id_and_comment()
{
  EventFilter filter = make_of_type_filter(NodeId{ObjectTypeId::AlarmConditionType});

  SimpleAttributeOperand ackedId;
  ackedId.type_definition_id() = NodeId{ObjectTypeId::AcknowledgeableConditionType};
  ackedId.browse_path().push_back(QualifiedName{0, "AckedState"});
  ackedId.browse_path().push_back(QualifiedName{0, "Id"});
  ackedId.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(ackedId));

  filter.select_clauses().push_back(make_select_clause("Comment", NodeId{ObjectTypeId::ConditionType}));
  return filter;
}

// OPC 10000-9 5.5.2 (Comment field): "Any change in this field, shall trigger a new event to be
// generated." An implementation that stores the comment on the Condition and relies on the AuditCondition
// Comment Event to advertise it satisfies the audit clause and still leaves every other Client watching
// the Condition unaware that a comment was added - the Condition Event is the only carrier of the
// updated Comment.
// @verifies AC-SVR-AC-016-COMMENT-TRIGGERS-EVENT
TEST_F(ComplianceConditionSubscriptionTest, AddComment_CommentChangeRaisesANewConditionEventCarryingIt)
{
  mCondition->enable_sync();
  auto eventId = get_event_id(mCondition);
  ASSERT_FALSE(eventId.empty());

  // OfType(ConditionType) admits Condition Events only - the AuditConditionCommentEventType raised by
  // the same call is not a ConditionType subtype, so it cannot stand in for the Event required here.
  create_event_monitored_item(make_condition_filter_with_comment(NodeId{ObjectTypeId::ConditionType}));

  const String commentText{"operator handover note"};
  auto status = call_condition_method(
    mConditionId, "AddComment", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", commentText}}});
  ASSERT_TRUE(status.is_good()) << "AddComment failed: " << status.as_uint32();

  constexpr size_t commentIndex = 11;
  std::vector<EventFieldList> events;
  bool sawComment = false;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!sawComment && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        if (e.event_fields().size() > commentIndex)
        {
          const auto* comment = e.event_fields()[commentIndex].try_as<LocalizedText>();
          if (comment && comment->text() == commentText)
            sawComment = true;
        }
        events.push_back(std::move(e));
      }
    }
  }

  ASSERT_FALSE(events.empty()) << "no Condition Event was delivered at all after AddComment";
  EXPECT_TRUE(sawComment) << "no Condition Event carried the updated Comment (collected " << events.size()
                          << " events)";
}

// OPC 10000-9 5.7.3: "A valid EventId will result in an Event Notification where AckedState/Id is set
// to True and the Comment Property contains the text of the optional comment argument." The Event is
// the acknowledgement's only broadcast, so dropping the comment argument from the emitted Event - while
// still flipping AckedState - loses who said what to every other operator watching the alarm.
// @verifies AC-SVR-AC-027-ACKNOWLEDGE-SETS-ACKED
TEST_F(ComplianceConditionSubscriptionTest, Acknowledge_EventCarriesAckedStateIdTrueAndTheSuppliedComment)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  ASSERT_FALSE(mAlarm->snapshot()->acked());

  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  create_event_monitored_item(make_alarm_filter_with_acked_id_and_comment());

  const String commentText{"acknowledged by operator 7"};
  auto status = call_condition_method(
    mAlarmId, "Acknowledge", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", commentText}}});
  ASSERT_TRUE(status.is_good()) << "Acknowledge failed: " << status.as_uint32();

  constexpr size_t ackedIdIndex = 11;
  constexpr size_t commentIndex = 12;

  std::vector<EventFieldList> events;
  std::optional<size_t> ackedEventIdx;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!ackedEventIdx && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool* ackedId =
          e.event_fields().size() > ackedIdIndex ? e.event_fields()[ackedIdIndex].try_as<bool>() : nullptr;
        const bool acked = ackedId != nullptr && *ackedId;
        events.push_back(std::move(e));
        if (acked && !ackedEventIdx)
          ackedEventIdx = events.size() - 1;
      }
    }
  }

  ASSERT_FALSE(events.empty()) << "no Event was delivered at all after Acknowledge";
  ASSERT_TRUE(ackedEventIdx.has_value())
    << "no Event carried AckedState/Id = True (collected " << events.size() << " events)";

  const auto& ackedEvent = events[*ackedEventIdx];
  ASSERT_GT(ackedEvent.event_fields().size(), commentIndex);
  const auto* comment = ackedEvent.event_fields()[commentIndex].try_as<LocalizedText>();
  ASSERT_NE(comment, nullptr) << "the acknowledging Event carries no Comment value";
  EXPECT_EQ(comment->text(), commentText)
    << "the acknowledging Event's Comment does not hold the supplied text";
}

// OPC 10000-9 5.5.7: ConditionRefresh "is only available on the ConditionType ... the ObjectId shall be
// the well-known NodeId of the ConditionType ObjectType." Refresh is Subscription-wide, so a Server that
// simply ignores the ObjectId (the method's own handler needs only the SubscriptionId) accepts an
// instance id too - and tells the Client, wrongly, that it refreshed that one Condition.
// @verifies AC-SVR-AC-018-CONDITIONREFRESH-WELLKNOWN-OBJECTID
// The execution-evidence reader requires the full TEST_F identity on one line.
// clang-format off
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh_AcceptsTheConditionTypeIdAndRefusesAConditionInstanceId)
// clang-format on
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);  // something retained, so an accepted refresh has work to do
  create_event_monitored_item(make_condition_event_filter());

  // 1. The well-known ConditionType ObjectId is accepted.
  auto wellKnownReq = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto wellKnownResult = mSession->methods().try_call_sync(std::move(wellKnownReq));
  ASSERT_TRUE(wellKnownResult.is_good()) << "Call failed: " << wellKnownResult.status_code().as_uint32();
  ASSERT_FALSE(wellKnownResult.value().results().empty());
  EXPECT_TRUE(wellKnownResult.value().results()[0].status_code().is_good())
    << "ConditionRefresh on the ConditionType NodeId was refused: "
    << wellKnownResult.value().results()[0].status_code().as_uint32();

  // Drain to RefreshEnd before the second call. The per-subscription single-flight guard would answer
  // an overlapping call with Bad_RefreshInProgress, which is bad for the wrong reason and would make
  // the refusal below vacuous.
  const NodeId refreshEndType{ObjectTypeId::RefreshEndEventType};
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    bool sawEnd = false;
    size_t collected = 0;
    while (!sawEnd && std::chrono::steady_clock::now() < deadline)
    {
      for (const auto& e : collect_events(10))
      {
        ++collected;
        if (event_type_from(e) == refreshEndType)
          sawEnd = true;
      }
    }
    ASSERT_TRUE(sawEnd) << "the accepted refresh never terminated (collected " << collected << " events)";
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(100));  // let the guard's strand-side erase land

  // 2. A Condition INSTANCE id, with the same well-known MethodId and the same valid SubscriptionId,
  //    is refused: only the ObjectId differs from the accepted call above.
  auto instanceReq = make_condition_call(
    mConditionId, NodeId{MethodId::ConditionType_ConditionRefresh}, Array<Variant>{Variant{mSubscriptionId}});
  auto instanceResult = mSession->methods().try_call_sync(std::move(instanceReq));
  ASSERT_TRUE(instanceResult.is_good()) << "Call failed: " << instanceResult.status_code().as_uint32();
  ASSERT_FALSE(instanceResult.value().results().empty());

  const auto instanceStatus = instanceResult.value().results()[0].status_code();
  EXPECT_TRUE(instanceStatus.is_bad())
    << "ConditionRefresh on a Condition instance NodeId must be refused; got: " << instanceStatus.as_uint32();
  EXPECT_FALSE(instanceStatus == StatusCode{Status::BadRefreshInProgress})
    << "refused only because a refresh was still running - the ObjectId rule was not exercised";
}

// ===========================================================================
// Confirm: state transition, refusal codes, audit fan-out
// ===========================================================================

/// The shared alarm filter plus ConfirmedState/Id (the Boolean the spec names, not the
/// TwoStateVariable's display text) and Comment: indices 11 and 12.
static EventFilter make_alarm_filter_with_confirmed_id_and_comment()
{
  EventFilter filter = make_of_type_filter(NodeId{ObjectTypeId::AlarmConditionType});

  SimpleAttributeOperand confirmedId;
  confirmedId.type_definition_id() = NodeId{ObjectTypeId::AcknowledgeableConditionType};
  confirmedId.browse_path().push_back(QualifiedName{0, "ConfirmedState"});
  confirmedId.browse_path().push_back(QualifiedName{0, "Id"});
  confirmedId.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(confirmedId));

  filter.select_clauses().push_back(make_select_clause("Comment", NodeId{ObjectTypeId::ConditionType}));
  return filter;
}

/// An OfType(auditType) filter plus that audit type's own ConditionEventId Property, at index 11.
static EventFilter make_audit_filter_with_condition_event_id(const NodeId& auditType)
{
  EventFilter filter = make_of_type_filter(auditType);
  filter.select_clauses().push_back(make_select_clause("ConditionEventId", auditType));
  return filter;
}

// OPC 10000-9 5.7.4: a Confirm with a valid EventId results in an Event Notification where
// ConfirmedState/Id is True and the Comment Property holds the text of the comment argument. A plausible
// implementation flips ConfirmedState on the stored Condition and announces it only through the
// AuditConditionConfirmEventType - leaving every other operator subscribed to the alarm itself with a
// stale ConfirmedState and no record of what was said when responsibility was discharged.
// @verifies AC-SVR-AC-032-CONFIRM-SETS-CONFIRMED
TEST_F(ComplianceConditionSubscriptionTest, Confirm_EventCarriesConfirmedStateIdTrueAndTheSuppliedComment)
{
  // Drive the alarm to the state in which a Confirm is legitimately outstanding: active and acknowledged.
  // Acknowledging server-side keeps the EventId coordination out of the assertion.
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  auto ackEventId = get_event_id(mAlarm);
  ASSERT_FALSE(ackEventId.empty());
  mAlarm->acknowledge_sync(ackEventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(mAlarm->snapshot()->acked());
  ASSERT_FALSE(mAlarm->snapshot()->confirmed()) << "a Confirm must still be outstanding";

  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  create_event_monitored_item(make_alarm_filter_with_confirmed_id_and_comment());

  const String commentText{"confirmed by operator 3"};
  auto status = call_condition_method(
    mAlarmId, "Confirm", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", commentText}}});
  ASSERT_TRUE(status.is_good()) << "Confirm failed: " << status.as_uint32();

  constexpr size_t confirmedIdIndex = 11;
  constexpr size_t commentIndex = 12;

  std::vector<EventFieldList> events;
  std::optional<size_t> confirmedEventIdx;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!confirmedEventIdx && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool* confirmedId = e.event_fields().size() > confirmedIdIndex
                                    ? e.event_fields()[confirmedIdIndex].try_as<bool>()
                                    : nullptr;
        const bool confirmed = confirmedId != nullptr && *confirmedId;
        events.push_back(std::move(e));
        if (confirmed && !confirmedEventIdx)
          confirmedEventIdx = events.size() - 1;
      }
    }
  }

  ASSERT_FALSE(events.empty()) << "no Event was delivered at all after Confirm";
  ASSERT_TRUE(confirmedEventIdx.has_value())
    << "no Event carried ConfirmedState/Id = True (collected " << events.size() << " events)";

  const auto& confirmedEvent = events[*confirmedEventIdx];
  ASSERT_GT(confirmedEvent.event_fields().size(), commentIndex);
  const auto* comment = confirmedEvent.event_fields()[commentIndex].try_as<LocalizedText>();
  ASSERT_NE(comment, nullptr) << "the confirming Event carries no Comment value";
  EXPECT_EQ(comment->text(), commentText) << "the confirming Event's Comment does not hold the supplied text";
}

// OPC 10000-9 5.7.4 Table: Confirm answers Bad_ConditionBranchAlreadyConfirmed when the branch the
// EventId names is already confirmed, and Bad_MethodInvalid when the MethodId does not correspond to the
// ObjectId. Collapsing the pair into one generic Bad_* costs a Client the ability to tell a benign race
// (another operator confirmed first - nothing to retry) from a malformed call it must fix.
// @verifies AC-SVR-AC-033-CONFIRM-CODES
TEST_F(ComplianceConditionTest, Confirm_RefusesAnAlreadyConfirmedBranchAndAForeignMethodIdWithTheirOwnCodes)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  auto ackEventId = get_event_id(mAlarm);
  ASSERT_FALSE(ackEventId.empty());
  mAlarm->acknowledge_sync(ackEventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(mAlarm->snapshot()->acked());

  // (a) Confirm once through the real path, then confirm the state that Confirm produced. The alarm is
  //     still active, so the confirmed state stays retained and its EventId remains addressable.
  auto firstEventId = get_event_id(mAlarm);
  ASSERT_FALSE(firstEventId.empty());
  auto firstStatus = call_condition_method(
    mAlarmId, "Confirm", Array<Variant>{Variant{firstEventId}, Variant{LocalizedText{"", "Confirm"}}});
  ASSERT_TRUE(firstStatus.is_good()) << "the first Confirm must succeed for the second to be a REPEAT "
                                        "confirm rather than an unknown EventId; got: "
                                     << firstStatus.as_uint32();
  ASSERT_TRUE(mAlarm->snapshot()->confirmed());

  auto confirmedEventId = get_event_id(mAlarm);
  ASSERT_FALSE(confirmedEventId.empty());
  auto secondStatus = call_condition_method(mAlarmId,
    "Confirm",
    Array<Variant>{Variant{confirmedEventId}, Variant{LocalizedText{"", "Confirm again"}}});
  EXPECT_EQ(secondStatus, StatusCode{Status::BadConditionBranchAlreadyConfirmed})
    << "a second Confirm of an already-confirmed branch should be Bad_ConditionBranchAlreadyConfirmed, "
       "got: "
    << secondStatus.as_uint32();

  // (b) A real Confirm Method node that belongs to a DIFFERENT Condition is not a valid pairing with
  //     this ObjectId.
  auto foreignMethodId = find_method_via_browse(mAckConditionId, "Confirm");
  ASSERT_FALSE(foreignMethodId.is_null()) << "the ack condition should expose its own Confirm Method";
  auto ownMethodId = find_method_via_browse(mAlarmId, "Confirm");
  ASSERT_FALSE(ownMethodId.is_null()) << "the alarm should expose its own Confirm Method";
  ASSERT_FALSE(foreignMethodId == ownMethodId)
    << "the two Conditions must expose distinct Confirm nodes for this to be a foreign methodId";

  auto foreignReq = make_condition_call(mAlarmId,
    foreignMethodId,
    Array<Variant>{Variant{confirmedEventId}, Variant{LocalizedText{"", "wrong method for this object"}}});
  auto foreignResult = mSession->methods().try_call_sync(std::move(foreignReq));
  ASSERT_TRUE(foreignResult.is_good()) << "Call failed: " << foreignResult.status_code().as_uint32();
  ASSERT_FALSE(foreignResult.value().results().empty());
  EXPECT_EQ(foreignResult.value().results()[0].status_code(), StatusCode{Status::BadMethodInvalid})
    << "Confirm with a methodId belonging to another Condition should be Bad_MethodInvalid, got: "
    << foreignResult.value().results()[0].status_code().as_uint32();
}

// OPC 10000-9 5.7.4: Confirm generates an AuditConditionConfirmEventType, and Part 5 auditing delivers
// an Event to every Client whose Subscription selected it. Confirmation is an operator's assertion that
// they have dealt with the alarm, so an emit path that stops at the first interested monitored item
// leaves a second auditor's record silently incomplete - invisible until the audit trail is queried.
// @verifies AC-SVR-AC-034-CONFIRM-AUDIT
TEST_F(ComplianceConditionSubscriptionTest, Confirm_RaisesAnAuditEventForEveryInterestedSubscriber)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  auto ackEventId = get_event_id(mAlarm);
  ASSERT_FALSE(ackEventId.empty());
  mAlarm->acknowledge_sync(ackEventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(mAlarm->snapshot()->acked());

  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  // Two independently registered subscribers, each interested in exactly this audit type.
  constexpr uint32_t firstHandle = 4001;
  constexpr uint32_t secondHandle = 4002;
  const NodeId auditType{ObjectTypeId::AuditConditionConfirmEventType};
  (void)::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_of_type_filter(auditType),
    {.clientHandle = firstHandle, .samplingInterval = 0.0, .queueSize = 50});
  (void)::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_of_type_filter(auditType),
    {.clientHandle = secondHandle, .samplingInterval = 0.0, .queueSize = 50});

  auto status = call_condition_method(
    mAlarmId, "Confirm", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Confirmed"}}});
  ASSERT_TRUE(status.is_good()) << "Confirm failed: " << status.as_uint32();

  std::vector<EventFieldList> events;
  bool sawFirst = false;
  bool sawSecond = false;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!(sawFirst && sawSecond) && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool isConfirmAudit = (event_type_from(e) == auditType);
        const uint32_t handle = e.client_handle();
        if (isConfirmAudit && handle == firstHandle)
          sawFirst = true;
        if (isConfirmAudit && handle == secondHandle)
          sawSecond = true;
        events.push_back(std::move(e));
      }
    }
  }

  ASSERT_FALSE(events.empty()) << "no Event was delivered at all after Confirm";
  EXPECT_TRUE(sawFirst) << "the first subscriber received no AuditConditionConfirmEventType (collected "
                        << events.size() << " events)";
  EXPECT_TRUE(sawSecond) << "the second subscriber received no AuditConditionConfirmEventType (collected "
                         << events.size() << " events)";
}

// OPC 10000-9 5.5.2: the Condition Methods are invoked on a Condition instance; a Method declaration on
// an ObjectType is not executable. AC-SVR-AC-018-CONDITIONREFRESH-WELLKNOWN-OBJECTID requires the exact
// opposite for ConditionRefresh, so a Server that applies one rule to all Condition Methods necessarily
// gets one of the two wrong - and here the declaring type Node does source the Method, so a Server that
// checks only the Part 4 object/method pairing lets an unexecutable call through.
// @verifies AC-SVR-AC-035-NON-CONDITION-OBJECT
TEST_F(ComplianceConditionTest, Acknowledge_IsRefusedOnANonConditionObjectAndOnTheConditionTypeNode)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  ASSERT_FALSE(mAlarm->snapshot()->acked());

  // A genuinely acknowledgeable EventId: with a bogus one the refusals below would prove nothing about
  // the ObjectId, only about the EventId.
  auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());

  // (a) A plain Object that is not a Condition, with the well-known Acknowledge MethodId.
  auto folderReq = make_condition_call(NodeId{ObjectId::ObjectsFolder},
    NodeId{MethodId::AcknowledgeableConditionType_Acknowledge},
    Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack a folder"}}});
  auto folderResult = mSession->methods().try_call_sync(std::move(folderReq));
  ASSERT_TRUE(folderResult.is_good()) << "Call failed: " << folderResult.status_code().as_uint32();
  ASSERT_FALSE(folderResult.value().results().empty());
  EXPECT_TRUE(folderResult.value().results()[0].status_code().is_bad())
    << "Acknowledge on an Object that is not a Condition must be refused; got: "
    << folderResult.value().results()[0].status_code().as_uint32();

  // (b) The type Node that DECLARES Acknowledge, with the same well-known MethodId: only the ObjectId
  //     differs from a call that would be accepted on the instance.
  auto typeReq = make_condition_call(NodeId{ObjectTypeId::AcknowledgeableConditionType},
    NodeId{MethodId::AcknowledgeableConditionType_Acknowledge},
    Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "Ack the type"}}});
  auto typeResult = mSession->methods().try_call_sync(std::move(typeReq));
  ASSERT_TRUE(typeResult.is_good()) << "Call failed: " << typeResult.status_code().as_uint32();
  ASSERT_FALSE(typeResult.value().results().empty());
  EXPECT_TRUE(typeResult.value().results()[0].status_code().is_bad())
    << "Acknowledge on the AcknowledgeableConditionType Node must be refused; got: "
    << typeResult.value().results()[0].status_code().as_uint32();

  // Neither refusal may have quietly acknowledged the Condition the EventId belongs to.
  EXPECT_FALSE(mAlarm->snapshot()->acked())
    << "a refused Condition Method must not have changed the Condition's state";
}

// ===========================================================================
// Audit Events name the Event they are about (ConditionEventId)
// ===========================================================================

// OPC 10000-9 5.10: AuditConditionCommentEventType/ConditionEventId is the EventId the AddComment Method
// received. A Server that leaves it null, or fills it with the audit Event's OWN EventId, still emits an
// audit record and still passes a "did an audit Event appear" check - but the trail then records that
// someone commented and not on what, and the EventId is the only handle
// (AC-SVR-AC-021-REFRESH-ORIGINAL-EVENTID makes it stable across refreshes).
// @verifies AC-SVR-AC-066-COMMENT-EVENTID
TEST_F(ComplianceConditionSubscriptionTest, AddComment_AuditEventNamesTheEventTheCommentWasAddedTo)
{
  mCondition->enable_sync();
  const auto commentedEventId = get_event_id(mCondition);
  ASSERT_FALSE(commentedEventId.empty());

  const NodeId auditType{ObjectTypeId::AuditConditionCommentEventType};
  create_event_monitored_item(make_audit_filter_with_condition_event_id(auditType));

  auto status = call_condition_method(mConditionId,
    "AddComment",
    Array<Variant>{Variant{commentedEventId}, Variant{LocalizedText{"", "audit trail note"}}});
  ASSERT_TRUE(status.is_good()) << "AddComment failed: " << status.as_uint32();

  constexpr size_t conditionEventIdIndex = 11;
  std::vector<EventFieldList> events;
  std::optional<size_t> auditIdx;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!auditIdx && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool isAudit = (event_type_from(e) == auditType);
        events.push_back(std::move(e));
        if (isAudit && !auditIdx)
          auditIdx = events.size() - 1;
      }
    }
  }

  ASSERT_FALSE(events.empty()) << "no Event was delivered at all after AddComment";
  ASSERT_TRUE(auditIdx.has_value()) << "no AuditConditionCommentEventType Event was delivered (collected "
                                    << events.size() << " events)";

  const auto& audit = events[*auditIdx];
  ASSERT_GT(audit.event_fields().size(), conditionEventIdIndex);
  const auto* conditionEventId = audit.event_fields()[conditionEventIdIndex].try_as<ByteString>();
  ASSERT_NE(conditionEventId, nullptr) << "the comment audit Event carries no ConditionEventId value";
  EXPECT_FALSE(conditionEventId->empty()) << "the comment audit Event's ConditionEventId is empty";
  EXPECT_TRUE(*conditionEventId == commentedEventId)
    << "ConditionEventId is not the EventId of the Event the comment was added to";
}

// OPC 10000-9 5.10: the same rule for AuditConditionAcknowledgeEventType, and the more consequential of
// the two - this field is the audit trail's record of who accepted responsibility for WHICH alarm. A
// Server that populates the audit Event's own EventId here produces a trail that cannot be joined back
// to the alarm it is about.
// @verifies AC-SVR-AC-067-ACKNOWLEDGE-EVENTID
TEST_F(ComplianceConditionSubscriptionTest, Acknowledge_AuditEventNamesTheEventThatWasAcknowledged)
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  ASSERT_FALSE(mAlarm->snapshot()->acked());

  const auto acknowledgedEventId = get_event_id(mAlarm);
  ASSERT_FALSE(acknowledgedEventId.empty());

  const NodeId auditType{ObjectTypeId::AuditConditionAcknowledgeEventType};
  create_event_monitored_item(make_audit_filter_with_condition_event_id(auditType));

  auto status = call_condition_method(mAlarmId,
    "Acknowledge",
    Array<Variant>{Variant{acknowledgedEventId}, Variant{LocalizedText{"", "acknowledged by operator 7"}}});
  ASSERT_TRUE(status.is_good()) << "Acknowledge failed: " << status.as_uint32();

  constexpr size_t conditionEventIdIndex = 11;
  std::vector<EventFieldList> events;
  std::optional<size_t> auditIdx;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!auditIdx && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool isAudit = (event_type_from(e) == auditType);
        events.push_back(std::move(e));
        if (isAudit && !auditIdx)
          auditIdx = events.size() - 1;
      }
    }
  }

  ASSERT_FALSE(events.empty()) << "no Event was delivered at all after Acknowledge";
  ASSERT_TRUE(auditIdx.has_value()) << "no AuditConditionAcknowledgeEventType Event was delivered (collected "
                                    << events.size() << " events)";

  const auto& audit = events[*auditIdx];
  ASSERT_GT(audit.event_fields().size(), conditionEventIdIndex);
  const auto* conditionEventId = audit.event_fields()[conditionEventIdIndex].try_as<ByteString>();
  ASSERT_NE(conditionEventId, nullptr) << "the acknowledge audit Event carries no ConditionEventId value";
  EXPECT_FALSE(conditionEventId->empty()) << "the acknowledge audit Event's ConditionEventId is empty";
  EXPECT_TRUE(*conditionEventId == acknowledgedEventId)
    << "ConditionEventId is not the EventId that was acknowledged";
}

// OPC 10000-9 5.10: AuditConditionConfirmEventType/ConditionEventId is the EventId the Confirm Method
// received - the third of the identifying-field trio with the comment and acknowledge audit Events. A
// Confirm arrives one step after an Acknowledge on the same Condition, and each step allocates a fresh
// EventId, so a Server that fills this field from the Condition's CURRENT event, or from the audit
// Event's own EventId, still emits a well-formed audit record while pointing the trail at the wrong
// Event - the one thing that distinguishes "confirmed the alarm they acknowledged" from "confirmed
// something else".
// @verifies AC-SVR-AC-068-CONFIRM-EVENTID
TEST_F(ComplianceConditionSubscriptionTest, Confirm_AuditEventNamesTheEventThatWasConfirmed)
{
  // Drive the alarm to the only state in which a Confirm is legitimately outstanding: active and
  // acknowledged. Acknowledging server-side keeps the EventId coordination out of the assertion.
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  const auto ackEventId = get_event_id(mAlarm);
  ASSERT_FALSE(ackEventId.empty());
  mAlarm->acknowledge_sync(ackEventId, LocalizedText{"", "Ack"});
  ASSERT_TRUE(mAlarm->snapshot()->acked());
  ASSERT_FALSE(mAlarm->snapshot()->confirmed()) << "a Confirm must still be outstanding";

  // The acknowledgement allocated a new EventId; this - not ackEventId - is what Confirm is given, so a
  // Server that echoes the wrong one is caught rather than accidentally right.
  const auto confirmedEventId = get_event_id(mAlarm);
  ASSERT_FALSE(confirmedEventId.empty());
  ASSERT_FALSE(confirmedEventId == ackEventId)
    << "the acknowledgement must have allocated a distinct EventId for this test to discriminate";

  const NodeId auditType{ObjectTypeId::AuditConditionConfirmEventType};
  create_event_monitored_item(make_audit_filter_with_condition_event_id(auditType));

  auto status = call_condition_method(mAlarmId,
    "Confirm",
    Array<Variant>{Variant{confirmedEventId}, Variant{LocalizedText{"", "confirmed by operator 3"}}});
  ASSERT_TRUE(status.is_good()) << "Confirm failed: " << status.as_uint32();

  constexpr size_t conditionEventIdIndex = 11;
  std::vector<EventFieldList> events;
  std::optional<size_t> auditIdx;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!auditIdx && std::chrono::steady_clock::now() < deadline)
    {
      for (auto& e : collect_events(10))
      {
        const bool isAudit = (event_type_from(e) == auditType);
        events.push_back(std::move(e));
        if (isAudit && !auditIdx)
          auditIdx = events.size() - 1;
      }
    }
  }

  ASSERT_FALSE(events.empty()) << "no Event was delivered at all after Confirm";
  ASSERT_TRUE(auditIdx.has_value()) << "no AuditConditionConfirmEventType Event was delivered (collected "
                                    << events.size() << " events)";

  const auto& audit = events[*auditIdx];
  ASSERT_GT(audit.event_fields().size(), conditionEventIdIndex);
  const auto* conditionEventId = audit.event_fields()[conditionEventIdIndex].try_as<ByteString>();
  ASSERT_NE(conditionEventId, nullptr) << "the confirm audit Event carries no ConditionEventId value";
  EXPECT_FALSE(conditionEventId->empty()) << "the confirm audit Event's ConditionEventId is empty";
  EXPECT_TRUE(*conditionEventId == confirmedEventId)
    << "ConditionEventId is not the EventId that was confirmed";
}

// ===========================================================================
// Silencing is a property of the Alarm, not of the silencing Session
// ===========================================================================

/// The shared alarm filter plus SilenceState/Id - the Boolean the silencing obligation is about, not the
/// TwoStateVariable's display text. Appended last, so SilenceState/Id is select-clause index 11.
static EventFilter make_alarm_filter_with_silence_id()
{
  EventFilter filter = make_of_type_filter(NodeId{ObjectTypeId::AlarmConditionType});

  SimpleAttributeOperand silenceId;
  silenceId.type_definition_id() = NodeId{ObjectTypeId::AlarmConditionType};
  silenceId.browse_path().push_back(QualifiedName{0, "SilenceState"});
  silenceId.browse_path().push_back(QualifiedName{0, "Id"});
  silenceId.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  filter.select_clauses().push_back(std::move(silenceId));
  return filter;
}

// OPC 10000-9 5.8: "Silencing an Alarm shall silence the Alarm on all systems (screens) that it is being
// reported on." Per-Session silencing is the intuitive scope and it is wrong - an operator silencing an
// audible alarm expects the plant to go quiet, not their own screen. A Server that records the silence
// against the calling Session (or only replays it into that Session's Subscriptions) looks correct to
// the operator who pressed the button and leaves every other console still sounding.
// @verifies AC-SVR-AC-103-SILENCE-IS-GLOBAL
TEST_F(ComplianceConditionSubscriptionTest, Silence_IsSeenByASessionOtherThanTheOneThatSilenced)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);  // activation clears SilenceState, so the Silence below is the transition
  ASSERT_FALSE(mFullAlarm->snapshot()->silenced().value_or(true))
    << "the alarm must start un-silenced for the Silence below to be the observed transition";

  constexpr size_t silenceIdIndex = 11;

  // Subscriber A: this fixture's Session - the one that will call Silence.
  create_event_monitored_item(make_alarm_filter_with_silence_id());

  boost::asio::thread_pool clientPool2;
  {
    // A second client/channel/session to the same Server. As in the cross-session refresh test, this
    // rides a None channel, which the client refuses unless the application opts in.
    auto client2 = CoreClient::create(clientPool2.get_executor(),
      ua::client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{.crypto = ua::test_helpers::test_crypto()});
    auto channel2 = client2.open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session2 = channel2.create_session_sync({.sessionName = "SilenceObserver"});
    session2.activate_sync();

    // Subscriber B: an independent Session that only watches - it never calls Silence, so anything it
    // sees is the Alarm's own state and not an echo of its own request.
    const uint32_t observerSubscriptionId =
      create_subscription(session2, {.publishingInterval = 50.0, .lifetimeCount = 60});
    (void)::ua::test_helpers::create_event_monitored_item(session2,
      observerSubscriptionId,
      NodeId{ObjectId::Server},
      make_alarm_filter_with_silence_id(),
      {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 50});

    const auto status = call_condition_method(mFullAlarmId, "Silence");
    EXPECT_TRUE(status.is_good()) << "Silence failed: " << status.as_uint32();

    std::vector<EventFieldList> silencerEvents;
    std::vector<EventFieldList> observerEvents;
    bool silencerSaw = false;
    bool observerSaw = false;
    {
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
      while (!(silencerSaw && observerSaw) && std::chrono::steady_clock::now() < deadline)
      {
        for (auto& e : collect_events(10))
        {
          const bool* silenced = e.event_fields().size() > silenceIdIndex
                                   ? e.event_fields()[silenceIdIndex].try_as<bool>()
                                   : nullptr;
          if (silenced != nullptr && *silenced)
            silencerSaw = true;
          silencerEvents.push_back(std::move(e));
        }
        for (auto& e : ::ua::test_helpers::collect_events(session2,
               observerSubscriptionId,
               {.minCount = 1,
                 .timeout = std::chrono::milliseconds{500},
                 .pollInterval = std::chrono::milliseconds{50}}))
        {
          const bool* silenced = e.event_fields().size() > silenceIdIndex
                                   ? e.event_fields()[silenceIdIndex].try_as<bool>()
                                   : nullptr;
          if (silenced != nullptr && *silenced)
            observerSaw = true;
          observerEvents.push_back(std::move(e));
        }
      }
    }

    EXPECT_FALSE(silencerEvents.empty()) << "the silencing Session received no Event at all";
    EXPECT_FALSE(observerEvents.empty()) << "the observing Session received no Event at all";
    EXPECT_TRUE(silencerSaw) << "the silencing Session saw no Event carrying SilenceState/Id = True (of "
                             << silencerEvents.size() << " events)";
    EXPECT_TRUE(observerSaw) << "the Session that did NOT silence saw no Event carrying SilenceState/Id = "
                                "True - the silence was scoped to the calling Session (of "
                             << observerEvents.size() << " events)";

    // And the state lives on the Alarm rather than on either Session's view of it.
    EXPECT_TRUE(mFullAlarm->snapshot()->silenced().value_or(false))
      << "SilenceState did not transition on the Alarm itself";

    delete_subscription(session2, observerSubscriptionId);
    (void)session2.try_close_sync();
    (void)channel2.try_close_sync();
  }  // session2/channel2/client2 destroyed before pool stop so the cert store timer is cancelled.
  clientPool2.join();
}

// ===========================================================================
// Every alarm-management Method accepts the ConditionId as its ObjectId
// ===========================================================================

// OPC 10000-9 section section 5.8.5, 5.8.7, 5.8.8, 5.8.10, 5.8.12 and 5.8.14 each repeat the same sentence
// for Reset, Silence, Suppress, Unsuppress, RemoveFromService and PlaceInService: "Servers shall allow
// Clients to call the <M> Method by specifying ConditionId as the ObjectId." A Server need not expose
// Condition instances in its AddressSpace, so the ConditionId paired with the AlarmConditionType's own Method
// Node is the only encoding a Client is guaranteed to be able to form; an implementation that routes only the
// per-instance Method Nodes it materialised satisfies the browse-then-call form and drops the mandatory
// one. Six separate call sites, so the realistic defect is that some are wired and some are not - which
// is why all six are driven here rather than one per test.
// @verifies AC-SVR-AC-112-CONDITIONID-AS-OBJECTID
TEST_F(ComplianceConditionTest, AlarmManagementMethods_AllSixAcceptTheConditionIdAsObjectId)
{
  auto callByNodeId = [this](const NodeId& objectId, const NodeId& methodId) -> StatusCode
  {
    auto req = make_condition_call(objectId, methodId);
    auto result = mSession->methods().try_call_sync(std::move(req));
    if (result.is_bad())
      return result.status_code();
    if (result.value().results().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.value().results()[0].status_code();
  };

  // --- Arm 1: the ConditionId as ObjectId, paired with the Method Node materialised on the instance.
  // Activation makes Silence meaningful and latches the alarm so Reset has something to clear.
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  EXPECT_TRUE(call_condition_method(mFullAlarmId, "Silence").is_good())
    << "Silence(ConditionId, instance MethodId) refused";
  EXPECT_TRUE(call_condition_method(mFullAlarmId, "Suppress").is_good())
    << "Suppress(ConditionId, instance MethodId) refused";
  EXPECT_TRUE(call_condition_method(mFullAlarmId, "Unsuppress").is_good())
    << "Unsuppress(ConditionId, instance MethodId) refused";
  EXPECT_TRUE(call_condition_method(mFullAlarmId, "RemoveFromService").is_good())
    << "RemoveFromService(ConditionId, instance MethodId) refused";
  EXPECT_TRUE(call_condition_method(mFullAlarmId, "PlaceInService").is_good())
    << "PlaceInService(ConditionId, instance MethodId) refused";

  // Reset clears LatchedState and requires the alarm to be inactive and acknowledged first.
  mFullAlarm->deactivate_sync();
  const auto firstEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(firstEventId.empty());
  mFullAlarm->acknowledge_sync(firstEventId, LocalizedText{"", "ack"});
  EXPECT_TRUE(call_condition_method(mFullAlarmId, "Reset").is_good())
    << "Reset(ConditionId, instance MethodId) refused";

  // --- Arm 2: the same ConditionId as ObjectId, paired with the well-known AlarmConditionType Method
  // Node - the pairing a Client must use when the Condition instance is not in the AddressSpace. Only
  // the MethodId differs from arm 1, so a failure here is about the mandatory encoding and nothing else.
  mFullAlarm->activate_sync(600);  // re-latches and clears the states arm 1 left behind

  const auto silenceStatus = callByNodeId(mFullAlarmId, NodeId{MethodId::AlarmConditionType_Silence});
  EXPECT_TRUE(silenceStatus.is_good())
    << "Silence(ConditionId, AlarmConditionType.Silence) refused: " << silenceStatus.as_uint32();
  const auto suppressStatus = callByNodeId(mFullAlarmId, NodeId{MethodId::AlarmConditionType_Suppress});
  EXPECT_TRUE(suppressStatus.is_good())
    << "Suppress(ConditionId, AlarmConditionType.Suppress) refused: " << suppressStatus.as_uint32();
  const auto unsuppressStatus = callByNodeId(mFullAlarmId, NodeId{MethodId::AlarmConditionType_Unsuppress});
  EXPECT_TRUE(unsuppressStatus.is_good())
    << "Unsuppress(ConditionId, AlarmConditionType.Unsuppress) refused: " << unsuppressStatus.as_uint32();
  const auto removeStatus =
    callByNodeId(mFullAlarmId, NodeId{MethodId::AlarmConditionType_RemoveFromService});
  EXPECT_TRUE(removeStatus.is_good())
    << "RemoveFromService(ConditionId, AlarmConditionType.RemoveFromService) refused: "
    << removeStatus.as_uint32();
  const auto placeStatus = callByNodeId(mFullAlarmId, NodeId{MethodId::AlarmConditionType_PlaceInService});
  EXPECT_TRUE(placeStatus.is_good())
    << "PlaceInService(ConditionId, AlarmConditionType.PlaceInService) refused: " << placeStatus.as_uint32();

  mFullAlarm->deactivate_sync();
  const auto secondEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(secondEventId.empty());
  mFullAlarm->acknowledge_sync(secondEventId, LocalizedText{"", "ack"});
  const auto resetStatus = callByNodeId(mFullAlarmId, NodeId{MethodId::AlarmConditionType_Reset});
  EXPECT_TRUE(resetStatus.is_good()) << "Reset(ConditionId, AlarmConditionType.Reset) refused: "
                                     << resetStatus.as_uint32();
}

// OPC 10000-9 section section 5.8.5, 5.8.7, 5.8.8, 5.8.10, 5.8.12 and 5.8.14 each repeat "Servers shall allow
// Clients to call the <M> Method by specifying ConditionId as the ObjectId". The clause exists because a
// Server need not expose Condition instances in its AddressSpace, so the only pairing a Client is guaranteed
// to be able to form is the ConditionId it read off an Event together with the Method Node declared on
// AlarmConditionType. An implementation that installs its Method handlers only on the per-instance Method
// Nodes it materialised answers the browse-then-call form and leaves the mandatory one unanswered; the
// six handlers are six separate installations, so the realistic shape of that defect is some Methods
// wired and some not, which is why all six are driven. A status code alone cannot separate "accepted"
// from "accepted, then applied to some other Condition", so every call here names one of two Alarms that
// share their ObjectType, their optional feature set and their owning Object - the ConditionId is the
// only thing that tells them apart - and the bystander's state is asserted unmoved beside the named
// Alarm's transition. Preconditions are staged through the in-process ConditionInstance API so that no
// control depends on the Call path under test.
// @relation(AC-SVR-AC-112-CONDITIONID-AS-OBJECTID, scope=function)
TEST_F(ComplianceConditionTest, AlarmManagementMethods_ConditionIdAsObjectIdNamesTheAlarmActedOn)
{
  auto& server = mServer.server();
  auto& conditions = server.conditions();

  // A second Alarm identical to mFullAlarm in every respect the dispatcher could key on except its
  // ConditionId: same ObjectType, same optional features, same parent Object.
  auto targetLogic = std::make_unique<AlarmConditionLogic>();
  targetLogic->set_supports_confirm(true);
  targetLogic->set_supports_suppressed(true);
  targetLogic->set_supports_out_of_service(true);
  targetLogic->set_supports_silence(true);
  targetLogic->set_supports_latched(true);
  auto target = conditions.create_condition_sync(NodeId{0, uint32_t{0}},
    NodeId{ObjectId::ObjectsFolder},
    String{"ConditionIdTargetAlarm"},
    std::move(targetLogic),
    NodeId{ObjectTypeId::AlarmConditionType});
  ASSERT_TRUE(target != nullptr);
  const NodeId targetId = target->condition_id();
  ASSERT_FALSE(targetId.is_null());
  ASSERT_FALSE(targetId == mFullAlarmId)
    << "the two Alarms must be distinct or the ConditionId cannot be shown to select one of them";

  // Every observation below pairs the ConditionId with the AlarmConditionType Method Node - the pairing
  // a Client forms when the Condition instance is not in the AddressSpace.
  auto callWithConditionId = [this](const NodeId& conditionId, MethodId method) -> StatusCode
  {
    auto req = make_condition_call(conditionId, NodeId{method});
    auto result = mSession->methods().try_call_sync(std::move(req));
    if (result.is_bad())
      return result.status_code();
    if (result.value().results().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.value().results()[0].status_code();
  };

  target->enable_sync();
  target->activate_sync(500);
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  // --- Silence, section 5.8.7 -------------------------------------------------------------------------
  ASSERT_FALSE(target->snapshot()->silenced().value_or(true))
    << "the named Alarm must start un-silenced for the transition below to be observable";
  ASSERT_FALSE(mFullAlarm->snapshot()->silenced().value_or(true))
    << "the bystander must start un-silenced for the control below to discriminate";

  const auto silenceStatus = callWithConditionId(targetId, MethodId::AlarmConditionType_Silence);
  EXPECT_TRUE(silenceStatus.is_good())
    << "Silence refused the ConditionId as its ObjectId: " << silenceStatus.as_uint32();
  EXPECT_TRUE(target->snapshot()->silenced().value_or(false))
    << "Silence(ConditionId) did not silence the Alarm the ConditionId names";
  EXPECT_FALSE(mFullAlarm->snapshot()->silenced().value_or(true))
    << "Silence(ConditionId) silenced a different Alarm sharing the same owning Object";

  // --- Suppress, section 5.8.8 ------------------------------------------------------------------------
  ASSERT_FALSE(target->snapshot()->suppressed().value_or(true))
    << "the named Alarm must start unsuppressed for the transition below to be observable";
  ASSERT_FALSE(mFullAlarm->snapshot()->suppressed().value_or(true))
    << "the bystander must start unsuppressed for the control below to discriminate";

  const auto suppressStatus = callWithConditionId(targetId, MethodId::AlarmConditionType_Suppress);
  EXPECT_TRUE(suppressStatus.is_good())
    << "Suppress refused the ConditionId as its ObjectId: " << suppressStatus.as_uint32();
  EXPECT_TRUE(target->snapshot()->suppressed().value_or(false))
    << "Suppress(ConditionId) did not suppress the Alarm the ConditionId names";
  EXPECT_FALSE(mFullAlarm->snapshot()->suppressed().value_or(true))
    << "Suppress(ConditionId) suppressed a different Alarm sharing the same owning Object";

  // --- Unsuppress, section 5.8.10 ---------------------------------------------------------------------
  // Both Alarms suppressed first, so that clearing the right one is not a no-op and clearing the wrong
  // one is visible.
  target->suppress_sync();
  mFullAlarm->suppress_sync();
  ASSERT_TRUE(target->snapshot()->suppressed().value_or(false))
    << "the named Alarm must be suppressed for the Unsuppress below to be observable";
  ASSERT_TRUE(mFullAlarm->snapshot()->suppressed().value_or(false))
    << "the bystander must be suppressed for the control below to discriminate";

  const auto unsuppressStatus = callWithConditionId(targetId, MethodId::AlarmConditionType_Unsuppress);
  EXPECT_TRUE(unsuppressStatus.is_good())
    << "Unsuppress refused the ConditionId as its ObjectId: " << unsuppressStatus.as_uint32();
  EXPECT_FALSE(target->snapshot()->suppressed().value_or(true))
    << "Unsuppress(ConditionId) left the Alarm the ConditionId names suppressed";
  EXPECT_TRUE(mFullAlarm->snapshot()->suppressed().value_or(false))
    << "Unsuppress(ConditionId) unsuppressed a different Alarm sharing the same owning Object";

  // --- RemoveFromService, section 5.8.12 --------------------------------------------------------------
  target->place_in_service_sync();
  mFullAlarm->place_in_service_sync();
  ASSERT_FALSE(target->snapshot()->out_of_service().value_or(true))
    << "the named Alarm must be in service for the RemoveFromService below to be observable";
  ASSERT_FALSE(mFullAlarm->snapshot()->out_of_service().value_or(true))
    << "the bystander must be in service for the control below to discriminate";

  const auto removeStatus = callWithConditionId(targetId, MethodId::AlarmConditionType_RemoveFromService);
  EXPECT_TRUE(removeStatus.is_good())
    << "RemoveFromService refused the ConditionId as its ObjectId: " << removeStatus.as_uint32();
  EXPECT_TRUE(target->snapshot()->out_of_service().value_or(false))
    << "RemoveFromService(ConditionId) did not take the Alarm the ConditionId names out of service";
  EXPECT_FALSE(mFullAlarm->snapshot()->out_of_service().value_or(true))
    << "RemoveFromService(ConditionId) took a different Alarm out of service";

  // --- PlaceInService, section 5.8.14 -----------------------------------------------------------------
  target->remove_from_service_sync();
  mFullAlarm->remove_from_service_sync();
  ASSERT_TRUE(target->snapshot()->out_of_service().value_or(false))
    << "the named Alarm must be out of service for the PlaceInService below to be observable";
  ASSERT_TRUE(mFullAlarm->snapshot()->out_of_service().value_or(false))
    << "the bystander must be out of service for the control below to discriminate";

  const auto placeStatus = callWithConditionId(targetId, MethodId::AlarmConditionType_PlaceInService);
  EXPECT_TRUE(placeStatus.is_good()) << "PlaceInService refused the ConditionId as its ObjectId: "
                                     << placeStatus.as_uint32();
  EXPECT_FALSE(target->snapshot()->out_of_service().value_or(true))
    << "PlaceInService(ConditionId) did not return the Alarm the ConditionId names to service";
  EXPECT_TRUE(mFullAlarm->snapshot()->out_of_service().value_or(false))
    << "PlaceInService(ConditionId) returned a different Alarm to service";

  // --- Reset, section 5.8.5 ---------------------------------------------------------------------------
  // Reset clears LatchedState, and the logic accepts it only on an Alarm that is inactive and
  // acknowledged. Both Alarms are made Reset-eligible, so a Reset that landed on the bystander would
  // actually unlatch it rather than being rejected on its state.
  target->deactivate_sync();
  mFullAlarm->deactivate_sync();
  const auto targetEventId = get_event_id(target);
  ASSERT_FALSE(targetEventId.empty());
  target->acknowledge_sync(targetEventId, LocalizedText{"", "ack"});
  const auto bystanderEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(bystanderEventId.empty());
  mFullAlarm->acknowledge_sync(bystanderEventId, LocalizedText{"", "ack"});

  ASSERT_TRUE(target->snapshot()->latched().value_or(false))
    << "the named Alarm must be latched for the Reset below to be observable";
  ASSERT_TRUE(mFullAlarm->snapshot()->latched().value_or(false))
    << "the bystander must be latched for the control below to discriminate";
  ASSERT_FALSE(mFullAlarm->snapshot()->active())
    << "the bystander must itself be Reset-eligible, or a misrouted Reset would be refused anyway";
  ASSERT_TRUE(mFullAlarm->snapshot()->acked())
    << "the bystander must itself be Reset-eligible, or a misrouted Reset would be refused anyway";

  const auto resetByConditionIdStatus = callWithConditionId(targetId, MethodId::AlarmConditionType_Reset);
  EXPECT_TRUE(resetByConditionIdStatus.is_good())
    << "Reset refused the ConditionId as its ObjectId: " << resetByConditionIdStatus.as_uint32();
  EXPECT_FALSE(target->snapshot()->latched().value_or(true))
    << "Reset(ConditionId) left the Alarm the ConditionId names latched";
  EXPECT_TRUE(mFullAlarm->snapshot()->latched().value_or(false))
    << "Reset(ConditionId) unlatched a different Alarm sharing the same owning Object";
}

// ===========================================================================
// Reads of a Disabled Condition, and ConditionRefresh's own refusal codes
// ===========================================================================

/// Read one node's Value with both timestamps requested, so SourceTimestamp is populated. The file's
/// `read_value_dv` leaves TimestampsToReturn at its default; the ConditionVariable obligations below
/// are about SourceTimestamp specifically, so they must ask for it.
static DataValue read_value_with_timestamps(ua::client::Session& session, const NodeId& nodeId)
{
  ReadRequest req;
  req.timestamps_to_return() = TimestampsToReturn::Both;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  auto resp = session.attributes().try_read_sync(std::move(req));
  if (resp.is_bad() || resp.value().results().empty())
    return {};
  return resp.value().results()[0];
}

/// True when a read reported a Bad status. A Good read commonly omits the status entirely, so the
/// absence of a status is a Good read, not an unknown one.
static bool read_reported_bad(const DataValue& dv)
{
  return dv.status().has_value() && dv.status().value().is_bad();
}

// OPC 10000-9 5.5.4: while a Condition is Disabled only EventId, EventType, SourceNode, SourceName,
// Time and EnabledState stay valid; every other Condition Variable must report a Bad status instead of
// the value it last held. Disabling reads naturally as an event-suppression concern - clear Retain,
// stop emitting, leave the stored state alone - and an implementation that stops there keeps serving
// the last live Severity and Quality with a Good status, so a Client that polls rather than subscribes
// cannot tell a disabled Condition from a healthy one. The whitelisted members are asserted still Good
// beside them, so a blanket "everything is Bad once disabled" is not a pass either.
// @verifies AC-SVR-AC-011-DISABLED-VARIABLES-BAD
TEST_F(ComplianceConditionTest, DisabledCondition_StateVariablesReadBadRatherThanTheirLastValues)
{
  const auto severityId = find_hier_child(*mSession, mAlarmId, String{"Severity"});
  ASSERT_FALSE(severityId.is_null()) << "Severity is Mandatory on ConditionType";
  const auto qualityId = find_hier_child(*mSession, mAlarmId, String{"Quality"});
  ASSERT_FALSE(qualityId.is_null()) << "Quality is Mandatory on ConditionType";
  const auto enabledStateId = find_hier_child(*mSession, mAlarmId, String{"EnabledState"});
  ASSERT_FALSE(enabledStateId.is_null()) << "EnabledState is Mandatory on ConditionType";
  const auto sourceNameId = find_hier_child(*mSession, mAlarmId, String{"SourceName"});
  ASSERT_FALSE(sourceNameId.is_null()) << "SourceName is Mandatory on BaseEventType";

  // Drive the Condition to a state whose values are visibly live, so "returns its last value" is
  // distinguishable from "never had one" once it is disabled.
  mAlarm->enable_sync();
  mAlarm->activate_sync(750);
  ASSERT_TRUE(mAlarm->snapshot()->enabled());

  const auto liveSeverity = read_value_with_timestamps(*mSession, severityId);
  ASSERT_FALSE(read_reported_bad(liveSeverity)) << "Severity must read while the Condition is enabled";
  const auto* liveSeverityValue = liveSeverity.value().try_as<uint16_t>();
  ASSERT_NE(liveSeverityValue, nullptr) << "Severity must read as a typed UInt16 while enabled";
  ASSERT_EQ(*liveSeverityValue, uint16_t{750}) << "the live Severity must be the one just set";
  const auto liveQuality = read_value_with_timestamps(*mSession, qualityId);
  ASSERT_FALSE(read_reported_bad(liveQuality)) << "Quality must read while the Condition is enabled";

  mAlarm->disable_sync();
  ASSERT_FALSE(mAlarm->snapshot()->enabled());

  const auto disabledSeverity = read_value_with_timestamps(*mSession, severityId);
  EXPECT_TRUE(read_reported_bad(disabledSeverity))
    << "a disabled Condition kept serving Severity with a Good status";
  EXPECT_EQ(
    disabledSeverity.status().value_or(StatusCode{Status::Good}), StatusCode{Status::BadConditionDisabled})
    << "Severity on a disabled Condition should be Bad_ConditionDisabled";
  const auto* staleSeverity = disabledSeverity.value().try_as<uint16_t>();
  EXPECT_TRUE(staleSeverity == nullptr || *staleSeverity != uint16_t{750})
    << "a disabled Condition must not keep serving the Severity it held while enabled";

  const auto disabledQuality = read_value_with_timestamps(*mSession, qualityId);
  EXPECT_TRUE(read_reported_bad(disabledQuality))
    << "a disabled Condition kept serving Quality with a Good status";
  EXPECT_EQ(
    disabledQuality.status().value_or(StatusCode{Status::Good}), StatusCode{Status::BadConditionDisabled})
    << "Quality on a disabled Condition should be Bad_ConditionDisabled";

  // The always-valid members stay readable: the Condition's existence and its Disabled state are not
  // hidden, only its state variables.
  const auto disabledEnabledState = read_value_with_timestamps(*mSession, enabledStateId);
  EXPECT_FALSE(read_reported_bad(disabledEnabledState))
    << "EnabledState must stay readable while disabled - it is how a Client learns the Condition is off";
  const auto disabledSourceName = read_value_with_timestamps(*mSession, sourceNameId);
  EXPECT_FALSE(read_reported_bad(disabledSourceName))
    << "SourceName must stay readable while the Condition is disabled";
}

// OPC 10000-9 5.5.7: ConditionRefresh answers Bad_SubscriptionIdInvalid for a Subscription the Server
// does not hold for this Session, and Bad_NothingToDo for a Subscription that holds no event
// MonitoredItem. The second is the one worth distinguishing and the one an implementation omits: the
// refresh handler needs only the SubscriptionId, so a Subscription that exists but has nothing to
// refresh sails through and reports success, telling the Client its screens were repopulated when no
// notification will ever arrive. The control at the end adds an event MonitoredItem to the SAME
// Subscription and refreshes again, so the Bad_NothingToDo above cannot be blamed on the Subscription.
// @verifies AC-SVR-AC-024-REFRESH-CODES
// clang-format off  -- the macro must stay on ONE line: the execution-evidence gate matches the JUnit
// name against a single-line TEST_F, so a wrapped macro reads as a test that does not exist.
TEST_F(ComplianceConditionSubscriptionTest,
  ConditionRefresh_AnswersAnUnknownSubscriptionAndAnEmptyOneWithTheirOwnCodes)
// clang-format on
{
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);  // something retained, so an accepted refresh would have work to do

  // (a) A SubscriptionId the Server holds for nobody.
  auto unknownReq = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{uint32_t{99999}}});
  auto unknownResult = mSession->methods().try_call_sync(std::move(unknownReq));
  ASSERT_TRUE(unknownResult.is_good()) << "Call failed: " << unknownResult.status_code().as_uint32();
  ASSERT_FALSE(unknownResult.value().results().empty());
  EXPECT_EQ(unknownResult.value().results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid})
    << "an unknown SubscriptionId should be Bad_SubscriptionIdInvalid, got: "
    << unknownResult.value().results()[0].status_code().as_uint32();

  // (b) This Session's own Subscription, which exists and is valid but carries no event MonitoredItem
  //     (the fixture creates the Subscription; the MonitoredItem is added per test, and not yet here).
  auto emptyReq = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto emptyResult = mSession->methods().try_call_sync(std::move(emptyReq));
  ASSERT_TRUE(emptyResult.is_good()) << "Call failed: " << emptyResult.status_code().as_uint32();
  ASSERT_FALSE(emptyResult.value().results().empty());
  const auto emptyStatus = emptyResult.value().results()[0].status_code();
  EXPECT_EQ(emptyStatus, StatusCode{Status::BadNothingToDo})
    << "a Subscription with no event MonitoredItem should be Bad_NothingToDo, got: "
    << emptyStatus.as_uint32();
  EXPECT_FALSE(emptyStatus == StatusCode{Status::BadSubscriptionIdInvalid})
    << "the two refusals must be distinguishable: a valid Subscription was reported as an invalid id";

  // Control: the same Subscription, now carrying an event MonitoredItem, is refreshed successfully - so
  // the refusal above was about the missing MonitoredItem and not about the Subscription.
  create_event_monitored_item(make_condition_event_filter());
  std::this_thread::sleep_for(std::chrono::milliseconds(100));  // let any in-flight refresh guard clear
  auto populatedReq = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto populatedResult = mSession->methods().try_call_sync(std::move(populatedReq));
  ASSERT_TRUE(populatedResult.is_good()) << "Call failed: " << populatedResult.status_code().as_uint32();
  ASSERT_FALSE(populatedResult.value().results().empty());
  EXPECT_TRUE(populatedResult.value().results()[0].status_code().is_good())
    << "the same Subscription with an event MonitoredItem should refresh successfully, got: "
    << populatedResult.value().results()[0].status_code().as_uint32();
}

// ===========================================================================
// Every Part 9 Method raises its declared audit subtype, on every invocation
// ===========================================================================

/// An OfType(auditType) filter plus AuditEventType's own `Status` Property - the Boolean that records
/// whether the audited invocation succeeded. Appended last, so Status is select-clause index 11.
static EventFilter make_audit_filter_with_status(const NodeId& auditType)
{
  EventFilter filter = make_of_type_filter(auditType);
  filter.select_clauses().push_back(make_select_clause("Status", NodeId{ObjectTypeId::AuditEventType}));
  return filter;
}

/// One audited Method family: the subtype its `AlwaysGeneratesEvent` reference names, the Subscription
/// handle that admits only that subtype, and what was observed for it.
struct AuditSubtypeExpectation
{
  const char* label;
  uint32_t handle;
  NodeId auditType;
  bool expectRefusalArm;
  bool sawSuccess{false};
  bool sawRefusal{false};
};

// OPC 10000-9 4.11: "An Event of this type shall be generated for every invocation of the Method." Every
// Part 9 Condition Method carries an AlwaysGeneratesEvent reference to a specific AuditConditionEventType
// subtype, and "every invocation" includes the ones that fail - AuditEventType.Status exists precisely to
// carry the outcome, and the refused invocation is the one an auditor most wants. Emitting on the success
// path is the natural implementation and it silently loses the whole refusal half of the trail. Each
// family is watched through its own MonitoredItem filtered OfType the exact subtype, so a Server that
// emits only the parent AuditConditionEventType satisfies nothing here.
// @verifies AC-SVR-AC-041-METHOD-AUDIT-EVENTS
// clang-format off  -- the macro must stay on ONE line: the execution-evidence gate matches the JUnit
// name against a single-line TEST_F, so a wrapped macro reads as a test that does not exist.
TEST_F(ComplianceConditionSubscriptionTest,
  Part9Methods_RaiseTheirDeclaredAuditSubtypeOnEveryInvocationIncludingRefusals)
// clang-format on
{
  std::vector<AuditSubtypeExpectation> expectations{
    {"Enable/Disable", 5001, NodeId{ObjectTypeId::AuditConditionEnableEventType}, true, false, false},
    {"AddComment", 5002, NodeId{ObjectTypeId::AuditConditionCommentEventType}, true, false, false},
    {"Acknowledge", 5003, NodeId{ObjectTypeId::AuditConditionAcknowledgeEventType}, true, false, false},
    {"Confirm", 5004, NodeId{ObjectTypeId::AuditConditionConfirmEventType}, true, false, false},
    {"Shelving", 5005, NodeId{ObjectTypeId::AuditConditionShelvingEventType}, true, false, false},
    {"Reset", 5006, NodeId{ObjectTypeId::AuditConditionResetEventType}, true, false, false},
    {"Suppression", 5007, NodeId{ObjectTypeId::AuditConditionSuppressionEventType}, false, false, false},
    {"OutOfService", 5008, NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType}, false, false, false},
    {"Silence", 5009, NodeId{ObjectTypeId::AuditConditionSilenceEventType}, false, false, false}};

  for (const auto& expectation : expectations)
  {
    (void)::ua::test_helpers::create_event_monitored_item(*mSession,
      mSubscriptionId,
      NodeId{ObjectId::Server},
      make_audit_filter_with_status(expectation.auditType),
      {.clientHandle = expectation.handle, .samplingInterval = 0.0, .queueSize = 100});
  }

  const ByteString unknownEventId{std::vector<uint8_t>{0x7F, 0x7E, 0x7D, 0x7C}};

  // --- Enable / Disable, both outcomes, on the plain Condition -----------------------------------
  ASSERT_FALSE(mCondition->snapshot()->enabled()) << "the Condition must start disabled";
  ASSERT_TRUE(call_condition_method(mConditionId, "Enable").is_good()) << "Enable should succeed";
  ASSERT_TRUE(call_condition_method(mConditionId, "Enable").is_bad())
    << "a second Enable must be refused for the refusal arm to be driven";
  ASSERT_TRUE(call_condition_method(mConditionId, "Disable").is_good()) << "Disable should succeed";
  ASSERT_TRUE(call_condition_method(mConditionId, "Disable").is_bad())
    << "a second Disable must be refused for the refusal arm to be driven";

  // --- The alarm Methods, on the full-featured alarm ---------------------------------------------
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  const auto commentEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(commentEventId.empty());
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "AddComment",
    Array<Variant>{Variant{commentEventId}, Variant{LocalizedText{"", "audited comment"}}})
                .is_good())
    << "AddComment should succeed with a valid EventId";
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "AddComment",
    Array<Variant>{Variant{unknownEventId}, Variant{LocalizedText{"", "comment on nothing"}}})
                .is_bad())
    << "AddComment with an unknown EventId must be refused for the refusal arm to be driven";

  const auto ackEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(ackEventId.empty());
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "Acknowledge",
    Array<Variant>{Variant{ackEventId}, Variant{LocalizedText{"", "audited ack"}}})
                .is_good())
    << "Acknowledge should succeed with a valid EventId";
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "Acknowledge",
    Array<Variant>{Variant{unknownEventId}, Variant{LocalizedText{"", "ack nothing"}}})
                .is_bad())
    << "Acknowledge with an unknown EventId must be refused for the refusal arm to be driven";

  const auto confirmEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(confirmEventId.empty());
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "Confirm",
    Array<Variant>{Variant{confirmEventId}, Variant{LocalizedText{"", "audited confirm"}}})
                .is_good())
    << "Confirm should succeed with a valid EventId";
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "Confirm",
    Array<Variant>{Variant{unknownEventId}, Variant{LocalizedText{"", "confirm nothing"}}})
                .is_bad())
    << "Confirm with an unknown EventId must be refused for the refusal arm to be driven";

  // Suppression / out-of-service / silence: the logic accepts these unconditionally, so only the
  // success arm is reachable and only it is claimed below.
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Suppress").is_good()) << "Suppress should succeed";
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Unsuppress").is_good()) << "Unsuppress should succeed";
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "RemoveFromService").is_good())
    << "RemoveFromService should succeed";
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "PlaceInService").is_good())
    << "PlaceInService should succeed";
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Silence").is_good()) << "Silence should succeed";

  // Shelving: shelve, then shelve again (already shelved), then unshelve twice (not shelved).
  ASSERT_TRUE(call_child_method(mFullAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{5000.0}})
                .is_good())
    << "TimedShelve should succeed";
  ASSERT_TRUE(
    call_child_method(mFullAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{5000.0}}).is_bad())
    << "a second TimedShelve must be refused for the refusal arm to be driven";
  ASSERT_TRUE(call_child_method(mFullAlarmId, "ShelvingState", "Unshelve").is_good())
    << "Unshelve should succeed";
  ASSERT_TRUE(call_child_method(mFullAlarmId, "ShelvingState", "Unshelve").is_bad())
    << "a second Unshelve must be refused for the refusal arm to be driven";

  // Reset: refused while the alarm is still active, accepted once it is inactive and acknowledged.
  ASSERT_TRUE(mFullAlarm->snapshot()->active());
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Reset").is_bad())
    << "Reset on an active alarm must be refused for the refusal arm to be driven";
  mFullAlarm->deactivate_sync();
  if (!mFullAlarm->snapshot()->acked())
  {
    const auto resetAckEventId = get_event_id(mFullAlarm);
    ASSERT_FALSE(resetAckEventId.empty());
    mFullAlarm->acknowledge_sync(resetAckEventId, LocalizedText{"", "ack for reset"});
  }
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Reset").is_good()) << "Reset should succeed";

  // --- Collect and evaluate -----------------------------------------------------------------------
  constexpr size_t statusIndex = 11;
  size_t collected = 0;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    bool complete = false;
    while (!complete && std::chrono::steady_clock::now() < deadline)
    {
      for (const auto& event : collect_events(10))
      {
        ++collected;
        const auto eventType = event_type_from(event);
        const uint32_t handle = event.client_handle();
        const bool* status = event.event_fields().size() > statusIndex
                               ? event.event_fields()[statusIndex].try_as<bool>()
                               : nullptr;
        if (status == nullptr)
          continue;
        for (auto& expectation : expectations)
        {
          if (handle != expectation.handle || !(eventType == expectation.auditType))
            continue;
          if (*status)
            expectation.sawSuccess = true;
          else
            expectation.sawRefusal = true;
        }
      }
      complete = true;
      for (const auto& expectation : expectations)
      {
        if (!expectation.sawSuccess || (expectation.expectRefusalArm && !expectation.sawRefusal))
          complete = false;
      }
    }
  }

  EXPECT_GT(collected, 0u) << "no audit Event was delivered at all";
  for (const auto& expectation : expectations)
  {
    EXPECT_TRUE(expectation.sawSuccess)
      << expectation.label << ": no Event of the exact declared audit subtype with Status = True (of "
      << collected << " events)";
    if (expectation.expectRefusalArm)
    {
      EXPECT_TRUE(expectation.sawRefusal)
        << expectation.label
        << ": the refused invocation raised no audit Event with Status = False - 'every invocation' "
           "includes the ones that fail (of "
        << collected << " events)";
    }
  }
}

// ===========================================================================
// TwoStateVariable Id, and ConditionVariable SourceTimestamp
// ===========================================================================

// OPC 10000-9 5.4.2: a TwoStateVariable's `Id` Property carries the current state as a Boolean, while
// the parent Variable's Value is the localised display text. An implementation that keeps the state only
// in the LocalizedText - or that materialises `Id` as an inert Property nobody updates - forces a Client
// to parse "Enabled"/"Disabled" to learn the state, which is exactly what `Id` exists to prevent. Both
// halves are asserted: `Id` is a typed Boolean each time, and it moved when the state moved.
// @verifies AC-SVR-AC-042-TWOSTATE-ID-IS-CURRENT
TEST_F(ComplianceConditionTest, TwoStateVariable_IdIsTheCurrentBooleanStateAndTracksIt)
{
  // EnabledState, driven by the Enable Method over the wire.
  const auto enabledStateId = find_hier_child(*mSession, mConditionId, String{"EnabledState"});
  ASSERT_FALSE(enabledStateId.is_null()) << "EnabledState is Mandatory on ConditionType";
  const auto enabledIdNode = find_hier_child(*mSession, enabledStateId, String{"Id"});
  ASSERT_FALSE(enabledIdNode.is_null()) << "EnabledState/Id is Mandatory on TwoStateVariableType";

  ASSERT_FALSE(mCondition->snapshot()->enabled()) << "the Condition must start disabled";
  const auto beforeEnable = read_value_with_timestamps(*mSession, enabledIdNode);
  ASSERT_FALSE(read_reported_bad(beforeEnable)) << "EnabledState/Id must be readable";
  const auto* beforeEnableId = beforeEnable.value().try_as<bool>();
  ASSERT_NE(beforeEnableId, nullptr) << "EnabledState/Id must read as a typed Boolean, never as null";
  EXPECT_FALSE(*beforeEnableId) << "EnabledState/Id must be False while the Condition is disabled";

  ASSERT_TRUE(call_condition_method(mConditionId, "Enable").is_good()) << "Enable should succeed";

  const auto afterEnable = read_value_with_timestamps(*mSession, enabledIdNode);
  ASSERT_FALSE(read_reported_bad(afterEnable)) << "EnabledState/Id must still be readable after Enable";
  const auto* afterEnableId = afterEnable.value().try_as<bool>();
  ASSERT_NE(afterEnableId, nullptr) << "EnabledState/Id must read as a typed Boolean, never as null";
  EXPECT_TRUE(*afterEnableId) << "EnabledState/Id must be True once the Condition is enabled";
  EXPECT_NE(*beforeEnableId, *afterEnableId) << "EnabledState/Id did not track the state change";

  // ActiveState on the alarm, so the obligation is shown on a second TwoStateVariable rather than on the
  // one every Condition happens to special-case.
  mAlarm->enable_sync();
  const auto activeStateId = find_hier_child(*mSession, mAlarmId, String{"ActiveState"});
  ASSERT_FALSE(activeStateId.is_null()) << "ActiveState is Mandatory on AlarmConditionType";
  const auto activeIdNode = find_hier_child(*mSession, activeStateId, String{"Id"});
  ASSERT_FALSE(activeIdNode.is_null()) << "ActiveState/Id is Mandatory on TwoStateVariableType";

  const auto beforeActivate = read_value_with_timestamps(*mSession, activeIdNode);
  ASSERT_FALSE(read_reported_bad(beforeActivate)) << "ActiveState/Id must be readable";
  const auto* beforeActivateId = beforeActivate.value().try_as<bool>();
  ASSERT_NE(beforeActivateId, nullptr) << "ActiveState/Id must read as a typed Boolean, never as null";
  EXPECT_FALSE(*beforeActivateId) << "ActiveState/Id must be False before the alarm activates";

  mAlarm->activate_sync(500);
  ASSERT_TRUE(mAlarm->snapshot()->active());

  const auto afterActivate = read_value_with_timestamps(*mSession, activeIdNode);
  ASSERT_FALSE(read_reported_bad(afterActivate)) << "ActiveState/Id must still be readable when active";
  const auto* afterActivateId = afterActivate.value().try_as<bool>();
  ASSERT_NE(afterActivateId, nullptr) << "ActiveState/Id must read as a typed Boolean, never as null";
  EXPECT_TRUE(*afterActivateId) << "ActiveState/Id must be True once the alarm is active";
  EXPECT_NE(*beforeActivateId, *afterActivateId) << "ActiveState/Id did not track the state change";
}

// OPC 10000-9 5.3: a ConditionVariable's SourceTimestamp is the time its value last changed, and the
// SourceTimestamp Property beside it must agree with the DataValue the Read Service returns. Stamping
// the value with "now" as it is read is the natural implementation for a live variable and it is wrong
// here: the timestamp is how an operator knows how long a Condition has held, so restamping makes every
// alarm look as if it had just occurred. The third read - after a genuine second change - proves the
// stability asserted above is not simply a frozen constant.
// @verifies AC-SVR-AC-045-CONDITIONVARIABLE-SOURCETIMESTAMP
TEST_F(ComplianceConditionTest, ConditionVariable_SourceTimestampIsTheTimeOfChangeNotOfTheRead)
{
  mCondition->enable_sync();
  const auto commentId = find_hier_child(*mSession, mConditionId, String{"Comment"});
  ASSERT_FALSE(commentId.is_null()) << "Comment is a Mandatory ConditionVariable on ConditionType";

  const auto firstEventId = get_event_id(mCondition);
  ASSERT_FALSE(firstEventId.empty());
  ASSERT_TRUE(call_condition_method(mConditionId,
    "AddComment",
    Array<Variant>{Variant{firstEventId}, Variant{LocalizedText{"", "first note"}}})
                .is_good())
    << "AddComment should succeed";

  const auto atChange = read_value_with_timestamps(*mSession, commentId);
  ASSERT_FALSE(read_reported_bad(atChange)) << "the Comment ConditionVariable must be readable";
  ASSERT_TRUE(atChange.source_timestamp().has_value())
    << "a Read with TimestampsToReturn=Both must carry a SourceTimestamp";
  const DateTime changeTimestamp = atChange.source_timestamp().value();
  ASSERT_FALSE(changeTimestamp.is_null()) << "the SourceTimestamp must not be the null DateTime";

  // An interval with no change at all, then the same read again.
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  const auto afterInterval = read_value_with_timestamps(*mSession, commentId);
  ASSERT_FALSE(read_reported_bad(afterInterval)) << "the Comment ConditionVariable must still be readable";
  ASSERT_TRUE(afterInterval.source_timestamp().has_value());
  EXPECT_TRUE(afterInterval.source_timestamp().value() == changeTimestamp)
    << "the SourceTimestamp moved although the value did not - it was stamped at the read, not at the "
       "change";

  // The SourceTimestamp Property beside the value must report the same instant as the DataValue.
  const auto sourceTimestampNode = find_hier_child(*mSession, commentId, String{"SourceTimestamp"});
  EXPECT_FALSE(sourceTimestampNode.is_null())
    << "a ConditionVariable carries a SourceTimestamp Property (ConditionVariableType)";
  if (!sourceTimestampNode.is_null())
  {
    const auto propertyValue = read_value_with_timestamps(*mSession, sourceTimestampNode);
    EXPECT_FALSE(read_reported_bad(propertyValue)) << "the SourceTimestamp Property must be readable";
    const auto* propertyTimestamp = propertyValue.value().try_as<DateTime>();
    ASSERT_NE(propertyTimestamp, nullptr) << "the SourceTimestamp Property must read as a typed DateTime";
    EXPECT_TRUE(*propertyTimestamp == changeTimestamp)
      << "the SourceTimestamp Property and the DataValue's SourceTimestamp disagree";
  }

  // A genuine second change must move it, or the equality above would be satisfied by a constant.
  const auto secondEventId = get_event_id(mCondition);
  ASSERT_FALSE(secondEventId.empty());
  ASSERT_TRUE(call_condition_method(mConditionId,
    "AddComment",
    Array<Variant>{Variant{secondEventId}, Variant{LocalizedText{"", "second note"}}})
                .is_good())
    << "the second AddComment should succeed";

  const auto afterSecondChange = read_value_with_timestamps(*mSession, commentId);
  ASSERT_FALSE(read_reported_bad(afterSecondChange));
  ASSERT_TRUE(afterSecondChange.source_timestamp().has_value());
  EXPECT_TRUE(afterSecondChange.source_timestamp().value() > changeTimestamp)
    << "the SourceTimestamp did not advance when the ConditionVariable's value actually changed";
}

// ===========================================================================
// HasTrueSubState / HasFalseSubState endpoint typing, and the Disabled state
// ===========================================================================

/// Every target of one ReferenceType, in one direction, for each node in `nodeIds` - one Browse Service
/// call per chunk of nodes rather than one per node. The surveys below ask the same question of a few
/// hundred Nodes, and a request each exhausts the Session's request budget long before the survey is
/// finished, after which every later browse returns nothing. The result is parallel to `nodeIds`; a node
/// whose operation failed carries an empty entry.
static std::vector<std::vector<NodeId>> browse_reference_targets_batch(ua::client::Session& session,
  const std::vector<NodeId>& nodeIds, const NodeId& referenceType, BrowseDirection direction,
  bool includeSubtypes)
{
  constexpr size_t nodesPerRequest = 64;  // comfortably inside the Server's MaxNodesPerBrowse limit

  std::vector<std::vector<NodeId>> targets(nodeIds.size());
  for (size_t offset = 0; offset < nodeIds.size(); offset += nodesPerRequest)
  {
    const size_t count = std::min(nodesPerRequest, nodeIds.size() - offset);
    BrowseRequest req;
    for (size_t i = 0; i < count; ++i)
    {
      BrowseDescription desc;
      desc.node_id() = nodeIds[offset + i];
      desc.browse_direction() = direction;
      desc.reference_type_id() = referenceType;
      desc.include_subtypes() = includeSubtypes;
      desc.node_class_mask() = 0;  // any node class
      desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
      req.nodes_to_browse().push_back(std::move(desc));
    }

    auto result = session.view().try_browse_sync(std::move(req));
    if (result.is_bad())
      continue;
    const auto& results = result.value().results();
    for (size_t i = 0; i < count && i < results.size(); ++i)
    {
      for (const auto& ref : results[i].references())
        targets[offset + i].push_back(ref.node_id().node_id());
    }
  }
  return targets;
}

/// Every target of one ReferenceType from a node, in one direction; empty when the browse fails.
static std::vector<NodeId> browse_reference_targets(ua::client::Session& session, const NodeId& nodeId,
  const NodeId& referenceType, BrowseDirection direction, bool includeSubtypes)
{
  auto perNode = browse_reference_targets_batch(
    session, std::vector<NodeId>{nodeId}, referenceType, direction, includeSubtypes);
  return perNode.empty() ? std::vector<NodeId>{} : std::move(perNode.front());
}

/// The HasTypeDefinition target of each node, parallel to `nodeIds`; a null NodeId where a node has none.
static std::vector<NodeId> type_definitions_of(
  ua::client::Session& session, const std::vector<NodeId>& nodeIds)
{
  std::vector<NodeId> types;
  types.reserve(nodeIds.size());
  for (const auto& targets : browse_reference_targets_batch(
         session, nodeIds, NodeId{ReferenceTypeId::HasTypeDefinition}, BrowseDirection::Forward, false))
  {
    types.push_back(targets.empty() ? NodeId{} : targets.front());
  }
  return types;
}

/// For each entry of `typeIds`, whether it is `baseTypeId` or reaches it by walking HasSubtype inversely.
/// The whole batch advances one hop per Browse call, so the walk costs the depth of the hierarchy in
/// requests rather than that depth times the number of types. Bounded so a malformed hierarchy cannot spin.
static std::vector<bool> types_derive_from(
  ua::client::Session& session, const std::vector<NodeId>& typeIds, const NodeId& baseTypeId)
{
  std::vector<bool> derives(typeIds.size(), false);
  std::vector<NodeId> current = typeIds;
  for (int hop = 0; hop < 16; ++hop)
  {
    std::vector<size_t> pendingIndices;
    std::vector<NodeId> pendingTypes;
    for (size_t i = 0; i < current.size(); ++i)
    {
      if (derives[i] || current[i].is_null())
        continue;
      if (current[i] == baseTypeId)
      {
        derives[i] = true;
        continue;
      }
      pendingIndices.push_back(i);
      pendingTypes.push_back(current[i]);
    }
    if (pendingTypes.empty())
      break;

    const auto supertypes = browse_reference_targets_batch(
      session, pendingTypes, NodeId{ReferenceTypeId::HasSubtype}, BrowseDirection::Inverse, false);
    for (size_t i = 0; i < pendingIndices.size(); ++i)
      current[pendingIndices[i]] = supertypes[i].empty() ? NodeId{} : supertypes[i].front();
  }
  return derives;
}

/// One sub-state edge discovered in the AddressSpace.
struct SubStateEdge
{
  NodeId source;
  NodeId target;
};

/// Every `referenceType` edge leaving each root or any of its immediate hierarchical children.
/// HasTrueSubState / HasFalseSubState are NonHierarchical, so they are browsed for by name rather than
/// picked up by a hierarchical walk.
static std::vector<SubStateEdge> collect_sub_state_edges(
  ua::client::Session& session, const NodeId& referenceType, const std::vector<NodeId>& roots)
{
  std::vector<NodeId> holders = roots;
  for (const auto& children : browse_reference_targets_batch(
         session, roots, NodeId{ReferenceTypeId::HierarchicalReferences}, BrowseDirection::Forward, true))
  {
    holders.insert(holders.end(), children.begin(), children.end());
  }

  std::vector<SubStateEdge> edges;
  const auto perHolder =
    browse_reference_targets_batch(session, holders, referenceType, BrowseDirection::Forward, false);
  for (size_t i = 0; i < perHolder.size(); ++i)
  {
    for (const auto& target : perHolder[i])
      edges.push_back(SubStateEdge{holders[i], target});
  }
  return edges;
}

/// Part 9 5.2 endpoint typing over the edges of one sub-state polarity: every source an instance of
/// TwoStateVariableType, every target a state variable or a state machine. `label` names the
/// ReferenceType in the failure messages, and every message names the Node it is about, since the whole
/// survey is checked from here.
static void expect_sub_state_endpoints_typed(
  ua::client::Session& session, const std::vector<SubStateEdge>& edges, const char* label)
{
  std::vector<NodeId> sources;
  std::vector<NodeId> targets;
  sources.reserve(edges.size());
  targets.reserve(edges.size());
  for (const auto& edge : edges)
  {
    sources.push_back(edge.source);
    targets.push_back(edge.target);
  }

  const auto sourceTypes = type_definitions_of(session, sources);
  const auto targetTypes = type_definitions_of(session, targets);
  const auto sourceIsTwoState =
    types_derive_from(session, sourceTypes, NodeId{VariableTypeId::TwoStateVariableType});
  const auto targetIsStateVariable =
    types_derive_from(session, targetTypes, NodeId{VariableTypeId::StateVariableType});
  const auto targetIsStateMachine =
    types_derive_from(session, targetTypes, NodeId{ObjectTypeId::StateMachineType});

  for (size_t i = 0; i < edges.size(); ++i)
  {
    const bool sourceTyped = sourceIsTwoState[i];
    const bool targetTyped = targetIsStateVariable[i] || targetIsStateMachine[i];

    EXPECT_FALSE(sourceTypes[i].is_null())
      << "the " << label << " source " << ua::to_string(edges[i].source) << " carries no HasTypeDefinition";
    EXPECT_TRUE(sourceTyped) << "the " << label << " source " << ua::to_string(edges[i].source)
                             << " is not a TwoStateVariableType instance";
    EXPECT_FALSE(targetTypes[i].is_null())
      << "the " << label << " target " << ua::to_string(edges[i].target) << " carries no HasTypeDefinition";
    EXPECT_TRUE(targetTyped) << "the " << label << " target " << ua::to_string(edges[i].target)
                             << " is neither a state variable nor a state machine";
  }
}

/// The Condition type Nodes and the fixture's instances - the region of the AddressSpace where Part 9
/// sub-state relationships live - plus the Objects folder the instances hang from.
static std::vector<NodeId> sub_state_survey_roots(const NodeId& alarmId, const NodeId& fullAlarmId,
  const NodeId& ackConditionId, const NodeId& exclusiveLimitId, const NodeId& nonExclusiveLimitId)
{
  return std::vector<NodeId>{NodeId{ObjectTypeId::ConditionType},
    NodeId{ObjectTypeId::DialogConditionType},
    NodeId{ObjectTypeId::AcknowledgeableConditionType},
    NodeId{ObjectTypeId::AlarmConditionType},
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType},
    NodeId{ObjectTypeId::NonExclusiveLimitAlarmType},
    NodeId{ObjectTypeId::OffNormalAlarmType},
    alarmId,
    fullAlarmId,
    ackConditionId,
    exclusiveLimitId,
    nonExclusiveLimitId,
    NodeId{ObjectId::ObjectsFolder}};
}

// OPC 10000-9 5.2: a HasTrueSubState Reference runs from a TwoStateVariableType instance to a state
// variable or a state machine - the relationship that gives an alarm its state hierarchy. Every such
// Reference reachable from the Part 9 Condition types, the fixture's instances and the Objects folder is
// surveyed, and both of its endpoints are resolved to their HasTypeDefinition and walked up the type
// hierarchy: a source that is not a TwoStateVariable, or a target that is neither a state variable nor a
// state machine, is a relationship no Client can interpret.
// @verifies AC-SVR-AC-046-HASTRUESUBSTATE-TYPING
TEST_F(ComplianceConditionTest, HasTrueSubState_RunsFromATwoStateVariableToAStateVariableOrStateMachine)
{
  const auto edges = collect_sub_state_edges(*mSession,
    NodeId{ReferenceTypeId::HasTrueSubState},
    sub_state_survey_roots(mAlarmId, mFullAlarmId, mAckConditionId, mExclusiveLimitId, mNonExclusiveLimitId));
  ASSERT_FALSE(edges.empty())
    << "no HasTrueSubState Reference was reachable at all - the survey would be vacuous";

  expect_sub_state_endpoints_typed(*mSession, edges, "HasTrueSubState");
}

// OPC 10000-9 5.2: the false-side twin of the rule above - a HasFalseSubState Reference runs from a
// TwoStateVariableType instance to a state variable or a state machine. The same region is surveyed for
// the false polarity, with the true-polarity survey run first as a positive control: it must find edges,
// so an empty HasFalseSubState result is the absence of the Reference from the model rather than a survey
// that cannot see a sub-state Reference at all.
// @verifies AC-SVR-AC-047-HASFALSESUBSTATE-TYPING
TEST_F(ComplianceConditionTest, HasFalseSubState_RunsFromATwoStateVariableToAStateVariableOrStateMachine)
{
  const auto roots =
    sub_state_survey_roots(mAlarmId, mFullAlarmId, mAckConditionId, mExclusiveLimitId, mNonExclusiveLimitId);

  ASSERT_FALSE(collect_sub_state_edges(*mSession, NodeId{ReferenceTypeId::HasTrueSubState}, roots).empty())
    << "the survey found no sub-state Reference of either polarity - it cannot see one at all";

  const auto edges = collect_sub_state_edges(*mSession, NodeId{ReferenceTypeId::HasFalseSubState}, roots);
  expect_sub_state_endpoints_typed(*mSession, edges, "HasFalseSubState");
}

// OPC 10000-9 5.5.2: EnabledState's False state - Disabled - carries no sub-state machine. A disabled
// Condition reports nothing at all, so a sub-state beneath Disabled would be state no Client can ever
// observe; a Server that models "why it is disabled" as a sub-state of the Disabled state produces
// exactly that. The positive control asserts the same browse DOES find the HasTrueSubState References
// hanging off the Enabled side, so an empty result here is the absence of the Reference and not a browse
// that cannot see sub-state References at all.
// @verifies AC-SVR-AC-048-ENABLEDSTATE-FALSE-NOT-EXTENDED
TEST_F(ComplianceConditionTest, EnabledState_DisabledStateCarriesNoSubStateMachine)
{
  const std::vector<NodeId> holders{NodeId{ObjectTypeId::ConditionType},
    NodeId{ObjectTypeId::AcknowledgeableConditionType},
    NodeId{ObjectTypeId::AlarmConditionType},
    NodeId{ObjectTypeId::DialogConditionType},
    mConditionId,
    mAlarmId,
    mAckConditionId,
    mFullAlarmId};

  size_t enabledStatesChecked = 0;
  for (const auto& holder : holders)
  {
    const auto enabledStateId = find_hier_child(*mSession, holder, String{"EnabledState"});
    if (enabledStateId.is_null())
      continue;
    ++enabledStatesChecked;
    const auto falseSubStates = browse_reference_targets(
      *mSession, enabledStateId, NodeId{ReferenceTypeId::HasFalseSubState}, BrowseDirection::Forward, false);
    EXPECT_TRUE(falseSubStates.empty())
      << "EnabledState carries " << falseSubStates.size()
      << " HasFalseSubState Reference(s) - the Disabled state must not be extended";
  }
  ASSERT_GT(enabledStatesChecked, 0u) << "no EnabledState Node was found - the assertions above were "
                                         "vacuous";

  // Positive control: the Enabled side of the same TwoStateVariable does carry sub-states, so the browse
  // used above is capable of seeing a sub-state Reference when one is present.
  const auto alarmEnabledStateId =
    find_hier_child(*mSession, NodeId{ObjectTypeId::AlarmConditionType}, String{"EnabledState"});
  ASSERT_FALSE(alarmEnabledStateId.is_null()) << "AlarmConditionType.EnabledState must be browsable";
  const auto trueSubStates = browse_reference_targets(*mSession,
    alarmEnabledStateId,
    NodeId{ReferenceTypeId::HasTrueSubState},
    BrowseDirection::Forward,
    false);
  EXPECT_FALSE(trueSubStates.empty())
    << "AlarmConditionType.EnabledState should carry HasTrueSubState References; without them the "
       "empty HasFalseSubState results above prove nothing";
}

// ===========================================================================
// SupportsFilteredRetain, communication failure, and the audit umbrella
// ===========================================================================

/// The shared condition filter plus a `Severity >= threshold` where clause. Two MonitoredItems whose
/// filters differ only in that threshold are what makes per-filter Retain observable at all: the
/// Condition is one object, so "Retain for this Client's filter" can only be seen as two Subscribers
/// disagreeing about it.
static EventFilter make_severity_threshold_filter(uint16_t threshold)
{
  EventFilter filter = make_condition_event_filter();

  ContentFilterElement element;
  element.filter_operator() = FilterOperator::GreaterThanOrEqual;

  SimpleAttributeOperand severityOperand;
  severityOperand.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  severityOperand.browse_path().push_back(QualifiedName{0, "Severity"});
  severityOperand.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  RefStructure<Structure> severityRef;
  severityRef =
    std::unique_ptr<Structure>(std::make_unique<SimpleAttributeOperand>(std::move(severityOperand)));
  element.filter_operands().push_back(std::move(severityRef));

  LiteralOperand thresholdOperand;
  thresholdOperand.value() = Variant{threshold};
  RefStructure<Structure> thresholdRef;
  thresholdRef = std::unique_ptr<Structure>(std::make_unique<LiteralOperand>(std::move(thresholdOperand)));
  element.filter_operands().push_back(std::move(thresholdRef));

  filter.where_clause().elements().push_back(std::move(element));
  return filter;
}

// OPC 10000-9 5.5.2: "SupportsFilteredRetain Property is only provided on the ConditionType. When this
// Property is set to True on the Type, then the Server provides a Client specific Retain flag value
// taking into account any Client provided filter. When the property is False on the ConditionType then
// the Server does not provide a Client specific the value of the Retain flag." This Server leaves the
// Property False, so Retain is one flag on the Condition and the Figure-11 per-filter processing does not
// apply: a Condition that stops passing a Client's where clause simply stops being delivered to that
// Client, and no per-filter Retain=False retraction may be synthesised for it. That retraction is the
// half an implementation is most likely to add speculatively, and adding it without the declaration
// removes the Condition from the alarm display of a Client that never asked for filtered Retain. The wide
// filter is watched alongside so that "no retraction on the narrow filter" is distinguished from a state
// change that never reached the wire at all.
// @verifies AC-SVR-AC-050-FILTERED-RETAIN
TEST_F(ComplianceConditionSubscriptionTest, Retain_IsGlobalWhereFilteredRetainIsNotDeclared)
{
  constexpr size_t severityIndex = 6;  // per make_condition_event_filter's select order
  constexpr size_t retainIndex = 8;
  constexpr uint32_t narrowHandle = 9001;  // Severity >= 700
  constexpr uint32_t wideHandle = 9002;  // Severity >= 100

  auto countWithSeverity =
    [&](const std::vector<EventFieldList>& events, uint32_t handle, uint16_t severity) -> size_t
  {
    size_t matches = 0;
    for (const auto& event : events)
    {
      if (event.client_handle() != handle || event.event_fields().size() <= severityIndex)
        continue;
      const auto* value = event.event_fields()[severityIndex].try_as<uint16_t>();
      if (value != nullptr && *value == severity)
        ++matches;
    }
    return matches;
  };

  auto countWithRetain = [&](
                           const std::vector<EventFieldList>& events, uint32_t handle, bool retain) -> size_t
  {
    size_t matches = 0;
    for (const auto& event : events)
    {
      if (event.client_handle() != handle || event.event_fields().size() <= retainIndex)
        continue;
      const auto* value = event.event_fields()[retainIndex].try_as<bool>();
      if (value != nullptr && *value == retain)
        ++matches;
    }
    return matches;
  };

  (void)::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_severity_threshold_filter(700),
    {.clientHandle = narrowHandle, .samplingInterval = 0.0, .queueSize = 100});
  (void)::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_severity_threshold_filter(100),
    {.clientHandle = wideHandle, .samplingInterval = 0.0, .queueSize = 100});

  std::vector<EventFieldList> observedEvents;
  auto pumpEvents = [&]()
  {
    for (auto& event : collect_events(10))
      observedEvents.push_back(std::move(event));
  };

  mAlarm->enable_sync();
  mAlarm->activate_sync(800);
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (countWithSeverity(observedEvents, narrowHandle, 800) == 0 &&
           std::chrono::steady_clock::now() < deadline)
      pumpEvents();
  }
  ASSERT_GT(countWithSeverity(observedEvents, narrowHandle, 800), 0u)
    << "the narrow filter never admitted the Condition, so the absence asserted below would be vacuous";

  // The Condition moves to a severity the narrow filter no longer admits, while staying Retained
  // globally - active and unacknowledged.
  mAlarm->activate_sync(200);
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (
      countWithSeverity(observedEvents, wideHandle, 200) == 0 && std::chrono::steady_clock::now() < deadline)
      pumpEvents();
  }

  EXPECT_GT(countWithSeverity(observedEvents, wideHandle, 200), 0u)
    << "the wide filter did not see the severity-200 state - the state change never reached the wire";
  EXPECT_GT(countWithRetain(observedEvents, wideHandle, true), 0u)
    << "under the unfiltered rules the Condition is still Retained, so the filter that admits it must "
       "carry Retain=True";
  EXPECT_EQ(countWithRetain(observedEvents, narrowHandle, false), 0u)
    << "this Condition does not declare SupportsFilteredRetain, so Retain follows the unfiltered rules "
       "and no per-filter retraction may be sent to the narrowed filter";
}

/// The condition fixture with auditing switched on, so the section 5.10 umbrella applies in its positive
/// form.
class ComplianceConditionAuditingEnabledTest : public ComplianceConditionSubscriptionTest
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.auditingEnabled = true;
  }
};

/// The same fixture with auditing switched off - the configuration section 5.10 explicitly permits, in which
/// a conforming Server raises nothing and still answers every request normally.
class ComplianceConditionAuditingDisabledTest : public ComplianceConditionSubscriptionTest
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    cfg.auditingEnabled = false;
  }
};

// OPC 10000-9 5.10: where auditing is supported, every Alarms and Conditions action raises an Event of
// AuditConditionEventType or one of its subtypes. This is the umbrella over the per-Method rows, and the
// gap it catches is different from theirs: an implementation that wires the audit emission for the
// Methods it was asked about and reaches for a generic AuditEventType (or nothing) for the rest still
// passes every per-Method check that was written, while an auditor filtering on AuditConditionEventType -
// the only filter that can be written without enumerating the subtypes - sees the trail with holes in it.
// Every action is therefore watched through a single MonitoredItem filtered OfType the PARENT type, and
// what arrives is independently resolved up the HasSubtype hierarchy so a loose OfType cannot supply the
// answer.
// @verifies AC-SVR-AC-061-CONDITION-AUDIT
TEST_F(ComplianceConditionAuditingEnabledTest, EveryConditionActionRaisesAnAuditConditionEventOrASubtype)
{
  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionEventType}));

  auto nextAuditType = [this]() -> NodeId
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline)
    {
      for (const auto& event : collect_events(10))
      {
        const auto type = event_type_from(event);
        if (!type.is_null())
          return type;
      }
    }
    return {};
  };
  auto drainAuditEvents = [this]()
  {
    while (!collect_events(4).empty())
    {
    }
  };

  struct AuditedAction
  {
    const char* label;
    NodeId observed;
  };

  std::vector<AuditedAction> actions;

  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Enable").is_good()) << "Enable should succeed";
  actions.push_back(AuditedAction{"enable", nextAuditType()});
  drainAuditEvents();

  // Staged through the in-process API so the staging cannot itself be mistaken for the audited action.
  mFullAlarm->activate_sync(500);
  drainAuditEvents();

  const auto commentEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(commentEventId.empty());
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "AddComment",
    Array<Variant>{Variant{commentEventId}, Variant{LocalizedText{"", "audited comment"}}})
                .is_good())
    << "AddComment should succeed";
  actions.push_back(AuditedAction{"comment", nextAuditType()});
  drainAuditEvents();

  const auto ackEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(ackEventId.empty());
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "Acknowledge",
    Array<Variant>{Variant{ackEventId}, Variant{LocalizedText{"", "audited ack"}}})
                .is_good())
    << "Acknowledge should succeed";
  actions.push_back(AuditedAction{"acknowledge", nextAuditType()});
  drainAuditEvents();

  const auto confirmEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(confirmEventId.empty());
  ASSERT_TRUE(call_condition_method(mFullAlarmId,
    "Confirm",
    Array<Variant>{Variant{confirmEventId}, Variant{LocalizedText{"", "audited confirm"}}})
                .is_good())
    << "Confirm should succeed";
  actions.push_back(AuditedAction{"confirm", nextAuditType()});
  drainAuditEvents();

  ASSERT_TRUE(call_child_method(mFullAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{5000.0}})
                .is_good())
    << "TimedShelve should succeed";
  actions.push_back(AuditedAction{"shelve", nextAuditType()});
  drainAuditEvents();

  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Disable").is_good()) << "Disable should succeed";
  actions.push_back(AuditedAction{"disable", nextAuditType()});

  ASSERT_EQ(actions.size(), 6u) << "all six Alarms and Conditions actions must have been driven";

  std::vector<NodeId> observedTypes;
  observedTypes.reserve(actions.size());
  for (const auto& action : actions)
    observedTypes.push_back(action.observed);

  const auto derives =
    types_derive_from(*mSession, observedTypes, NodeId{ObjectTypeId::AuditConditionEventType});
  ASSERT_EQ(derives.size(), actions.size());
  for (size_t i = 0; i < actions.size(); ++i)
  {
    EXPECT_FALSE(actions[i].observed.is_null())
      << actions[i].label << ": no Event of AuditConditionEventType or a subtype was raised at all";
    EXPECT_TRUE(derives[i]) << actions[i].label << ": raised " << ua::to_string(actions[i].observed)
                            << ", which is not AuditConditionEventType or one of its subtypes";
  }
}

// OPC 10000-9 5.10 gates the audit obligation on the Server: "If Auditing is supported by a Server,
// Events of AuditConditionEventType shall be generated." The gate conditions the audit emission alone
// and never the action, so on a Server whose `ServerConfig::auditingEnabled` is false every
// Alarms and Conditions action must still complete normally - a gate implemented in the Method
// dispatcher rather than in the emit path shows up here as a Method that starts failing once auditing is
// switched off. Every one of the six actions is therefore driven through the Call service, the surface a
// Client sees. What the Server does or does not raise in this configuration is not asserted: the clause
// is a one-way conditional with no negative limb.
// @verifies AC-SVR-AC-061-CONDITION-AUDIT
TEST_F(ComplianceConditionAuditingDisabledTest, EveryConditionActionSucceedsWhereAuditingIsNotSupported)
{
  EXPECT_TRUE(call_condition_method(mFullAlarmId, "Enable").is_good())
    << "Enable must succeed even where auditing is not supported";
  mFullAlarm->activate_sync(500);

  const auto commentEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(commentEventId.empty());
  EXPECT_TRUE(call_condition_method(mFullAlarmId,
    "AddComment",
    Array<Variant>{Variant{commentEventId}, Variant{LocalizedText{"", "unaudited comment"}}})
                .is_good())
    << "AddComment must succeed even where auditing is not supported";

  const auto ackEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(ackEventId.empty());
  EXPECT_TRUE(call_condition_method(mFullAlarmId,
    "Acknowledge",
    Array<Variant>{Variant{ackEventId}, Variant{LocalizedText{"", "unaudited ack"}}})
                .is_good())
    << "Acknowledge must succeed even where auditing is not supported";

  const auto confirmEventId = get_event_id(mFullAlarm);
  ASSERT_FALSE(confirmEventId.empty());
  EXPECT_TRUE(call_condition_method(mFullAlarmId,
    "Confirm",
    Array<Variant>{Variant{confirmEventId}, Variant{LocalizedText{"", "unaudited confirm"}}})
                .is_good())
    << "Confirm must succeed even where auditing is not supported";

  EXPECT_TRUE(call_child_method(mFullAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{5000.0}})
                .is_good())
    << "TimedShelve must succeed even where auditing is not supported";
  EXPECT_TRUE(call_condition_method(mFullAlarmId, "Disable").is_good())
    << "Disable must succeed even where auditing is not supported";
}

// OPC 10000-9 5.10: the audit Event records the state change, not the Call that caused it - an alarm
// enabled by a startup rule or acknowledged from a local HMI is as significant to an auditor as one
// driven over OPC UA, and the Server must raise the same AuditConditionEventType subtype for it. The
// natural place to emit the audit record is the Method dispatcher, because that is where the Session,
// the ClientUserId and the outcome are all in hand; an implementation that stops there leaves every
// internally driven transition unrecorded, and the resulting trail reads as though nothing happened
// rather than as though something happened without a Client. The clause sits under the section 5.10.1 gate,
// so the fixture is the auditing-enabled one: on a Server that supports no auditing there is nothing to
// raise. The Condition Events are watched alongside, so a missing audit Event cannot be confused with a
// transition that never occurred.
// @verifies AC-SVR-AC-062-AUDIT-ON-INTERNAL-ACTION
TEST_F(ComplianceConditionAuditingEnabledTest, InternalEnableAndAcknowledgeStillRaiseTheirAuditEvents)
{
  constexpr uint32_t auditHandle = 8001;
  constexpr uint32_t conditionHandle = 8002;

  (void)::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_of_type_filter(NodeId{ObjectTypeId::AuditConditionEventType}),
    {.clientHandle = auditHandle, .samplingInterval = 0.0, .queueSize = 100});
  (void)::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_of_type_filter(NodeId{ObjectTypeId::ConditionType}),
    {.clientHandle = conditionHandle, .samplingInterval = 0.0, .queueSize = 100});

  // An internal Enable: the Server application's own API, with no Session, no ObjectId and no MethodId -
  // exactly the startup/vendor-driven mechanism the clause is about.
  mCondition->enable_sync();
  ASSERT_TRUE(mCondition->snapshot()->enabled()) << "the internal Enable must have taken effect";

  // An internal Acknowledge, likewise: the alarm is driven and acknowledged without a Call service
  // request ever being made.
  mAlarm->enable_sync();
  mAlarm->activate_sync(500);
  const auto eventId = get_event_id(mAlarm);
  ASSERT_FALSE(eventId.empty());
  mAlarm->acknowledge_sync(eventId, LocalizedText{"", "acknowledged at the local HMI"});
  ASSERT_TRUE(mAlarm->snapshot()->acked()) << "the internal Acknowledge must have taken effect";

  bool sawEnableAudit = false;
  bool sawAcknowledgeAudit = false;
  bool sawConditionEvent = false;
  size_t collected = 0;
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!(sawEnableAudit && sawAcknowledgeAudit) && std::chrono::steady_clock::now() < deadline)
    {
      for (const auto& event : collect_events(10))
      {
        ++collected;
        if (event.client_handle() == conditionHandle)
          sawConditionEvent = true;
        if (event.client_handle() != auditHandle)
          continue;
        const auto type = event_type_from(event);
        if (type == NodeId{ObjectTypeId::AuditConditionEnableEventType})
          sawEnableAudit = true;
        if (type == NodeId{ObjectTypeId::AuditConditionAcknowledgeEventType})
          sawAcknowledgeAudit = true;
      }
    }
  }

  ASSERT_TRUE(sawConditionEvent)
    << "not one Condition Event reached the wire (of " << collected
    << " events), so the internal transitions cannot be shown to have happened at all";
  EXPECT_TRUE(sawEnableAudit)
    << "the Condition was enabled by an internal mechanism and no AuditConditionEnableEventType was "
       "raised (of "
    << collected << " events)";
  EXPECT_TRUE(sawAcknowledgeAudit) << "the Condition was acknowledged by an internal mechanism and no "
                                      "AuditConditionAcknowledgeEventType was raised (of "
                                   << collected << " events)";
}

// ===========================================================================
// The notifier hierarchy: ConditionSources, areas, and the Server Object root
// ===========================================================================

/// Read a node's NodeClass attribute. The Read Service returns the enumeration as an Int32, so it is
/// widened back here; a failed read reports Unspecified rather than guessing a class.
static NodeClass read_node_class(ua::client::Session& session, const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::NodeClass);
  req.nodes_to_read().push_back(std::move(rv));
  auto resp = session.attributes().try_read_sync(std::move(req));
  if (resp.is_bad() || resp.value().results().empty())
    return NodeClass::Unspecified;
  const auto& dv = resp.value().results()[0];
  if (dv.status().has_value() && dv.status().value().is_bad())
    return NodeClass::Unspecified;
  const auto* raw = dv.value().try_as<int32_t>();
  return raw == nullptr ? NodeClass::Unspecified : static_cast<NodeClass>(*raw);
}

/// The Node a Condition names as its source, read from the Condition's own `SourceNode` Property over
/// the wire rather than from the fixture's knowledge of how it was created. A null NodeId when the
/// Property is missing or unreadable, which the callers assert on.
static NodeId read_condition_source_node(ua::client::Session& session, const NodeId& conditionId)
{
  const auto sourceNodeProperty = find_hier_child(session, conditionId, String{"SourceNode"});
  if (sourceNodeProperty.is_null())
    return {};
  const auto dv = read_value_dv(session, sourceNodeProperty);
  if (read_reported_bad(dv))
    return {};
  const auto* source = dv.value().try_as<NodeId>();
  return source == nullptr ? NodeId{} : *source;
}

/// Every Node reachable from `root` by following HasEventSource and its subtypes forward, transitively.
/// HasNotifier is a subtype of HasEventSource (Part 5 section 11.15), so one browse with includeSubtypes
/// walks both legs of the notifier hierarchy. Bounded in depth so a cyclic hierarchy cannot spin, and `root`
/// itself is not reported as reached.
static std::vector<NodeId> collect_notifier_hierarchy(ua::client::Session& session, const NodeId& root)
{
  std::vector<NodeId> reached;
  std::vector<NodeId> frontier{root};
  for (int depth = 0; depth < 8 && !frontier.empty(); ++depth)
  {
    std::vector<NodeId> next;
    for (const auto& targets : browse_reference_targets_batch(
           session, frontier, NodeId{ReferenceTypeId::HasEventSource}, BrowseDirection::Forward, true))
    {
      for (const auto& target : targets)
      {
        if (std::find(reached.begin(), reached.end(), target) != reached.end())
          continue;
        reached.push_back(target);
        next.push_back(target);
      }
    }
    frontier = std::move(next);
  }
  return reached;
}

/// Enable every Condition so each publishes a populated `SourceNode`: a Condition serves its Event-field
/// Variables from the snapshot its last Event filled, so one that has never been enabled has nothing for
/// the survey to read.
static void enable_conditions(const std::vector<std::shared_ptr<ConditionInstance>>& instances)
{
  for (const auto& instance : instances)
    instance->enable_sync();
}

/// The fixture's Condition instances, in the order they are created by `configure_server`.
static std::vector<NodeId> fixture_condition_ids(const NodeId& conditionId, const NodeId& alarmId,
  const NodeId& ackConditionId, const NodeId& fullAlarmId, const NodeId& dialogId,
  const NodeId& exclusiveLimitId, const NodeId& nonExclusiveLimitId, const NodeId& offNormalId)
{
  return std::vector<NodeId>{conditionId,
    alarmId,
    ackConditionId,
    fullAlarmId,
    dialogId,
    exclusiveLimitId,
    nonExclusiveLimitId,
    offNormalId};
}

// OPC 10000-9 5.5.3: every Node that acts as a ConditionSource must be the target of a HasEventSource
// Reference, or of a subtype of one. Wiring a Condition to its source with HasCondition alone is the
// natural implementation - it is the Reference a Client browses to find the alarm - and it leaves the
// source outside the notifier hierarchy, so the alarm fires correctly and no conforming Client ever
// discovers it. Each source is read from the Condition's own SourceNode Property so the survey does not
// assume how the fixture wired them.
// @verifies AC-SVR-AC-070-CONDITIONSOURCE-HASEVENTSOURCE-TARGET
TEST_F(ComplianceConditionTest, EveryConditionSourceIsTheTargetOfAHasEventSourceReference)
{
  enable_conditions({mCondition,
    mAlarm,
    mAckCondition,
    mFullAlarm,
    mDialog,
    mExclusiveLimit,
    mNonExclusiveLimit,
    mOffNormal});
  const auto conditions = fixture_condition_ids(mConditionId,
    mAlarmId,
    mAckConditionId,
    mFullAlarmId,
    mDialogId,
    mExclusiveLimitId,
    mNonExclusiveLimitId,
    mOffNormalId);

  std::vector<NodeId> sources;
  for (const auto& conditionId : conditions)
  {
    const auto source = read_condition_source_node(*mSession, conditionId);
    ASSERT_FALSE(source.is_null()) << "the Condition " << ua::to_string(conditionId)
                                   << " publishes no readable SourceNode, so its source cannot be checked";
    sources.push_back(source);
  }
  ASSERT_EQ(sources.size(), conditions.size()) << "every fixture Condition must contribute a source";

  for (size_t i = 0; i < sources.size(); ++i)
  {
    const auto notifiers = browse_reference_targets(
      *mSession, sources[i], NodeId{ReferenceTypeId::HasEventSource}, BrowseDirection::Inverse, true);
    EXPECT_FALSE(notifiers.empty())
      << "the ConditionSource " << ua::to_string(sources[i]) << " of Condition "
      << ua::to_string(conditions[i])
      << " is the target of no HasEventSource Reference or subtype - it sits outside the notifier "
         "hierarchy";
  }
}

// OPC 10000-9 5.12 with Clause 6: the AddressSpace organisation a Client uses to detect Conditions is a
// notifier hierarchy rooted at the Server Object, so every ConditionSource must be reachable from that
// Object by walking HasNotifier and HasEventSource. Storing only the inverse leg of the Reference on the
// source Node satisfies an inverse browse and leaves the forward walk - the one a Client actually makes,
// downwards from the Server Object - finding nothing. The two sets are gathered independently: the
// sources come from each Condition's SourceNode Property, the reachable set from the walk.
// @verifies AC-SVR-AC-071-CONDITION-HIERARCHY
TEST_F(ComplianceConditionTest, EveryConditionSourceIsReachableFromTheServerObjectByTheNotifierWalk)
{
  enable_conditions({mCondition,
    mAlarm,
    mAckCondition,
    mFullAlarm,
    mDialog,
    mExclusiveLimit,
    mNonExclusiveLimit,
    mOffNormal});
  const auto conditions = fixture_condition_ids(mConditionId,
    mAlarmId,
    mAckConditionId,
    mFullAlarmId,
    mDialogId,
    mExclusiveLimitId,
    mNonExclusiveLimitId,
    mOffNormalId);

  std::vector<NodeId> sources;
  for (const auto& conditionId : conditions)
  {
    const auto source = read_condition_source_node(*mSession, conditionId);
    ASSERT_FALSE(source.is_null()) << "the Condition " << ua::to_string(conditionId)
                                   << " publishes no readable SourceNode";
    if (std::find(sources.begin(), sources.end(), source) == sources.end())
      sources.push_back(source);
  }
  ASSERT_FALSE(sources.empty()) << "no ConditionSource was enumerated - the comparison would be vacuous";

  const auto reached = collect_notifier_hierarchy(*mSession, NodeId{ObjectId::Server});
  ASSERT_FALSE(reached.empty())
    << "walking HasNotifier / HasEventSource forward from the Server Object reached no Node at all, so "
       "no ConditionSource is discoverable by browsing down from the well-known root";

  for (const auto& source : sources)
  {
    EXPECT_NE(std::find(reached.begin(), reached.end(), source), reached.end())
      << "the ConditionSource " << ua::to_string(source)
      << " is not reachable from the Server Object by the notifier walk";
  }

  // The converse half: the walk must not present as a ConditionSource anything that is not one. A Node
  // reached by the walk counts as a ConditionSource exactly when it emits a HasCondition Reference.
  for (const auto& node : reached)
  {
    const auto conditionsOfNode = browse_reference_targets(
      *mSession, node, NodeId{ReferenceTypeId::HasCondition}, BrowseDirection::Forward, true);
    if (conditionsOfNode.empty())
      continue;
    EXPECT_NE(std::find(sources.begin(), sources.end(), node), sources.end())
      << "the notifier walk reached " << ua::to_string(node)
      << ", which carries HasCondition References but is not one of the Server's ConditionSources";
  }
}

// OPC 10000-9 6: where areas exist they are linked to one another by HasNotifier and to their
// ConditionSources by HasEventSource, with the Server Object as the well-known root - that chain is what
// lets a Client subscribe to an area instead of to every Condition beneath it. A Server that records the
// link only on the source Node, or that leaves the source hanging off no notifier at all, breaks the
// chain at the point a Client starts from. All three links are asserted: the source is linked by a
// HasEventSource or subtype, each notifier holding it is the root or is itself reached from the root,
// and the forward walk from the root reaches the source.
// @verifies AC-SVR-AC-085-AREAS-LINKED-BY-NOTIFIER
TEST_F(SeededOffNormalAlarmTest, AreasAndTheirConditionSourcesAreLinkedByTheNotifierHierarchy)
{
  const NodeId serverObject{ObjectId::Server};

  const auto notifiersOfSource = browse_reference_targets(
    *mSession, mSourceId, NodeId{ReferenceTypeId::HasEventSource}, BrowseDirection::Inverse, true);
  ASSERT_FALSE(notifiersOfSource.empty())
    << "the ConditionSource " << ua::to_string(mSourceId)
    << " is linked to no notifier by a HasEventSource Reference or subtype";

  const auto reached = collect_notifier_hierarchy(*mSession, serverObject);

  for (const auto& notifier : notifiersOfSource)
  {
    const bool linkedToRoot =
      notifier == serverObject || std::find(reached.begin(), reached.end(), notifier) != reached.end();
    EXPECT_TRUE(linkedToRoot)
      << "the notifier " << ua::to_string(notifier) << " holding the ConditionSource "
      << ua::to_string(mSourceId)
      << " is neither the Server Object nor linked to it - the area chain does not reach the root";
  }

  EXPECT_NE(std::find(reached.begin(), reached.end(), mSourceId), reached.end())
    << "walking HasNotifier / HasEventSource forward from the Server Object does not reach the "
       "ConditionSource "
    << ua::to_string(mSourceId) << " (the walk reached " << reached.size() << " Node(s))";

  // The Server Object is the root of the hierarchy, not a member of it: nothing links downwards into it.
  const auto notifiersOfServer = browse_reference_targets(
    *mSession, serverObject, NodeId{ReferenceTypeId::HasEventSource}, BrowseDirection::Inverse, true);
  EXPECT_TRUE(notifiersOfServer.empty())
    << "the Server Object is the target of " << notifiersOfServer.size()
    << " HasEventSource Reference(s) or subtype(s) - it must be the root of the notifier hierarchy";
}

// ===========================================================================
// HasCondition endpoint typing, and its survival of instantiation
// ===========================================================================

/// The Nodes in the type space that may legally emit a `HasCondition` Reference, in the region where
/// Part 9 and Part 12 place them: the Condition ObjectTypes, the CertificateGroup types that carry the
/// standard type-level HasCondition, and the immediate hierarchical children of each - the
/// InstanceDeclarations, which the clause permits as sources too.
static std::vector<NodeId> type_space_has_condition_holders(ua::client::Session& session)
{
  const std::vector<NodeId> typeNodes{NodeId{ObjectTypeId::CertificateGroupType},
    NodeId{ObjectTypeId::CertificateGroupFolderType},
    NodeId{ObjectTypeId::ConditionType},
    NodeId{ObjectTypeId::DialogConditionType},
    NodeId{ObjectTypeId::AcknowledgeableConditionType},
    NodeId{ObjectTypeId::AlarmConditionType},
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType},
    NodeId{ObjectTypeId::NonExclusiveLimitAlarmType},
    NodeId{ObjectTypeId::OffNormalAlarmType},
    NodeId{ObjectTypeId::CertificateExpirationAlarmType},
    NodeId{ObjectTypeId::ServerConfigurationType}};

  std::vector<NodeId> holders = typeNodes;
  for (const auto& children : browse_reference_targets_batch(
         session, typeNodes, NodeId{ReferenceTypeId::HierarchicalReferences}, BrowseDirection::Forward, true))
  {
    holders.insert(holders.end(), children.begin(), children.end());
  }
  return holders;
}

/// Whether `sourceId` is an ObjectType or VariableType Node, or an InstanceDeclaration of one - the
/// source set OPC 10000-9 5.12 allows for a HasCondition Reference used in a Type definition. An
/// InstanceDeclaration is recognised by climbing inverse hierarchical References until a type Node is
/// found; the climb is bounded so a malformed model cannot spin.
static bool is_type_definition_has_condition_source(ua::client::Session& session, const NodeId& sourceId)
{
  const auto nodeClass = read_node_class(session, sourceId);
  if (nodeClass == NodeClass::ObjectType || nodeClass == NodeClass::VariableType)
    return true;
  if (nodeClass != NodeClass::Object && nodeClass != NodeClass::Variable)
    return false;

  NodeId current = sourceId;
  for (int hop = 0; hop < 8; ++hop)
  {
    const auto parents = browse_reference_targets(
      session, current, NodeId{ReferenceTypeId::HierarchicalReferences}, BrowseDirection::Inverse, true);
    if (parents.empty())
      return false;
    current = parents.front();
    const auto parentClass = read_node_class(session, current);
    if (parentClass == NodeClass::ObjectType || parentClass == NodeClass::VariableType)
      return true;
  }
  return false;
}

// OPC 10000-9 5.12: a HasCondition Reference used in a Type definition runs from an ObjectType or a
// VariableType Node - or from one of their InstanceDeclarations, which the same clause allows - to a
// Condition instance declaration or a ConditionType. A Server that materialises the Reference from an
// ordinary instance Node it happens to hold in the type space publishes a relationship a Client cannot
// interpret when it browses the type to learn what Conditions the instances of that type will carry.
// Both endpoints are surveyed, and the source set is asserted to include a genuine type Node so the
// InstanceDeclaration allowance cannot carry the whole survey.
// @verifies AC-SVR-AC-072-HASCONDITION-IN-TYPE
TEST_F(ComplianceConditionTest, HasCondition_InATypeDefinitionRunsFromAnObjectTypeOrVariableType)
{
  const auto holders = type_space_has_condition_holders(*mSession);
  ASSERT_FALSE(holders.empty()) << "no type-space Node was reachable - the survey would be vacuous";

  std::vector<NodeId> sources;
  std::vector<NodeId> targets;
  const auto perHolder = browse_reference_targets_batch(
    *mSession, holders, NodeId{ReferenceTypeId::HasCondition}, BrowseDirection::Forward, true);
  for (size_t i = 0; i < perHolder.size(); ++i)
  {
    for (const auto& target : perHolder[i])
    {
      sources.push_back(holders[i]);
      targets.push_back(target);
    }
  }
  ASSERT_FALSE(sources.empty())
    << "no HasCondition Reference was found anywhere in the type space - the assertions below would "
       "assert over nothing";

  const auto targetIsConditionType =
    types_derive_from(*mSession, targets, NodeId{ObjectTypeId::ConditionType});
  const auto targetIsConditionInstance = types_derive_from(
    *mSession, type_definitions_of(*mSession, targets), NodeId{ObjectTypeId::ConditionType});

  size_t sourcesThatAreTypeNodes = 0;
  for (size_t i = 0; i < sources.size(); ++i)
  {
    const auto sourceClass = read_node_class(*mSession, sources[i]);
    if (sourceClass == NodeClass::ObjectType || sourceClass == NodeClass::VariableType)
      ++sourcesThatAreTypeNodes;

    EXPECT_TRUE(is_type_definition_has_condition_source(*mSession, sources[i]))
      << "the type-definition HasCondition source " << ua::to_string(sources[i]) << " (NodeClass "
      << static_cast<int32_t>(sourceClass)
      << ") is neither an ObjectType nor a VariableType nor an InstanceDeclaration of one";
    EXPECT_TRUE(targetIsConditionType[i] || targetIsConditionInstance[i])
      << "the type-definition HasCondition target " << ua::to_string(targets[i])
      << " is neither a ConditionType nor a Condition instance declaration";
  }
  EXPECT_GT(sourcesThatAreTypeNodes, 0u)
    << "not one surveyed HasCondition ran from a type Node itself, so the ObjectType / VariableType "
       "half of the obligation was never exercised";
}

/// A custom ObjectType that carries a type-level HasCondition Reference, so instantiation of that type
/// can be watched. Deriving it from OffNormalAlarmType lets `Conditions::create_condition_sync` - the
/// Server's own instantiation path - be the thing that builds the instance, rather than the fixture
/// assembling the instance Node by hand.
class HasConditionInstantiationTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto addressSpace = mServer.server().address_space();

    mCarrierTypeId = NodeId{0, uint32_t{60001}};
    auto typeNode = addressSpace.create_node_sync(mCarrierTypeId, NodeClass::ObjectType);
    typeNode.set_browse_name(QualifiedName{0, "ConditionCarryingAlarmType"});
    typeNode.set_display_name(LocalizedText{"", "ConditionCarryingAlarmType"});
    typeNode.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype},
      ExpandedNodeId{NodeId{ObjectTypeId::OffNormalAlarmType}},
      /*isForward=*/false);
    // Best effort: the forward leg lives on the standard type Node, which a Server may hold read-only.
    // The instantiation path only needs the inverse leg written above.
    auto offNormalTypeNode = addressSpace.find_node_sync(NodeId{ObjectTypeId::OffNormalAlarmType});
    (void)offNormalTypeNode.try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, mCarrierTypeId);

    // The type-level HasCondition under test: a ConditionType target, which the clause says is shared
    // by every instance rather than copied into one.
    typeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasCondition}, NodeId{ObjectTypeId::CertificateExpirationAlarmType});
  }

  /// Instantiate the carrier type through the Server's own condition-creation path.
  std::shared_ptr<ConditionInstance> instantiate_carrier(const char* browseName)
  {
    auto logic = std::make_unique<OffNormalAlarmLogic>();
    logic->set_normal_state(Variant{false});
    auto result = mServer.server().conditions().try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{browseName},
      std::move(logic),
      mCarrierTypeId);
    if (result.is_bad())
      return nullptr;
    return result.value();
  }

  NodeId mCarrierTypeId;
};

// OPC 10000-9 5.12: HasCondition References used in a Type definition shall exist on the instances of
// that Type as well - that is how a Client that browsed the type to learn which Conditions it carries
// finds the same Conditions on a live instance. Instantiation naturally copies InstanceDeclarations and
// hierarchical structure, so a non-hierarchical Reference such as HasCondition is exactly the one an
// implementation drops. The type's own Reference is asserted first, so a failure below is the loss of
// the Reference at instantiation and not the absence of the Reference from the type.
// @verifies AC-SVR-AC-073-HASCONDITION-SURVIVES-INSTANTIATION
TEST_F(HasConditionInstantiationTest, ATypesHasConditionReferencesAppearOnItsInstances)
{
  const auto typeTargets = browse_reference_targets(
    *mSession, mCarrierTypeId, NodeId{ReferenceTypeId::HasCondition}, BrowseDirection::Forward, true);
  ASSERT_FALSE(typeTargets.empty())
    << "the carrier ObjectType publishes no HasCondition Reference, so instantiation has nothing to "
       "replicate and the assertion below would be vacuous";

  auto instance = instantiate_carrier("CarrierAlarm");
  ASSERT_NE(instance, nullptr) << "the carrier type must instantiate through the Server's own path";
  const auto instanceId = instance->condition_id();
  ASSERT_FALSE(instanceId.is_null()) << "the instantiated Condition must have a NodeId";

  const auto instanceTargets = browse_reference_targets(
    *mSession, instanceId, NodeId{ReferenceTypeId::HasCondition}, BrowseDirection::Forward, true);
  ASSERT_FALSE(instanceTargets.empty())
    << "the instance of a type carrying HasCondition References carries none of its own";

  for (const auto& typeTarget : typeTargets)
  {
    EXPECT_NE(std::find(instanceTargets.begin(), instanceTargets.end(), typeTarget), instanceTargets.end())
      << "the type's HasCondition target " << ua::to_string(typeTarget) << " is missing from its instance "
      << ua::to_string(instanceId);
  }
}

// OPC 10000-9 5.12: where the type-level HasCondition target is a ConditionType, the same TargetNode is
// referenced on every instance - the ConditionType is shared, not copied. The obvious way to make
// AC-SVR-AC-073 pass is to deep-copy whatever the type pointed at into each instance, which multiplies
// the type system by the instance count and leaves each Client looking at a private ConditionType it
// cannot match against the one it read from the type. Two instances are built from the same type and
// three things are asserted: both carry the Reference, both name the same Node, and that Node is the
// ConditionType itself rather than a per-instance Object.
// @verifies AC-SVR-AC-074-HASCONDITION-TYPE-TARGET-SHARED
TEST_F(HasConditionInstantiationTest, AConditionTypeTargetIsSharedByEveryInstanceRatherThanCopied)
{
  auto first = instantiate_carrier("CarrierAlarmOne");
  ASSERT_NE(first, nullptr) << "the carrier type must instantiate through the Server's own path";
  auto second = instantiate_carrier("CarrierAlarmTwo");
  ASSERT_NE(second, nullptr) << "the carrier type must instantiate a second time";

  const auto firstTargets = browse_reference_targets(
    *mSession, first->condition_id(), NodeId{ReferenceTypeId::HasCondition}, BrowseDirection::Forward, true);
  const auto secondTargets = browse_reference_targets(
    *mSession, second->condition_id(), NodeId{ReferenceTypeId::HasCondition}, BrowseDirection::Forward, true);
  ASSERT_FALSE(firstTargets.empty()) << "the first instance carries no HasCondition Reference";
  ASSERT_FALSE(secondTargets.empty()) << "the second instance carries no HasCondition Reference";

  EXPECT_EQ(firstTargets.size(), secondTargets.size())
    << "the two instances of the same type carry different numbers of HasCondition Reference";
  for (const auto& target : firstTargets)
  {
    EXPECT_NE(std::find(secondTargets.begin(), secondTargets.end(), target), secondTargets.end())
      << "the first instance names the HasCondition target " << ua::to_string(target)
      << " and the second does not - the ConditionType was copied per instance instead of shared";
  }
  for (const auto& target : firstTargets)
  {
    EXPECT_EQ(target, NodeId{ObjectTypeId::CertificateExpirationAlarmType})
      << "the instance's HasCondition target " << ua::to_string(target)
      << " is not the ConditionType the type named";
    EXPECT_EQ(read_node_class(*mSession, target), NodeClass::ObjectType)
      << "the instance's HasCondition target " << ua::to_string(target)
      << " is not an ObjectType - a per-instance copy was created";
  }
}

// OPC 10000-9 5.12: a HasCondition used directly at instance level runs from an Object, a Variable or a
// Method to a Condition instance. The source set is wider than the type-level one - a Method may carry a
// Condition describing its own executability - and the target set is narrower: at instance level the
// Reference must land on a live Condition, not on a type. A Server that wires the Reference from the
// Condition back to itself, or that points it at the ConditionType it instantiated, publishes something
// a Client following HasCondition from a source cannot use. Both endpoints of every instance-level
// Reference the Server created are resolved and checked.
// @verifies AC-SVR-AC-075-HASCONDITION-IN-INSTANCE
TEST_F(ComplianceConditionTest, HasCondition_AtInstanceLevelRunsFromAnObjectVariableOrMethodToACondition)
{
  std::vector<NodeId> roots{NodeId{ObjectId::ObjectsFolder}, NodeId{ObjectId::Server}};
  for (const auto& conditionId : fixture_condition_ids(mConditionId,
         mAlarmId,
         mAckConditionId,
         mFullAlarmId,
         mDialogId,
         mExclusiveLimitId,
         mNonExclusiveLimitId,
         mOffNormalId))
  {
    roots.push_back(conditionId);
  }

  std::vector<NodeId> sources;
  std::vector<NodeId> targets;
  const auto perRoot = browse_reference_targets_batch(
    *mSession, roots, NodeId{ReferenceTypeId::HasCondition}, BrowseDirection::Forward, true);
  for (size_t i = 0; i < perRoot.size(); ++i)
  {
    for (const auto& target : perRoot[i])
    {
      sources.push_back(roots[i]);
      targets.push_back(target);
    }
  }
  ASSERT_FALSE(sources.empty())
    << "no instance-level HasCondition Reference was found - the Server publishes no route from a "
       "source to its Conditions, and the assertions below would assert over nothing";

  const auto targetIsCondition = types_derive_from(
    *mSession, type_definitions_of(*mSession, targets), NodeId{ObjectTypeId::ConditionType});

  for (size_t i = 0; i < sources.size(); ++i)
  {
    const auto sourceClass = read_node_class(*mSession, sources[i]);
    EXPECT_TRUE(sourceClass == NodeClass::Object || sourceClass == NodeClass::Variable ||
                sourceClass == NodeClass::Method)
      << "the instance-level HasCondition source " << ua::to_string(sources[i]) << " has NodeClass "
      << static_cast<int32_t>(sourceClass) << ", which is not an Object, a Variable or a Method";
    EXPECT_TRUE(targetIsCondition[i])
      << "the instance-level HasCondition target " << ua::to_string(targets[i])
      << " is not a Condition instance - it carries no type definition deriving from ConditionType";
  }
}

// ===========================================================================
// Communication failure and the Event fields it makes unavailable
// ===========================================================================

// OPC 10000-9 5.14.2: when communication with the underlying system fails, the address-space Variables
// backing the affected Event fields must read Value NULL with StatusCode Bad_CommunicationError. The
// sampled-input path is the natural place to lose this: a failed read of the bound input has no state to
// apply, so the straightforward implementation returns early and leaves every derived field serving the
// last good value with a Good status - a Client polling the alarm sees a healthy, quiet plant while the
// plant is unreachable. Communication is broken by removing the Node the alarm samples, which is the
// only break this fixture can drive; the live values are read first so "still holding its last value"
// is distinguishable from "never had one".
// @verifies AC-SVR-AC-076-COMMS-FAILURE-EVENT-FIELDS
// @relation(AC-SVR-AC-076-COMMS-FAILURE-EVENT-FIELDS, scope=function)
TEST_F(ComplianceLimitAlarmTest, EventFieldsBackedByAnUnreachableSystemReadBadRatherThanTheirLastValues)
{
  const auto severityId = find_hier_child(*mSession, mLimitAlarmId, String{"Severity"});
  ASSERT_FALSE(severityId.is_null()) << "Severity is Mandatory on ConditionType";
  const auto activeStateId = find_hier_child(*mSession, mLimitAlarmId, String{"ActiveState"});
  ASSERT_FALSE(activeStateId.is_null()) << "ActiveState is Mandatory on AlarmConditionType";
  const auto activeIdNode = find_hier_child(*mSession, activeStateId, String{"Id"});
  ASSERT_FALSE(activeIdNode.is_null()) << "ActiveState/Id is Mandatory on TwoStateVariableType";

  // Drive the alarm from the underlying system while communication is up, so the fields below hold live
  // values that came from the input rather than defaults.
  auto addressSpace = mServer.server().address_space();
  auto inputNode = addressSpace.find_node_sync(mInputNodeId);
  auto inputVar = inputNode.as<VariableAccessor>();
  ASSERT_TRUE(inputVar.has_value());
  inputVar->write_value_sync(95.0);
  mLimitAlarm->enable_sync();

  bool activated = false;
  for (int attempt = 0; attempt < 150 && !activated; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    activated = mLimitAlarm->snapshot()->active();
  }
  ASSERT_TRUE(activated) << "the alarm must activate from its bound input before communication is broken";

  const auto liveSeverity = read_value_with_timestamps(*mSession, severityId);
  ASSERT_FALSE(read_reported_bad(liveSeverity)) << "Severity must read while the input is reachable";
  const auto* liveSeverityValue = liveSeverity.value().try_as<uint16_t>();
  ASSERT_NE(liveSeverityValue, nullptr) << "Severity must read as a typed UInt16 while communication is up";
  const uint16_t lastGoodSeverity = *liveSeverityValue;

  const auto liveActive = read_value_with_timestamps(*mSession, activeIdNode);
  ASSERT_FALSE(read_reported_bad(liveActive)) << "ActiveState/Id must read while the input is reachable";
  const auto* liveActiveValue = liveActive.value().try_as<bool>();
  ASSERT_NE(liveActiveValue, nullptr) << "ActiveState/Id must read as a typed Boolean";
  ASSERT_TRUE(*liveActiveValue) << "the live ActiveState/Id must be True before communication is broken";

  // Break communication with the underlying system: the sampled input Node disappears, so every sample
  // the alarm takes from now on fails.
  const auto deleted =
    addressSpace.try_delete_node_sync(mInputNodeId, /*deleteForwardHierarchicallyReferencedNodes=*/false);
  ASSERT_FALSE(deleted.is_bad()) << "the bound input Node must be removable so the failure can be driven";
  std::this_thread::sleep_for(std::chrono::milliseconds(2500));  // > two 1000 ms sampling cycles

  const auto brokenSeverity = read_value_with_timestamps(*mSession, severityId);
  EXPECT_TRUE(read_reported_bad(brokenSeverity))
    << "Severity kept a Good status after communication with the underlying system was broken";
  EXPECT_EQ(
    brokenSeverity.status().value_or(StatusCode{Status::Good}), StatusCode{Status::BadCommunicationError})
    << "Severity must report Bad_CommunicationError once its backing system is unreachable";
  EXPECT_TRUE(brokenSeverity.value().empty())
    << "Severity must read NULL once its backing system is unreachable, not its last value ("
    << lastGoodSeverity << ")";

  const auto brokenActive = read_value_with_timestamps(*mSession, activeIdNode);
  EXPECT_TRUE(read_reported_bad(brokenActive))
    << "ActiveState/Id kept a Good status after communication with the underlying system was broken";
  EXPECT_EQ(
    brokenActive.status().value_or(StatusCode{Status::Good}), StatusCode{Status::BadCommunicationError})
    << "ActiveState/Id must report Bad_CommunicationError once its backing system is unreachable";
  EXPECT_TRUE(brokenActive.value().empty())
    << "ActiveState/Id must read NULL once its backing system is unreachable, not its last value";
}

// ===========================================================================
// TwoStateVariable: where its display labels live, and what its Id reads
// ===========================================================================

// Part 9 section 5.2 - the TrueState and FalseState Properties shall only exist on InstanceDeclarations.
// section 5.2 calls the two Properties "meta-data for the Type", and Figure 9 draws where they belong: the
// TwoStateVariable declared inside a Condition type - MyAlarmType/Acknowledge in the figure - carries
// TrueState and FalseState, and the same member on the instances MyAlarm1 and MyAlarm2 carries neither.
// A Client resolves the wording from the type once. A Server that copies the labels onto every instance
// republishes the same two LocalizedTexts per Alarm and invites a Client to write instance-specific
// wording into what the type declares, which is the same wording every other instance of that type reads.
// Note that this rule does NOT forbid the Properties on the type-definition Nodes: TwoStateVariableType
// declares both as Optional InstanceDeclarations (i=11110 / i=11111 in the standard NodeSet), and so does
// every TwoStateVariable InstanceDeclaration beneath a Condition type - those declarations ARE the
// InstanceDeclarations the clause permits. The declaration half is asserted beside the instances so a
// Server that carries the labels nowhere at all is not read as compliant either.
// @verifies AC-SVR-AC-121-TWOSTATE-LABELS
TEST_F(ComplianceConditionTest, TwoStateVariable_LabelPropertiesAppearOnlyOnInstanceDeclarations)
{
  struct TwoStateMember
  {
    NodeId type;
    NodeId instance;
    const char* member;
  };

  const std::vector<TwoStateMember> members{
    {NodeId{ObjectTypeId::ConditionType}, mConditionId, "EnabledState"},
    {NodeId{ObjectTypeId::AlarmConditionType}, mAlarmId, "ActiveState"},
    {NodeId{ObjectTypeId::AcknowledgeableConditionType}, mAckConditionId, "AckedState"}};

  size_t declarationsCarryingLabels = 0;
  size_t instancesSurveyed = 0;
  for (const auto& member : members)
  {
    const auto declarationId = find_hier_child(*mSession, member.type, String{member.member});
    ASSERT_FALSE(declarationId.is_null())
      << member.member << " is a Mandatory member of " << ua::to_string(member.type)
      << " and must be browsable on the type";
    const auto instanceId = find_hier_child(*mSession, member.instance, String{member.member});
    ASSERT_FALSE(instanceId.is_null()) << member.member << " is Mandatory and must be materialised on the "
                                       << "instance " << ua::to_string(member.instance);

    // Control: a Property of the instance's TwoStateVariable IS visible to this browse - Id is Mandatory
    // on TwoStateVariableType - so an absent TrueState below is genuinely absent rather than invisible.
    ASSERT_FALSE(find_hier_child(*mSession, instanceId, String{"Id"}).is_null())
      << "the TwoStateVariable " << ua::to_string(instanceId)
      << " exposes no Id, so this browse sees none of its Properties and the absences asserted below "
         "would prove nothing";

    if (!find_hier_child(*mSession, declarationId, String{"TrueState"}).is_null())
      ++declarationsCarryingLabels;
    ++instancesSurveyed;

    for (const char* label : {"TrueState", "FalseState"})
    {
      const auto labelId = find_hier_child(*mSession, instanceId, String{label});
      EXPECT_TRUE(labelId.is_null())
        << "the TwoStateVariable " << ua::to_string(instanceId) << " on an instance of "
        << ua::to_string(member.type) << " carries a " << label << " Property (" << ua::to_string(labelId)
        << "); the labels are meta-data for the Type and exist only on its InstanceDeclaration";
    }
  }

  ASSERT_EQ(instancesSurveyed, members.size())
    << "not every surveyed TwoStateVariable member was reached, so the absences checked nothing";
  EXPECT_GT(declarationsCarryingLabels, 0u)
    << "not one of the " << members.size()
    << " surveyed TwoStateVariable InstanceDeclarations carries a TrueState Property - the labels exist "
       "nowhere, so no Client can render either state";
}

// Part 9 section 5.2 - a TwoStateVariable's Id value shall be the current state, either True or False.
// The clause is about every TwoStateVariable the Server publishes, not only the two a Condition
// special-cases: a Server that keeps its state in the parent Variable's LocalizedText and materialises
// `Id` as an inert Property nobody writes serves a null or a stale default on the per-limit and optional
// sub-states, and a Client reading them is told the alarm is in a state it left long ago. Every
// TwoStateVariable reachable on a full-featured alarm and on a NonExclusive limit alarm is therefore
// surveyed, and one of them is watched across a real state change so a uniformly False survey cannot pass.
// @verifies AC-SVR-AC-120-TWOSTATE-ID-BOOLEAN
TEST_F(ComplianceConditionTest, EveryTwoStateVariablesIdReadsAsTheCurrentBooleanState)
{
  mFullAlarm->enable_sync();
  mNonExclusiveLimit->enable_sync();

  const std::vector<NodeId> owners{mFullAlarmId, mNonExclusiveLimitId};
  std::vector<NodeId> members;
  for (const auto& perOwner : browse_reference_targets_batch(
         *mSession, owners, NodeId{ReferenceTypeId::HierarchicalReferences}, BrowseDirection::Forward, true))
  {
    members.insert(members.end(), perOwner.begin(), perOwner.end());
  }
  ASSERT_FALSE(members.empty()) << "the alarms under survey expose no hierarchical members at all";

  const auto memberIsTwoState = types_derive_from(
    *mSession, type_definitions_of(*mSession, members), NodeId{VariableTypeId::TwoStateVariableType});

  size_t twoStateVariablesChecked = 0;
  for (size_t i = 0; i < members.size(); ++i)
  {
    if (!memberIsTwoState[i])
      continue;
    const auto idNode = find_hier_child(*mSession, members[i], String{"Id"});
    EXPECT_FALSE(idNode.is_null()) << "the TwoStateVariable " << ua::to_string(members[i])
                                   << " exposes no Id, so its current state is unreadable";
    if (idNode.is_null())
      continue;
    ++twoStateVariablesChecked;

    const auto dv = read_value_dv(*mSession, idNode);
    EXPECT_FALSE(read_reported_bad(dv)) << "the Id of the TwoStateVariable " << ua::to_string(members[i])
                                        << " reads a Bad status instead of its current state";
    EXPECT_NE(dv.value().try_as<bool>(), nullptr)
      << "the Id of the TwoStateVariable " << ua::to_string(members[i])
      << " does not read as a Boolean - it must be True or False, never null or another type";
  }
  ASSERT_GT(twoStateVariablesChecked, 0u)
    << "no TwoStateVariable was found beneath the surveyed alarms, so the reads above checked nothing";

  // The value must be the CURRENT state, so one of the surveyed Variables is moved and read again.
  const auto activeStateId = find_hier_child(*mSession, mFullAlarmId, String{"ActiveState"});
  ASSERT_FALSE(activeStateId.is_null()) << "ActiveState is Mandatory on AlarmConditionType";
  const auto activeIdNode = find_hier_child(*mSession, activeStateId, String{"Id"});
  ASSERT_FALSE(activeIdNode.is_null()) << "ActiveState/Id is Mandatory on TwoStateVariableType";

  // The DataValue is held in a named local: `try_as` hands back a pointer into its storage, and reading
  // through that pointer after a temporary DataValue died is a use-after-scope.
  const auto beforeDv = read_value_dv(*mSession, activeIdNode);
  const auto* beforeId = beforeDv.value().try_as<bool>();
  ASSERT_NE(beforeId, nullptr) << "ActiveState/Id must read as a Boolean before the alarm activates";
  const bool before = *beforeId;

  mFullAlarm->activate_sync(500);
  ASSERT_TRUE(mFullAlarm->snapshot()->active()) << "the alarm must have activated for the read to move";

  const auto after = read_value_dv(*mSession, activeIdNode);
  const auto* afterId = after.value().try_as<bool>();
  ASSERT_NE(afterId, nullptr) << "ActiveState/Id must still read as a Boolean once the alarm is active";
  EXPECT_TRUE(*afterId) << "ActiveState/Id read False while the alarm is active - it is not the current "
                           "state";
  EXPECT_NE(before, *afterId) << "ActiveState/Id did not move when the state moved";
}

// ===========================================================================
// Alarm grouping: FirstInGroupFlag and the Object it names
// ===========================================================================

// Part 9 section 5.8.2 - if the FirstInGroupFlag Variable is present, then the FirstInGroup Object shall also
// be present. The flag asserts "this Alarm was the first of its group to go active" and the Object says which
// group; exposing the flag alone publishes an assertion with no subject, and a Client that wants to show
// the operator the originating alarm of a flood has a Boolean it cannot attribute to anything. Both are
// Optional, so the pairing is checked wherever the flag is found - across the AlarmConditionType
// hierarchy and the Server's own alarm instances - and the survey asserts it found the flag somewhere.
// @verifies AC-SVR-AC-105-FIRSTINGROUPFLAG-NEEDS-GROUP
TEST_F(ComplianceConditionTest, FirstInGroupFlag_IsExposedOnlyBesideItsFirstInGroupObject)
{
  const NodeId alarmType{ObjectTypeId::AlarmConditionType};
  std::vector<NodeId> alarmNodes{alarmType, mAlarmId, mFullAlarmId, mExclusiveLimitId, mOffNormalId};
  for (const auto& subtype : browse_reference_targets(
         *mSession, alarmType, NodeId{ReferenceTypeId::HasSubtype}, BrowseDirection::Forward, false))
  {
    alarmNodes.push_back(subtype);
  }

  size_t flagHolders = 0;
  for (const auto& node : alarmNodes)
  {
    const auto flagId = find_hier_child(*mSession, node, String{"FirstInGroupFlag"});
    if (flagId.is_null())
      continue;
    ++flagHolders;
    EXPECT_FALSE(find_hier_child(*mSession, node, String{"FirstInGroup"}).is_null())
      << "the Alarm " << ua::to_string(node) << " exposes FirstInGroupFlag (" << ua::to_string(flagId)
      << ") but not the FirstInGroup Object the flag is about";
  }
  ASSERT_GT(flagHolders, 0u) << "none of the " << alarmNodes.size()
                             << " surveyed Alarm Nodes exposes FirstInGroupFlag, so the pairing rule was "
                                "never exercised";
}

// ===========================================================================
// LimitAlarm threshold ordering
// ===========================================================================

// Part 9 section 5.8.18 - the limits shall follow the inequality HighHigh > High > Low > LowLow.
// Out of order the exclusive limit states stop being decidable: a High threshold below the Low one puts a
// process value in two limit states at once, or in none, and every consumer that assumes a single active
// limit state then reads a stale or arbitrary one. The limits are read back over the wire rather than
// taken from the fixture's configuration, so a Server that publishes a configured threshold into the wrong
// Property is caught here as readily as one that accepts a mis-ordered configuration. The fixture's own
// two alarms are configured in order, though, so the survey over them alone would hold of a Server that
// publishes whatever it is handed; a mis-ordered configuration is therefore offered through the same API
// before the survey runs. The Server may refuse it - refusing is one way to satisfy the clause - but if it
// accepts one, the alarm it produced is surveyed with the rest and its published limits must still order.
// @verifies AC-SVR-AC-203-LIMIT-INEQUALITY
TEST_F(ComplianceConditionTest, EveryLimitAlarmsDeclaredLimitsFollowTheHighHighToLowLowOrdering)
{
  struct DeclaredLimit
  {
    const char* name;
    double value;
  };

  std::vector<NodeId> surveyed{mExclusiveLimitId, mNonExclusiveLimitId};

  auto misOrderedLogic = std::make_unique<LimitAlarmLogic>();
  misOrderedLogic->set_exclusive(true);
  bool misOrderedRefused = false;
  try
  {
    LimitConfig inverted;
    inverted.highHighLimit = 10.0;  // below the High limit the inequality requires it to exceed
    inverted.highLimit = 90.0;
    misOrderedLogic->set_limits(inverted);
  }
  catch (const std::exception&)
  {
    misOrderedRefused = true;  // the configuration never took effect, so no mis-ordered pair is published
  }
  if (!misOrderedRefused)
  {
    auto created = mServer.server().conditions().try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"MisOrderedLimitAlarm"},
      std::move(misOrderedLogic),
      NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
    EXPECT_TRUE(created.is_good())
      << "a mis-ordered limit configuration was accepted by the logic and then produced no alarm, so "
         "neither the refusal nor the publication of the mis-ordered pair can be judged";
    if (created.is_good())
      surveyed.push_back(created.value()->condition_id());
  }

  size_t alarmsWithLimits = 0;
  for (const auto& alarmId : surveyed)
  {
    // Read in descending order of the inequality, so consecutive pairs are exactly the comparisons.
    std::vector<DeclaredLimit> declared;
    for (const char* name : {"HighHighLimit", "HighLimit", "LowLimit", "LowLowLimit"})
    {
      const auto propertyId = find_hier_child(*mSession, alarmId, String{name});
      if (propertyId.is_null())
        continue;
      const auto dv = read_value_dv(*mSession, propertyId);
      EXPECT_FALSE(read_reported_bad(dv)) << "the LimitAlarm " << ua::to_string(alarmId) << " declares "
                                          << name << " but reading it reports a Bad status";
      const auto* value = dv.value().try_as<double>();
      if (value == nullptr)
        continue;
      declared.push_back(DeclaredLimit{name, *value});
    }

    if (declared.size() < 2)
      continue;
    ++alarmsWithLimits;
    for (size_t i = 1; i < declared.size(); ++i)
    {
      EXPECT_GT(declared[i - 1].value, declared[i].value)
        << "the LimitAlarm " << ua::to_string(alarmId) << " declares " << declared[i - 1].name << " = "
        << declared[i - 1].value << " and " << declared[i].name << " = " << declared[i].value
        << ", which breaks HighHigh > High > Low > LowLow";
    }
  }
  ASSERT_GT(alarmsWithLimits, 0u)
    << "no LimitAlarm published two or more readable limits, so the inequality was never compared";
}

// ===========================================================================
// DiscrepancyAlarm: the ExpectedTime window
// ===========================================================================

/// Two DiscrepancyAlarms driven from bound inputs: one whose input never reaches the target, and one whose
/// input reaches it well inside a generous ExpectedTime. Both are needed because the obligation is about
/// the DURATION of a mismatch - an implementation that alarms on the mismatch itself passes the first arm
/// and fails the second.
class DiscrepancyAlarmWindowTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto addressSpace = mServer.server().address_space();
    auto& conditions = mServer.server().conditions();

    mMissingInputId = NodeId{0, uint32_t{50101}};
    auto missingNode = addressSpace.create_node_sync(mMissingInputId, NodeClass::Variable);
    auto missingVar = missingNode.as<VariableAccessor>();
    ASSERT_TRUE(missingVar.has_value());
    missingVar->set_browse_name(QualifiedName{0, "DiscrepancyInputThatMisses"});
    missingVar->set_display_name(LocalizedText{"", "DiscrepancyInputThatMisses"});
    missingVar->set_data_type(NodeId{DataTypeId::Double});
    missingVar->write_value_sync(0.0);
    missingVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    mReachingInputId = NodeId{0, uint32_t{50102}};
    auto reachingNode = addressSpace.create_node_sync(mReachingInputId, NodeClass::Variable);
    auto reachingVar = reachingNode.as<VariableAccessor>();
    ASSERT_TRUE(reachingVar.has_value());
    reachingVar->set_browse_name(QualifiedName{0, "DiscrepancyInputThatReaches"});
    reachingVar->set_display_name(LocalizedText{"", "DiscrepancyInputThatReaches"});
    reachingVar->set_data_type(NodeId{DataTypeId::Double});
    reachingVar->write_value_sync(0.0);
    reachingVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMissingInputId);
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mReachingInputId);

    auto missingLogic = std::make_unique<DiscrepancyAlarmLogic>();
    missingLogic->set_target_value(Variant{sTargetValue});
    missingLogic->set_expected_time(sShortExpectedTimeMs);
    auto missingResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"DiscrepancyMissesTarget"},
      std::move(missingLogic),
      NodeId{ObjectTypeId::DiscrepancyAlarmType});
    if (missingResult.is_good())
    {
      mMissingAlarm = missingResult.value();
      mMissingAlarm->bind_input_sync(mMissingInputId, sSamplingIntervalMs);
    }

    auto reachingLogic = std::make_unique<DiscrepancyAlarmLogic>();
    reachingLogic->set_target_value(Variant{sTargetValue});
    reachingLogic->set_expected_time(sLongExpectedTimeMs);
    auto reachingResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"DiscrepancyReachesTarget"},
      std::move(reachingLogic),
      NodeId{ObjectTypeId::DiscrepancyAlarmType});
    if (reachingResult.is_good())
    {
      mReachingAlarm = reachingResult.value();
      mReachingAlarm->bind_input_sync(mReachingInputId, sSamplingIntervalMs);
    }
  }

  static constexpr double sTargetValue = 100.0;
  static constexpr double sShortExpectedTimeMs = 300.0;
  static constexpr double sLongExpectedTimeMs = 3000.0;
  static constexpr double sSamplingIntervalMs = 100.0;

  NodeId mMissingInputId;
  NodeId mReachingInputId;
  std::shared_ptr<ConditionInstance> mMissingAlarm;
  std::shared_ptr<ConditionInstance> mReachingAlarm;
};

// Part 9 section 5.8.25 - the ExpectedTime Property provides the Duration within which the value pointed to
// by the InputNode shall equal the value specified by the TargetValueNode. The alarm is about how long the
// two disagree, not about their disagreeing: a valve, a damper or a drive takes time to travel, so an
// implementation that compares the values and activates when they differ raises an alarm on every normal
// commanded movement. Both arms are driven from bound inputs over the Server's own sampling path - one
// input never reaches its target and must activate its alarm, the other reaches its target well inside a
// ten-times-longer window and must not.
// @verifies AC-SVR-AC-219-DISCREPANCY-EXPECTEDTIME
TEST_F(DiscrepancyAlarmWindowTest, DiscrepancyAlarm_ActivatesOnlyWhenTheTargetIsMissedForLongerThanExpected)
{
  ASSERT_NE(mMissingAlarm, nullptr) << "a DiscrepancyAlarmType Condition could not be created at all";
  ASSERT_NE(mReachingAlarm, nullptr) << "the second DiscrepancyAlarmType Condition could not be created";

  mMissingAlarm->enable_sync();
  mReachingAlarm->enable_sync();

  // The second alarm's input arrives at the target immediately - far inside its 3 s ExpectedTime.
  auto addressSpace = mServer.server().address_space();
  auto reachingNode = addressSpace.find_node_sync(mReachingInputId);
  auto reachingVar = reachingNode.as<VariableAccessor>();
  ASSERT_TRUE(reachingVar.has_value());
  reachingVar->write_value_sync(sTargetValue);

  bool missingActivated = false;
  for (int attempt = 0; attempt < 150 && !missingActivated; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    missingActivated = mMissingAlarm->snapshot()->active();
  }
  EXPECT_TRUE(missingActivated) << "the input stayed away from its target for far longer than the "
                                << sShortExpectedTimeMs
                                << " ms ExpectedTime and the DiscrepancyAlarm never activated";

  // Well past the second alarm's own ExpectedTime, measured from the moment its input reached the target.
  std::this_thread::sleep_for(std::chrono::milliseconds(3500));
  EXPECT_FALSE(mReachingAlarm->snapshot()->active())
    << "the input reached its target immediately, inside a " << sLongExpectedTimeMs
    << " ms ExpectedTime, and the DiscrepancyAlarm activated anyway - it is alarming on the mismatch "
       "rather than on its duration";
}

// ===========================================================================
// The comment-bearing Method variants: refusal rules and audit obligations
// ===========================================================================

/// An alarm whose logic declares a MaxTimeShelved, so the shelving bound the section 5.8.17 Methods share can
/// be crossed. The fixture's own alarms leave the bound unset, in which case there is nothing to exceed.
class BoundedShelvingAlarmTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto logic = std::make_unique<AlarmConditionLogic>();
    logic->set_supports_confirm(true);
    logic->set_max_time_shelved(sMaxTimeShelvedMs);
    mBoundedAlarm = mServer.server().conditions().create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"BoundedShelvingAlarm"},
      std::move(logic),
      NodeId{ObjectTypeId::AlarmConditionType});
    mBoundedAlarmId = mBoundedAlarm->condition_id();
  }

  static constexpr double sMaxTimeShelvedMs = 2000.0;

  NodeId mBoundedAlarmId;
  std::shared_ptr<ConditionInstance> mBoundedAlarm;
};

// Part 9 section 5.8.17.5 - if a MaxTimeShelved Property exists on the Alarm then the shelving time given to
// TimedShelve2 shall be less than or equal to it. TimedShelve2 is a separate Method node from TimedShelve
// with its own dispatch entry, so a Server that guards the original and forwards the comment-bearing
// variant straight to the shelve path lets an operator hide an alarm indefinitely by calling the newer
// Method - the bound exists precisely so that cannot happen. Two controls follow the assertion: the same
// over-long duration is refused by the original Method, so MaxTimeShelved is in force at all, and a
// duration inside the bound is accepted, so the refusals are about the bound and not about shelving.
// @relation(AC-SVR-AC-140-TIMEDSHELVE2-MAXTIME, scope=function)
TEST_F(BoundedShelvingAlarmTest, TimedShelve2_IsRefusedWhenTheShelvingTimeExceedsMaxTimeShelved)
{
  mBoundedAlarm->enable_sync();
  mBoundedAlarm->activate_sync(500);

  const auto shelvingStateId = find_child_via_browse(mBoundedAlarmId, "ShelvingState");
  ASSERT_FALSE(shelvingStateId.is_null()) << "the alarm exposes no ShelvingState Object";
  ASSERT_FALSE(find_method_via_browse(shelvingStateId, "TimedShelve2").is_null())
    << "the ShelvingState exposes no TimedShelve2 Method, so the MaxTimeShelved bound cannot be shown to "
       "apply to it";

  const auto overMax = call_child_method(mBoundedAlarmId,
    "ShelvingState",
    "TimedShelve2",
    Array<Variant>{Variant{sMaxTimeShelvedMs * 2.0}, Variant{LocalizedText{"", "shelved for a long shift"}}});
  EXPECT_EQ(overMax, StatusCode{Status::BadShelvingTimeOutOfRange})
    << "TimedShelve2 with a ShelvingTime of " << (sMaxTimeShelvedMs * 2.0) << " ms against a MaxTimeShelved "
    << "of " << sMaxTimeShelvedMs << " ms returned " << overMax.as_uint32()
    << " instead of Bad_ShelvingTimeOutOfRange";

  const auto originalOverMax = call_child_method(
    mBoundedAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{sMaxTimeShelvedMs * 2.0}});
  ASSERT_EQ(originalOverMax, StatusCode{Status::BadShelvingTimeOutOfRange})
    << "the original TimedShelve did not enforce MaxTimeShelved either (got " << originalOverMax.as_uint32()
    << "), so the bound is not in force on this alarm and the assertion above proves nothing";

  const auto withinMax = call_child_method(
    mBoundedAlarmId, "ShelvingState", "TimedShelve", Array<Variant>{Variant{sMaxTimeShelvedMs / 2.0}});
  ASSERT_TRUE(withinMax.is_good()) << "a ShelvingTime inside MaxTimeShelved was refused with "
                                   << withinMax.as_uint32() << ", so the alarm cannot be shelved at all";
}

// Part 9 section 5.8.11 - if Auditing is supported, Unsuppress2 shall generate an Event of
// AuditConditionSuppressionEventType for all invocations of the Method. The comment-bearing variant is a
// distinct Method node with its own dispatch entry, and audit emission wired per entry is exactly what an
// implementation adding the newer overload forgets: the suppression is lifted, the alarm reappears, and
// the trail an auditor reads shows nobody touched it.
// @relation(AC-SVR-AC-130-UNSUPPRESS2-AUDIT, scope=function)
TEST_F(ComplianceConditionAuditingEnabledTest, Unsuppress2_RaisesAnAuditConditionSuppressionEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->suppress_sync();
  ASSERT_FALSE(find_method_via_browse(mFullAlarmId, "Unsuppress2").is_null())
    << "the alarm exposes no Unsuppress2 Method, so its audit obligation cannot be discharged";

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionSuppressionEventType}));

  const auto status = call_condition_method(
    mFullAlarmId, "Unsuppress2", Array<Variant>{Variant{LocalizedText{"", "unsuppressed by the operator"}}});

  bool sawAudit = false;
  size_t collected = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawAudit && std::chrono::steady_clock::now() < deadline)
  {
    for (const auto& event : collect_events(10))
    {
      ++collected;
      if (event_type_from(event) == NodeId{ObjectTypeId::AuditConditionSuppressionEventType})
        sawAudit = true;
    }
  }
  EXPECT_TRUE(sawAudit) << "Unsuppress2 returned " << status.as_uint32()
                        << " and no AuditConditionSuppressionEventType was raised (of " << collected
                        << " events seen)";
}

// Part 9 section 5.8.13 - if Auditing is supported, RemoveFromService2 shall generate an Event of
// AuditConditionOutOfServiceEventType for all invocations of the Method. Taking an alarm out of service
// stops it reporting altogether, which is the single most consequential thing an operator can do to it, so
// the audit record is what lets a reviewer find out who silenced the plant and when.
// @relation(AC-SVR-AC-134-REMOVEFROMSERVICE2-AUDIT, scope=function)
TEST_F(ComplianceConditionAuditingEnabledTest, RemoveFromService2_RaisesAnAuditConditionOutOfServiceEvent)
{
  mFullAlarm->enable_sync();
  ASSERT_FALSE(find_method_via_browse(mFullAlarmId, "RemoveFromService2").is_null())
    << "the alarm exposes no RemoveFromService2 Method, so its audit obligation cannot be discharged";

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType}));

  const auto status = call_condition_method(mFullAlarmId,
    "RemoveFromService2",
    Array<Variant>{Variant{LocalizedText{"", "removed from service for maintenance"}}});

  bool sawAudit = false;
  size_t collected = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawAudit && std::chrono::steady_clock::now() < deadline)
  {
    for (const auto& event : collect_events(10))
    {
      ++collected;
      if (event_type_from(event) == NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType})
        sawAudit = true;
    }
  }
  EXPECT_TRUE(sawAudit) << "RemoveFromService2 returned " << status.as_uint32()
                        << " and no AuditConditionOutOfServiceEventType was raised (of " << collected
                        << " events seen)";
}

// Part 9 section 5.8.15 - if Auditing is supported, PlaceInService2 shall generate an Event of
// AuditConditionOutOfServiceEventType for all invocations of the Method. Returning an alarm to service is
// the other half of the record: an audit trail carrying only the removals leaves a reviewer unable to tell
// an alarm that is still suppressed today from one that was restored minutes later.
// @relation(AC-SVR-AC-136-PLACEINSERVICE2-AUDIT, scope=function)
TEST_F(ComplianceConditionAuditingEnabledTest, PlaceInService2_RaisesAnAuditConditionOutOfServiceEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->remove_from_service_sync();
  ASSERT_FALSE(find_method_via_browse(mFullAlarmId, "PlaceInService2").is_null())
    << "the alarm exposes no PlaceInService2 Method, so its audit obligation cannot be discharged";

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType}));

  const auto status = call_condition_method(
    mFullAlarmId, "PlaceInService2", Array<Variant>{Variant{LocalizedText{"", "returned to service"}}});

  bool sawAudit = false;
  size_t collected = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawAudit && std::chrono::steady_clock::now() < deadline)
  {
    for (const auto& event : collect_events(10))
    {
      ++collected;
      if (event_type_from(event) == NodeId{ObjectTypeId::AuditConditionOutOfServiceEventType})
        sawAudit = true;
    }
  }
  EXPECT_TRUE(sawAudit) << "PlaceInService2 returned " << status.as_uint32()
                        << " and no AuditConditionOutOfServiceEventType was raised (of " << collected
                        << " events seen)";
}

// Part 9 section 5.8.17.3 - if Auditing is supported, Unshelve2 shall generate an Event of
// AuditConditionShelvingEventType for all invocations of the Method. Unshelving is the transition that
// puts an alarm back in front of an operator, so an unaudited one leaves a reviewer unable to establish
// when the alarm became visible again.
// @relation(AC-SVR-AC-138-UNSHELVE2-AUDIT, scope=function)
TEST_F(ComplianceConditionAuditingEnabledTest, Unshelve2_RaisesAnAuditConditionShelvingEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);
  mFullAlarm->timed_shelve_sync(5000.0);

  const auto shelvingStateId = find_child_via_browse(mFullAlarmId, "ShelvingState");
  ASSERT_FALSE(shelvingStateId.is_null()) << "the alarm exposes no ShelvingState Object";
  ASSERT_FALSE(find_method_via_browse(shelvingStateId, "Unshelve2").is_null())
    << "the ShelvingState exposes no Unshelve2 Method, so its audit obligation cannot be discharged";

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionShelvingEventType}));

  const auto status = call_child_method(mFullAlarmId,
    "ShelvingState",
    "Unshelve2",
    Array<Variant>{Variant{LocalizedText{"", "unshelved by the operator"}}});

  bool sawAudit = false;
  size_t collected = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawAudit && std::chrono::steady_clock::now() < deadline)
  {
    for (const auto& event : collect_events(10))
    {
      ++collected;
      if (event_type_from(event) == NodeId{ObjectTypeId::AuditConditionShelvingEventType})
        sawAudit = true;
    }
  }
  EXPECT_TRUE(sawAudit) << "Unshelve2 returned " << status.as_uint32()
                        << " and no AuditConditionShelvingEventType was raised (of " << collected
                        << " events seen)";
}

// Part 9 section 5.8.17.5 - if Auditing is supported, TimedShelve2 shall generate an Event of
// AuditConditionShelvingEventType for all invocations of the Method. Timed shelving hides an alarm for a
// duration the operator chooses, and the audit Event carrying that invocation is what tells a reviewer how
// long the silence was meant to last; an unaudited call leaves a gap in the display that nothing explains.
// @relation(AC-SVR-AC-141-TIMEDSHELVE2-AUDIT, scope=function)
TEST_F(ComplianceConditionAuditingEnabledTest, TimedShelve2_RaisesAnAuditConditionShelvingEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  const auto shelvingStateId = find_child_via_browse(mFullAlarmId, "ShelvingState");
  ASSERT_FALSE(shelvingStateId.is_null()) << "the alarm exposes no ShelvingState Object";
  ASSERT_FALSE(find_method_via_browse(shelvingStateId, "TimedShelve2").is_null())
    << "the ShelvingState exposes no TimedShelve2 Method, so its audit obligation cannot be discharged";

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionShelvingEventType}));

  const auto status = call_child_method(mFullAlarmId,
    "ShelvingState",
    "TimedShelve2",
    Array<Variant>{Variant{5000.0}, Variant{LocalizedText{"", "shelved for five seconds"}}});

  bool sawAudit = false;
  size_t collected = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawAudit && std::chrono::steady_clock::now() < deadline)
  {
    for (const auto& event : collect_events(10))
    {
      ++collected;
      if (event_type_from(event) == NodeId{ObjectTypeId::AuditConditionShelvingEventType})
        sawAudit = true;
    }
  }
  EXPECT_TRUE(sawAudit) << "TimedShelve2 returned " << status.as_uint32()
                        << " and no AuditConditionShelvingEventType was raised (of " << collected
                        << " events seen)";
}

// Part 9 section 5.8.17.7 - if Auditing is supported, OneShotShelve2 shall generate an Event of
// AuditConditionShelvingEventType for all invocations of the Method. This is the third of the shelving
// Methods that share the audit type, and the one whose effect lasts until the alarm next goes inactive, so
// the record of who invoked it is the only account of why the alarm stayed hidden.
// @relation(AC-SVR-AC-143-ONESHOTSHELVE2-AUDIT, scope=function)
TEST_F(ComplianceConditionAuditingEnabledTest, OneShotShelve2_RaisesAnAuditConditionShelvingEvent)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  const auto shelvingStateId = find_child_via_browse(mFullAlarmId, "ShelvingState");
  ASSERT_FALSE(shelvingStateId.is_null()) << "the alarm exposes no ShelvingState Object";
  ASSERT_FALSE(find_method_via_browse(shelvingStateId, "OneShotShelve2").is_null())
    << "the ShelvingState exposes no OneShotShelve2 Method, so its audit obligation cannot be discharged";

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditConditionShelvingEventType}));

  const auto status = call_child_method(mFullAlarmId,
    "ShelvingState",
    "OneShotShelve2",
    Array<Variant>{Variant{LocalizedText{"", "shelved until it clears"}}});

  bool sawAudit = false;
  size_t collected = 0;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawAudit && std::chrono::steady_clock::now() < deadline)
  {
    for (const auto& event : collect_events(10))
    {
      ++collected;
      if (event_type_from(event) == NodeId{ObjectTypeId::AuditConditionShelvingEventType})
        sawAudit = true;
    }
  }
  EXPECT_TRUE(sawAudit) << "OneShotShelve2 returned " << status.as_uint32()
                        << " and no AuditConditionShelvingEventType was raised (of " << collected
                        << " events seen)";
}

// ===========================================================================
// AlarmMetrics: its mandatory components, its rate windows, and Reset's codes
// ===========================================================================

/// An AlarmMetricsType Object materialised through the Server's own instantiation service, so what is
/// browsed below is the Server's projection of the Part 9 section 9.2 type rather than a hand-built stand-in.
class AlarmMetricsInstanceTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    InstantiationService instantiation{mServer.server().address_space()};
    InstantiationOptions options;

    std::promise<NodeSubtreeResult> promise;
    instantiation.instantiate_object_async(NodeId{ObjectId::ObjectsFolder},
      QualifiedName{0, "ServerAlarmMetrics"},
      NodeId{ObjectTypeId::AlarmMetricsType},
      options,
      [&promise](NodeSubtreeResult result) { promise.set_value(std::move(result)); });

    auto result = promise.get_future().get();
    if (result.is_good())
    {
      auto subtree = std::move(result).value();
      mMetricsId = subtree.root();
      subtree.release();
    }
  }

  NodeId mMetricsId;
};

// Part 9 section 9.2 Table 145 - an AlarmMetricsType Object carries AlarmCount, StartTime,
// MaximumActiveState, MaximumUnAck, CurrentAlarmRate, MaximumAlarmRate, MaximumReAlarmCount and
// AverageAlarmRate as Mandatory components, plus the Mandatory Reset Method. Every one of them is Mandatory
// because the numbers are meaningless apart: a count without the StartTime it was accumulated from cannot be
// turned into a rate, and a rate without the maximum beside it cannot be judged. A Server that materialises
// the handful of components its own implementation happens to compute publishes an Object a Client cannot
// interpret.
// @verifies AC-SVR-AC-212-ALARMMETRICS-COMPONENTS
TEST_F(AlarmMetricsInstanceTest, AlarmMetrics_ExposesEveryMandatoryComponent)
{
  ASSERT_FALSE(mMetricsId.is_null())
    << "no AlarmMetricsType Object could be instantiated, so its components were never browsed";

  for (const char* component : {"AlarmCount",
         "StartTime",
         "MaximumActiveState",
         "MaximumUnAck",
         "CurrentAlarmRate",
         "MaximumAlarmRate",
         "MaximumReAlarmCount",
         "AverageAlarmRate"})
  {
    EXPECT_FALSE(find_hier_child(*mSession, mMetricsId, String{component}).is_null())
      << "the AlarmMetricsType Object " << ua::to_string(mMetricsId) << " exposes no " << component
      << ", which Table 145 declares Mandatory";
  }

  EXPECT_FALSE(find_method_via_browse(mMetricsId, "Reset").is_null())
    << "the AlarmMetricsType Object " << ua::to_string(mMetricsId)
    << " exposes no Reset Method, which Table 145 declares Mandatory";
}

// Part 9 section 9.3 Table 146 - every AlarmRateVariableType Variable carries a Mandatory Rate Property
// giving the number of minutes the rate is calculated over. A Double called "AlarmRate" with no window beside
// it is not a rate at all, and the window is in MINUTES where the rest of the SDK's rates are per second, so
// a Client that assumes the usual convention is wrong by a factor of sixty and its trend line is silently
// mis-scaled. Each of the three AlarmRateVariableType components is checked for the Property and for the
// UInt16 DataType that carries the minute count.
// @verifies AC-SVR-AC-214-ALARMRATE-RATE-MANDATORY
TEST_F(AlarmMetricsInstanceTest, AlarmRateVariables_DeclareTheRateWindowTheyAreComputedOver)
{
  ASSERT_FALSE(mMetricsId.is_null())
    << "no AlarmMetricsType Object could be instantiated, so no AlarmRateVariable was reached";

  size_t rateVariablesChecked = 0;
  for (const char* rateVariable : {"CurrentAlarmRate", "MaximumAlarmRate", "AverageAlarmRate"})
  {
    const auto rateVariableId = find_hier_child(*mSession, mMetricsId, String{rateVariable});
    ASSERT_FALSE(rateVariableId.is_null())
      << rateVariable << " is a Mandatory AlarmRateVariableType component of AlarmMetricsType";
    ++rateVariablesChecked;

    const auto rateProperty = find_hier_child(*mSession, rateVariableId, String{"Rate"});
    EXPECT_FALSE(rateProperty.is_null())
      << "the AlarmRateVariable " << rateVariable << " (" << ua::to_string(rateVariableId)
      << ") exposes no Rate Property, so the window its Double is computed over is unknowable";
    if (rateProperty.is_null())
      continue;

    const auto dataType = read_data_type(*mSession, rateProperty);
    EXPECT_EQ(dataType, (NodeId{uint32_t{0}, static_cast<uint32_t>(DataTypeId::UInt16)}))
      << "the Rate Property of " << rateVariable << " has DataType " << ua::to_string(dataType)
      << " rather than UInt16, the type Table 146 gives the minute count";
  }
  ASSERT_EQ(rateVariablesChecked, 3u)
    << "fewer than the three Mandatory AlarmRateVariableType components were reached";
}

// Part 9 section 9.4 Table 147 - Reset answers Bad_MethodInvalid when the MethodId provided does not
// correspond to the ObjectId provided, and a not-valid-Object code when the specified ObjectId is not valid.
// The two are easy to collapse into one generic refusal, and a Client cannot then tell a mis-paired call it
// can fix by re-browsing from an ObjectId it cannot use at all. The correct pairing is exercised between them
// as a control: whatever it answers, it must not be Bad_MethodInvalid, or the code asserted above would be
// what this Method returns to everybody. The invalid ObjectId is the null NodeId, which Part 3 section 8.2
// says no Node in the AddressSpace carries. Part 4 Table 67 - the Call table Part 9 Table 147 defers to -
// gives Bad_NodeIdInvalid and Bad_NodeIdUnknown the identical description ('Used to indicate that the
// specified Object is not valid'), so either is conforming here and the probe accepts both; what it refuses
// is a generic collapse onto Bad_MethodInvalid or a Good code.
// @verifies AC-SVR-AC-215-METRICS-RESET-CODES
TEST_F(AlarmMetricsInstanceTest, AlarmMetricsReset_RefusesAForeignMethodIdAndAnInvalidObjectIdWithOwnCodes)
{
  ASSERT_FALSE(mMetricsId.is_null()) << "no AlarmMetricsType Object could be instantiated";
  const auto resetId = find_method_via_browse(mMetricsId, "Reset");
  ASSERT_FALSE(resetId.is_null()) << "the AlarmMetricsType Object exposes no Reset Method to call";
  const auto foreignMethodId = find_method_via_browse(mConditionId, "Enable");
  ASSERT_FALSE(foreignMethodId.is_null()) << "the fixture's Condition should expose its own Enable Method";

  auto statusOf = [this](CallRequest req) -> StatusCode
  {
    auto result = mSession->methods().try_call_sync(std::move(req));
    if (result.is_bad())
      return result.status_code();
    if (result.value().results().empty())
      return StatusCode{Status::BadUnexpectedError};
    return result.value().results()[0].status_code();
  };

  const auto foreignStatus = statusOf(make_condition_call(mMetricsId, foreignMethodId));
  EXPECT_EQ(foreignStatus, StatusCode{Status::BadMethodInvalid})
    << "Reset called with a MethodId belonging to another Object returned " << foreignStatus.as_uint32()
    << " instead of Bad_MethodInvalid";

  const auto pairedStatus = statusOf(make_condition_call(mMetricsId, resetId));
  ASSERT_NE(pairedStatus, StatusCode{Status::BadMethodInvalid})
    << "the correct (AlarmMetrics, Reset) pairing is itself Bad_MethodInvalid, so the code asserted above "
       "is what this Method answers to every caller";

  const auto nullObjectStatus = statusOf(make_condition_call(NodeId{}, resetId));
  EXPECT_TRUE(nullObjectStatus == StatusCode{Status::BadNodeIdInvalid} ||
              nullObjectStatus == StatusCode{Status::BadNodeIdUnknown})
    << "Reset called against a null ObjectId returned " << nullObjectStatus.as_uint32()
    << ", which is neither of the two codes Part 4 Table 67 assigns to an ObjectId that is not valid";
}

/// The auditing-enabled subscription fixture with an AlarmMetricsType Object materialised through the
/// Server's own instantiation service, so its Reset Method can be invoked over the wire while an audit
/// MonitoredItem is watching. `AlarmMetricsInstanceTest` above cannot serve: it carries no Subscription,
/// and the audit obligation is only observable as a delivered Event.
class AuditingAlarmMetricsTest : public ComplianceConditionAuditingEnabledTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    InstantiationService instantiation{mServer.server().address_space()};
    InstantiationOptions options;

    std::promise<NodeSubtreeResult> promise;
    instantiation.instantiate_object_async(NodeId{ObjectId::ObjectsFolder},
      QualifiedName{0, "AuditedAlarmMetrics"},
      NodeId{ObjectTypeId::AlarmMetricsType},
      options,
      [&promise](NodeSubtreeResult result) { promise.set_value(std::move(result)); });

    auto result = promise.get_future().get();
    if (result.is_good())
    {
      auto subtree = std::move(result).value();
      mMetricsId = subtree.root();
      subtree.release();
    }
  }

  NodeId mMetricsId;
};

// Part 9 section 9.4 - if Auditing is supported, the AlarmMetrics Reset Method shall generate an audit Event
// for the invocation; Table 148 names AuditUpdateMethodEventType as the type it AlwaysGeneratesEvent. Reset
// discards every counter, rate and time the Object holds, so it destroys precisely the evidence an engineer
// would use to judge whether the alarm system is improving - an unaudited Reset moves the baseline and
// leaves no record that anybody moved it. What arrives is resolved up the HasSubtype hierarchy rather than
// matched by NodeId, so a Server that raises a more specific audit subtype is not read as non-compliant.
// @verifies AC-SVR-AC-213-ALARMMETRICS-RESET-AUDIT
TEST_F(AuditingAlarmMetricsTest, AlarmMetricsReset_RaisesAnAuditEventForTheInvocation)
{
  ASSERT_FALSE(mMetricsId.is_null())
    << "no AlarmMetricsType Object could be instantiated, so Reset was never invoked";
  const auto resetId = find_method_via_browse(mMetricsId, "Reset");
  ASSERT_FALSE(resetId.is_null()) << "the AlarmMetricsType Object exposes no Reset Method to invoke";

  create_event_monitored_item(make_of_type_filter(NodeId{ObjectTypeId::AuditEventType}));

  auto result = mSession->methods().try_call_sync(make_condition_call(mMetricsId, resetId));
  const auto status = (result.is_bad() || result.value().results().empty())
                        ? result.status_code()
                        : result.value().results()[0].status_code();

  bool sawMethodAudit = false;
  std::vector<NodeId> observedTypes;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawMethodAudit && std::chrono::steady_clock::now() < deadline)
  {
    std::vector<NodeId> round;
    for (const auto& event : collect_events(10))
    {
      const auto type = event_type_from(event);
      if (!type.is_null())
        round.push_back(type);
    }
    if (round.empty())
      continue;
    observedTypes.insert(observedTypes.end(), round.begin(), round.end());
    for (const bool derives :
      types_derive_from(*mSession, round, NodeId{ObjectTypeId::AuditUpdateMethodEventType}))
    {
      sawMethodAudit = sawMethodAudit || derives;
    }
  }

  EXPECT_TRUE(sawMethodAudit)
    << "Reset returned " << status.as_uint32()
    << " and no Event of AuditUpdateMethodEventType or a subtype was raised for the invocation; "
    << observedTypes.size() << " audit Event(s) were seen, the first of type "
    << ua::to_string(observedTypes.empty() ? NodeId{} : observedTypes.front());
}

// ===========================================================================
// AlarmSuppressionGroups and the SuppressedState they drive
// ===========================================================================

/// A full-featured alarm bound by a HasAlarmSuppressionGroup Reference to an AlarmSuppressionGroupType
/// Object, which in turn holds one Boolean member Variable through an AlarmSuppressionGroupMember
/// Reference. Part 9 section 5.8.4 defines the group as active exactly when any of its member Variables reads
/// True, so writing that Variable is how a group is driven active and inactive without standing up a second
/// alarm whose own state could be mistaken for the effect under test.
class AlarmSuppressionGroupTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto addressSpace = mServer.server().address_space();

    mGroupMemberId = NodeId{0, uint32_t{50301}};
    auto memberNode = addressSpace.create_node_sync(mGroupMemberId, NodeClass::Variable);
    auto memberVar = memberNode.as<VariableAccessor>();
    ASSERT_TRUE(memberVar.has_value());
    memberVar->set_browse_name(QualifiedName{0, "SuppressionGroupTrigger"});
    memberVar->set_display_name(LocalizedText{"", "SuppressionGroupTrigger"});
    memberVar->set_data_type(NodeId{DataTypeId::Boolean});
    memberVar->write_value_sync(false);
    memberVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mGroupMemberId);

    InstantiationService instantiation{addressSpace};
    InstantiationOptions options;

    std::promise<NodeSubtreeResult> promise;
    instantiation.instantiate_object_async(NodeId{ObjectId::ObjectsFolder},
      QualifiedName{0, "TurbineSuppressionGroup"},
      NodeId{ObjectTypeId::AlarmSuppressionGroupType},
      options,
      [&promise](NodeSubtreeResult result) { promise.set_value(std::move(result)); });

    auto result = promise.get_future().get();
    if (result.is_good())
    {
      auto subtree = std::move(result).value();
      mGroupId = subtree.root();
      subtree.release();
    }
    if (mGroupId.is_null())
      return;

    auto groupNode = addressSpace.find_node_sync(mGroupId);
    mMemberEdgeAdded =
      groupNode.try_add_reference_sync(NodeId{ReferenceTypeId::AlarmSuppressionGroupMember}, mGroupMemberId)
        .is_good();
    auto alarmNode = addressSpace.find_node_sync(mFullAlarmId);
    mGroupEdgeAdded =
      alarmNode.try_add_reference_sync(NodeId{ReferenceTypeId::HasAlarmSuppressionGroup}, mGroupId).is_good();
  }

  NodeId mGroupId;
  NodeId mGroupMemberId;
  bool mMemberEdgeAdded{false};
  bool mGroupEdgeAdded{false};
};

// Part 9 section 5.8.2 - when an AlarmSuppressionGroup goes active the Server shall set the SuppressedState
// of the Alarm containing the HasAlarmSuppressionGroup Reference to True, and when all of the referenced
// groups are no longer active the Server shall set SuppressedState back to False. The whole point of a
// suppression group is to quiet the flood one plant upset produces, so a Server that publishes the References
// and leaves the members' SuppressedState alone still floods the operator's list while every Node a Client
// can browse says the suppression is configured. Both directions are driven, because a Server that latches
// SuppressedState True on the first activation hides the alarms for good.
// @verifies AC-SVR-AC-107-SUPPRESSIONGROUP-DRIVES-SUPPRESSED
// @relation(AC-SVR-AC-107-SUPPRESSIONGROUP-DRIVES-SUPPRESSED, scope=function)
TEST_F(AlarmSuppressionGroupTest, AnActiveAlarmSuppressionGroupSuppressesTheAlarmsThatReferenceIt)
{
  ASSERT_FALSE(mGroupId.is_null())
    << "no AlarmSuppressionGroupType Object could be instantiated, so no group was ever bound to the alarm";
  ASSERT_TRUE(mGroupEdgeAdded)
    << "the HasAlarmSuppressionGroup Reference from the alarm to its group was refused, so the alarm was "
       "never a member of a suppression group at all";
  ASSERT_TRUE(mMemberEdgeAdded)
    << "the AlarmSuppressionGroupMember Reference from the group to its Boolean member was refused, so the "
       "group has nothing that can make it active";

  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(700);

  const auto suppressedStateId = find_hier_child(*mSession, mFullAlarmId, String{"SuppressedState"});
  ASSERT_FALSE(suppressedStateId.is_null())
    << "the alarm declares suppression support and exposes no SuppressedState to be driven";
  const auto suppressedIdNode = find_hier_child(*mSession, suppressedStateId, String{"Id"});
  ASSERT_FALSE(suppressedIdNode.is_null()) << "SuppressedState/Id is Mandatory on TwoStateVariableType";

  // Reads SuppressedState/Id over the wire; `fallback` is returned for a Bad or untyped read so a failed
  // read can never be counted as the state an assertion below is waiting for.
  auto readSuppressed = [this, &suppressedIdNode](bool fallback)
  {
    const auto dv = read_value_dv(*mSession, suppressedIdNode);
    const auto* value = read_reported_bad(dv) ? nullptr : dv.value().try_as<bool>();
    return value == nullptr ? fallback : *value;
  };
  auto awaitSuppressed = [&readSuppressed](bool expected)
  {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    bool observed = readSuppressed(!expected);
    while (observed != expected && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      observed = readSuppressed(!expected);
    }
    return observed;
  };

  const auto initial = read_value_dv(*mSession, suppressedIdNode);
  ASSERT_FALSE(read_reported_bad(initial)) << "SuppressedState/Id does not read at all on this alarm";
  const auto* initialId = initial.value().try_as<bool>();
  ASSERT_NE(initialId, nullptr) << "SuppressedState/Id must read as a Boolean";
  ASSERT_FALSE(*initialId) << "the alarm is Suppressed before its group ever went active, so the two "
                              "transitions below would prove nothing";

  auto addressSpace = mServer.server().address_space();
  auto memberNode = addressSpace.find_node_sync(mGroupMemberId);
  auto memberVar = memberNode.as<VariableAccessor>();
  ASSERT_TRUE(memberVar.has_value()) << "the group's Boolean member Variable is no longer reachable";

  memberVar->write_value_sync(true);
  EXPECT_TRUE(awaitSuppressed(true))
    << "the AlarmSuppressionGroup the alarm references went active and SuppressedState stayed False - the "
       "alarm keeps annunciating through the flood the group exists to quiet";

  memberVar->write_value_sync(false);
  EXPECT_FALSE(awaitSuppressed(false))
    << "every AlarmSuppressionGroup the alarm references is inactive again and SuppressedState stayed True "
       "- the alarm stays hidden with nothing suppressing it";
}

// ===========================================================================
// DeviationAlarm: the setpoint it measures against, and its signed limits
// ===========================================================================

/// One Exclusive and one NonExclusive DeviationAlarm carrying the four signed deviation limits Part 9
/// section 5.8.22 describes - positive above the setpoint, negative below it. Neither alarm's setpoint is
/// modelled as a Variable in the AddressSpace, which is exactly the underlying-system case section 5.8.22
/// gives its own SetpointNode rule for.
///
/// A third alarm is offered a configuration that is correctly ORDERED but wrongly signed - a positive
/// LowLimit and a zero LowLowLimit. Every conforming configuration satisfies the sign and non-zero rules
/// by construction, so a survey over the first two alone would hold of a Server that publishes whatever
/// deviation limits it is handed; the sign and non-zero clauses would then have no way to fail. The
/// Server may refuse the configuration - refusing is one way to satisfy section 5.8.22, and the alarm is then
/// simply absent from `deviation_alarms()` - but if it accepts one, the limits it publishes are surveyed
/// with the rest and must obey the rules.
class DeviationAlarmLimitTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto& conditions = mServer.server().conditions();
    auto makeDeviationLogic = [](bool exclusive)
    {
      auto logic = std::make_unique<LimitAlarmLogic>();
      logic->set_exclusive(exclusive);
      LimitConfig c;
      c.highHighLimit = sHighHighLimit;
      c.highLimit = sHighLimit;
      c.lowLimit = sLowLimit;
      c.lowLowLimit = sLowLowLimit;
      logic->set_limits(c);
      return logic;
    };

    auto exclusiveResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"ExclusiveDeviation"},
      makeDeviationLogic(true),
      NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
    if (exclusiveResult.is_good())
    {
      mExclusiveDeviation = exclusiveResult.value();
      mExclusiveDeviationId = mExclusiveDeviation->condition_id();
    }

    auto nonExclusiveResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"NonExclusiveDeviation"},
      makeDeviationLogic(false),
      NodeId{ObjectTypeId::NonExclusiveDeviationAlarmType});
    if (nonExclusiveResult.is_good())
    {
      mNonExclusiveDeviation = nonExclusiveResult.value();
      mNonExclusiveDeviationId = mNonExclusiveDeviation->condition_id();
    }

    // Ordered HighHigh > High > Low > LowLow, so the ordering rule is not what is under test here; the low
    // limits are on the wrong side of the setpoint and one of them is zero.
    auto misSignedLogic = std::make_unique<LimitAlarmLogic>();
    misSignedLogic->set_exclusive(true);
    LimitConfig misSigned;
    misSigned.highHighLimit = sHighHighLimit;
    misSigned.highLimit = sHighLimit;
    misSigned.lowLimit = sMisSignedLowLimit;
    misSigned.lowLowLimit = sMisSignedLowLowLimit;
    misSignedLogic->set_limits(misSigned);

    auto misSignedResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"MisSignedDeviation"},
      std::move(misSignedLogic),
      NodeId{ObjectTypeId::ExclusiveDeviationAlarmType});
    if (misSignedResult.is_good())
    {
      mMisSignedDeviation = misSignedResult.value();
      mMisSignedDeviationId = mMisSignedDeviation->condition_id();
    }
  }

  /// The DeviationAlarms that were actually created, so a survey over them is never silently empty.
  std::vector<NodeId> deviation_alarms() const
  {
    std::vector<NodeId> ids;
    if (!mExclusiveDeviationId.is_null())
      ids.push_back(mExclusiveDeviationId);
    if (!mNonExclusiveDeviationId.is_null())
      ids.push_back(mNonExclusiveDeviationId);
    if (!mMisSignedDeviationId.is_null())
      ids.push_back(mMisSignedDeviationId);
    return ids;
  }

  static constexpr double sHighHighLimit = 20.0;
  static constexpr double sHighLimit = 10.0;
  static constexpr double sLowLimit = -10.0;
  static constexpr double sLowLowLimit = -20.0;
  static constexpr double sMisSignedLowLimit = 5.0;
  static constexpr double sMisSignedLowLowLimit = 0.0;

  NodeId mExclusiveDeviationId;
  NodeId mNonExclusiveDeviationId;
  NodeId mMisSignedDeviationId;
  std::shared_ptr<ConditionInstance> mExclusiveDeviation;
  std::shared_ptr<ConditionInstance> mNonExclusiveDeviation;
  std::shared_ptr<ConditionInstance> mMisSignedDeviation;
};

// Part 9 section 5.8.22.1 - a DeviationAlarm carries a SetpointNode, and its LowLimit and LowLowLimit shall
// be negative while its HighLimit and HighHighLimit shall be positive. The limits are offsets from the
// setpoint rather than process values, which is the whole difference between this type and a LimitAlarm: a
// Server that copies a LimitAlarm's absolute thresholds into a DeviationAlarm publishes a positive LowLimit
// that sits above the setpoint, so the low alarm is active whenever the process is exactly on target. The
// SetpointNode is asserted beside the signs because a signed offset with nothing to be an offset from is
// uninterpretable either way. One of the surveyed alarms was offered exactly that mis-signed configuration
// (see the fixture), so the sign clause has something to fail on rather than only conforming values.
// @verifies AC-SVR-AC-209-DEVIATION-LIMIT-SIGNS
TEST_F(DeviationAlarmLimitTest, EveryDeviationAlarmNamesItsSetpointAndSignsItsLimitsAgainstIt)
{
  const auto alarms = deviation_alarms();
  ASSERT_FALSE(alarms.empty())
    << "no DeviationAlarmType Condition could be created at all, so nothing was surveyed";

  const std::vector<std::pair<const char*, bool>> limits{
    {"HighHighLimit", true}, {"HighLimit", true}, {"LowLimit", false}, {"LowLowLimit", false}};

  size_t limitsRead = 0;
  for (const auto& alarmId : alarms)
  {
    EXPECT_FALSE(find_hier_child(*mSession, alarmId, String{"SetpointNode"}).is_null())
      << "the DeviationAlarm " << ua::to_string(alarmId)
      << " exposes no SetpointNode, so the value its limits are offsets from is unknowable";

    for (const auto& [name, mustBePositive] : limits)
    {
      const auto propertyId = find_hier_child(*mSession, alarmId, String{name});
      if (propertyId.is_null())
        continue;
      const auto dv = read_value_dv(*mSession, propertyId);
      EXPECT_FALSE(read_reported_bad(dv)) << "the DeviationAlarm " << ua::to_string(alarmId) << " declares "
                                          << name << " but reading it reports a Bad status";
      const auto* value = dv.value().try_as<double>();
      if (value == nullptr)
        continue;
      ++limitsRead;
      if (mustBePositive)
      {
        EXPECT_GT(*value, 0.0) << "the DeviationAlarm " << ua::to_string(alarmId) << " declares " << name
                               << " = " << *value
                               << ", which places an above-setpoint threshold at or below the setpoint";
      }
      else
      {
        EXPECT_LT(*value, 0.0) << "the DeviationAlarm " << ua::to_string(alarmId) << " declares " << name
                               << " = " << *value
                               << ", which places a below-setpoint threshold at or above the setpoint";
      }
    }
  }
  ASSERT_GT(limitsRead, 0u)
    << "not one deviation limit was readable across the surveyed alarms, so no sign was ever checked";
}

// Part 9 section 5.8.22 - if provided, the deviation limits shall not be zero and shall follow HighHighLimit
// > HighLimit and LowLimit > LowLowLimit. Zero is the addition worth having over the sign rule alone: a zero
// deviation limit puts the threshold exactly on the setpoint, so the alarm activates on any deviation at
// all and chatters on measurement noise for as long as the loop is running. The ordering is stated the way
// it is because both low limits are negative, so LowLowLimit is the more negative of the pair - an
// implementation that sorts the low limits by magnitude gets them the wrong way round. One of the surveyed
// alarms was offered a zero LowLowLimit (see the fixture), so the non-zero clause has something to fail on
// rather than only the conforming values the other two were configured with.
// @verifies AC-SVR-AC-217-DEVIATION-LIMIT-RULES
TEST_F(DeviationAlarmLimitTest, DeviationLimitsAreNonZeroAndOrderedOutwardFromTheSetpoint)
{
  const auto alarms = deviation_alarms();
  ASSERT_FALSE(alarms.empty())
    << "no DeviationAlarmType Condition could be created at all, so nothing was surveyed";

  struct DeclaredLimit
  {
    bool declared{false};
    double value{0.0};
  };

  auto readLimit = [this](const NodeId& alarmId, const char* name)
  {
    DeclaredLimit limit;
    const auto propertyId = find_hier_child(*mSession, alarmId, String{name});
    if (propertyId.is_null())
      return limit;
    const auto dv = read_value_dv(*mSession, propertyId);
    const auto* value = read_reported_bad(dv) ? nullptr : dv.value().try_as<double>();
    if (value != nullptr)
      limit = DeclaredLimit{true, *value};
    return limit;
  };

  size_t comparisons = 0;
  for (const auto& alarmId : alarms)
  {
    const auto highHigh = readLimit(alarmId, "HighHighLimit");
    const auto high = readLimit(alarmId, "HighLimit");
    const auto low = readLimit(alarmId, "LowLimit");
    const auto lowLow = readLimit(alarmId, "LowLowLimit");

    const std::vector<std::pair<const char*, DeclaredLimit>> declared{
      {"HighHighLimit", highHigh}, {"HighLimit", high}, {"LowLimit", low}, {"LowLowLimit", lowLow}};
    for (const auto& [name, limit] : declared)
    {
      if (!limit.declared)
        continue;
      EXPECT_NE(limit.value, 0.0)
        << "the DeviationAlarm " << ua::to_string(alarmId) << " declares " << name
        << " = 0, which puts the threshold on the setpoint and alarms on any deviation at all";
    }

    if (highHigh.declared && high.declared)
    {
      ++comparisons;
      EXPECT_GT(highHigh.value, high.value)
        << "the DeviationAlarm " << ua::to_string(alarmId) << " declares HighHighLimit = " << highHigh.value
        << " and HighLimit = " << high.value << ", so the more severe threshold is not the further one";
    }
    if (low.declared && lowLow.declared)
    {
      ++comparisons;
      EXPECT_GT(low.value, lowLow.value)
        << "the DeviationAlarm " << ua::to_string(alarmId) << " declares LowLimit = " << low.value
        << " and LowLowLimit = " << lowLow.value
        << ", so the more severe threshold is not the further below the setpoint";
    }
  }
  ASSERT_GT(comparisons, 0u)
    << "no DeviationAlarm published a pair of limits to order, so the inequalities were never compared";
}

// Part 9 section 5.8.22 - in cases where the Alarm is generated by an underlying system and the Variable is
// not in the AddressSpace, a NULL NodeId shall be provided for SetpointNode. Omitting the Node instead, or
// letting it read Bad, collapses two situations a Client must tell apart: "there is a setpoint and this
// Server cannot expose it as a Node" against "this Alarm has not been configured with a setpoint at all".
// Only the first is a working alarm, and only the explicit NULL NodeId says so. The alarms surveyed here are
// fed by no address-space setpoint, so the rule applies to every one of them.
// @verifies AC-SVR-AC-218-SETPOINTNODE-NULL-WHEN-ABSENT
TEST_F(DeviationAlarmLimitTest, SetpointNodeReadsANullNodeIdWhereTheSetpointIsNotInTheAddressSpace)
{
  const auto alarms = deviation_alarms();
  ASSERT_FALSE(alarms.empty())
    << "no DeviationAlarmType Condition could be created at all, so no SetpointNode was read";

  size_t setpointsRead = 0;
  for (const auto& alarmId : alarms)
  {
    const auto setpointId = find_hier_child(*mSession, alarmId, String{"SetpointNode"});
    EXPECT_FALSE(setpointId.is_null()) << "the DeviationAlarm " << ua::to_string(alarmId)
                                       << " omits SetpointNode rather than publishing it with a NULL NodeId";
    if (setpointId.is_null())
      continue;
    ++setpointsRead;

    const auto dv = read_value_dv(*mSession, setpointId);
    EXPECT_FALSE(read_reported_bad(dv))
      << "the SetpointNode of the DeviationAlarm " << ua::to_string(alarmId)
      << " reports a Bad status; the absence of the setpoint must be carried as a NULL NodeId value";
    const auto* setpoint = dv.value().try_as<NodeId>();
    EXPECT_NE(setpoint, nullptr) << "the SetpointNode of the DeviationAlarm " << ua::to_string(alarmId)
                                 << " reads an empty Variant rather than a NodeId-typed NULL NodeId";
    if (setpoint == nullptr)
      continue;
    EXPECT_TRUE(setpoint->is_null()) << "the SetpointNode of the DeviationAlarm " << ua::to_string(alarmId)
                                     << " reads " << ua::to_string(*setpoint)
                                     << ", which is not in the AddressSpace as a setpoint Variable";
  }
  ASSERT_GT(setpointsRead, 0u)
    << "no surveyed DeviationAlarm exposed a SetpointNode, so nothing was read for the NULL NodeId rule";
}

// ===========================================================================
// R18 round twelve: refresh completeness, alarm sub-state aggregation, and the
// limit / discrete / rate-of-change type families
// ===========================================================================

/// Poll `predicate` until it holds or the deadline passes. Alarm state driven from a bound input is
/// evaluated by the sampling timer on the instance strand, so the state a stimulus produces is not
/// visible the instant the stimulus returns; a fixed sleep either flakes or wastes the whole budget.
template<typename Predicate>
static bool poll_until(Predicate predicate, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;)
  {
    if (predicate())
      return true;
    if (std::chrono::steady_clock::now() >= deadline)
      return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

// Field positions in `make_condition_event_filter`'s select order (and `branch_event_filter`'s, which
// appends BranchId to it). Named here because the refresh surveys below read four of them.
static constexpr size_t refreshEventIdField = 0;
static constexpr size_t refreshEventTypeField = 1;
static constexpr size_t refreshSourceNodeField = 2;
static constexpr size_t refreshRetainField = 8;
static constexpr size_t refreshBranchIdField = 11;

/// The EventType of one delivered event, or a null NodeId when the field is absent.
static NodeId event_type_of(const EventFieldList& event)
{
  if (event.event_fields().size() <= refreshEventTypeField)
    return {};
  const auto* type = event.event_fields()[refreshEventTypeField].try_as<NodeId>();
  return type == nullptr ? NodeId{} : *type;
}

/// True for the two synthetic events that bracket a refresh rather than report a Condition state.
static bool is_refresh_marker(const EventFieldList& event)
{
  const auto type = event_type_of(event);
  return type == NodeId{ObjectTypeId::RefreshStartEventType} ||
         type == NodeId{ObjectTypeId::RefreshEndEventType};
}

/// Publish until the RefreshEnd terminator arrives, returning everything collected on the way. A refresh
/// is a bounded RefreshStart -> retained Conditions -> RefreshEnd sequence that splits across several
/// Publish responses under load, so a single fixed window truncates it (the trap the two older
/// ConditionRefresh tests in this file record).
static std::vector<EventFieldList> collect_until_refresh_end(
  ua::client::Session& session, uint32_t subscriptionId, bool& sawEnd)
{
  std::vector<EventFieldList> events;
  sawEnd = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!sawEnd && std::chrono::steady_clock::now() < deadline)
  {
    for (auto& event : ::ua::test_helpers::collect_events(session,
           subscriptionId,
           {.minCount = 1,
             .timeout = std::chrono::milliseconds{500},
             .pollInterval = std::chrono::milliseconds{50}}))
    {
      const bool isEnd = (event_type_of(event) == NodeId{ObjectTypeId::RefreshEndEventType});
      events.push_back(std::move(event));
      if (isEnd)
        sawEnd = true;
    }
  }
  return events;
}

/// Drain whatever the Subscription already holds, so a survey of a later refresh cannot be satisfied by
/// an Event the earlier stimulus produced.
static void drain_pending_events(ua::client::Session& session, uint32_t subscriptionId)
{
  for (int round = 0; round < 10; ++round)
  {
    const auto drained = ::ua::test_helpers::collect_events(session,
      subscriptionId,
      {.minCount = 1000,
        .timeout = std::chrono::milliseconds{200},
        .pollInterval = std::chrono::milliseconds{50}});
    if (drained.empty())
      return;
  }
}

/// The events strictly between the first RefreshStart and the last RefreshEnd. The refresh is located by
/// its markers rather than by position because section 5.5.7 (3) explicitly permits the Server to intersperse
/// new Event Notifications with the refreshed ones.
static std::vector<EventFieldList> events_inside_refresh(const std::vector<EventFieldList>& events)
{
  std::optional<size_t> startIdx;
  std::optional<size_t> endIdx;
  for (size_t i = 0; i < events.size(); ++i)
  {
    const auto type = event_type_of(events[i]);
    if (!startIdx && type == NodeId{ObjectTypeId::RefreshStartEventType})
      startIdx = i;
    if (type == NodeId{ObjectTypeId::RefreshEndEventType})
      endIdx = i;
  }
  std::vector<EventFieldList> inside;
  if (!startIdx || !endIdx || *endIdx <= *startIdx)
    return inside;
  for (size_t i = *startIdx + 1; i < *endIdx; ++i)
  {
    if (!is_refresh_marker(events[i]))
      inside.push_back(events[i]);
  }
  return inside;
}

/// The SourceNode of one delivered event, or a null NodeId when the field is absent.
static NodeId source_node_of(const EventFieldList& event)
{
  if (event.event_fields().size() <= refreshSourceNodeField)
    return {};
  const auto* source = event.event_fields()[refreshSourceNodeField].try_as<NodeId>();
  return source == nullptr ? NodeId{} : *source;
}

/// The BranchId of one delivered event; null on the trunk (OPC 10000-9 5.5.3) and null when the field
/// was not selected.
static NodeId branch_id_of(const EventFieldList& event)
{
  if (event.event_fields().size() <= refreshBranchIdField)
    return {};
  const auto* branch = event.event_fields()[refreshBranchIdField].try_as<NodeId>();
  return branch == nullptr ? NodeId{} : *branch;
}

// ===========================================================================
// ConditionRefresh completeness: prior states, and only the interesting ones
// ===========================================================================

/// The branching alarm of `SeededBranchingAlarmRoomyCapTest` (a cap of 100, so nothing is evicted while
/// the refresh surveys run) plus a second Alarm on a source of its own that is driven into an
/// UNINTERESTING state - activated, acknowledged, then returned to normal, so its Retain is False. The
/// second alarm is what makes the completeness clause falsifiable in both directions: without it a
/// Server that replays every Condition it has ever seen passes a survey that only counts what arrived.
class BranchingAlarmRefreshTest : public SeededBranchingAlarmRoomyCapTest
{
protected:
  void configure_server() override
  {
    SeededBranchingAlarmRoomyCapTest::configure_server();

    auto& server = mServer.server();
    auto addressSpace = server.address_space();

    mQuietSourceId = NodeId{mNamespaceIndex, std::string{"QuietAlarmSource"}};
    auto sourceNode = addressSpace.create_node_sync(mQuietSourceId, NodeClass::Object);
    sourceNode.set_browse_name(QualifiedName{mNamespaceIndex, "QuietAlarmSource"});
    sourceNode.set_display_name(LocalizedText{"", "QuietAlarmSource"});
    sourceNode.as<ua::ObjectAccessor>()->set_event_notifier(
      ua::EventNotifierType{ua::EventNotifierType::Bit::SubscribeToEvents});
    sourceNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mQuietSourceId);
    addressSpace.find_node_sync(NodeId{ObjectId::Server})
      .add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, mQuietSourceId);

    mQuietAlarm = server.conditions().create_condition_sync(NodeId{mNamespaceIndex, uint32_t{0}},
      mQuietSourceId,
      String{"QuietAlarm"},
      std::make_unique<AlarmConditionLogic>(),
      NodeId{ObjectTypeId::AlarmConditionType});
    mQuietAlarm->enable_sync();
  }

  /// Drive the second alarm through a complete cycle and leave it uninteresting: active, acknowledged,
  /// then back to normal. Returns false when it did not end with Retain False, in which case it is not
  /// the uninteresting subject the omission clause is about.
  bool make_quiet_alarm_uninteresting()
  {
    mQuietAlarm->activate_sync(500);
    auto eventId = get_event_id(mQuietAlarm);
    if (eventId.empty())
      return false;
    mQuietAlarm->acknowledge_sync(eventId, LocalizedText{"", "acknowledged before the refresh"});
    mQuietAlarm->deactivate_sync();
    return poll_until([this] { return !mQuietAlarm->snapshot()->retained(); }, std::chrono::seconds{2});
  }

  NodeId mQuietSourceId;
  std::shared_ptr<ua::ConditionInstance> mQuietAlarm;
};

// OPC 10000-9 5.5.7: "ConditionRefresh shall also issue Event Notifications for prior states if they
// still need attention. In particular, this is True for Condition instances where previous states still
// need acknowledgement or confirmation." The natural implementation replays the Condition's CURRENT
// state - it is the state the instance holds, and rebuilding it is one call - which leaves every
// unacknowledged branch out of the reply. The operator's alarm list then loses a branch that is still
// unacknowledged on the Server, and nothing tells either side that it went missing. The alarm is driven
// through unacknowledged activate/deactivate cycles first, so branches exist to be omitted; the branch
// events are distinguished from the trunk by BranchId, which is null on the trunk (5.5.3).
// @verifies AC-SVR-AC-023-REFRESH-PRIOR-STATES
TEST_F(BranchingAlarmRefreshTest, ConditionRefresh_ReissuesTheUnacknowledgedPriorBranchesBesideTheTrunk)
{
  drive_unacknowledged_toggles(2);
  drain_pending_events(*mSession, mSubscriptionId);

  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Call failed: " << result.status_code().as_uint32();
  ASSERT_FALSE(result.value().results().empty());
  ASSERT_TRUE(result.value().results()[0].status_code().is_good())
    << "ConditionRefresh failed: " << result.value().results()[0].status_code().as_uint32();

  bool sawEnd = false;
  const auto events = collect_until_refresh_end(*mSession, mSubscriptionId, sawEnd);
  ASSERT_TRUE(sawEnd) << "RefreshEnd was not delivered within the deadline (collected " << events.size()
                      << " events), so the refresh sequence is incomplete and its contents prove nothing";

  const auto inside = events_inside_refresh(events);
  GTEST_LOG_(INFO) << "refresh replayed " << inside.size() << " Condition state(s) of " << events.size()
                   << " delivered events";
  ASSERT_FALSE(inside.empty()) << "the refresh replayed no Condition state at all between RefreshStart "
                                  "and RefreshEnd, so the prior-state clause was never reached";

  size_t branchStates = 0;
  size_t retainedBranchStates = 0;
  for (const auto& event : inside)
  {
    if (branch_id_of(event).is_null())
      continue;  // the trunk, i.e. the current state
    ++branchStates;
    if (event.event_fields().size() > refreshRetainField)
    {
      const auto* retain = event.event_fields()[refreshRetainField].try_as<bool>();
      if (retain != nullptr && *retain)
        ++retainedBranchStates;
    }
  }

  EXPECT_GT(branchStates, 0u)
    << "the Condition carries unacknowledged prior branches and the refresh replayed only its current "
       "state - every branch still awaiting acknowledgement is missing from the Client's alarm list";
  EXPECT_EQ(branchStates, retainedBranchStates)
    << "a prior state was reissued with Retain=False, which retracts the branch the refresh was supposed "
       "to restore";
}

// OPC 10000-9 5.5.7: a refresh issues Event Notifications "of any Retained Conditions and Retained
// Branches of Conditions" - the Retain flag is what decides which states are interesting, and the ones
// that are not are not issued. Both halves matter, and only one of them is natural to get right: an
// implementation that replays every Condition it holds satisfies "all the interesting ones" and floods
// the operator's list with alarms that returned to normal and were acknowledged, which is precisely the
// state the Retain flag exists to exclude. The quiet alarm is driven through a complete cycle first and
// its Events are observed arriving on this Subscription, so its later absence is an omission rather than
// a Notifier that was never wired.
// @verifies AC-SVR-AC-039-REFRESH-ALL-INTERESTING
TEST_F(BranchingAlarmRefreshTest, ConditionRefresh_IssuesEveryInterestingStateAndOmitsTheUninterestingOnes)
{
  drive_unacknowledged_toggles(2);
  ASSERT_TRUE(make_quiet_alarm_uninteresting())
    << "the second alarm did not end the drive with Retain=False, so it is not an uninteresting subject "
       "and its absence from the refresh would prove nothing";

  // Control: the quiet alarm's own Events reach this Subscription, so its absence below is the Retain
  // rule and not a source that was never routed.
  const auto beforeRefresh = ::ua::test_helpers::collect_events(*mSession,
    mSubscriptionId,
    {.minCount = 1000,
      .timeout = std::chrono::milliseconds{1500},
      .pollInterval = std::chrono::milliseconds{50}});
  size_t quietEventsSeen = 0;
  for (const auto& event : beforeRefresh)
  {
    if (source_node_of(event) == mQuietSourceId)
      ++quietEventsSeen;
  }
  ASSERT_GT(quietEventsSeen, 0u)
    << "no Event from the quiet alarm's source reached this Subscription at all, so the omission "
       "asserted below would hold of a Server that never routed it";
  drain_pending_events(*mSession, mSubscriptionId);

  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh},
    Array<Variant>{Variant{mSubscriptionId}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Call failed: " << result.status_code().as_uint32();
  ASSERT_FALSE(result.value().results().empty());
  ASSERT_TRUE(result.value().results()[0].status_code().is_good())
    << "ConditionRefresh failed: " << result.value().results()[0].status_code().as_uint32();

  bool sawEnd = false;
  const auto events = collect_until_refresh_end(*mSession, mSubscriptionId, sawEnd);
  ASSERT_TRUE(sawEnd) << "RefreshEnd was not delivered within the deadline (collected " << events.size()
                      << " events)";

  const auto inside = events_inside_refresh(events);
  size_t interestingStates = 0;
  size_t uninterestingStates = 0;
  for (const auto& event : inside)
  {
    if (source_node_of(event) == mQuietSourceId)
      ++uninterestingStates;
    else
      ++interestingStates;
  }
  GTEST_LOG_(INFO) << "refresh replayed " << inside.size() << " Condition state(s): " << interestingStates
                   << " from the retained alarm, " << uninterestingStates << " from the quiet one";

  EXPECT_GT(interestingStates, 0u)
    << "the branching alarm is retained and holds unacknowledged branches, and the refresh replayed none "
       "of its states";
  EXPECT_EQ(uninterestingStates, 0u)
    << "the refresh replayed " << uninterestingStates
    << " state(s) of an Alarm whose Retain is False - an acknowledged alarm that returned to normal is "
       "put back on the operator's list by every resynchronisation";
}

// ===========================================================================
// RefreshRequiredEventType on a lost Condition Event
// ===========================================================================

// OPC 10000-9 5.11.4: "When a Server detects an Event queue overflow, it shall track if any Condition
// Events have been lost, if any Condition Events were lost, it shall issue a RefreshRequiredEventType
// Event to the Client after the Event queue is no longer in an overflow state." The EventQueueOverflow
// Event that Part 4 already requires says an Event was dropped; it does not say the dropped Event
// carried Condition state, and a Client cannot tell from it whether its alarm list is still current. An
// implementation that emits the overflow Event and stops there leaves the Client displaying a list that
// stopped tracking reality at a moment it cannot identify. The queue is capped at one and six Condition
// state changes are driven with no Publish in flight, so loss is forced rather than hoped for - and the
// loss is asserted before the notification is looked for.
// @verifies AC-SVR-AC-040-REFRESHREQUIRED
// @relation(AC-SVR-AC-040-REFRESHREQUIRED, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, LosingACondition_EventToQueueOverflowRaisesRefreshRequired)
{
  const uint32_t itemId = ::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_condition_event_filter(),
    {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 1, .discardOldest = true});
  ASSERT_NE(itemId, 0u) << "the event MonitoredItem could not be created, so nothing can overflow";

  mAlarm->enable_sync();
  constexpr int drivenStateChanges = 6;
  for (int i = 0; i < drivenStateChanges / 2; ++i)
  {
    mAlarm->activate_sync(static_cast<uint16_t>(500 + i));
    mAlarm->deactivate_sync();
  }

  const auto delivered = ::ua::test_helpers::collect_events(*mSession,
    mSubscriptionId,
    {.minCount = 1000,
      .timeout = std::chrono::milliseconds{2500},
      .pollInterval = std::chrono::milliseconds{50}});

  size_t conditionStates = 0;
  size_t refreshRequired = 0;
  for (const auto& event : delivered)
  {
    const auto type = event_type_of(event);
    if (type == NodeId{ObjectTypeId::RefreshRequiredEventType})
      ++refreshRequired;
    else if (type != NodeId{ObjectTypeId::EventQueueOverflowEventType})
      ++conditionStates;
  }
  GTEST_LOG_(INFO) << "drove " << drivenStateChanges << " Condition state changes into a queue of 1 and "
                   << "received " << delivered.size() << " event(s), " << conditionStates
                   << " of them Condition states";

  ASSERT_LT(conditionStates, static_cast<size_t>(drivenStateChanges))
    << "every driven Condition state was delivered, so no Condition Event was lost and the clause this "
       "test is about was never entered";
  EXPECT_GT(refreshRequired, 0u)
    << "Condition Events were dropped by the queue and no RefreshRequiredEventType followed - the Client "
       "is never told that its alarm list has gone stale";
}

// OPC 10000-9 section 4.5: RefreshRequiredEventType ignores "the Event content filtering associated with a
// Subscription". The where clause admits the Alarm's own state changes and nothing else, so a
// RefreshRequired Event, which carries no ConditionId, reaches the item only because it ignores the clause.
// @relation(AC-SVR-AC-220-REFRESHREQUIRED-IGNORES-WHERE, scope=function)
TEST_F(ComplianceConditionSubscriptionTest, LosingACondition_EventRaisesRefreshRequiredWhateverTheWhereClause)
{
  const uint32_t itemId = ::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_condition_id_filter(mAlarmId),
    {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 1, .discardOldest = true});
  ASSERT_NE(itemId, 0u) << "the event MonitoredItem could not be created, so nothing can overflow";

  mAlarm->enable_sync();
  constexpr int drivenStateChanges = 6;
  for (int i = 0; i < drivenStateChanges / 2; ++i)
  {
    mAlarm->activate_sync(static_cast<uint16_t>(500 + i));
    mAlarm->deactivate_sync();
  }

  const auto delivered = ::ua::test_helpers::collect_events(*mSession,
    mSubscriptionId,
    {.minCount = 1000,
      .timeout = std::chrono::milliseconds{2500},
      .pollInterval = std::chrono::milliseconds{50}});

  size_t conditionStates = 0;
  size_t refreshRequired = 0;
  for (const auto& event : delivered)
  {
    const auto type = event_type_of(event);
    if (type == NodeId{ObjectTypeId::RefreshRequiredEventType})
      ++refreshRequired;
    else if (type != NodeId{ObjectTypeId::EventQueueOverflowEventType})
      ++conditionStates;
  }

  ASSERT_GT(conditionStates, 0u) << "control: the where clause admits the Alarm's own state changes";
  ASSERT_LT(conditionStates, static_cast<size_t>(drivenStateChanges))
    << "every driven Condition state was delivered, so no Condition Event was lost and no RefreshRequired "
       "is owed";
  EXPECT_GT(refreshRequired, 0u) << "Condition Events were lost and the RefreshRequired Event owed for them "
                                    "was filtered out by a where clause it does not satisfy";
}

// ===========================================================================
// ConditionRefresh2 and the original EventId
// ===========================================================================

// OPC 10000-9 5.5.8: on a ConditionRefresh2 "the EventId for such a refreshed Notification shall be
// identical to the one for the original Notification". Regenerating the Event is explicitly allowed -
// the other fields may legitimately have moved on - so the natural implementation builds a fresh Event
// from the Condition's current state, and a fresh Event gets a fresh EventId. Every refreshed alarm is
// then unacknowledgeable: Acknowledge is addressed by EventId, and the one the Client now holds names an
// Event the Server never issued. The original EventId is taken from the wire rather than from the
// Server-side snapshot, so an implementation that is merely self-consistent between its refresh builder
// and its snapshot does not pass.
// @verifies AC-SVR-AC-058-REFRESH2-ORIGINAL-EVENTID
TEST_F(ComplianceConditionSubscriptionTest, ConditionRefresh2_ReissuesTheRetainedStateWithItsOriginalEventId)
{
  const uint32_t itemId = ::ua::test_helpers::create_event_monitored_item(*mSession,
    mSubscriptionId,
    NodeId{ObjectId::Server},
    make_condition_event_filter(),
    {.clientHandle = 1, .samplingInterval = 0.0, .queueSize = 100});
  ASSERT_NE(itemId, 0u) << "ConditionRefresh2 is scoped to one MonitoredItem, so its id is required";

  mAlarm->enable_sync();
  mAlarm->activate_sync(500);

  const auto original = ::ua::test_helpers::collect_events(*mSession,
    mSubscriptionId,
    {.minCount = 1000,
      .timeout = std::chrono::milliseconds{1500},
      .pollInterval = std::chrono::milliseconds{50}});
  ByteString originalEventId;
  for (const auto& event : original)
  {
    if (is_refresh_marker(event) || event.event_fields().size() <= refreshEventIdField)
      continue;
    const auto* eventId = event.event_fields()[refreshEventIdField].try_as<ByteString>();
    if (eventId != nullptr && !eventId->empty())
      originalEventId = *eventId;  // the last Condition Event delivered is the retained current state
  }
  ASSERT_FALSE(originalEventId.empty())
    << "no Condition Event carrying an EventId was delivered before the refresh, so there is no original "
       "to compare against";

  auto req = make_condition_call(NodeId{ObjectTypeId::ConditionType},
    NodeId{MethodId::ConditionType_ConditionRefresh2},
    Array<Variant>{Variant{mSubscriptionId}, Variant{itemId}});
  auto result = mSession->methods().try_call_sync(std::move(req));
  ASSERT_TRUE(result.is_good()) << "Call failed: " << result.status_code().as_uint32();
  ASSERT_FALSE(result.value().results().empty());
  const auto callStatus = result.value().results()[0].status_code();
  // 5.5.8 makes the Method optional - "Clients must be prepared to handle Servers which do not provide
  // the Method" - but THIS Server provides it (`ua_conditions.cpp:1217`), so a Bad_MethodInvalid here is
  // a regression to report rather than a reason to abstain. Asserted, because no test skips itself: a
  // conditional skip also makes this test's coverage marker read as dead to the liveness gate, which cannot
  // tell a guard that never fires from a test that never runs.
  ASSERT_NE(callStatus, StatusCode{Status::BadMethodInvalid})
    << "this Server implements ConditionRefresh2 but answered Bad_MethodInvalid";
  ASSERT_TRUE(callStatus.is_good()) << "ConditionRefresh2 failed: " << callStatus.as_uint32();

  bool sawEnd = false;
  const auto events = collect_until_refresh_end(*mSession, mSubscriptionId, sawEnd);
  ASSERT_TRUE(sawEnd) << "RefreshEnd was not delivered within the deadline (collected " << events.size()
                      << " events)";

  const auto inside = events_inside_refresh(events);
  ASSERT_FALSE(inside.empty())
    << "ConditionRefresh2 replayed no Condition state at all, so no EventId was reissued";

  bool reissuedTheOriginal = false;
  size_t eventIdsCompared = 0;
  for (const auto& event : inside)
  {
    if (event.event_fields().size() <= refreshEventIdField)
      continue;
    const auto* eventId = event.event_fields()[refreshEventIdField].try_as<ByteString>();
    if (eventId == nullptr)
      continue;
    ++eventIdsCompared;
    if (*eventId == originalEventId)
      reissuedTheOriginal = true;
  }
  GTEST_LOG_(INFO) << "ConditionRefresh2 replayed " << inside.size() << " state(s), " << eventIdsCompared
                   << " of them carrying an EventId";
  ASSERT_GT(eventIdsCompared, 0u) << "no replayed state carried an EventId field at all";
  EXPECT_TRUE(reissuedTheOriginal)
    << "ConditionRefresh2 reissued the retained state under a new EventId; Acknowledge is addressed by "
       "EventId, so every refreshed alarm becomes unacknowledgeable";
}

// ===========================================================================
// SuppressedOrShelved aggregates all three suppressions
// ===========================================================================

// OPC 10000-9 5.8.2: "When an Alarm has any or all of the SuppressedState, OutOfServiceState or
// ShelvingState set to True, the SuppressedOrShelved property shall be set True." The Property's name
// carries two of the three inputs and the third - OutOfServiceState, the one maintenance personnel set -
// is easy to leave out of the disjunction; the Alarm then keeps appearing on a display that filters on
// this single flag, which is the whole point of taking an instrument out of service. Each input is
// driven ALONE and cleared again, so an implementation that happens to be true for another reason cannot
// pass, and the flag is read over the wire rather than from the Server-side logic object.
// @verifies AC-SVR-AC-102-SUPPRESSEDORSHELVED
TEST_F(ComplianceConditionTest, SuppressedOrShelved_IsTrueForEachOfItsThreeInputsAloneAndFalseForNone)
{
  mFullAlarm->enable_sync();
  mFullAlarm->activate_sync(500);

  const auto flagId = find_hier_child(*mSession, mFullAlarmId, String{"SuppressedOrShelved"});
  ASSERT_FALSE(flagId.is_null()) << "SuppressedOrShelved is Mandatory on AlarmConditionType";

  auto readFlag = [this, &flagId]() -> std::optional<bool>
  {
    const auto dv = read_value_dv(*mSession, flagId);
    if (read_reported_bad(dv))
      return std::nullopt;
    const auto* value = dv.value().try_as<bool>();
    return value == nullptr ? std::nullopt : std::optional<bool>{*value};
  };

  ASSERT_EQ(readFlag(), std::optional<bool>{false})
    << "SuppressedOrShelved must read False on an Alarm that is neither suppressed, out of service nor "
       "shelved - the baseline every arm below is measured against";

  // SuppressedState alone.
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Suppress").is_good());
  EXPECT_EQ(readFlag(), std::optional<bool>{true})
    << "SuppressedState is set and SuppressedOrShelved did not follow it";
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "Unsuppress").is_good());
  ASSERT_EQ(readFlag(), std::optional<bool>{false}) << "clearing SuppressedState left the flag set, so "
                                                       "the next arm would not be measuring its own input";

  // OutOfServiceState alone.
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "RemoveFromService").is_good());
  EXPECT_EQ(readFlag(), std::optional<bool>{true})
    << "the Alarm was removed from service and SuppressedOrShelved stayed False - a display filtering on "
       "this flag still shows an instrument that maintenance took out of service";
  ASSERT_TRUE(call_condition_method(mFullAlarmId, "PlaceInService").is_good());
  ASSERT_EQ(readFlag(), std::optional<bool>{false}) << "returning the Alarm to service left the flag set";

  // ShelvingState alone.
  ASSERT_TRUE(call_child_method(mFullAlarmId, "ShelvingState", "OneShotShelve").is_good());
  EXPECT_EQ(readFlag(), std::optional<bool>{true})
    << "the Alarm is shelved and SuppressedOrShelved stayed False";
  ASSERT_TRUE(call_child_method(mFullAlarmId, "ShelvingState", "Unshelve").is_good());
  EXPECT_EQ(readFlag(), std::optional<bool>{false})
    << "SuppressedOrShelved stayed True with all three of its inputs clear";
}

// ===========================================================================
// TwoStateVariable TransitionTime
// ===========================================================================

// OPC 10000-9 5.2: "TransitionTime specifies the time when the current state was entered." It is what an
// operator display turns into "how long has this alarm been active", so an implementation that fills the
// Property at read time - the same mistake this file already records for ConditionVariable
// SourceTimestamp - reports every alarm as having just changed state, and an alarm that has been
// standing for an hour is indistinguishable from one that arrived a second ago. The Property is read
// twice across a quarter second with no transition in between, and then once more after a real
// transition, so neither a frozen constant nor a restamped clock passes.
// @verifies AC-SVR-AC-118-TWOSTATE-TRANSITIONTIME
TEST_F(ComplianceConditionTest, TwoStateVariable_TransitionTimeIsTheTimeOfTheLastTransitionIntoItsState)
{
  mAlarm->enable_sync();

  const auto activeStateId = find_hier_child(*mSession, mAlarmId, String{"ActiveState"});
  ASSERT_FALSE(activeStateId.is_null()) << "ActiveState is Mandatory on AlarmConditionType";
  const auto transitionTimeId = find_hier_child(*mSession, activeStateId, String{"TransitionTime"});
  ASSERT_FALSE(transitionTimeId.is_null())
    << "ActiveState/TransitionTime is not materialised, so the time the current state was entered is "
       "published nowhere";

  auto readTransitionTime = [this, &transitionTimeId]() -> std::optional<DateTime>
  {
    const auto dv = read_value_dv(*mSession, transitionTimeId);
    if (read_reported_bad(dv))
      return std::nullopt;
    const auto* value = dv.value().try_as<DateTime>();
    return value == nullptr ? std::nullopt : std::optional<DateTime>{*value};
  };

  const DateTime beforeActivation = DateTime::now();
  mAlarm->activate_sync(500);
  ASSERT_TRUE(mAlarm->snapshot()->active()) << "the alarm must be active for ActiveState to have entered "
                                               "its True state";
  const DateTime afterActivation = DateTime::now();

  const auto atTransition = readTransitionTime();
  ASSERT_TRUE(atTransition.has_value()) << "ActiveState/TransitionTime does not read as a UtcTime value";
  ASSERT_FALSE(atTransition->is_null()) << "ActiveState/TransitionTime reads the null DateTime although "
                                           "the state has just been entered";
  EXPECT_TRUE(*atTransition >= beforeActivation && *atTransition <= afterActivation)
    << "ActiveState/TransitionTime is outside the interval in which the transition actually happened, so "
       "it is not the time the current state was entered";

  // An interval with no transition at all, then the same read again.
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  const auto afterInterval = readTransitionTime();
  ASSERT_TRUE(afterInterval.has_value());
  EXPECT_TRUE(*afterInterval == *atTransition)
    << "ActiveState/TransitionTime moved although the state did not - it is being stamped at the read "
       "rather than at the transition";

  // A genuine transition must move it, or the equality above would be satisfied by a constant.
  mAlarm->deactivate_sync();
  ASSERT_FALSE(mAlarm->snapshot()->active());
  const auto afterSecondTransition = readTransitionTime();
  ASSERT_TRUE(afterSecondTransition.has_value());
  EXPECT_TRUE(*afterSecondTransition > *atTransition)
    << "ActiveState/TransitionTime did not advance when ActiveState entered its other state";
}

// ===========================================================================
// Limit Properties: set where exposed, unreadable where unavailable
// ===========================================================================

/// The four limit Properties of the LimitAlarmType, with the values the fixture configured its two limit
/// alarms with.
struct FixtureConfiguredLimit
{
  std::string_view name;
  double value;
};

static const std::vector<FixtureConfiguredLimit>& fixture_configured_limits()
{
  static const std::vector<FixtureConfiguredLimit> limits{
    {"HighHighLimit", 90.0}, {"HighLimit", 70.0}, {"LowLimit", 30.0}, {"LowLowLimit", 10.0}};
  return limits;
}

// OPC 10000-9 5.8.18: the four limit Properties "shall be set for any Alarm limits that are exposed by
// the derived limit Alarm types". Materialising the Property is the visible half of instantiation and
// wiring a value into it is a separate step, so a Property that exists and reads null, or reads a
// default the Server invented, is what an implementation that stops after instantiation produces. A
// Client is then told the alarm has a threshold and not what it is - worse than not exposing it, because
// the gap is displayed. Each exposed limit is read over the wire and compared with the value the alarm
// was configured with, so a Property carrying a plausible zero is not mistaken for one carrying its
// limit.
// @verifies AC-SVR-AC-201-LIMITALARM-LIMITS-SET
TEST_F(ComplianceConditionTest, EveryLimitPropertyALimitAlarmExposesCarriesTheLimitItWasConfiguredWith)
{
  const std::vector<NodeId> alarms{mExclusiveLimitId, mNonExclusiveLimitId};

  size_t limitsExposed = 0;
  for (const auto& alarmId : alarms)
  {
    for (const auto& limit : fixture_configured_limits())
    {
      const auto propertyId = find_hier_child(*mSession, alarmId, String{limit.name});
      EXPECT_FALSE(propertyId.is_null())
        << "the limit alarm " << ua::to_string(alarmId) << " was configured with a " << limit.name
        << " and exposes no such Property, so the threshold it alarms on is published nowhere";
      if (propertyId.is_null())
        continue;
      ++limitsExposed;

      const auto dv = read_value_dv(*mSession, propertyId);
      EXPECT_FALSE(read_reported_bad(dv))
        << "the limit alarm " << ua::to_string(alarmId) << " exposes " << limit.name
        << " and reading it reports a Bad status although the underlying value was supplied";
      const auto* value = dv.value().try_as<double>();
      EXPECT_NE(value, nullptr) << "the limit alarm " << ua::to_string(alarmId) << " exposes " << limit.name
                                << " and it reads an empty Variant rather than a Double";
      if (value == nullptr)
        continue;
      EXPECT_DOUBLE_EQ(*value, limit.value)
        << "the limit alarm " << ua::to_string(alarmId) << " publishes " << limit.name << " = " << *value
        << " where it was configured with " << limit.value
        << " - the exposed Property is not set to the limit the alarm evaluates";
    }
  }
  ASSERT_GT(limitsExposed, 0u)
    << "no surveyed limit alarm exposed a single limit Property, so nothing was read";
  GTEST_LOG_(INFO) << "surveyed " << limitsExposed << " exposed limit Properties across " << alarms.size()
                   << " limit alarms";
}

// OPC 10000-9 5.8.18: "For cases where an underlying system cannot provide the actual value of a limit,
// the limit Property shall still be provided, but will have its AccessLevel set to not readable." The
// forbidden outcome is a plausible substitute: a Client comparing the process value against a limit the
// Server invented computes an alarm margin that does not exist, and nothing in the read says the number
// is fabricated. The alarm here is configured with one limit only, so the other three are limits this
// Server cannot supply. Omitting them altogether is the OTHER way the clause is satisfied - only limits
// the type EXPOSES must be set, and 5.8.19.2 explicitly permits an instance to omit limits. This Server
// takes the omission route, deterministically, so the survey pins that it exposes none: any exposed one
// is also checked unreadable by the loop, and a change of route fails the pin for re-examination.
TEST_F(ComplianceConditionTest, ALimitThisServerCannotSupplyIsNotPublishedAsAReadableDefault)
{
  auto partialLogic = std::make_unique<LimitAlarmLogic>();
  partialLogic->set_exclusive(true);
  LimitConfig onlyHighHigh;
  onlyHighHigh.highHighLimit = 90.0;
  partialLogic->set_limits(onlyHighHigh);

  auto created = mServer.server().conditions().try_create_condition_sync(NodeId{0, uint32_t{0}},
    NodeId{ObjectId::ObjectsFolder},
    String{"PartiallyConfiguredLimitAlarm"},
    std::move(partialLogic),
    NodeId{ObjectTypeId::ExclusiveLimitAlarmType});
  ASSERT_TRUE(created.is_good())
    << "a limit alarm carrying one limit could not be created, so no unsupplied limit exists to read";
  auto partialAlarm = created.value();
  const auto alarmId = partialAlarm->condition_id();

  // The one limit that WAS supplied, as the control: it must read, or an unreadable result below would
  // say nothing about availability.
  const auto suppliedId = find_hier_child(*mSession, alarmId, String{"HighHighLimit"});
  ASSERT_FALSE(suppliedId.is_null()) << "the configured HighHighLimit is not exposed at all";
  ASSERT_FALSE(read_reported_bad(read_value_dv(*mSession, suppliedId)))
    << "the limit this Server CAN supply does not read either, so unreadability is not evidence of "
       "unavailability here";

  size_t unsuppliedButExposed = 0;
  for (const char* name : {"HighLimit", "LowLimit", "LowLowLimit"})
  {
    const auto propertyId = find_hier_child(*mSession, alarmId, String{name});
    if (propertyId.is_null())
      continue;  // not exposed: 5.8.19.2 permits an instance to omit a limit
    ++unsuppliedButExposed;

    const auto dv = read_value_dv(*mSession, propertyId);

    bool readable = true;
    ReadRequest accessLevelReq;
    ReadValueId accessLevelRv;
    accessLevelRv.node_id() = propertyId;
    accessLevelRv.attribute_id() = static_cast<uint32_t>(AttributeId::AccessLevel);
    accessLevelReq.nodes_to_read().push_back(std::move(accessLevelRv));
    auto accessLevelRead = mSession->attributes().try_read_sync(std::move(accessLevelReq));
    if (accessLevelRead.is_good() && !accessLevelRead.value().results().empty())
    {
      const auto* raw = accessLevelRead.value().results()[0].value().try_as<uint8_t>();
      if (raw != nullptr)
        readable = AccessLevelType{*raw}.test(AccessLevelType::Bit::CurrentRead);
    }

    EXPECT_TRUE(read_reported_bad(dv) || !readable)
      << "the limit alarm " << ua::to_string(alarmId) << " exposes " << name
      << " for a limit the underlying system never supplied, and it reads Good with AccessLevel "
         "CurrentRead - a Client cannot tell the published number from a configured threshold";
  }

  GTEST_LOG_(INFO) << unsuppliedButExposed
                   << " unsupplied limit Property(ies) were exposed by the partially configured alarm";
  EXPECT_EQ(unsuppliedButExposed, size_t{0})
    << "this Server omits an unconfigured limit from the instance (5.8.19.2) rather than publishing it "
       "unreadable (5.8.18); it now exposes one, so the route it takes has changed";
}

// ===========================================================================
// ExclusiveLimitStateMachineType is only ever a sub-state machine
// ===========================================================================

// OPC 10000-9 5.8.19.2: "This state machine as it is defined shall be used as a sub state machine for a
// state machine which has an Active state", and 5.8.19.3 fixes the binding for the concrete case: "The
// LimitState is a sub state of the ActiveState and has an IsTrueSubStateOf reference to the ActiveState."
// A standalone instance has no state to activate it, so it never runs and a Client that follows the
// Alarm's ActiveState down to find the violated limit finds nothing. Instantiation copies the members of
// a type but not necessarily the NonHierarchical References between them, which is exactly how the
// binding goes missing on an instance while the type declaration keeps it.
//
// NOTE ON SCOPE: the criterion's wording names HasSubStateMachine, and asserting that alone would fail a
// conforming Server - NS0 binds LimitState (i=9455) to ActiveState (i=9398) with HasTrueSubState, not
// HasSubStateMachine. Either incoming edge is accepted here; what is asserted is that no
// ExclusiveLimitStateMachine stands alone.
// @verifies AC-SVR-AC-206-EXCLUSIVELIMIT-AS-SUBSTATE
TEST_F(ComplianceConditionTest, EveryExclusiveLimitStateMachineIsBoundToTheStateOfAnEnclosingMachine)
{
  const NodeId exclusiveLimitAlarmType{ObjectTypeId::ExclusiveLimitAlarmType};
  std::vector<NodeId> owners{mExclusiveLimitId, exclusiveLimitAlarmType};
  for (const auto& subtype : browse_reference_targets(*mSession,
         exclusiveLimitAlarmType,
         NodeId{ReferenceTypeId::HasSubtype},
         BrowseDirection::Forward,
         false))
  {
    owners.push_back(subtype);
  }

  // The owner each member was reached FROM is kept alongside it. Part 3 section 5.3.3 lets a Server model
  // only one direction of a Reference -- "It might not always be possible for Servers to instantiate both
  // forward and inverse References" -- so recovering the parent by an inverse browse is not something a
  // conforming Server owes, and this one does not offer it. The forward walk already knows the answer.
  std::vector<NodeId> members;
  std::vector<NodeId> memberOwners;
  {
    const auto perOwnerMembers = browse_reference_targets_batch(
      *mSession, owners, NodeId{ReferenceTypeId::HierarchicalReferences}, BrowseDirection::Forward, true);
    for (size_t ownerIndex = 0; ownerIndex < perOwnerMembers.size(); ++ownerIndex)
    {
      for (const auto& member : perOwnerMembers[ownerIndex])
      {
        members.push_back(member);
        memberOwners.push_back(owners[ownerIndex]);
      }
    }
  }
  ASSERT_FALSE(members.empty()) << "the ExclusiveLimitAlarm types and instances surveyed expose no "
                                   "hierarchical members at all";

  const auto memberTypes = type_definitions_of(*mSession, members);
  std::vector<NodeId> stateMachines;
  std::vector<NodeId> stateMachineOwners;
  for (size_t i = 0; i < members.size(); ++i)
  {
    if (memberTypes[i] == NodeId{ObjectTypeId::ExclusiveLimitStateMachineType})
    {
      stateMachines.push_back(members[i]);
      stateMachineOwners.push_back(memberOwners[i]);
    }
  }
  GTEST_LOG_(INFO) << "found " << stateMachines.size() << " ExclusiveLimitStateMachineType instance(s) "
                   << "beneath " << owners.size() << " ExclusiveLimitAlarm types and instances";
  ASSERT_FALSE(stateMachines.empty())
    << "no ExclusiveLimitStateMachineType instance was found at all - LimitState is Mandatory on "
       "ExclusiveLimitAlarmType, so a Server exposing an ExclusiveLimitAlarm must carry one";

  // The sub-state edge is asserted on the TYPE DECLARATIONS and reported on instances, and the split is
  // normative rather than a convenience. Part 3 section 6.4.4.4.2: "If there would be a NonHierarchical
  // Reference between E and F in the InstanceDeclarationHierarchy, it is not specified if it occurs in
  // the instance hierarchy or not... or to both or none of them." HasTrueSubState is NonHierarchical
  // (Part 9 section 5.4.2), and ActiveState and LimitState are two InstanceDeclarations of one type, so an
  // instance carrying neither edge is conforming. Part 9 section 5.4.2's "it is required that the sub state
  // provides the inverse Reference" is a DIRECTION rule -- its own first half contrasts forward with
  // inverse -- not an instance-reproduction rule; where Part 9 does mean propagation it says so
  // outright (section 5.12, "All HasCondition References used in a Type shall exist in instances of these
  // Types as well"). Demanding it of instances would convict every Condition instance this SDK builds,
  // and this campaign already narrowed AC-SVR-ADDRSP-145 on the same clause.
  size_t declarationsChecked = 0;
  for (const auto& machineId : stateMachines)
  {
    const auto trueSubStateOf = browse_reference_targets(
      *mSession, machineId, NodeId{ReferenceTypeId::HasTrueSubState}, BrowseDirection::Inverse, false);
    const auto falseSubStateOf = browse_reference_targets(
      *mSession, machineId, NodeId{ReferenceTypeId::HasFalseSubState}, BrowseDirection::Inverse, false);
    const auto subStateMachineOf = browse_reference_targets(
      *mSession, machineId, NodeId{ReferenceTypeId::HasSubStateMachine}, BrowseDirection::Inverse, false);
    const bool bound = !(trueSubStateOf.empty() && falseSubStateOf.empty() && subStateMachineOf.empty());

    if (machineId.namespace_index() == 0)
    {
      ++declarationsChecked;
      EXPECT_TRUE(bound)
        << "the ExclusiveLimitStateMachine InstanceDeclaration " << ua::to_string(machineId)
        << " is the target of no IsTrueSubStateOf, IsFalseSubStateOf or HasSubStateMachine Reference. "
           "Part 9 section 5.8.19.3 fixes this edge on the type -- \"The LimitState is a sub state of the "
           "ActiveState and has an IsTrueSubStateOf reference to the ActiveState\" -- so a model whose "
           "type declaration lacks it cannot be navigated from the Alarm's ActiveState by any Client";
    }
    else if (!bound)
    {
      GTEST_LOG_(INFO) << "instance " << ua::to_string(machineId)
                       << " carries no sub-state edge; Part 3 section 6.4.4.4.2 leaves reproduction of a "
                          "NonHierarchical Reference between two InstanceDeclarations unspecified, so "
                          "this is recorded and not asserted";
    }
  }
  ASSERT_GT(declarationsChecked, 0u)
    << "no ExclusiveLimitStateMachine InstanceDeclaration was surveyed at all, so the assertion above "
       "ran against nothing and this test would pass on an empty model";

  // What section 5.8.19.2 DOES bind on an instance: "This state machine as it is defined shall be used as a
  // sub state machine for a state machine which has an Active state." So no instance may stand alone.
  for (size_t i = 0; i < stateMachines.size(); ++i)
  {
    if (stateMachines[i].namespace_index() == 0)
      continue;
    EXPECT_FALSE(find_hier_child(*mSession, stateMachineOwners[i], String{"ActiveState"}).is_null())
      << "the ExclusiveLimitStateMachine instance " << ua::to_string(stateMachines[i]) << " hangs off "
      << ua::to_string(stateMachineOwners[i])
      << ", which exposes no ActiveState -- so it is not being used as the sub state machine of a "
         "machine which has an Active state, which is the one thing section 5.8.19.2 does say about where "
         "this state machine may appear";
  }
}

// ===========================================================================
// Discrete Alarm subtypes: categorisation only
// ===========================================================================

/// The BrowseNames of a Node's hierarchical children, sorted. The member SET is what a categorisation
/// -only subtype must not extend.
static std::vector<std::string> hierarchical_member_names(ua::client::Session& session, const NodeId& nodeId)
{
  BrowseDescription desc;
  desc.node_id() = nodeId;
  desc.browse_direction() = BrowseDirection::Forward;
  desc.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
  desc.include_subtypes() = true;
  desc.node_class_mask() = 0;
  desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
  BrowseRequest req;
  req.nodes_to_browse().push_back(std::move(desc));

  std::vector<std::string> names;
  auto result = session.view().try_browse_sync(std::move(req));
  if (result.is_bad() || result.value().results().empty())
    return names;
  for (const auto& ref : result.value().results()[0].references())
    names.push_back(static_cast<std::string>(ref.browse_name().name()));
  std::sort(names.begin(), names.end());
  return names;
}

/// Everything in `names` that `other` does not carry.
static std::vector<std::string> names_absent_from(
  const std::vector<std::string>& names, const std::vector<std::string>& other)
{
  std::vector<std::string> extra;
  for (const auto& name : names)
  {
    if (std::find(other.begin(), other.end(), name) == other.end())
      extra.push_back(name);
  }
  return extra;
}

static std::string join_names(const std::vector<std::string>& names)
{
  std::string joined;
  for (const auto& name : names)
  {
    if (!joined.empty())
      joined += ", ";
    joined += name;
  }
  return joined;
}

/// A TripAlarmType instance, an OffNormalAlarmType instance and an AlarmConditionType instance, all
/// created through the same API with identically configured logic - so any difference between their
/// member sets comes from the type and not from how they were built.
class DiscreteAlarmSubtypeTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto& conditions = mServer.server().conditions();

    auto makeOffNormalLogic = []
    {
      auto logic = std::make_unique<OffNormalAlarmLogic>();
      logic->set_supports_confirm(true);
      logic->set_normal_state(Variant{false});
      return logic;
    };

    auto tripResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"TripAlarmInstance"},
      makeOffNormalLogic(),
      NodeId{ObjectTypeId::TripAlarmType});
    if (tripResult.is_good())
    {
      mTrip = tripResult.value();
      mTripId = mTrip->condition_id();
    }

    auto offNormalResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"OffNormalAlarmInstance"},
      makeOffNormalLogic(),
      NodeId{ObjectTypeId::OffNormalAlarmType});
    if (offNormalResult.is_good())
    {
      mOffNormalSubtype = offNormalResult.value();
      mOffNormalSubtypeId = mOffNormalSubtype->condition_id();
    }

    auto parentLogic = std::make_unique<AlarmConditionLogic>();
    parentLogic->set_supports_confirm(true);
    auto parentResult = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"PlainAlarmInstance"},
      std::move(parentLogic),
      NodeId{ObjectTypeId::AlarmConditionType});
    if (parentResult.is_good())
    {
      mParentAlarm = parentResult.value();
      mParentAlarmId = mParentAlarm->condition_id();
    }
  }

  /// Drive one alarm through activation, acknowledgement and shelving over the wire, reporting which of
  /// the three the Server actually applied.
  struct DriveOutcome
  {
    bool activated{false};
    bool acknowledged{false};
    bool shelved{false};
  };

  DriveOutcome drive_alarm(std::shared_ptr<ConditionInstance>& instance, const NodeId& conditionId)
  {
    DriveOutcome outcome;
    instance->enable_sync();
    instance->activate_sync(500);
    outcome.activated = instance->snapshot()->active();

    auto eventId = get_event_id(instance);
    if (!eventId.empty())
    {
      const auto status = call_condition_method(
        conditionId, "Acknowledge", Array<Variant>{Variant{eventId}, Variant{LocalizedText{"", "ack"}}});
      outcome.acknowledged = status.is_good() && instance->snapshot()->acked();
    }

    const auto shelveStatus = call_child_method(conditionId, "ShelvingState", "OneShotShelve");
    outcome.shelved = shelveStatus.is_good() && instance->snapshot()->suppressed_or_shelved();
    return outcome;
  }

  NodeId mTripId;
  NodeId mOffNormalSubtypeId;
  NodeId mParentAlarmId;
  std::shared_ptr<ConditionInstance> mTrip;
  std::shared_ptr<ConditionInstance> mOffNormalSubtype;
  std::shared_ptr<ConditionInstance> mParentAlarm;
};

// OPC 10000-9 5.8.24.4: the TripAlarmType "is mainly used for categorization" and Table 108 declares no
// member of its own; 5.8.24.1's Table 105 does the same for the DiscreteAlarmType. A subtype that added
// behaviour or members would break every Client that subscribed to the parent type expecting to receive
// it, which is the whole reason the subtype exists. Both subtypes are driven through activation,
// acknowledgement and shelving over the wire beside a plain AlarmConditionType instance built from the
// same API: a Server that routes a Condition Method by exact type definition rather than by walking the
// type hierarchy leaves the subtype instances unacknowledgeable and unshelveable while the parent works.
//
// NOTE ON SCOPE: the criterion says neither subtype exposes Properties beyond its parent's. Table 106
// declares NormalState Mandatory on the OffNormalAlarmType, so demanding that of the OffNormal instance
// would fail a conforming Server; the added-member assertion is therefore exact - TripAlarmType adds
// nothing to OffNormalAlarmType, and OffNormalAlarmType adds NormalState and nothing else.
// @verifies AC-SVR-AC-115-DISCRETE-SUBTYPES
TEST_F(DiscreteAlarmSubtypeTest, ADiscreteAlarmSubtypeBehavesAsItsParentAndAddsNoMemberOfItsOwn)
{
  // Asserted rather than skipped. The fixture instantiates all three types against this Server and
  // succeeds, so a null here is a fixture or product regression to report - and a conditional
  // skip would additionally make this test's coverage marker read as dead to the liveness gate,
  // which cannot tell a guard that never fires from a test that never runs.
  ASSERT_FALSE(mTripId.is_null() || mOffNormalSubtypeId.is_null() || mParentAlarmId.is_null())
    << "this Server could not instantiate one of TripAlarmType, OffNormalAlarmType or "
       "AlarmConditionType, so the subtypes have nothing to be compared against";

  const auto tripMembers = hierarchical_member_names(*mSession, mTripId);
  const auto offNormalMembers = hierarchical_member_names(*mSession, mOffNormalSubtypeId);
  const auto parentMembers = hierarchical_member_names(*mSession, mParentAlarmId);
  GTEST_LOG_(INFO) << "member counts - TripAlarm " << tripMembers.size() << ", OffNormalAlarm "
                   << offNormalMembers.size() << ", AlarmCondition " << parentMembers.size();
  ASSERT_FALSE(parentMembers.empty()) << "the plain AlarmConditionType instance exposes no members at "
                                         "all, so every set difference below would be meaningless";

  EXPECT_TRUE(names_absent_from(tripMembers, offNormalMembers).empty())
    << "the TripAlarmType instance carries member(s) its parent OffNormalAlarmType does not: "
    << join_names(names_absent_from(tripMembers, offNormalMembers))
    << " - Table 108 declares the subtype as categorisation only";
  EXPECT_TRUE(names_absent_from(offNormalMembers, tripMembers).empty())
    << "the TripAlarmType instance is MISSING member(s) of its parent OffNormalAlarmType: "
    << join_names(names_absent_from(offNormalMembers, tripMembers))
    << " - a categorisation-only subtype inherits the whole parent";

  const auto addedByOffNormal = names_absent_from(offNormalMembers, parentMembers);
  EXPECT_EQ(addedByOffNormal, (std::vector<std::string>{"NormalState"}))
    << "the OffNormalAlarmType instance adds { " << join_names(addedByOffNormal)
    << " } over an AlarmConditionType instance built the same way; Table 106 adds NormalState and "
       "nothing else, and Table 105 adds nothing at all to the AlarmConditionType";

  const auto tripOutcome = drive_alarm(mTrip, mTripId);
  const auto offNormalOutcome = drive_alarm(mOffNormalSubtype, mOffNormalSubtypeId);
  const auto parentOutcome = drive_alarm(mParentAlarm, mParentAlarmId);

  ASSERT_TRUE(parentOutcome.activated && parentOutcome.acknowledged && parentOutcome.shelved)
    << "the plain AlarmConditionType instance could not be driven through activation, acknowledgement "
       "and shelving, so the subtypes have no behaviour to be compared with";

  EXPECT_EQ(tripOutcome.activated, parentOutcome.activated)
    << "the TripAlarmType instance did not activate as its parent type does";
  EXPECT_EQ(tripOutcome.acknowledged, parentOutcome.acknowledged)
    << "Acknowledge was not applied to the TripAlarmType instance although it works on the parent type";
  EXPECT_EQ(tripOutcome.shelved, parentOutcome.shelved)
    << "OneShotShelve was not applied to the TripAlarmType instance although it works on the parent type";

  EXPECT_EQ(offNormalOutcome.activated, parentOutcome.activated)
    << "the OffNormalAlarmType instance did not activate as its parent type does";
  EXPECT_EQ(offNormalOutcome.acknowledged, parentOutcome.acknowledged)
    << "Acknowledge was not applied to the OffNormalAlarmType instance although it works on the parent "
       "type";
  EXPECT_EQ(offNormalOutcome.shelved, parentOutcome.shelved)
    << "OneShotShelve was not applied to the OffNormalAlarmType instance although it works on the parent "
       "type";
}

// ===========================================================================
// OffNormalAlarm: Active is inequality with NormalState
// ===========================================================================

/// An OffNormalAlarm bound to an Int32 input whose normal value is 0. Int32 rather than Boolean because
/// the discriminating stimulus is a value on the OTHER side of normal: with a Boolean there is only one
/// non-normal value and a threshold implementation cannot be told from an equality one.
class BoundOffNormalAlarmTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto addressSpace = mServer.server().address_space();
    auto& conditions = mServer.server().conditions();

    mOffNormalInputId = NodeId{0, uint32_t{50301}};
    auto inputNode = addressSpace.create_node_sync(mOffNormalInputId, NodeClass::Variable);
    auto inputVar = inputNode.as<VariableAccessor>();
    ASSERT_TRUE(inputVar.has_value());
    inputVar->set_browse_name(QualifiedName{0, "OffNormalInput"});
    inputVar->set_display_name(LocalizedText{"", "OffNormalInput"});
    inputVar->set_data_type(NodeId{DataTypeId::Int32});
    inputVar->write_value_sync(sNormalValue);
    inputVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mOffNormalInputId);

    auto logic = std::make_unique<OffNormalAlarmLogic>();
    logic->set_normal_state(Variant{sNormalValue});
    auto created = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"BoundOffNormalAlarm"},
      std::move(logic),
      NodeId{ObjectTypeId::OffNormalAlarmType});
    if (created.is_good())
    {
      mBoundOffNormal = created.value();
      mBoundOffNormalId = mBoundOffNormal->condition_id();
      mBoundOffNormal->enable_sync();
      mBoundOffNormal->bind_input_sync(mOffNormalInputId, sSamplingIntervalMs);
    }
  }

  void write_input(int32_t value)
  {
    auto inputNode = mServer.server().address_space().find_node_sync(mOffNormalInputId);
    auto inputVar = inputNode.as<VariableAccessor>();
    ASSERT_TRUE(inputVar.has_value());
    inputVar->write_value_sync(value);
  }

  bool wait_for_active(bool expected)
  {
    return poll_until([this, expected] { return mBoundOffNormal->snapshot()->active() == expected; },
      std::chrono::seconds{3});
  }

  static constexpr int32_t sNormalValue = 0;
  static constexpr double sSamplingIntervalMs = 100.0;

  NodeId mOffNormalInputId;
  NodeId mBoundOffNormalId;
  std::shared_ptr<ConditionInstance> mBoundOffNormal;
};

// OPC 10000-9 5.8.24.2: "When the value of the Variable referenced by the InputNode Property is not equal
// to the value of the NormalState Property the Alarm is Active." NormalState names a value rather than a
// range, so the comparison is equality in both directions - and an implementation that reuses the limit
// alarm's evaluation, the only other input-driven path a Server has, compares with a threshold and
// leaves the Alarm inactive for every input BELOW normal. The stimulus therefore moves the input above
// normal, back to normal, and then below normal; the third arm is the one a threshold fails.
// @verifies AC-SVR-AC-116-OFFNORMAL-ACTIVE
TEST_F(BoundOffNormalAlarmTest, OffNormalAlarm_IsActiveWheneverItsInputDiffersFromNormalStateEitherWay)
{
  // Asserted rather than skipped, for the reason its neighbours record: the fixture does instantiate
  // this alarm against this Server, so a null is a regression, and a conditional skip would make the
  // coverage marker read as dead.
  ASSERT_FALSE(mBoundOffNormalId.is_null())
    << "this Server could not instantiate an OffNormalAlarmType bound to an input, so the NormalState "
       "comparison has no subject";

  ASSERT_TRUE(wait_for_active(false))
    << "the alarm is Active while its input holds the NormalState value, so the comparison is not "
       "equality with NormalState at all";

  write_input(1);
  EXPECT_TRUE(wait_for_active(true))
    << "the input moved away from NormalState (0 -> 1) and the Alarm did not become Active";

  write_input(sNormalValue);
  EXPECT_TRUE(wait_for_active(false))
    << "the input returned to the NormalState value and the Alarm stayed Active";

  write_input(-5);
  EXPECT_TRUE(wait_for_active(true))
    << "the input moved away from NormalState in the other direction (0 -> -5) and the Alarm stayed "
       "inactive - the evaluation is a threshold, and NormalState names a value rather than a bound";
}

// ===========================================================================
// RateOfChangeAlarm: the limits are per second
// ===========================================================================

/// An ExclusiveRateOfChangeAlarmType bound to a Double input, carrying a High limit of 50 and no
/// EngineeringUnits - so 5.8.23.3's default reading applies and the limit means 50 units per second.
class RateOfChangeAlarmTest : public ComplianceConditionTest
{
protected:
  void configure_server() override
  {
    ComplianceConditionTest::configure_server();

    auto addressSpace = mServer.server().address_space();
    auto& conditions = mServer.server().conditions();

    mRateInputId = NodeId{0, uint32_t{50401}};
    auto inputNode = addressSpace.create_node_sync(mRateInputId, NodeClass::Variable);
    auto inputVar = inputNode.as<VariableAccessor>();
    ASSERT_TRUE(inputVar.has_value());
    inputVar->set_browse_name(QualifiedName{0, "RateOfChangeInput"});
    inputVar->set_display_name(LocalizedText{"", "RateOfChangeInput"});
    inputVar->set_data_type(NodeId{DataTypeId::Double});
    inputVar->write_value_sync(0.0);
    inputVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mRateInputId);

    auto logic = std::make_unique<LimitAlarmLogic>();
    logic->set_exclusive(true);
    LimitConfig limits;
    limits.highLimit = sHighLimit;
    logic->set_limits(limits);

    auto created = conditions.try_create_condition_sync(NodeId{0, uint32_t{0}},
      NodeId{ObjectId::ObjectsFolder},
      String{"RateOfChangeAlarm"},
      std::move(logic),
      NodeId{ObjectTypeId::ExclusiveRateOfChangeAlarmType});
    if (created.is_good())
    {
      mRateAlarm = created.value();
      mRateAlarmId = mRateAlarm->condition_id();
      mRateAlarm->enable_sync();
      mRateAlarm->bind_input_sync(mRateInputId, sSamplingIntervalMs);
    }
  }

  void write_input(double value)
  {
    auto inputNode = mServer.server().address_space().find_node_sync(mRateInputId);
    auto inputVar = inputNode.as<VariableAccessor>();
    ASSERT_TRUE(inputVar.has_value());
    inputVar->write_value_sync(value);
  }

  static constexpr double sHighLimit = 50.0;  // units per second, per 5.8.23.3's default
  static constexpr double sSamplingIntervalMs = 50.0;

  NodeId mRateInputId;
  NodeId mRateAlarmId;
  std::shared_ptr<ConditionInstance> mRateAlarm;
};

// OPC 10000-9 5.8.23.3 with 5.8.18: "EngineeringUnits provides the engineering units associated with the
// limits values. If this is not provided the assumed Engineering Unit is the same as the EU associated
// with the parent variable per second"; 5.8.18 says the same in one line - "For Rate of change limit
// Alarms, it is assumed this rate is units per second unless otherwise specified." The implicit unit is
// where a factor of sixty hides, and worse: the natural implementation of a Type derived from
// ExclusiveLimitAlarmType compares the input VALUE against the limit, because that is what every other
// limit alarm does and every number involved stays plausible. The two arms separate rate from value -
// one drives the input at 100 units per second while its value stays below the limit, the other parks
// the value far above the limit at a rate of zero.
// @verifies AC-SVR-AC-210-RATEOFCHANGE-PER-SECOND
TEST_F(RateOfChangeAlarmTest, ARateOfChangeAlarmWithNoEngineeringUnitsReadsItsLimitAsUnitsPerSecond)
{
  // Both preconditions are asserted rather than skipped. The fixture instantiates this alarm against
  // this Server, and it builds it WITHOUT an EngineeringUnits Property precisely so that the
  // per-second default is the reading under test - so neither condition is a property of the Server
  // that this test must tolerate, and a conditional skip would additionally make the coverage
  // marker read as dead to the liveness gate while the test is red on a real defect.
  ASSERT_FALSE(mRateAlarmId.is_null())
    << "this Server offers no way to instantiate a RateOfChangeAlarm, so the address space contains no "
       "subject for the per-second rule - refusing the type is one way to satisfy 5.8.23, and a Server "
       "that took it would need this criterion ruled no-subject rather than tested";

  // The default reading applies only where no EngineeringUnits is published; where one is, the limit
  // means whatever it declares and the arms below would be asserting the wrong unit.
  const auto engineeringUnits = find_hier_child(*mSession, mRateAlarmId, String{"EngineeringUnits"});
  ASSERT_TRUE(engineeringUnits.is_null())
    << "the fixture's RateOfChangeAlarm has acquired an EngineeringUnits Property, so its limits are "
       "read in the declared unit rather than the per-second default and the arms below would assert "
       "the wrong unit";

  // Arm 1 - a rate far above the limit while the value stays below it. Ten steps of 5 units every 50 ms
  // is 100 units per second against a limit of 50, and the value never exceeds 50.
  bool activatedOnRate = false;
  for (int step = 1; step <= 9 && !activatedOnRate; ++step)
  {
    write_input(static_cast<double>(step) * 5.0);
    activatedOnRate =
      poll_until([this] { return mRateAlarm->snapshot()->active(); }, std::chrono::milliseconds{50});
  }
  EXPECT_TRUE(activatedOnRate)
    << "the input rose at 100 units per second against a High limit of " << sHighLimit
    << " per second and the Alarm never activated - the limit is not being read as a rate";

  // Arm 2 - the value parked far above the limit at a rate of zero. A Server comparing the value against
  // the limit is Active here; one comparing the rate is not.
  write_input(1000.0);
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  EXPECT_FALSE(mRateAlarm->snapshot()->active())
    << "the input has been constant at 1000 for well over a second - a rate of zero against a High limit "
       "of "
    << sHighLimit
    << " per second - and the Alarm is Active, so the limit is being compared "
       "with the value rather than with its rate of change";
}

// Part 9 section 5.8.18, on the limit Properties of `LimitAlarmType`: "These Properties are listed as
// optional but at least one is required. For cases where an underlying system cannot provide the
// actual value of a limit, **the limit Property shall still be provided, but will have its
// AccessLevel set to not readable**."
//
// `ConfiguredLimit::unavailable()` expresses the third state separately from an absent outer
// optional. The optional-child filter must materialise it, but the one-time wiring pass must clear
// CurrentRead and must not install a substitute value reader.
//
// The substitute is the reason the clause exists. A Client reads the limits to compute how far the
// process value is from alarming; against a plausible default it computes a margin that does not
// exist, and against an absent Property it cannot tell an alarm with no HighHigh limit from one whose
// HighHigh limit the field device did not report this scan.
//
// The control is the limit that IS supplied: HighHigh materialises and reads Good, so a failure here
// is about the unavailable case and not about limit Properties in general.
// @verifies AC-SVR-AC-202-LIMIT-UNAVAILABLE-STATUS
TEST_F(ComplianceLimitAlarmTest, AnUnsuppliableLimitIsPublishedUnreadableRatherThanOmitted)
{
  auto addressSpace = mServer.server().address_space();
  auto alarm = addressSpace.try_find_node_sync(mLimitAlarmId);
  ASSERT_TRUE(alarm.is_good()) << "the alarm instance is not in the address space";

  std::map<std::string, NodeId> properties;
  for (const auto& ref : alarm.value().get_references_sync())
  {
    if (!ref.is_forward() || !ref.target_id().is_local())
      continue;
    auto child = addressSpace.try_find_node_sync(ref.target_id().node_id());
    if (child.is_good())
      properties.emplace(std::string{child.value().get_browse_name().name()}, child.value().get_node_id());
  }

  // The control: the limit the fixture supplies a value for is present and readable.
  auto supplied = properties.find("HighHighLimit");
  ASSERT_NE(supplied, properties.end())
    << "the configured HighHigh limit did not materialise at all, so this test's comparison has no "
       "baseline and says nothing about the unavailable case";
  auto suppliedNode = addressSpace.try_find_node_sync(supplied->second);
  ASSERT_TRUE(suppliedNode.is_good());
  if (auto variable = suppliedNode.value().as<VariableAccessor>())
  {
    EXPECT_TRUE(variable->get_access_level().test(AccessLevelType::Bit::CurrentRead))
      << "a limit whose value the system does supply must be readable";
  }

  // The subject: a limit this alarm has, whose value the underlying system cannot provide.
  auto unsuppliable = properties.find("HighLimit");
  ASSERT_NE(unsuppliable, properties.end())
    << "a limit whose value the underlying system cannot provide was omitted from the instance "
       "entirely. Part 9 section 5.8.18 requires the Property to be provided and made unreadable, "
       "precisely so a Client can tell 'this alarm has no High limit' from 'this alarm's High limit "
       "was not reported'";

  auto unsuppliableNode = addressSpace.try_find_node_sync(unsuppliable->second);
  ASSERT_TRUE(unsuppliableNode.is_good());
  auto variable = unsuppliableNode.value().as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value()) << "HighLimit is not a Variable";
  EXPECT_FALSE(variable->get_access_level().test(AccessLevelType::Bit::CurrentRead))
    << "the unsuppliable limit is published readable, so a Client will read whatever value stands in "
       "for the one the system could not give and compute an alarm margin from it";
}
