// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_base_event.h"
#include "ua_generic_event.h"
#include "ua_objecttype_id.h"
#include "ua_variant.h"
#include "ua_data_value.h"

using namespace ua;

namespace
{

const NodeId serverObjectId{0, 2253u};

BaseEvent make_base_event()
{
  BaseEvent event;
  event.eventType = NodeId{ObjectTypeId::BaseEventType};
  event.sourceNode = serverObjectId;
  event.sourceName = String{"Server"};
  event.message = LocalizedText{LocaleId{}, String{"Test event"}};
  event.severity = 500;
  event.eventId = ByteString{0x01, 0x02, 0x03};
  event.time = DateTime::now();
  event.receiveTime = DateTime::now();
  return event;
}

}  // namespace

// ============================================================================
// BaseEvent field resolution
// ============================================================================

TEST(BaseEventTests, ResolveMandatoryFields)
{
  auto event = make_base_event();

  // EventId
  auto eventId = event.resolve_field(std::array{QualifiedName{0, "EventId"}});
  ASSERT_FALSE(eventId.empty());
  EXPECT_TRUE(eventId.is_byte_string());

  // EventType
  auto eventType = event.resolve_field(std::array{QualifiedName{0, "EventType"}});
  ASSERT_FALSE(eventType.empty());
  EXPECT_TRUE(eventType.is_node_id());
  auto expectedType = NodeId{ObjectTypeId::BaseEventType};
  EXPECT_EQ(eventType.as<NodeId>(), expectedType);

  // SourceNode
  auto sourceNode = event.resolve_field(std::array{QualifiedName{0, "SourceNode"}});
  ASSERT_FALSE(sourceNode.empty());
  EXPECT_TRUE(sourceNode.is_node_id());
  EXPECT_EQ(sourceNode.as<NodeId>(), serverObjectId);

  // SourceName
  auto sourceName = event.resolve_field(std::array{QualifiedName{0, "SourceName"}});
  ASSERT_FALSE(sourceName.empty());
  EXPECT_TRUE(sourceName.is_string());

  // Time
  auto time = event.resolve_field(std::array{QualifiedName{0, "Time"}});
  ASSERT_FALSE(time.empty());
  EXPECT_TRUE(time.is_date_time());

  // ReceiveTime
  auto receiveTime = event.resolve_field(std::array{QualifiedName{0, "ReceiveTime"}});
  ASSERT_FALSE(receiveTime.empty());
  EXPECT_TRUE(receiveTime.is_date_time());

  // Message
  auto message = event.resolve_field(std::array{QualifiedName{0, "Message"}});
  ASSERT_FALSE(message.empty());
  EXPECT_TRUE(message.is_localized_text());

  // Severity
  auto severity = event.resolve_field(std::array{QualifiedName{0, "Severity"}});
  ASSERT_FALSE(severity.empty());
  EXPECT_TRUE(severity.is_uint16());
  EXPECT_EQ(severity.as<uint16_t>(), 500);
}

TEST(BaseEventTests, ResolveUnknownFieldReturnsNull)
{
  auto event = make_base_event();

  auto result = event.resolve_field(std::array{QualifiedName{0, "NonExistentField"}});
  EXPECT_TRUE(result.empty());
}

TEST(BaseEventTests, ResolveEmptyBrowsePathReturnsNull)
{
  auto event = make_base_event();

  auto result = event.resolve_field(std::span<const QualifiedName>{});
  EXPECT_TRUE(result.empty());
}

TEST(BaseEventTests, ResolveMultiElementPathReturnsNull)
{
  auto event = make_base_event();

  std::array path{QualifiedName{0, "Message"}, QualifiedName{0, "Text"}};
  auto result = event.resolve_field(path);
  EXPECT_TRUE(result.empty());
}

TEST(BaseEventTests, ResolveNonZeroNamespaceReturnsNull)
{
  auto event = make_base_event();

  auto result = event.resolve_field(std::array{QualifiedName{1, "EventId"}});
  EXPECT_TRUE(result.empty());
}

TEST(BaseEventTests, DefaultMessageResolvesToLocalizedText)
{
  // TEST-BET-006-N1: A default-constructed Message still resolves to a LocalizedText
  // (documents current behavior - no null fallback).
  BaseEvent event;
  event.eventType = NodeId{ObjectTypeId::BaseEventType};
  event.sourceNode = serverObjectId;
  event.severity = 1;

  auto result = event.resolve_field(std::array{QualifiedName{0, "Message"}});
  ASSERT_FALSE(result.empty());
  EXPECT_TRUE(result.is_localized_text());
}

TEST(BaseEventTests, OptionalFieldNotSetReturnsNull)
{
  auto event = make_base_event();
  auto result = event.resolve_field(std::array{QualifiedName{0, "ConditionClassId"}});
  EXPECT_TRUE(result.empty());
}

TEST(BaseEventTests, OptionalFieldSetReturnsValue)
{
  auto event = make_base_event();
  event.conditionClassId = NodeId{0, 12345u};

  auto result = event.resolve_field(std::array{QualifiedName{0, "ConditionClassId"}});
  ASSERT_FALSE(result.empty());
  EXPECT_TRUE(result.is_node_id());
  auto expected = NodeId{0, 12345u};
  EXPECT_EQ(result.as<NodeId>(), expected);
}

// @relation(AC-SVR-AC-040-CONDITION-EVENT-CLASSIFICATION, scope=function)
TEST(BaseEventTests, ConditionTypeAndResolvedSubtypesAreConditionEvents)
{
  auto condition = make_base_event();
  condition.eventType = NodeId{ObjectTypeId::ConditionType};

  auto conditionSubtype = make_base_event();
  conditionSubtype.eventType = NodeId{2, 5001u};
  conditionSubtype.eventTypeHierarchy =
    std::make_shared<const std::vector<NodeId>>(std::initializer_list<NodeId>{
      conditionSubtype.eventType,
      NodeId{ObjectTypeId::AcknowledgeableConditionType},
      NodeId{ObjectTypeId::ConditionType},
      NodeId{ObjectTypeId::BaseEventType},
    });

  EXPECT_TRUE(condition.is_condition_event());
  EXPECT_TRUE(conditionSubtype.is_condition_event());
}

// @relation(AC-SVR-AC-040-CONDITION-EVENT-CLASSIFICATION, scope=function)
TEST(BaseEventTests, NonConditionHierarchyIsNotAConditionEvent)
{
  auto event = make_base_event();
  event.eventType = NodeId{ObjectTypeId::AuditEventType};
  event.eventTypeHierarchy = std::make_shared<const std::vector<NodeId>>(std::initializer_list<NodeId>{
    event.eventType,
    NodeId{ObjectTypeId::BaseEventType},
  });

  EXPECT_FALSE(event.is_condition_event());
}

// ============================================================================
// GenericEvent
// ============================================================================

TEST(GenericEventTests, ResolveBaseFieldsWork)
{
  auto typeId = NodeId{1, 5000u};
  GenericEvent event{typeId};
  event.sourceNode = NodeId{1, 100u};
  event.severity = 300;

  auto severity = event.resolve_field(std::array{QualifiedName{0, "Severity"}});
  ASSERT_FALSE(severity.empty());
  EXPECT_EQ(severity.as<uint16_t>(), 300);

  auto eventType = event.resolve_field(std::array{QualifiedName{0, "EventType"}});
  ASSERT_FALSE(eventType.empty());
  EXPECT_EQ(eventType.as<NodeId>(), typeId);
}

TEST(GenericEventTests, SetAndResolveExtensionField)
{
  GenericEvent event{NodeId{1, 5000u}};
  event.set_field({QualifiedName{1, "PressureValue"}}, Variant{4.82});

  auto result = event.resolve_field(std::array{QualifiedName{1, "PressureValue"}});
  ASSERT_FALSE(result.empty());
  EXPECT_TRUE(result.is_double());
  EXPECT_DOUBLE_EQ(result.as<double>(), 4.82);
}

TEST(GenericEventTests, SetFieldOverwritesExisting)
{
  GenericEvent event{NodeId{1, 5000u}};
  event.set_field({QualifiedName{1, "Temperature"}}, Variant{25.0});
  event.set_field({QualifiedName{1, "Temperature"}}, Variant{30.0});

  auto result = event.resolve_field(std::array{QualifiedName{1, "Temperature"}});
  ASSERT_FALSE(result.empty());
  EXPECT_DOUBLE_EQ(result.as<double>(), 30.0);
}

TEST(GenericEventTests, ResolveUnknownExtensionFieldReturnsNull)
{
  GenericEvent event{NodeId{1, 5000u}};
  event.set_field({QualifiedName{1, "Temperature"}}, Variant{25.0});

  auto result = event.resolve_field(std::array{QualifiedName{1, "Humidity"}});
  EXPECT_TRUE(result.empty());
}

TEST(GenericEventTests, MultiElementBrowsePath)
{
  GenericEvent event{NodeId{1, 5000u}};
  std::vector<QualifiedName> path{QualifiedName{1, "Component"}, QualifiedName{1, "Value"}};
  event.set_field(path, Variant{42});

  std::array<QualifiedName, 2> lookup{QualifiedName{1, "Component"}, QualifiedName{1, "Value"}};
  auto result = event.resolve_field(lookup);
  ASSERT_FALSE(result.empty());
  EXPECT_EQ(result.as<int32_t>(), 42);
}

TEST(GenericEventTests, BaseFieldsTakePriorityOverExtension)
{
  GenericEvent event{NodeId{1, 5000u}};
  event.severity = 500;
  event.set_field({QualifiedName{0, "Severity"}}, Variant{uint16_t{999}});

  auto result = event.resolve_field(std::array{QualifiedName{0, "Severity"}});
  ASSERT_FALSE(result.empty());
  EXPECT_EQ(result.as<uint16_t>(), 500);
}
