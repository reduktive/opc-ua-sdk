// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_address_space_change_event_emitter.h"
#include "ua_base_model_change_event_payload.h"
#include "ua_general_model_change_event_payload.h"
#include "ua_model_change_structure_data_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_semantic_change_event_payload.h"
#include "ua_semantic_change_structure_data_type.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"

#include <memory>
#include <stdexcept>
#include <vector>

namespace
{

using namespace ua;
using namespace ua::server;

class CapturingSink final : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    events.push_back(event.clone());
  }

  std::vector<std::unique_ptr<BaseEvent>> events;
};

class ThrowingSink final : public EventSink
{
public:
  void emit(BaseEvent&) override
  {
    ++calls;
    throw std::runtime_error{"sentinel sink failure"};
  }

  size_t calls{0};
};

uint8_t verb(ModelChangeStructureVerbMask mask)
{
  return static_cast<uint8_t>(static_cast<int32_t>(mask));
}

// One Semantic change listing @p owners, each with the owner's type.
detail::AddressSpaceChange semantic_change(std::vector<detail::ModelChangeEntry> owners)
{
  detail::AddressSpaceChange change;
  change.kind = detail::AddressSpaceChangeKind::Semantic;
  change.changes = std::move(owners);
  return change;
}

// One operation's model changes.
detail::AddressSpaceChange model_change(
  std::vector<detail::ModelChangeEntry> changes, bool unspecified = false)
{
  detail::AddressSpaceChange change;
  change.kind = detail::AddressSpaceChangeKind::Model;
  change.changes = std::move(changes);
  change.unspecified = unspecified;
  return change;
}

template<typename Change>
const Change* only_change(const Variant& changes)
{
  if (!changes.is_array_of_structure())
    return nullptr;
  const auto& entries = changes.as<Array<RefStructure<Structure>>>();
  if (entries.size() != 1)
    return nullptr;
  return dynamic_cast<const Change*>(entries[0].get());
}

// Part 3 section section 5.6.2/9.33.1 and Part 5 section 12.17 require the semantic payload to name the
// changed Property's owner and the owner's TypeDefinition.
// @relation(AC-SVR-ADDRSP-088-SEMANTICCHANGEEVENT-RAISED, scope=function)
// @relation(AC-SVR-BASE-023-SEMANTICCHANGEEVENT, scope=function)
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-01-SEMANTIC-PAYLOAD, scope=function)
TEST(AddressSpaceChangeEventEmitterTest, SemanticChangeUsesExactOwnerAndTypePayload)
{
  auto sink = std::make_shared<CapturingSink>();
  AddressSpaceChangeEventEmitter emitter{sink};
  const NodeId affected{2, "semantic-owner"};
  const NodeId affectedType{2, "semantic-owner-type"};

  emitter.emit(semantic_change({{affected, affectedType, 0}}));

  ASSERT_EQ(sink->events.size(), 1u);
  const auto* event = dynamic_cast<const SemanticChangeEventPayload*>(sink->events.front().get());
  ASSERT_NE(event, nullptr);
  EXPECT_EQ(event->sourceNode, NodeId{ObjectId::Server});
  const auto* entry = only_change<SemanticChangeStructureDataType>(event->changes);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->affected(), affected);
  EXPECT_EQ(entry->affected_type(), affectedType);
}

// Part 3 section 9.33.1: one SemanticChangeEvent lists every owner of a change, in the order given.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-01-SEMANTIC-PAYLOAD, scope=function)
TEST(AddressSpaceChangeEventEmitterTest, ASemanticChangeListsEveryOwner)
{
  auto sink = std::make_shared<CapturingSink>();
  AddressSpaceChangeEventEmitter emitter{sink};
  const NodeId firstOwner{2, "first-owner"};
  const NodeId firstType{2, "first-type"};
  const NodeId secondOwner{2, "second-owner"};
  const NodeId secondType{2, "second-type"};

  emitter.emit(semantic_change({{firstOwner, firstType, 0}, {secondOwner, secondType, 0}}));

  ASSERT_EQ(sink->events.size(), 1u);
  const auto* event = dynamic_cast<const SemanticChangeEventPayload*>(sink->events.front().get());
  ASSERT_NE(event, nullptr);
  ASSERT_TRUE(event->changes.is_array_of_structure());
  const auto& entries = event->changes.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(entries.size(), 2u);
  const auto* first = dynamic_cast<const SemanticChangeStructureDataType*>(entries[0].get());
  const auto* second = dynamic_cast<const SemanticChangeStructureDataType*>(entries[1].get());
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  EXPECT_EQ(first->affected(), firstOwner);
  EXPECT_EQ(first->affected_type(), firstType);
  EXPECT_EQ(second->affected(), secondOwner);
  EXPECT_EQ(second->affected_type(), secondType);
}

// Part 3 section 9.32.1 and Part 5 section 12.16 assign a DataType Attribute mutation to a
// GeneralModelChangeEvent carrying exactly the DataTypeChanged verb.
// @relation(AC-SVR-ADDRSP-245-NODEVERSION-MODELCHANGE-INVARIANT, scope=function)
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-02-VERSIONED-DATATYPE, scope=function)
TEST(AddressSpaceChangeEventEmitterTest, DataTypeChangeUsesGeneralModelEventAndExactVerb)
{
  auto sink = std::make_shared<CapturingSink>();
  AddressSpaceChangeEventEmitter emitter{sink};
  const NodeId affected{2, "retyped-variable"};
  const NodeId affectedType{0, VariableTypeId::BaseDataVariableType};

  emitter.emit(model_change({{affected, affectedType, verb(ModelChangeStructureVerbMask::DataTypeChanged)}}));

  ASSERT_EQ(sink->events.size(), 1u);
  const auto* event = dynamic_cast<const GeneralModelChangeEventPayload*>(sink->events.front().get());
  ASSERT_NE(event, nullptr);
  EXPECT_EQ(event->sourceNode, NodeId{ObjectId::Server});
  const auto* entry = only_change<ModelChangeStructureDataType>(event->changes);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->affected(), affected);
  EXPECT_EQ(entry->affected_type(), affectedType);
  EXPECT_EQ(
    entry->verb(), static_cast<uint8_t>(static_cast<int32_t>(ModelChangeStructureVerbMask::DataTypeChanged)));
}

// Part 5 sections 6.4.31 and 6.4.33: the SDK generates its model and semantic change Events in the context
// of the whole AddressSpace, so each names the Server Object as its SourceNode and "Server" as its
// SourceName.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-04-SERVER-CONTEXT, scope=function)
// @relation(AC-SVR-EVT-TYP-013-SOURCENODE-SERVER-OBJECT, scope=function)
// @relation(AC-SVR-EVT-TYP-014-SOURCENAME-SERVER, scope=function)
// @relation(AC-SVR-EVT-TYP-016-SOURCENODE-SERVER-OBJECT, scope=function)
// @relation(AC-SVR-EVT-TYP-017-SOURCENAME-SERVER, scope=function)
TEST(AddressSpaceChangeEmitter, ModelChangeEventFieldsNameTheServer)
{
  auto sink = std::make_shared<CapturingSink>();
  AddressSpaceChangeEventEmitter emitter{sink};

  emitter.emit(model_change({{NodeId{2, "retyped-variable"},
    NodeId{0, VariableTypeId::BaseDataVariableType},
    verb(ModelChangeStructureVerbMask::DataTypeChanged)}}));
  emitter.emit(semantic_change({{NodeId{2, "semantic-owner"}, NodeId{2, "owner-type"}, 0}}));

  ASSERT_EQ(sink->events.size(), 2u);
  const auto* modelChange = dynamic_cast<const GeneralModelChangeEventPayload*>(sink->events[0].get());
  ASSERT_NE(modelChange, nullptr) << "the DataType change was not reported as a GeneralModelChangeEvent";
  EXPECT_EQ(modelChange->sourceNode, NodeId{ObjectId::Server});
  EXPECT_EQ(std::string{static_cast<std::string_view>(modelChange->sourceName)}, "Server");

  const auto* semanticChange = dynamic_cast<const SemanticChangeEventPayload*>(sink->events[1].get());
  ASSERT_NE(semanticChange, nullptr) << "the semantic change was not reported as a SemanticChangeEvent";
  EXPECT_EQ(semanticChange->sourceNode, NodeId{ObjectId::Server});
  EXPECT_EQ(std::string{static_cast<std::string_view>(semanticChange->sourceName)}, "Server");
}

// The change receiver runs at an async mutation boundary. Sink teardown or a throwing sink is
// contained and cannot unwind into the completed AddressSpace mutation.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-03-BOUNDARY-FAILURES, scope=function)
TEST(AddressSpaceChangeEventEmitterTest, MissingAndThrowingSinksAreContained)
{
  auto throwing = std::make_shared<ThrowingSink>();
  AddressSpaceChangeEventEmitter throwingEmitter{throwing};
  EXPECT_NO_THROW(throwingEmitter.emit(semantic_change({{NodeId{1, "owner"}, NodeId{1, "type"}, 0}})));
  EXPECT_EQ(throwing->calls, 1u);

  std::weak_ptr<EventSink> expired;
  {
    auto sink = std::make_shared<CapturingSink>();
    expired = sink;
  }
  AddressSpaceChangeEventEmitter expiredEmitter{expired};
  EXPECT_NO_THROW(expiredEmitter.emit(
    model_change({{NodeId{1, "node"}, NodeId{1, "type"}, verb(ModelChangeStructureVerbMask::NodeAdded)}})));
}

// Part 5 12.16 Table 240: one GeneralModelChangeEvent carries every change of an operation, each Node once
// with the verbs of its changes, and its TypeDefinition when it is an Object or Variable.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-ONE-EVENT-LISTS-AN-OPERATIONS-CHANGES, scope=function)
TEST(AddressSpaceChangeEventEmitterTest, AnOperationsChangesAreListedInOneGeneralModelChangeEvent)
{
  auto sink = std::make_shared<CapturingSink>();
  AddressSpaceChangeEventEmitter emitter{sink};
  const detail::ModelChangeEntry added{NodeId{2, "added"},
    NodeId{0, VariableTypeId::BaseDataVariableType},
    static_cast<uint8_t>(
      verb(ModelChangeStructureVerbMask::NodeAdded) | verb(ModelChangeStructureVerbMask::ReferenceAdded))};
  const detail::ModelChangeEntry parent{
    NodeId{2, "parent"}, NodeId{}, verb(ModelChangeStructureVerbMask::ReferenceAdded)};

  emitter.emit(model_change({added, parent}));

  ASSERT_EQ(sink->events.size(), 1u);
  const auto* event = dynamic_cast<const GeneralModelChangeEventPayload*>(sink->events.front().get());
  ASSERT_NE(event, nullptr);
  ASSERT_TRUE(event->changes.is_array_of_structure());
  const auto& entries = event->changes.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(entries.size(), 2u);
  const detail::ModelChangeEntry* expected[] = {&added, &parent};
  for (std::size_t i = 0; i < entries.size(); ++i)
  {
    const auto* entry = dynamic_cast<const ModelChangeStructureDataType*>(entries[i].get());
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->affected(), expected[i]->affected);
    EXPECT_EQ(entry->affected_type(), expected[i]->affectedType);
    EXPECT_EQ(entry->verb(), expected[i]->verbs);
  }
}

// Part 3 9.32.5: "The BaseModelChangeEventType is the base type for ModelChangeEvents and does not contain
// information about the changes but only indicates that changes occurred." ModelChangeStructureVerbMask has
// no verb for a ValueRank or ArrayDimensions change, and the server's MaxArrayLength bounds an Event field
// (Part 5 6.3.2): an operation holding such a change, or more changes than MaxArrayLength, is reported by
// that type itself, never by two event types (Part 3 9.32.7).
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-05-BASE-MODEL-CHANGE-PAYLOAD, scope=function)
TEST(AddressSpaceChangeEventEmitterTest, AChangeWithNoVerbOrALongerListUsesOneBaseModelChangeEvent)
{
  auto sink = std::make_shared<CapturingSink>();
  AddressSpaceChangeEventEmitter emitter{sink, Logger{}, 1u};
  const detail::ModelChangeEntry dataType{NodeId{2, "reshaped"},
    NodeId{0, VariableTypeId::BaseDataVariableType},
    verb(ModelChangeStructureVerbMask::DataTypeChanged)};
  const detail::ModelChangeEntry other{
    NodeId{2, "other"}, NodeId{}, verb(ModelChangeStructureVerbMask::ReferenceAdded)};

  emitter.emit(model_change({dataType}, /*unspecified=*/true));
  emitter.emit(model_change({dataType, other}));
  // The control: a list MaxArrayLength holds stays a GeneralModelChangeEvent.
  emitter.emit(model_change({dataType}));

  ASSERT_EQ(sink->events.size(), 3u);
  for (std::size_t index : {0u, 1u})
  {
    const auto& event = *sink->events[index];
    EXPECT_NE(dynamic_cast<const BaseModelChangeEventPayload*>(&event), nullptr)
      << "Event " << index << " is not a ModelChangeEvent";
    EXPECT_EQ(dynamic_cast<const GeneralModelChangeEventPayload*>(&event), nullptr)
      << "Event " << index << " is a GeneralModelChangeEvent";
    EXPECT_EQ(event.eventType, NodeId{ObjectTypeId::BaseModelChangeEventType})
      << "Event " << index << " has the type " << to_string(event.eventType);
    EXPECT_EQ(event.sourceNode, NodeId{ObjectId::Server});
  }
  EXPECT_NE(dynamic_cast<const GeneralModelChangeEventPayload*>(sink->events[2].get()), nullptr)
    << "a list within MaxArrayLength is no longer a GeneralModelChangeEvent";
}

}  // namespace
