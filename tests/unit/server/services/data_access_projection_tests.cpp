// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/strand.hpp>

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "fake_async_namespace.h"
#include "fake_node.h"
#include "ua_data_access_projection.h"
#include "ua_enum_value_type.h"
#include "ua_instance_utils.h"
#include "ua_referencetype_id.h"

namespace ua::server
{
namespace
{

// @relation(AC-SVR-DA-013-MULTISTATEVALUE-PROPERTIES, scope=function)
TEST(DataAccessProjectionTests, ValueAsTextFollowsTheOwningVariablesCurrentEnumValue)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace = AddressSpace::create("urn:test:data-access-projection", threadPool.get_executor());
  const NodeId ownerId{1, 9500u};
  const NodeId enumValuesId{1, 9501u};
  const NodeId valueAsTextId{1, 9502u};

  auto ownerNode = addressSpace.create_node_sync(ownerId, NodeClass::Variable);
  auto owner = ownerNode.as<VariableAccessor>();
  ASSERT_TRUE(owner.has_value());
  owner->set_browse_name(QualifiedName{1, "State"});
  owner->set_data_type(NodeId{DataTypeId::Int64});
  owner->write_value_sync(Variant{int64_t{2}});

  auto enumNode = addressSpace.create_node_sync(enumValuesId, NodeClass::Variable);
  auto enumValues = enumNode.as<VariableAccessor>();
  ASSERT_TRUE(enumValues.has_value());
  enumValues->set_browse_name(QualifiedName{0, "EnumValues"});
  enumValues->set_data_type(NodeId{DataTypeId::EnumValueType});
  Array<RefStructure<Structure>> entries;
  for (const auto& [value, label] : std::vector<std::pair<int64_t, std::string>>{{1, "Low"}, {2, "High"}})
  {
    auto entry = std::make_unique<EnumValueType>();
    entry->value() = value;
    entry->display_name() = LocalizedText{"", label};
    entries.push_back(RefStructure<Structure>{std::move(entry)});
  }
  enumValues->write_value_sync(Variant{std::move(entries)});
  ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, enumValuesId);

  auto textNode = addressSpace.create_node_sync(valueAsTextId, NodeClass::Variable);
  auto valueAsText = textNode.as<VariableAccessor>();
  ASSERT_TRUE(valueAsText.has_value());
  valueAsText->set_browse_name(QualifiedName{0, "ValueAsText"});
  valueAsText->set_data_type(NodeId{DataTypeId::LocalizedText});
  valueAsText->write_value_sync(Variant{LocalizedText{"", "Low"}});
  ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, valueAsTextId);
  textNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerId, false);

  std::promise<data_access_projection::OptionalLocalizedTextResult> promise;
  auto future = promise.get_future();
  data_access_projection::value_as_text_async(addressSpace,
    textNode,
    boost::asio::make_strand(addressSpace.executor()),
    [&promise](data_access_projection::OptionalLocalizedTextResult result)
    { promise.set_value(std::move(result)); });

  auto projected = future.get();
  ASSERT_TRUE(projected.is_good());
  ASSERT_TRUE(projected.value().has_value());
  EXPECT_EQ(projected.value()->text(), "High");

  owner->write_value_sync(Variant{int64_t{99}});
  std::promise<data_access_projection::OptionalLocalizedTextResult> unmatchedPromise;
  auto unmatchedFuture = unmatchedPromise.get_future();
  data_access_projection::value_as_text_async(addressSpace,
    textNode,
    boost::asio::make_strand(addressSpace.executor()),
    [&unmatchedPromise](data_access_projection::OptionalLocalizedTextResult result)
    { unmatchedPromise.set_value(std::move(result)); });
  auto unmatched = unmatchedFuture.get();
  ASSERT_TRUE(unmatched.is_good());
  EXPECT_FALSE(unmatched.value().has_value())
    << "a current numeric value absent from EnumValues has no text that the server can invent";
  ua::test_utils::drain_with_timeout(threadPool);
}

DataValueResult read_data_value(const AddressSpace& addressSpace, const NodeId& nodeId)
{
  std::promise<DataValueResult> promise;
  auto future = promise.get_future();
  instance_utils::read_variable_data_value_async(
    addressSpace, nodeId, [&promise](DataValueResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

std::string text_of(const DataValueResult& result)
{
  const auto* text = result.is_good() ? result.value().value().try_as<LocalizedText>() : nullptr;
  return text != nullptr ? static_cast<std::string>(text->text()) : std::string{"<no text>"};
}

// A wired ValueAsText Property answers every reader - not just the Read service - from its Variable's current
// Value, with the Value's own timestamps, so a MonitoredItem sampling the Property sees it change when the
// Value does (Part 8 section 5.3.3.5). The control before wiring shows the stored text going stale. The Value
// is a Byte: the DataType may be any integer type, and the EnumValues entries are keyed by Int64.
TEST(DataAccessProjectionTests, AWiredValueAsTextPropertyAnswersFromTheCurrentValue)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:wired", threadPool.get_executor());
  const NodeId ownerId{1, 9520u};
  const NodeId enumValuesId{1, 9521u};
  const NodeId valueAsTextId{1, 9522u};

  auto ownerNode = addressSpace.create_node_sync(ownerId, NodeClass::Variable);
  auto owner = ownerNode.as<VariableAccessor>();
  ASSERT_TRUE(owner.has_value());
  owner->set_browse_name(QualifiedName{1, "State"});
  owner->set_data_type(NodeId{DataTypeId::Byte});
  const DateTime firstChange{DateTime::now().value() - std::chrono::hours{1}};
  DataValue first{Variant{uint8_t{2}}};
  first.source_timestamp() = firstChange;
  owner->write_value_sync(std::move(first));

  auto enumNode = addressSpace.create_node_sync(enumValuesId, NodeClass::Variable);
  auto enumValues = enumNode.as<VariableAccessor>();
  ASSERT_TRUE(enumValues.has_value());
  enumValues->set_browse_name(QualifiedName{0, "EnumValues"});
  enumValues->set_data_type(NodeId{DataTypeId::EnumValueType});
  Array<RefStructure<Structure>> entries;
  for (const auto& [value, label] : std::vector<std::pair<int64_t, std::string>>{{1, "Low"}, {2, "High"}})
  {
    auto entry = std::make_unique<EnumValueType>();
    entry->value() = value;
    entry->display_name() = LocalizedText{"", label};
    entries.push_back(RefStructure<Structure>{std::move(entry)});
  }
  enumValues->write_value_sync(Variant{std::move(entries)});
  ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, enumValuesId);

  auto textNode = addressSpace.create_node_sync(valueAsTextId, NodeClass::Variable);
  auto valueAsText = textNode.as<VariableAccessor>();
  ASSERT_TRUE(valueAsText.has_value());
  valueAsText->set_browse_name(QualifiedName{0, "ValueAsText"});
  valueAsText->set_data_type(NodeId{DataTypeId::LocalizedText});
  valueAsText->write_value_sync(Variant{LocalizedText{"", "Low"}});
  ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, valueAsTextId);

  ASSERT_EQ(text_of(read_data_value(addressSpace, valueAsTextId)), "Low")
    << "control: unwired, the Property answers the text last written to it, whatever the Value";

  std::promise<VoidResult> wired;
  instance_utils::wire_value_as_text_async(
    addressSpace, ownerId, [&wired](VoidResult result) { wired.set_value(std::move(result)); });
  ASSERT_TRUE(wired.get_future().get().is_good());
  EXPECT_EQ(valueAsText->get_minimum_sampling_interval(), std::optional<Duration>{-1.0})
    << "a value that changes without being written cannot promise write-driven (0) sampling";

  const auto high = read_data_value(addressSpace, valueAsTextId);
  EXPECT_EQ(text_of(high), "High");
  ASSERT_TRUE(high.is_good());
  EXPECT_EQ(high.value().source_timestamp(), std::optional<DateTime>{firstChange})
    << "the text carries the timestamp of the Value it describes";

  owner->write_value_sync(Variant{uint8_t{1}});
  EXPECT_EQ(text_of(read_data_value(addressSpace, valueAsTextId)), "Low");

  owner->write_value_sync(Variant{uint8_t{99}});
  const auto unmatched = read_data_value(addressSpace, valueAsTextId);
  ASSERT_TRUE(unmatched.is_good())
    << "a Value with no EnumValues entry is not a failure to read the Property";
  EXPECT_EQ(text_of(unmatched), "") << "and has no text for the server to invent: an empty LocalizedText";
  ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-DA-013-MULTISTATEVALUE-PROPERTIES, scope=function)
TEST(DataAccessProjectionTests, ValueAsTextWithoutAnOwningPropertyReferenceDoesNotInventAProjection)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:no-owner", threadPool.get_executor());
  auto textNode = addressSpace.create_node_sync(NodeId{1, 9510u}, NodeClass::Variable);
  textNode.set_browse_name(QualifiedName{0, "ValueAsText"});

  std::promise<data_access_projection::OptionalLocalizedTextResult> promise;
  auto future = promise.get_future();
  data_access_projection::value_as_text_async(addressSpace,
    textNode,
    boost::asio::make_strand(addressSpace.executor()),
    [&promise](data_access_projection::OptionalLocalizedTextResult result)
    { promise.set_value(std::move(result)); });

  auto projected = future.get();
  ASSERT_TRUE(projected.is_good());
  EXPECT_FALSE(projected.value().has_value());
  ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-DATA-ACCESS-PROJECTION-01-RICH-REFERENCE-FAILURE, scope=function)
TEST(DataAccessProjectionTests, PropertyEnumerationFailurePreservesExactRichResult)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:reference-failure", threadPool.get_executor());
  auto holder =
    ua::test::behaviour_pins::FakeAsyncNamespace::create("urn:test:data-access-projection:holder");
  const auto holderIndex = addressSpace.add_namespace_sync(holder);
  const NodeId propertyId{holderIndex, 9520u};
  holder->hold(
    propertyId, std::make_shared<ua::test::behaviour_pins::FakeNode>(propertyId, NodeClass::Variable));
  const auto propertyAccessor = addressSpace.find_node_sync(propertyId);
  const std::shared_ptr<const ErrorDetail> sentinelDetail =
    make_error_detail("DataAccessProjectionReferenceSentinel",
      "ValueAsText property enumeration failed",
      "DataAccessProjectionTests");
  holder->set_next_get_references(
    propertyId, NodeAccessor::ReferencesResult{StatusCode{Status::BadInternalError}, sentinelDetail});

  std::promise<data_access_projection::OptionalLocalizedTextResult> promise;
  auto future = promise.get_future();
  data_access_projection::value_as_text_async(addressSpace,
    propertyAccessor,
    boost::asio::make_strand(addressSpace.executor()),
    [&promise](data_access_projection::OptionalLocalizedTextResult result)
    { promise.set_value(std::move(result)); });

  auto projected = future.get();
  ASSERT_TRUE(projected.is_bad());
  EXPECT_EQ(projected.status_code(), StatusCode{Status::BadInternalError});
  EXPECT_EQ(projected.shared_detail(), sentinelDetail);
  ua::test_utils::drain_with_timeout(threadPool);
}

// A snapshot whose owning Variable is created in @p addressSpace.
data_access_projection::DictionarySnapshot make_dictionary_snapshot(AddressSpace& addressSpace)
{
  data_access_projection::DictionarySnapshot snapshot{
    addressSpace.create_node_sync(NodeId{1, 9530u}, NodeClass::Variable)};
  snapshot.currentValue = 2;
  snapshot.enumValues = {
    {1, LocalizedText{"", "Low"}}, {2, LocalizedText{"", "High"}}, {3, LocalizedText{"", "Running"}}};
  snapshot.dictionaryEntries = Array<NodeId>{Dimensions{3, 2},
    {NodeId{1, 9540u},
      NodeId{1, 9541u},
      NodeId{1, 9542u},
      NodeId{1, 9543u},
      NodeId{1, 9544u},
      NodeId{1, 9545u}}};
  return snapshot;
}

// @relation(AC-SVR-DA-037-VALUEASDICTIONARYENTRIES-ORDER, scope=function)
TEST(DataAccessProjectionTests, CurrentDictionaryEntriesSelectsTheCurrentValuesRowInDictionaryOrder)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:dictionary", threadPool.get_executor());
  auto snapshot = make_dictionary_snapshot(addressSpace);

  auto high = data_access_projection::current_dictionary_entries(snapshot);
  ASSERT_TRUE(high.is_good());
  ASSERT_EQ(high.value().size(), 2u);
  EXPECT_EQ(high.value()[0], NodeId(1, 9542u));
  EXPECT_EQ(high.value()[1], NodeId(1, 9543u));

  snapshot.currentValue = 3;
  auto running = data_access_projection::current_dictionary_entries(snapshot);
  ASSERT_TRUE(running.is_good());
  ASSERT_EQ(running.value().size(), 2u);
  EXPECT_EQ(running.value()[0], NodeId(1, 9544u));
  EXPECT_EQ(running.value()[1], NodeId(1, 9545u));
  ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-DA-038-VALUEASDICTIONARYENTRIES-WRITEABLE, scope=function)
TEST(DataAccessProjectionTests, DictionaryEntryWriteTargetsTheOwningVariablesEnumeratedValue)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:dictionary", threadPool.get_executor());
  auto snapshot = make_dictionary_snapshot(addressSpace);
  Array<NodeId> selected{NodeId{1, 9544u}};

  auto target =
    data_access_projection::dictionary_write_target(snapshot, DataValue{Variant{std::move(selected)}});

  ASSERT_TRUE(target.is_good());
  EXPECT_EQ(target.value().owner.get_node_id(), NodeId(1, 9530u));
  auto value = target.value().value.value().to<int64_t>();
  ASSERT_TRUE(value.is_good());
  EXPECT_EQ(value.value(), 3);
  ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-DA-038-VALUEASDICTIONARYENTRIES-WRITEABLE, scope=function)
TEST(DataAccessProjectionTests, UndefinedDictionaryEntryIsRejectedWithRichOutOfRangeResult)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:dictionary", threadPool.get_executor());
  auto snapshot = make_dictionary_snapshot(addressSpace);
  Array<NodeId> selected{NodeId{1, 9599u}};

  auto target =
    data_access_projection::dictionary_write_target(snapshot, DataValue{Variant{std::move(selected)}});

  ASSERT_TRUE(target.is_bad());
  EXPECT_EQ(target.status_code(), StatusCode{Status::BadOutOfRange});
  ASSERT_TRUE(target.shared_detail());
  EXPECT_EQ(target.shared_detail()->code, "DictionaryEntryNotDefined");
  ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-DATA-ACCESS-PROJECTION-02-RICH-DICTIONARY-REFERENCE-FAILURE, scope=function)
TEST(DataAccessProjectionTests, DictionaryPropertyEnumerationFailurePreservesExactRichResult)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace = AddressSpace::create(
    "urn:test:data-access-projection:dictionary-reference-failure", threadPool.get_executor());
  auto holder =
    ua::test::behaviour_pins::FakeAsyncNamespace::create("urn:test:data-access-projection:holder");
  const auto holderIndex = addressSpace.add_namespace_sync(holder);
  const NodeId propertyId{holderIndex, 9550u};
  holder->hold(
    propertyId, std::make_shared<ua::test::behaviour_pins::FakeNode>(propertyId, NodeClass::Variable));
  const auto propertyAccessor = addressSpace.find_node_sync(propertyId);
  const std::shared_ptr<const ErrorDetail> sentinelDetail =
    make_error_detail("DictionaryProjectionReferenceSentinel",
      "ValueAsDictionaryEntries property enumeration failed",
      "DataAccessProjectionTests");
  holder->set_next_get_references(
    propertyId, NodeAccessor::ReferencesResult{StatusCode{Status::BadInternalError}, sentinelDetail});

  std::promise<data_access_projection::OptionalDictionarySnapshotResult> promise;
  auto future = promise.get_future();
  data_access_projection::dictionary_snapshot_async(addressSpace,
    propertyAccessor,
    boost::asio::make_strand(addressSpace.executor()),
    [&promise](data_access_projection::OptionalDictionarySnapshotResult result)
    { promise.set_value(std::move(result)); });

  auto projected = future.get();
  ASSERT_TRUE(projected.is_bad());
  EXPECT_EQ(projected.status_code(), StatusCode{Status::BadInternalError});
  EXPECT_EQ(projected.shared_detail(), sentinelDetail);
  ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-DATA-ACCESS-PROJECTION-02-RICH-DICTIONARY-REFERENCE-FAILURE, scope=function)
TEST(DataAccessProjectionTests, DictionaryPropertyWithoutAnOwnerReturnsGoodEmptyProjection)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:dictionary-no-owner", threadPool.get_executor());
  auto property = addressSpace.create_node_sync(NodeId{1, 9560u}, NodeClass::Variable);
  property.set_browse_name(QualifiedName{0, "ValueAsDictionaryEntries"});

  std::promise<data_access_projection::OptionalDictionarySnapshotResult> promise;
  auto future = promise.get_future();
  data_access_projection::dictionary_snapshot_async(addressSpace,
    property,
    boost::asio::make_strand(addressSpace.executor()),
    [&promise](data_access_projection::OptionalDictionarySnapshotResult result)
    { promise.set_value(std::move(result)); });

  auto projected = future.get();
  ASSERT_TRUE(projected.is_good());
  EXPECT_FALSE(projected.value().has_value());
  ua::test_utils::drain_with_timeout(threadPool);
}

// The snapshot a ValueAsDictionaryEntries Read or Write works from keys the table by the owning Variable's
// current Value, which may be of any integer DataType (Part 8 section 5.3.3.5), not only Int64.
TEST(DataAccessProjectionTests, DictionarySnapshotReadsTheCurrentValueOfAnyIntegerDataType)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace =
    AddressSpace::create("urn:test:data-access-projection:dictionary-uint16", threadPool.get_executor());
  const NodeId ownerId{1, 9570u};
  const NodeId enumValuesId{1, 9571u};
  const NodeId dictionaryId{1, 9572u};
  const NodeId propertyId{1, 9573u};

  auto ownerNode = addressSpace.create_node_sync(ownerId, NodeClass::Variable);
  auto owner = ownerNode.as<VariableAccessor>();
  ASSERT_TRUE(owner.has_value());
  owner->set_browse_name(QualifiedName{1, "State"});
  owner->set_data_type(NodeId{DataTypeId::UInt16});
  owner->write_value_sync(Variant{uint16_t{2}});

  const auto addProperty = [&](const NodeId& id, std::string_view name, Variant value)
  {
    auto node = addressSpace.create_node_sync(id, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{0, std::string{name}});
    variable->write_value_sync(std::move(value));
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, id);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerId, false);
  };

  Array<RefStructure<Structure>> entries;
  for (const auto& [value, label] : std::vector<std::pair<int64_t, std::string>>{{1, "Low"}, {2, "High"}})
  {
    auto entry = std::make_unique<EnumValueType>();
    entry->value() = value;
    entry->display_name() = LocalizedText{"", label};
    entries.push_back(RefStructure<Structure>{std::move(entry)});
  }
  addProperty(enumValuesId, "EnumValues", Variant{std::move(entries)});
  addProperty(dictionaryId,
    "EnumDictionaryEntries",
    Variant{Array<NodeId>{Dimensions{2, 1}, {NodeId{1, 9580u}, NodeId{1, 9581u}}}});
  addProperty(propertyId, "ValueAsDictionaryEntries", Variant{});

  std::promise<data_access_projection::OptionalDictionarySnapshotResult> promise;
  auto future = promise.get_future();
  data_access_projection::dictionary_snapshot_async(addressSpace,
    addressSpace.find_node_sync(propertyId),
    boost::asio::make_strand(addressSpace.executor()),
    [&promise](data_access_projection::OptionalDictionarySnapshotResult result)
    { promise.set_value(std::move(result)); });

  auto snapshot = future.get();
  ASSERT_TRUE(snapshot.is_good()) << "a UInt16 Value is an integer the table can be keyed by: 0x" << std::hex
                                  << snapshot.status_code().as_uint32();
  ASSERT_TRUE(snapshot.value().has_value());
  EXPECT_EQ(snapshot.value()->currentValue, 2);
  auto row = data_access_projection::current_dictionary_entries(*snapshot.value());
  ASSERT_TRUE(row.is_good());
  ASSERT_EQ(row.value().size(), 1u);
  EXPECT_EQ(row.value()[0], (NodeId{1, 9581u}));
  ua::test_utils::drain_with_timeout(threadPool);
}

}  // namespace
}  // namespace ua::server
