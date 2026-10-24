// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_type_loader.h"
#include "ua_type_model_access.h"
#include "ua_dynamic_type_registry.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_attribute_id.h"
#include "ua_browse_direction.h"
#include "ua_browse_result_mask.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_expanded_node_id.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_browse_description.h"
#include "ua_browse_result.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_structure_type.h"
#include "ua_variable_id.h"
#include "ua_variant.h"

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace ua;
using namespace ua::dynamic_types;

namespace
{

// ---------------------------------------------------------------------------
// Mock node model
// ---------------------------------------------------------------------------

struct MockNode
{
  NodeId nodeId;
  QualifiedName browseName;
  bool isAbstract{false};
  std::optional<StructureDefinition> structureDefinition;
  std::optional<EnumDefinition> enumDefinition;
};

struct MockReference
{
  NodeId sourceId;
  NodeId referenceTypeId;
  bool isForward{true};
  ExpandedNodeId targetId;
  QualifiedName targetBrowseName;
};

// ---------------------------------------------------------------------------
// MockTypeModelAccess
// ---------------------------------------------------------------------------

class MockTypeModelAccess : public TypeModelAccess
{
public:
  std::unordered_map<NodeId, MockNode> nodes;
  std::vector<MockReference> references;
  std::vector<String> namespaceArray;

  void add_node(MockNode node)
  {
    auto id = node.nodeId;
    nodes[id] = std::move(node);
  }

  void add_reference_async(
    NodeId source, NodeId refType, bool isForward, NodeId target, QualifiedName targetBrowseName)
  {
    MockReference ref;
    ref.sourceId = source;
    ref.referenceTypeId = refType;
    ref.isForward = isForward;
    ref.targetId = ExpandedNodeId{target};
    ref.targetBrowseName = std::move(targetBrowseName);
    references.push_back(std::move(ref));
  }

  // Add a HasSubtype from parent to child (forward), plus the inverse from child to parent.
  void add_subtype(NodeId parent, NodeId child, string_view childBrowseName)
  {
    QualifiedName childQn;
    childQn.name() = String{childBrowseName};
    childQn.namespace_index() = child.namespace_index();

    QualifiedName parentQn;
    if (auto it = nodes.find(parent); it != nodes.end())
    {
      parentQn = it->second.browseName;
    }

    // Forward: parent -> child (HasSubtype)
    add_reference_async(parent, NodeId{ReferenceTypeId::HasSubtype}, true, child, childQn);
    // Inverse: child -> parent (HasSubtype, inverse)
    add_reference_async(child, NodeId{ReferenceTypeId::HasSubtype}, false, parent, parentQn);
  }

  void add_encoding(NodeId dataTypeId, NodeId encodingId, string_view encodingName)
  {
    QualifiedName qn;
    qn.name() = String{encodingName};
    add_reference_async(dataTypeId, NodeId{ReferenceTypeId::HasEncoding}, true, encodingId, qn);
  }

  void read_async(std::vector<ua::ReadValueId> nodesToRead, ReadCallback complete) override
  {
    std::vector<DataValue> results;
    results.reserve(nodesToRead.size());

    for (const auto& rv : nodesToRead)
    {
      auto attrId = static_cast<AttributeId>(rv.attribute_id());
      auto nodeId = rv.node_id();

      // Special handling for NamespaceArray
      if (nodeId == NodeId{VariableId::Server_NamespaceArray} && attrId == AttributeId::Value)
      {
        Array<String> nsArr;
        nsArr.resize(namespaceArray.size());
        for (size_t i = 0; i < namespaceArray.size(); ++i)
        {
          nsArr[i] = namespaceArray[i];
        }
        DataValue dv{Variant{std::move(nsArr)}};
        results.push_back(std::move(dv));
        continue;
      }

      auto it = nodes.find(nodeId);
      if (it == nodes.end())
      {
        DataValue dv{StatusCode{Status::BadNodeIdUnknown}};
        results.push_back(std::move(dv));
        continue;
      }

      const auto& node = it->second;

      switch (attrId)
      {
      case AttributeId::BrowseName:
      {
        DataValue dv{Variant{node.browseName}};
        results.push_back(std::move(dv));
        break;
      }
      case AttributeId::IsAbstract:
      {
        DataValue dv{Variant{node.isAbstract}};
        results.push_back(std::move(dv));
        break;
      }
      case AttributeId::DataTypeDefinition:
      {
        if (node.structureDefinition)
        {
          DataValue dv{Variant{*node.structureDefinition}};
          results.push_back(std::move(dv));
        }
        else if (node.enumDefinition)
        {
          DataValue dv{Variant{*node.enumDefinition}};
          results.push_back(std::move(dv));
        }
        else
        {
          DataValue dv{StatusCode{Status::BadAttributeIdInvalid}};
          results.push_back(std::move(dv));
        }
        break;
      }
      default:
      {
        DataValue dv{StatusCode{Status::BadAttributeIdInvalid}};
        results.push_back(std::move(dv));
        break;
      }
      }
    }

    complete(ua::Result<std::vector<DataValue>>{std::move(results)});
  }

  void browse_async(std::vector<ua::BrowseDescription> nodesToBrowse, BrowseCallback complete) override
  {
    std::vector<BrowseResult> results;
    results.reserve(nodesToBrowse.size());

    for (const auto& bd : nodesToBrowse)
    {
      BrowseResult br;
      Array<ReferenceDescription> refs;

      std::vector<ReferenceDescription> matching;
      for (const auto& mockRef : references)
      {
        // Match source
        if (mockRef.sourceId != bd.node_id())
        {
          continue;
        }

        // Match direction
        if (bd.browse_direction() == BrowseDirection::Forward && !mockRef.isForward)
        {
          continue;
        }
        if (bd.browse_direction() == BrowseDirection::Inverse && mockRef.isForward)
        {
          continue;
        }

        // Match reference type
        if (!bd.reference_type_id().is_null() && mockRef.referenceTypeId != bd.reference_type_id())
        {
          continue;
        }

        ReferenceDescription rd;
        rd.reference_type_id() = mockRef.referenceTypeId;
        rd.is_forward() = mockRef.isForward;
        rd.node_id() = mockRef.targetId;
        rd.browse_name() = mockRef.targetBrowseName;
        matching.push_back(std::move(rd));
      }

      refs.resize(matching.size());
      for (size_t i = 0; i < matching.size(); ++i)
      {
        refs[i] = std::move(matching[i]);
      }
      br.references() = std::move(refs);
      results.push_back(std::move(br));
    }

    complete(ua::Result<std::vector<BrowseResult>>{std::move(results)});
  }
};

// ---------------------------------------------------------------------------
// A model that answers one chosen Browse or Read Uncertain, with or without its data
// ---------------------------------------------------------------------------

class UncertainAnswerModelAccess : public MockTypeModelAccess
{
public:
  static constexpr Status uncertainCode = Status::UncertainNotAllNodesAvailable;

  std::size_t uncertainBrowse = 0;  ///< 1-based number of the Browse answered Uncertain; 0 for none.
  std::size_t uncertainRead = 0;  ///< 1-based number of the Read answered Uncertain; 0 for none.
  bool withData = true;  ///< Whether the Uncertain answer holds the data.

  void read_async(std::vector<ua::ReadValueId> nodesToRead, ReadCallback complete) override
  {
    const bool uncertain = ++mReads == uncertainRead;
    MockTypeModelAccess::read_async(std::move(nodesToRead),
      [uncertain, withData = withData, complete = std::move(complete)](
        ua::Result<std::vector<DataValue>> answer) mutable
      { complete(uncertain ? make_uncertain(std::move(answer), withData) : std::move(answer)); });
  }

  void browse_async(std::vector<ua::BrowseDescription> nodesToBrowse, BrowseCallback complete) override
  {
    const bool uncertain = ++mBrowses == uncertainBrowse;
    MockTypeModelAccess::browse_async(std::move(nodesToBrowse),
      [uncertain, withData = withData, complete = std::move(complete)](
        ua::Result<std::vector<BrowseResult>> answer) mutable
      { complete(uncertain ? make_uncertain(std::move(answer), withData) : std::move(answer)); });
  }

private:
  template<typename T>
  static ua::Result<T> make_uncertain(ua::Result<T> answer, bool withData)
  {
    if (withData)
    {
      return ua::Result<T>{std::move(answer).value(), StatusCode{uncertainCode}};
    }
    return ua::Result<T>{StatusCode{uncertainCode}};
  }

  std::size_t mReads = 0;
  std::size_t mBrowses = 0;
};

// ---------------------------------------------------------------------------
// Helper: build StructureDefinition with fields
// ---------------------------------------------------------------------------

StructureField make_field(string_view name, DataTypeId dataType)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = NodeId{dataType};
  field.value_rank() = -1;
  field.is_optional() = false;
  return field;
}

StructureField make_custom_field(string_view name, NodeId dataType)
{
  StructureField field;
  field.name() = String{name};
  field.data_type() = std::move(dataType);
  field.value_rank() = -1;
  field.is_optional() = false;
  return field;
}

StructureDefinition make_struct_def(StructureType structType, std::vector<StructureField> fields)
{
  StructureDefinition def;
  def.structure_type() = structType;
  Array<StructureField> arr;
  arr.resize(fields.size());
  for (size_t i = 0; i < fields.size(); ++i)
  {
    arr[i] = std::move(fields[i]);
  }
  def.fields() = std::move(arr);
  return def;
}

EnumDefinition make_enum_def(std::vector<std::pair<string_view, int64_t>> entries)
{
  EnumDefinition def;
  Array<EnumField> fields;
  fields.resize(entries.size());
  for (size_t i = 0; i < entries.size(); ++i)
  {
    fields[i].value() = entries[i].second;
    fields[i].display_name() = LocalizedText{"", String{entries[i].first}};
    fields[i].name() = String{entries[i].first};
  }
  def.fields() = std::move(fields);
  return def;
}

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class TypeLoaderTest : public ::testing::Test
{
protected:
  MockTypeModelAccess mAccess;
  DynamicTypeRegistry mRegistry;

  // Node IDs for NS0 base types
  static constexpr uint32_t sBaseDataTypeId = 24;
  static constexpr uint32_t sStructureId = 22;
  static constexpr uint32_t sEnumerationId = 29;
  static constexpr uint32_t sOptionSetId = 12755;
  static constexpr uint32_t sUInt32Id = 7;

  // Node IDs for test types (namespace 1)
  NodeId mPriorityEnumId{1, uint32_t{1001}};
  NodeId mAccessFlagsId{1, uint32_t{1010}};
  NodeId mGeoCoordId{1, uint32_t{2001}};
  NodeId mSensorLocId{1, uint32_t{2003}};
  NodeId mMeasurementId{1, uint32_t{3001}};
  NodeId mTaskInfoId{1, uint32_t{2011}};

  // Encoding IDs (namespace 1)
  NodeId mGeoCoordEncodingId{1, uint32_t{5001}};
  NodeId mSensorLocEncodingId{1, uint32_t{5003}};
  NodeId mMeasurementEncodingId{1, uint32_t{5010}};
  NodeId mTaskInfoEncodingId{1, uint32_t{5012}};

  void SetUp() override
  {
    // Set up namespace array
    mAccess.namespaceArray.push_back(String{"http://opcfoundation.org/UA/"});
    mAccess.namespaceArray.push_back(String{"urn:test"});

    populate_base_types();
    populate_priority_enum();
    populate_access_flags_option_set();
    populate_geo_coordinate();
    populate_sensor_location();
    populate_measurement_union();
    populate_task_info();
  }

  void populate_base_types()
  {
    // BaseDataType (i=24) - root of all DataTypes
    {
      MockNode node;
      node.nodeId = NodeId{0, sBaseDataTypeId};
      node.browseName.name() = String{"BaseDataType"};
      node.browseName.namespace_index() = 0;
      node.isAbstract = true;
      mAccess.add_node(std::move(node));
    }
    // Structure (i=22) - abstract base, subtype of BaseDataType
    {
      MockNode node;
      node.nodeId = NodeId{0, sStructureId};
      node.browseName.name() = String{"Structure"};
      node.browseName.namespace_index() = 0;
      node.isAbstract = true;
      mAccess.add_node(std::move(node));
      mAccess.add_subtype(NodeId{0, sBaseDataTypeId}, NodeId{0, sStructureId}, "Structure");
    }
    // Enumeration (i=29) - abstract base, subtype of BaseDataType
    {
      MockNode node;
      node.nodeId = NodeId{0, sEnumerationId};
      node.browseName.name() = String{"Enumeration"};
      node.browseName.namespace_index() = 0;
      node.isAbstract = true;
      mAccess.add_node(std::move(node));
      mAccess.add_subtype(NodeId{0, sBaseDataTypeId}, NodeId{0, sEnumerationId}, "Enumeration");
    }
    // OptionSet (i=12755) - abstract base, subtype of Structure in standard model
    {
      MockNode node;
      node.nodeId = NodeId{0, sOptionSetId};
      node.browseName.name() = String{"OptionSet"};
      node.browseName.namespace_index() = 0;
      node.isAbstract = true;
      mAccess.add_node(std::move(node));
      mAccess.add_subtype(NodeId{0, sStructureId}, NodeId{0, sOptionSetId}, "OptionSet");
    }
    // UInt32 (i=7) - built-in, subtype of BaseDataType
    {
      MockNode node;
      node.nodeId = NodeId{0, sUInt32Id};
      node.browseName.name() = String{"UInt32"};
      node.browseName.namespace_index() = 0;
      mAccess.add_node(std::move(node));
      mAccess.add_subtype(NodeId{0, sBaseDataTypeId}, NodeId{0, sUInt32Id}, "UInt32");
    }
  }

  void populate_priority_enum()
  {
    MockNode node;
    node.nodeId = mPriorityEnumId;
    node.browseName.name() = String{"Priority"};
    node.browseName.namespace_index() = 1;
    node.enumDefinition = make_enum_def({{"Low", 0}, {"High", 1}});
    mAccess.add_node(std::move(node));

    // HasSubtype: Enumeration -> Priority
    mAccess.add_subtype(NodeId{0, sEnumerationId}, mPriorityEnumId, "Priority");
  }

  void populate_access_flags_option_set()
  {
    MockNode node;
    node.nodeId = mAccessFlagsId;
    node.browseName.name() = String{"AccessFlags"};
    node.browseName.namespace_index() = 1;
    node.enumDefinition = make_enum_def({{"CanRead", 0}, {"CanWrite", 1}});
    mAccess.add_node(std::move(node));

    // AccessFlags is a subtype of OptionSet (i=12755), which itself is under Structure.
    // This makes it discoverable via the Structure hierarchy walk.
    // The is_option_set() function finds OptionSet(12755) in the parent chain.
    mAccess.add_subtype(NodeId{0, sOptionSetId}, mAccessFlagsId, "AccessFlags");
  }

  void populate_geo_coordinate()
  {
    MockNode node;
    node.nodeId = mGeoCoordId;
    node.browseName.name() = String{"GeoCoordinate"};
    node.browseName.namespace_index() = 1;
    std::vector<StructureField> fields;
    fields.push_back(make_field("Lat", DataTypeId::Double));
    fields.push_back(make_field("Lon", DataTypeId::Double));
    node.structureDefinition = make_struct_def(StructureType::Structure, std::move(fields));
    mAccess.add_node(std::move(node));

    mAccess.add_subtype(NodeId{0, sStructureId}, mGeoCoordId, "GeoCoordinate");
    mAccess.add_encoding(mGeoCoordId, mGeoCoordEncodingId, "Default Binary");
  }

  void populate_sensor_location()
  {
    MockNode node;
    node.nodeId = mSensorLocId;
    node.browseName.name() = String{"SensorLocation"};
    node.browseName.namespace_index() = 1;
    std::vector<StructureField> fields;
    fields.push_back(make_field("Name", DataTypeId::String));
    fields.push_back(make_custom_field("Coord", mGeoCoordId));
    node.structureDefinition = make_struct_def(StructureType::Structure, std::move(fields));
    mAccess.add_node(std::move(node));

    mAccess.add_subtype(NodeId{0, sStructureId}, mSensorLocId, "SensorLocation");
    mAccess.add_encoding(mSensorLocId, mSensorLocEncodingId, "Default Binary");
  }

  void populate_measurement_union()
  {
    MockNode node;
    node.nodeId = mMeasurementId;
    node.browseName.name() = String{"Measurement"};
    node.browseName.namespace_index() = 1;
    std::vector<StructureField> fields;
    fields.push_back(make_field("IntVal", DataTypeId::Int32));
    fields.push_back(make_field("FloatVal", DataTypeId::Double));
    node.structureDefinition = make_struct_def(StructureType::Union, std::move(fields));
    mAccess.add_node(std::move(node));

    mAccess.add_subtype(NodeId{0, sStructureId}, mMeasurementId, "Measurement");
    mAccess.add_encoding(mMeasurementId, mMeasurementEncodingId, "Default Binary");
  }

  void populate_task_info()
  {
    MockNode node;
    node.nodeId = mTaskInfoId;
    node.browseName.name() = String{"TaskInfo"};
    node.browseName.namespace_index() = 1;
    std::vector<StructureField> fields;
    fields.push_back(make_field("Name", DataTypeId::String));
    fields.push_back(make_custom_field("Priority", mPriorityEnumId));
    fields.push_back(make_custom_field("Access", mAccessFlagsId));
    node.structureDefinition = make_struct_def(StructureType::Structure, std::move(fields));
    mAccess.add_node(std::move(node));

    mAccess.add_subtype(NodeId{0, sStructureId}, mTaskInfoId, "TaskInfo");
    mAccess.add_encoding(mTaskInfoId, mTaskInfoEncodingId, "Default Binary");
  }

  ExpandedNodeId expanded(NodeId nodeId)
  {
    if (nodeId.namespace_index() == 0)
    {
      return ExpandedNodeId{nodeId};
    }
    NodeId localPart = nodeId;
    localPart.namespace_index() = 0;
    return ExpandedNodeId{std::move(localPart), "urn:test"};
  }
};

// ===========================================================================
// Tests
// ===========================================================================

TEST_F(TypeLoaderTest, LoadTypes_DiscoverAndRegisterAll)
{
  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good()) << "load_types failed: " << result.status_code().as_uint32();

  auto stats = result.value();

  // We expect at least: Priority enum, AccessFlags optionset
  EXPECT_GE(stats.enumCount, 2u);
  // GeoCoordinate, SensorLocation, Measurement, TaskInfo
  EXPECT_GE(stats.structureCount, 4u);

  // Verify structures registered by expanded type ID
  EXPECT_NE(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
  EXPECT_NE(mRegistry.find_structure(expanded(mSensorLocId)), nullptr);
  EXPECT_NE(mRegistry.find_structure(expanded(mMeasurementId)), nullptr);
  EXPECT_NE(mRegistry.find_structure(expanded(mTaskInfoId)), nullptr);

  // Verify SensorLocation's Coord field has a nested descriptor pointing to GeoCoordinate
  const auto sensorLocDesc = mRegistry.find_structure(expanded(mSensorLocId));
  ASSERT_NE(sensorLocDesc, nullptr);
  ASSERT_EQ(sensorLocDesc->field_count(), 2u);
  // Field 1 is Coord (custom type)
  auto nested = sensorLocDesc->nested_descriptor(1);
  ASSERT_NE(nested, nullptr);
  EXPECT_EQ(static_cast<string_view>(nested->type_name()), "GeoCoordinate");
}

TEST_F(TypeLoaderTest, LoadTypes_WithFilter)
{
  // Only select namespace 1 types with numeric id < 2010
  auto filter = [](const DiscoveredType& discovered) -> bool
  {
    const auto& typeId = discovered.node_id();
    if (typeId.namespace_index() != 1)
    {
      return false;
    }
    if (!typeId.is_numeric())
    {
      return false;
    }
    return typeId.identifier().get_numeric() < 2010;
  };

  auto result = try_load_types_sync(mAccess, mRegistry, filter);
  ASSERT_TRUE(result.is_good());

  // GeoCoordinate (2001) and SensorLocation (2003) should be registered
  EXPECT_NE(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
  EXPECT_NE(mRegistry.find_structure(expanded(mSensorLocId)), nullptr);

  // Priority enum (1001) should also be registered
  EXPECT_NE(mRegistry.find_enum(expanded(mPriorityEnumId)), nullptr);

  // Measurement (3001) and TaskInfo (2011) should NOT be registered (filtered out)
  EXPECT_EQ(mRegistry.find_structure(expanded(mMeasurementId)), nullptr);
  EXPECT_EQ(mRegistry.find_structure(expanded(mTaskInfoId)), nullptr);
}

TEST_F(TypeLoaderTest, LoadTypes_FilteredTypeDependencyStillRegistered)
{
  // Filter only selects SensorLocation (2003)
  auto filter = [this](const DiscoveredType& discovered) -> bool
  {
    return discovered.node_id() == mSensorLocId;
  };

  auto result = try_load_types_sync(mAccess, mRegistry, filter);
  ASSERT_TRUE(result.is_good());

  // SensorLocation should be registered
  EXPECT_NE(mRegistry.find_structure(expanded(mSensorLocId)), nullptr);

  // GeoCoordinate should be registered as a dependency of SensorLocation
  EXPECT_NE(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
}

// ---------------------------------------------------------------------------
// Widened TypeFilter: the DiscoveredType view exposes browse name, abstractness,
// supertype, and kind - not just the NodeId.
// ---------------------------------------------------------------------------

TEST_F(TypeLoaderTest, LoadTypes_FilterReceivesPopulatedDiscoveredType)
{
  // Add an abstract namespace-1 structure so the filter is offered a type whose is_abstract()
  // is true. (NS0 abstract bases such as Structure/Enumeration are skipped before the filter.)
  const NodeId abstractId{1, uint32_t{2099}};
  {
    MockNode node;
    node.nodeId = abstractId;
    node.browseName.name() = String{"AbstractBase"};
    node.browseName.namespace_index() = 1;
    node.isAbstract = true;
    node.structureDefinition = make_struct_def(StructureType::Structure, std::vector<StructureField>{});
    mAccess.add_node(std::move(node));
    mAccess.add_subtype(NodeId{0, sStructureId}, abstractId, "AbstractBase");
  }

  struct Seen
  {
    String browseName;
    bool isAbstract;
    NodeId superType;
    DiscoveredTypeKind kind;
  };

  std::unordered_map<NodeId, Seen> seen;
  auto filter = [&seen](const DiscoveredType& discovered) -> bool
  {
    seen[discovered.node_id()] =
      Seen{discovered.browse_name(), discovered.is_abstract(), discovered.super_type(), discovered.kind()};
    return true;  // select all; we only assert on what the view reported
  };

  auto result = try_load_types_sync(mAccess, mRegistry, filter);
  ASSERT_TRUE(result.is_good());

  // GeoCoordinate: concrete structure, direct subtype of Structure (i=22).
  ASSERT_TRUE(seen.count(mGeoCoordId));
  EXPECT_EQ(static_cast<string_view>(seen[mGeoCoordId].browseName), "GeoCoordinate");
  EXPECT_FALSE(seen[mGeoCoordId].isAbstract);
  EXPECT_EQ(seen[mGeoCoordId].superType, NodeId(0, sStructureId));
  EXPECT_EQ(seen[mGeoCoordId].kind, DiscoveredTypeKind::Structure);

  // Priority: plain enumeration, direct subtype of Enumeration (i=29).
  ASSERT_TRUE(seen.count(mPriorityEnumId));
  EXPECT_EQ(seen[mPriorityEnumId].kind, DiscoveredTypeKind::Enumeration);
  EXPECT_EQ(seen[mPriorityEnumId].superType, NodeId(0, sEnumerationId));

  // AccessFlags: option set (carries an EnumDefinition -> Enumeration kind), subtype of OptionSet.
  ASSERT_TRUE(seen.count(mAccessFlagsId));
  EXPECT_EQ(seen[mAccessFlagsId].kind, DiscoveredTypeKind::Enumeration);
  EXPECT_EQ(seen[mAccessFlagsId].superType, NodeId(0, sOptionSetId));

  // AbstractBase: is_abstract() is surfaced as true.
  ASSERT_TRUE(seen.count(abstractId));
  EXPECT_TRUE(seen[abstractId].isAbstract);
  EXPECT_EQ(seen[abstractId].kind, DiscoveredTypeKind::Structure);
}

TEST_F(TypeLoaderTest, LoadTypes_FilterByBrowseName)
{
  auto filter = [](const DiscoveredType& discovered) -> bool
  {
    return static_cast<string_view>(discovered.browse_name()) == "GeoCoordinate";
  };

  auto result = try_load_types_sync(mAccess, mRegistry, filter);
  ASSERT_TRUE(result.is_good());

  EXPECT_NE(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
  // TaskInfo is neither selected nor a dependency of GeoCoordinate.
  EXPECT_EQ(mRegistry.find_structure(expanded(mTaskInfoId)), nullptr);
  EXPECT_EQ(mRegistry.find_enum(expanded(mPriorityEnumId)), nullptr);
}

TEST_F(TypeLoaderTest, LoadTypes_FilterByKindEnumeration)
{
  auto filter = [](const DiscoveredType& discovered) -> bool
  {
    return discovered.kind() == DiscoveredTypeKind::Enumeration;
  };

  auto result = try_load_types_sync(mAccess, mRegistry, filter);
  ASSERT_TRUE(result.is_good());

  // Both enumeration-kind types selected (Priority plain enum, AccessFlags option set).
  EXPECT_NE(mRegistry.find_enum(expanded(mPriorityEnumId)), nullptr);
  EXPECT_NE(mRegistry.find_enum(expanded(mAccessFlagsId)), nullptr);
  // No structure selected; enums have no field dependencies, so none is pulled in.
  EXPECT_EQ(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
  EXPECT_EQ(mRegistry.find_structure(expanded(mTaskInfoId)), nullptr);
}

TEST_F(TypeLoaderTest, LoadTypes_FilterBySuperType)
{
  // Select only the direct subtypes of Enumeration (i=29): Priority, but not AccessFlags
  // (whose supertype is OptionSet) nor any structure.
  const NodeId enumerationBase{0, uint32_t{29}};
  auto filter = [enumerationBase](const DiscoveredType& discovered) -> bool
  {
    return discovered.super_type() == enumerationBase;
  };

  auto result = try_load_types_sync(mAccess, mRegistry, filter);
  ASSERT_TRUE(result.is_good());

  EXPECT_NE(mRegistry.find_enum(expanded(mPriorityEnumId)), nullptr);
  EXPECT_EQ(mRegistry.find_enum(expanded(mAccessFlagsId)), nullptr);
  EXPECT_EQ(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
}

// ---------------------------------------------------------------------------
// Cascading dependency failure: the parent's ErrorDetail carries the child's
// root cause through its cause chain.
// ---------------------------------------------------------------------------

TEST_F(TypeLoaderTest, LoadTypes_CascadingFailureErrorDetailChain)
{
  // Child structure with NO Default Binary encoding -> fails to register at the root.
  const NodeId childId{1, uint32_t{2050}};
  {
    MockNode child;
    child.nodeId = childId;
    child.browseName.name() = String{"ChildNoEncoding"};
    child.browseName.namespace_index() = 1;
    std::vector<StructureField> childFields;
    childFields.push_back(make_field("X", DataTypeId::Double));
    child.structureDefinition = make_struct_def(StructureType::Structure, std::move(childFields));
    mAccess.add_node(std::move(child));
    mAccess.add_subtype(NodeId{0, sStructureId}, childId, "ChildNoEncoding");
    // Deliberately no add_encoding(childId, ...): the missing Default Binary is the root cause.
  }
  // Parent structure with a field of the child type -> its dependency cascade fails.
  const NodeId parentId{1, uint32_t{2051}};
  {
    MockNode parent;
    parent.nodeId = parentId;
    parent.browseName.name() = String{"ParentWithBadChild"};
    parent.browseName.namespace_index() = 1;
    std::vector<StructureField> parentFields;
    parentFields.push_back(make_custom_field("Child", childId));
    parent.structureDefinition = make_struct_def(StructureType::Structure, std::move(parentFields));
    mAccess.add_node(std::move(parent));
    mAccess.add_subtype(NodeId{0, sStructureId}, parentId, "ParentWithBadChild");
    mAccess.add_encoding(parentId, NodeId{1, uint32_t{5051}}, "Default Binary");
  }

  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());  // top-level ok; per-type failures are recorded, not fatal
  const auto& stats = result.value();
  ASSERT_TRUE(stats.has_failures());

  // Neither the parent nor the failed child ends up registered.
  EXPECT_EQ(mRegistry.find_structure(expanded(parentId)), nullptr);
  EXPECT_EQ(mRegistry.find_structure(expanded(childId)), nullptr);

  const TypeRegistrationFailure* parentFailure = nullptr;
  for (const auto& failure : stats.failures)
  {
    if (failure.typeId == parentId)
    {
      parentFailure = &failure;
      break;
    }
  }
  ASSERT_NE(parentFailure, nullptr) << "parent should have a recorded failure";
  ASSERT_NE(parentFailure->detail, nullptr);
  EXPECT_NE(parentFailure->detail->summary.find("dependency failed"), std::string::npos);

  // Walk the cause chain to the child's missing-encoding root.
  bool foundEncodingRoot = false;
  for (auto detail = parentFailure->detail; detail != nullptr; detail = detail->cause)
  {
    if (detail->summary.find("Default Binary") != std::string::npos)
    {
      foundEncodingRoot = true;
      break;
    }
  }
  EXPECT_TRUE(foundEncodingRoot) << "the cause chain should reach the child's missing-encoding root";
}

// Two parents share one failing child, so whichever parent the loader visits second finds the child already
// failed. Both parents' cause chains still reach the child's root cause, whatever the visiting order.
TEST_F(TypeLoaderTest, LoadTypes_EveryDependentOfAFailedTypeReachesItsRootCause)
{
  const NodeId childId{1, uint32_t{2060}};
  {
    MockNode child;
    child.nodeId = childId;
    child.browseName.name() = String{"SharedChildNoEncoding"};
    child.browseName.namespace_index() = 1;
    std::vector<StructureField> childFields;
    childFields.push_back(make_field("X", DataTypeId::Double));
    child.structureDefinition = make_struct_def(StructureType::Structure, std::move(childFields));
    mAccess.add_node(std::move(child));
    mAccess.add_subtype(NodeId{0, sStructureId}, childId, "SharedChildNoEncoding");
  }
  const std::vector<NodeId> parentIds{NodeId{1, uint32_t{2061}}, NodeId{1, uint32_t{2062}}};
  for (std::size_t i = 0; i < parentIds.size(); ++i)
  {
    const std::string name = "ParentOfSharedChild" + std::to_string(i);
    MockNode parent;
    parent.nodeId = parentIds[i];
    parent.browseName.name() = String{name};
    parent.browseName.namespace_index() = 1;
    std::vector<StructureField> parentFields;
    parentFields.push_back(make_custom_field("Child", childId));
    parent.structureDefinition = make_struct_def(StructureType::Structure, std::move(parentFields));
    mAccess.add_node(std::move(parent));
    mAccess.add_subtype(NodeId{0, sStructureId}, parentIds[i], name);
    mAccess.add_encoding(
      parentIds[i], NodeId{1, uint32_t{5061 + static_cast<uint32_t>(i)}}, "Default Binary");
  }

  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());
  const auto& stats = result.value();

  for (const auto& parentId : parentIds)
  {
    SCOPED_TRACE(parentId.as_definition());
    const TypeRegistrationFailure* parentFailure = nullptr;
    for (const auto& failure : stats.failures)
    {
      if (failure.typeId == parentId)
      {
        parentFailure = &failure;
        break;
      }
    }
    ASSERT_NE(parentFailure, nullptr) << "each parent should have a recorded failure";
    bool foundEncodingRoot = false;
    for (auto detail = parentFailure->detail; detail != nullptr; detail = detail->cause)
    {
      if (detail->summary.find("Default Binary") != std::string::npos)
      {
        foundEncodingRoot = true;
        break;
      }
    }
    EXPECT_TRUE(foundEncodingRoot) << "the cause chain should reach the shared child's missing-encoding root";
  }
}

// ---------------------------------------------------------------------------
// WorkBudget: the loader bounds one load to 1000 node units; excess types are
// recorded as per-type BadEncodingLimitsExceeded failures, not a fatal abort.
// ---------------------------------------------------------------------------

TEST_F(TypeLoaderTest, LoadTypes_NodeWorkBudgetExceeded)
{
  constexpr uint32_t extra = 1100;  // exceeds the WorkBudget{1000, ...} node bound
  for (uint32_t i = 0; i < extra; ++i)
  {
    const uint32_t id = 6000 + i;
    MockNode node;
    node.nodeId = NodeId{1, id};
    node.browseName.name() = String{"Budget" + std::to_string(i)};
    node.browseName.namespace_index() = 1;
    node.structureDefinition = make_struct_def(StructureType::Structure, std::vector<StructureField>{});
    mAccess.add_node(std::move(node));
    mAccess.add_subtype(NodeId{0, sStructureId}, NodeId{1, id}, "Budget");
    mAccess.add_encoding(NodeId{1, id}, NodeId{1, uint32_t{20000 + i}}, "Default Binary");
  }

  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());
  const auto& stats = result.value();

  ASSERT_TRUE(stats.has_failures());
  bool foundBudgetFailure = false;
  for (const auto& failure : stats.failures)
  {
    if (failure.detail && failure.detail->summary.find("work budget") != std::string::npos)
    {
      foundBudgetFailure = true;
      break;
    }
  }
  EXPECT_TRUE(foundBudgetFailure) << "expected at least one work-budget-exceeded failure";
}

TEST_F(TypeLoaderTest, LoadTypes_EnumFieldResolvedToInt32)
{
  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  const auto taskInfoDesc = mRegistry.find_structure(expanded(mTaskInfoId));
  ASSERT_NE(taskInfoDesc, nullptr);
  ASSERT_GE(taskInfoDesc->field_count(), 2u);

  // Field 1 is Priority (enum) - should be Int32, not ExtensionObject
  EXPECT_EQ(taskInfoDesc->field_built_in_type(1), BuiltInTypeId::Int32);
}

TEST_F(TypeLoaderTest, LoadTypes_OptionSetFieldResolvedToUInt32)
{
  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  const auto taskInfoDesc = mRegistry.find_structure(expanded(mTaskInfoId));
  ASSERT_NE(taskInfoDesc, nullptr);
  ASSERT_GE(taskInfoDesc->field_count(), 3u);

  // Field 2 is Access (option set subtype of UInt32) - should be UInt32
  EXPECT_EQ(taskInfoDesc->field_built_in_type(2), BuiltInTypeId::UInt32);
}

TEST_F(TypeLoaderTest, LoadType_SingleWithDeps)
{
  auto result = try_load_type_sync(mAccess, mRegistry, mSensorLocId);
  ASSERT_TRUE(result.is_good());

  auto stats = result.value();

  // SensorLocation registered
  EXPECT_NE(mRegistry.find_structure(expanded(mSensorLocId)), nullptr);

  // GeoCoordinate registered as dependency
  EXPECT_NE(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);

  // Total structures: SensorLocation + GeoCoordinate
  EXPECT_EQ(stats.structureCount, 2u);
}

TEST_F(TypeLoaderTest, LoadTypes_AbstractTypesSkipped)
{
  // Add an abstract structure type
  MockNode abstractNode;
  abstractNode.nodeId = NodeId{1, uint32_t{9001}};
  abstractNode.browseName.name() = String{"AbstractBase"};
  abstractNode.browseName.namespace_index() = 1;
  abstractNode.isAbstract = true;
  std::vector<StructureField> fields;
  fields.push_back(make_field("X", DataTypeId::Int32));
  abstractNode.structureDefinition = make_struct_def(StructureType::Structure, std::move(fields));
  mAccess.add_node(std::move(abstractNode));

  NodeId abstractId{1, uint32_t{9001}};
  mAccess.add_subtype(NodeId{0, sStructureId}, abstractId, "AbstractBase");
  mAccess.add_encoding(abstractId, NodeId{1, uint32_t{9901}}, "Default Binary");

  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  auto stats = result.value();
  EXPECT_GE(stats.skippedAbstract, 1u);

  // Should NOT be registered
  EXPECT_EQ(mRegistry.find_structure(expanded(abstractId)), nullptr);
}

TEST_F(TypeLoaderTest, LoadTypes_MissingEncodingRecordedAsFailure)
{
  // Add a structure type with NO HasEncoding reference
  MockNode noEncNode;
  noEncNode.nodeId = NodeId{1, uint32_t{9002}};
  noEncNode.browseName.name() = String{"NoEncoding"};
  noEncNode.browseName.namespace_index() = 1;
  std::vector<StructureField> fields;
  fields.push_back(make_field("Y", DataTypeId::Double));
  noEncNode.structureDefinition = make_struct_def(StructureType::Structure, std::move(fields));
  mAccess.add_node(std::move(noEncNode));

  NodeId noEncId{1, uint32_t{9002}};
  mAccess.add_subtype(NodeId{0, sStructureId}, noEncId, "NoEncoding");
  // Deliberately NOT adding an encoding reference

  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  auto stats = result.value();

  // Should appear in failures
  bool found = false;
  for (const auto& failure : stats.failures)
  {
    if (failure.typeId == noEncId)
    {
      found = true;
      EXPECT_NE(failure.detail, nullptr);
      break;
    }
  }
  EXPECT_TRUE(found) << "Missing encoding type should appear in failures";

  // Should NOT be registered
  EXPECT_EQ(mRegistry.find_structure(expanded(noEncId)), nullptr);
}

TEST_F(TypeLoaderTest, LoadTypes_UnionRegisteredAsUnion)
{
  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  const auto measurementDesc = mRegistry.find_structure(expanded(mMeasurementId));
  ASSERT_NE(measurementDesc, nullptr);
  EXPECT_EQ(measurementDesc->structure_type(), StructureType::Union);
  EXPECT_EQ(measurementDesc->field_count(), 2u);
}

TEST_F(TypeLoaderTest, LoadTypes_EmptyModel)
{
  // Create a fresh access with no types at all (just namespace array)
  MockTypeModelAccess emptyAccess;
  emptyAccess.namespaceArray.push_back(String{"http://opcfoundation.org/UA/"});

  DynamicTypeRegistry emptyRegistry;
  auto result = try_load_types_sync(emptyAccess, emptyRegistry);
  ASSERT_TRUE(result.is_good());

  auto stats = result.value();
  EXPECT_EQ(stats.structureCount, 0u);
  EXPECT_EQ(stats.enumCount, 0u);
  EXPECT_EQ(stats.failure_count(), 0u);
}

TEST_F(TypeLoaderTest, LoadType_SingleEnumType)
{
  auto result = try_load_type_sync(mAccess, mRegistry, mPriorityEnumId);
  ASSERT_TRUE(result.is_good());

  auto stats = result.value();
  EXPECT_EQ(stats.enumCount, 1u);

  // Priority enum should be registered
  EXPECT_NE(mRegistry.find_enum(expanded(mPriorityEnumId)), nullptr);
}

TEST_F(TypeLoaderTest, LoadType_UnknownType)
{
  NodeId unknownId{1, uint32_t{99999}};
  auto result = try_load_type_sync(mAccess, mRegistry, unknownId);

  // The result should indicate the type was not found
  // Either the overall result is bad, or the stats have a failure
  if (result.is_good())
  {
    auto stats = result.value();
    EXPECT_TRUE(stats.has_failures());
  }
  else
  {
    EXPECT_FALSE(result.is_good());
  }
}

TEST_F(TypeLoaderTest, LoadTypes_EnumRegistered)
{
  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  // Priority (plain enum)
  const auto priorityDesc = mRegistry.find_enum(expanded(mPriorityEnumId));
  ASSERT_NE(priorityDesc, nullptr);
  EXPECT_EQ(static_cast<string_view>(priorityDesc->type_name()), "Priority");
  EXPECT_FALSE(priorityDesc->is_option_set());
}

TEST_F(TypeLoaderTest, LoadTypes_OptionSetRegistered)
{
  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  // AccessFlags (option set)
  const auto accessDesc = mRegistry.find_enum(expanded(mAccessFlagsId));
  ASSERT_NE(accessDesc, nullptr);
  EXPECT_EQ(static_cast<string_view>(accessDesc->type_name()), "AccessFlags");
  EXPECT_TRUE(accessDesc->is_option_set());
}

TEST_F(TypeLoaderTest, LoadTypes_NoFailuresInCleanModel)
{
  auto result = try_load_types_sync(mAccess, mRegistry);
  ASSERT_TRUE(result.is_good());

  auto stats = result.value();
  EXPECT_FALSE(stats.has_failures()) << "Expected no failures; got " << stats.failure_count();
}

// The walk decides which types exist, so an Uncertain Browse page below the first level is refused rather
// than ending the walk with the types found so far: the load fails and nothing is registered.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST_F(TypeLoaderTest, LoadTypes_AnUncertainBrowsePageMidWalkIsRefused)
{
  UncertainAnswerModelAccess access;
  access.namespaceArray = mAccess.namespaceArray;
  access.nodes = mAccess.nodes;
  access.references = mAccess.references;
  access.uncertainBrowse = 2;  // the second level of the HasSubtype walk
  access.withData = true;

  auto result = try_load_types_sync(access, mRegistry);
  ASSERT_TRUE(result.is_bad()) << "status 0x" << std::hex << result.status_code().as_uint32();
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReferencesAnswerUncertain");
  EXPECT_EQ(
    result.shared_detail()->innerStatus, StatusCode{UncertainAnswerModelAccess::uncertainCode}.value());
  EXPECT_EQ(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
  EXPECT_EQ(mRegistry.find_enum(expanded(mPriorityEnumId)), nullptr);
}

// The type-information Read the loader registers from is refused when Uncertain, here without data: the load
// fails with Bad_InternalError rather than answering the Uncertain code with nothing registered.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST_F(TypeLoaderTest, LoadTypes_AnUncertainTypeInfoReadIsRefused)
{
  UncertainAnswerModelAccess access;
  access.namespaceArray = mAccess.namespaceArray;
  access.nodes = mAccess.nodes;
  access.references = mAccess.references;
  access.uncertainRead = 2;  // read 1 is the NamespaceArray, read 2 the type information
  access.withData = false;

  auto result = try_load_types_sync(access, mRegistry);
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_EQ(
    result.shared_detail()->innerStatus, StatusCode{UncertainAnswerModelAccess::uncertainCode}.value());
  EXPECT_EQ(mRegistry.find_structure(expanded(mGeoCoordId)), nullptr);
}

// Runs a whole-hierarchy load on its own thread and answers it, or nothing when it has not completed within
// @p limit. The thread holds the model and the registry through shared pointers, so a load that never ends
// leaves a detached thread behind rather than one that reads a destroyed test's objects.
std::optional<LoaderRegistrationStatsResult> load_types_within(std::shared_ptr<MockTypeModelAccess> access,
  std::shared_ptr<DynamicTypeRegistry> registry,
  std::chrono::seconds limit)
{
  auto answer = std::make_shared<std::promise<LoaderRegistrationStatsResult>>();
  auto future = answer->get_future();
  std::thread{[access, registry, answer] { answer->set_value(try_load_types_sync(*access, *registry)); }}
    .detach();
  if (future.wait_for(limit) != std::future_status::ready)
  {
    return std::nullopt;
  }
  return future.get();
}

// HasSubtype is a HasChild ReferenceType and so spans a non-looping hierarchy, but the parent of each
// discovered type is whatever the server answers to its inverse HasSubtype Browse. An enumeration whose
// parent chain loops - here P1's parent is P2 and P2's parent is P1, and a third type names itself - must
// still be registered, as a plain enumeration, and the load must complete.
// @relation(AC-CL-ADDRSP-013-CYCLIC-PARENT-CHAIN-ENDS, scope=function)
TEST_F(TypeLoaderTest, LoadTypes_CyclicHasSubtypeParentChainIsNotAnOptionSet)
{
  auto access = std::make_shared<MockTypeModelAccess>();
  access->namespaceArray = mAccess.namespaceArray;
  access->nodes = mAccess.nodes;

  const NodeId firstId{1, uint32_t{7001}};
  const NodeId secondId{1, uint32_t{7002}};
  const NodeId selfId{1, uint32_t{7003}};
  const std::vector<std::pair<NodeId, string_view>> cyclic{
    {firstId, "CyclicFirst"}, {secondId, "CyclicSecond"}, {selfId, "SelfParent"}};
  for (const auto& [id, name] : cyclic)
  {
    MockNode node;
    node.nodeId = id;
    node.browseName.name() = String{name};
    node.browseName.namespace_index() = 1;
    node.enumDefinition = make_enum_def({{"Off", 0}, {"On", 1}});
    access->add_node(std::move(node));

    QualifiedName qn;
    qn.name() = String{name};
    qn.namespace_index() = 1;
    // Forward only: the types are discovered under Enumeration, but their parents are the ones below.
    access->add_reference_async(
      NodeId{0, sEnumerationId}, NodeId{ReferenceTypeId::HasSubtype}, /*isForward*/ true, id, qn);
  }
  // The inverse HasSubtype answers come first, so they are the parents the loader records.
  access->add_reference_async(
    firstId, NodeId{ReferenceTypeId::HasSubtype}, /*isForward*/ false, secondId, QualifiedName{});
  access->add_reference_async(
    secondId, NodeId{ReferenceTypeId::HasSubtype}, /*isForward*/ false, firstId, QualifiedName{});
  access->add_reference_async(
    selfId, NodeId{ReferenceTypeId::HasSubtype}, /*isForward*/ false, selfId, QualifiedName{});
  access->references.insert(access->references.end(), mAccess.references.begin(), mAccess.references.end());

  auto registry = std::make_shared<DynamicTypeRegistry>();
  const auto result = load_types_within(access, registry, std::chrono::seconds{30});
  ASSERT_TRUE(result.has_value()) << "the load did not complete on a cyclic HasSubtype parent chain";
  ASSERT_TRUE(result->is_good()) << "status 0x" << std::hex << result->status_code().as_uint32();

  for (const auto& [id, name] : cyclic)
  {
    const auto descriptor = registry->find_enum(expanded(id));
    ASSERT_NE(descriptor, nullptr) << name;
    EXPECT_FALSE(descriptor->is_option_set()) << name;
  }
  // The well-formed chains next to the cyclic ones are still classified.
  const auto accessFlags = registry->find_enum(expanded(mAccessFlagsId));
  ASSERT_NE(accessFlags, nullptr);
  EXPECT_TRUE(accessFlags->is_option_set());
}

// Security regression (anti unbounded-allocation DoS): the DataType hierarchy is discovered entirely
// from server-returned references, so a malicious or buggy server can inflate it without limit (a
// cyclic HasSubtype graph would do the same). Discovering more than the supported maximum must fail
// with BadEncodingLimitsExceeded rather than accumulate and allocate O(N) batches against attacker
// input. Here a single browse of BaseDataType advertises > 100000 direct subtypes.
TEST(TypeLoaderSecurity, DiscoveredHierarchyExceedingCapIsRejected)
{
  MockTypeModelAccess access;
  access.namespaceArray.push_back(String{"http://opcfoundation.org/UA/"});

  constexpr size_t overCap = 100001;  // > kMaxDiscoveredTypes (100000)
  for (size_t i = 0; i < overCap; ++i)
  {
    QualifiedName childBrowseName;
    childBrowseName.name() = String{"T"};
    access.add_reference_async(NodeId{DataTypeId::BaseDataType},
      NodeId{ReferenceTypeId::HasSubtype},
      /*isForward*/ true,
      NodeId{1, static_cast<uint32_t>(i + 1)},
      childBrowseName);
  }

  DynamicTypeRegistry registry;
  auto result = try_load_types_sync(access, registry);
  ASSERT_FALSE(result.is_good()) << "an over-cap discovered hierarchy must be rejected";
  EXPECT_EQ(result.status_code().as_status(), Status::BadEncodingLimitsExceeded);
}

}  // namespace
