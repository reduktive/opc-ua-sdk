// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The C++ to OPC UA type mapping (public API review 2026-10, item 8b section 9.3; D-20). A mapped type names
// its DataType, ValueRank and ArrayDimensions; a namespace-0 DataType is a plain NodeId and any other
// carries its namespace URI; an unmapped type has no DataType at all rather than BaseDataType.

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ua_argument.h"
#include "ua_built_in_type_id.h"
#include "ua_byte_string.h"
#include "ua_data_type_of.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_decimal.h"
#include "ua_diagnostic_info.h"
#include "ua_guid.h"
#include "ua_localized_text.h"
#include "ua_node_class.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_status_code.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_xml_element.h"

namespace
{

/// A structure an application wrote by hand, in its own namespace.
struct Recipe
{};

/// A structure an application wrote by hand and left unmapped.
struct Unmapped
{};

}  // namespace

template<>
struct ua::DataTypeOf<Recipe>
{
  static constexpr uint32_t id{3005};
  static constexpr std::string_view namespaceUri{"urn:example:recipes"};
};

namespace
{
using namespace ua;

/// The DataType NodeId of a built-in type is its built-in type identifier (OPC 10000-6 5.1.2).
template<typename T>
void expect_built_in(BuiltInTypeId builtIn)
{
  const auto dataType = data_type_of<T>();
  EXPECT_TRUE(dataType.namespace_uri().empty()) << to_string(builtIn);
  EXPECT_EQ(dataType.node_id(), (NodeId{0, static_cast<uint32_t>(utils::to_underlying(builtIn))}))
    << to_string(builtIn);
  EXPECT_EQ(dataType.node_id(), (NodeId{0, static_cast<uint32_t>(utils::to_underlying(built_in_type<T>()))}))
    << "the mapping must agree with built_in_type for " << to_string(builtIn);
  EXPECT_EQ(value_rank_of<T>().as_int32(), ValueRank::scalar);
  EXPECT_TRUE(array_dimensions_of<T>().empty());
}

TEST(DataTypeOf, EveryBuiltInTypeIsItsBuiltInDataType)
{
  expect_built_in<bool>(BuiltInTypeId::Boolean);
  expect_built_in<int8_t>(BuiltInTypeId::SByte);
  expect_built_in<uint8_t>(BuiltInTypeId::Byte);
  expect_built_in<int16_t>(BuiltInTypeId::Int16);
  expect_built_in<uint16_t>(BuiltInTypeId::UInt16);
  expect_built_in<int32_t>(BuiltInTypeId::Int32);
  expect_built_in<uint32_t>(BuiltInTypeId::UInt32);
  expect_built_in<int64_t>(BuiltInTypeId::Int64);
  expect_built_in<uint64_t>(BuiltInTypeId::UInt64);
  expect_built_in<float>(BuiltInTypeId::Float);
  expect_built_in<double>(BuiltInTypeId::Double);
  expect_built_in<String>(BuiltInTypeId::String);
  expect_built_in<DateTime>(BuiltInTypeId::DateTime);
  expect_built_in<Guid>(BuiltInTypeId::Guid);
  expect_built_in<ByteString>(BuiltInTypeId::ByteString);
  expect_built_in<XmlElement>(BuiltInTypeId::XmlElement);
  expect_built_in<NodeId>(BuiltInTypeId::NodeId);
  expect_built_in<ExpandedNodeId>(BuiltInTypeId::ExpandedNodeId);
  expect_built_in<StatusCode>(BuiltInTypeId::StatusCode);
  expect_built_in<QualifiedName>(BuiltInTypeId::QualifiedName);
  expect_built_in<LocalizedText>(BuiltInTypeId::LocalizedText);
  expect_built_in<DataValue>(BuiltInTypeId::DataValue);
  expect_built_in<DiagnosticInfo>(BuiltInTypeId::DiagnosticInfo);
}

TEST(DataTypeOf, TheTypesWhoseDataTypeIsNotTheirEncodingAreNamedExplicitly)
{
  EXPECT_EQ(data_type_of<std::string>(), ExpandedNodeId{NodeId{DataTypeId::String}});
  EXPECT_EQ(data_type_of<Variant>(), ExpandedNodeId{NodeId{DataTypeId::BaseDataType}});
  EXPECT_EQ(data_type_of<Decimal>(), ExpandedNodeId{NodeId{DataTypeId::Decimal}})
    << "Decimal travels as an ExtensionObject, but its DataType is Decimal";
}

TEST(DataTypeOf, AGeneratedStructureAndEnumerationAreTheirOwnDataTypes)
{
  EXPECT_EQ(data_type_of<Argument>(), ExpandedNodeId{NodeId{DataTypeId::Argument}});
  EXPECT_EQ(data_type_of<NodeClass>(), ExpandedNodeId{NodeId{DataTypeId::NodeClass}})
    << "an enumeration is its own DataType, not Int32";
  EXPECT_EQ(value_rank_of<NodeClass>().as_int32(), ValueRank::scalar);
}

TEST(DataTypeOf, AnArrayIsOneDimensionOfItsElementsDataType)
{
  EXPECT_EQ(data_type_of<Array<double>>(), ExpandedNodeId{NodeId{DataTypeId::Double}});
  EXPECT_EQ(data_type_of<std::vector<String>>(), ExpandedNodeId{NodeId{DataTypeId::String}});
  EXPECT_EQ(value_rank_of<std::vector<int32_t>>().as_int32(), 1);
  EXPECT_EQ(array_dimensions_of<Array<Argument>>(), std::vector<uint32_t>{0});
}

TEST(DataTypeOf, AnOptionalIsTheTypeItHolds)
{
  EXPECT_EQ(data_type_of<std::optional<bool>>(), ExpandedNodeId{NodeId{DataTypeId::Boolean}});
  EXPECT_EQ(value_rank_of<std::optional<std::vector<double>>>().as_int32(), 1);
  EXPECT_TRUE(array_dimensions_of<std::optional<double>>().empty());
}

TEST(DataTypeOf, AnotherNamespacesDataTypeCarriesItsUriForTheServerToResolve)
{
  const auto dataType = data_type_of<Recipe>();
  EXPECT_EQ(dataType.namespace_uri(), String{"urn:example:recipes"});
  EXPECT_EQ(dataType.node_id().identifier().get_numeric(), 3005u);
}

// An unmapped type has no DataType: no fallback to BaseDataType, Structure or the encoding's built-in type.
static_assert(!hasDataType<Unmapped>);
static_assert(!hasDataType<char>, "char is neither SByte nor Byte");
static_assert(!hasDataType<long double>);
static_assert(!hasDataType<PermissionType>, "an option set is not mapped (section 9.3)");
static_assert(!hasDataType<Array<Array<int32_t>>>, "a nested array is not a one-dimensional array");
static_assert(!hasDataType<std::vector<std::optional<int32_t>>>);
static_assert(!hasDataType<std::optional<std::optional<int32_t>>>);
static_assert(hasDataType<Recipe> && hasDataType<NodeClass> && hasDataType<const Argument&>);

}  // namespace
