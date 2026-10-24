// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 4 section 7.27: "Bad_IndexRangeInvalid is only used for invalid syntax of the NumericRange. All other
// invalid requests with a valid syntax shall result in Bad_IndexRangeNoData." A range whose number of
// dimensions differs from the Value's is valid syntax (NR-10 rule 9), and a Value with an Uncertain status
// is narrowed like a Good one.
//
// Tier: these tests send the ReadRequest through the Session's service call unmodified. The Client's typed
// tier refuses a dimension-count mismatch locally with Bad_IndexRangeInvalid before sending
// (`client_read_write_index_matrix_tests.cpp`, MultiDimAllDimsRequired), so a test driven through it never
// reaches the Server, whose answer is what these criteria are about.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <cstdint>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;

namespace
{

class ReadIndexRange : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    mMatrixId = create_array_variable(7700u,
      "Matrix2x3",
      2,
      std::vector<uint32_t>{0, 0},
      DataValue{Variant{Array<int32_t>{Dimensions{2, 3}, std::vector<int32_t>{1, 2, 3, 4, 5, 6}}}});
    DataValue uncertain{Variant{Array<int32_t>{10, 20, 30, 40, 50}}};
    uncertain.status() = StatusCode{Status::UncertainLastUsableValue};
    mUncertainArrayId = create_array_variable(7701u, "UncertainArray", 1, std::nullopt, std::move(uncertain));
    DataValue waiting;
    waiting.status() = StatusCode{Status::BadWaitingForInitialData};
    mWaitingId = create_array_variable(7702u, "WaitingForInitialData", 1, std::nullopt, std::move(waiting));
    DataValue exceeded{Variant{int32_t{7}}};
    exceeded.status() = StatusCode{Status::UncertainEngineeringUnitsExceeded};
    mUncertainScalarId =
      create_array_variable(7703u, "UncertainScalar", ValueRank::scalar, std::nullopt, std::move(exceeded));
  }

  NodeId create_array_variable(uint32_t id, const char* name, int32_t valueRank,
    std::optional<std::vector<uint32_t>> arrayDimensions, DataValue value)
  {
    auto addressSpace = mServer.server().address_space();
    const NodeId nodeId{mTestNamespaceIndex, id};
    auto node = addressSpace.create_node_sync(nodeId, NodeClass::Variable);
    node.set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    node.set_display_name(LocalizedText{"", name});
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = node.as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    if (!variable.has_value())
      return nodeId;
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_value_rank(ValueRank{valueRank});
    variable->set_array_dimensions(std::move(arrayDimensions));
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(std::move(value));
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, nodeId);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);
    return nodeId;
  }

  NodeId mMatrixId;
  NodeId mUncertainArrayId;
  NodeId
    mWaitingId;  ///< An Int32 array Variable whose stored DataValue is Bad_WaitingForInitialData, no Value.
  NodeId mUncertainScalarId;  ///< An Int32 Variable whose stored DataValue is 7,
                              ///< Uncertain_EngineeringUnitsExceeded.
};

/// The Read service's data-encoding step, over the same Variables.
class ReadDataEncoding : public ReadIndexRange
{};

Status status_of(const DataValue& value)
{
  return value.status().value_or(StatusCode{Status::Good}).as_status();
}

}  // namespace

// @relation(AC-SVR-ATTR-READ-027-ALL-DIMENSIONS-SPECIFIED, scope=function)
TEST_F(ReadIndexRange, ADimensionCountMismatchOnAMatrixIsIndexRangeNoData)
{
  auto response = mSession->attributes().read_sync(ReadRequestBuilder()
                                                     .read(mMatrixId)
                                                     .index_range(String{"0:1"})
                                                     .read(mMatrixId)
                                                     .index_range(String{"0:1,0:1,0:1"})
                                                     .read(mMatrixId)
                                                     .index_range(String{"0:1,1:2"}));
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 3u);

  EXPECT_EQ(status_of(response.results()[0]), Status::BadIndexRangeNoData)
    << "a one-dimension range on a 2x3 matrix answered " << to_string(response.results()[0].value());
  EXPECT_TRUE(response.results()[0].value().empty()) << "a bad result carries a value";
  EXPECT_EQ(status_of(response.results()[1]), Status::BadIndexRangeNoData)
    << "a three-dimension range on a 2x3 matrix answered " << to_string(response.results()[1].value());
  EXPECT_TRUE(response.results()[1].value().empty()) << "a bad result carries a value";

  EXPECT_EQ(status_of(response.results()[2]), Status::Good) << "the control range naming both dimensions";
  const auto* block = response.results()[2].value().try_as<Array<int32_t>>();
  ASSERT_NE(block, nullptr) << "the control range answered " << to_string(response.results()[2].value());
  EXPECT_EQ(std::vector<int32_t>(block->begin(), block->end()), (std::vector<int32_t>{2, 3, 5, 6}));
  ASSERT_TRUE(block->dimensions().has_value()) << "the narrowed matrix carries no dimensions";
  EXPECT_EQ(*block->dimensions(), (Dimensions{2, 2}));
}

// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-READ-UNCERTAIN-NARROWS, scope=function)
TEST_F(ReadIndexRange, AnUncertainValueIsNarrowed)
{
  auto response =
    mSession->attributes().read_sync(ReadRequestBuilder().read(mUncertainArrayId).index_range(String{"2:3"}));
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(status_of(response.results()[0]), Status::UncertainLastUsableValue);
  EXPECT_EQ(to_string(response.results()[0].value()), to_string(Variant{Array<int32_t>{30, 40}}))
    << "the Uncertain value was not narrowed to the selected elements";
}

// A guard: the Read keeps a Bad value's own status rather than the range's code, and gives it no Value.
// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-01-READ-BAD-VALUE-KEEPS-ITS-STATUS, scope=function)
TEST_F(ReadIndexRange, ABadValueKeepsItsStatus)
{
  auto response =
    mSession->attributes().read_sync(ReadRequestBuilder().read(mWaitingId).index_range(String{"2:3"}));
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(status_of(response.results()[0]), Status::BadWaitingForInitialData);
  EXPECT_TRUE(response.results()[0].value().empty())
    << "the Bad value was answered with " << to_string(response.results()[0].value());
}

// Part 4 section 7.29, Table 171: a dataEncoding "only applies if the DataType of the Variable is a subtype
// of Structure". The rule depends on the Variable's DataType, not on the status of the value read, so an
// Uncertain Int32 value with an encoding is Bad_DataEncodingInvalid with no Value (Table 135). The same value
// without an encoding, and a Bad value, are the controls.
// @relation(AC-SVR-ATTR-READ-021-UNCERTAIN-NON-STRUCTURE-VALUE-ENCODING-INVALID, scope=function)
TEST_F(ReadDataEncoding, AnUncertainNonStructureValueReadWithAnEncodingIsDataEncodingInvalid)
{
  const QualifiedName defaultBinary{0, "Default Binary"};
  auto response = mSession->attributes().read_sync(ReadRequestBuilder()
                                                     .read(mUncertainScalarId)
                                                     .data_encoding(defaultBinary)
                                                     .read(mUncertainScalarId)
                                                     .read(mWaitingId)
                                                     .data_encoding(defaultBinary));
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 3u);

  EXPECT_EQ(status_of(response.results()[0]), Status::BadDataEncodingInvalid)
    << "the Uncertain Int32 value read with an encoding";
  EXPECT_TRUE(response.results()[0].value().empty())
    << "the Uncertain Int32 value read with an encoding was answered with "
    << to_string(response.results()[0].value());

  EXPECT_EQ(status_of(response.results()[1]), Status::UncertainEngineeringUnitsExceeded)
    << "the control read with no encoding";
  const auto* kept = response.results()[1].value().try_as<int32_t>();
  ASSERT_NE(kept, nullptr) << "the control read with no encoding answered "
                           << to_string(response.results()[1].value());
  EXPECT_EQ(*kept, 7);

  EXPECT_EQ(status_of(response.results()[2]), Status::BadWaitingForInitialData)
    << "the Bad value read with an encoding";
  EXPECT_TRUE(response.results()[2].value().empty());
}
