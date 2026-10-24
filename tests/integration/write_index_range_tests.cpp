// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 4 section 5.10.4.4, Table 61, Bad_IndexRangeInvalid: "It is also used if writing of IndexRange is
// supported in general for a Node but the passed IndexRange cannot be written by the Server." NR-42 A-14: a
// Write whose range has a different number of dimensions from the matrix keeps Bad_IndexRangeInvalid, while
// the Read of the same range answers Bad_IndexRangeNoData. A guard: it fails if the Read's change reaches the
// Write.
//
// Tier: the WriteRequest is sent through the Session's service call unmodified. The Client's typed tier
// refuses a dimension-count mismatch locally before sending (`client_read_write_index_matrix_tests.cpp`), so
// a test driven through it never reaches the Server, whose answer is what the criterion is about.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_array.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_session_attribute_services.h"
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

class WriteIndexRange : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    mMatrixId = NodeId{mTestNamespaceIndex, uint32_t{7710}};
    auto node = addressSpace.create_node_sync(mMatrixId, NodeClass::Variable);
    node.set_browse_name(QualifiedName{mTestNamespaceIndex, "WritableMatrix2x3"});
    node.set_display_name(LocalizedText{"", "WritableMatrix2x3"});
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_value_rank(ValueRank{2});
    variable->set_array_dimensions(std::vector<uint32_t>{0, 0});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    variable->write_value_sync(
      DataValue{Variant{Array<int32_t>{Dimensions{2, 3}, std::vector<int32_t>{1, 2, 3, 4, 5, 6}}}});
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMatrixId);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);
  }

  NodeId mMatrixId;
};

}  // namespace

// @relation(AC-SVR-ATTR-WRITE-020-DIMENSION-COUNT-MISMATCH-STAYS-INVALID, scope=function)
TEST_F(WriteIndexRange, ADimensionCountMismatchOnAMatrixIsIndexRangeInvalid)
{
  auto response = mSession->attributes().write_sync(
    WriteRequestBuilder()
      .write(mMatrixId, Variant{Array<int32_t>{10, 11}})
      .index_range(String{"0:1"})
      .write(mMatrixId, Variant{Array<int32_t>{Dimensions{2, 2}, std::vector<int32_t>{20, 21, 22, 23}}})
      .index_range(String{"0:1,1:2"})
      .build());
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_THAT(response.results()[0], HasStatus(Status::BadIndexRangeInvalid))
    << "a one-dimension range written to a 2x3 matrix";
  EXPECT_THAT(response.results()[1], HasStatus(Status::Good)) << "the control range naming both dimensions";

  const auto read = mSession->attributes().read_sync(read_value(mMatrixId));
  ASSERT_EQ(read.results().size(), 1u);
  EXPECT_EQ(to_string(read.results()[0].value()),
    to_string(Variant{Array<int32_t>{Dimensions{2, 3}, std::vector<int32_t>{1, 20, 21, 4, 22, 23}}}))
    << "the refused operation wrote something, or the control did not";
}
