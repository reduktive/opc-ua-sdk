// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 4 section 7.27: a syntactically valid IndexRange that is not valid for the Value, such as one with a
// different number of dimensions from a matrix, results in Bad_IndexRangeNoData, and the clause is not
// limited to the Read Service. With ArrayDimensions {0, 0} the length is dynamic (Part 3 section 5.6.2,
// Table 13), so Part 4 section 5.12.2.4, Table 71 puts the code in the Publish response: both items are
// created and the mismatched one reports it per notification.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_session_monitored_item_services.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

class MonitoredItemIndexRange : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    mMatrixId = NodeId{mTestNamespaceIndex, uint32_t{7800}};
    auto node = addressSpace.create_node_sync(mMatrixId, NodeClass::Variable);
    node.set_browse_name(QualifiedName{mTestNamespaceIndex, "SampledMatrix2x3"});
    node.set_display_name(LocalizedText{"", "SampledMatrix2x3"});
    node.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_value_rank(ValueRank{2});
    variable->set_array_dimensions(std::vector<uint32_t>{0, 0});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    variable->write_value_sync(
      DataValue{Variant{Array<int32_t>{Dimensions{2, 3}, std::vector<int32_t>{1, 2, 3, 4, 5, 6}}}});
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMatrixId);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);
  }

  void SetUp() override
  {
    ComplianceWithNodes::SetUp();
    mSubscriptionId = create_subscription(*mSession, {.publishingInterval = 50.0});
  }

  void TearDown() override
  {
    if (mSession)
      delete_subscription(*mSession, mSubscriptionId);
    ComplianceWithNodes::TearDown();
  }

  NodeId mMatrixId;
  uint32_t mSubscriptionId{0};
};

constexpr uint32_t mismatchHandle = 1;
constexpr uint32_t controlHandle = 2;

}  // namespace

// @relation(AC-SVR-ATTR-READ-027-SAMPLED-DIMENSION-MISMATCH, scope=function)
TEST_F(MonitoredItemIndexRange, ADimensionCountMismatchOnAMatrixIsIndexRangeNoData)
{
  CreateMonitoredItemsRequest request = build_create_mi_request(
    mSubscriptionId, mMatrixId, {.clientHandle = mismatchHandle, .samplingInterval = 50.0, .queueSize = 1});
  request.items_to_create()[0].item_to_monitor().index_range() = "0:1";
  auto control = build_create_mi_request(
    mSubscriptionId, mMatrixId, {.clientHandle = controlHandle, .samplingInterval = 50.0, .queueSize = 1});
  control.items_to_create()[0].item_to_monitor().index_range() = "0:1,1:2";
  request.items_to_create().push_back(std::move(control.items_to_create()[0]));

  auto created = mSession->monitored_items().create_monitored_items_sync(std::move(request));
  ASSERT_EQ(created.results().size(), 2u);
  EXPECT_EQ(created.results()[0].status_code().as_status(), Status::Good)
    << "the item whose range does not fit the dynamic-length matrix was refused at creation";
  EXPECT_EQ(created.results()[1].status_code().as_status(), Status::Good);

  // Every notification of either item, until both have reported.
  std::map<uint32_t, DataValue> firstNotification;
  const auto deadline = std::chrono::steady_clock::now() + 3s;
  while (firstNotification.size() < 2u && std::chrono::steady_clock::now() < deadline)
  {
    auto change = wait_for_data_change(*mSession, mSubscriptionId, subscription_detail::AlwaysTrue{}, 500ms);
    if (!change)
      continue;
    for (const auto& item : change->monitored_items())
      firstNotification.try_emplace(item.client_handle(), item.value());
  }
  ASSERT_EQ(firstNotification.count(mismatchHandle), 1u) << "the mismatched item reported nothing";
  ASSERT_EQ(firstNotification.count(controlHandle), 1u) << "the control item reported nothing";

  const auto& mismatch = firstNotification.at(mismatchHandle);
  EXPECT_EQ(mismatch.status().value_or(StatusCode{Status::Good}).as_status(), Status::BadIndexRangeNoData)
    << "the one-dimension range on a 2x3 matrix reported " << to_string(mismatch.value());
  EXPECT_TRUE(mismatch.value().empty()) << "a bad notification carries a value";

  const auto& sampled = firstNotification.at(controlHandle);
  EXPECT_EQ(sampled.status().value_or(StatusCode{Status::Good}).as_status(), Status::Good);
  const auto* block = sampled.value().try_as<Array<int32_t>>();
  ASSERT_NE(block, nullptr) << "the control item reported " << to_string(sampled.value());
  EXPECT_EQ(std::vector<int32_t>(block->begin(), block->end()), (std::vector<int32_t>{2, 3, 5, 6}));
  ASSERT_TRUE(block->dimensions().has_value()) << "the narrowed matrix carries no dimensions";
  EXPECT_EQ(*block->dimensions(), (Dimensions{2, 2}));
}
