// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// What CreateMonitoredItems gives a namespace for a ranged item (COMP-SVR-NAMESPACE-CALLS-15 rule 1): the
// item's IndexRange in `MonitoringCreateItem::indexRange`, except for an item on one of the five attributes
// the service produces, which registers the attribute the namespace holds with no range, and which the item
// narrows after projecting it. The fixture is create_flow_tests.cpp's (create_flow_fixture.h).

#include <gtest/gtest.h>

#include "create_flow_fixture.h"

#include <string>
#include <string_view>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace ua::test::create_flow;

// COMP-SVR-NAMESPACE-CALLS-15 rule 1 and DL-69 (D3): an item on UserAccessLevel registers AccessLevel, the
// attribute the namespace holds, with no IndexRange; the item narrows the projected value itself, so the
// first notification of a scalar with the range "0" is Bad_IndexRangeNoData, as before B4c.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-SERVICE-PRODUCED-ATTRIBUTE-REGISTERS-WITHOUT-A-RANGE, scope=function)
TEST_F(CreateFlow, AServiceProducedAttributeRegistersWithoutARange)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId v =
    create_variable(NodeId{index, 810}, NodeId{DataTypeId::Int32}, DataValue{Variant{int32_t{0}}});
  measure(n);
  auto sub = subscription(1);
  auto item = value_item(v, 1);
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::UserAccessLevel);
  item.item_to_monitor().index_range() = "0";

  const auto results = create(*sub, list_of(std::move(item)), mSecurity);

  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  const auto calls = n.calls();
  const auto creates =
    naming(calls, [](const Call& call) { return is_member(call, Member::CreateMonitoring); }, {v});
  ASSERT_EQ(creates.size(), 1u) << "create_monitoring calls naming the Variable" << describe(calls);
  ASSERT_EQ(creates[0].monitoringItems.size(), 1u) << describe(calls);
  const auto& registered = creates[0].monitoringItems[0];
  EXPECT_EQ(registered.attributeId, AttributeId::AccessLevel)
    << "the item was registered on attribute " << static_cast<uint32_t>(registered.attributeId);
  EXPECT_EQ(std::string{std::string_view{registered.indexRange}}, "")
    << "the item was registered with an IndexRange the namespace's sample cannot hold";
  ASSERT_TRUE(publish_until(*sub, [&] { return !reports_of(1).empty(); })) << "the item reported nothing";
  EXPECT_EQ(reports_of(1).front().status.as_status(), Status::BadIndexRangeNoData) << reports_text(1);
}
