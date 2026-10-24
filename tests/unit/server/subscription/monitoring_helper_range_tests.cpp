// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the monitoring helper narrows what it delivers to a ranged registration (COMP-SVR-NAMESPACE-CALLS-15
// rule 2, NR-48 rule 2): each value is narrowed to the registration's own IndexRange before it is compared
// with the last one delivered. The fixture is monitoring_helper_tests.cpp's (monitoring_helper_fixture.h).

#include <gtest/gtest.h>

#include "monitoring_helper_fixture.h"

#include "ua_array.h"

#include <chrono>
#include <thread>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;
using namespace ua::test::monitoring_helper;

// COMP-SVR-NAMESPACE-CALLS-15 rule 2 (NR-48 rule 2, DL-68 (2)): two Reported registrations on one Value, with
// the ranges "1" and "0:1", each receive their own slice of a reported change; a later change outside both
// slices, reported without timestamps, is no change for either.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-REPORTED-VALUE-IS-NARROWED-PER-REGISTRATION, scope=function)
TEST_F(MonitoringHelperIndex, AReportedValueIsNarrowedPerRegistration)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:reported-range");
  auto n = variable(*ns, 70u, Variant{Array<int32_t>{0, 0, 0}});
  auto single = sink();
  auto pair = sink();
  auto first = resolved(n->node_id(), AttributeId::Value, 1, 100, single, n, Helper::Delivery::Reported);
  first.item.indexRange = "1";
  auto second = resolved(n->node_id(), AttributeId::Value, 2, 100, pair, n, Helper::Delivery::Reported);
  second.item.indexRange = "0:1";
  const std::vector<Helper::ResolvedMonitoringItem> items{first, second};
  const auto created = ns->helper().create_monitoring(items);
  ASSERT_EQ(created.size(), items.size());
  for (size_t index = 0; index < created.size(); ++index)
    ASSERT_TRUE(created[index].result.is_good())
      << "create " << index << ": " << to_string(created[index].result.status_code());

  ns->helper().attribute_changed(
    n->node_id(), AttributeId::Value, DataValue{Variant{Array<int32_t>{10, 20, 30}}});
  ASSERT_TRUE(single->wait_for_samples(1, 2s)) << single->text();
  ASSERT_TRUE(pair->wait_for_samples(1, 2s)) << pair->text();
  ns->helper().attribute_changed(
    n->node_id(), AttributeId::Value, DataValue{Variant{Array<int32_t>{10, 20, 99}}});
  std::this_thread::sleep_for(400ms);

  const auto singleEvents = single->events();
  ASSERT_EQ(singleEvents.size(), 1u) << "the registration with the range 1: " << single->text();
  EXPECT_EQ(singleEvents[0].value.value(), Variant{Array<int32_t>{20}})
    << "the registration with the range 1: " << single->text();
  const auto pairEvents = pair->events();
  ASSERT_EQ(pairEvents.size(), 1u) << "the registration with the range 0:1: " << pair->text();
  EXPECT_EQ(pairEvents[0].value.value(), (Variant{Array<int32_t>{10, 20}}))
    << "the registration with the range 0:1: " << pair->text();
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 2, and an option is applied or refused with a reason, never ignored: the
// helper refuses a registration whose IndexRange does not parse with Bad_IndexRangeInvalid (OPC 10000-4 7.27,
// "2:1" names a lower bound above its upper bound), and registers the item beside it.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-AN-INDEXRANGE-THAT-DOES-NOT-PARSE-IS-REFUSED-BY-THE-HELPER, scope=function)
TEST_F(MonitoringHelperIndex, AnIndexRangeThatDoesNotParseIsRefused)
{
  auto ns = registered_namespace("urn:test:monitoring-helper:range-syntax");
  auto n = variable(*ns, 71u, Variant{Array<int32_t>{1, 2, 3}});
  auto refusedSink = sink();
  auto createdSink = sink();
  auto invalid =
    resolved(n->node_id(), AttributeId::Value, 1, 100, refusedSink, n, Helper::Delivery::Sampled);
  invalid.item.indexRange = "2:1";
  auto valid = resolved(n->node_id(), AttributeId::Value, 2, 100, createdSink, n, Helper::Delivery::Sampled);
  valid.item.indexRange = "0";
  const std::vector<Helper::ResolvedMonitoringItem> items{invalid, valid};

  const auto created = ns->helper().create_monitoring(items);

  ASSERT_EQ(created.size(), items.size());
  EXPECT_EQ(created[0].result.status_code().as_status(), Status::BadIndexRangeInvalid)
    << "the registration with the range 2:1: " << to_string(created[0].result.status_code());
  ASSERT_TRUE(created[1].result.is_good())
    << "the registration with the range 0: " << to_string(created[1].result.status_code());
  EXPECT_NE(created[1].result.value().handle, MonitoringHandle{0});
}
