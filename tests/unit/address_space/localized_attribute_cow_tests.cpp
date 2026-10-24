// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_node_accessor.h"
#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "monitored_item_probe.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_default_object_node.h"
#include "ua_to_string.h"

using namespace ua;
using namespace std::chrono_literals;

namespace
{

LocalizedText read_display_name(const ua::NodeAccessor& node)
{
  auto variant = node.read_attribute(AttributeId::DisplayName);
  if (variant.empty() || !variant.is_localized_text())
  {
    return {};
  }
  return variant.as<LocalizedText>();
}

}  // namespace

// The legacy shared-list COW model was replaced by the rich
// `LocalizedText` type whose aggregate storage is itself copy-on-write
// (a `shared_ptr<const vector<Scalar>>`). This test now exercises the
// write-merge + read-back contract at the BaseNode layer and verifies
// that per-locale upsert is applied (SVR-MI-GEN-071 / SVR-ATTR-WRITE-001).
TEST(LocalizedAttributeCowTests, DisplayNameAccumulatesLocalesAndMergesPerLocale)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:MyUri", tp.get_executor());

  NodeId nodeId{123};
  auto createResult = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto node = createResult.value();

  node.set_display_name(LocalizedText{"en", "Hello"});
  auto snap1 = read_display_name(node);
  EXPECT_TRUE(snap1.is_scalar());
  EXPECT_EQ(snap1.text(), String{"Hello"});
  EXPECT_EQ(snap1.locale(), LocaleId{String{"en"}});

  // Write a different locale - merge_with upgrades storage to an aggregate.
  node.set_display_name(LocalizedText{"fr", "Bonjour"});
  auto snap2 = read_display_name(node);
  EXPECT_EQ(snap2.translation_count(), 2u);
  EXPECT_EQ(snap2.text_for_locale("en").value_or(String{}), String{"Hello"});
  EXPECT_EQ(snap2.text_for_locale("fr").value_or(String{}), String{"Bonjour"});

  // Replace-by-locale (last write wins for the same locale).
  node.set_display_name(LocalizedText{"fr", "Salut"});
  auto snap3 = read_display_name(node);
  EXPECT_EQ(snap3.text_for_locale("fr").value_or(String{}), String{"Salut"});
  EXPECT_EQ(snap3.text_for_locale("en").value_or(String{}), String{"Hello"});
  ::ua::test_utils::drain_with_timeout(tp);
}

// F1: Writing {"",""} clears all stored translations (spec section 5.10.4).
TEST(LocalizedAttributeCowTests, ClearAllTranslationsViaEmptyWrite)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:MyUri", tp.get_executor());

  NodeId nodeId{200};
  auto createResult = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto node = createResult.value();

  node.set_display_name(LocalizedText{"en-US", "Hello"});
  node.set_display_name(LocalizedText{"de-DE", "Hallo"});
  auto snap1 = read_display_name(node);
  ASSERT_EQ(snap1.translation_count(), 2u);

  // Write empty locale + empty text -> clears all.
  node.set_display_name(LocalizedText{"", ""});
  auto snap2 = read_display_name(node);
  EXPECT_TRUE(snap2.is_null());
  ::ua::test_utils::drain_with_timeout(tp);
}

// F2: Writing {"en-US",""} deletes that locale, leaving others intact.
TEST(LocalizedAttributeCowTests, DeleteSingleLocaleViaEmptyTextWrite)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:MyUri", tp.get_executor());

  NodeId nodeId{201};
  auto createResult = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto node = createResult.value();

  node.set_display_name(LocalizedText{"en-US", "Hello"});
  node.set_display_name(LocalizedText{"de-DE", "Hallo"});
  auto snap1 = read_display_name(node);
  ASSERT_EQ(snap1.translation_count(), 2u);

  // Delete en-US by writing empty text for that locale.
  node.set_display_name(LocalizedText{"en-US", ""});
  auto snap2 = read_display_name(node);
  EXPECT_FALSE(snap2.text_for_locale("en-US").has_value());
  EXPECT_EQ(snap2.text_for_locale("de-DE").value_or(String{}), String{"Hallo"});
  ::ua::test_utils::drain_with_timeout(tp);
}

// F3: an item monitoring a Node's DisplayName receives a DataValue whose Variant holds the merged
// LocalizedText (SVR-MI-GEN-071 - the notification carries the stored value). The in-memory namespace
// reports the write by NodeId and attribute, and the item receives it at its next tick.
TEST(LocalizedAttributeCowTests, AMonitoredDisplayNameReceivesTheMergedLocalizedText)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:MyUri", tp.get_executor());
  auto accessor = addressSpace.create_node_sync(NodeId{1, 300}, NodeClass::Object);
  auto sink = std::make_shared<test::RecordingSampleSink>();
  const auto created = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 300},
      .attributeId = AttributeId::DisplayName,
      .monitoredItemId = 1,
      .samplingInterval = 0,
      .queueSize = 1,
      .sink = sink});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());

  // Write via the raw write_attribute path (same path set_display_name uses).
  accessor.write_attribute_sync(AttributeId::DisplayName, Variant{LocalizedText{"en-US", "Hello"}});

  ASSERT_TRUE(sink->wait_for_samples(1, 1s));
  const auto received = sink->samples().front().second;
  ASSERT_TRUE(received.value().is_localized_text());
  const auto& lt = received.value().as<LocalizedText>();
  EXPECT_FALSE(lt.is_null());
  EXPECT_EQ(lt.text(), String{"Hello"});
  EXPECT_EQ(lt.locale(), LocaleId{String{"en-US"}});

  EXPECT_TRUE(test::unmonitor(addressSpace, 1, created.value().handle).is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// F4a: two items monitoring the same Node's DisplayName each receive the write once, with the same
// merged DataValue.
TEST(LocalizedAttributeCowTests, TwoItemsOnADisplayNameEachReceiveTheWrite)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:MyUri", tp.get_executor());
  auto accessor = addressSpace.create_node_sync(NodeId{1, 400}, NodeClass::Object);
  auto first = std::make_shared<test::RecordingSampleSink>();
  auto second = std::make_shared<test::RecordingSampleSink>();
  const auto createdFirst = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 400},
      .attributeId = AttributeId::DisplayName,
      .monitoredItemId = 10,
      .samplingInterval = 0,
      .queueSize = 1,
      .sink = first});
  const auto createdSecond = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 400},
      .attributeId = AttributeId::DisplayName,
      .monitoredItemId = 20,
      .samplingInterval = 0,
      .queueSize = 1,
      .sink = second});
  ASSERT_TRUE(createdFirst.is_good()) << to_string(createdFirst.status_code());
  ASSERT_TRUE(createdSecond.is_good()) << to_string(createdSecond.status_code());

  accessor.write_attribute_sync(AttributeId::DisplayName, Variant{LocalizedText{"en", "World"}});

  ASSERT_TRUE(first->wait_for_samples(1, 1s));
  ASSERT_TRUE(second->wait_for_samples(1, 1s));
  // Nothing more arrives: each item receives the one write once.
  EXPECT_FALSE(first->wait_for_samples(2, 200ms));
  EXPECT_FALSE(second->wait_for_samples(2, 200ms));

  // Both items receive the same merged DataValue.
  const auto received1 = first->samples().front();
  const auto received2 = second->samples().front();
  EXPECT_EQ(received1.first, IntegerId{10});
  EXPECT_EQ(received2.first, IntegerId{20});
  ASSERT_TRUE(received1.second.value().is_localized_text());
  ASSERT_TRUE(received2.second.value().is_localized_text());
  EXPECT_EQ(received1.second.value().as<LocalizedText>().text(), String{"World"});
  EXPECT_EQ(received2.second.value().as<LocalizedText>().text(), String{"World"});

  EXPECT_TRUE(test::unmonitor(addressSpace, 1, createdFirst.value().handle).is_good());
  EXPECT_TRUE(test::unmonitor(addressSpace, 1, createdSecond.value().handle).is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// F4b: deleting one of two items on a DisplayName leaves the other receiving its writes.
TEST(LocalizedAttributeCowTests, DeletingOneItemLeavesTheOtherReceiving)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:MyUri", tp.get_executor());
  auto accessor = addressSpace.create_node_sync(NodeId{1, 401}, NodeClass::Object);
  auto first = std::make_shared<test::RecordingSampleSink>();
  auto second = std::make_shared<test::RecordingSampleSink>();
  const auto createdFirst = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 401},
      .attributeId = AttributeId::DisplayName,
      .monitoredItemId = 10,
      .samplingInterval = 0,
      .queueSize = 1,
      .sink = first});
  const auto createdSecond = test::monitor(addressSpace,
    {.nodeId = NodeId{1, 401},
      .attributeId = AttributeId::DisplayName,
      .monitoredItemId = 20,
      .samplingInterval = 0,
      .queueSize = 1,
      .sink = second});
  ASSERT_TRUE(createdFirst.is_good()) << to_string(createdFirst.status_code());
  ASSERT_TRUE(createdSecond.is_good()) << to_string(createdSecond.status_code());

  // Delete only the first item.
  ASSERT_TRUE(test::unmonitor(addressSpace, 1, createdFirst.value().handle).is_good());

  accessor.write_attribute_sync(AttributeId::DisplayName, Variant{LocalizedText{"en", "Test"}});

  ASSERT_TRUE(second->wait_for_samples(1, 1s));
  EXPECT_EQ(second->samples().front().second.value().as<LocalizedText>().text(), String{"Test"});
  EXPECT_TRUE(first->samples().empty());

  EXPECT_TRUE(test::unmonitor(addressSpace, 1, createdSecond.value().handle).is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}
