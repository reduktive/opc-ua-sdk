// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_access_level_ex_type.h"
#include "ua_address_space.h"
#include "ua_attribute_wire.h"
#include "ua_default_base_node.h"
#include "ua_node_accessor.h"
#include "ua_node_description.h"
#include "ua_to_string.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <thread>

using namespace ua;

namespace
{

VoidResult write_inline(const NodeAccessor& accessor, AttributeId attributeId, Variant value)
{
  auto* const node = dynamic_cast<default_ns::BaseNode*>(accessor.operator->());
  if (node == nullptr)
  {
    return VoidResult{Status::BadInternalError};
  }
  std::optional<VoidResult> answer;
  node->write_attribute_async(
    attributeId, std::move(value), [&answer](VoidResult result) { answer = std::move(result); });
  return answer.value_or(VoidResult{Status::BadInternalError});
}

}  // namespace

// NR-21 rule 5: a Node of the in-memory namespace holds its description. Two descriptions taken with no write
// between them read one body, and a description taken before a write keeps reading the body it was given.
// @relation(AC-COMP-DEFAULT-NODE-ATTR-STORAGE-05-A-READER-KEEPS-ONE-BODY, scope=function)
TEST(InMemoryDescriptions, AReaderOfTheOldDescriptionKeepsOneBody)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:in-memory-descriptions", pool.get_executor());
    const NodeAccessor node = addressSpace.create_node_sync(NodeId{1, uint32_t{1}},
      NodeClass::Object,
      InitialAttributes{{AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{1, "Held"})},
        {AttributeId::DisplayName,
          attribute_wire::display_name(LocalizedText{LocaleId{"en"}, String{"Old"}})}});

    const NodeDescription before = node->attributes();
    const NodeDescription again = node->attributes();
    EXPECT_EQ(&before.display_name(), &again.display_name());

    ASSERT_TRUE(
      write_inline(node, AttributeId::DisplayName, Variant{LocalizedText{LocaleId{"en"}, String{"New"}}})
        .is_good());

    EXPECT_EQ(before.display_name(), (LocalizedText{LocaleId{"en"}, String{"Old"}}));
    const NodeDescription after = node->attributes();
    EXPECT_EQ(after.display_name(), (LocalizedText{LocaleId{"en"}, String{"New"}}));
    EXPECT_NE(&after.display_name(), &before.display_name());
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// NR-21 rule 5: a change is read, built and stored under one hold of the Node's lock, so two concurrent
// writes to one Node both land. AccessLevel is the low byte of AccessLevelEx: a write of AccessLevel keeps
// the high bits another thread writes to AccessLevelEx meanwhile.
// @relation(AC-COMP-DEFAULT-NODE-ATTR-STORAGE-05-TWO-CONCURRENT-WRITES-BOTH-LAND, scope=function)
TEST(InMemoryDescriptions, TwoConcurrentWritesToOneNodeBothLand)
{
  constexpr uint32_t lowByte = 0x03u;
  constexpr uint32_t withHighBit = 0x103u;
  constexpr int rounds = 300;
  constexpr int levelWritesPerRound = 64;

  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:in-memory-descriptions", pool.get_executor());
    const NodeAccessor node = addressSpace.create_node_sync(NodeId{1, uint32_t{2}},
      NodeClass::Variable,
      InitialAttributes{
        {AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{1, "Variable"})}});

    int lost{0};
    for (int round = 0; round < rounds; ++round)
    {
      ASSERT_TRUE(write_inline(node, AttributeId::AccessLevelEx, Variant{lowByte}).is_good());
      std::atomic<bool> writing{false};
      std::thread levels(
        [&node, &writing]
        {
          for (int write = 0; write < levelWritesPerRound; ++write)
          {
            (void)write_inline(node, AttributeId::AccessLevel, Variant{static_cast<uint8_t>(lowByte)});
            writing.store(true, std::memory_order_release);
          }
        });
      while (!writing.load(std::memory_order_acquire))
      {
        std::this_thread::yield();
      }
      const VoidResult extended = write_inline(node, AttributeId::AccessLevelEx, Variant{withHighBit});
      levels.join();
      ASSERT_TRUE(extended.is_good()) << to_string(extended.status_code());

      const NodeDescription description = node->attributes();
      const auto held = description.access_level_ex();
      ASSERT_TRUE(held.has_value());
      if (held->as_underlying_type() != withHighBit)
      {
        ++lost;
      }
      ASSERT_TRUE(description.access_level().has_value());
      EXPECT_EQ(description.access_level()->as_underlying_type(), lowByte);
    }
    EXPECT_EQ(lost, 0) << "rounds in which an AccessLevel write lost the AccessLevelEx written meanwhile";
  }
  ::ua::test_utils::drain_with_timeout(pool);
}
