// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// `node_utils::encode_writable_attribute` converts a written Attribute value to the form a Node stores,
// before the Write service checks it against the Node. For ArrayDimensions (delivery decision DL-32) it takes
// a one-dimensional UInt32 array or null and nothing else: Part 3 section 5.6.2, Table 13 gives the Attribute
// the DataType UInt32[], and Part 4 section 5.10.4.2, Table 59 answers a value of another type
// Bad_TypeMismatch.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_array.h"
#include "ua_array_base.h"
#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_datatype_id.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_node_utilities.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <cstdint>
#include <optional>
#include <vector>

using namespace ua;

// Each refused value has one entry, which the ValueRank of 1 would take, so only its type or shape refuses
// it. The UInt32 array {7} is the control, and the node then stores [7]; null is the other value the encoder
// takes.
// @relation(AC-SVR-ATTR-WRITE-033-NOT-A-UINT32-ARRAY, scope=function)
TEST(NodeUtilitiesEncode, ArrayDimensionsTakesAOneDimensionalUInt32ArrayOrNull)
{
  boost::asio::thread_pool pool{2};
  auto addressSpace = AddressSpace::create("urn:test:node-utilities-encode", pool.get_executor());
  const NodeId v1Id{1, uint32_t{100}};
  {
    auto created = addressSpace.try_create_sync<VariableAccessor>(v1Id, NodeClass::Variable);
    ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    auto& variable = created.value();
    variable.set_data_type(NodeId{DataTypeId::Int32});
    variable.set_value_rank(ValueRank{1});
    variable.set_array_dimensions(std::vector<uint32_t>{5});
    variable.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ArrayDimensions});
  }
  auto node = addressSpace.find_node_sync(v1Id);
  const auto held = [&]
  {
    return node.as<VariableAccessor>()->get_array_dimensions();
  };
  using Held = std::optional<std::vector<uint32_t>>;

  struct Refused
  {
    const char* what;
    Variant value;
  };

  const Refused refused[] = {{"the Int32 array {3}", Variant{Array<int32_t>{3}}},
    {"the UInt32 array {3} with array dimensions {1, 1}",
      Variant{Array<uint32_t>{ua::Dimensions{1, 1}, std::vector<uint32_t>{3}}}},
    {"the scalar UInt32 3", Variant{uint32_t{3}}}};
  for (const auto& [what, value] : refused)
  {
    const auto encoded = node_utils::encode_writable_attribute(node, AttributeId::ArrayDimensions, value);
    EXPECT_EQ(encoded.status_code().as_status(), Status::BadTypeMismatch)
      << what << " encoded as " << to_string(encoded.status_code());
    EXPECT_EQ(held(), (Held{std::vector<uint32_t>{5}})) << what;
  }

  const auto control =
    node_utils::encode_writable_attribute(node, AttributeId::ArrayDimensions, Variant{Array<uint32_t>{7}});
  ASSERT_TRUE(control.is_good()) << "the UInt32 array {7} encoded as " << to_string(control.status_code());
  const auto stored = node.try_write_attribute_sync(AttributeId::ArrayDimensions, control.value());
  EXPECT_TRUE(stored.is_good()) << to_string(stored.status_code());
  EXPECT_EQ(held(), (Held{std::vector<uint32_t>{7}})) << "the encoded {7} is not what the node stores";

  const auto null = node_utils::encode_writable_attribute(node, AttributeId::ArrayDimensions, Variant{});
  EXPECT_TRUE(null.is_good()) << "null encoded as " << to_string(null.status_code());
  ::ua::test_utils::drain_with_timeout(pool);
}
