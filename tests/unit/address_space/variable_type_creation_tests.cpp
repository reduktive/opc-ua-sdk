// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// DL-20: a VariableType's Value given at creation through `AddressSpace::create_node_async` reads back,
// whether it is given as the value's Variant, as AddNodes carries it (Part 4 section 7.24.6, Table 159), or
// as a DataValue holding the value, the form the SDK's own creators use.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <cstdint>
#include <future>
#include <optional>

using namespace std::chrono_literals;
using namespace ua;

namespace
{

NodeAccessorResult create_variable_type(AddressSpace& addressSpace, const NodeId& nodeId, Variant value)
{
  InitialAttributes attributes;
  attributes.emplace_back(AttributeId::BrowseName, Variant{QualifiedName{1, "CreatedVariableType"}});
  attributes.emplace_back(AttributeId::DataType, Variant{NodeId{DataTypeId::Int32}});
  attributes.emplace_back(AttributeId::Value, std::move(value));

  std::promise<NodeAccessorResult> created;
  auto future = created.get_future();
  addressSpace.create_node_async(nodeId,
    NodeClass::VariableType,
    std::move(attributes),
    [&created](NodeAccessorResult result) { created.set_value(std::move(result)); });
  if (future.wait_for(5s) != std::future_status::ready)
    return NodeAccessorResult{StatusCode{Status::BadTimeout}};
  return future.get();
}

}  // namespace

// @relation(AC-COMP-ADDRSP-CREATE-NODE-INITIAL-ATTRIBUTES-01-VARIABLETYPE-VALUE-AS-VARIANT, scope=function)
TEST(VariableTypeCreation, AValueGivenAsAVariantReadsBack)
{
  boost::asio::thread_pool pool{2};
  auto addressSpace = AddressSpace::create("urn:test:variable-type-creation", pool.get_executor());

  const auto asVariant = create_variable_type(addressSpace, NodeId{1, uint32_t{7800}}, Variant{int32_t{7}});
  ASSERT_EQ(asVariant.status_code().as_status(), Status::Good);
  const auto asDataValue =
    create_variable_type(addressSpace, NodeId{1, uint32_t{7801}}, Variant{DataValue{Variant{int32_t{7}}}});
  ASSERT_EQ(asDataValue.status_code().as_status(), Status::Good);

  const auto variantType = asVariant.value().as<VariableTypeAccessor>();
  ASSERT_TRUE(variantType.has_value());
  const auto variantValue = variantType->get_value();
  ASSERT_TRUE(variantValue.has_value()) << "a Value given as a Variant at creation reads back as no value";
  EXPECT_EQ(variantValue->value(), Variant{int32_t{7}}) << to_string(variantValue->value());

  const auto dataValueType = asDataValue.value().as<VariableTypeAccessor>();
  ASSERT_TRUE(dataValueType.has_value());
  const auto dataValueValue = dataValueType->get_value();
  ASSERT_TRUE(dataValueValue.has_value()) << "the DataValue form no longer reads back";
  EXPECT_EQ(dataValueValue->value(), Variant{int32_t{7}}) << to_string(dataValueValue->value());

  ::ua::test_utils::drain_with_timeout(pool);
}
