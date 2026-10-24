// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (typed accessors).
//
// The pins reach their Node, a FakeNode held by a FakeAsyncNamespace, through
// an AddressSpace: accessors come only from an address space.

#include <future>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_async_namespace.h"
#include "fake_node.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_duration.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_read_value_id.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_utilities.h"
#include "ua_variant.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

namespace ua::test::behaviour_pins
{
namespace
{

class TypedAccessorsPin : public ::testing::Test
{};

}  // namespace

// ---------------------------------------------------------------------------
// TA-L - NodeAccessor::as<T>() returns nullopt when the wrapped node's
//        NodeClass does not match the typed accessor's expected class.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in NodeAccessor::as<T> that returns
// a default-constructed T (without checking is_matching_class()) would
// produce dangerous typed accessors against the wrong node class. The pin
// stages a Variable-class fake and asks for MethodAccessor - must yield
// nullopt.

TEST_F(TypedAccessorsPin, NodeAccessorAsTReturnsNullOptOnTypeMismatch)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create(String{"urn:test:ta-l"}, pool.get_executor());
    auto fakeNs = FakeAsyncNamespace::create("urn:test:ta-l:fake");
    const auto index = addressSpace.try_add_namespace_sync(fakeNs);
    ASSERT_TRUE(index.is_good());
    const NodeId variableId{index.value(), std::string_view{"ta-l:variable"}};
    fakeNs->hold(variableId, std::make_shared<FakeNode>(variableId, NodeClass::Variable));
    const NodeAccessor accessor = addressSpace.find_node_sync(variableId);

    auto methodAccessor = accessor.as<MethodAccessor>();
    EXPECT_FALSE(methodAccessor.has_value())
      << "as<MethodAccessor>() on a Variable-class node must return nullopt";

    // Sanity check: matching cast yields the typed accessor.
    auto variableAccessor = accessor.as<VariableAccessor>();
    EXPECT_TRUE(variableAccessor.has_value())
      << "as<VariableAccessor>() on a Variable-class node must return the accessor";
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

}  // namespace ua::test::behaviour_pins
