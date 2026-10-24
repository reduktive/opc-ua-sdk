// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "instantiation/ua_node_subtree.h"

using namespace ua;

TEST(NodeSubtreeTests, DestructorDeletesCreatedNodes)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  const NodeId id{1, "subtree-test"};
  {
    auto createResult = addressSpace.try_create_node_sync(id, NodeClass::Object, {});
    ASSERT_TRUE(createResult.is_good());

    NodeSubtree subtree{addressSpace, id, {id}};
  }

  auto findResult = addressSpace.try_find_node_sync(id);
  ASSERT_TRUE(findResult.is_bad());
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NodeSubtreeTests, ReleasePreventsDestructorDeletion)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  const NodeId id{1, "subtree-test-release"};
  {
    auto createResult = addressSpace.try_create_node_sync(id, NodeClass::Object, {});
    ASSERT_TRUE(createResult.is_good());

    NodeSubtree subtree{addressSpace, id, {id}};
    subtree.release();
  }

  auto findResult = addressSpace.try_find_node_sync(id);
  ASSERT_TRUE(findResult.is_good());

  addressSpace.delete_node_sync(id, true);
  ::ua::test_utils::drain_with_timeout(tp);
}
