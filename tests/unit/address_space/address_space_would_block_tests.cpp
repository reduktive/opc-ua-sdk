// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// The AddressSpace's blocking primitives refuse on a thread of its executor.
///
/// try_find_node_sync, try_create_node_sync and try_delete_node_sync wait on a future for an answer
/// the node's namespace may deliver by posting to the address space's executor. On a thread of that
/// executor the wait could never end, so each refuses with Bad_WouldBlock there - promptly, without
/// starting the operation - and still works from an application thread.

#include "posting_writes_namespace.h"
#include "ua_address_space.h"
#include "ua_node_class.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <boost/asio/post.hpp>

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>

using namespace ua;

namespace
{

constexpr auto timeout = std::chrono::seconds{5};

/// Runs @p call on the executor's thread and returns its status, or nullopt if it did not return.
std::optional<StatusCode> status_on_executor(
  ua::test::OneThreadExecutor& executor, std::function<StatusCode()> call)
{
  auto outcome = std::make_shared<std::promise<StatusCode>>();
  auto future = outcome->get_future();
  boost::asio::post(executor.executor(), [call = std::move(call), outcome] { outcome->set_value(call()); });
  if (future.wait_for(timeout) != std::future_status::ready)
    return std::nullopt;
  return future.get();
}

}  // namespace

TEST(AddressSpaceWouldBlock, FindOnTheExecutorRefusesAndWorksFromAnApplicationThread)
{
  ua::test::OneThreadExecutor executor;
  auto addressSpace = AddressSpace::create("urn:test:would-block", executor.executor());
  const NodeId nodeId{1, 100u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(nodeId, NodeClass::Object).is_good());

  const auto refused = status_on_executor(
    executor, [&addressSpace, nodeId] { return addressSpace.try_find_node_sync(nodeId).status_code(); });
  ASSERT_TRUE(refused.has_value()) << "try_find_node_sync blocked the address space's executor";
  EXPECT_EQ(*refused, StatusCode{Status::BadWouldBlock});

  EXPECT_TRUE(addressSpace.try_find_node_sync(nodeId).is_good());
}

TEST(AddressSpaceWouldBlock, CreateOnTheExecutorRefusesWithoutCreating)
{
  ua::test::OneThreadExecutor executor;
  auto addressSpace = AddressSpace::create("urn:test:would-block", executor.executor());
  const NodeId nodeId{1, 101u};

  const auto refused = status_on_executor(executor,
    [&addressSpace, nodeId]
    { return addressSpace.try_create_node_sync(nodeId, NodeClass::Object).status_code(); });
  ASSERT_TRUE(refused.has_value()) << "try_create_node_sync blocked the address space's executor";
  EXPECT_EQ(*refused, StatusCode{Status::BadWouldBlock});
  EXPECT_EQ(addressSpace.try_find_node_sync(nodeId).status_code(), StatusCode{Status::BadNodeIdUnknown})
    << "a refused create must not have created the node";

  EXPECT_TRUE(addressSpace.try_create_node_sync(nodeId, NodeClass::Object).is_good());
}

TEST(AddressSpaceWouldBlock, DeleteOnTheExecutorRefusesWithoutDeleting)
{
  ua::test::OneThreadExecutor executor;
  auto addressSpace = AddressSpace::create("urn:test:would-block", executor.executor());
  const NodeId nodeId{1, 102u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(nodeId, NodeClass::Object).is_good());

  const auto refused = status_on_executor(executor,
    [&addressSpace, nodeId] { return addressSpace.try_delete_node_sync(nodeId, false).status_code(); });
  ASSERT_TRUE(refused.has_value()) << "try_delete_node_sync blocked the address space's executor";
  EXPECT_EQ(*refused, StatusCode{Status::BadWouldBlock});
  EXPECT_TRUE(addressSpace.try_find_node_sync(nodeId).is_good()) << "a refused delete must not have deleted";

  EXPECT_TRUE(addressSpace.try_delete_node_sync(nodeId, false).is_good());
  EXPECT_EQ(addressSpace.try_find_node_sync(nodeId).status_code(), StatusCode{Status::BadNodeIdUnknown});
}
