// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5i - DeleteNodes flow.
//
//
// Pins authored:
//   DN-A  DeleteNodesEmptyRequestReturnsBadNothingToDo
//   DN-B  DeleteNodesOverLimitReturnsBadTooManyOperations
//   DN-C  DeleteNodesPerItemAuthorizationDenyMarksOnlyDeniedSlot
//   DN-D  DeleteNodesPerItemAuthorizationUsesNodeIdScope
//   DN-F  DeleteNodesBatchStatusReplicatesAcrossAuthorizedIndices
//   DN-G  DeleteNodesPerItemBadResultMergedIntoCorrectSlot (BadNodeIdUnknown
//         per Part 4 section 5.7.4)
//   DN-H  DeleteNodesForwardsDeleteTargetReferencesFlagToDelegate
//   DN-J  DeleteNodesUserCallbackFiresOnSinglePoolThread
//
// Skipped (infra gaps): DN-E timeout, DN-I audit-event capture.

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_delete_nodes_item.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_node_management_service.h"
#include "ua_object_id.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_node_management_delegate.h"
#include "node_management_pin_fixture.h"

using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

class DeleteNodesPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(1);
    mSession = std::make_shared<NodeManagementPinSessionInfo>(mPool->executor());
    mDelegate = std::make_shared<FakeNodeManagementDelegate>();
  }

  void TearDown() override
  {
    if (mPool)
      mPool->stop();
  }

  ua::Response invoke(ua::DeleteNodesRequest&& req)
  {
    // DeleteNodes authorises against the target NodeAccessor; pre-create it.
    for (const auto& item : req.nodes_to_delete().payload())
    {
      mSession->ensure_authz_node(item.node_id());
    }
    std::promise<ua::Response> p;
    auto fut = p.get_future();
    auto svc = ua::server::NodeManagementService::create(mSession,
      mDelegate,
      1,
      std::move(req),
      mPool->executor(),
      [&p](ua::Response r) { p.set_value(std::move(r)); });
    (void)svc;
    EXPECT_EQ(fut.wait_for(5s), std::future_status::ready);
    return fut.get();
  }

  static ua::DeleteNodesItem make_item(const ua::NodeId& nodeId, bool deleteTargetReferences = false)
  {
    ua::DeleteNodesItem item;
    item.node_id() = nodeId;
    item.delete_target_references() = deleteTargetReferences;
    return item;
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<NodeManagementPinSessionInfo> mSession;
  std::shared_ptr<FakeNodeManagementDelegate> mDelegate;
};

}  // namespace

TEST_F(DeleteNodesPin, DeleteNodesEmptyRequestReturnsBadNothingToDo)
{
  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 1;

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadNothingToDo);
}

TEST_F(DeleteNodesPin, DeleteNodesOverLimitReturnsBadTooManyOperations)
{
  mSession->serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = 1;

  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 2;
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 1u}));
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 2u}));

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadTooManyOperations);
}

TEST_F(DeleteNodesPin, DeleteNodesPerItemAuthorizationDenyMarksOnlyDeniedSlot)
{
  const ua::NodeId allow0{1, 1u};
  const ua::NodeId deny1{1, 2u};
  const ua::NodeId allow2{1, 3u};

  mSession->ensure_authz_node(deny1);
  mSession->set_node_permissions(deny1, ua::PermissionType{});

  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 3;
  req.nodes_to_delete().payload().push_back(make_item(allow0));
  req.nodes_to_delete().payload().push_back(make_item(deny1));
  req.nodes_to_delete().payload().push_back(make_item(allow2));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_TRUE(ua::StatusCode{response->results()[0]}.is_good());
  EXPECT_EQ(response->results()[1], ua::Status::BadUserAccessDenied);
  EXPECT_TRUE(ua::StatusCode{response->results()[2]}.is_good());
}

TEST_F(DeleteNodesPin, DeleteNodesPerItemAuthorizationUsesNodeIdScope)
{
  // Per Part 4 section 5.7.4: auth scope is the node_id() of each item.
  const ua::NodeId n0{2, 1u};
  const ua::NodeId n1{2, 2u};
  const ua::NodeId n2{2, 3u};

  for (const auto& node : {n0, n1, n2})
  {
    mSession->ensure_authz_node(node);
    mSession->set_node_permissions(node, ua::PermissionType{ua::PermissionType::Bit::DeleteNode});
  }

  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 4;
  req.nodes_to_delete().payload().push_back(make_item(n0));
  req.nodes_to_delete().payload().push_back(make_item(n1));
  req.nodes_to_delete().payload().push_back(make_item(n2));

  auto result = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteNodesResponse*>(result.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (const auto& item : response->results())
    EXPECT_TRUE(ua::StatusCode{item}.is_good());
}

TEST_F(DeleteNodesPin, DeleteNodesBatchStatusReplicatesAcrossAuthorizedIndices)
{
  mDelegate->deleteNodesFactory = [](const std::vector<ua::DeleteNodesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.batchStatus = ua::VoidResult{ua::Status::BadOutOfMemory};
    return batch;
  };

  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 5;
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 1u}));
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 2u}));
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 3u}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_EQ(response->results()[0], ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[1], ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[2], ua::Status::BadOutOfMemory);
}

TEST_F(DeleteNodesPin, DeleteNodesPerItemBadResultMergedIntoCorrectSlot)
{
  // Per Part 4 section 5.7.4: BadNodeIdUnknown is the documented per-item failure
  // code when the target node does not exist. A regression that mapped this
  // to Status::Good (e.g. treating "nothing to delete" as a no-op) would FAIL.
  mDelegate->deleteNodesFactory = [](const std::vector<ua::DeleteNodesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadNodeIdUnknown,
      std::shared_ptr<const ua::ErrorDetail>{
        ua::make_error_detail("Unknown", "node id unknown", "FakeDelegate")}});
    return batch;
  };

  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 6;
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{4, 99u}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0], ua::Status::BadNodeIdUnknown);
}

TEST_F(DeleteNodesPin, DeleteNodesForwardsDeleteTargetReferencesFlagToDelegate)
{
  // Two items: index 0 with delete_target_references=true, index 1 with
  // delete_target_references=false. The delegate must observe both flags
  // unchanged (Part 4 section 5.7.4). A regression that hard-coded the flag would
  // FAIL on either index.
  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 7;
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 100u}, /*deleteTargetReferences=*/true));
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 200u}, /*deleteTargetReferences=*/false));

  (void)invoke(std::move(req));

  ASSERT_EQ(mDelegate->deleteNodesRecordedItems.size(), 2u);
  EXPECT_TRUE(mDelegate->deleteNodesRecordedItems[0].delete_target_references());
  EXPECT_FALSE(mDelegate->deleteNodesRecordedItems[1].delete_target_references());
}

TEST_F(DeleteNodesPin, DeleteNodesUserCallbackFiresOnSinglePoolThread)
{
  std::promise<std::thread::id> userCallbackThread;
  auto fut = userCallbackThread.get_future();

  std::atomic<std::thread::id> delegateThread{};
  mDelegate->deleteNodesFactory = [&delegateThread](const std::vector<ua::DeleteNodesItem>& items)
  {
    delegateThread.store(std::this_thread::get_id());
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.assign(items.size(), ua::VoidResult{});
    return batch;
  };

  mSession->ensure_authz_node(ua::NodeId{1, 1u});

  ua::DeleteNodesRequest req;
  req.request_header().request_handle() = 8;
  req.nodes_to_delete().payload().push_back(make_item(ua::NodeId{1, 1u}));

  auto svc = ua::server::NodeManagementService::create(mSession,
    mDelegate,
    1,
    std::move(req),
    mPool->executor(),
    [&userCallbackThread](ua::Response) { userCallbackThread.set_value(std::this_thread::get_id()); });
  (void)svc;

  ASSERT_EQ(fut.wait_for(5s), std::future_status::ready);
  EXPECT_NE(delegateThread.load(), std::thread::id{});
  EXPECT_EQ(fut.get(), delegateThread.load());
}

}  // namespace ua::test::behaviour_pins
