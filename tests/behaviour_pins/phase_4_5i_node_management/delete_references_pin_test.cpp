// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5i - DeleteReferences flow.
//
//
// Pins authored:
//   DR-A  DeleteReferencesEmptyRequestReturnsBadNothingToDo
//   DR-B  DeleteReferencesOverLimitReturnsBadTooManyOperations
//   DR-C  DeleteReferencesPerItemAuthorizationDenyMarksOnlyDeniedSlot
//   DR-D  DeleteReferencesPerItemAuthorizationUsesSourceNodeIdScope
//   DR-F  DeleteReferencesBatchStatusReplicatesAcrossAuthorizedIndices
//   DR-G  DeleteReferencesPropagatesBadNoMatchPerSpec (Part 4 section 5.7.5)
//   DR-H  DeleteReferencesPropagatesBadReferenceTypeIdInvalid
//   DR-J  DeleteReferencesUserCallbackFiresOnSinglePoolThread
//
// Skipped (infra gaps): DR-E timeout, DR-I audit-event capture.

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_delete_references_item.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
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

class DeleteReferencesPin : public ::testing::Test
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

  ua::Response invoke(ua::DeleteReferencesRequest&& req)
  {
    // DeleteReferences authorises against the source NodeAccessor; pre-create it.
    for (const auto& item : req.references_to_delete().payload())
    {
      mSession->ensure_authz_node(item.source_node_id());
      mSession->ensure_authz_node(item.target_node_id().node_id());
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

  static ua::DeleteReferencesItem make_item(const ua::NodeId& source)
  {
    ua::DeleteReferencesItem item;
    item.source_node_id() = source;
    item.reference_type_id() = nodeManagementPinReferenceTypeId;
    item.is_forward() = true;
    item.target_node_id() = ua::ExpandedNodeId{source};
    return item;
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<NodeManagementPinSessionInfo> mSession;
  std::shared_ptr<FakeNodeManagementDelegate> mDelegate;
};

}  // namespace

TEST_F(DeleteReferencesPin, DeleteReferencesEmptyRequestReturnsBadNothingToDo)
{
  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 1;

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadNothingToDo);
}

TEST_F(DeleteReferencesPin, DeleteReferencesOverLimitReturnsBadTooManyOperations)
{
  mSession->serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = 1;

  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 2;
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{1, 1u}));
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{1, 2u}));

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadTooManyOperations);
}

// @relation(SVR-NM-DR-024, scope=function)
TEST_F(DeleteReferencesPin, DeleteReferencesPerItemAuthorizationDenyMarksOnlyDeniedSlot)
{
  const ua::NodeId allow0{1, 1u};
  const ua::NodeId deny1{1, 2u};
  const ua::NodeId allow2{1, 3u};

  mSession->ensure_authz_node(deny1);
  mSession->set_node_permissions(deny1, ua::PermissionType{});

  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 3;
  req.references_to_delete().payload().push_back(make_item(allow0));
  req.references_to_delete().payload().push_back(make_item(deny1));
  req.references_to_delete().payload().push_back(make_item(allow2));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_TRUE(ua::StatusCode{response->results()[0]}.is_good());
  EXPECT_EQ(response->results()[1], ua::Status::BadUserAccessDenied);
  EXPECT_TRUE(ua::StatusCode{response->results()[2]}.is_good());
}

// @relation(SVR-NM-DR-024, scope=function)
TEST_F(DeleteReferencesPin, DeleteReferencesPerItemAuthorizationUsesSourceNodeIdScope)
{
  // Per Part 4 section 5.7.5: auth scope is the source NodeId.
  const ua::NodeId src0{2, 1u};
  const ua::NodeId src1{2, 2u};
  const ua::NodeId src2{2, 3u};

  for (const auto& source : {src0, src1, src2})
  {
    mSession->ensure_authz_node(source);
    mSession->set_node_permissions(source, ua::PermissionType{ua::PermissionType::Bit::RemoveReference});
  }
  const ua::NodeId deniedTarget{2, 99u};
  mSession->ensure_authz_node(deniedTarget);
  mSession->set_node_permissions(deniedTarget, ua::PermissionType{});

  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 4;
  for (const auto& source : {src0, src1, src2})
  {
    auto item = make_item(source);
    item.target_node_id() = ua::ExpandedNodeId{deniedTarget};
    req.references_to_delete().payload().push_back(std::move(item));
  }

  auto result = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteReferencesResponse*>(result.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (const auto& item : response->results())
    EXPECT_TRUE(ua::StatusCode{item}.is_good());
}

TEST_F(DeleteReferencesPin, DeleteReferencesBatchStatusReplicatesAcrossAuthorizedIndices)
{
  mDelegate->deleteReferencesFactory = [](const std::vector<ua::DeleteReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.batchStatus = ua::VoidResult{ua::Status::BadOutOfMemory};
    return batch;
  };

  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 5;
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{1, 1u}));
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{1, 2u}));
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{1, 3u}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_EQ(response->results()[0], ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[1], ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[2], ua::Status::BadOutOfMemory);
}

TEST_F(DeleteReferencesPin, DeleteReferencesPropagatesBadNoMatchPerSpec)
{
  // Part 4 section 5.7.5: when the reference being deleted does not exist the
  // delegate returns BadNoMatch. A regression mapping it to Good (treating
  // "nothing to delete" as a no-op) would FAIL.
  mDelegate->deleteReferencesFactory = [](const std::vector<ua::DeleteReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadNoMatch,
      std::shared_ptr<const ua::ErrorDetail>{
        ua::make_error_detail("NoMatch", "reference not found", "FakeDelegate")}});
    return batch;
  };

  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 6;
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0], ua::Status::BadNoMatch);
}

// @relation(SVR-NM-DR-021, scope=function)
TEST_F(DeleteReferencesPin, DeleteReferencesPropagatesBadReferenceTypeIdInvalid)
{
  mDelegate->deleteReferencesFactory = [](const std::vector<ua::DeleteReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadReferenceTypeIdInvalid,
      std::shared_ptr<const ua::ErrorDetail>{
        ua::make_error_detail("BadRefType", "invalid ref type", "FakeDelegate")}});
    return batch;
  };

  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 7;
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::DeleteReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0], ua::Status::BadReferenceTypeIdInvalid);
}

TEST_F(DeleteReferencesPin, DeleteReferencesUserCallbackFiresOnSinglePoolThread)
{
  std::promise<std::thread::id> userCallbackThread;
  auto fut = userCallbackThread.get_future();

  std::atomic<std::thread::id> delegateThread{};
  mDelegate->deleteReferencesFactory = [&delegateThread](const std::vector<ua::DeleteReferencesItem>& items)
  {
    delegateThread.store(std::this_thread::get_id());
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.assign(items.size(), ua::VoidResult{});
    return batch;
  };

  mSession->ensure_authz_node(ua::NodeId{1, 1u});

  ua::DeleteReferencesRequest req;
  req.request_header().request_handle() = 8;
  req.references_to_delete().payload().push_back(make_item(ua::NodeId{1, 1u}));

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
