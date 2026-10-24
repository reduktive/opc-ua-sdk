// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5i - AddReferences flow.
//
//
// Pins authored:
//   AR-A  AddReferencesEmptyRequestReturnsBadNothingToDo
//   AR-B  AddReferencesOverLimitReturnsBadTooManyOperations
//   AR-C  AddReferencesPerItemAuthorizationDenyMarksOnlyDeniedSlot
//   AR-D  AddReferencesPerItemAuthorizationUsesSourceNodeIdScope
//   AR-F  AddReferencesBatchStatusReplicatesAcrossAuthorizedIndices
//   AR-G  AddReferencesPerItemBadResultMergedIntoCorrectSlot
//   AR-H  AddReferencesPropagatesBadTargetNodeIdInvalid
//   AR-I  AddReferencesPropagatesBadReferenceNotAllowed
//   AR-J  AddReferencesPropagatesBadServerIndexInvalid
//   AR-L  AddReferencesUserCallbackFiresOnSinglePoolThread
//
// Skipped (infra gaps - see PR summary): AR-E timeout (deferred fake
// authorizer), AR-K audit-event capture (EventBus listener).

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_add_references_item.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
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

class AddReferencesPin : public ::testing::Test
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

  ua::Response invoke(ua::AddReferencesRequest&& req)
  {
    // AddReferences authorises against the source NodeAccessor; pre-create it.
    for (const auto& item : req.references_to_add().payload())
    {
      mSession->ensure_authz_node(item.source_node_id());
      if (item.target_node_id().is_local() && !item.target_node_id().node_id().is_null())
        mSession->ensure_authz_node(item.target_node_id().node_id(), item.target_node_class());
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

  static ua::AddReferencesItem make_item(const ua::NodeId& source)
  {
    ua::AddReferencesItem item;
    item.source_node_id() = source;
    item.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
    item.is_forward() = true;
    item.target_node_id().node_id() = ua::NodeId{1, 9000u};
    item.target_node_class() = ua::NodeClass::Object;
    return item;
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<NodeManagementPinSessionInfo> mSession;
  std::shared_ptr<FakeNodeManagementDelegate> mDelegate;
};

}  // namespace

TEST_F(AddReferencesPin, AddReferencesEmptyRequestReturnsBadNothingToDo)
{
  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadNothingToDo);
}

// Covers SVR-NM-SVC-002 (coverage-audit retag).
TEST_F(AddReferencesPin, AddReferencesOverLimitReturnsBadTooManyOperations)
{
  mSession->serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = 1;

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 2;
  req.references_to_add().payload().push_back(make_item(ua::NodeId{1, 1u}));
  req.references_to_add().payload().push_back(make_item(ua::NodeId{1, 2u}));

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadTooManyOperations);
}

// @relation(SVR-NM-AR-027, scope=function)
TEST_F(AddReferencesPin, AddReferencesPerItemAuthorizationDenyMarksOnlyDeniedSlot)
{
  const ua::NodeId allow0{1, 1u};
  const ua::NodeId deny1{1, 2u};
  const ua::NodeId allow2{1, 3u};

  mSession->ensure_authz_node(deny1);
  mSession->set_node_permissions(deny1, ua::PermissionType{});

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 3;
  req.references_to_add().payload().push_back(make_item(allow0));
  req.references_to_add().payload().push_back(make_item(deny1));
  req.references_to_add().payload().push_back(make_item(allow2));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_TRUE(ua::StatusCode{response->results()[0]}.is_good());
  EXPECT_EQ(response->results()[1], ua::Status::BadUserAccessDenied);
  EXPECT_TRUE(ua::StatusCode{response->results()[2]}.is_good());
}

// @relation(SVR-NM-AR-027, scope=function)
TEST_F(AddReferencesPin, AddReferencesPerItemAuthorizationUsesSourceNodeIdScope)
{
  // Each source grants only AddReference while the shared target grants nothing.
  // A regression that scopes authorization on the target is therefore refused.
  const ua::NodeId src0{2, 1u};
  const ua::NodeId src1{2, 2u};
  const ua::NodeId src2{2, 3u};

  for (const auto& source : {src0, src1, src2})
  {
    mSession->ensure_authz_node(source);
    mSession->set_node_permissions(source, ua::PermissionType{ua::PermissionType::Bit::AddReference});
  }
  const ua::NodeId target{1, 9000u};
  mSession->ensure_authz_node(target);
  mSession->set_node_permissions(target, ua::PermissionType{});

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 4;
  req.references_to_add().payload().push_back(make_item(src0));
  req.references_to_add().payload().push_back(make_item(src1));
  req.references_to_add().payload().push_back(make_item(src2));

  auto result = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddReferencesResponse*>(result.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (const auto& item : response->results())
    EXPECT_TRUE(ua::StatusCode{item}.is_good());
}

TEST_F(AddReferencesPin, AddReferencesBatchStatusReplicatesAcrossAuthorizedIndices)
{
  mDelegate->addReferencesFactory = [](const std::vector<ua::AddReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.batchStatus = ua::VoidResult{ua::Status::BadOutOfMemory};
    return batch;
  };

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 5;
  req.references_to_add().payload().push_back(make_item(ua::NodeId{1, 1u}));
  req.references_to_add().payload().push_back(make_item(ua::NodeId{1, 2u}));
  req.references_to_add().payload().push_back(make_item(ua::NodeId{1, 3u}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_EQ(response->results()[0], ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[1], ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[2], ua::Status::BadOutOfMemory);
}

// @relation(SVR-NM-AR-020, SVR-NM-AR-028, scope=function)
TEST_F(AddReferencesPin, AddReferencesPerItemBadResultMergedIntoCorrectSlot)
{
  auto detail1 = ua::make_error_detail("Dup", "duplicate", "FakeDelegate");
  std::shared_ptr<const ua::ErrorDetail> sharedDetail1{std::move(detail1)};
  auto detail2 = ua::make_error_detail("BadSrc", "source invalid", "FakeDelegate");
  std::shared_ptr<const ua::ErrorDetail> sharedDetail2{std::move(detail2)};

  mDelegate->addReferencesFactory = [&](const std::vector<ua::AddReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.emplace_back(ua::VoidResult{});
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadDuplicateReferenceNotAllowed, sharedDetail1});
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadSourceNodeIdInvalid, sharedDetail2});
    return batch;
  };

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 6;
  req.references_to_add().payload().push_back(make_item(ua::NodeId{4, 1u}));
  req.references_to_add().payload().push_back(make_item(ua::NodeId{4, 2u}));
  req.references_to_add().payload().push_back(make_item(ua::NodeId{4, 3u}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_TRUE(ua::StatusCode{response->results()[0]}.is_good());
  EXPECT_EQ(response->results()[1], ua::Status::BadDuplicateReferenceNotAllowed);
  EXPECT_EQ(response->results()[2], ua::Status::BadSourceNodeIdInvalid);
}

// @relation(SVR-NM-AR-023, scope=function)
TEST_F(AddReferencesPin, AddReferencesPropagatesBadTargetNodeIdInvalid)
{
  mDelegate->addReferencesFactory = [](const std::vector<ua::AddReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadTargetNodeIdInvalid,
      std::shared_ptr<const ua::ErrorDetail>{
        ua::make_error_detail("BadTarget", "target invalid", "FakeDelegate")}});
    return batch;
  };

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 7;
  req.references_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0], ua::Status::BadTargetNodeIdInvalid);
}

// @relation(SVR-NM-AR-025, scope=function)
TEST_F(AddReferencesPin, AddReferencesPropagatesBadReferenceNotAllowed)
{
  mDelegate->addReferencesFactory = [](const std::vector<ua::AddReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadReferenceNotAllowed,
      std::shared_ptr<const ua::ErrorDetail>{
        ua::make_error_detail("BadRef", "reference not allowed", "FakeDelegate")}});
    return batch;
  };

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 8;
  req.references_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0], ua::Status::BadReferenceNotAllowed);
}

TEST_F(AddReferencesPin, AddReferencesPropagatesBadServerIndexInvalid)
{
  mDelegate->addReferencesFactory = [](const std::vector<ua::AddReferencesItem>&)
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.emplace_back(ua::VoidResult{ua::Status::BadServerIndexInvalid,
      std::shared_ptr<const ua::ErrorDetail>{
        ua::make_error_detail("BadSrv", "server index invalid", "FakeDelegate")}});
    return batch;
  };

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 9;
  req.references_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddReferencesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0], ua::Status::BadServerIndexInvalid);
}

TEST_F(AddReferencesPin, AddReferencesUserCallbackFiresOnSinglePoolThread)
{
  std::promise<std::thread::id> userCallbackThread;
  auto fut = userCallbackThread.get_future();

  std::atomic<std::thread::id> delegateThread{};
  mDelegate->addReferencesFactory = [&delegateThread](const std::vector<ua::AddReferencesItem>& items)
  {
    delegateThread.store(std::this_thread::get_id());
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.assign(items.size(), ua::VoidResult{});
    return batch;
  };

  mSession->ensure_authz_node(ua::NodeId{ua::ObjectId::ObjectsFolder});

  ua::AddReferencesRequest req;
  req.request_header().request_handle() = 10;
  req.references_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

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
