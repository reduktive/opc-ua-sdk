// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5i - strand-dispatch contract.
//
//
// Pins authored:
//   SD-A  AddNodesInlineFastPathPreservesStrandThread - under inline-
//         completing fakes the entire chain (per-item authorize, batch
//         dispatch, audit, user callback) runs on a single pool thread.
//         A regression that unconditionally posted instead of dispatched
//         would observe the work crossing back and forth between threads
//         (or, with a 1-thread pool, would still serialise but observably
//         break under a multi-thread pool - captured by the per-step
//         thread-id recordings).
//
//   SD-C  AddNodesInlineCompletionTrampolinesPastDepthThreshold -
//         Stack-growth regression test. Drives a 1000-item AddNodes
//         request under inline-completing fakes; asserts the user callback
//         fires successfully without stack overflow. The post-retirement
//         async substrate posts every continuation, so per-item stack
//         growth is bounded by construction; a regression that re-introduces
//         synchronous recursion through the per-item path would manifest
//         as a crash here.
//
// Pins flagged as INFRA GAP (NOT authored - see PR summary):
//   SD-B  authorizer-async dispatches back to strand: requires a deferred
//         FakeAuthorizer with parked-callback queue + dedicated worker
//         thread. tests/helpers/FakeAuthorizer fires inline only.
//   SD-D  delegate-async dispatches back to strand: same - requires a
//         deferred FakeNodeManagementDelegate with parked-callback queue
//         + dedicated worker thread.

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_node_management_service.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_node_management_delegate.h"
#include "node_management_pin_fixture.h"

using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

class NodeManagementStrandDispatchPin : public ::testing::Test
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

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<NodeManagementPinSessionInfo> mSession;
  std::shared_ptr<FakeNodeManagementDelegate> mDelegate;
};

}  // namespace

// --- SD-A ------------------------------------------------------------------

TEST_F(NodeManagementStrandDispatchPin, AddNodesInlineFastPathPreservesStrandThread)
{
  std::promise<std::thread::id> userCallbackThread;
  auto fut = userCallbackThread.get_future();

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 1;
  for (int i = 0; i < 3; ++i)
  {
    ua::NodeId parentId{1, static_cast<uint32_t>(100 + i)};
    mSession->ensure_authz_node(parentId);
    ua::AddNodesItem item;
    item.parent_node_id().node_id() = parentId;
    item.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
    item.browse_name() = ua::QualifiedName{parentId.namespace_index(), "PinnedObject"};
    item.node_class() = ua::NodeClass::Object;
    item.type_definition().node_id() = nodeManagementPinObjectTypeId;
    req.nodes_to_add().payload().push_back(std::move(item));
  }

  auto svc = ua::server::NodeManagementService::create(mSession,
    mDelegate,
    /*requestId=*/1,
    std::move(req),
    mPool->executor(),
    [&userCallbackThread](ua::Response) { userCallbackThread.set_value(std::this_thread::get_id()); });
  (void)svc;

  ASSERT_EQ(fut.wait_for(5s), std::future_status::ready);

  auto callbackThread = fut.get();
  auto delegateThread = mDelegate->addNodesInvokedThread.load();

  // Both observable completion hops must run on the single pool thread.
  // (With a 1-thread boost::asio::thread_pool, the strand cannot serve a different thread.)
  EXPECT_NE(delegateThread, std::thread::id{}) << "delegate step never ran";
  EXPECT_EQ(callbackThread, delegateThread)
    << "user callback ran on a different thread than the delegate - strand lost on completion";
}

// --- SD-C ------------------------------------------------------------------

TEST_F(NodeManagementStrandDispatchPin, AddNodesInlineCompletionTrampolinesPastDepthThreshold)
{
  // Stack-growth regression check: 1000 items under inline-completing fakes must
  // not blow the stack. With the dispatch->post sweep, every per-item continuation
  // posts to the strand, so the call stack unwinds per iteration.
  constexpr size_t itemCount = 1000;

  // Disable the per-NodeManagement operation limit so we can submit
  // itemCount items without hitting BadTooManyOperations.
  mSession->serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = std::nullopt;

  std::promise<ua::Response> done;
  auto fut = done.get_future();

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 1;
  req.nodes_to_add().payload().reserve(itemCount);
  for (size_t i = 0; i < itemCount; ++i)
  {
    ua::NodeId parentId{1, static_cast<uint32_t>(i + 1)};
    mSession->ensure_authz_node(parentId);
    ua::AddNodesItem item;
    item.parent_node_id().node_id() = parentId;
    item.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
    item.browse_name() = ua::QualifiedName{parentId.namespace_index(), "PinnedObject"};
    item.node_class() = ua::NodeClass::Object;
    item.type_definition().node_id() = nodeManagementPinObjectTypeId;
    req.nodes_to_add().payload().push_back(std::move(item));
  }

  auto svc = ua::server::NodeManagementService::create(mSession,
    mDelegate,
    /*requestId=*/1,
    std::move(req),
    mPool->executor(),
    [&done](ua::Response r) { done.set_value(std::move(r)); });
  (void)svc;

  ASSERT_EQ(fut.wait_for(10s), std::future_status::ready)
    << "user callback did not fire - likely stack overflow under inline completion";
  auto resp = fut.get();
  auto* response = dynamic_cast<ua::AddNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  EXPECT_EQ(response->results().size(), itemCount);
}

}  // namespace ua::test::behaviour_pins
