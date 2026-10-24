// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5i (NodeManagementService - AddNodes flow).
//
// These pins lock the externally-observable behaviour of the AddNodes flow
// of NodeManagementService. The flow is callback-canonical at its public
// surface (ServiceCallComplete) but coroutine-canonical internally
// (process_add_nodes - 4 lexical co_awaits). 4.5i{b} will restructure the
// internal co_awaits into named per-flow continuations; the pins here freeze
// the externally-observable contract that survives that restructure.
//
// Pins authored (per runbook section 4.1):
//   AN-A  AddNodesEmptyRequestReturnsBadNothingToDo
//   AN-B  AddNodesOverLimitReturnsBadTooManyOperations
//   AN-D  AddNodesPerItemAuthorizationDenyMarksOnlyDeniedSlot
//   AN-E  AddNodesPerItemAuthorizationUsesDestinationNamespaceScope
//   AN-G  AddNodesBatchStatusReplicatesAcrossAuthorizedIndices
//   AN-H  AddNodesBatchStatusDoesNotOverwriteUnauthorizedSlots
//   AN-I  AddNodesPerItemBadResultMergedIntoCorrectSlot
//   AN-J  AddNodesPropagatesBadReferenceTypeIdInvalid
//   AN-N  AddNodesUserCallbackFiresOnSinglePoolThread (threading affinity
//         under a single-thread pool - proxy for strand affinity since
//         boost::asio::strand<boost::asio::any_io_executor> offers no public running_in_this_thread()
//         accessor)
//
// Pins flagged but NOT authored (infra gaps - see PR summary):
//   AN-C  null-authorizer fail-closed: SessionSecurityContext interface
//         contract requires authorizer() to be non-null in the pre-flip
//         body's `sec && sec->authorizer()` branch - emulating null requires
//         a session-context fake whose pointer is non-null but returns null;
//         our fixture's authorizer() returns the std::shared_ptr we own, so
//         testing this branch requires a separate mode.
//   AN-F  authorizer-timeout: requires a deferred FakeAuthorizer (parked-
//         callback queue + dedicated worker thread) to never fire the
//         callback. tests/helpers/FakeAuthorizer fires inline only.
//   AN-K/L/M  audit-event emission: emit_node_mgmt_audit() static_casts
//         EventSink to EventBus and gates on has_event_interest(). A real
//         EventBus listener is required; SessionInfo::event_sink() returns
//         nullptr in our fixture, so the audit-event branch is dormant.
//   AN-O  diagnostic-collector per-item details: requires accessing the
//         response's DiagnosticInfos and matching them to per-failure
//         indices - the response Array<DiagnosticInfo> shape needs a
//         dedicated decode helper.
//   AN-P  cancellation-flag pointer-identity: requires reading
//         service->mCancelled (private). Out of pin-test scope without
//         a TestAccess friend, which is a production-source change.
//   AN-Q  arity-mismatch documents-current-behaviour: deliberately not
//         frozen - pins assert spec-required behaviour; AN-Q is a
//         flagged defect to fix in 4.5i{b}, not pin.
//   AN-R  audit suppression when disabled: same EventBus dependency as
//         AN-K.

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <unordered_set>
#include <vector>

#include <gtest/gtest.h>

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_nodes_result.h"
#include "ua_node_management_service.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_node_management_delegate.h"
#include "node_management_pin_fixture.h"

using namespace std::chrono_literals;

namespace ua::test::behaviour_pins
{
namespace
{

// --- Fixture ---------------------------------------------------------------

class AddNodesPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Single-thread pool: lets us assert "user callback fires on the same
    // thread that ran the strand-posted process_request()" deterministically.
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mSession = std::make_shared<NodeManagementPinSessionInfo>(mPool->executor());
    mDelegate = std::make_shared<FakeNodeManagementDelegate>();
  }

  void TearDown() override
  {
    if (mPool)
      mPool->stop();
  }

  // Drive the service and wait (on the main test thread only) for the
  // ServiceCallComplete callback. Returns the Response.
  ua::Response invoke(ua::AddNodesRequest&& request)
  {
    // The fixture materialises parents needed by the post-authorization model validation.
    for (const auto& item : request.nodes_to_add().payload())
    {
      mSession->ensure_authz_node(item.parent_node_id().node_id());
    }
    std::promise<ua::Response> p;
    auto fut = p.get_future();
    auto svc = ua::server::NodeManagementService::create(mSession,
      mDelegate,
      /*requestId=*/1,
      std::move(request),
      mPool->executor(),
      [&p](ua::Response r) { p.set_value(std::move(r)); });
    (void)svc;
    EXPECT_EQ(fut.wait_for(5s), std::future_status::ready) << "ServiceCallComplete did not fire within 5s";
    return fut.get();
  }

  ua::AddNodesItem make_item(
    const ua::NodeId& parent, std::optional<uint16_t> requestedNamespace = std::nullopt)
  {
    ua::AddNodesItem item;
    item.parent_node_id().node_id() = parent;
    uint16_t destinationNamespace = requestedNamespace.value_or(parent.namespace_index());
    if (destinationNamespace == 0)
      destinationNamespace = 1;
    item.requested_new_node_id().node_id() = ua::NodeId{destinationNamespace, mNextRequestedNodeIdentifier++};
    item.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
    item.browse_name() = ua::QualifiedName{parent.namespace_index(), "PinnedObject"};
    item.node_class() = ua::NodeClass::Object;
    item.type_definition().node_id() = nodeManagementPinObjectTypeId;
    return item;
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<NodeManagementPinSessionInfo> mSession;
  std::shared_ptr<FakeNodeManagementDelegate> mDelegate;
  uint32_t mNextRequestedNodeIdentifier{70000u};
};

}  // namespace

// --- AN-A ------------------------------------------------------------------

TEST_F(AddNodesPin, AddNodesEmptyRequestReturnsBadNothingToDo)
{
  ua::AddNodesRequest req;
  req.request_header().request_handle() = 1;

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for empty request";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadNothingToDo);
}

// --- AN-B ------------------------------------------------------------------

TEST_F(AddNodesPin, AddNodesOverLimitReturnsBadTooManyOperations)
{
  // Configure server limit = 1; submit 2 items.
  mSession->serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = 1;

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 2;
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

  auto resp = invoke(std::move(req));
  auto* fault = dynamic_cast<ua::ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for over-limit request";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadTooManyOperations);
}

// --- AN-D ------------------------------------------------------------------

// @relation(SVR-NM-AN-030, scope=function)
TEST_F(AddNodesPin, AddNodesPerItemAuthorizationDenyMarksOnlyDeniedSlot)
{
  // Mixed-batch stimulus: items 0,2 allowed; item 1 denied. The denied slot
  // must carry BadUserAccessDenied; the allowed slots carry the delegate's
  // (default Good) result. A regression that re-indexed by authorised
  // position would FAIL.
  const ua::NodeId allow0{1, 100u};
  const ua::NodeId deny1{2, 200u};
  const ua::NodeId allow2{3, 300u};

  mSession->ensure_authz_namespace(deny1.namespace_index(), ua::PermissionType{});
  mSession->ensure_authz_node(deny1);

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 3;
  req.nodes_to_add().payload().push_back(make_item(allow0));
  req.nodes_to_add().payload().push_back(make_item(deny1));
  req.nodes_to_add().payload().push_back(make_item(allow2));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);

  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(response->results()[1].status_code(), ua::Status::BadUserAccessDenied);
  EXPECT_TRUE(response->results()[2].status_code().is_good());
}

// --- AN-E ------------------------------------------------------------------

// @relation(AC-SVR-AUTHZ-003-DESTINATION-DECIDES, scope=function)
TEST_F(AddNodesPin, AddNodesPerItemAuthorizationUsesDestinationNamespaceScope)
{
  // The two parents live in differently-governed Namespaces, while both requested
  // NodeIds name one destination Namespace that grants AddNode. Moving only the
  // parent therefore cannot change the decision.
  const ua::NodeId firstParent{2, 1u};
  const ua::NodeId secondParent{3, 1u};
  constexpr uint16_t destinationNamespace = 4;
  mSession->ensure_authz_namespace(firstParent.namespace_index(), ua::PermissionType{});
  mSession->ensure_authz_namespace(secondParent.namespace_index(), ua::PermissionType{});
  mSession->ensure_authz_namespace(
    destinationNamespace, ua::PermissionType{ua::PermissionType::Bit::AddNode});
  for (const auto& parent : {firstParent, secondParent})
  {
    mSession->ensure_authz_node(parent);
    mSession->set_node_permissions(parent, ua::PermissionType{});
  }
  mSession->set_node_permissions(nodeManagementPinObjectTypeId, ua::PermissionType{});

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 4;
  req.nodes_to_add().payload().push_back(make_item(firstParent, destinationNamespace));
  req.nodes_to_add().payload().push_back(make_item(secondParent, destinationNamespace));

  auto result = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddNodesResponse*>(result.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  for (const auto& item : response->results())
    EXPECT_TRUE(item.status_code().is_good());
}

// @relation(AC-SVR-AUTHZ-003-DESTINATION-DECIDES, scope=function)
TEST_F(AddNodesPin, DestinationNamespaceDenialCannotBeBypassedThroughAnotherParentNamespace)
{
  // Build a fresh security snapshot whose destination Namespace denies AddNode, then give only a
  // separate parent Namespace that bit. The parent grant must not leak across the boundary.
  mSession = std::make_shared<NodeManagementPinSessionInfo>(mPool->executor(), ua::PermissionType{});
  const ua::NodeId parent{2, 1u};
  mSession->ensure_authz_namespace(
    parent.namespace_index(), ua::PermissionType{ua::PermissionType::Bit::AddNode});
  mSession->ensure_authz_node(parent);

  ua::AddNodesRequest request;
  request.request_header().request_handle() = 5;
  request.nodes_to_add().payload().push_back(make_item(parent, uint16_t{1}));

  auto result = invoke(std::move(request));
  auto* response = dynamic_cast<ua::AddNodesResponse*>(result.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), ua::Status::BadUserAccessDenied);
  EXPECT_EQ(mDelegate->addNodesCalls, 0u);
}

// --- AN-G ------------------------------------------------------------------

TEST_F(AddNodesPin, AddNodesBatchStatusReplicatesAcrossAuthorizedIndices)
{
  // All 3 items authorised; delegate returns batchStatus=BadOutOfMemory with
  // a known ErrorDetail pointer. Every input slot must carry the batch
  // status (and - once a DiagnosticInfo decode helper exists for AN-O -
  // the same shared_detail pointer). Asserts batch-failure replication.
  auto detail = ua::make_error_detail("BatchOOM", "delegate batch OOM", "FakeDelegate");
  std::shared_ptr<const ua::ErrorDetail> sharedDetail{std::move(detail)};

  mDelegate->addNodesFactory = [sharedDetail](const std::vector<ua::AddNodesItem>&)
  {
    ua::BatchResult<FakeNodeManagementDelegate::AddNodesItemResult> batch;
    batch.batchStatus = ua::VoidResult{ua::Status::BadOutOfMemory, sharedDetail};
    return batch;
  };

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 5;
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{1, 10u}));
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{1, 20u}));
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{1, 30u}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_EQ(response->results()[0].status_code(), ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[1].status_code(), ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[2].status_code(), ua::Status::BadOutOfMemory);
}

// --- AN-H ------------------------------------------------------------------

TEST_F(AddNodesPin, AddNodesBatchStatusDoesNotOverwriteUnauthorizedSlots)
{
  // Item 1 is denied; items 0,2 authorised. Delegate returns batch=BadOutOfMemory.
  // Slot 1 must remain BadUserAccessDenied (NOT BadOutOfMemory). Locks that
  // batch-status replication iterates over authorisedIndices only.
  const ua::NodeId allow0{3, 1u};
  const ua::NodeId deny1{4, 2u};
  const ua::NodeId allow2{5, 3u};

  mSession->ensure_authz_namespace(deny1.namespace_index(), ua::PermissionType{});
  mSession->ensure_authz_node(deny1);

  mDelegate->addNodesFactory = [](const std::vector<ua::AddNodesItem>&)
  {
    ua::BatchResult<FakeNodeManagementDelegate::AddNodesItemResult> batch;
    batch.batchStatus = ua::VoidResult{ua::Status::BadOutOfMemory};
    return batch;
  };

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 6;
  req.nodes_to_add().payload().push_back(make_item(allow0));
  req.nodes_to_add().payload().push_back(make_item(deny1));
  req.nodes_to_add().payload().push_back(make_item(allow2));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_EQ(response->results()[0].status_code(), ua::Status::BadOutOfMemory);
  EXPECT_EQ(response->results()[1].status_code(), ua::Status::BadUserAccessDenied);
  EXPECT_EQ(response->results()[2].status_code(), ua::Status::BadOutOfMemory);
}

// --- AN-I ------------------------------------------------------------------

// @relation(SVR-NM-AN-020, SVR-NM-AN-024, scope=function)
TEST_F(AddNodesPin, AddNodesPerItemBadResultMergedIntoCorrectSlot)
{
  // 3-item all-authorised; delegate returns mixed per-item: index 0 Good,
  // index 1 BadNodeIdExists+detail, index 2 BadParentNodeIdInvalid+detail.
  // Slots 1 and 2 must carry the bad statuses with non-null shared_detail.
  // Slot 0 must carry the delegate's good result. Locks per-item merge +
  // ErrorDetail propagation.
  auto detail1 = ua::make_error_detail("NodeExists", "node id collision", "FakeDelegate");
  std::shared_ptr<const ua::ErrorDetail> sharedDetail1{std::move(detail1)};
  auto detail2 = ua::make_error_detail("BadParent", "parent invalid", "FakeDelegate");
  std::shared_ptr<const ua::ErrorDetail> sharedDetail2{std::move(detail2)};

  ua::NodeId addedSlot0;
  mDelegate->addNodesFactory = [&](const std::vector<ua::AddNodesItem>& items)
  {
    ua::BatchResult<FakeNodeManagementDelegate::AddNodesItemResult> batch;
    ua::AddNodesResult good;
    good.status_code() = ua::Status::Good;
    addedSlot0 = items.front().requested_new_node_id().node_id();
    good.added_node_id() = addedSlot0;
    batch.items.emplace_back(std::move(good));
    batch.items.emplace_back(
      FakeNodeManagementDelegate::AddNodesItemResult{ua::Status::BadNodeIdExists, sharedDetail1});
    batch.items.emplace_back(
      FakeNodeManagementDelegate::AddNodesItemResult{ua::Status::BadParentNodeIdInvalid, sharedDetail2});
    return batch;
  };

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 7;
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{4, 1u}));
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{4, 2u}));
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{4, 3u}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);

  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(response->results()[0].added_node_id(), addedSlot0);
  EXPECT_EQ(response->results()[1].status_code(), ua::Status::BadNodeIdExists);
  EXPECT_EQ(response->results()[2].status_code(), ua::Status::BadParentNodeIdInvalid);
}

// --- AN-J ------------------------------------------------------------------

// Covers SVR-NM-AN-022 (coverage-audit retag).
// @relation(SVR-NM-AN-021, scope=function)
TEST_F(AddNodesPin, AddNodesPropagatesBadReferenceTypeIdInvalid)
{
  mDelegate->addNodesFactory = [](const std::vector<ua::AddNodesItem>&)
  {
    ua::BatchResult<FakeNodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.emplace_back(
      FakeNodeManagementDelegate::AddNodesItemResult{ua::Status::BadReferenceTypeIdInvalid,
        std::shared_ptr<const ua::ErrorDetail>{
          ua::make_error_detail("BadRefType", "invalid reference type", "FakeDelegate")}});
    return batch;
  };

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 8;
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

  auto resp = invoke(std::move(req));
  auto* response = dynamic_cast<ua::AddNodesResponse*>(resp.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  EXPECT_EQ(response->results()[0].status_code(), ua::Status::BadReferenceTypeIdInvalid);
}

// --- AN-N (threading affinity proxy) ---------------------------------------

TEST_F(AddNodesPin, AddNodesUserCallbackFiresOnSinglePoolThread)
{
  // Single-thread pool: the strand must serialise all work on the same
  // pool thread. The pin asserts the user callback's thread id equals the
  // delegate-invocation thread id (both must be the single pool thread).
  // This is a proxy for true strand-affinity (boost::asio::strand<boost::asio::any_io_executor> offers no
  // public running_in_this_thread()); a regression that detached the user callback to a different thread
  // would FAIL.
  std::promise<std::thread::id> userCallbackThread;
  auto fut = userCallbackThread.get_future();

  mSession->ensure_authz_node(ua::NodeId{ua::ObjectId::ObjectsFolder});

  ua::AddNodesRequest req;
  req.request_header().request_handle() = 9;
  req.nodes_to_add().payload().push_back(make_item(ua::NodeId{ua::ObjectId::ObjectsFolder}));

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
  EXPECT_NE(delegateThread, std::thread::id{}) << "delegate was never invoked";
  EXPECT_EQ(callbackThread, delegateThread)
    << "user callback fired on a different thread than the delegate - strand affinity broken";
}

}  // namespace ua::test::behaviour_pins
