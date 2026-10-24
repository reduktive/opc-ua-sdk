// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5c (RegisterNodesServiceSet - Register flow).
//
// What is pinned (per runbook section 4.1):
//   RN-A - empty list returns BadNothingToDo + detail.
//   RN-B - oversized batch returns BadTooManyOperations + detail.
//   RN-C - null NodeId rejects entire request with BadNodeIdInvalid + detail.
//   RN-D - per-id handle list matches request order (single-namespace KAT).
//   RN-E - namespace without delegate echoes original IDs.
//   RN-F - batch-level delegate failure echoes originals with Status::Good.
//   RN-G - multi-namespace per-slot order preserved.
//   RN-H - user callback fires on the service strand pool thread.
//
// Pins NOT covered (and why) - see runbook section 4.1 / section 4 closing notes:
//   RN-I (timer-cancelled-on-finish) - the externally-observable signal
//     ("got success rather than timeout") is too weak to catch a regression
//     where the timer fires before the success callback under the same race;
//     a direct test would need an internal hook. Deferred.
//   RN-J (session expired) - racy across the create()/start() boundary; the
//     post to the strand may run before the test can drop the SessionInfo
//     shared_ptr. Deferred.

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "fake_register_nodes_delegate.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "ua_default_namespace.h"
#include "ua_register_nodes_service.h"
#include "ua_server.h"
#include <boost/asio/thread_pool.hpp>

#include "test_components.h"

namespace ua::test::behaviour_pins
{
namespace
{
using namespace std::chrono_literals;
using ua::test::behaviour_pins::phase_4_5c::FakeRegisterNodesNamespace;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
//
// Builds a 1-thread boost::asio::thread_pool, a real Server (so Logger/Authorizer/etc. are
// fully wired), and a SessionInfoStub. A 1-thread pool means the service's
// strand-posted work runs on exactly one OS thread - pin RN-H uses this to
// assert thread-id equality between the user callback and a fixture-posted
// observer.

class RegisterNodesPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = ua::test_utils::create_test_config(),
      .server = ua::server::ServerConfig{}};

    mServer = std::make_unique<ua::server::Server>(ua::server::Server::create(mPool->executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));

    // Capture the pool thread id so RN-H can assert the user-callback
    // thread-id equals the strand pool thread id.
    {
      std::promise<std::thread::id> p;
      boost::asio::post(*mPool, [&p]() { p.set_value(std::this_thread::get_id()); });
      mPoolThreadId = p.get_future().get();
    }
  }

  void TearDown() override
  {
    // Drop the namespace explicitly first so its worker thread (deferred mode)
    // joins before the pool stops. The pool stop must come last:
    // explicit boost::asio::thread_pool::stop() in test teardown.
    mFakeNs.reset();
    mServer.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  // Build a default_ns namespace with no register-nodes-delegate (the no-delegate
  // fast path). Adds it to the address space and returns its assigned index.
  uint16_t add_default_namespace(ua::string_view uri)
  {
    auto ns = ua::default_ns::Namespace::create(uri, mPool->executor());
    return mServer->address_space().add_namespace_sync(ns);
  }

  // Build a FakeRegisterNodesNamespace and add it to the address space.
  uint16_t add_fake_namespace(ua::string_view uri, bool deferred = false)
  {
    auto ns = FakeRegisterNodesNamespace::create(uri, mPool->executor(), deferred);
    mFakeNs = ns;
    return mServer->address_space().add_namespace_sync(ns);
  }

  // Set the OperationLimits.MaxNodesPerRegisterNodes server capability so RN-B
  // can drive the oversize-batch path. Must be called BEFORE creating the
  // service (the service reads from sessionInfo->server_configuration() at
  // start time).
  void set_max_nodes_per_register_nodes(uint32_t limit)
  {
    // The Server holds its own ServerConfig; the SessionInfoStub copies
    // it at construction. Update the underlying config so the stub picks it up.
    auto& caps = const_cast<ua::server::ServerConfig&>(mServer->config().server).server_capabilities();
    caps.operationLimits.maxNodesPerRegisterNodes = limit;
  }

  std::shared_ptr<SessionInfoStub> make_session_info()
  {
    return std::make_shared<SessionInfoStub>(std::move(*mServer), mPool->executor());
  }

  // Run a RegisterNodes request and return the response variant, blocking the
  // main thread on a future. Times out after 2 seconds.
  ua::server::RegisterNodesServiceSet::ResponseOrServiceFault run_register_request(
    std::shared_ptr<SessionInfoStub> sessionInfo, ua::RegisterNodesRequest&& request)
  {
    std::promise<ua::server::RegisterNodesServiceSet::ResponseOrServiceFault> done;
    auto svc = ua::server::RegisterNodesServiceSet::create(sessionInfo,
      std::move(request),
      mPool->executor(),
      [&done](ua::server::RegisterNodesServiceSet::ResponseOrServiceFault r)
      { done.set_value(std::move(r)); });
    (void)svc;
    auto fut = done.get_future();
    if (fut.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "RegisterNodes service did not deliver a response within 2s";
    }
    return fut.get();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<ua::server::Server> mServer;
  std::shared_ptr<FakeRegisterNodesNamespace> mFakeNs;
  std::thread::id mPoolThreadId{};
};

// Helpers to extract the variant alternatives without std::get throwing.
const ua::ServiceFault* as_fault(const ua::server::RegisterNodesServiceSet::ResponseOrServiceFault& r)
{
  return std::get_if<ua::ServiceFault>(&r);
}

const ua::RegisterNodesResponse* as_register_response(
  const ua::server::RegisterNodesServiceSet::ResponseOrServiceFault& r)
{
  return std::get_if<ua::RegisterNodesResponse>(&r);
}

}  // namespace

// ---------------------------------------------------------------------------
// RN-A - Empty list returns BadNothingToDo + detail.
// ---------------------------------------------------------------------------

// Pin name lacks "WithDetail" because ErrorDetail does not survive wire encoding
// at this layer; ResponseHeader carries StatusCode + DiagnosticInfo only, and the
// DiagnosticInfo is gated by the server's DiagnosticPolicy. Detail propagation
// is asserted at the SDK Result<T> boundary in service unit tests.
TEST_F(RegisterNodesPin, RegisterNodesEmptyListReturnsBadNothingToDo)
{
  auto sessionInfo = make_session_info();
  ua::RegisterNodesRequest request;  // empty nodes_to_register

  auto response = run_register_request(sessionInfo, std::move(request));

  const auto* fault = as_fault(response);
  ASSERT_NE(fault, nullptr) << "empty RegisterNodes must return a ServiceFault";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadNothingToDo);
}

// ---------------------------------------------------------------------------
// RN-B - Oversized batch returns BadTooManyOperations + detail.
// ---------------------------------------------------------------------------

TEST_F(RegisterNodesPin, RegisterNodesOversizedBatchReturnsBadTooManyOperations)
{
  set_max_nodes_per_register_nodes(2);
  auto sessionInfo = make_session_info();

  ua::RegisterNodesRequest request;
  request.nodes_to_register().resize(3);
  request.nodes_to_register()[0] = ua::NodeId{1, uint32_t{100}};
  request.nodes_to_register()[1] = ua::NodeId{1, uint32_t{101}};
  request.nodes_to_register()[2] = ua::NodeId{1, uint32_t{102}};

  auto response = run_register_request(sessionInfo, std::move(request));

  const auto* fault = as_fault(response);
  ASSERT_NE(fault, nullptr) << "oversize RegisterNodes must return a ServiceFault";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadTooManyOperations);
}

// ---------------------------------------------------------------------------
// RN-C - A null / empty NodeId is echoed back, NOT rejected (OPC UA Part 4 section 5.8.5).
// ---------------------------------------------------------------------------
//
// RegisterNodes "does not validate the NodeIds... Servers will simply copy unknown NodeIds in the
// response." Complete rejection with Bad_NodeIdInvalid (Table 44) is reserved for *structurally*
// invalid NodeIds (size violations / invalid identifier types) - which a decoded NodeId cannot be.
// A null NodeId (i=0) or empty-identifier NodeId is structurally valid, so the Server must echo it
// back unchanged and return a RegisterNodesResponse, not a ServiceFault. (CTT View RegisterNodes
// Err-005/006 send i=0 and b= and require ServiceResult Good.)

// Covers SVR-VIEW-REG-008 (coverage-audit retag).
TEST_F(RegisterNodesPin, RegisterNodesNullNodeIdIsEchoedBackNotRejected)
{
  auto sessionInfo = make_session_info();

  ua::RegisterNodesRequest request;
  request.nodes_to_register().resize(5);
  request.nodes_to_register()[0] = ua::NodeId{1, uint32_t{100}};
  request.nodes_to_register()[1] = ua::NodeId{1, uint32_t{101}};
  request.nodes_to_register()[2] = ua::NodeId{1, uint32_t{102}};
  request.nodes_to_register()[3] = ua::NodeId{};  // null - structurally valid, must be echoed
  request.nodes_to_register()[4] = ua::NodeId{1, uint32_t{104}};

  auto response = run_register_request(sessionInfo, std::move(request));

  const auto* ok = as_register_response(response);
  ASSERT_NE(ok, nullptr) << "a null NodeId must NOT fault the request - RegisterNodes does not validate";
  ASSERT_EQ(ok->registered_node_ids().size(), 5u) << "response size/order matches the request";
  EXPECT_EQ(ok->registered_node_ids()[3], ua::NodeId{}) << "the null NodeId is echoed back unchanged";
  EXPECT_EQ(ok->registered_node_ids()[0], (ua::NodeId{1, uint32_t{100}}));
  EXPECT_EQ(ok->registered_node_ids()[4], (ua::NodeId{1, uint32_t{104}}));
}

// ---------------------------------------------------------------------------
// RN-D - Per-id handle list matches request order (single-namespace KAT).
// ---------------------------------------------------------------------------
//
// Uses a fake delegate that returns a hardcoded BatchResult. The response
// slot[i] must equal the staged handle that corresponds to request[i].

// Covers SVR-VIEW-REG-004 (coverage-audit retag).
TEST_F(RegisterNodesPin, RegisterNodesPerIdHandleListMatchesRequestOrder)
{
  uint16_t nsIdx = add_fake_namespace("urn:test:rn-d");

  // Stage 4 mapped handles, one per input. The fake echoes them out in
  // invocation order.
  ua::BatchResult<ua::NodeId> staged;
  staged.batchStatus = ua::VoidResult{};
  staged.items = {ua::NodeId{nsIdx, uint32_t{0xA0}},
    ua::NodeId{nsIdx, uint32_t{0xA1}},
    ua::NodeId{nsIdx, uint32_t{0xA2}},
    ua::NodeId{nsIdx, uint32_t{0xA3}}};
  mFakeNs->push_register_response(std::move(staged));

  auto sessionInfo = make_session_info();
  ua::RegisterNodesRequest request;
  request.nodes_to_register().resize(4);
  request.nodes_to_register()[0] = ua::NodeId{nsIdx, ua::string_view{"n0"}};
  request.nodes_to_register()[1] = ua::NodeId{nsIdx, ua::string_view{"n1"}};
  request.nodes_to_register()[2] = ua::NodeId{nsIdx, ua::string_view{"n2"}};
  request.nodes_to_register()[3] = ua::NodeId{nsIdx, ua::string_view{"n3"}};

  auto response = run_register_request(sessionInfo, std::move(request));

  const auto* ok = as_register_response(response);
  ASSERT_NE(ok, nullptr) << "single-namespace happy-path must yield RegisterNodesResponse";
  ASSERT_EQ(ok->registered_node_ids().size(), 4u);
  EXPECT_EQ(ok->registered_node_ids()[0], (ua::NodeId{nsIdx, uint32_t{0xA0}}));
  EXPECT_EQ(ok->registered_node_ids()[1], (ua::NodeId{nsIdx, uint32_t{0xA1}}));
  EXPECT_EQ(ok->registered_node_ids()[2], (ua::NodeId{nsIdx, uint32_t{0xA2}}));
  EXPECT_EQ(ok->registered_node_ids()[3], (ua::NodeId{nsIdx, uint32_t{0xA3}}));
}

// ---------------------------------------------------------------------------
// RN-E - Namespace without delegate echoes original IDs.
// ---------------------------------------------------------------------------

TEST_F(RegisterNodesPin, RegisterNodesNoDelegateNamespaceEchoesOriginalIds)
{
  uint16_t nsIdx = add_default_namespace("urn:test:rn-e");
  auto sessionInfo = make_session_info();

  const ua::NodeId n0{nsIdx, ua::string_view{"a"}};
  const ua::NodeId n1{nsIdx, ua::string_view{"b"}};
  const ua::NodeId n2{nsIdx, ua::string_view{"c"}};

  ua::RegisterNodesRequest request;
  request.nodes_to_register().resize(3);
  request.nodes_to_register()[0] = n0;
  request.nodes_to_register()[1] = n1;
  request.nodes_to_register()[2] = n2;

  auto response = run_register_request(sessionInfo, std::move(request));

  const auto* ok = as_register_response(response);
  ASSERT_NE(ok, nullptr) << "no-delegate namespace must yield RegisterNodesResponse";
  ASSERT_EQ(ok->registered_node_ids().size(), 3u);
  EXPECT_EQ(ok->registered_node_ids()[0], n0);
  EXPECT_EQ(ok->registered_node_ids()[1], n1);
  EXPECT_EQ(ok->registered_node_ids()[2], n2);
}

// ---------------------------------------------------------------------------
// RN-F - Batch-level delegate failure echoes originals with Status::Good.
// ---------------------------------------------------------------------------
//
// When the delegate's BatchResult.batchStatus is bad, the service does NOT
// propagate that status to the user - instead it echoes the request NodeIds
// at the matching slots and returns Status::Good. This is the spec-mandated
// best-effort skip-and-echo behaviour (no DiagnosticInfo array on the wire
// for RegisterNodes per spec).

TEST_F(RegisterNodesPin, RegisterNodesBatchFailureFallsBackToOriginalIdsWithStatusGood)
{
  uint16_t nsIdx = add_fake_namespace("urn:test:rn-f");

  ua::BatchResult<ua::NodeId> staged;
  staged.batchStatus = ua::VoidResult{ua::StatusCode{ua::Status::BadInternalError},
    ua::make_error_detail("FakeBatchFailure", "synthetic batch failure", "FakeRegisterNodesNamespace")};
  // items intentionally empty - spec-mandated batch-failure semantics.
  mFakeNs->push_register_response(std::move(staged));

  auto sessionInfo = make_session_info();
  const ua::NodeId n0{nsIdx, ua::string_view{"x"}};
  const ua::NodeId n1{nsIdx, ua::string_view{"y"}};
  const ua::NodeId n2{nsIdx, ua::string_view{"z"}};

  ua::RegisterNodesRequest request;
  request.nodes_to_register().resize(3);
  request.nodes_to_register()[0] = n0;
  request.nodes_to_register()[1] = n1;
  request.nodes_to_register()[2] = n2;

  auto response = run_register_request(sessionInfo, std::move(request));

  const auto* ok = as_register_response(response);
  ASSERT_NE(ok, nullptr) << "batch-failure must NOT propagate to a ServiceFault - service still returns OK";
  EXPECT_TRUE(ok->response_header().service_result().is_good());
  ASSERT_EQ(ok->registered_node_ids().size(), 3u);
  EXPECT_EQ(ok->registered_node_ids()[0], n0) << "slot 0 must echo original";
  EXPECT_EQ(ok->registered_node_ids()[1], n1) << "slot 1 must echo original";
  EXPECT_EQ(ok->registered_node_ids()[2], n2) << "slot 2 must echo original";
}

// ---------------------------------------------------------------------------
// RN-G - Multi-namespace per-slot order preserved.
// ---------------------------------------------------------------------------
//
// Locks the spec's order-correspondence rule across two namespaces. Per-slot
// writes must land at the response index matching the original request index,
// not at a sequential index assigned by namespace ordering.

TEST_F(RegisterNodesPin, RegisterNodesAcrossTwoNamespacesPreservesPerSlotOrder)
{
  // Namespace 1 (single-instance fake stored in mFakeNs).
  uint16_t ns1 = add_fake_namespace("urn:test:rn-g-ns1", /*deferred=*/false);
  auto fakeNs1 = mFakeNs;

  // Namespace 2 (separate fake - keep alive in this test scope and add to AS).
  auto fakeNs2 = FakeRegisterNodesNamespace::create("urn:test:rn-g-ns2", mPool->executor(), false);
  uint16_t ns2 = mServer->address_space().add_namespace_sync(fakeNs2);

  // Stage per-namespace batches. NS1 gets handles for indices [0, 2]; NS2
  // gets handles for indices [1, 3]. The service's iteration order over
  // operationGroups is not deterministic (unordered_map), but the per-slot
  // write target is the original request index - so the response must be
  // [NS1@0xA0, NS2@0xB1, NS1@0xA2, NS2@0xB3] regardless of iteration order.
  ua::BatchResult<ua::NodeId> ns1Batch;
  ns1Batch.batchStatus = ua::VoidResult{};
  ns1Batch.items = {ua::NodeId{ns1, uint32_t{0xA0}}, ua::NodeId{ns1, uint32_t{0xA2}}};
  fakeNs1->push_register_response(std::move(ns1Batch));

  ua::BatchResult<ua::NodeId> ns2Batch;
  ns2Batch.batchStatus = ua::VoidResult{};
  ns2Batch.items = {ua::NodeId{ns2, uint32_t{0xB1}}, ua::NodeId{ns2, uint32_t{0xB3}}};
  fakeNs2->push_register_response(std::move(ns2Batch));

  auto sessionInfo = make_session_info();
  ua::RegisterNodesRequest request;
  request.nodes_to_register().resize(4);
  request.nodes_to_register()[0] = ua::NodeId{ns1, ua::string_view{"a"}};
  request.nodes_to_register()[1] = ua::NodeId{ns2, ua::string_view{"b"}};
  request.nodes_to_register()[2] = ua::NodeId{ns1, ua::string_view{"c"}};
  request.nodes_to_register()[3] = ua::NodeId{ns2, ua::string_view{"d"}};

  auto response = run_register_request(sessionInfo, std::move(request));

  const auto* ok = as_register_response(response);
  ASSERT_NE(ok, nullptr);
  ASSERT_EQ(ok->registered_node_ids().size(), 4u);
  EXPECT_EQ(ok->registered_node_ids()[0], (ua::NodeId{ns1, uint32_t{0xA0}}));
  EXPECT_EQ(ok->registered_node_ids()[1], (ua::NodeId{ns2, uint32_t{0xB1}}));
  EXPECT_EQ(ok->registered_node_ids()[2], (ua::NodeId{ns1, uint32_t{0xA2}}));
  EXPECT_EQ(ok->registered_node_ids()[3], (ua::NodeId{ns2, uint32_t{0xB3}}));

  // Worker thread join: fakeNs2 owns no worker (inline mode). Drop it before
  // pool stops to keep teardown clean.
  fakeNs2.reset();
}

// ---------------------------------------------------------------------------
// RN-H - User callback fires on the service strand pool thread.
// ---------------------------------------------------------------------------

TEST_F(RegisterNodesPin, RegisterNodesUserCallbackFiresOnServiceStrand)
{
  uint16_t nsIdx = add_default_namespace("urn:test:rn-h");
  auto sessionInfo = make_session_info();

  ua::RegisterNodesRequest request;
  request.nodes_to_register().resize(1);
  request.nodes_to_register()[0] = ua::NodeId{nsIdx, ua::string_view{"only"}};

  std::promise<std::thread::id> callbackThread;
  auto svc = ua::server::RegisterNodesServiceSet::create(sessionInfo,
    std::move(request),
    mPool->executor(),
    [&callbackThread](ua::server::RegisterNodesServiceSet::ResponseOrServiceFault)
    { callbackThread.set_value(std::this_thread::get_id()); });
  (void)svc;

  auto fut = callbackThread.get_future();
  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
  const auto observedId = fut.get();

  // 1-thread pool: every strand-posted task runs on the single pool thread.
  EXPECT_EQ(observedId, mPoolThreadId) << "user callback fired on a thread other than the strand pool thread";
  EXPECT_NE(observedId, std::this_thread::get_id())
    << "user callback fired on the test main thread - strand was bypassed";
}

}  // namespace ua::test::behaviour_pins
