// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5f - MethodServiceSet (Call flow).
//
//
// Coverage (compact corpus targeting top-level service-level properties - the
// pins that lock the entry-point pipeline without standing up real method-node
// infrastructure):
//
//   MS-F  CallReturnsBadNothingToDoForEmptyRequest
//   MS-G  CallReturnsBadTooManyOperationsBeyondMaxNodesPerMethodCall
//   MS-K  CallCompletionCallbackFiresOnServiceStrand
//   DISABLED_CallDestructorDuringFlightFiresShutdownCallback   (D1, expected-fail
//     until matching {b} flip restructures lifetime to weak_from_this with
//     explicit destructor BadShutdown emission)
//   DISABLED_CallCancelDuringInFlightFiresBadRequestCancelledByClient   (CT-A,
//     expected-fail until matching {b} flip ships the deferred-collaborator
//     fakes from runbook section 4.0.1 - the fakes required to deterministically
//     suspend the per-item flow are sub-phase-local infrastructure that the
//     {b} flip authors)
//
// Scope notes:
//   * Pin coverage of the per-item path (MS-A success KAT, MS-B/D method
//     hierarchy walk, VO-A..G, PMF-A..G, SD-A..D) is deferred - those pins
//     require a FakeAsyncMethodDelegate / FakeAsyncAuthorizer pair (runbook
//     section 4.0.1) plus configurable method-node fixtures. The matching {b} flip
//     authors that infrastructure in lockstep with the production restructure;
//     these top-level service-level pins are the {a} corpus baseline.
//   * Per-method failure isolation (PMF-A through PMF-G) is partly covered by
//     the existing tests/unit/server/services/method_service_delegate_tests.cpp
//     suite. The runbook section 4.5 cross-references this; pin authoring would
//     duplicate without adding signal until the section 4.0.1 fakes ship.

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_diagnostic_bits.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_method_service_set.h"
#include "ua_namespace_array.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_namespace.h"
#include "stubs.h"
#include "test_utilities.h"

#include "test_components.h"

namespace ua::test::behaviour_pins::method
{
namespace
{

using namespace std::chrono_literals;

// SessionInfoStub uses MessageSecurityMode::None which gates the
// DiagnosticCollector to mReturnDiagnostics=0. Override to surface details.
class PermissiveDiagsSessionInfo : public SessionInfoStub
{
public:
  using SessionInfoStub::SessionInfoStub;

  ::ua::server::DiagnosticSecurityContext diagnostic_security_context() const override
  {
    ::ua::server::DiagnosticSecurityContext ctx;
    ctx.authenticated = true;
    ctx.securedChannel = true;
    ctx.effectiveLevel = ::ua::server::ServerConfig::DiagnosticPolicy::Level::Full;
    ctx.maskPreAuthErrors = false;
    return ctx;
  }
};

class MethodServicePin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<::boost::asio::thread_pool>(/*noOfThreads=*/1);
    {
      std::promise<std::thread::id> p;
      boost::asio::post(*mPool, [&p]() { p.set_value(std::this_thread::get_id()); });
      mPoolThreadId = p.get_future().get();
    }

    ::ua::server::CreateConfig cfg{.identity = ::ua::ApplicationIdentity::load_default(),
      .application = ::ua::test_utils::create_test_config(),
      .server = mServerCfg};
    mServer.emplace(::ua::server::Server::create(mPool->executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));
  }

  void TearDown() override
  {
    mSession.reset();
    mServer.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  void build_session()
  {
    mSession = std::make_shared<PermissiveDiagsSessionInfo>(std::move(*mServer), mPool->executor());
    mServer.reset();
  }

  ::ua::Response run_call(::ua::CallRequest&& req)
  {
    std::promise<::ua::Response> p;
    auto fut = p.get_future();
    mService = ::ua::server::MethodServiceSet::create(mSession,
      /*sessionLocales=*/{},
      /*requestId=*/0,
      std::move(req),
      mPool->executor(),
      [&p](::ua::Response r) { p.set_value(std::move(r)); });
    if (fut.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "Call callback did not fire within 2s";
      return {};
    }
    return fut.get();
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::thread::id mPoolThreadId;
  ::ua::server::ServerConfig mServerCfg;
  std::optional<::ua::server::Server> mServer;
  std::shared_ptr<PermissiveDiagsSessionInfo> mSession;
  std::shared_ptr<::ua::server::MethodServiceSet> mService;
};

// ---------------------------------------------------------------------------
// MS-F - Empty methods_to_call yields ServiceFault.BadNothingToDo with a
//        non-null service detail (set_service_detail at :491). Falsifiable bug:
//        a {b} flip that drops the empty-list check at ua_method_service_set.cpp:396-400.
// ---------------------------------------------------------------------------
TEST_F(MethodServicePin, CallReturnsBadNothingToDoForEmptyRequest)
{
  build_session();

  ::ua::CallRequest req;
  req.request_header().return_diagnostics() =
    ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;
  // methods_to_call() left empty.

  auto response = run_call(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for empty methods_to_call";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadNothingToDo);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value())
    << "service-level detail must be propagated";
}

// ---------------------------------------------------------------------------
// MS-G - Over-limit methods_to_call yields ServiceFault.BadTooManyOperations.
//        Falsifiable bug: a {b} flip that drops the operation-limits check at
//        ua_method_service_set.cpp:402-411.
// ---------------------------------------------------------------------------
TEST_F(MethodServicePin, CallReturnsBadTooManyOperationsBeyondMaxNodesPerMethodCall)
{
  // Configure server with limit=1; submit 2 methods.
  mServerCfg.server_capabilities().operationLimits.maxNodesPerMethodCall = 1;
  mServer.reset();
  ::ua::server::CreateConfig cfg{.identity = ::ua::ApplicationIdentity::load_default(),
    .application = ::ua::test_utils::create_test_config(),
    .server = mServerCfg};
  mServer.emplace(::ua::server::Server::create(mPool->executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));
  build_session();

  ::ua::CallRequest req;
  req.request_header().return_diagnostics() =
    ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;
  req.methods_to_call().resize(2);
  req.methods_to_call()[0].method_id() = ::ua::NodeId{0u, 0u};
  req.methods_to_call()[0].object_id() = ::ua::NodeId{0u, 0u};
  req.methods_to_call()[1].method_id() = ::ua::NodeId{0u, 1u};
  req.methods_to_call()[1].object_id() = ::ua::NodeId{0u, 1u};

  auto response = run_call(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for over-limit methods_to_call";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadTooManyOperations);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value())
    << "service-level detail must propagate the TooManyMethodsToCall code";
}

// ---------------------------------------------------------------------------
// MS-K - Completion callback fires on the service strand pool thread (1-thread
//        pool means the strand worker IS the only pool worker). Falsifiable
//        bug: a {b} flip that fires the callback inline on the cancel/timeout
//        path or on a different executor.
// ---------------------------------------------------------------------------
TEST_F(MethodServicePin, CallCompletionCallbackFiresOnServiceStrand)
{
  build_session();

  std::promise<std::thread::id> p;
  auto fut = p.get_future();
  ::ua::CallRequest req;
  // Empty methods_to_call drives the synchronous BadNothingToDo path; we don't
  // care about the response here, only the thread the callback fires on.
  mService = ::ua::server::MethodServiceSet::create(mSession,
    /*sessionLocales=*/{},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response) { p.set_value(std::this_thread::get_id()); });

  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
  auto cbThread = fut.get();
  EXPECT_EQ(cbThread, mPoolThreadId) << "completion callback fires on the service strand pool thread";
  EXPECT_NE(cbThread, std::this_thread::get_id())
    << "completion callback must not fire on the test main thread";
}

// ---------------------------------------------------------------------------
// D1 - Destructor-during-flight fires the user callback with BadShutdown.
//
// Authored against the {b} flip's restructured lifetime: weak_from_this everywhere,
// per-flow structs allocated on the strand, ~MethodServiceSet gated by try_finish().
// The test parks the find_node await for the method node
// on a FakeNamespace at index 2, waits for parked count > 0, then drops the
// service's last shared_ptr. The destructor observes the per-op flow is still in
// flight, calls try_finish() (returns true), and fires Status::BadShutdown.
// ---------------------------------------------------------------------------
TEST_F(MethodServicePin, CallDestructorDuringFlightFiresShutdownCallback)
{
  auto fakeNs = ::ua::test_helpers::FakeNamespace::create("urn:test:method-fake-ns");
  fakeNs->decline_create_nodes_as_unsupported();
  ASSERT_TRUE(mServer.has_value());
  const uint16_t fakeIdx = mServer->address_space().add_namespace_sync(fakeNs);
  build_session();

  std::promise<::ua::StatusCode> p;
  auto fut = p.get_future();

  ::ua::CallRequest req;
  req.request_header().return_diagnostics() =
    ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;
  req.methods_to_call().resize(1);
  req.methods_to_call()[0].method_id() = ::ua::NodeId{fakeIdx, 1u};
  req.methods_to_call()[0].object_id() = ::ua::NodeId{fakeIdx, 2u};

  mService = ::ua::server::MethodServiceSet::create(mSession,
    /*sessionLocales=*/{},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response r)
    {
      ::ua::StatusCode sc{::ua::Status::Good};
      if (auto* fault = dynamic_cast<::ua::ServiceFault*>(r.second.get()))
        sc = fault->response_header().service_result();
      p.set_value(sc);
    });

  for (int i = 0; i < 200 && fakeNs->pending_find_node_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_GE(fakeNs->pending_find_node_count(), 1u)
    << "expected find_node_async to be parked before destruction";

  mService.reset();

  ASSERT_EQ(fut.wait_for(500ms), std::future_status::ready)
    << "destructor must drive the user callback with BadShutdown";
  EXPECT_EQ(fut.get(), ::ua::Status::BadShutdown);
}

// ---------------------------------------------------------------------------
// CT-A - cancel() during in-flight Call fires BadRequestCancelledByClient.
//
// Parks find_node_async on the FakeNamespace, then invokes service->cancel().
// The service's strand-posted cancel handler calls send_service_fault which
// gates on try_finish() (returns true since no completion point ran), so the user
// callback fires with BadRequestCancelledByClient.
// ---------------------------------------------------------------------------
TEST_F(MethodServicePin, CallCancelDuringInFlightFiresBadRequestCancelledByClient)
{
  auto fakeNs = ::ua::test_helpers::FakeNamespace::create("urn:test:method-cancel-fake-ns");
  fakeNs->decline_create_nodes_as_unsupported();
  ASSERT_TRUE(mServer.has_value());
  const uint16_t fakeIdx = mServer->address_space().add_namespace_sync(fakeNs);
  build_session();

  std::promise<::ua::StatusCode> p;
  auto fut = p.get_future();

  ::ua::CallRequest req;
  req.request_header().return_diagnostics() =
    ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;
  req.methods_to_call().resize(1);
  req.methods_to_call()[0].method_id() = ::ua::NodeId{fakeIdx, 1u};
  req.methods_to_call()[0].object_id() = ::ua::NodeId{fakeIdx, 2u};

  mService = ::ua::server::MethodServiceSet::create(mSession,
    /*sessionLocales=*/{},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response r)
    {
      ::ua::StatusCode sc{::ua::Status::Good};
      if (auto* fault = dynamic_cast<::ua::ServiceFault*>(r.second.get()))
        sc = fault->response_header().service_result();
      p.set_value(sc);
    });

  for (int i = 0; i < 200 && fakeNs->pending_find_node_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_GE(fakeNs->pending_find_node_count(), 1u);

  mService->cancel();

  ASSERT_EQ(fut.wait_for(500ms), std::future_status::ready);
  EXPECT_EQ(fut.get(), ::ua::Status::BadRequestCancelledByClient);
}

}  // namespace
}  // namespace ua::test::behaviour_pins::method
