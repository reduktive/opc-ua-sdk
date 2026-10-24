// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5h - TranslateBrowsePathsService.
//
//
// Coverage (compact corpus targeting top-level synchronous service-level
// gates of the TranslateBrowsePaths pipeline; per-item walk pins (TBP-A..H)
// and strand-dispatch pins (TBP-I) deferred - those require a FakeAsyncNamespace
// per runbook section 4.0.1 that the matching {b} flip authors):
//
//   TBP-J  TranslateBrowsePathsRejectsEmptyBrowsePathsWithBadNothingToDo
//   TBP-K  TranslateBrowsePathsRejectsExceedingLimitWithBadTooManyOperations
//   TBP-AFF TranslateBrowsePathsUserCallbackFiresOnServiceStrand
//   DISABLED_TranslateBrowsePathsDestructorDuringFlightFiresShutdownCallback (D1)
//
// TBP-L (200-deep path stack-protection) deferred - exercising it requires
// the FakeAsyncNamespace to suspend each per-element await deterministically.
// The {b} flip authors that fixture; the {a} corpus baselines top-level gates.

#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include "ua_diagnostic_bits.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_namespace_array.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

#include "fake_namespace.h"
#include "stubs.h"
#include "test_utilities.h"

#include "test_components.h"

namespace ua::test::behaviour_pins::translate_browse_paths
{
namespace
{

using namespace std::chrono_literals;

// Permissive DiagnosticSecurityContext so the two-arg DiagnosticCollector ctor
// surfaces ErrorDetail content via apply_to.
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

class TranslateBrowsePathsPin : public ::testing::Test
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

  ::ua::Response run_translate(::ua::TranslateBrowsePathsToNodeIdsRequest&& req)
  {
    std::promise<::ua::Response> p;
    auto fut = p.get_future();
    mService = ::ua::server::TranslateBrowsePathsService::create(mSession,
      /*sessionLocales=*/{},
      /*requestId=*/0,
      std::move(req),
      mPool->executor(),
      [&p](::ua::Response r) { p.set_value(std::move(r)); });
    if (fut.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "Translate callback did not fire within 2s";
      return {};
    }
    return fut.get();
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::thread::id mPoolThreadId;
  ::ua::server::ServerConfig mServerCfg;
  std::optional<::ua::server::Server> mServer;
  std::shared_ptr<PermissiveDiagsSessionInfo> mSession;
  std::shared_ptr<::ua::server::TranslateBrowsePathsService> mService;
};

// ---------------------------------------------------------------------------
// TBP-J - Empty browse_paths yields ServiceFault.BadNothingToDo with detail.
//        Falsifiable bug: a {b} flip that drops the empty-list check at
//        ua_translate_browse_paths_service.cpp:292-298.
// ---------------------------------------------------------------------------
TEST_F(TranslateBrowsePathsPin, TranslateBrowsePathsRejectsEmptyBrowsePathsWithBadNothingToDo)
{
  build_session();

  ::ua::TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().return_diagnostics() =
    ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;
  // browse_paths() left empty.

  auto response = run_translate(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for empty browse_paths";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadNothingToDo);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value())
    << "service-level detail must propagate";
}

// ---------------------------------------------------------------------------
// TBP-K - Operation count exceeds maxNodesPerTranslateBrowsePathsToNodeIds ->
//         ServiceFault.BadTooManyOperations.
//         Falsifiable bug: a {b} flip that drops the limits check at
//         ua_translate_browse_paths_service.cpp:300-310.
// ---------------------------------------------------------------------------
TEST_F(TranslateBrowsePathsPin, TranslateBrowsePathsRejectsExceedingLimitWithBadTooManyOperations)
{
  mServerCfg.server_capabilities().operationLimits.maxNodesPerTranslateBrowsePathsToNodeIds = 1;
  mServer.reset();
  ::ua::server::CreateConfig cfg{.identity = ::ua::ApplicationIdentity::load_default(),
    .application = ::ua::test_utils::create_test_config(),
    .server = mServerCfg};
  mServer.emplace(::ua::server::Server::create(mPool->executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));
  build_session();

  ::ua::TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().return_diagnostics() =
    ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;
  req.browse_paths().resize(2);
  req.browse_paths()[0].starting_node() = ::ua::NodeId{0u, 0u};
  req.browse_paths()[1].starting_node() = ::ua::NodeId{0u, 1u};

  auto response = run_translate(std::move(req));
  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault for over-limit browse_paths";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadTooManyOperations);
  EXPECT_TRUE(fault->response_header().service_diagnostics().symbolic_id().has_value());
}

// ---------------------------------------------------------------------------
// TBP-AFF - User callback fires on the service strand pool thread.
// ---------------------------------------------------------------------------
TEST_F(TranslateBrowsePathsPin, TranslateBrowsePathsUserCallbackFiresOnServiceStrand)
{
  build_session();

  std::promise<std::thread::id> p;
  auto fut = p.get_future();
  ::ua::TranslateBrowsePathsToNodeIdsRequest req;
  // Empty browse_paths drives the synchronous BadNothingToDo path.
  mService = ::ua::server::TranslateBrowsePathsService::create(mSession,
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
// TBP-D1 - Destructor-during-flight fires the user callback with BadShutdown.
//
// Authored against the {b} flip's restructured lifetime (weak_from_this everywhere,
// per-flow structs allocated on the strand, ~TranslateBrowsePathsService gated by
// try_finish()). The test parks the find_node await on a
// FakeNamespace at index 2 (which never fires its callback), waits for the parked
// request count to be > 0, then drops the service's last shared_ptr. The destructor
// observes the per-op flow is still in flight, calls try_finish() (returns true),
// and fires Status::BadShutdown to the user callback.
// ---------------------------------------------------------------------------
TEST_F(TranslateBrowsePathsPin, TranslateBrowsePathsDestructorDuringFlightFiresShutdownCallback)
{
  // Inject FakeNamespace into the Server's address space so find_node on a NS=2
  // NodeId parks instead of completing.
  auto fakeNs = ::ua::test_helpers::FakeNamespace::create("urn:test:tbp-fake-ns");
  fakeNs->decline_create_nodes_as_unsupported();
  ASSERT_TRUE(mServer.has_value());
  const uint16_t fakeIdx = mServer->address_space().add_namespace_sync(fakeNs);
  build_session();

  std::promise<::ua::StatusCode> p;
  auto fut = p.get_future();

  ::ua::TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().return_diagnostics() =
    ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;
  req.browse_paths().resize(1);
  req.browse_paths()[0].starting_node() = ::ua::NodeId{fakeIdx, 1u};
  // A non-empty relative path so the operation reaches the find_node_async await
  // (the empty-path guard fires BadNothingToDo synchronously, before find_node).
  req.browse_paths()[0].relative_path().elements().payload().resize(1);
  req.browse_paths()[0].relative_path().elements().payload()[0].target_name() =
    ::ua::QualifiedName{0u, ::ua::String{"x"}};

  mService = ::ua::server::TranslateBrowsePathsService::create(mSession,
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

  // Wait for the per-op find_node to be parked on the fake NS.
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

}  // namespace
}  // namespace ua::test::behaviour_pins::translate_browse_paths
