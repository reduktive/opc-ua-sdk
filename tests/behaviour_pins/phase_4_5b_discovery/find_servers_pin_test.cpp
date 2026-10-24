// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5b - DiscoveryServiceSet<FindServersRequest> flow.
//
//
// Coverage (runbook section 4.1):
//   FS-A FindServersAsyncReturnsConfiguredServers
//   FS-B FindServersDeduplicatesDiscoveryUrlsAcrossEndpoints
//   FS-C FindServersResponseHeaderCarriesRequestHandle
//   FS-D FindServersErrorDetailSuppressedOnWireForAnonymousCaller
//   FS-E FindServersTimeoutEmitsServiceFaultWithBadTimeout
//   FS-F FindServersUserCallbackFiresOnServiceStrand
//   DISABLED_FindServersDestructorDuringFlightFiresShutdownCallback   (D1, expected-fail
//     until matching {b} flip restructures lifetime to weak_from_this with explicit
//     destructor BadShutdown emission)

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_application_description.h"
#include "ua_crypto_types.h"
#include "ua_diagnostic_bits.h"
#include "ua_error_detail.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_message_security_mode.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_transport_address.h"

#include "fake_discovery_dependencies.h"
#include "pin_certificate_store.h"
#include "ua_discovery_service_set.h"

namespace ua::test::behaviour_pins::discovery
{
namespace
{

using namespace std::chrono_literals;

constexpr uint32_t fullDiagnostics =
  ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;

// Stage two listener handles, each with a single None-mode endpoint. None-mode
// endpoints don't require a server certificate - the inner Discovery::get_endpoints_coro
// path emits them even when the cert store returns an empty list.
::ua::server::ServerEndpointConfig make_endpoint(std::string name,
  ::ua::SecurityPolicyId policy = ::ua::SecurityPolicyId::None,
  ::ua::MessageSecurityMode mode = ::ua::MessageSecurityMode::None)
{
  ::ua::server::ServerEndpointConfig cfg;
  cfg.name = std::move(name);
  cfg.securityPolicyId = policy;
  cfg.messageSecurityMode = mode;
  cfg.transportProfile = ::ua::TransportProfileId::UaTcpUaScUaBinary;
  // No user identity tokens - Discovery iterates this vector to copy into the
  // EndpointDescription, an empty vector is acceptable.
  return cfg;
}

class FindServersPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<::boost::asio::thread_pool>(/*noOfThreads=*/1);
    // Capture the pool worker thread id so FS-F can assert the user callback fires
    // on a different thread than the test main thread.
    {
      std::promise<std::thread::id> p;
      boost::asio::post(*mPool, [&p]() { p.set_value(std::this_thread::get_id()); });
      mPoolThreadId = p.get_future().get();
    }

    mCertStore = PinCertificateStore::create();

    mDeps = std::make_shared<::ua::test_helpers::FakeDiscoveryDependencies>(mPool->executor());
    mDeps->set_default_application_group_certificate_store(mCertStore);
  }

  void TearDown() override
  {
    mDeps.reset();
    mCertStore.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  // Single listener with two None-mode endpoints; deduplicated advertised URL pair.
  void stage_two_listeners_two_urls()
  {
    mDeps->add_listener(::ua::server::ListenerHandle{1},
      {make_endpoint("ep1"), make_endpoint("ep2")},
      {::ua::transport::EndpointUrl{"opc.tcp://localhost:4840/"}});

    mDeps->add_listener(::ua::server::ListenerHandle{2},
      {make_endpoint("ep3")},
      {::ua::transport::EndpointUrl{"opc.tcp://localhost:4841/"}});
  }

  // Stage one listener with two endpoints sharing a single advertised URL - drives
  // the dedup loop at ua_discovery_service_set.cpp:104-117.
  void stage_one_listener_dedup()
  {
    mDeps->add_listener(::ua::server::ListenerHandle{1},
      {make_endpoint("ep1"), make_endpoint("ep2")},
      {::ua::transport::EndpointUrl{"opc.tcp://localhost:4840/"}});
  }

  ::ua::Response run_find_servers(::ua::FindServersRequest&& req)
  {
    std::promise<::ua::Response> p;
    auto fut = p.get_future();
    mService = ::ua::server::DiscoveryServiceSet<::ua::FindServersRequest>::create(mDeps,
      ::ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(req),
      mPool->executor(),
      [&p](::ua::Response r) { p.set_value(std::move(r)); });

    if (fut.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "FindServers callback did not fire within 2s";
      return {};
    }
    return fut.get();
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::thread::id mPoolThreadId;
  std::shared_ptr<PinCertificateStore> mCertStore;
  std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies> mDeps;
  std::shared_ptr<::ua::server::DiscoveryServiceSet<::ua::FindServersRequest>> mService;
};

// ---------------------------------------------------------------------------
// FS-A - Happy path: FindServers returns a single ApplicationDescription whose
//        discovery_urls match the deduplicated listener-advertised URL list.
//        Falsifiable bug: a {b} flip that drops the dedup loop or the AppDesc
//        construction would surface here.
// ---------------------------------------------------------------------------
TEST_F(FindServersPin, FindServersAsyncReturnsConfiguredServers)
{
  stage_two_listeners_two_urls();

  ::ua::FindServersRequest req;
  auto response = run_find_servers(std::move(req));

  auto* findResponse = dynamic_cast<::ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr) << "expected FindServersResponse, got ServiceFault";
  EXPECT_EQ(findResponse->response_header().service_result(), ::ua::Status::Good);

  auto& servers = findResponse->servers().payload();
  ASSERT_EQ(servers.size(), 1u) << "FindServers emits a single AppDescription per server";

  auto& discoveryUrls = servers[0].discovery_urls().payload();
  ASSERT_EQ(discoveryUrls.size(), 2u) << "two distinct advertised URLs across two listeners";
}

// ---------------------------------------------------------------------------
// FS-B - Dedup: two endpoint configs sharing the same advertised URL surface as
//        a single discovery URL. Falsifiable bug: a careless {b} flip that
//        replaces the linear-search dedup with naive concatenation.
// ---------------------------------------------------------------------------
TEST_F(FindServersPin, FindServersDeduplicatesDiscoveryUrlsAcrossEndpoints)
{
  stage_one_listener_dedup();

  ::ua::FindServersRequest req;
  auto response = run_find_servers(std::move(req));

  auto* findResponse = dynamic_cast<::ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  auto& servers = findResponse->servers().payload();
  ASSERT_EQ(servers.size(), 1u);
  auto& urls = servers[0].discovery_urls().payload();
  EXPECT_EQ(urls.size(), 1u) << "shared advertised URL must dedupe to one entry";
}

// ---------------------------------------------------------------------------
// FS-C - Request-handle correlation. Falsifiable bug: a {b} flip that loses
//        prepare_response_header(...) silently breaks the wire correlation.
// ---------------------------------------------------------------------------
TEST_F(FindServersPin, FindServersResponseHeaderCarriesRequestHandle)
{
  stage_two_listeners_two_urls();

  ::ua::FindServersRequest req;
  req.request_header().request_handle() = ::ua::IntegerId{0x12345678};
  auto response = run_find_servers(std::move(req));

  auto* findResponse = dynamic_cast<::ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->response_header().request_handle(), ::ua::IntegerId{0x12345678});
}

// ---------------------------------------------------------------------------
// FS-D - CertStore failure: ServiceFault with BadInternalError, but the rich diagnostic content is
//        SUPPRESSED on the wire. Discovery is session-less / no-message-security, so internal
//        ErrorDetail must NOT reach the unauthenticated caller even with returnDiagnostics requested
//        (OPC 10000-2 6.3; 10000-4 7.41.2.1; 10000-12 7.10.11 - detailed diagnostics are privilege-
//        gated). Returning the DiagnosticInfo is discretionary (10000-4 7.12/7.33), so suppression is
//        conformant. The StatusCode still propagates; the detail is logged server-side instead (see the
//        GetEndpoints GE-E pin for the log-path assertion).
//
// Falsifiable bug: a regression that swaps Discovery back to the ungated DiagnosticCollector ctor would
// surface the interned ErrorDetail strings here and fail the suppression checks.
// ---------------------------------------------------------------------------
TEST_F(FindServersPin, FindServersErrorDetailSuppressedOnWireForAnonymousCaller)
{
  stage_two_listeners_two_urls();
  std::shared_ptr<const ::ua::ErrorDetail> innerDetail{::ua::make_error_detail(
    "PinCertStoreInjectedFailure", "PinCertStore staged failure", "PinCertificateStore")};
  mCertStore->set_inline_failure(::ua::Status::BadInternalError, innerDetail);
  mCertStore->set_mode(PinCertificateStore::Mode::InlineFail);

  ::ua::FindServersRequest req;
  req.request_header().return_diagnostics() = fullDiagnostics;
  auto response = run_find_servers(std::move(req));

  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault on cert-store failure";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadInternalError)
    << "the StatusCode is not secret and still propagates";

  const auto& diag = fault->response_header().service_diagnostics();
  EXPECT_FALSE(diag.symbolic_id().has_value())
    << "internal ErrorDetail must be masked on the anonymous discovery wire";
  EXPECT_FALSE(diag.localized_text().has_value());
  EXPECT_FALSE(diag.additional_info().has_value());
  EXPECT_TRUE(fault->response_header().string_table().payload().empty());
}

// ---------------------------------------------------------------------------
// FS-E - Timeout-hint expiry yields ServiceFault.BadTimeout. Falsifiable bug:
//        a {b} flip that drops `set_timeout(...)` from the FindServers entry.
// ---------------------------------------------------------------------------
TEST_F(FindServersPin, FindServersTimeoutEmitsServiceFaultWithBadTimeout)
{
  stage_two_listeners_two_urls();
  mCertStore->set_mode(PinCertificateStore::Mode::AsyncDeferred);

  ::ua::FindServersRequest req;
  req.request_header().timeout_hint() = 50;  // 50ms

  std::promise<::ua::Response> p;
  auto fut = p.get_future();
  mService = ::ua::server::DiscoveryServiceSet<::ua::FindServersRequest>::create(mDeps,
    ::ua::LocaleId{"en"},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response r) { p.set_value(std::move(r)); });

  // Wait > timeout_hint for the timeout to fire.
  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready) << "timer must fire within the 2s test budget";

  auto response = fut.get();
  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault on timeout";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadTimeout);
}

// ---------------------------------------------------------------------------
// FS-F - User callback fires on the service strand pool thread. The pool has
//        one worker; the callback thread id must equal the pool worker id (and
//        must NOT equal the test main thread id).
// ---------------------------------------------------------------------------
TEST_F(FindServersPin, FindServersUserCallbackFiresOnServiceStrand)
{
  stage_two_listeners_two_urls();

  std::promise<std::thread::id> p;
  auto fut = p.get_future();
  ::ua::FindServersRequest req;
  mService = ::ua::server::DiscoveryServiceSet<::ua::FindServersRequest>::create(mDeps,
    ::ua::LocaleId{"en"},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response) { p.set_value(std::this_thread::get_id()); });

  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
  auto cbThread = fut.get();
  EXPECT_EQ(cbThread, mPoolThreadId) << "user callback fires on service strand pool thread";
  EXPECT_NE(cbThread, std::this_thread::get_id()) << "callback must not fire on test main thread";
}

// ---------------------------------------------------------------------------
// DISABLED_FindServersDestructorDuringFlightFiresShutdownCallback (D1)
//
// Per the runbook D1 disposition (ratified by the user): destructor-during-flight
// must fire the user callback with Status::BadShutdown. Pre-flip code captures
// `auto self = this->shared_from_this()` at ua_discovery_service_set.cpp:88,
// keeping the service alive across the cert-store await and so making the
// destructor unobservable while the flow is mid-flight. This pin asserts the
// post-flip target behaviour and is expected-fail until the matching {b} flip
// restructures the lifetime to weak_from_this and emits BadShutdown explicitly
// from ~DiscoveryServiceSet.
// ---------------------------------------------------------------------------
TEST_F(FindServersPin, FindServersDestructorDuringFlightFiresShutdownCallback)
{
  stage_two_listeners_two_urls();
  mCertStore->set_mode(PinCertificateStore::Mode::AsyncDeferred);

  std::promise<::ua::StatusCode> p;
  auto fut = p.get_future();
  ::ua::FindServersRequest req;
  mService = ::ua::server::DiscoveryServiceSet<::ua::FindServersRequest>::create(mDeps,
    ::ua::LocaleId{"en"},
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

  // Wait for the cert-store callback to be parked, then destroy the service.
  for (int i = 0; i < 200 && mCertStore->parked_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  mService.reset();

  ASSERT_EQ(fut.wait_for(500ms), std::future_status::ready)
    << "destructor must drive the user callback with BadShutdown";
  EXPECT_EQ(fut.get(), ::ua::Status::BadShutdown);
}

}  // namespace
}  // namespace ua::test::behaviour_pins::discovery
