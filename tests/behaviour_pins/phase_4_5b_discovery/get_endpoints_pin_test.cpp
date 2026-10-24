// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.5b - DiscoveryServiceSet<GetEndpointsRequest> flow.
//
//
// Coverage:
//   GE-A GetEndpointsReturnsConfiguredEndpoints
//   GE-B GetEndpointsOrdersByDescendingSecurityLevel
//   GE-C GetEndpointsFiltersByProfileUri
//   GE-D GetEndpointsErrorDetailSuppressedOnWireForAnonymousCaller
//   GE-E GetEndpointsErrorDetailLoggedServerSideButSuppressedOnWire
//        (Stage-2 F4: anonymous/no-security discovery masks internal ErrorDetail on the wire
//        per OPC 10000-2 6.3 / 10000-4 7.41.2.1, but logs the full detail server-side)
//   GE-F GetEndpointsResponseHeaderCarriesRequestHandle
//   GE-G GetEndpointsTimeoutEmitsServiceFaultWithBadTimeout
//   GE-H GetEndpointsUserCallbackFiresOnServiceStrand
//   DISABLED_GetEndpointsDestructorDuringFlightFiresShutdownCallback (D1, expected-fail
//     until matching {b} flip restructures lifetime)
//
// `Discovery::is_endpoint_url_accepted` (the public static helper at
// ua_discovery_service_set.cpp:260-286) is NOT pinned here - it is already
// covered by tests/unit/server/core/create_session_endpoint_url_validation_tests.cpp
// (and consumed by the 4.9 ServerSession CreateSession pin corpus).

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ua_crypto_types.h"
#include "ua_diagnostic_bits.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_message_security_mode.h"
#include "ua_server.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_transport_address.h"

#include "fake_discovery_dependencies.h"
#include "pin_certificate_store.h"
#include "ua_discovery_service_set.h"
#include "ua_log_entry.h"
#include "ua_log_sink.h"
#include "ua_logger.h"

#include <atomic>
#include <mutex>
#include <variant>

namespace ua::test::behaviour_pins::discovery
{
namespace
{

using namespace std::chrono_literals;

constexpr uint32_t fullDiagnostics =
  ::ua::server::diag::serviceLevelMask | ::ua::server::diag::operationLevelMask;

// Records structured log fields so a test can assert the discovery error path logged the full
// ErrorDetail server-side (the string_view field values are alive during the synchronous log() call).
class CapturingLogSink : public ::ua::LogSink
{
public:
  void log(const ::ua::LogEntry& entry) override
  {
    std::lock_guard lock(mMutex);
    std::string joined{entry.message};
    for (const auto& field : entry.fields)
    {
      if (const auto* text = std::get_if<std::string_view>(&field.value))
      {
        joined += '|';
        joined += *text;
      }
    }
    mEntries.push_back(std::move(joined));
  }

  bool any_contains(std::string_view needle) const
  {
    std::lock_guard lock(mMutex);
    for (const auto& entry : mEntries)
    {
      if (entry.find(needle) != std::string::npos)
        return true;
    }
    return false;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mEntries;
};

::ua::Logger make_capturing_logger(std::shared_ptr<CapturingLogSink> sink)
{
  return ::ua::Logger{
    std::move(sink), std::make_shared<std::atomic<::ua::LogLevel>>(::ua::LogLevel::Trace), "test"};
}

::ua::server::ServerEndpointConfig make_endpoint(std::string name,
  ::ua::SecurityPolicyId policy = ::ua::SecurityPolicyId::None,
  ::ua::MessageSecurityMode mode = ::ua::MessageSecurityMode::None)
{
  ::ua::server::ServerEndpointConfig cfg;
  cfg.name = std::move(name);
  cfg.securityPolicyId = policy;
  cfg.messageSecurityMode = mode;
  cfg.transportProfile = ::ua::TransportProfileId::UaTcpUaScUaBinary;
  return cfg;
}

class GetEndpointsPin : public ::testing::Test
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

  // Two listeners x two endpoints each = 4 endpoints. All None-mode (no cert needed).
  void stage_four_none_endpoints()
  {
    mDeps->add_listener(::ua::server::ListenerHandle{1},
      {make_endpoint("ep1"), make_endpoint("ep2")},
      {::ua::transport::EndpointUrl{"opc.tcp://localhost:4840/"}});

    mDeps->add_listener(::ua::server::ListenerHandle{2},
      {make_endpoint("ep3"), make_endpoint("ep4")},
      {::ua::transport::EndpointUrl{"opc.tcp://localhost:4841/"}});
  }

  ::ua::Response run_get_endpoints(::ua::GetEndpointsRequest&& req)
  {
    std::promise<::ua::Response> p;
    auto fut = p.get_future();
    mService = ::ua::server::DiscoveryServiceSet<::ua::GetEndpointsRequest>::create(mDeps,
      ::ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(req),
      mPool->executor(),
      [&p](::ua::Response r) { p.set_value(std::move(r)); });

    if (fut.wait_for(2s) != std::future_status::ready)
    {
      ADD_FAILURE() << "GetEndpoints callback did not fire within 2s";
      return {};
    }
    return fut.get();
  }

  std::unique_ptr<::boost::asio::thread_pool> mPool;
  std::thread::id mPoolThreadId;
  std::shared_ptr<PinCertificateStore> mCertStore;
  std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies> mDeps;
  std::shared_ptr<::ua::server::DiscoveryServiceSet<::ua::GetEndpointsRequest>> mService;
};

// ---------------------------------------------------------------------------
// GE-A - Happy path: 4 staged endpoints surface as 4 EndpointDescriptions.
//        Falsifiable bug: a {b} flip that loses the per-listener iteration.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsReturnsConfiguredEndpoints)
{
  stage_four_none_endpoints();

  ::ua::GetEndpointsRequest req;
  auto response = run_get_endpoints(std::move(req));

  auto* getResponse = dynamic_cast<::ua::GetEndpointsResponse*>(response.second.get());
  ASSERT_NE(getResponse, nullptr) << "expected GetEndpointsResponse, got ServiceFault";
  EXPECT_EQ(getResponse->response_header().service_result(), ::ua::Status::Good);
  EXPECT_EQ(getResponse->endpoints().payload().size(), 4u);
}

// ---------------------------------------------------------------------------
// GE-B - Endpoints emerge in non-increasing security-level order. The test
//        cert store returns an empty ApplicationCertificate list; an authenticated
//        endpoint (any SecurityPolicyId other than None) is skipped per
//        ua_discovery_service_set.cpp:357-368 ("authenticated channel requires
//        a certificate - skip endpoint if missing"). To exercise the std::sort
//        without standing up real X509Certificates, the KAT uses 4 None-policy
//        endpoints - all yield compute_security_level == 0, so any permutation
//        of the staged order satisfies the descending ordering invariant. The
//        pin still catches a {b} flip that loses the security_level assignment
//        (each entry must equal 0).
//
//        A stronger multi-tier KAT (asserting strictly descending levels via
//        SecurityPolicyId values from ua_security_level.h's tier table) is
//        deferred until the corpus ships real X509Certificate fixtures via
//        test_pki_helpers - captured in the runbook section 4.3 GE-B TODO.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsOrdersByDescendingSecurityLevel)
{
  stage_four_none_endpoints();

  ::ua::GetEndpointsRequest req;
  auto response = run_get_endpoints(std::move(req));

  auto* getResponse = dynamic_cast<::ua::GetEndpointsResponse*>(response.second.get());
  ASSERT_NE(getResponse, nullptr);
  auto& endpoints = getResponse->endpoints().payload();
  ASSERT_EQ(endpoints.size(), 4u);

  for (size_t i = 1; i < endpoints.size(); ++i)
  {
    EXPECT_GE(endpoints[i - 1].security_level(), endpoints[i].security_level());
  }
  for (const auto& ep : endpoints)
  {
    EXPECT_EQ(ep.security_level(), 0u) << "None-policy endpoints must yield compute_security_level == 0";
  }
}

// ---------------------------------------------------------------------------
// GE-C - Profile-URI filter excludes endpoints whose transport_profile_uri is
//        NOT in the request filter list. The SDK currently only models a single
//        TransportProfileId enum value (UaTcpUaScUaBinary); we exercise the filter
//        loop by requesting an unknown profile URI and asserting the response
//        contains zero endpoints. Falsifiable bug: a {b} flip that drops the
//        std::erase_if filter at ua_discovery_service_set.cpp:170-178 would
//        return all four endpoints instead of zero.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsFiltersByProfileUri)
{
  stage_four_none_endpoints();

  ::ua::GetEndpointsRequest req;
  req.profile_uris().payload().push_back(::ua::String{"unknown://nonsense-profile-uri"});

  auto response = run_get_endpoints(std::move(req));
  auto* getResponse = dynamic_cast<::ua::GetEndpointsResponse*>(response.second.get());
  ASSERT_NE(getResponse, nullptr);
  auto& endpoints = getResponse->endpoints().payload();
  EXPECT_EQ(endpoints.size(), 0u) << "filter that matches none must drop all endpoints";
}

// ---------------------------------------------------------------------------
// GE-D - CertStore failure: ServiceFault.BadInternalError, but service diagnostics are SUPPRESSED on
//        the wire. Discovery is session-less / no-message-security, so internal ErrorDetail must NOT
//        reach the unauthenticated caller even when returnDiagnostics is requested
//        (OPC 10000-2 6.3 "error codes can be used as an attack vector; their uses should be limited";
//        10000-4 7.41.2.1; 10000-12 7.10.11 detailed diagnostics are privilege-gated). Returning the
//        DiagnosticInfo is discretionary/vendor-specific (10000-4 7.12/7.33), so suppression is
//        conformant. The precise StatusCode still propagates - only the rich detail is withheld.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsErrorDetailSuppressedOnWireForAnonymousCaller)
{
  stage_four_none_endpoints();
  std::shared_ptr<const ::ua::ErrorDetail> innerDetail{::ua::make_error_detail(
    "PinCertStoreInjectedFailure", "PinCertStore staged failure", "PinCertificateStore")};
  mCertStore->set_inline_failure(::ua::Status::BadInternalError, innerDetail);
  mCertStore->set_mode(PinCertificateStore::Mode::InlineFail);

  ::ua::GetEndpointsRequest req;
  req.request_header().return_diagnostics() = fullDiagnostics;
  auto response = run_get_endpoints(std::move(req));

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
// GE-E - Lossless ErrorDetail propagation to the LOG, suppression on the WIRE. The full detail
//        (code / summary / additional-info) must be preserved server-side for operators/audit
//        (never silently discard ErrorDetail; OPC 10000-4 7.41.2.1 "Servers shall log
//        details"), but must NOT be serialised into the wire serviceDiagnostics returned to the
//        anonymous discovery caller. Falsifiable both ways: if the fix leaked the detail to the wire
//        the wire-suppression checks fail; if the fix dropped the detail entirely the log checks fail.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsErrorDetailLoggedServerSideButSuppressedOnWire)
{
  stage_four_none_endpoints();

  auto sink = std::make_shared<CapturingLogSink>();
  mDeps->set_logger(make_capturing_logger(sink));

  // make_error_detail 4-arg signature is (code, summary, detail, source).
  std::shared_ptr<const ::ua::ErrorDetail> innerDetail{::ua::make_error_detail(
    "InnerCode", "Inner summary text", "additional info payload", "PinCertificateStore")};
  mCertStore->set_inline_failure(::ua::Status::BadInternalError, innerDetail);
  mCertStore->set_mode(PinCertificateStore::Mode::InlineFail);

  ::ua::GetEndpointsRequest req;
  req.request_header().return_diagnostics() = fullDiagnostics;
  auto response = run_get_endpoints(std::move(req));

  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr);

  // (b) WIRE: the rich detail is suppressed for the anonymous caller.
  const auto& diag = fault->response_header().service_diagnostics();
  EXPECT_FALSE(diag.symbolic_id().has_value());
  EXPECT_FALSE(diag.localized_text().has_value());
  EXPECT_FALSE(diag.additional_info().has_value());
  EXPECT_TRUE(fault->response_header().string_table().payload().empty());

  // (a) LOG: the full ErrorDetail is preserved server-side.
  EXPECT_TRUE(sink->any_contains("InnerCode"))
    << "the ErrorDetail code must be logged server-side before wire masking";
  EXPECT_TRUE(sink->any_contains("additional info payload"))
    << "the ErrorDetail additional-info must be logged server-side before wire masking";
}

// An Uncertain certificate-store answer is not used to build endpoints. The GetEndpoints ServiceFault is
// Bad_InternalError, never the Uncertain code, and the refusal (CertificateStoreAnswerUncertain) is logged
// server-side. FindServers and CreateSession take their endpoints from the same step.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(GetEndpointsPin, AnUncertainCertificateStoreAnswerIsRefusedWithBadInternalError)
{
  stage_four_none_endpoints();

  auto sink = std::make_shared<CapturingLogSink>();
  mDeps->set_logger(make_capturing_logger(sink));
  mCertStore->set_inline_failure(::ua::Status::UncertainLastUsableValue, nullptr);
  mCertStore->set_mode(PinCertificateStore::Mode::InlineFail);

  ::ua::GetEndpointsRequest req;
  auto response = run_get_endpoints(std::move(req));

  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "an Uncertain store answer must not build a GetEndpointsResponse";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadInternalError)
    << "the fault must carry the refusal, not the store's Uncertain code";
  EXPECT_TRUE(sink->any_contains("CertificateStoreAnswerUncertain"))
    << "the refusal of the Uncertain answer must be logged server-side";
}

// ---------------------------------------------------------------------------
// GE-F - Request-handle correlation. Falsifiable bug: a {b} flip that loses
//        prepare_response_header(...) for the GetEndpoints flow.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsResponseHeaderCarriesRequestHandle)
{
  stage_four_none_endpoints();
  ::ua::GetEndpointsRequest req;
  req.request_header().request_handle() = ::ua::IntegerId{0xDEADBEEF};

  auto response = run_get_endpoints(std::move(req));
  auto* getResponse = dynamic_cast<::ua::GetEndpointsResponse*>(response.second.get());
  ASSERT_NE(getResponse, nullptr);
  EXPECT_EQ(getResponse->response_header().request_handle(), ::ua::IntegerId{0xDEADBEEF});
}

// ---------------------------------------------------------------------------
// GE-G - Timeout-hint expiry yields ServiceFault.BadTimeout (mirror of FS-E).
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsTimeoutEmitsServiceFaultWithBadTimeout)
{
  stage_four_none_endpoints();
  mCertStore->set_mode(PinCertificateStore::Mode::AsyncDeferred);

  ::ua::GetEndpointsRequest req;
  req.request_header().timeout_hint() = 50;

  std::promise<::ua::Response> p;
  auto fut = p.get_future();
  mService = ::ua::server::DiscoveryServiceSet<::ua::GetEndpointsRequest>::create(mDeps,
    ::ua::LocaleId{"en"},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response r) { p.set_value(std::move(r)); });

  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
  auto response = fut.get();
  auto* fault = dynamic_cast<::ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "expected ServiceFault on timeout";
  EXPECT_EQ(fault->response_header().service_result(), ::ua::Status::BadTimeout);
}

// ---------------------------------------------------------------------------
// GE-H - User callback fires on the service strand pool thread.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsUserCallbackFiresOnServiceStrand)
{
  stage_four_none_endpoints();

  std::promise<std::thread::id> p;
  auto fut = p.get_future();
  ::ua::GetEndpointsRequest req;
  mService = ::ua::server::DiscoveryServiceSet<::ua::GetEndpointsRequest>::create(mDeps,
    ::ua::LocaleId{"en"},
    /*requestId=*/0,
    std::move(req),
    mPool->executor(),
    [&p](::ua::Response) { p.set_value(std::this_thread::get_id()); });

  ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
  auto cbThread = fut.get();
  EXPECT_EQ(cbThread, mPoolThreadId);
  EXPECT_NE(cbThread, std::this_thread::get_id());
}

// ---------------------------------------------------------------------------
// DISABLED_GetEndpointsDestructorDuringFlightFiresShutdownCallback (D1)
//
// See find_servers_pin_test.cpp for the rationale. The pin asserts the
// post-flip target behaviour and is expected-fail until the matching {b}
// flip restructures the lifetime to weak_from_this.
// ---------------------------------------------------------------------------
TEST_F(GetEndpointsPin, GetEndpointsDestructorDuringFlightFiresShutdownCallback)
{
  stage_four_none_endpoints();
  mCertStore->set_mode(PinCertificateStore::Mode::AsyncDeferred);

  std::promise<::ua::StatusCode> p;
  auto fut = p.get_future();
  ::ua::GetEndpointsRequest req;
  mService = ::ua::server::DiscoveryServiceSet<::ua::GetEndpointsRequest>::create(mDeps,
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

  for (int i = 0; i < 200 && mCertStore->parked_count() == 0; ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  mService.reset();

  ASSERT_EQ(fut.wait_for(500ms), std::future_status::ready);
  EXPECT_EQ(fut.get(), ::ua::Status::BadShutdown);
}

}  // namespace
}  // namespace ua::test::behaviour_pins::discovery
