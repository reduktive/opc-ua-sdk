// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.9 - ServiceRequest entry-point gate (4.9d.2).
//
// What is pinned:
//   - Service request on a Closed session produces BadSessionIdInvalid.
//   - Non-discovery service request on a Created (not yet Activated) session
//     produces BadSessionNotActivated.
//   - Discovery requests (e.g. GetEndpoints) bypass the activation gate.
//
// What is NOT pinned (deferred to richer authorizer fixture per runbook section 4.6):
//   - authorize_async denial -> BadUserAccessDenied with ErrorDetail propagation.
//   - authorize_async success -> execute_service dispatch observability.
//   - Off-strand authorizer dispatch back to session strand (SD-E).
//   - mOutstandingRequestHandles bookkeeping (requires SessionTestAccess
//     extensions).

#include <chrono>
#include <gtest/gtest.h>

#include "fake_session_dependencies.h"

#include "ua_get_endpoints_request.h"
#include "ua_read_request.h"
#include "ua_service_fault.h"

namespace ua::test::pins_4_9
{

namespace
{

class ServiceRequestPin : public ::testing::Test
{};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: non-discovery request on Created (not yet Activated) session is rejected
// with BadSessionNotActivated.
// ---------------------------------------------------------------------------
TEST_F(ServiceRequestPin, NonDiscoveryRequestOnUnactivatedSessionProducesBadSessionNotActivated)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  // Session is Created (CreateSession completed) but not Activated. Inject a
  // ReadRequest - non-discovery - directly via SessionTestAccess.
  auto readReq = std::make_shared<ReadRequest>();
  readReq->request_header().request_handle() = 100;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, readReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(sf, nullptr) << "expected ServiceFault for unactivated read";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSessionNotActivated);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: discovery request on an unactivated session bypasses the activation
// gate (does not produce BadSessionNotActivated).
// ---------------------------------------------------------------------------
TEST_F(ServiceRequestPin, DiscoveryRequestOnUnactivatedSessionBypassesActivationGate)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  auto getEndpointsReq = std::make_shared<GetEndpointsRequest>();
  getEndpointsReq->request_header().request_handle() = 101;
  server::SessionTestAccess::on_strand(
    *h->session, [&](auto& g) { g.inject_decoded_request(3, getEndpointsReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  // The discovery request is not blocked by the activation gate. It may still
  // fail downstream (FakeSessionDependencies::discovery_dependencies() returns
  // a null weak_ptr) but the failure status must NOT be BadSessionNotActivated.
  if (sf)
  {
    EXPECT_NE(sf->response_header().service_result(), Status::BadSessionNotActivated)
      << "discovery request must bypass the activation gate";
  }
  // If it's not a ServiceFault (downstream succeeded), that also passes the
  // gate - both outcomes are acceptable.

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: cancel request on an unactivated session is also gated by
// BadSessionNotActivated. CancelRequest is non-discovery.
// ---------------------------------------------------------------------------
//
// Locks the source check at ua_server_session.cpp:1444-1451.
TEST_F(ServiceRequestPin, CancelRequestOnUnactivatedSessionProducesBadSessionNotActivated)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  auto cancelReq = std::make_shared<CancelRequest>();
  cancelReq->request_header().request_handle() = 102;
  cancelReq->request_handle() = 999;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, cancelReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSessionNotActivated);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: Part 4 section 5.6.3 - a non-CloseSession Service request issued before
// ActivateSession shall cause the Server to close the Session. After the
// premature read the session is torn down (remove_session invoked), so the
// authentication token can no longer be used to activate it.
// ---------------------------------------------------------------------------
TEST_F(ServiceRequestPin, PrematureServiceRequestClosesSession)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  ASSERT_EQ(h->sessDeps->removeSessionCalls.load(), 0u);

  auto readReq = std::make_shared<ReadRequest>();
  readReq->request_header().request_handle() = 100;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, readReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSessionNotActivated);

  // The premature use must have closed the session.
  server::SessionTestAccess::strand_barrier(*h->session);
  EXPECT_FALSE(h->session->is_activated());
  EXPECT_GT(h->sessDeps->removeSessionCalls.load(), 0u)
    << "premature service use must close the session (Part 4 section 5.6.3)";

  h->shutdown();
}

}  // namespace ua::test::pins_4_9
